#!/usr/bin/env python3
"""
Bug bounty reconnaissance with the Malanta API.
 
What it does (high level):
1) Maps a company's external assets (root domains → subdomains)
2) Surfaces likely takeover conditions
3) Gathers supporting evidence (DNS, certificate exposure, IP ranges)
 
Security & privacy notes (for contributors):
- Never print the API key. Avoid logging request bodies/headers that may contain secrets.
- Use timeouts and bounded retries to avoid indefinite hangs.
- Provide a custom User-Agent (minimal fingerprinting, but helps backend triage).
- Exit with non-zero codes on failures for CI/CD hygiene.
- Prefer env var for API key (safer than shell history), but allow CLI override for DX.
 
Threading / concurrency notes:
- Per-domain recon is run concurrently using ThreadPoolExecutor.
- Thread count is controlled by the CLI flag `--threads` (default: 1).
- Each thread operates independently with its own retries and backoff handling.
- Errors inside a thread are logged but do not abort the entire run.
- Use higher `--threads` for speed when API quotas/network allow, lower it if you hit rate-limits or local CPU/network constraints.
 
Output notes:
- By default, all results are returned (no sampling limits).
- Results are printed to stdout in JSON for easy piping (jq, gron, etc.).
- To save JSON directly to a file, pass `--out filename.json`.
"""
 
from __future__ import annotations
 
import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
 
import requests
 
API_BASE = "https://api.malanta.ai"
USER_AGENT = "malanta-example/1.0 (+https://github.com/YOURORG/YOURREPO)"
DEFAULT_TIMEOUT = 60  # seconds
MAX_RETRIES = 3
BACKOFF_BASE = 0.8    # exponential backoff base (jitter added)
 
 
# ---------------------------
# Utility / HTTP primitives
# ---------------------------
 
def _pick(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Case-insensitive dict getter: returns the first present, non-empty key."""
    if not isinstance(d, dict):
        return default
    lower = {k.lower(): v for k, v in d.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v not in (None, ""):
            return v
    return default
 
 
def _json_get(session: requests.Session, path: str, *, headers: Dict[str, str], params: Dict[str, Any], timeout: int = DEFAULT_TIMEOUT) -> List[Any]:
    """GET {API_BASE}{path} as JSON with bounded retries and exponential backoff."""
    url = f"{API_BASE}{path}"
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = session.get(url, headers=headers, params=params, timeout=timeout)
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", "1"))
                _sleep_with_backoff(attempt, base=retry_after or BACKOFF_BASE)
                _warn("429 rate-limited; backing off", url=url, attempt=attempt)
                continue
 
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("data", "items", "results", "records", "domains"):
                    if key in data and isinstance(data[key], list):
                        return data[key]
                return [data]
            return [data]
        except (requests.Timeout, requests.ConnectionError) as e:
            if attempt >= MAX_RETRIES:
                raise
            _sleep_with_backoff(attempt)
            _warn("Network issue; retrying", url=url, attempt=attempt, error=str(e))
        except requests.HTTPError as e:
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                raise
            if attempt >= MAX_RETRIES:
                raise
            _sleep_with_backoff(attempt)
            _warn("HTTP error; retrying", url=url, status=resp.status_code, attempt=attempt, error=str(e))
 
 
def _sleep_with_backoff(attempt: int, *, base: float = BACKOFF_BASE) -> None:
    delay = (base * (2 ** (attempt - 1))) + (0.05 * (attempt % 3))
    time.sleep(min(delay, 10.0))  # guard upper bound
 
 
def _warn(msg: str, **kv: Any) -> None:
    logging.warning("%s %s", msg, " ".join(f"{k}={v}" for k, v in kv.items()))
 
 
def _info(msg: str, **kv: Any) -> None:
    logging.info("%s %s", msg, " ".join(f"{k}={v}" for k, v in kv.items()))
 
 
# ---------------------------
# API calls
# ---------------------------
 
def fetch_company_domains(session, headers, company):
    raw = _json_get(session, "/getCompanyDomainsByCompany", headers=headers, params={"company_name": company})
    return sorted({_pick(it, "Domain", "domain", "root_domain", "name") for it in raw if _pick(it, "Domain", "domain", "root_domain", "name")})
 
 
def fetch_subdomains(session, headers, domain):
    return _json_get(session, "/getSubdomainsByDomain", headers=headers, params={"domain": domain})
 
 
def fetch_vuln_subs_company(session, headers, company):
    return _json_get(session, "/insightsVulnerableSubdomainsByCompany", headers=headers, params={"company_name": company})
 
 
def fetch_takeover_candidates_company(session, headers, company):
    return _json_get(session, "/getVulnerableForHijackSubDomainsByCompany", headers=headers, params={"company_name": company})
 
 
def fetch_dns_latest(session, headers, domain):
    return _json_get(session, "/getValidDnsRecordsLatestsByDomain", headers=headers, params={"domain": domain})
 
 
def fetch_cert_exposure(session, headers, domain):
    return _json_get(session, "/insightsCertificatesExposureByDomain", headers=headers, params={"domain": domain})
 
 
def fetch_ip_ranges(session, headers, domain):
    return _json_get(session, "/getIpRangesByDomain", headers=headers, params={"domain": domain})
 
 
# ---------------------------
# Recon workflow
# ---------------------------
 
def _process_domain(session, headers, d, vuln_company, takeover_company):
    subs = fetch_subdomains(session, headers, d)
    dns_latest = fetch_dns_latest(session, headers, d)
    certs = fetch_cert_exposure(session, headers, d)
    ip_ranges = fetch_ip_ranges(session, headers, d)
 
    fqdn_list = [_pick(s, "fqdn") for s in subs if _pick(s, "fqdn")]
 
    _info("domain-summary", domain=d, subs=len(subs), dns=len(dns_latest), certs=len(certs), ip_ranges=len(ip_ranges))
 
    return {
        "domain": d,
        "subdomains": subs,
        "fqdns": fqdn_list,
        "dns_records": dns_latest,
        "cert_exposures": certs,
        "vulnerable_company": vuln_company,
        "takeover_candidates": takeover_company,
        "ip_ranges": ip_ranges,
    }
 
 
def recon_company(session, headers, company, *, threads=2) -> Dict[str, Any]:
    """Run recon across all domains concurrently, returning all results (no sampling)."""
    result: Dict[str, Any] = {"company": company, "domains": []}
 
    domains = fetch_company_domains(session, headers, company)
    _info("mapped-company-domains", company=company, count=len(domains))
    result["domain_count"] = len(domains)
    result["domains_list"] = domains
 
    vuln_company = fetch_vuln_subs_company(session, headers, company)
    takeover_company = fetch_takeover_candidates_company(session, headers, company)
 
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(_process_domain, session, headers, d, vuln_company, takeover_company) for d in domains]
        for f in as_completed(futures):
            try:
                result["domains"].append(f.result())
            except Exception as e:
                logging.error("Domain task failed: %s", e)
 
    return result
 
 
# ---------------------------
# CLI
# ---------------------------
 
def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Bug bounty recon example using the Malanta API", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--company", required=True, help="Company name to map (e.g., 'Example Ltd.')")
    p.add_argument("--api-key", help="Malanta API key (if omitted, uses MALANTA_API_KEY env var)", default=os.environ.get("MALANTA_API_KEY"))
    p.add_argument("--out", help="Write JSON results to this file (otherwise prints to stdout)")
    p.add_argument("--threads", type=int, default=1, help="Number of concurrent threads (per-domain recon)")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args(argv)
 
 
def build_session(api_key: str) -> requests.Session:
    if not api_key:
        raise SystemExit("Missing API key. Provide --api-key or set MALANTA_API_KEY env var.")
    s = requests.Session()
    s.headers.update({"x-api-key": api_key, "User-Agent": USER_AGENT, "Accept": "application/json"})
    return s
 
 
def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(message)s")
 
    try:
        session = build_session(args.api_key)
        result = recon_company(session, session.headers, args.company, threads=args.threads)
    except requests.HTTPError as e:
        logging.error("HTTP error: %s", e)
        return 2
    except requests.RequestException as e:
        logging.error("Network error: %s", e)
        return 3
    except KeyboardInterrupt:
        logging.warning("Interrupted by user")
        return 130
    except Exception as e:
        logging.exception("Unexpected error: %s", e)
        return 1
 
    payload = json.dumps(result, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(payload)
        _info("wrote-output", path=args.out, bytes=len(payload.encode("utf-8")))
    else:
        print(payload)
 
    return 0
 
 
if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

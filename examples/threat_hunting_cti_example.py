#!/usr/bin/env python3
"""
Threat hunting & CTI pivots with the Malanta API.

Focus:
- Registrar pivot (track registrar and changes across time)
- Nameserver pivot (NS providers; drift over history)
- Creation & update timeline anomalies (e.g., newly created or frequent changes)
- Light vendor inference from NS/DNS to detect "asset sprawl" patterns

Security best-practices:
- Do not print or log API keys.
- Use timeouts, bounded retries, and clear exit codes for CI/CD hygiene.
- Keep a minimal, descriptive User-Agent to aid backend triage.
- Normalize JSON response shapes; be resilient to missing fields.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import requests

API_BASE = "https://api.malanta.ai"
USER_AGENT = "malanta-example/1.0 (+https://github.com/YOURORG/YOURREPO)"
DEFAULT_TIMEOUT = 60
MAX_RETRIES = 3
BACKOFF_BASE = 0.8  # seconds; exponential backoff base (small jitter added)

# Known corp registrars (adjust to your org norms)
PREFERRED_REGISTRARS = {
    "MarkMonitor Inc.",
    "CSC Corporate Domains, Inc.",
    "GoDaddy Corporate Domains, LLC",
    "SafeNames Ltd",
    "Nom-IQ Limited (DBA Com Laude)",
}

# Lightweight vendor inference by nameserver/CNAME/IP-owner tokens.
# This is heuristic and intentionally conservative.
VENDOR_TOKENS = {
    "aws": ("awsdns.", ".amazonaws.com", ".cloudfront.net"),
    "azure": (".azure-dns.", ".azurewebsites.net"),
    "cloudflare": (".nsone.net", ".cloudflare.com", ".cloudflaressl.com"),
    "google": (".googledomains.com", ".googlehosted.com", ".ghs.googlehosted.com"),
    "fastly": (".fastly.net",),
    "akamai": (".akam.net", ".edgesuite.net"),
    "vercel": (".vercel-dns.com", ".vercel.app"),
    "netlify": (".netlify.app",),
    "github": (".github.io",),
    "heroku": (".herokuapp.com",),
}

# ---------------------------
# Utilities
# ---------------------------

def _pick(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Case-insensitive dict getter: return first present non-empty key."""
    if not isinstance(d, dict):
        return default
    lower = {k.lower(): v for k, v in d.items()}
    for k in keys:
        v = lower.get(k.lower())
        if v not in (None, ""):
            return v
    return default


def _sleep_with_backoff(attempt: int, *, base: float = BACKOFF_BASE) -> None:
    delay = (base * (2 ** (attempt - 1))) + (0.05 * (attempt % 3))
    time.sleep(min(delay, 10.0))


def _warn(msg: str, **kv: Any) -> None:
    logging.warning("%s %s", msg, " ".join(f"{k}={v}" for k, v in kv.items()))


def _info(msg: str, **kv: Any) -> None:
    logging.info("%s %s", msg, " ".join(f"{k}={v}" for k, v in kv.items()))


def _json_get(
    session: requests.Session,
    path: str,
    *,
    headers: Dict[str, str],
    params: Dict[str, Any],
    timeout: int = DEFAULT_TIMEOUT,
) -> List[Any]:
    """
    GET {API_BASE}{path} with bounded retries. Normalizes the JSON to a list.

    Retries on:
      - 429 Too Many Requests
      - 5xx responses
      - Requests exceptions (timeouts, connection errors)
    """
    url = f"{API_BASE}{path}"
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = session.get(url, headers=headers, params=params, timeout=timeout)
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", "1"))
                _warn("429 rate-limited; retrying", url=url, attempt=attempt)
                _sleep_with_backoff(attempt, base=retry_after or BACKOFF_BASE)
                continue

            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("data", "items", "results", "records"):
                    if key in data and isinstance(data[key], list):
                        return data[key]
                return [data]
            return [data]
        except (requests.Timeout, requests.ConnectionError) as e:
            if attempt >= MAX_RETRIES:
                raise
            _warn("network error; retrying", url=url, attempt=attempt, error=str(e))
            _sleep_with_backoff(attempt)
        except requests.HTTPError as e:
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                raise
            if attempt >= MAX_RETRIES:
                raise
            _warn("http error; retrying", url=url, status=resp.status_code, attempt=attempt, error=str(e))
            _sleep_with_backoff(attempt)


# ---------------------------
# Endpoint wrappers (parsing matches your examples)
# ---------------------------

def get_company_domains(session: requests.Session, headers: Dict[str, str], company: str) -> List[str]:
    """
    /getCompanyDomainsByCompany
    Example item: {"Company": "Example Ltd.", "Domain": "example.com"}
    """
    items = _json_get(session, "/getCompanyDomainsByCompany", headers=headers, params={"company_name": company})
    domains = {
        _pick(it, "Domain", "domain", "root_domain", "name")
        for it in items
        if _pick(it, "Domain", "domain", "root_domain", "name")
    }
    return sorted(domains)


def get_whois_latest(session: requests.Session, headers: Dict[str, str], domain: str) -> Dict[str, Any]:
    """
    /getWhoisLatestsByDomain
    Example item keys (subset): domain_name, create_date, update_date, expiry_date,
    domain_registrar_name, name_server_1..4
    """
    items = _json_get(session, "/getWhoisLatestsByDomain", headers=headers, params={"domain": domain})
    return items[0] if items else {}


def get_whois_history(session: requests.Session, headers: Dict[str, str], domain: str) -> List[Dict[str, Any]]:
    """
    /getWhoisHistoryByDomain
    Returns a list of historical WHOIS snapshots with same key shapes as latest.
    """
    return _json_get(session, "/getWhoisHistoryByDomain", headers=headers, params={"domain": domain})


def get_dns_latest(session: requests.Session, headers: Dict[str, str], domain: str) -> List[Dict[str, Any]]:
    """
    /getValidDnsRecordsLatestsByDomain
    Example (from prior script): {"record_type": "A"|"AAAA"|"CNAME"|"NS", "record_value": "...", "fqdn": "..."}
    If your environment returns a different shape, the code handles missing keys gracefully.
    """
    return _json_get(session, "/getValidDnsRecordsLatestsByDomain", headers=headers, params={"domain": domain})


# ---------------------------
# Analysis helpers
# ---------------------------

def _collect_nameservers(whois_doc: Dict[str, Any]) -> List[str]:
    ns = []
    for i in range(1, 7):  # guard for future NS fields
        val = _pick(whois_doc, f"name_server_{i}")
        if isinstance(val, str) and val.strip():
            ns.append(val.strip().lower())
    return sorted(set(ns))


def _registrar(whois_doc: Dict[str, Any]) -> str:
    return (_pick(whois_doc, "domain_registrar_name") or "").strip()


def _creation_date(whois_doc: Dict[str, Any]) -> Optional[str]:
    # Your example shows YYYY-MM-DD; keep as string for portability.
    cd = _pick(whois_doc, "create_date")
    return cd.strip() if isinstance(cd, str) and cd.strip() else None


def _infer_vendor_from_tokens(value: str) -> Optional[str]:
    v = value.lower()
    for vendor, tokens in VENDOR_TOKENS.items():
        if any(tok in v for tok in tokens):
            return vendor
    return None


def infer_vendors_from_ns(ns_list: Iterable[str]) -> List[str]:
    vendors = {v for ns in ns_list if (v := _infer_vendor_from_tokens(ns))}
    return sorted(vendors)


def infer_vendors_from_dns(dns_records: Iterable[Dict[str, Any]]) -> List[str]:
    vendors = set()
    for rec in dns_records:
        t = (_pick(rec, "record_type") or "").upper()
        val = _pick(rec, "record_value") or ""
        if not val:
            continue
        # CNAME/NS often encode provider; A/AAAA may not be helpful without RIR/ASN resolution.
        if t in {"CNAME", "NS"}:
            if v := _infer_vendor_from_tokens(val):
                vendors.add(v)
    return sorted(vendors)


def diff_nameserver_sets(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identify nameserver changes across WHOIS history.
    Output is an ordered list of transitions with {from: [...], to: [...], at: query_time}.
    """
    events: List[Dict[str, Any]] = []
    prev: Optional[List[str]] = None
    for snap in sorted(history, key=lambda x: _pick(x, "query_time") or ""):
        current = _collect_nameservers(snap)
        if prev is not None and current != prev:
            events.append({
                "at": _pick(snap, "query_time"),
                "from": prev,
                "to": current,
            })
        prev = current
    return events


def registrar_changes(history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Track registrar changes over time.
    """
    events: List[Dict[str, Any]] = []
    prev: Optional[str] = None
    for snap in sorted(history, key=lambda x: _pick(x, "query_time") or ""):
        reg = _registrar(snap)
        if prev is not None and reg != prev:
            events.append({
                "at": _pick(snap, "query_time"),
                "from": prev,
                "to": reg,
            })
        prev = reg
    return events


def suspicious_asset_sprawl(
    registrar: str,
    ns_vendors: List[str],
    dns_vendors: List[str],
) -> Dict[str, Any]:
    """
    Simple heuristics to flag possible "sprawl":
      - Registrar not in preferred list (tunable policy)
      - Multiple vendors visible via NS/DNS pivots
    """
    vendor_set = sorted(set(ns_vendors) | set(dns_vendors))
    return {
        "non_preferred_registrar": (registrar not in PREFERRED_REGISTRARS) if registrar else None,
        "vendor_count": len(vendor_set),
        "vendors": vendor_set,
    }


# ---------------------------
# Orchestration
# ---------------------------

def analyze_domain(
    session: requests.Session,
    headers: Dict[str, str],
    domain: str,
) -> Dict[str, Any]:
    latest = get_whois_latest(session, headers, domain)
    history = get_whois_history(session, headers, domain)
    dns_latest = get_dns_latest(session, headers, domain)

    registrar = _registrar(latest)
    ns_list = _collect_nameservers(latest)
    ns_vendors = infer_vendors_from_ns(ns_list)
    dns_vendors = infer_vendors_from_dns(dns_latest)

    result = {
        "domain": domain,
        "whois_latest": {
            "registrar": registrar,
            "create_date": _creation_date(latest),
            "update_date": _pick(latest, "update_date"),
            "expiry_date": _pick(latest, "expiry_date"),
            "nameservers": ns_list,
        },
        "whois_history_stats": {
            "history_len": len(history),
            "registrar_changes": registrar_changes(history),
            "nameserver_changes": diff_nameserver_sets(history),
        },
        "vendor_inference": {
            "from_nameservers": ns_vendors,
            "from_dns_records": dns_vendors,
        },
        "sprawl_indicators": suspicious_asset_sprawl(registrar, ns_vendors, dns_vendors),
        "samples": {
            # Keep samples small for safe console rendering and GitHub Actions logs
            "dns_sample": dns_latest[:5],
            "whois_history_sample": history[:2],
        },
    }
    _info("domain-analyzed", domain=domain,
          registrar=registrar or "unknown",
          ns=len(ns_list), dns=len(dns_latest))
    return result


def run_threat_hunting(
    session: requests.Session,
    headers: Dict[str, str],
    company: str,
) -> Dict[str, Any]:
    """
    Main workflow:
    1) Seed with all company domains
    2) For each domain, pull WHOIS latest/history + DNS latest
    3) Compute registrar/NS changes & vendor hints for sprawl
    """
    result: Dict[str, Any] = {"company": company, "domains": []}

    domains = get_company_domains(session, headers, company)
    _info("mapped-company-domains", company=company, count=len(domains))
    result["domain_count"] = len(domains)
    result["domain_samples"] = domains[:5]

    for d in domains:
        result["domains"].append(analyze_domain(session, headers, d))

    # Org-wide quick look: aggregate vendors across domains
    vendors_org = sorted({
        v
        for entry in result["domains"]
        for v in (entry.get("vendor_inference", {}).get("from_nameservers", []) +
                  entry.get("vendor_inference", {}).get("from_dns_records", []))
        if v
    })
    result["org_vendor_summary"] = {
        "unique_vendor_count": len(vendors_org),
        "vendors": vendors_org,
    }
    return result


# ---------------------------
# CLI
# ---------------------------

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Threat hunting & CTI pivots using the Malanta API",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--company", required=True, help="Company name (e.g., 'Opswat')")
    p.add_argument(
        "--api-key",
        help="Malanta API key (or set MALANTA_API_KEY env var)",
        default=os.environ.get("MALANTA_API_KEY"),
    )
    p.add_argument("--out", help="Write JSON results to a file (otherwise prints to stdout)")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args(argv)


def build_session(api_key: str) -> requests.Session:
    if not api_key:
        raise SystemExit("Missing API key. Provide --api-key or set MALANTA_API_KEY.")
    s = requests.Session()
    s.headers.update({
        "x-api-key": api_key,
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    })
    return s


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    try:
        session = build_session(args.api_key)
        result = run_threat_hunting(session, session.headers, args.company)
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

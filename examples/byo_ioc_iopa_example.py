#!/usr/bin/env python3
"""
BYO IOC → Indicators-of-Pre-Attack (IoPA) with the Malanta API.

Workflow (high level):
1) Accept seed IOCs: domains and/or IPs (email optional as input seed).
2) Pivot via DNS:
   - For IPs: dnsRecordsPerIP → collect FQDNs/domains
   - For domains: dnsRecordsPerDomain → collect FQDNs/domains, A/AAAA IPs
3) For each discovered FQDN: getCertificatesByFqdn → extract certificate Subject CN (domain candidates)
4) Build unified unique sets: {domains, IPs}
5) Query clusters:
   - getClustersByIp for each IP
   - getClustersByDomain for each domain
6) Emit IoPA: unique domains, emails, and IPs derived from clusters.

Security & ops notes:
- Never log the API key. 
- Use timeouts + bounded retries.
- Use a descriptive User-Agent (helps backend triage).
- Output is structured JSON; safe to pipe into jq, SIEMs, and CI.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import requests

API_BASE = "https://api.malanta.ai"
USER_AGENT = "malanta-example/1.0 (+https://github.com/YOURORG/YOURREPO)"
DEFAULT_TIMEOUT = 60
MAX_RETRIES = 3
BACKOFF_BASE = 0.8  # seconds (exponential), with tiny jitter


# ---------------------------
# Utilities
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


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _sleep_with_backoff(attempt: int, *, base: float = BACKOFF_BASE) -> None:
    delay = (base * (2 ** (attempt - 1))) + (0.05 * (attempt % 3))  # small jitter
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
    GET {API_BASE}{path} with bounded retries and JSON normalization.
    Returns a list; wraps dict/singleton into a list.
    Retries on 429, 5xx, and network errors.
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
# Endpoint wrappers (robust to minor field variation)
# ---------------------------

def dns_records_per_ip(session: requests.Session, headers: Dict[str, str], ip: str) -> List[Dict[str, Any]]:
    """
    /dnsRecordsPerIP
    Intended to return DNS records related to an IP; commonly includes FQDN(s).
    """
    return _json_get(session, "/dnsRecordsPerIP", headers=headers, params={"ip": ip})


def dns_records_per_domain(session: requests.Session, headers: Dict[str, str], domain: str) -> List[Dict[str, Any]]:
    """
    /dnsRecordsPerDomain
    Expected fields (varies): fqdn, record_type, record_value, domain
    """
    return _json_get(session, "/dnsRecordsPerDomain", headers=headers, params={"domain": domain})


def get_certificates_by_fqdn(session: requests.Session, headers: Dict[str, str], fqdn: str) -> List[Dict[str, Any]]:
    """
    /getCertificatesByFqdn
    We will try multiple field names to extract certificate Subject Common Name.
    """
    return _json_get(session, "/getCertificatesByFqdn", headers=headers, params={"fqdn": fqdn})


def get_clusters_by_ip(session: requests.Session, headers: Dict[str, str], ip: str) -> List[Dict[str, Any]]:
    """
    /getClustersByIp
    Example item: {"cluster_id": "...", "domain_or_child": "malicious-url.com", "email": "...", "ip": "..."}
    """
    return _json_get(session, "/getClustersByIp", headers=headers, params={"ip": ip})


def get_clusters_by_domain(session: requests.Session, headers: Dict[str, str], domain: str) -> List[Dict[str, Any]]:
    """
    /getClustersByDomain
    Example item: similar to getClustersByIp
    """
    return _json_get(session, "/getClustersByDomain", headers=headers, params={"domain": domain})


# ---------------------------
# Pivot logic
# ---------------------------

def extract_domains_from_dns(records: Iterable[Dict[str, Any]]) -> Set[str]:
    """
    Collect candidate domains/FQDNs from DNS records.
    Considers 'fqdn', 'domain', and CNAME/NS record_value which often carries a domain-like value.
    """
    out: Set[str] = set()
    for r in records:
        fqdn = _pick(r, "fqdn", "FQDN", "host", "name")
        if isinstance(fqdn, str) and fqdn.strip():
            out.add(fqdn.strip().lower())

        dom = _pick(r, "domain", "Domain", "root_domain")
        if isinstance(dom, str) and dom.strip():
            out.add(dom.strip().lower())

        # record_value may be a domain-like value for CNAME/NS
        t = (_pick(r, "record_type") or "").upper()
        val = _pick(r, "record_value")
        if isinstance(val, str) and val and t in {"CNAME", "NS"}:
            out.add(val.strip().rstrip(".").lower())
    return out


def extract_ips_from_dns(records: Iterable[Dict[str, Any]]) -> Set[str]:
    """
    Collect IPs from A/AAAA records.
    """
    out: Set[str] = set()
    for r in records:
        t = (_pick(r, "record_type") or "").upper()
        val = _pick(r, "record_value")
        if isinstance(val, str) and val:
            if t in {"A", "AAAA"}:
                # Validate IP/IPv6 literal; skip CNAME-like values
                v = val.strip()
                if _is_ip(v):
                    out.add(v)
    return out


def extract_subject_cn(cert_doc: Dict[str, Any]) -> Optional[str]:
    """
    Pull a plausible Subject Common Name from certificate doc.
    We try multiple common field names to be robust:
    - "subject_cn", "subjectCN", "common_name", "cn", "initial_CN", "subject"
    If 'subject' looks like a DN string, try to isolate CN=... if present.
    """
    cn = _pick(cert_doc, "subject_cn", "subjectCN", "subject_common_name", "cn", "initial_CN")
    if isinstance(cn, str) and cn.strip():
        return cn.strip().lower()

    subject = _pick(cert_doc, "subject")
    if isinstance(subject, str) and subject:
        # naive CN=... extractor
        parts = [p.strip() for p in subject.split(",")]
        for p in parts:
            if p.lower().startswith("cn=") and len(p) > 3:
                return p[3:].strip().lower()
    return None


def expand_iocs(
    session: requests.Session,
    headers: Dict[str, str],
    seed_domains: Iterable[str],
    seed_ips: Iterable[str],
    *,
    max_fqdn_per_domain: int = 50,
) -> Tuple[Set[str], Set[str]]:
    """
    From input seeds, expand into unified sets {domains, ips}
    using dnsRecordsPerIP, dnsRecordsPerDomain, and getCertificatesByFqdn (Subject CN).
    """
    domains: Set[str] = set()
    ips: Set[str] = set()

    # Normalize seeds
    for d in seed_domains:
        if isinstance(d, str) and d.strip():
            domains.add(d.strip().lower())
    for ip in seed_ips:
        if isinstance(ip, str) and ip.strip() and _is_ip(ip.strip()):
            ips.add(ip.strip())

    # 1) For IPs → DNS (FQDNs/domains), then cert CN
    for ip in list(ips):
        dns = dns_records_per_ip(session, headers, ip)
        new_domains = extract_domains_from_dns(dns)
        domains.update(new_domains)

        # For each FQDN/domain from IP pivot, fetch certificates → Subject CN
        # Choose a bounded sample per domain to avoid hammering the API:
        for fqdn in list(new_domains)[:max_fqdn_per_domain]:
            certs = get_certificates_by_fqdn(session, headers, fqdn)
            for c in certs:
                cn = extract_subject_cn(c)
                if cn:
                    domains.add(cn)

    # 2) For Domains → DNS (FQDNs/domains, A/AAAA IPs), then cert CN
    for d in list(domains):
        dns = dns_records_per_domain(session, headers, d)
        # Add domains/FQDNs we see in DNS
        discovered = extract_domains_from_dns(dns)
        domains.update(discovered)
        # Add IPs we see (A/AAAA)
        ips.update(extract_ips_from_dns(dns))

        # Certificates by FQDN to extract Subject CNs
        for fqdn in list(discovered)[:max_fqdn_per_domain]:
            certs = get_certificates_by_fqdn(session, headers, fqdn)
            for c in certs:
                cn = extract_subject_cn(c)
                if cn:
                    domains.add(cn)

    return domains, ips


# ---------------------------
# Cluster queries → IoPA extraction
# ---------------------------

def clusters_for_sets(
    session: requests.Session,
    headers: Dict[str, str],
    domains: Iterable[str],
    ips: Iterable[str],
) -> Dict[str, Any]:
    """
    Query clusters by domain and IP; deduplicate IoPA fields (domains, emails, IPs).
    """
    iopa_domains: Set[str] = set()
    iopa_emails: Set[str] = set()
    iopa_ips: Set[str] = set()
    cluster_rows: List[Dict[str, Any]] = []

    # By domain
    for d in sorted(set(domains)):
        rows = get_clusters_by_domain(session, headers, d)
        for r in rows:
            dom = _pick(r, "domain_or_child", "domain", "fqdn")
            if isinstance(dom, str) and dom.strip():
                iopa_domains.add(dom.strip().lower())
            em = _pick(r, "email")
            if isinstance(em, str) and em.strip():
                iopa_emails.add(em.strip().lower())
            ip = _pick(r, "ip")
            if isinstance(ip, str) and _is_ip(ip.strip()):
                iopa_ips.add(ip.strip())
        cluster_rows.extend(rows)

    # By IP
    for ip in sorted({x for x in ips if _is_ip(x)}):
        rows = get_clusters_by_ip(session, headers, ip)
        for r in rows:
            dom = _pick(r, "domain_or_child", "domain", "fqdn")
            if isinstance(dom, str) and dom.strip():
                iopa_domains.add(dom.strip().lower())
            em = _pick(r, "email")
            if isinstance(em, str) and em.strip():
                iopa_emails.add(em.strip().lower())
            ip2 = _pick(r, "ip")
            if isinstance(ip2, str) and _is_ip(ip2.strip()):
                iopa_ips.add(ip2.strip())
        cluster_rows.extend(rows)

    return {
        "iopa_domains": sorted(iopa_domains),
        "iopa_emails": sorted(iopa_emails),
        "iopa_ips": sorted(iopa_ips),
        "cluster_samples": cluster_rows[:10],  # keep output compact for terminals/CI
    }


# ---------------------------
# Orchestration
# ---------------------------

def run_byo_ioc(
    session: requests.Session,
    headers: Dict[str, str],
    seed_domains: List[str],
    seed_ips: List[str],
    seed_emails: List[str],
) -> Dict[str, Any]:
    """
    Main pipeline:
      - Expand IOCs via DNS + Cert Subject CN
      - Query clusters with unified sets
      - Output IoPA lists (domains, emails, IPs) + samples
    """
    _info("seeds", domains=len(seed_domains), ips=len(seed_ips), emails=len(seed_emails))

    expanded_domains, expanded_ips = expand_iocs(session, headers, seed_domains, seed_ips)
    _info("expanded", domains=len(expanded_domains), ips=len(expanded_ips))

    cluster_out = clusters_for_sets(session, headers, expanded_domains, expanded_ips)

    result = {
        "seeds": {
            "domains": sorted({d.lower() for d in seed_domains if isinstance(d, str)}),
            "ips": sorted({ip for ip in seed_ips if isinstance(ip, str)}),
            "emails": sorted({e.lower() for e in seed_emails if isinstance(e, str)}),
        },
        "expanded": {
            "domains": sorted(expanded_domains),
            "ips": sorted(expanded_ips),
        },
        "iopa": {
            "domains": cluster_out["iopa_domains"],
            "emails": sorted(set(cluster_out["iopa_emails"]) | set(seed_emails)),  # include seed emails
            "ips": cluster_out["iopa_ips"],
        },
        "cluster_samples": cluster_out["cluster_samples"],
    }
    return result


# ---------------------------
# CLI
# ---------------------------

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="BYO IOC → Indicators-of-Pre-Attack (IoPA) using the Malanta API",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--api-key",
        help="Malanta API key (or set MALANTA_API_KEY env var)",
        default=os.environ.get("MALANTA_API_KEY"),
    )
    p.add_argument("--out", help="Write JSON results to a file")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    # IOC inputs (repeatable)
    p.add_argument("--domain", action="append", default=[], help="Seed domain IOC (repeatable)")
    p.add_argument("--ip", action="append", default=[], help="Seed IP IOC (repeatable)")
    p.add_argument("--email", action="append", default=[], help="Seed email IOC (repeatable)")
    args = p.parse_args(argv)

    if not (args.domain or args.ip or args.email):
        p.error("Provide at least one IOC: --domain, --ip, or --email")
    return args


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
        result = run_byo_ioc(session, session.headers, args.domain, args.ip, args.email)
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

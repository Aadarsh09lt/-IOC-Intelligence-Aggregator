#!/usr/bin/env python3
"""
IOC Intelligence Aggregator
A lightweight enrichment utility for domains, IPs, URLs, and file hashes.
"""

import argparse
import ipaddress
import os
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import dns.reversename
import requests
import whois
from ipwhois import IPWhois

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",       # Freenom free TLDs
    ".xyz", ".top", ".club", ".online",       # commonly abused generics
    ".click", ".link", ".download", ".stream",
    ".zip", ".mov",                           # Google TLDs misused in phishing
    ".ru", ".cn", ".pw", ".su",               # historically abused ccTLDs
    ".work", ".buzz", ".life", ".site",
}

VPN_ASN_KEYWORDS = {"nordvpn", "expressvpn", "protonvpn", "mullvad", "pia ",
                    "private internet access", "ipvanish", "surfshark",
                    "cyberghost", "hidemyass", "vyprvpn", "windscribe",
                    "tunnelbear", "purevpn", "hotspotshield"}

HOSTING_ASN_KEYWORDS = {"digitalocean", "linode", "vultr", "amazon",
                         "google", "microsoft", "hetzner", "ovh", "leaseweb",
                         "choopa", "as-choopa", "cloudflare", "fastly",
                         "akamai", "rackspace", "softlayer", "namecheap",
                         "godaddy", "hostgator", "bluehost", "siteground"}

PROXY_ASN_KEYWORDS = {"zscaler", "netskope", "palo alto", "symantec",
                       "forcepoint", "barracuda", "squid", "luminati",
                       "bright data", "smartproxy", "oxylabs"}

# TOR exit node list (public DNSBL)
TOR_DNSBL = "dan.me.uk"

# ---------------------------------------------------------------------------
# API key loading
# ---------------------------------------------------------------------------

def _env(key: str) -> str:
    return os.environ.get(key, "").strip()


VT_KEY   = _env("VT_API_KEY")
ABUSEIPDB_KEY = _env("ABUSEIPDB_API_KEY")
OTX_KEY  = _env("OTX_API_KEY")


# ---------------------------------------------------------------------------
# IOC type detection
# ---------------------------------------------------------------------------

def detect_ioc_type(value: str) -> str:
    value = value.strip()
    # URL
    if value.startswith(("http://", "https://", "ftp://")):
        return "url"
    # IPv4
    try:
        ipaddress.IPv4Address(value)
        return "ip"
    except ValueError:
        pass
    # IPv6
    try:
        ipaddress.IPv6Address(value)
        return "ip"
    except ValueError:
        pass
    # Hash (MD5/SHA1/SHA256)
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return "hash_md5"
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return "hash_sha1"
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return "hash_sha256"
    # Domain (basic check)
    if re.fullmatch(r"[A-Za-z0-9._-]+\.[A-Za-z]{2,}", value):
        return "domain"
    return "unknown"


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

class Output:
    """Accumulates lines for both terminal display and file save."""

    def __init__(self):
        self._lines = []

    def section(self, title: str):
        self._lines.append("")
        self._lines.append(title)
        self._lines.append("-" * len(title))

    def kv(self, key: str, value):
        line = f"  {key}: {value}"
        self._lines.append(line)

    def item(self, text: str):
        self._lines.append(f"  {text}")

    def note(self, text: str):
        self._lines.append(f"  [note] {text}")

    def warn(self, text: str):
        self._lines.append(f"  [!] {text}")

    def error(self, text: str):
        self._lines.append(f"  [error] {text}")

    def raw(self, text: str):
        self._lines.append(text)

    def render(self) -> str:
        return "\n".join(self._lines)

    def print(self):
        print(self.render())

    def save(self, filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.render())
            f.write("\n")


# ---------------------------------------------------------------------------
# DNS enrichment
# ---------------------------------------------------------------------------

def dns_lookup(target: str, out: Output):
    out.section("DNS Records")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    found_any = False
    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype)
            for rdata in answers:
                val = str(rdata).strip().strip('"')
                out.kv(rtype, val)
                found_any = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            pass
        except Exception as e:
            out.error(f"{rtype} lookup failed: {e}")
    if not found_any:
        out.item("No DNS records resolved.")


def reverse_dns(ip: str, out: Output):
    out.section("Reverse DNS")
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(rev_name, "PTR")
        for rdata in answers:
            out.kv("PTR", str(rdata))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        out.item("No PTR record found.")
    except Exception as e:
        out.error(f"PTR lookup failed: {e}")


# ---------------------------------------------------------------------------
# WHOIS / Domain enrichment
# ---------------------------------------------------------------------------

def domain_whois(target: str, out: Output):
    out.section("Domain Information")
    try:
        w = whois.whois(target)
        registrar = w.registrar or "N/A"
        out.kv("Registrar", registrar)

        def _fmt_date(d):
            if isinstance(d, list):
                d = d[0]
            if isinstance(d, datetime):
                return d.strftime("%Y-%m-%d")
            return str(d) if d else "N/A"

        created   = _fmt_date(w.creation_date)
        expires   = _fmt_date(w.expiration_date)
        updated   = _fmt_date(w.updated_date)

        out.kv("Created",  created)
        out.kv("Updated",  updated)
        out.kv("Expires",  expires)

        status = w.status
        if isinstance(status, list):
            for s in status:
                out.kv("Status", str(s).split(" ")[0])
        elif status:
            out.kv("Status", str(status).split(" ")[0])

        ns = w.name_servers
        if ns:
            if isinstance(ns, list):
                for n in ns:
                    out.kv("Nameserver", str(n).lower())
            else:
                out.kv("Nameserver", str(ns).lower())

        # Domain age
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation).days
            years  = age_days // 365
            months = (age_days % 365) // 30
            out.kv("Domain Age", f"{years} year(s), {months} month(s)")

    except Exception as e:
        out.error(f"WHOIS lookup failed: {e}")


# ---------------------------------------------------------------------------
# SSL certificate
# ---------------------------------------------------------------------------

def ssl_info(hostname: str, out: Output, port: int = 443):
    out.section("SSL Certificate")
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=10),
            server_hostname=hostname
        )
        cert = conn.getpeercert()
        conn.close()

        subject_dict = dict(x[0] for x in cert.get("subject", []))
        issuer_dict  = dict(x[0] for x in cert.get("issuer",  []))

        out.kv("Subject CN", subject_dict.get("commonName", "N/A"))
        out.kv("Issuer CN",  issuer_dict.get("commonName",  "N/A"))
        out.kv("Issuer Org", issuer_dict.get("organizationName", "N/A"))

        not_before = cert.get("notBefore", "N/A")
        not_after  = cert.get("notAfter",  "N/A")
        out.kv("Valid From",  not_before)
        out.kv("Valid Until", not_after)

        # Check expiry
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            exp = exp.replace(tzinfo=timezone.utc)
            if exp < datetime.now(timezone.utc):
                out.warn("Certificate is EXPIRED.")
        except Exception:
            pass

        # Self-signed check
        if subject_dict.get("commonName") == issuer_dict.get("commonName"):
            out.warn("Certificate appears self-signed (subject == issuer).")

        # SAN entries
        sans = cert.get("subjectAltName", [])
        for san_type, san_val in sans:
            out.kv(f"SAN ({san_type})", san_val)

    except ssl.SSLCertVerificationError as e:
        out.warn(f"SSL verification error: {e}")
    except ConnectionRefusedError:
        out.item("Port 443 not reachable.")
    except socket.timeout:
        out.item("SSL connection timed out.")
    except Exception as e:
        out.error(f"SSL retrieval failed: {e}")


# ---------------------------------------------------------------------------
# ASN / IP geolocation
# ---------------------------------------------------------------------------

def asn_geo_info(ip: str, out: Output):
    out.section("ASN & Geolocation")
    asn_desc = ""

    # Primary: RDAP via ipwhois
    rdap_ok = False
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        asn      = result.get("asn", "N/A")
        asn_desc = result.get("asn_description", "N/A")
        cidr     = result.get("asn_cidr", "N/A")
        country  = result.get("asn_country_code", "N/A")
        out.kv("ASN",          f"AS{asn}")
        out.kv("Organization", asn_desc)
        out.kv("Network",      cidr)
        out.kv("Country",      country)
        rdap_ok = True
    except Exception:
        pass

    # Geolocation + ASN fallback via ip-api.com
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=8,
            params={"fields": "status,country,regionName,city,isp,org,as,query"}
        )
        if r.status_code == 200:
            geo = r.json()
            if geo.get("status") == "success":
                if not rdap_ok:
                    asn_raw  = geo.get("as", "")       # e.g. "AS15169 Google LLC"
                    asn_org  = geo.get("org", "")
                    isp      = geo.get("isp", "")
                    asn_desc = asn_org or isp
                    if asn_raw:
                        parts = asn_raw.split(" ", 1)
                        out.kv("ASN", parts[0])
                        if len(parts) > 1:
                            out.kv("Organization", parts[1])
                            asn_desc = parts[1]
                    elif asn_org:
                        out.kv("Organization", asn_org)
                    if isp and isp != asn_org:
                        out.kv("ISP", isp)
                city    = geo.get("city")
                region  = geo.get("regionName")
                country = geo.get("country")
                if city:
                    out.kv("City",    city)
                if region:
                    out.kv("Region",  region)
                if country:
                    out.kv("Country", country)
    except Exception:
        pass

    if not asn_desc:
        out.item("ASN data unavailable.")

    return asn_desc


# ---------------------------------------------------------------------------
# Infrastructure classification
# ---------------------------------------------------------------------------

def _is_tor_exit(ip: str) -> bool:
    """Check if IP is a known TOR exit node via DNSBL."""
    try:
        rev_ip = ".".join(reversed(ip.split(".")))
        query  = f"{rev_ip}.{TOR_DNSBL}"
        dns.resolver.resolve(query, "A")
        return True
    except Exception:
        return False


def classify_infrastructure(ip: str, asn_desc: str, out: Output):
    out.section("Infrastructure Classification")
    desc_lower = asn_desc.lower() if asn_desc else ""
    classified = False

    # TOR check (only for IPv4)
    try:
        ipaddress.IPv4Address(ip)
        if _is_tor_exit(ip):
            out.item("TOR Exit Node")
            classified = True
    except ValueError:
        pass

    # VPN
    for kw in VPN_ASN_KEYWORDS:
        if kw in desc_lower:
            provider = asn_desc
            out.item(f"VPN Provider  Provider: {provider}")
            classified = True
            break

    # Proxy
    if not classified:
        for kw in PROXY_ASN_KEYWORDS:
            if kw in desc_lower:
                out.item(f"Proxy Service  Provider: {asn_desc}")
                classified = True
                break

    # Hosting
    if not classified:
        for kw in HOSTING_ASN_KEYWORDS:
            if kw in desc_lower:
                out.item(f"Hosting Provider  Provider: {asn_desc}")
                classified = True
                break

    if not classified:
        out.item(f"Residential / Unknown ISP  Provider: {asn_desc or 'N/A'}")


# ---------------------------------------------------------------------------
# Suspicious TLD
# ---------------------------------------------------------------------------

def check_suspicious_tld(domain: str, out: Output):
    tld = "." + domain.rsplit(".", 1)[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        out.section("TLD Observation")
        out.note(
            f"Domain uses TLD '{tld}', which is commonly observed in "
            "malicious campaigns. This is informational only."
        )


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

VT_BASE = "https://www.virustotal.com/api/v3"

def _vt_headers():
    return {"x-apikey": VT_KEY, "Accept": "application/json"}


def vt_domain(domain: str, out: Output):
    if not VT_KEY:
        out.item("VirusTotal API key not set (VT_API_KEY).")
        return
    try:
        r = requests.get(f"{VT_BASE}/domains/{domain}",
                         headers=_vt_headers(), timeout=15)
        _vt_parse(r, out)
    except Exception as e:
        out.error(f"VirusTotal request failed: {e}")


def vt_ip(ip: str, out: Output):
    if not VT_KEY:
        out.item("VirusTotal API key not set (VT_API_KEY).")
        return
    try:
        r = requests.get(f"{VT_BASE}/ip_addresses/{ip}",
                         headers=_vt_headers(), timeout=15)
        _vt_parse(r, out)
    except Exception as e:
        out.error(f"VirusTotal request failed: {e}")


def vt_url(url: str, out: Output):
    if not VT_KEY:
        out.item("VirusTotal API key not set (VT_API_KEY).")
        return
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = requests.get(f"{VT_BASE}/urls/{url_id}",
                         headers=_vt_headers(), timeout=15)
        _vt_parse(r, out)
    except Exception as e:
        out.error(f"VirusTotal request failed: {e}")


def vt_hash(file_hash: str, out: Output):
    if not VT_KEY:
        out.item("VirusTotal API key not set (VT_API_KEY).")
        return
    try:
        r = requests.get(f"{VT_BASE}/files/{file_hash}",
                         headers=_vt_headers(), timeout=15)
        _vt_parse(r, out)
    except Exception as e:
        out.error(f"VirusTotal request failed: {e}")


def _vt_parse(r: requests.Response, out: Output):
    if r.status_code == 404:
        out.item("No record found on VirusTotal.")
        return
    if r.status_code == 401:
        out.error("VirusTotal: invalid or missing API key.")
        return
    if r.status_code != 200:
        out.error(f"VirusTotal returned HTTP {r.status_code}.")
        return
    data = r.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values()) if stats else 0
    out.kv("Detections", f"{malicious} malicious, {suspicious} suspicious / {total} engines")

    reputation = data.get("reputation")
    if reputation is not None:
        out.kv("Reputation Score", reputation)

    categories = data.get("categories", {})
    if categories:
        unique_cats = sorted(set(categories.values()))
        out.kv("Categories", ", ".join(unique_cats))


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

def abuseipdb_check(ip: str, out: Output):
    if not ABUSEIPDB_KEY:
        out.item("AbuseIPDB API key not set (ABUSEIPDB_API_KEY).")
        return
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=15
        )
        if r.status_code == 401:
            out.error("AbuseIPDB: invalid or missing API key.")
            return
        if r.status_code != 200:
            out.error(f"AbuseIPDB returned HTTP {r.status_code}.")
            return
        data = r.json().get("data", {})
        out.kv("Abuse Confidence", f"{data.get('abuseConfidenceScore', 0)}%")
        out.kv("Total Reports",    data.get("totalReports", 0))
        out.kv("Last Reported",    data.get("lastReportedAt", "N/A"))
        out.kv("ISP",              data.get("isp", "N/A"))
        out.kv("Usage Type",       data.get("usageType", "N/A"))
        categories = data.get("reports", [])
        all_cats = set()
        for report in categories[:20]:
            for c in report.get("categories", []):
                all_cats.add(str(c))
        if all_cats:
            out.kv("Reported Categories", ", ".join(sorted(all_cats)))
    except Exception as e:
        out.error(f"AbuseIPDB request failed: {e}")


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

OTX_BASE = "https://otx.alienvault.com/api/v1"

def otx_domain(domain: str, out: Output):
    _otx_query(f"{OTX_BASE}/indicators/domain/{domain}/general", out)


def otx_ip(ip: str, out: Output):
    _otx_query(f"{OTX_BASE}/indicators/IPv4/{ip}/general", out)


def otx_url(url: str, out: Output):
    import urllib.parse
    encoded = urllib.parse.quote(url, safe="")
    _otx_query(f"{OTX_BASE}/indicators/url/{encoded}/general", out)


def otx_hash(file_hash: str, out: Output):
    _otx_query(f"{OTX_BASE}/indicators/file/{file_hash}/general", out)


def _otx_query(url: str, out: Output):
    headers = {}
    if OTX_KEY:
        headers["X-OTX-API-KEY"] = OTX_KEY
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code == 404:
            out.item("No OTX record found.")
            return
        if r.status_code != 200:
            out.error(f"OTX returned HTTP {r.status_code}.")
            return
        data = r.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        out.kv("Associated Pulses", pulse_count)

        pulses = data.get("pulse_info", {}).get("pulses", [])
        if pulses:
            for p in pulses[:5]:
                name     = p.get("name", "N/A")
                modified = p.get("modified", "N/A")[:10]
                out.item(f"  Pulse: {name}  ({modified})")
            if len(pulses) > 5:
                out.item(f"  ... and {len(pulses) - 5} more pulse(s).")

        tags = data.get("tags", [])
        if tags:
            out.kv("Tags", ", ".join(tags[:10]))

    except Exception as e:
        out.error(f"OTX request failed: {e}")


# ---------------------------------------------------------------------------
# High-level scan functions
# ---------------------------------------------------------------------------

def scan_domain(target: str, out: Output):
    out.raw(f"IOC: {target}")
    out.raw(f"Type: Domain")
    out.raw(f"Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    domain_whois(target, out)
    check_suspicious_tld(target, out)
    dns_lookup(target, out)
    ssl_info(target, out)

    # Resolve to IP for further enrichment
    try:
        answers = dns.resolver.resolve(target, "A")
        ips = [str(r) for r in answers]
    except Exception:
        ips = []

    if ips:
        ip = ips[0]
        asn_desc = asn_geo_info(ip, out)
        classify_infrastructure(ip, asn_desc, out)
        reverse_dns(ip, out)

        if VT_KEY or True:  # always show section header
            out.section("VirusTotal")
            vt_domain(target, out)

        if ABUSEIPDB_KEY:
            out.section("AbuseIPDB")
            abuseipdb_check(ip, out)

        out.section("AlienVault OTX")
        otx_domain(target, out)
    else:
        out.section("VirusTotal")
        vt_domain(target, out)
        out.section("AlienVault OTX")
        otx_domain(target, out)


def scan_ip(target: str, out: Output):
    out.raw(f"IOC: {target}")
    out.raw(f"Type: IP Address")
    out.raw(f"Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    reverse_dns(target, out)
    asn_desc = asn_geo_info(target, out)
    classify_infrastructure(target, asn_desc, out)

    out.section("VirusTotal")
    vt_ip(target, out)

    out.section("AbuseIPDB")
    abuseipdb_check(target, out)

    out.section("AlienVault OTX")
    otx_ip(target, out)


def scan_url(target: str, out: Output):
    out.raw(f"IOC: {target}")
    out.raw(f"Type: URL")
    out.raw(f"Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    parsed = urlparse(target)
    hostname = parsed.hostname or ""

    if hostname:
        # Determine if hostname is IP or domain
        is_ip = False
        try:
            ipaddress.ip_address(hostname)
            is_ip = True
        except ValueError:
            pass

        if is_ip:
            reverse_dns(hostname, out)
            asn_desc = asn_geo_info(hostname, out)
            classify_infrastructure(hostname, asn_desc, out)
        else:
            domain_whois(hostname, out)
            check_suspicious_tld(hostname, out)
            dns_lookup(hostname, out)
            ssl_info(hostname, out, port=parsed.port or 443)
            try:
                answers = dns.resolver.resolve(hostname, "A")
                ip = str(next(iter(answers)))
                asn_desc = asn_geo_info(ip, out)
                classify_infrastructure(ip, asn_desc, out)
            except Exception:
                pass

    out.section("VirusTotal")
    vt_url(target, out)

    out.section("AlienVault OTX")
    otx_url(target, out)


def scan_hash(target: str, ioc_type: str, out: Output):
    hash_type = {"hash_md5": "MD5", "hash_sha1": "SHA1",
                 "hash_sha256": "SHA256"}.get(ioc_type, "Hash")
    out.raw(f"IOC: {target}")
    out.raw(f"Type: File Hash ({hash_type})")
    out.raw(f"Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    out.section("VirusTotal")
    vt_hash(target, out)

    out.section("AlienVault OTX")
    otx_hash(target, out)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="ioc",
        description="IOC Intelligence Aggregator - enrichment utility for domains, IPs, URLs, and file hashes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables for API keys:
  VT_API_KEY          VirusTotal API key
  ABUSEIPDB_API_KEY   AbuseIPDB API key
  OTX_API_KEY         AlienVault OTX API key (optional, raises rate limit)

Examples:
  python ioc.py example.com
  python ioc.py 8.8.8.8
  python ioc.py https://malicious.example.com/payload
  python ioc.py d41d8cd98f00b204e9800998ecf8427e
        """
    )
    parser.add_argument("ioc", help="IOC value to investigate")
    parser.add_argument(
        "--type", choices=["domain", "ip", "url", "hash"],
        help="Override automatic IOC type detection"
    )
    parser.add_argument(
        "--no-save", action="store_true",
        help="Do not save a report to disk"
    )
    args = parser.parse_args()

    target   = args.ioc.strip()
    ioc_type = args.type or detect_ioc_type(target)

    if ioc_type == "unknown":
        print(f"Unable to determine IOC type for: {target}", file=sys.stderr)
        print("Use --type to specify: domain, ip, url, or hash", file=sys.stderr)
        sys.exit(1)

    out = Output()

    if ioc_type == "domain":
        scan_domain(target, out)
    elif ioc_type == "ip":
        scan_ip(target, out)
    elif ioc_type == "url":
        scan_url(target, out)
    elif ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        scan_hash(target, ioc_type, out)
    elif ioc_type == "hash":
        # manual override - treat as generic hash
        out.raw(f"IOC: {target}")
        out.raw(f"Type: File Hash")
        out.raw(f"Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        out.section("VirusTotal")
        vt_hash(target, out)
        out.section("AlienVault OTX")
        otx_hash(target, out)

    out.print()

    if not args.no_save:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = os.path.join(REPORTS_DIR, f"{timestamp}.txt")
        out.save(report_path)
        print(f"\nReport saved: {report_path}")


if __name__ == "__main__":
    main()

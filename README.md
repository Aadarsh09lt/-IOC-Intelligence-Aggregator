# -IOC-Intelligence-Aggregator
IOC Intelligence Aggregator
===========================

A lightweight command-line tool for enriching indicators of compromise (IOCs)
during security investigations.

Supported IOC types
-------------------
  - Domain
  - IP Address
  - URL
  - File Hash (MD5, SHA1, SHA256)

Installation
------------

1. Install Python dependencies:

     pip install -r requirements.txt

2. Set API keys as environment variables (optional but recommended):

     export VT_API_KEY="your_virustotal_key"
     export ABUSEIPDB_API_KEY="your_abuseipdb_key"
     export OTX_API_KEY="your_otx_key"          # optional

   Without API keys, the tool still performs WHOIS, DNS, SSL, ASN,
   geolocation, and infrastructure classification lookups.

   Free API keys:
     VirusTotal   https://www.virustotal.com/gui/join-us
     AbuseIPDB    https://www.abuseipdb.com/register
     OTX          https://otx.alienvault.com/accounts/signup

Usage
-----

  python ioc.py <ioc_value> [--type TYPE] [--no-save]

Arguments:
  ioc           IOC value to investigate
  --type        Override auto-detection: domain, ip, url, hash
  --no-save     Do not write a report to disk

Examples
--------

  python ioc.py example.com
  python ioc.py 192.168.1.1
  python ioc.py https://malicious.example.com/payload
  python ioc.py d41d8cd98f00b204e9800998ecf8427e

Data sources
------------

  Passive / no key required:
    - python-whois      Domain registration data
    - dnspython         DNS resolution (A, AAAA, MX, NS, TXT, CNAME, PTR)
    - ipwhois (RDAP)    ASN number, organization, network range
    - ip-api.com        IP geolocation (city, region, country)
    - ssl (stdlib)      Certificate issuer, validity, SANs
    - dan.me.uk DNSBL   TOR exit node detection

  Requires API key:
    - VirusTotal        Malware detection counts across 96+ engines
    - AbuseIPDB         Abuse reports, confidence score, categories
    - AlienVault OTX    Threat intelligence pulses and tags

Reports
-------

Each scan is automatically saved as a plain text file:

  reports/YYYYMMDD_HHMMSS.txt

Pass --no-save to skip saving.

Notes
-----

  - No risk scoring or confidence scores are assigned.
  - TLD observations are informational only and do not imply malicious intent.
  - Infrastructure classification is best-effort based on ASN metadata.
  - ip-api.com imposes a rate limit of 45 requests/minute on the free tier.

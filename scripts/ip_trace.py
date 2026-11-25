#!/usr/bin/env python3
"""
ip_trace.py
------------
Operation Hydra - IP provenance & reputation helper.

Given a suspicious IP (e.g., extracted from email headers or malware
C2 traffic), this script:
  1. Resolves basic geolocation/ASN info via a free IP-info API.
  2. Prints a template AbuseIPDB query URL (API key required - not
     included here for security; the analyst supplies their own key
     as an environment variable if they want live reputation scores).

This is a read-only reconnaissance/analysis utility, not an
exploitation or attack tool.

Usage:
    python3 ip_trace.py 185.220.101.47
"""

import argparse
import json
import os
import urllib.request


def geolocate(ip):
    url = f"https://ipinfo.io/{ip}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return json.load(resp)
    except Exception as exc:
        return {"error": str(exc)}


def abuseipdb_hint(ip):
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return (
            "No ABUSEIPDB_API_KEY set. To pull a live reputation score, set the "
            "environment variable and query:\n"
            f"  https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90\n"
            "  Header: Key: <your_api_key>"
        )
    req = urllib.request.Request(
        f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
        headers={"Key": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.load(resp)
    except Exception as exc:
        return {"error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description="Geolocate and check reputation of an IP.")
    parser.add_argument("ip")
    args = parser.parse_args()

    print(f"== Geolocation for {args.ip} ==")
    print(json.dumps(geolocate(args.ip), indent=2))

    print(f"\n== AbuseIPDB ==")
    result = abuseipdb_hint(args.ip)
    print(result if isinstance(result, str) else json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

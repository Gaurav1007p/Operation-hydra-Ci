#!/usr/bin/env python3
"""
whois_lookup.py
----------------
Operation Hydra - domain provenance checker.

Wraps the system `whois` command to pull registrar, creation date,
and name-server info for a suspected spoofed/typosquat domain, and
flags domains registered very recently (a common phishing-infra tell).

Usage:
    python3 whois_lookup.py suspicious-domain.com

Requires the `whois` CLI to be installed (e.g. `apt install whois`).
"""

import argparse
import re
import subprocess
import sys
from datetime import datetime, timezone


def run_whois(domain):
    try:
        result = subprocess.run(
            ["whois", domain], capture_output=True, text=True, timeout=15
        )
        return result.stdout
    except FileNotFoundError:
        print("The 'whois' CLI is not installed. Try: apt install whois")
        sys.exit(1)
    except Exception as exc:
        print(f"WHOIS lookup failed: {exc}")
        sys.exit(1)


def extract_field(raw, patterns):
    for pattern in patterns:
        match = re.search(pattern, raw, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def flag_recent_registration(creation_date_str):
    if not creation_date_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"):
        try:
            created = datetime.strptime(creation_date_str[:19], fmt).replace(
                tzinfo=timezone.utc
            )
            age_days = (datetime.now(timezone.utc) - created).days
            if age_days < 30:
                return f"FLAG: domain is only {age_days} day(s) old - common phishing-infra pattern"
            return f"Domain age: {age_days} day(s)"
        except ValueError:
            continue
    return None


def main():
    parser = argparse.ArgumentParser(description="WHOIS lookup + recent-registration flag.")
    parser.add_argument("domain")
    args = parser.parse_args()

    raw = run_whois(args.domain)
    registrar = extract_field(raw, [r"Registrar:\s*(.+)"])
    created = extract_field(
        raw, [r"Creation Date:\s*(.+)", r"created:\s*(.+)", r"Registered on:\s*(.+)"]
    )
    ns = re.findall(r"Name Server:\s*(.+)", raw, re.IGNORECASE)

    print(f"Domain:    {args.domain}")
    print(f"Registrar: {registrar or 'not found'}")
    print(f"Created:   {created or 'not found'}")
    print(f"Nameservers: {', '.join(ns) if ns else 'not found'}")

    flag = flag_recent_registration(created)
    if flag:
        print(f"\n{flag}")


if __name__ == "__main__":
    main()

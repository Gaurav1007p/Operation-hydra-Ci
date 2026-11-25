#!/usr/bin/env python3
"""
spf_dkim_dmarc_checker.py
--------------------------
Operation Hydra - Phishing & Spoofing Investigation toolkit.

Looks up SPF, DKIM, and DMARC DNS TXT records for a given domain to
help an analyst quickly spot email-spoofing weaknesses (missing or
misconfigured records), similar to what MXToolbox reports in its UI.

This is a defensive/analysis utility only - it performs read-only DNS
TXT lookups and does not send email or interact with any mail server.

Usage:
    python3 spf_dkim_dmarc_checker.py example.com
    python3 spf_dkim_dmarc_checker.py example.com --selector default

Requires: dnspython  (pip install dnspython --break-system-packages)
"""

import argparse
import sys

try:
    import dns.resolver
except ImportError:
    print("This script requires dnspython: pip install dnspython --break-system-packages")
    sys.exit(1)


def query_txt(name):
    try:
        answers = dns.resolver.resolve(name, "TXT")
        return [b"".join(r.strings).decode(errors="replace") for r in answers]
    except Exception as exc:
        return [f"<lookup failed: {exc}>"]


def check_spf(domain):
    records = query_txt(domain)
    spf = [r for r in records if r.lower().startswith("v=spf1")]
    return spf or ["<no SPF record found>"]


def check_dmarc(domain):
    return query_txt(f"_dmarc.{domain}")


def check_dkim(domain, selector):
    return query_txt(f"{selector}._domainkey.{domain}")


def main():
    parser = argparse.ArgumentParser(description="Check SPF/DKIM/DMARC for a domain.")
    parser.add_argument("domain", help="Domain to check, e.g. example.com")
    parser.add_argument("--selector", default="default",
                         help="DKIM selector to check (default: 'default')")
    args = parser.parse_args()

    print(f"\n== SPF for {args.domain} ==")
    for r in check_spf(args.domain):
        print(" ", r)

    print(f"\n== DMARC for {args.domain} ==")
    for r in check_dmarc(args.domain):
        print(" ", r)

    print(f"\n== DKIM (selector='{args.selector}') for {args.domain} ==")
    for r in check_dkim(args.domain, args.selector):
        print(" ", r)

    print("\nInterpretation guide:")
    print(" - Missing SPF/DMARC records => domain is highly spoofable.")
    print(" - DMARC policy 'p=none' => failures are reported but not blocked.")
    print(" - DKIM lookup failure often just means wrong selector; try common")
    print("   ones (default, google, selector1, selector2, s1, s2, k1).")


if __name__ == "__main__":
    main()

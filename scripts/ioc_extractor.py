#!/usr/bin/env python3
"""
ioc_extractor.py
-----------------
Operation Hydra - lightweight IOC extraction utility.

Scans a text file (e.g., an exported email or sandbox report) and
pulls out IPv4 addresses, domains, SHA256 hashes, and URLs using
regex, then de-duplicates and prints them grouped by type. Useful for
quickly building an IOC table from raw evidence files.

Usage:
    python3 ioc_extractor.py ../evidence/phishing-emails/email_sample_1.txt
"""

import argparse
import re
import sys

PATTERNS = {
    "IPv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "SHA256": r"\b[a-fA-F0-9]{64}\b",
    "URL": r"hxxps?://[^\s]+|https?://[^\s]+",
    "Domain": r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|info|ru|in)\b",
}


def extract(text):
    found = {}
    for label, pattern in PATTERNS.items():
        matches = sorted(set(re.findall(pattern, text)))
        if matches:
            found[label] = matches
    return found


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from a text/log file.")
    parser.add_argument("file", help="Path to evidence/log file")
    args = parser.parse_args()

    try:
        with open(args.file, "r", errors="replace") as f:
            text = f.read()
    except FileNotFoundError:
        print(f"File not found: {args.file}")
        sys.exit(1)

    results = extract(text)
    if not results:
        print("No IOCs found.")
        return

    for label, matches in results.items():
        print(f"\n== {label} ({len(matches)}) ==")
        for m in matches:
            print(f"  {m}")


if __name__ == "__main__":
    main()

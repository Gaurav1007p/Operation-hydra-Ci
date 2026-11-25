# Tool Screenshots

This folder is where analysis-tool screenshots go when this
investigation is run against live evidence:

- `mxtoolbox_spf_check.png` — SPF/DKIM/DMARC results for each domain in
  `evidence/whois-dns-records/domain_analysis.md`
- `virustotal_hash_lookup.png` — VirusTotal detection ratio for each
  SHA256 hash listed in `evidence/malware-iocs/iocs.md`
- `abuseipdb_score.png` — AbuseIPDB confidence score for each C2/relay IP
- `whois_output.png` — raw WHOIS output for each suspicious domain

For this coursework submission, no real phishing infrastructure was
queried live (the domains/IPs/hashes are fabricated for the exercise),
so no screenshots are included here. When adapting this repo to a real
case, save each tool's output screenshot with the naming convention
above and reference it from the corresponding evidence file.

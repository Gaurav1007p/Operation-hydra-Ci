# Tools Used — Operation Hydra Investigation

| Tool | Purpose | Example Command / Usage | Justification |
|---|---|---|---|
| **MXToolbox** | SPF/DKIM/DMARC & blacklist lookups | Web UI: mxtoolbox.com/SuperTool.aspx | Fastest way to visualize email-auth posture of a sending domain without building custom tooling |
| **WHOIS** (CLI + domaintools.com) | Registrar, creation date, name servers | `whois secure-hdfcbank.net-verify-login.com` or `python3 scripts/whois_lookup.py <domain>` | Freshly-registered domains are a strong phishing-infrastructure indicator |
| **VirusTotal** | File hash & URL reputation scoring | Upload hash: `9f1c3a2b7e4d...` to virustotal.com | Cross-references 70+ AV engines; confirms malicious classification without executing the sample locally |
| **AbuseIPDB** | IP reputation / abuse reports | `python3 scripts/ip_trace.py 185.220.101.47` | Identifies bulletproof hosting / Tor exit nodes used as C2 or spoofing infrastructure |
| **dnspython** (Python library) | Programmatic DNS TXT record queries | `python3 scripts/spf_dkim_dmarc_checker.py <domain>` | Automates SPF/DKIM/DMARC checks across many domains for the report |
| **ipinfo.io API** | IP geolocation & ASN lookup | `python3 scripts/ip_trace.py <ip>` | Quickly maps attacker infrastructure to hosting providers/regions |
| **Regex-based IOC extractor** (custom) | Pulls IPs/domains/hashes/URLs from raw evidence | `python3 scripts/ioc_extractor.py <file>` | Speeds up building the IOC table from raw email/log text |
| **ANY.RUN / Hybrid-Analysis (methodology reference)** | Sandbox dynamic-analysis report format | N/A (simulated report, not executed) | Used as the reporting template for the malware behavior write-up in `evidence/malware-iocs/iocs.md` |
| **pandoc** | Markdown → DOCX/PDF report conversion | `pandoc report.md -o report.pdf` | Keeps the report source in version-controlled Markdown while producing polished deliverables |

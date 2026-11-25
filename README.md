# Operation Hydra: Unraveling a Multi-Vector Cyber Crime

**Unit 2 Assignment — Types of Cyber Crimes**
*Investigation and analysis of a simulated multi-stage cyber-crime campaign combining phishing, spoofing, malware injection, and financial fraud.*

## Summary

This repository documents a simulated investigation into "Operation
Hydra," a fictional multi-vector cyber-crime campaign used to satisfy
the requirements of the assignment. The campaign chains together:

1. **Phishing** emails impersonating a bank, a payment provider, and
   internal IT (see `evidence/phishing-emails/`)
2. **Domain/email spoofing** via typosquatted and homoglyph domains
   (see `evidence/whois-dns-records/`)
3. **Malware injection** — a Remote Access Trojan (RAT) delivered via
   attachment, providing keylogging, screen capture, and clipboard
   hijacking (see `evidence/malware-iocs/`)
4. **Financial fraud** — clipboard-hijacked UPI transfers layered
   through mule accounts and laundered through simulated crypto
   wallets (see `evidence/financial-fraud-logs/`)
5. **Legal & ethical analysis** mapping each crime to Indian and
   international law, plus stakeholder impact and policy
   recommendations (see `report/Operation_Hydra_Report.docx`)

All evidence (emails, hashes, IPs, transaction logs, wallet addresses)
is **fabricated for coursework purposes** and does not reference real
victims, real malware samples, or real financial instruments.

## Repository Structure

```
.
├── README.md                          <- you are here
├── tools.md                           <- tools used + commands + justification
├── report/
│   └── Operation_Hydra_Report.docx    <- full 5-8 page legal-technical report
├── evidence/
│   ├── phishing-emails/               <- 3 simulated phishing samples w/ headers
│   ├── malware-iocs/                  <- simulated sandbox report + IOC table
│   ├── financial-fraud-logs/          <- simulated UPI/crypto transaction trail
│   └── whois-dns-records/             <- simulated WHOIS/SPF/DKIM/DMARC findings
├── scripts/                           <- analysis tooling (see below)
├── screenshots/                       <- placeholder for tool-output screenshots
└── .github/workflows/ci.yml           <- markdown lint + structure + syntax checks
```

## Setup Instructions

```bash
git clone <this-repo-url>
cd operation-hydra

# Python deps for the analysis scripts
pip install dnspython --break-system-packages

# (optional) real WHOIS lookups require the whois CLI
sudo apt install whois
```

### Running the scripts

```bash
# Extract IOCs from a raw evidence file
python3 scripts/ioc_extractor.py evidence/phishing-emails/email_sample_1.txt

# Check SPF/DKIM/DMARC posture of a domain
python3 scripts/spf_dkim_dmarc_checker.py example.com

# WHOIS + recent-registration flag
python3 scripts/whois_lookup.py example.com

# IP geolocation + AbuseIPDB reputation hint
python3 scripts/ip_trace.py 185.220.101.47
```

## Evaluation Mapping

| Criterion | Marks | Where addressed |
|---|---|---|
| Cybercrime classification + legal framework | 2.0 | Report §1, `evidence/` overview |
| Phishing/Spoofing technical analysis | 2.0 | Report §2, `evidence/phishing-emails/`, `evidence/whois-dns-records/` |
| Malware/Trojan payload behavior analysis | 2.0 | Report §3, `evidence/malware-iocs/iocs.md` |
| Financial fraud simulation/tracing | 2.0 | Report §4, `evidence/financial-fraud-logs/` |
| Legal, ethical & impact analysis | 1.0 | Report §5 |
| GitHub documentation, structure, CI compliance | 1.0 | This README, `tools.md`, `.github/workflows/ci.yml` |

## Authorship Declaration

This repository was prepared as coursework for Unit 2: Types of Cyber
Crimes. All phishing email content, malware IOCs, financial
transaction logs, WHOIS records, and wallet addresses are **simulated
for educational purposes only** and do not depict real individuals,
organizations, malware, or financial activity. No real systems were
scanned, accessed, or attacked in the preparation of this assignment.

*Author: [Your Name] — [Student ID] — [Course/Section] — [Date]*

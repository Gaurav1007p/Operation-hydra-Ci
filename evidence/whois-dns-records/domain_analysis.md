# WHOIS / DNS Analysis — Operation Hydra (Simulated)

All records below are simulated for coursework purposes, styled after
real WHOIS/MXToolbox/AbuseIPDB output formats.

## Domain: secure-hdfcbank.net-verify-login.com

| Field | Value |
|---|---|
| Registrar | NameCheap Inc. (simulated) |
| Created | 2025-08-05 (6 days before campaign) |
| Registrant | Privacy-protected (WHOIS redaction service) |
| Name Servers | ns1.bulletproof-dns.net, ns2.bulletproof-dns.net |
| A Record | 185.220.101.47 |
| SPF Record | none published |
| DKIM | not configured |
| DMARC | none |
| AbuseIPDB Score (simulated) | 92/100 — reported for phishing, C2 |

## Domain: paypa1-support.com

| Field | Value |
|---|---|
| Registrar | Namecheap Inc. (simulated) |
| Created | 2025-08-06 |
| A Record | 45.155.205.13 |
| SPF Record | none |
| DKIM | fails signature check |
| DMARC | none |
| Notes | Homoglyph typosquat of paypal.com (digit "1" for "l") |

## Domain: victimc0rp-it.com

| Field | Value |
|---|---|
| Registrar | simulated registrar, redacted WHOIS |
| Created | 2025-08-09 |
| A Record | 103.224.182.9 |
| SPF/DKIM/DMARC | all fail/none |
| Notes | Zero-for-"o" homoglyph impersonating internal IT domain;
hosted MITM clone of the organization's real SSO portal |

## IP Reputation Summary (simulated AbuseIPDB / VirusTotal lookups)

| IP | Classification | Notes |
|---|---|---|
| 185.220.101.47 | Tor exit node / bulletproof hosting | Linked to PHISH-001 |
| 45.155.205.13 | Bulletproof hosting (offshore) | Linked to PHISH-002 |
| 103.224.182.9 | Bulletproof hosting, prior phishing reports | Linked to PHISH-003 |

## Toolchain used to produce these findings

- MXToolbox — SPF/DKIM/DMARC record lookups, blacklist checks
- WHOIS (`whois` CLI / whois.domaintools.com) — registrar & creation-date checks
- AbuseIPDB — IP reputation scoring
- VirusTotal — attachment hash & URL reputation

# OSINT Toolkit

Passive and active reconnaissance tool for domain intelligence gathering.

## Modules

| Module | What it does |
|---|---|
| `--whois` | Registrar, creation/expiry dates, org, country |
| `--dns` | A, AAAA, MX, NS, TXT, CNAME, SOA, SRV records |
| `--subs` | Subdomain enumeration (wordlist + crt.sh cert transparency) |
| `--dorks` | Pre-built Google dork queries with clickable URLs |
| `--emails` | Email harvesting from homepage + common patterns |

## Usage

```bash
pip install -r requirements.txt

# Run all modules
python osint.py example.com --all

# Individual modules
python osint.py example.com --whois --dns
python osint.py example.com --subs
python osint.py example.com --dorks

# Save JSON report
python osint.py example.com --all --report
```

## Disclaimer

For authorized reconnaissance only. Use responsibly and within legal boundaries.

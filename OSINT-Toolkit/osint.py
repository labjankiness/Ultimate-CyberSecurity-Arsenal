"""
OSINT Toolkit
Subdomain enumeration, WHOIS lookup, DNS recon, Google dorks, email harvesting.
Usage: python osint.py <domain> [--all] [--subs] [--whois] [--dns] [--dorks] [--emails]
"""

import argparse
import json
import socket
import subprocess
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import whois
from colorama import Fore, Style, init

init(autoreset=True)

SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "cpanel", "whm", "autodiscover", "autoconfig", "m", "mobile", "imap",
    "admin", "portal", "api", "dev", "staging", "test", "beta", "shop",
    "blog", "app", "static", "assets", "cdn", "media", "vpn", "remote",
    "secure", "login", "auth", "sso", "support", "help", "docs", "wiki",
    "forum", "community", "git", "gitlab", "jenkins", "jira", "confluence",
    "monitor", "status", "grafana", "kibana", "elastic", "db", "database",
    "mysql", "redis", "mongo", "postgres", "backup", "internal", "intranet",
    "extranet", "proxy", "gateway", "firewall", "router", "switch", "server",
]

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]

GOOGLE_DORKS = [
    ("site:{domain}", "All indexed pages"),
    ("site:{domain} filetype:pdf", "PDF documents"),
    ("site:{domain} filetype:xls OR filetype:xlsx", "Excel spreadsheets"),
    ("site:{domain} filetype:doc OR filetype:docx", "Word documents"),
    ("site:{domain} inurl:admin", "Admin panels"),
    ("site:{domain} inurl:login", "Login pages"),
    ("site:{domain} inurl:config", "Config files"),
    ("site:{domain} inurl:backup", "Backup files"),
    ('site:{domain} intext:"password"', "Pages mentioning password"),
    ('site:{domain} intext:"api_key" OR intext:"apikey"', "Exposed API keys"),
    ("site:{domain} inurl:phpinfo.php", "PHP info pages"),
    ("site:{domain} inurl:.git", "Git repos"),
    ('"@{domain}" email', "Email addresses"),
    ("site:linkedin.com {domain} employees", "LinkedIn employees"),
    ("site:github.com {domain}", "GitHub references"),
]

results = {
    "domain": "",
    "scan_time": "",
    "subdomains": [],
    "whois": {},
    "dns": {},
    "dorks": [],
    "emails": [],
}


def log(color, prefix, msg):
    print(f"{color}[{prefix}]{Style.RESET_ALL} {msg}")

def found(msg): log(Fore.GREEN,  "FOUND", msg)
def info(msg):  log(Fore.CYAN,   "INFO",  msg)
def warn(msg):  log(Fore.YELLOW, "WARN",  msg)
def err(msg):   log(Fore.RED,    " ERR ", msg)


def resolve_subdomain(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except Exception:
        return None, None


def enumerate_subdomains(domain):
    info(f"Enumerating subdomains for {domain} ({len(SUBDOMAIN_WORDLIST)} wordlist)...")
    found_subs = []

    with ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(resolve_subdomain, sub, domain): sub for sub in SUBDOMAIN_WORDLIST}
        for future in as_completed(futures):
            fqdn, ip = future.result()
            if fqdn:
                found(f"{fqdn} → {ip}")
                found_subs.append({"subdomain": fqdn, "ip": ip})

    # Also check crt.sh (certificate transparency logs)
    info("Checking certificate transparency logs (crt.sh)...")
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=10)
        if r.status_code == 200:
            seen = set()
            for entry in r.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if domain in sub and sub not in seen:
                        seen.add(sub)
                        try:
                            ip = socket.gethostbyname(sub)
                            if not any(s["subdomain"] == sub for s in found_subs):
                                found(f"{sub} → {ip} [crt.sh]")
                                found_subs.append({"subdomain": sub, "ip": ip, "source": "crt.sh"})
                        except Exception:
                            pass
    except Exception as e:
        warn(f"crt.sh lookup failed: {e}")

    info(f"Found {len(found_subs)} subdomains")
    results["subdomains"] = found_subs
    return found_subs


def whois_lookup(domain):
    info(f"WHOIS lookup for {domain}...")
    try:
        w = whois.whois(domain)
        data = {
            "registrar":       str(w.registrar or "N/A"),
            "creation_date":   str(w.creation_date or "N/A"),
            "expiration_date": str(w.expiration_date or "N/A"),
            "updated_date":    str(w.updated_date or "N/A"),
            "name_servers":    [str(ns) for ns in (w.name_servers or [])],
            "status":          str(w.status or "N/A"),
            "org":             str(w.org or "N/A"),
            "country":         str(w.country or "N/A"),
        }
        for k, v in data.items():
            if v and v != "N/A":
                found(f"{k}: {v}")
        results["whois"] = data
        return data
    except Exception as e:
        err(f"WHOIS failed: {e}")
        return {}


def dns_recon(domain):
    info(f"DNS reconnaissance for {domain}...")
    dns_data = {}
    for rtype in DNS_RECORD_TYPES:
        try:
            cmd = ["dig", "+short", domain, rtype]
            out = subprocess.check_output(cmd, timeout=5, stderr=subprocess.DEVNULL).decode().strip()
            if out:
                records = [r for r in out.split("\n") if r]
                dns_data[rtype] = records
                for r in records:
                    found(f"{rtype}: {r}")
        except Exception:
            pass
    results["dns"] = dns_data
    return dns_data


def generate_dorks(domain):
    info(f"Google dork queries for {domain}:")
    print()
    dork_list = []
    for dork_template, description in GOOGLE_DORKS:
        dork = dork_template.format(domain=domain)
        search_url = f"https://www.google.com/search?q={requests.utils.quote(dork)}"
        print(f"  {Fore.YELLOW}{description}{Style.RESET_ALL}")
        print(f"  Query: {Fore.CYAN}{dork}{Style.RESET_ALL}")
        print(f"  URL:   {search_url}")
        print()
        dork_list.append({"description": description, "query": dork, "url": search_url})
    results["dorks"] = dork_list
    return dork_list


def harvest_emails(domain):
    info(f"Email harvesting for {domain} via Hunter.io (no key — pattern-only)...")
    emails = set()

    # Infer common patterns from domain
    patterns = [
        f"info@{domain}", f"admin@{domain}", f"contact@{domain}",
        f"support@{domain}", f"security@{domain}", f"webmaster@{domain}",
        f"abuse@{domain}", f"noreply@{domain}", f"hello@{domain}",
    ]

    # Try to find emails from homepage
    try:
        r = requests.get(f"https://{domain}", timeout=8)
        import re
        found_emails = re.findall(r"[a-zA-Z0-9._%+\-]+@" + re.escape(domain), r.text)
        emails.update(found_emails)
    except Exception:
        pass

    for e in patterns:
        emails.add(e)

    for e in sorted(emails):
        found(f"Email: {e}")

    results["emails"] = list(emails)
    return list(emails)


def save_report(domain):
    filename = f"osint_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    log(Fore.GREEN, "SAVE", f"Report saved to {filename}")


def main():
    parser = argparse.ArgumentParser(description="OSINT Toolkit")
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--all",    action="store_true", help="Run all modules")
    parser.add_argument("--subs",   action="store_true", help="Subdomain enumeration")
    parser.add_argument("--whois",  action="store_true", help="WHOIS lookup")
    parser.add_argument("--dns",    action="store_true", help="DNS recon")
    parser.add_argument("--dorks",  action="store_true", help="Google dork generation")
    parser.add_argument("--emails", action="store_true", help="Email harvesting")
    parser.add_argument("--report", action="store_true", help="Save JSON report")
    args = parser.parse_args()

    domain = args.domain.lower().strip().lstrip("https://").lstrip("http://").split("/")[0]
    run_all = args.all or not any([args.subs, args.whois, args.dns, args.dorks, args.emails])

    results["domain"] = domain
    results["scan_time"] = datetime.now().isoformat()

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"  OSINT Toolkit")
    print(f"  Target: {domain}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    if run_all or args.whois:
        whois_lookup(domain)
        print()

    if run_all or args.dns:
        dns_recon(domain)
        print()

    if run_all or args.subs:
        enumerate_subdomains(domain)
        print()

    if run_all or args.dorks:
        generate_dorks(domain)

    if run_all or args.emails:
        harvest_emails(domain)
        print()

    print(f"{Fore.CYAN}{'='*60}")
    print(f"  Scan complete — {domain}")
    subs = len(results['subdomains'])
    print(f"  Subdomains: {subs}  |  DNS records: {sum(len(v) for v in results['dns'].values())}  |  Dorks: {len(results['dorks'])}")
    print(f"{'='*60}{Style.RESET_ALL}\n")

    if args.report:
        save_report(domain)


if __name__ == "__main__":
    main()

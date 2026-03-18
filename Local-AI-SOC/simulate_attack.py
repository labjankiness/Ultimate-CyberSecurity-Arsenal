import os
import time
import random

# Expanded attack patterns with severity categories
ATTACKS = {
    "high": [
        "sshd: Failed password for root from 203.0.113.5 port 22 ssh2 (attempt 47 of 50)",
        "sudo: unknown : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        "kernel: [12345.67] usb 1-1: New USB device found, idVendor=05ac, idProduct=0202 (Rubber Ducky?)",
        "sshd: Accepted publickey for root from 10.0.0.99 port 443 ssh2 (unknown key)",
    ],
    "medium": [
        "sshd: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2",
        "nginx: 192.168.1.10 - - 'GET /admin.php?id=1' OR '1'='1' HTTP/1.1 200",
        "sudo: ryan : TTY=pts/0 ; PWD=/home/ryan ; USER=root ; COMMAND=/usr/bin/apt install nmap",
        "sshd: Failed password for invalid user test from 198.51.100.23 port 22 ssh2",
    ],
    "low": [
        "sshd: Failed password for ryan from 192.168.1.2 port 22 ssh2",
        "nginx: 10.0.0.5 - - 'GET /robots.txt HTTP/1.1' 200",
        "sudo: ryan : TTY=pts/0 ; PWD=/home/ryan ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
        "kernel: [54321.00] Firewall: IN=eth0 OUT= SRC=8.8.8.8 DST=10.0.0.1 PROTO=ICMP",
    ],
}


def generate_noise():
    # Weighted selection: more medium/low alerts to simulate realistic noise
    severity = random.choices(
        ["high", "medium", "low"],
        weights=[15, 35, 50],
        k=1
    )[0]
    attack = random.choice(ATTACKS[severity])

    with open("mock_security.log", "a") as f:
        log = f"{time.ctime()} - [{severity.upper()}] - {attack}\n"
        f.write(log)
        print(f"[{severity.upper()}] {attack}")


if __name__ == "__main__":
    # Create log file if it doesn't exist
    if not os.path.exists("mock_security.log"):
        open("mock_security.log", "w").close()

    print("[*] Attack simulator running. Press Ctrl+C to stop.")
    while True:
        generate_noise()
        time.sleep(random.randint(5, 15))  # Randomized interval

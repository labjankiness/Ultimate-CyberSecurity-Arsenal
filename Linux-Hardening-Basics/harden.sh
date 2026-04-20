#!/bin/bash
# 🛡️ Linux Hardening Basics - Security Auditor & Hardener
# Targets: Ubuntu/Debian

MODE="harden"
if [[ "$1" == "--audit" ]]; then MODE="audit"; fi

echo "--- 🔒 Linux Security $MODE Initiated ---"

check_step() {
    local name=$1
    local cmd=$2
    if eval "$cmd"; then
        echo -e "[✅] $name: SECURE"
    else
        echo -e "[❌] $name: VULNERABLE"
        return 1
    fi
}

harden_ufw() {
    echo "[*] Configuring UFW..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw --force enable
}

harden_ssh() {
    echo "[*] Disabling root SSH login..."
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart ssh
}

run_audit() {
    echo "--- 📋 Security Audit Report ---"
    check_step "UFW Status" "ufw status | grep -q 'Status: active'"
    check_step "Root SSH Disabled" "grep -q '^PermitRootLogin no' /etc/ssh/sshd_config"
    check_step "Fail2Ban Installed" "command -v fail2ban-client > /dev/null"
    check_step "Password Aging Policy" "grep -q '^PASS_MAX_DAYS' /etc/login.defs"
    check_step "No Telnet Server" "! dpkg -l | grep -q telnetd"
    echo "--- End of Report ---"
}

if [[ "$MODE" == "audit" ]]; then
    run_audit
    exit 0
fi

# EXECUTE HARDENING
echo "[!] Applying active hardening measures (requires sudo)..."

# 1. Firewall
harden_ufw

# 2. SSH
harden_ssh

# 3. Fail2Ban
echo "[*] Installing Fail2Ban..."
apt update && apt install fail2ban -y
systemctl enable fail2ban && systemctl start fail2ban

# 4. Remove Legacy Tools
echo "[*] Removing insecure services..."
apt purge telnetd rsh-server rsh-client nis yp-tools -y

echo "[✅] Hardening complete. Please run with --audit to verify."

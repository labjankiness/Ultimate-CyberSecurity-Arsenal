#!/usr/bin/env python3
"""
Keylogger Detector — Linux Defensive Security Tool
Scans for signs of keylogger activity on a Linux system by checking:
  1. Suspicious processes reading from /dev/input/*
  2. Unexpected keyboard device listeners
  3. Known keylogger signatures in running processes
  4. Suspicious Python/shell scripts hooking input
  5. LD_PRELOAD hijacking (shared library injection)
  6. Kernel module-based keyloggers
  7. /dev/input device permissions anomalies
  8. Suspicious cron jobs and startup entries

WARNING: For educational and authorized defensive use only.
Run with sudo for full system visibility.
"""

import os
import re
import glob
import subprocess
import argparse
import sys
from pathlib import Path
from datetime import datetime


# ─── Colors ────────────────────────────────────────────────────────────────────

class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def warn(msg):
    print(f"  {C.RED}[!]{C.RESET} {msg}")

def safe(msg):
    print(f"  {C.GREEN}[OK]{C.RESET} {msg}")

def info(msg):
    print(f"  {C.CYAN}[i]{C.RESET} {msg}")

def header(msg):
    print(f"\n{C.BOLD}{C.CYAN}{'─' * 50}")
    print(f"  {msg}")
    print(f"{'─' * 50}{C.RESET}")


# ─── Check 1: Processes reading /dev/input ─────────────────────────────────────

def check_input_listeners():
    """Find processes that have /dev/input/* files open."""
    header("Check 1: Processes reading /dev/input devices")
    findings = []

    # Known safe processes that legitimately read input devices
    safe_procs = {
        "Xorg", "Xwayland", "gnome-shell", "kwin_wayland", "sway",
        "mutter", "wlroots", "libinput", "systemd-logind", "loginctl",
        "gdm", "sddm", "lightdm", "agetty", "login", "wayfire",
        "hyprland", "weston", "inputattach", "acpid", "upowerd",
        "thermald", "irqbalance", "pipewire", "wireplumber",
    }

    try:
        # Check /proc/*/fd for links to /dev/input/*
        for pid_dir in glob.glob("/proc/[0-9]*/fd"):
            pid = pid_dir.split("/")[2]
            try:
                comm_path = f"/proc/{pid}/comm"
                if not os.path.exists(comm_path):
                    continue
                with open(comm_path) as f:
                    proc_name = f.read().strip()

                for fd in os.listdir(pid_dir):
                    try:
                        link = os.readlink(os.path.join(pid_dir, fd))
                        if "/dev/input" in link:
                            if proc_name not in safe_procs:
                                findings.append((pid, proc_name, link))
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue
    except PermissionError:
        info("Run with sudo for full /proc visibility")
        return findings

    if findings:
        for pid, name, device in findings:
            warn(f"PID {pid} ({name}) is reading {device}")
    else:
        safe("No suspicious processes reading input devices")

    return findings


# ─── Check 2: Known keylogger signatures ──────────────────────────────────────

def check_known_signatures():
    """Search for known keylogger process names and patterns."""
    header("Check 2: Known keylogger signatures in processes")
    findings = []

    # Known keylogger names/patterns
    signatures = [
        "logkeys", "lkl", "keylogger", "pykeylogger", "keysniffer",
        "xinput-keylog", "xspy", "snoopy", "uberkey", "klog",
        "keyboard_monitor", "key_capture", "input_capture",
        "keysniff", "keystroke", "keyspy", "inputspy",
    ]

    try:
        my_pid = str(os.getpid())
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines()[1:]:  # skip header
            parts = line.split()
            if len(parts) > 1 and parts[1] == my_pid:
                continue  # Skip self
            # Skip if the match is just in a path containing our tool name
            if "detector.py" in line or "keylogger-detector" in line:
                continue
            line_lower = line.lower()
            for sig in signatures:
                if sig in line_lower:
                    findings.append((sig, line.strip()))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        info("Could not run ps command")
        return findings

    if findings:
        for sig, line in findings:
            warn(f"Matched '{sig}': {line[:100]}")
    else:
        safe("No known keylogger signatures found in running processes")

    return findings


# ─── Check 3: Suspicious Python/script processes ──────────────────────────────

def check_suspicious_scripts():
    """Look for Python or shell scripts that might be capturing keystrokes."""
    header("Check 3: Suspicious input-hooking scripts")
    findings = []

    suspicious_modules = [
        "pynput", "pyxhook", "evdev",
        "Xlib.display", "ctypes.CDLL.*libX", "input_event",
    ]

    try:
        my_pid = str(os.getpid())
        # Check running Python processes for suspicious imports
        result = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "python" in line.lower():
                parts = line.split()
                if len(parts) >= 11:
                    if parts[1] == my_pid:
                        continue  # Skip self
                    pid = parts[1]
                    cmd = " ".join(parts[10:])

                    # Try to read the script file if it's referenced
                    for part in parts[10:]:
                        if part.endswith(".py") and os.path.exists(part):
                            try:
                                with open(part) as f:
                                    content = f.read(4096)
                                for mod in suspicious_modules:
                                    if re.search(mod, content):
                                        findings.append((pid, cmd, mod))
                            except (PermissionError, OSError):
                                continue

        # Also check for shell scripts reading /dev/input
        for line in result.stdout.splitlines():
            if any(s in line for s in ["cat /dev/input", "dd if=/dev/input",
                                        "xxd /dev/input", "od /dev/input"]):
                parts = line.split()
                findings.append((parts[1] if len(parts) > 1 else "?",
                                line.strip(), "direct /dev/input read"))

    except (subprocess.TimeoutExpired, FileNotFoundError):
        info("Could not check running scripts")

    if findings:
        for pid, cmd, mod in findings:
            warn(f"PID {pid}: uses '{mod}' — {cmd[:80]}")
    else:
        safe("No suspicious input-hooking scripts detected")

    return findings


# ─── Check 4: LD_PRELOAD hijacking ────────────────────────────────────────────

def check_ld_preload():
    """Check for LD_PRELOAD-based keystroke interception."""
    header("Check 4: LD_PRELOAD / shared library injection")
    findings = []

    # Check environment variable
    preload_env = os.environ.get("LD_PRELOAD", "")
    if preload_env:
        findings.append(("env", f"LD_PRELOAD={preload_env}"))

    # Check /etc/ld.so.preload
    preload_file = "/etc/ld.so.preload"
    if os.path.exists(preload_file):
        try:
            with open(preload_file) as f:
                content = f.read().strip()
            if content:
                findings.append(("file", f"/etc/ld.so.preload contains: {content}"))
        except PermissionError:
            info(f"Cannot read {preload_file} (run with sudo)")

    # Known safe LD_PRELOAD patterns (Snap, Firefox sandbox, etc.)
    safe_preloads = [
        "bindtextdomain.so", "libmozsandbox.so", "libgtk3-nocsd.so",
        "libgamemodeauto.so", "libnvidia", "libcuda",
    ]

    # Check running processes for LD_PRELOAD in their environment
    try:
        for pid_dir in glob.glob("/proc/[0-9]*/environ"):
            pid = pid_dir.split("/")[2]
            try:
                with open(pid_dir, "rb") as f:
                    environ = f.read().decode("utf-8", errors="ignore")
                if "LD_PRELOAD=" in environ:
                    comm = open(f"/proc/{pid}/comm").read().strip()
                    for var in environ.split("\x00"):
                        if var.startswith("LD_PRELOAD="):
                            # Skip known safe preloads
                            if any(s in var for s in safe_preloads):
                                continue
                            findings.append(("proc", f"PID {pid} ({comm}): {var}"))
            except (PermissionError, OSError):
                continue
    except PermissionError:
        pass

    if findings:
        for source, detail in findings:
            warn(f"[{source}] {detail}")
    else:
        safe("No LD_PRELOAD hijacking detected")

    return findings


# ─── Check 5: Suspicious kernel modules ───────────────────────────────────────

def check_kernel_modules():
    """Check for suspicious kernel modules that might intercept keystrokes."""
    header("Check 5: Suspicious kernel modules")
    findings = []

    suspicious_modules = [
        "keylogger", "klog", "keysniffer", "rootkit", "reptile",
        "diamorphine", "suterusu", "knark", "adore", "azazel",
    ]

    try:
        result = subprocess.run(
            ["lsmod"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines()[1:]:
            mod_name = line.split()[0].lower()
            for sig in suspicious_modules:
                if sig in mod_name:
                    findings.append((mod_name, line.strip()))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        info("Could not run lsmod")

    # Check for hidden modules via /sys/module vs lsmod discrepancy
    try:
        sys_modules = set()
        for m in os.listdir("/sys/module"):
            sys_modules.add(m)

        result = subprocess.run(
            ["lsmod"], capture_output=True, text=True, timeout=5
        )
        lsmod_modules = set()
        for line in result.stdout.splitlines()[1:]:
            lsmod_modules.add(line.split()[0])

        # Modules in /sys/module but not in lsmod could be built-in or hidden
        # We only flag ones with suspicious names
        hidden = sys_modules - lsmod_modules
        for mod in hidden:
            for sig in suspicious_modules:
                if sig in mod.lower():
                    findings.append((mod, "Present in /sys/module but not in lsmod (possibly hidden)"))

    except (OSError, subprocess.TimeoutExpired):
        pass

    if findings:
        for name, detail in findings:
            warn(f"Module '{name}': {detail}")
    else:
        safe("No suspicious kernel modules detected")

    return findings


# ─── Check 6: /dev/input permissions ──────────────────────────────────────────

def check_input_permissions():
    """Check if /dev/input devices have unusual permissions."""
    header("Check 6: /dev/input device permissions")
    findings = []

    input_devices = glob.glob("/dev/input/event*")
    if not input_devices:
        info("No /dev/input/event* devices found")
        return findings

    for dev in input_devices:
        try:
            stat = os.stat(dev)
            mode = oct(stat.st_mode)[-3:]
            # Normal: 660 (rw-rw----) owned by root:input
            # Suspicious: world-readable (xx4, xx6, xx7)
            if int(mode[2]) >= 4:
                findings.append((dev, mode, "World-readable — any user can read keystrokes"))
        except OSError:
            continue

    if findings:
        for dev, mode, reason in findings:
            warn(f"{dev} (mode {mode}): {reason}")
    else:
        safe(f"Input device permissions look normal ({len(input_devices)} devices checked)")

    return findings


# ─── Check 7: Suspicious cron jobs & startup ──────────────────────────────────

def check_persistence():
    """Check cron jobs and startup entries for keylogger persistence."""
    header("Check 7: Suspicious cron jobs and startup entries")
    findings = []

    suspicious_patterns = [
        r"keylog", r"pynput", r"evdev", r"xinput.*--test",
        r"/dev/input", r"key_capture", r"keystroke",
    ]

    # Known safe files that mention input/keyboard legitimately
    safe_files = [
        "org.gnome.SettingsDaemon.MediaKeys",
        "org.gnome.SettingsDaemon.Keyboard",
        "org.freedesktop", "ibus", "fcitx", "gnome-initial-setup",
    ]

    # Check user crontab
    try:
        result = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            for i, line in enumerate(result.stdout.splitlines(), 1):
                if line.strip().startswith("#"):
                    continue
                for pat in suspicious_patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        findings.append(("crontab", f"Line {i}: {line.strip()}"))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check system cron directories
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]
    for cron_dir in cron_dirs:
        if os.path.isdir(cron_dir):
            for fname in os.listdir(cron_dir):
                fpath = os.path.join(cron_dir, fname)
                try:
                    with open(fpath) as f:
                        content = f.read(4096)
                    for pat in suspicious_patterns:
                        if re.search(pat, content, re.IGNORECASE):
                            findings.append(("cron", f"{fpath}: matches '{pat}'"))
                except (PermissionError, OSError):
                    continue

    # Check autostart directories
    autostart_dirs = [
        os.path.expanduser("~/.config/autostart"),
        "/etc/xdg/autostart",
    ]
    for adir in autostart_dirs:
        if os.path.isdir(adir):
            for fname in os.listdir(adir):
                if any(s in fname for s in safe_files):
                    continue
                fpath = os.path.join(adir, fname)
                try:
                    with open(fpath) as f:
                        content = f.read(4096)
                    for pat in suspicious_patterns:
                        if re.search(pat, content, re.IGNORECASE):
                            findings.append(("autostart", f"{fpath}: matches '{pat}'"))
                except (PermissionError, OSError):
                    continue

    # Check systemd user services
    systemd_user = os.path.expanduser("~/.config/systemd/user")
    if os.path.isdir(systemd_user):
        for fname in os.listdir(systemd_user):
            fpath = os.path.join(systemd_user, fname)
            try:
                with open(fpath) as f:
                    content = f.read(4096)
                for pat in suspicious_patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        findings.append(("systemd", f"{fpath}: matches '{pat}'"))
            except (PermissionError, OSError):
                continue

    if findings:
        for source, detail in findings:
            warn(f"[{source}] {detail}")
    else:
        safe("No suspicious persistence mechanisms found")

    return findings


# ─── Check 8: Recently modified suspicious files ──────────────────────────────

def check_recent_files():
    """Look for recently created/modified files that could be keylogger logs."""
    header("Check 8: Suspicious log files (potential keystroke dumps)")
    findings = []

    suspicious_names = [
        "*keylog*", "*keystroke*", "*keypress*", "*keydump*",
        "*input_log*", "*keyboard_log*", "*key_capture*",
    ]

    search_dirs = [
        "/tmp", "/var/tmp", "/dev/shm",
        os.path.expanduser("~"),
    ]

    for search_dir in search_dirs:
        for pattern in suspicious_names:
            for match in glob.glob(os.path.join(search_dir, pattern)):
                try:
                    stat = os.stat(match)
                    mtime = datetime.fromtimestamp(stat.st_mtime)
                    size = stat.st_size
                    findings.append((match, size, mtime))
                except OSError:
                    continue

            # Also check one level deep
            for match in glob.glob(os.path.join(search_dir, "*", pattern)):
                try:
                    stat = os.stat(match)
                    mtime = datetime.fromtimestamp(stat.st_mtime)
                    size = stat.st_size
                    findings.append((match, size, mtime))
                except OSError:
                    continue

    if findings:
        for path, size, mtime in findings:
            warn(f"{path} ({size} bytes, modified {mtime})")
    else:
        safe("No suspicious keystroke log files found")

    return findings


# ─── Main ──────────────────────────────────────────────────────────────────────

def print_banner():
    print(f"""{C.BOLD}{C.CYAN}
  ╔═══════════════════════════════════════════════╗
  ║   KEYLOGGER DETECTOR — Linux Defense Tool     ║
  ║   For authorized defensive security only      ║
  ╚═══════════════════════════════════════════════╝{C.RESET}
""")


def main():
    parser = argparse.ArgumentParser(
        description="Keylogger Detector — Scan for keylogger activity on Linux",
        epilog="Run with sudo for full system visibility.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show additional details"
    )
    parser.add_argument(
        "--check", type=int, choices=range(1, 9),
        help="Run only a specific check (1-8)",
    )

    args = parser.parse_args()
    print_banner()

    is_root = os.geteuid() == 0
    if not is_root:
        print(f"  {C.YELLOW}Note: Running without root. Some checks may be limited.")
        print(f"  Run with: sudo python3 detector.py{C.RESET}\n")

    checks = [
        (1, check_input_listeners),
        (2, check_known_signatures),
        (3, check_suspicious_scripts),
        (4, check_ld_preload),
        (5, check_kernel_modules),
        (6, check_input_permissions),
        (7, check_persistence),
        (8, check_recent_files),
    ]

    total_findings = 0

    for num, check_fn in checks:
        if args.check and args.check != num:
            continue
        findings = check_fn()
        total_findings += len(findings)

    # Summary
    print(f"\n{C.BOLD}{'═' * 50}")
    print(f"  SCAN COMPLETE")
    print(f"{'═' * 50}{C.RESET}")

    if total_findings == 0:
        print(f"\n  {C.GREEN}{C.BOLD}No threats detected.{C.RESET} System appears clean.\n")
    else:
        print(f"\n  {C.RED}{C.BOLD}{total_findings} potential issue(s) found.{C.RESET}")
        print(f"  Review the warnings above and investigate further.\n")

    return total_findings


if __name__ == "__main__":
    sys.exit(0 if main() == 0 else 1)

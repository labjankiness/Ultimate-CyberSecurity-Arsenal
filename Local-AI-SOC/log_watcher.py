import time
import threading
from triage_agent import analyze_log

LOG_FILE = "mock_security.log"


def watch_logs(dashboard_callback=None):
    print(f"[*] Monitoring {LOG_FILE} for threats...")
    with open(LOG_FILE, "r") as f:
        # Move to the end of the file
        f.seek(0, 2)

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            print(f"\n[!] New Alert Detected. Consulting AI...")
            report = analyze_log(line)

            # Save to markdown dashboard
            with open("threat_dashboard.md", "a") as dashboard:
                dashboard.write(f"### Alert at {time.ctime()}\n")
                dashboard.write(f"**Raw Log:** `{line.strip()}`\n\n")
                dashboard.write(f"**AI Analysis:**\n{report}\n\n---\n")

            # Feed to web dashboard if available
            if dashboard_callback:
                dashboard_callback(line, report)

            print(f"[+] Analysis complete. Report saved.")


if __name__ == "__main__":
    try:
        from dashboard import add_alert, run_dashboard

        # Start web dashboard in background
        dash_thread = threading.Thread(target=run_dashboard, daemon=True)
        dash_thread.start()
        print("[*] Web dashboard started at http://localhost:5050")

        # Start watching logs, feeding alerts to dashboard
        watch_logs(dashboard_callback=add_alert)
    except ImportError:
        # Fallback: run without web dashboard
        watch_logs()

"""
Log watcher for the AI-SOC pipeline.

Tail-follows mock_security.log, sends each new entry through the
LLM triage agent, stores results in SQLite, and feeds the web dashboard.

Usage:
    python log_watcher.py
"""

import json
import time
import threading
from typing import Optional, Callable

from triage_agent import analyze_log
from database import init_db, store_alert, store_responses
from response_engine import generate_response

LOG_FILE = "mock_security.log"


def watch_logs(dashboard_callback: Optional[Callable] = None) -> None:
    """Monitor the log file for new entries and process each one.

    Args:
        dashboard_callback: Optional function(raw_log, report_str) to
                            feed alerts to the web dashboard.
    """
    init_db()
    print(f"[*] Monitoring {LOG_FILE} for threats...")
    print(f"[*] Alerts stored in soc_alerts.db")

    with open(LOG_FILE, "r") as f:
        f.seek(0, 2)  # Move to end of file

        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue

            print(f"\n[!] New Alert Detected. Consulting AI...")
            alert = analyze_log(line)

            # Store in SQLite
            row_id = store_alert(alert)
            print(f"[+] Alert #{row_id} stored in database.")

            # Console output
            severity_color = ""
            tl = alert.get("threat_level", 0)
            if tl >= 8:
                severity_color = "CRITICAL"
            elif tl >= 5:
                severity_color = "MEDIUM"
            else:
                severity_color = "LOW"

            print(f"    Verdict:  {alert['verdict']}")
            print(f"    Severity: {alert['threat_level']}/10 [{severity_color}]")
            print(f"    Category: {alert['category']}")
            print(f"    Summary:  {alert['summary']}")

            # Correlation context
            if alert.get("is_correlated"):
                corr_id = alert.get("correlation_id", "N/A")
                stage = alert.get("chain_stage", "N/A")
                narrative = alert.get("correlation_narrative", "")
                print(f"    [CORRELATED] Incident: {corr_id} | Stage: {stage}")
                if narrative:
                    print(f"    [CORRELATED] {narrative}")

            # Generate and store response suggestions
            suggestions = generate_response(alert)
            if suggestions:
                store_responses(row_id, suggestions)
                print(f"    [RESPONSE] {len(suggestions)} suggested action(s):")
                for s in suggestions:
                    risk_tag = s["risk_level"].upper()
                    print(f"      [{risk_tag}] {s['action_name']}")

            # Markdown dashboard (secondary output)
            with open("threat_dashboard.md", "a") as dashboard:
                dashboard.write(f"### Alert #{row_id} at {alert['timestamp']}\n")
                dashboard.write(f"**Raw Log:** `{alert['raw_log']}`\n\n")
                dashboard.write(f"**Verdict:** {alert['verdict']} | ")
                dashboard.write(f"**Threat Level:** {alert['threat_level']}/10 | ")
                dashboard.write(f"**Category:** {alert['category']}\n\n")
                dashboard.write(f"**Summary:** {alert['summary']}\n\n")
                dashboard.write(f"**Remediation:** {alert['remediation']}\n\n---\n")

            # Feed to web dashboard if available
            if dashboard_callback:
                report_str = json.dumps(alert, indent=2)
                dashboard_callback(line, report_str)

            print(f"[+] Analysis complete. Report saved.")


if __name__ == "__main__":
    try:
        from dashboard import add_alert, run_dashboard

        dash_thread = threading.Thread(target=run_dashboard, daemon=True)
        dash_thread.start()
        print("[*] Web dashboard started at http://localhost:5050")

        watch_logs(dashboard_callback=add_alert)
    except ImportError:
        watch_logs()

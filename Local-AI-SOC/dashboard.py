"""
Web dashboard for the Local-AI-SOC.
Provides a live-updating view of threat analysis results.

Usage:
    python dashboard.py

Then open http://localhost:5050 in your browser.
"""

import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

# In-memory store for alerts (shared with log_watcher via import)
alerts = []
MAX_ALERTS = 100


def add_alert(raw_log, ai_analysis, timestamp=None):
    """Add an alert to the dashboard store."""
    alerts.insert(0, {
        "timestamp": timestamp or time.strftime("%Y-%m-%d %H:%M:%S"),
        "raw_log": raw_log.strip(),
        "analysis": ai_analysis.strip(),
    })
    if len(alerts) > MAX_ALERTS:
        alerts.pop()


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI-SOC Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
        }
        .header {
            background: linear-gradient(90deg, #1a1a2e, #16213e);
            padding: 20px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #0f3460;
        }
        .header h1 { color: #00d4ff; font-size: 24px; }
        .header .status {
            display: flex; align-items: center; gap: 8px;
            color: #4ade80; font-size: 14px;
        }
        .header .status .dot {
            width: 8px; height: 8px; background: #4ade80;
            border-radius: 50%; animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        .stats {
            display: flex; gap: 20px; padding: 20px 30px;
            border-bottom: 1px solid #1a1a2e;
        }
        .stat-card {
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 8px;
            padding: 15px 25px;
            min-width: 150px;
        }
        .stat-card .label { color: #6b7280; font-size: 12px; text-transform: uppercase; }
        .stat-card .value { font-size: 28px; font-weight: bold; margin-top: 5px; }
        .stat-card .value.high { color: #ef4444; }
        .stat-card .value.medium { color: #f59e0b; }
        .stat-card .value.ok { color: #4ade80; }
        .alerts-container { padding: 20px 30px; }
        .alerts-container h2 { color: #9ca3af; margin-bottom: 15px; font-size: 16px; }
        .alert-card {
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 12px;
            transition: border-color 0.2s;
        }
        .alert-card:hover { border-color: #374151; }
        .alert-time { color: #6b7280; font-size: 12px; }
        .alert-log {
            background: #0a0a0a;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
            color: #f59e0b;
            margin: 8px 0;
            word-break: break-all;
        }
        .alert-analysis {
            color: #d1d5db;
            font-size: 14px;
            line-height: 1.6;
            white-space: pre-wrap;
        }
        .empty-state {
            text-align: center; padding: 60px 20px; color: #4b5563;
        }
        .empty-state p { margin-top: 10px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AI-SOC Dashboard</h1>
        <div class="status"><div class="dot"></div> Live Monitoring</div>
    </div>
    <div class="stats">
        <div class="stat-card">
            <div class="label">Total Alerts</div>
            <div class="value ok" id="total-count">0</div>
        </div>
        <div class="stat-card">
            <div class="label">Last Updated</div>
            <div class="value" id="last-updated" style="font-size:16px;color:#9ca3af;">--</div>
        </div>
    </div>
    <div class="alerts-container">
        <h2>Recent Alerts</h2>
        <div id="alerts-list">
            <div class="empty-state">
                <h3>No alerts yet</h3>
                <p>Run <code>python simulate_attack.py</code> and <code>python log_watcher.py</code> to start generating alerts.</p>
            </div>
        </div>
    </div>
    <script>
        async function refresh() {
            try {
                const res = await fetch('/api/alerts');
                const data = await res.json();
                document.getElementById('total-count').textContent = data.length;
                const list = document.getElementById('alerts-list');
                if (data.length === 0) {
                    list.innerHTML = '<div class="empty-state"><h3>No alerts yet</h3><p>Run simulate_attack.py and log_watcher.py to start.</p></div>';
                } else {
                    document.getElementById('last-updated').textContent = data[0].timestamp;
                    list.innerHTML = data.map(a => `
                        <div class="alert-card">
                            <div class="alert-time">${a.timestamp}</div>
                            <div class="alert-log">${a.raw_log}</div>
                            <div class="alert-analysis">${a.analysis}</div>
                        </div>
                    `).join('');
                }
            } catch(e) {}
        }
        refresh();
        setInterval(refresh, 3000);
    </script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/alerts':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(alerts).encode())
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(DASHBOARD_HTML.encode())

    def log_message(self, format, *args):
        pass  # Suppress request logs


def run_dashboard(port=5050):
    server = HTTPServer(('0.0.0.0', port), DashboardHandler)
    print(f"[*] Dashboard running at http://localhost:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_dashboard()

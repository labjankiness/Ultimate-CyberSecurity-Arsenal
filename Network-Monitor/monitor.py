#!/usr/bin/env python3
"""
Network Monitor Dashboard
Real-time network traffic visualization with a web-based dashboard.
Uses psutil for system-level network stats and Flask for the web UI.
"""

import json
import time
import threading
import argparse
import socket
import sys
from collections import deque
from datetime import datetime

import psutil
from flask import Flask, jsonify, render_template_string

# ─── Configuration ─────────────────────────────────────────────────────────────

MAX_HISTORY = 120  # data points to keep (2 minutes at 1/sec)
SAMPLE_INTERVAL = 1.0  # seconds between samples

# ─── Data Collection ───────────────────────────────────────────────────────────

class NetworkCollector:
    """Collects and stores network statistics over time."""

    def __init__(self):
        self.lock = threading.Lock()
        self.history = deque(maxlen=MAX_HISTORY)
        self.connections_history = deque(maxlen=MAX_HISTORY)
        self.prev_counters = psutil.net_io_counters()
        self.prev_time = time.time()
        self.running = False

    def sample(self):
        """Take a single network sample."""
        now = time.time()
        counters = psutil.net_io_counters()
        dt = now - self.prev_time

        if dt <= 0:
            dt = 1.0

        # Calculate rates (bytes/sec)
        bytes_sent_rate = (counters.bytes_sent - self.prev_counters.bytes_sent) / dt
        bytes_recv_rate = (counters.bytes_recv - self.prev_counters.bytes_recv) / dt
        packets_sent_rate = (counters.packets_sent - self.prev_counters.packets_sent) / dt
        packets_recv_rate = (counters.packets_recv - self.prev_counters.packets_recv) / dt

        # Connection counts by state
        try:
            conns = psutil.net_connections(kind='inet')
            conn_states = {}
            for c in conns:
                state = c.status if c.status else "NONE"
                conn_states[state] = conn_states.get(state, 0) + 1
        except (psutil.AccessDenied, PermissionError):
            conns = []
            conn_states = {"UNKNOWN": 0}

        # Per-interface stats
        per_iface = {}
        iface_counters = psutil.net_io_counters(pernic=True)
        iface_addrs = psutil.net_if_addrs()
        iface_stats = psutil.net_if_stats()
        for name, cnt in iface_counters.items():
            addrs = []
            if name in iface_addrs:
                for addr in iface_addrs[name]:
                    if addr.family == socket.AF_INET:
                        addrs.append(addr.address)
            is_up = iface_stats[name].isup if name in iface_stats else False
            speed = iface_stats[name].speed if name in iface_stats else 0
            per_iface[name] = {
                "bytes_sent": cnt.bytes_sent,
                "bytes_recv": cnt.bytes_recv,
                "packets_sent": cnt.packets_sent,
                "packets_recv": cnt.packets_recv,
                "errors_in": cnt.errin,
                "errors_out": cnt.errout,
                "drops_in": cnt.dropin,
                "drops_out": cnt.dropout,
                "ip": addrs[0] if addrs else "—",
                "is_up": is_up,
                "speed": speed,
            }

        data_point = {
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "bytes_sent_rate": round(bytes_sent_rate),
            "bytes_recv_rate": round(bytes_recv_rate),
            "packets_sent_rate": round(packets_sent_rate),
            "packets_recv_rate": round(packets_recv_rate),
            "total_bytes_sent": counters.bytes_sent,
            "total_bytes_recv": counters.bytes_recv,
            "total_packets_sent": counters.packets_sent,
            "total_packets_recv": counters.packets_recv,
            "errors_in": counters.errin,
            "errors_out": counters.errout,
            "drops_in": counters.dropin,
            "drops_out": counters.dropout,
            "connections": len(conns),
            "conn_states": conn_states,
            "interfaces": per_iface,
        }

        with self.lock:
            self.history.append(data_point)

        self.prev_counters = counters
        self.prev_time = now

    def get_latest(self):
        """Get the most recent data point."""
        with self.lock:
            return self.history[-1] if self.history else {}

    def get_history(self):
        """Get all stored data points."""
        with self.lock:
            return list(self.history)

    def start(self):
        """Start background collection thread."""
        self.running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def stop(self):
        self.running = False

    def _loop(self):
        while self.running:
            self.sample()
            time.sleep(SAMPLE_INTERVAL)


# ─── Web Dashboard ─────────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Monitor</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f172a;color:#e2e8f0;font-family:'Inter',-apple-system,sans-serif;padding:20px}
h1{color:#38bdf8;margin-bottom:20px;font-size:1.8rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px}
.card h3{color:#94a3b8;font-size:0.8rem;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.card .value{font-size:1.8rem;font-weight:bold;color:#f8fafc}
.card .unit{font-size:0.9rem;color:#64748b;margin-left:4px}
.card.up .value{color:#4ade80}
.card.down .value{color:#38bdf8}
.card.warn .value{color:#fbbf24}
.section{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;margin-bottom:24px}
.section h2{color:#38bdf8;font-size:1.2rem;margin-bottom:16px}
canvas{width:100%!important;height:200px!important;border-radius:8px}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:#94a3b8;font-size:0.8rem;text-transform:uppercase;padding:8px;border-bottom:1px solid #334155}
td{padding:8px;border-bottom:1px solid #1e293b;font-size:0.9rem}
.status-up{color:#4ade80}
.status-down{color:#ef4444}
.conn-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:0.75rem;margin:2px;background:#334155}
.conn-badge.ESTABLISHED{background:#065f46;color:#6ee7b7}
.conn-badge.LISTEN{background:#1e3a5f;color:#93c5fd}
.conn-badge.TIME_WAIT{background:#78350f;color:#fde68a}
.conn-badge.CLOSE_WAIT{background:#7f1d1d;color:#fca5a5}
footer{text-align:center;color:#475569;margin-top:30px;font-size:0.85rem}
</style>
</head>
<body>
<h1>Network Monitor</h1>

<div class="grid">
  <div class="card down"><h3>Download</h3><div class="value" id="dl-rate">—</div></div>
  <div class="card up"><h3>Upload</h3><div class="value" id="ul-rate">—</div></div>
  <div class="card"><h3>Connections</h3><div class="value" id="conn-count">—</div></div>
  <div class="card"><h3>Packets/sec</h3><div class="value" id="pkt-rate">—</div></div>
  <div class="card warn"><h3>Errors</h3><div class="value" id="err-count">—</div></div>
  <div class="card warn"><h3>Drops</h3><div class="value" id="drop-count">—</div></div>
</div>

<div class="section">
  <h2>Traffic (last 2 minutes)</h2>
  <canvas id="chart"></canvas>
</div>

<div class="section">
  <h2>Connection States</h2>
  <div id="conn-states"></div>
</div>

<div class="section">
  <h2>Network Interfaces</h2>
  <table>
    <thead><tr><th>Interface</th><th>Status</th><th>IP</th><th>Speed</th><th>Sent</th><th>Received</th><th>Errors</th></tr></thead>
    <tbody id="iface-table"></tbody>
  </table>
</div>

<footer>Network Monitor Dashboard — Refreshes every second</footer>

<script>
const chart=document.getElementById('chart');
const ctx=chart.getContext('2d');
let dlHistory=[],ulHistory=[],labels=[];

function formatBytes(b){
  if(b>=1073741824)return (b/1073741824).toFixed(1)+' GB';
  if(b>=1048576)return (b/1048576).toFixed(1)+' MB';
  if(b>=1024)return (b/1024).toFixed(1)+' KB';
  return b+' B';
}

function formatRate(b){
  if(b>=1048576)return (b/1048576).toFixed(1)+' MB/s';
  if(b>=1024)return (b/1024).toFixed(1)+' KB/s';
  return b+' B/s';
}

function drawChart(){
  const w=chart.width=chart.offsetWidth;
  const h=chart.height=200;
  ctx.clearRect(0,0,w,h);

  if(dlHistory.length<2)return;

  const allVals=[...dlHistory,...ulHistory];
  const maxVal=Math.max(...allVals,1024);
  const pad={top:10,bottom:25,left:60,right:20};
  const cw=w-pad.left-pad.right;
  const ch=h-pad.top-pad.bottom;

  // Grid
  ctx.strokeStyle='#1e293b';ctx.lineWidth=1;
  for(let i=0;i<=4;i++){
    const y=pad.top+ch*(i/4);
    ctx.beginPath();ctx.moveTo(pad.left,y);ctx.lineTo(w-pad.right,y);ctx.stroke();
    ctx.fillStyle='#475569';ctx.font='11px sans-serif';ctx.textAlign='right';
    ctx.fillText(formatRate(maxVal*(1-i/4)),pad.left-8,y+4);
  }

  // Labels
  const step=Math.max(1,Math.floor(labels.length/6));
  ctx.fillStyle='#475569';ctx.font='11px sans-serif';ctx.textAlign='center';
  for(let i=0;i<labels.length;i+=step){
    const x=pad.left+cw*(i/(labels.length-1));
    ctx.fillText(labels[i],x,h-4);
  }

  function drawLine(data,color){
    ctx.beginPath();ctx.strokeStyle=color;ctx.lineWidth=2;
    for(let i=0;i<data.length;i++){
      const x=pad.left+cw*(i/(data.length-1));
      const y=pad.top+ch*(1-data[i]/maxVal);
      if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);
    }
    ctx.stroke();
    // Fill
    ctx.lineTo(pad.left+cw,pad.top+ch);ctx.lineTo(pad.left,pad.top+ch);ctx.closePath();
    ctx.fillStyle=color.replace('1)','0.1)');ctx.fill();
  }

  drawLine(dlHistory,'rgba(56,189,248,1)');
  drawLine(ulHistory,'rgba(74,222,128,1)');

  // Legend
  ctx.fillStyle='rgba(56,189,248,1)';ctx.fillRect(w-140,8,12,3);
  ctx.fillStyle='#94a3b8';ctx.font='11px sans-serif';ctx.textAlign='left';ctx.fillText('Download',w-124,12);
  ctx.fillStyle='rgba(74,222,128,1)';ctx.fillRect(w-140,20,12,3);
  ctx.fillStyle='#94a3b8';ctx.fillText('Upload',w-124,24);
}

async function update(){
  try{
    const res=await fetch('/api/history');
    const data=await res.json();
    if(!data.length)return;

    const latest=data[data.length-1];
    document.getElementById('dl-rate').innerHTML=formatRate(latest.bytes_recv_rate)+'<span class="unit">/s</span>';
    document.getElementById('ul-rate').innerHTML=formatRate(latest.bytes_sent_rate)+'<span class="unit">/s</span>';
    document.getElementById('conn-count').textContent=latest.connections;
    document.getElementById('pkt-rate').textContent=Math.round(latest.packets_sent_rate+latest.packets_recv_rate);
    document.getElementById('err-count').textContent=latest.errors_in+latest.errors_out;
    document.getElementById('drop-count').textContent=latest.drops_in+latest.drops_out;

    dlHistory=data.map(d=>d.bytes_recv_rate);
    ulHistory=data.map(d=>d.bytes_sent_rate);
    labels=data.map(d=>d.timestamp);
    drawChart();

    // Connection states
    const stDiv=document.getElementById('conn-states');
    stDiv.innerHTML='';
    for(const[state,count] of Object.entries(latest.conn_states||{})){
      stDiv.innerHTML+=`<span class="conn-badge ${state}">${state}: ${count}</span> `;
    }

    // Interfaces
    const tbody=document.getElementById('iface-table');
    tbody.innerHTML='';
    for(const[name,info] of Object.entries(latest.interfaces||{})){
      const status=info.is_up?'<span class="status-up">UP</span>':'<span class="status-down">DOWN</span>';
      const speed=info.speed?info.speed+'Mbps':'—';
      tbody.innerHTML+=`<tr>
        <td><strong>${name}</strong></td>
        <td>${status}</td>
        <td>${info.ip}</td>
        <td>${speed}</td>
        <td>${formatBytes(info.bytes_sent)}</td>
        <td>${formatBytes(info.bytes_recv)}</td>
        <td>${info.errors_in+info.errors_out}</td>
      </tr>`;
    }
  }catch(e){console.error(e)}
}

setInterval(update,1000);
update();
window.addEventListener('resize',drawChart);
</script>
</body>
</html>"""


def create_app(collector):
    """Create the Flask web application."""
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)

    @app.route("/api/latest")
    def api_latest():
        return jsonify(collector.get_latest())

    @app.route("/api/history")
    def api_history():
        return jsonify(collector.get_history())

    return app


# ─── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Network Monitor Dashboard — Real-time traffic visualization"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=5000,
        help="Web dashboard port (default: 5000)"
    )
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print stats as JSON to stdout instead of starting web server"
    )
    args = parser.parse_args()

    collector = NetworkCollector()
    collector.start()

    if args.json:
        # CLI-only mode: print stats to stdout
        try:
            while True:
                time.sleep(1)
                data = collector.get_latest()
                if data:
                    print(json.dumps({
                        "time": data["timestamp"],
                        "dl": data["bytes_recv_rate"],
                        "ul": data["bytes_sent_rate"],
                        "conns": data["connections"],
                        "pkts": data["packets_sent_rate"] + data["packets_recv_rate"],
                    }))
                    sys.stdout.flush()
        except KeyboardInterrupt:
            print("\nStopped.")
            return

    print(f"\n  Network Monitor Dashboard")
    print(f"  Open http://{args.host}:{args.port} in your browser")
    print(f"  Press Ctrl+C to stop\n")

    app = create_app(collector)
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

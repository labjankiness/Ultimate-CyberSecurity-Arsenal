import sys
import re
import requests
import sqlite3
import json
from datetime import datetime

class GuardianAnalyzer:
    def __init__(self, db_path='incidents.db'):
        self.conn = sqlite3.connect(db_path)
        self.create_table()
        self.patterns = {
            'brute_force': r"Failed password for (?:invalid user )?(\S+) from ([\d\.]+) port (\d+)",
            'invalid_user': r"Invalid user (\S+) from ([\d\.]+)",
            'successful_login': r"Accepted password for (\S+) from ([\d\.]+)"
        }

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                username TEXT,
                ip_address TEXT,
                raw_log TEXT,
                ai_summary TEXT
            )
        ''')
        self.conn.commit()

    def parse_line(self, line):
        for event_type, pattern in self.patterns.items():
            match = re.search(pattern, line)
            if match:
                groups = match.groups()
                return {
                    'event_type': event_type,
                    'username': groups[0],
                    'ip_address': groups[1],
                    'raw_log': line.strip()
                }
        return None

    def get_ai_insight(self, logs):
        prompt = f"Analyze these SSH security logs and provide a concise threat report. Focus on IP reputation risk and attack patterns:\n\n" + "\n".join(logs)
        try:
            response = requests.post('http://localhost:11434/api/generate', 
                                     json={'model': 'llama3', 'prompt': prompt, 'stream': False},
                                     timeout=10)
            return response.json().get('response', 'AI analysis unavailable.')
        except Exception:
            return "Connection to Ollama failed. AI insight skipped."

    def analyze(self, log_file):
        print(f"[*] Starting analysis: {log_file}")
        incidents = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    parsed = self.parse_line(line)
                    if parsed:
                        incidents.append(parsed)
        except FileNotFoundError:
            print(f"[!] Error: {log_file} not found.")
            return

        if not incidents:
            print("[+] No critical security events detected.")
            return

        # Group by IP for AI context
        ip_groups = {}
        for inc in incidents:
            ip = inc['ip_address']
            if ip not in ip_groups: ip_groups[ip] = []
            ip_groups[ip].append(inc['raw_log'])

        print(f"[*] Found {len(incidents)} suspicious events across {len(ip_groups)} unique IPs.")

        cursor = self.conn.cursor()
        for ip, logs in ip_groups.items():
            print(f"[*] Requesting AI insight for IP: {ip}")
            summary = self.get_ai_insight(logs[:15])
            
            for inc in incidents:
                if inc['ip_address'] == ip:
                    cursor.execute('''
                        INSERT INTO security_incidents (timestamp, event_type, username, ip_address, raw_log, ai_summary)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (datetime.now().isoformat(), inc['event_type'], inc['username'], inc['ip_address'], inc['raw_log'], summary))
        
        self.conn.commit()
        print(f"[+] Analysis complete. {len(incidents)} entries recorded in database.")

    def export_json(self, output_file='report.json'):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM security_incidents ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        
        data = []
        for row in rows:
            data.append({
                'id': row[0],
                'timestamp': row[1],
                'event_type': row[2],
                'username': row[3],
                'ip_address': row[4],
                'raw_log': row[5],
                'ai_summary': row[6]
            })
            
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[+] JSON Report exported to {output_file}")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else 'sample_logs/auth.log'
    guardian = GuardianAnalyzer()
    guardian.analyze(path)
    guardian.export_json()

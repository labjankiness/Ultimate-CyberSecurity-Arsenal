import socket
import logging
import datetime
import os
import sqlite3
import threading

class IoTHoneypot:
    def __init__(self, db_path='logs/honeypot.db'):
        if not os.path.exists('logs'):
            os.makedirs('logs')
        self.db_path = db_path
        self.init_db()
        logging.basicConfig(filename='logs/honeypot.log', level=logging.INFO, 
                            format='%(asctime)s - %(message)s')

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip_address TEXT,
                port INTEGER,
                payload TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def log_to_db(self, ip, port, payload):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO connections (timestamp, ip_address, port, payload)
            VALUES (?, ?, ?, ?)
        ''', (datetime.datetime.now().isoformat(), ip, port, payload))
        conn.commit()
        conn.close()

    def start_listener(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(5)
            print(f"[*] Honeypot active on port {port}")
            
            while True:
                client, addr = s.accept()
                logging.info(f"Conn: {addr[0]} -> {port}")
                payload = ""
                try:
                    data = client.recv(1024)
                    if data:
                        payload = data.decode('utf-8', errors='ignore')
                        logging.info(f"Payload from {addr[0]} on {port}: {payload}")
                    
                    self.log_to_db(addr[0], port, payload)
                    client.send(b"Connection refused by administrator.\n")
                except Exception as e:
                    logging.error(f"Error on port {port}: {e}")
                finally:
                    client.close()
        except Exception as e:
            print(f"[!] Critical failure on port {port}: {e}")

    def run(self, ports):
        threads = []
        for port in ports:
            t = threading.Thread(target=self.start_listener, args=(port,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        print("[+] IoT Honeypot is running. Press Ctrl+C to stop.")
        try:
            while True: threading.Event().wait(1)
        except KeyboardInterrupt:
            print("\n[!] Shutting down...")

if __name__ == "__main__":
    hp = IoTHoneypot()
    hp.run([80, 8080, 554, 23, 1883, 21])

"""
SSH Honeypot — Fake SSH server that logs all connection attempts.

Listens on a configurable port (default 2222), captures connection
metadata, credentials, and optionally records commands in a fake shell.
All data is stored in SQLite for analytics.

Usage:
    python honeypot.py                 # Listen on port 2222
    python honeypot.py --port 2223     # Custom port
    python honeypot.py --shell         # Enable fake shell recording
"""

import argparse
import socket
import sys
import threading
import time
from typing import Optional

from database import init_db, store_connection, store_command
from geo_lookup import lookup_ip


SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
MAX_CONNECTIONS = 50
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 20     # max connections per IP per window


class SSHHoneypot:
    """Fake SSH server that captures connection attempts."""

    def __init__(self, host: str = "0.0.0.0", port: int = 2222, enable_shell: bool = False) -> None:
        """Initialize the honeypot server.

        Args:
            host: Bind address.
            port: Listening port (default 2222).
            enable_shell: If True, simulate a fake shell after "login".
        """
        self.host = host
        self.port = port
        self.enable_shell = enable_shell
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self._rate_tracker: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _check_rate_limit(self, ip: str) -> bool:
        """Check if an IP has exceeded the rate limit.

        Args:
            ip: Source IP address.

        Returns:
            True if the connection should be allowed.
        """
        now = time.time()
        with self._lock:
            if ip not in self._rate_tracker:
                self._rate_tracker[ip] = []

            # Remove old entries
            self._rate_tracker[ip] = [
                t for t in self._rate_tracker[ip]
                if now - t < RATE_LIMIT_WINDOW
            ]

            if len(self._rate_tracker[ip]) >= RATE_LIMIT_MAX:
                return False

            self._rate_tracker[ip].append(now)
            return True

    def _handle_connection(self, client_socket: socket.socket, addr: tuple) -> None:
        """Handle a single incoming connection.

        Args:
            client_socket: The connected client socket.
            addr: (ip, port) tuple.
        """
        source_ip, source_port = addr
        start_time = time.time()
        client_banner = ""
        username = ""
        password = ""
        connection_id = None

        try:
            # Rate limit check
            if not self._check_rate_limit(source_ip):
                print(f"  [RATE LIMITED] {source_ip}:{source_port}")
                client_socket.close()
                return

            print(f"  [CONNECT] {source_ip}:{source_port}")

            # Send SSH banner
            client_socket.settimeout(30)
            client_socket.send(SSH_BANNER)

            # Receive client banner
            try:
                data = client_socket.recv(1024)
                if data:
                    client_banner = data.decode("utf-8", errors="replace").strip()
                    print(f"  [BANNER] {source_ip}: {client_banner[:80]}")
            except (socket.timeout, ConnectionResetError):
                pass

            # Simulate SSH authentication prompt
            # In a real SSH protocol this would be the key exchange, but for
            # a honeypot we simulate a simple username/password capture
            try:
                client_socket.send(b"\r\nlogin: ")
                data = client_socket.recv(256)
                if data:
                    username = data.decode("utf-8", errors="replace").strip()

                client_socket.send(b"password: ")
                data = client_socket.recv(256)
                if data:
                    password = data.decode("utf-8", errors="replace").strip()
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                pass

            # Geo lookup
            geo = lookup_ip(source_ip)

            # Store connection
            session_duration = time.time() - start_time
            connection_id = store_connection({
                "source_ip": source_ip,
                "source_port": source_port,
                "username": username,
                "password": password,
                "client_banner": client_banner,
                "geo_country": geo["country"],
                "geo_city": geo["city"],
                "session_duration": session_duration,
            })

            print(f"  [AUTH] {source_ip} → user='{username}' pass='{password}' "
                  f"[{geo['country']}] (#{connection_id})")

            # Fake shell mode
            if self.enable_shell and username and connection_id:
                self._fake_shell(client_socket, source_ip, connection_id)
            else:
                # Reject with realistic error
                client_socket.send(b"\r\nPermission denied (publickey,password).\r\n")

        except Exception as e:
            print(f"  [ERROR] {source_ip}: {e}")
        finally:
            try:
                client_socket.close()
            except Exception:
                pass
            duration = time.time() - start_time
            print(f"  [DISCONNECT] {source_ip}:{source_port} ({duration:.1f}s)")

    def _fake_shell(self, sock: socket.socket, ip: str, conn_id: int) -> None:
        """Simulate a fake bash shell to capture commands.

        Args:
            sock: Client socket.
            ip: Source IP for logging.
            conn_id: Database connection ID.
        """
        # Fake responses for common commands
        fake_responses = {
            "whoami": "root\n",
            "id": "uid=0(root) gid=0(root) groups=0(root)\n",
            "uname -a": "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
            "pwd": "/root\n",
            "ls": "Desktop  Documents  Downloads  .bashrc  .ssh\n",
            "ls -la": "total 32\ndrwx------  4 root root 4096 Mar 30 10:00 .\ndrwxr-xr-x 18 root root 4096 Mar 30 10:00 ..\n-rw-------  1 root root  220 Mar 30 10:00 .bash_history\n-rw-r--r--  1 root root 3771 Mar 30 10:00 .bashrc\ndrwx------  2 root root 4096 Mar 30 10:00 .ssh\n",
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0\n",
            "hostname": "honeypot\n",
            "uptime": " 10:00:00 up 42 days,  3:15,  1 user,  load average: 0.08, 0.03, 0.01\n",
            "w": " 10:00:00 up 42 days,  3:15,  1 user,  load average: 0.08, 0.03, 0.01\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    -                10:00    0.00s  0.00s  0.00s w\n",
        }

        try:
            sock.send(b"\r\nWelcome to Ubuntu 22.04.3 LTS\r\n\r\n")
            max_commands = 20

            for _ in range(max_commands):
                sock.send(b"root@honeypot:~# ")
                data = sock.recv(1024)
                if not data:
                    break

                cmd = data.decode("utf-8", errors="replace").strip()
                if not cmd:
                    continue

                # Store command
                store_command(conn_id, cmd)
                print(f"  [CMD] {ip}: {cmd}")

                if cmd in ("exit", "quit", "logout"):
                    sock.send(b"logout\r\n")
                    break

                # Send fake response
                response = fake_responses.get(cmd, f"bash: {cmd}: command not found\n")
                sock.send(response.encode())

        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass

    def start(self) -> None:
        """Start the honeypot server."""
        init_db()

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.server_socket.bind((self.host, self.port))
        except PermissionError:
            print(f"[!] Permission denied on port {self.port}. Try a port > 1024.")
            sys.exit(1)
        except OSError as e:
            print(f"[!] Cannot bind to {self.host}:{self.port}: {e}")
            sys.exit(1)

        self.server_socket.listen(MAX_CONNECTIONS)
        self.running = True

        shell_mode = " [SHELL MODE]" if self.enable_shell else ""
        print(f"[*] SSH Honeypot listening on {self.host}:{self.port}{shell_mode}")
        print(f"[*] Data stored in honeypot.db")
        print(f"[*] Press Ctrl+C to stop\n")

        try:
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client, addr = self.server_socket.accept()
                    thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client, addr),
                        daemon=True,
                    )
                    thread.start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            print("\n[*] Shutting down honeypot...")
        finally:
            self.running = False
            if self.server_socket:
                self.server_socket.close()
            print("[*] Honeypot stopped.")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="SSH Honeypot Server")
    parser.add_argument("--port", "-p", type=int, default=2222, help="Port to listen on (default: 2222)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--shell", action="store_true", help="Enable fake shell recording")
    args = parser.parse_args()

    honeypot = SSHHoneypot(host=args.host, port=args.port, enable_shell=args.shell)
    honeypot.start()


if __name__ == "__main__":
    main()

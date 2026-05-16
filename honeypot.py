import os
import time
import threading
import queue
import re
import socket
import sqlite3
import hashlib
import json
from flask import Flask, request, render_template
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed

app = Flask(__name__)
DB_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "honeypot_events.db"))

# --- THREAD-SAFE LOGGING ASYNC WORKER QUEUE ---
log_queue = queue.Queue()

def log_worker():
    """Background worker that continuously processes and writes logs sequentially."""
    while True:
        log_data = log_queue.get()
        if log_data is None:
            break
        ip, timestamp, detected_type, severity, payload, source, user_agent, fingerprint, score = log_data
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("""
                    INSERT INTO attack_logs (ip, timestamp, type, severity, payload, source, user_agent, fingerprint, score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (ip, timestamp, detected_type, severity, payload, source, user_agent, fingerprint, score))
                conn.commit()
        except Exception as e:
            print(f"[DB LOG ERROR] {e}")
        finally:
            log_queue.task_done()

# Start the dedicated background writer thread
threading.Thread(target=log_worker, daemon=True).start()

# --- SQLITE PERSISTENT STORAGE INITIALIZATION ---
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                timestamp TEXT,
                type TEXT,
                severity TEXT,
                payload TEXT,
                source TEXT,
                user_agent TEXT,
                fingerprint TEXT,
                score INTEGER
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON attack_logs(ip);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON attack_logs(timestamp);")
        conn.commit()

# --- SECURITY ENGINE ---
class SecurityEngine:
    def __init__(self):
        self.weights = {
            "BRUTE_FORCE": 15,
            "PATH_TRAVERSAL": 25,
            "SQL_INJECTION": 20,
            "XSS_ATTACK": 15,
            "SUSPICIOUS_COMMAND": 30,
            "GENERIC_SCAN": 5
        }
        self.signatures = {
            "SQL_INJECTION": r"(?i)(select|union|insert|delete|drop|' or '1'='1|--|#)",
            "PATH_TRAVERSAL": r"(?i)(\.\.\/|\/\.\.|/etc/passwd|/etc/shadow|/bin/sh|/windows/win.ini)",
            "XSS_ATTACK": r"(?i)(<script|javascript:|alert\(|onerror|onload=)",
        }

    def generate_fingerprint(self, ip, user_agent):
        fingerprint_input = f"{ip}:{user_agent}"
        return hashlib.md5(fingerprint_input.encode()).hexdigest()

    def evaluate_and_log(self, ip, source, payload, user_agent="Unknown/Direct", forced_type=None):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        detected_type = "GENERIC_SCAN"
        score = self.weights["GENERIC_SCAN"]

        if forced_type:
            detected_type = forced_type
            score = self.weights.get(forced_type, 10)
        else:
            payload_str = str(payload).lower()
            for attack_name, pattern in self.signatures.items():
                if re.search(pattern, payload_str):
                    detected_type = attack_name
                    score = self.weights[attack_name]
                    break

        if score >= 25:
            severity = "CRITICAL"
        elif score >= 15:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        fingerprint = self.generate_fingerprint(ip, user_agent)
        
        # FIXED: Pass logs to the thread-safe queue instantly instead of blocking pyftpdlib
        log_queue.put((ip, timestamp, detected_type, severity, str(payload), source, user_agent, fingerprint, score))

engine = SecurityEngine()

# --- PROTOCOL SERVICE 1: HTTP CORE HONEYPOT TRAP ---
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def http_trap(path):
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    payload_elements = {
        "uri_path": f"/{path}",
        "get_params": dict(request.args),
        "post_data": dict(request.form) if request.method == 'POST' else {}
    }
    engine.evaluate_and_log(ip, "HTTP_SERVER", json.dumps(payload_elements), user_agent)
    return render_template('login.html'), 200

# --- PROTOCOL SERVICE 2: FTP ADVANCED PORT DECEPTION ---
class LoggingAuthorizer(DummyAuthorizer):
    def validate_authentication(self, username, password, handler):
        try:
            super().validate_authentication(username, password, handler)
        except AuthenticationFailed:
            # FIXED: Queued immediately before thread teardown occurs
            handler.log_action(
                "FTP_SERVER", 
                f"Failed authentication attempt - Username: {username} | Password: {password}", 
                "BRUTE_FORCE"
            )
            raise
        else:
            # FIXED: Queued immediately upon successful authentication
            handler.log_action(
                "FTP_SERVER", 
                f"Successful exploit entry - Username: {username} | Password: {password}", 
                "BRUTE_FORCE"
            )

class MonitoredFTPHandler(FTPHandler):
    def log_action(self, source, payload, forced_type):
        engine.evaluate_and_log(self.remote_ip, source, payload, forced_type=forced_type)

    def process_command(self, cmd, *args, **kwargs):
        cmd_upper = cmd.upper()
        if cmd_upper not in ['USER', 'PASS']:
            arg_str = str(args[0]) if args and args[0] else ""
            payload_str = f"[COMMAND] {cmd_upper} {arg_str}".strip()
            
            if cmd_upper in ['SYST', 'FEAT', 'PWD', 'TYPE', 'PASV', 'EPSV', 'PORT']:
                current_threat_type = "GENERIC_SCAN"
            else:
                current_threat_type = "SUSPICIOUS_COMMAND"
                
            self.log_action("FTP_INTERACTIVE", payload_str, current_threat_type)
            
        super().process_command(cmd, *args, **kwargs)

    def on_incomplete_file_received(self, file):
        if os.path.exists(file):
            os.remove(file)

def start_ftp_server():
    os.makedirs("fake_fs", exist_ok=True)
    authorizer = LoggingAuthorizer()
    creds = [("admin", "1234"), ("root", "root"), ("user", "password")]
    for u, p in creds:
        authorizer.add_user(u, p, "fake_fs", perm="elradfmw")
        
    handler = MonitoredFTPHandler
    handler.authorizer = authorizer
    handler.banner = "220 FTP Standard Authentication Daemon Ready."
    server = FTPServer(("0.0.0.0", 2121), handler)
    server.serve_forever()

# --- PROTOCOL SERVICE 3: TELNET COMMAND EMULATION ---
def handle_telnet_session(client_socket, addr):
    ip = addr[0]
    client_socket.settimeout(30.0)
    try:
        client_socket.send(b"Ubuntu 22.04.3 LTS\n\rserver1 login: ")
        username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        client_socket.send(b"Password: ")
        password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()

        engine.evaluate_and_log(
            ip, 
            "TELNET_SHELL", 
            f"Terminal Authentication Input - User: {username} | Pass: {password}", 
            forced_type="BRUTE_FORCE"
        )
        
        client_socket.send(b"\n\rWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\n\rroot@production-srv:~# ")

        while True:
            command_bytes = client_socket.recv(1024)
            if not command_bytes:
                break
            command = command_bytes.decode('utf-8', errors='ignore').strip()
            if command.lower() in ["exit", "logout", "quit"]:
                break
            if not command:
                client_socket.send(b"root@production-srv:~# ")
                continue

            engine.evaluate_and_log(ip, "TELNET_INTERACTIVE", f"Executed shell input: '{command}'", forced_type="SUSPICIOUS_COMMAND")
            responses = {
                "ls": "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
                "whoami": "root",
                "id": "uid=0(root) gid=0(root) groups=0(root)",
                "pwd": "/root"
            }
            response_output = responses.get(command.lower(), f"bash: {command}: command not found")
            client_socket.send(f"{response_output}\n\rroot@production-srv:~# ".encode('utf-8'))
    except Exception:
        pass
    finally:
        client_socket.close()

def start_telnet_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 2323))
    server.listen(50)
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_telnet_session, args=(client, addr), daemon=True).start()

if __name__ == "__main__":
    print("HoneyPot Services running Successfully Access it on:-")
    print("HTTP :- 5000")
    print("FTP :- 2121")
    print("TELNET :- 2323")
    init_db()
    threading.Thread(target=start_ftp_server, daemon=True).start()
    threading.Thread(target=start_telnet_server, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

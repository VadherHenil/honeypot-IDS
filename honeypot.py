import os, time, threading, json, re, socket
from flask import Flask, request, render_template, jsonify
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer
from collections import defaultdict
import hashlib

app = Flask(__name__)
LOG_FILE = os.path.join(os.getcwd(), "logs.txt")

# --- MD5 FINGERPRINT GENERATOR ---
def generate_fingerprint(ip, user_agent, timestamp=None):
    """Generate MD5 fingerprint like 294202597930eea63be68cc03fa5b0f8"""
    if timestamp is None:
        timestamp = str(int(time.time()))
    
    # Create unique fingerprint: IP + UA + timestamp
    fingerprint_input = f"{ip}:{user_agent}:{timestamp}"
    return hashlib.md5(fingerprint_input.encode()).hexdigest()

# --- SECURITY ENGINE ---
class SecurityEngine:
    def __init__(self):
        self.request_counts = defaultdict(list)
        self.lock = threading.Lock()
        self.client_fingerprints = defaultdict(list)
        self.signatures = {
            "SQL_INJECTION": {"pattern": r"(?i)(select|union|insert|delete|drop|;)", "severity": "CRITICAL"},
            "XSS_ATTACK": {"pattern": r"(?i)(<script|javascript:|alert|onload)", "severity": "HIGH"},
            "PATH_TRAVERSAL": {"pattern": r"(?i)(\.\./|/\.\.|\/etc\/|\/bin\/|\/root\/)", "severity": "HIGH"},
            "COMMAND_INJECTION": {"pattern": r"(?i)(;|&&|whoami|cat\s|/bin/)", "severity": "CRITICAL"},
            "LDAP_INJECTION": {"pattern": r"(?i)(\*\$|\s*\$|\s*&\s*\$|\\\\$)", "severity": "HIGH"},
            "SSRF": {"pattern": r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0)", "severity": "HIGH"},
            "BRUTE_FORCE": {"pattern": r"(?i)(admin|root|123456|ftp|user)", "severity": "MEDIUM"}
        }

    def is_rate_limited(self, ip):
        with self.lock:
            now = time.time()
            self.request_counts[str(ip)] = [t for t in self.request_counts[str(ip)] if now - t < 1.0]
            self.request_counts[str(ip)].append(now)
            return len(self.request_counts[str(ip)]) > 20

    def evaluate_risk(self, payload, service):
        try:
            p_check = str(payload).upper()
            for name, info in self.signatures.items():
                if re.search(info["pattern"], p_check):
                    return name, info["severity"]
        except: pass
        if "LOGIN" in service: return "BRUTE_FORCE", "MEDIUM"
        return "ACTIVITY", "INFO"

    def log_event(self, ip, service, status, payload, user_agent="Unknown"):
        try:
            if self.is_rate_limited(ip): return False
            category, severity = self.evaluate_risk(payload, service)
            
            timestamp = str(int(time.time() * 1000))
            fingerprint = generate_fingerprint(ip, user_agent, timestamp)
            
            entry = {
                "time": time.strftime('%Y-%m-%d %H:%M:%S'),
                "ip": str(ip) if ip else "UNKNOWN",
                "type": category,
                "payload": f"[{status}] {payload}",
                "severity": severity,
                "source": service,
                "fingerprint": fingerprint,
                "user_agent": user_agent
            }
            
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
            return True
        except:
            return False

engine = SecurityEngine()

# --- HTTP ROUTES (UNCHANGED) ---
@app.route("/", methods=["GET", "POST"])
def index():
    ip = request.headers.get('CF-Connecting-IP', request.remote_addr)
    
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        if username == "admin" and password == "1234":
            engine.log_event(ip, "HTTP_LOGIN", "SUCCESS", f"User: {username}, Password: {password}", user_agent)
            return render_template("admin.html")
        else:
            engine.log_event(ip, "HTTP_LOGIN", "FAILED", f"User: {username}, Password: {password}", user_agent)
            
    user_agent = request.headers.get('User-Agent', 'Unknown')
    engine.log_event(ip, "HTTP_PAGEVIEW", "GET", request.path, user_agent)
    return render_template("login.html")

@app.route("/api/data")
def api_data():
    res = {"ips": {}, "stats": {"total": 0}}
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                try:
                    log = json.loads(line.strip())
                    ip_addr = log["ip"]
                    if ip_addr not in res["ips"]:
                        res["ips"][ip_addr] = {
                            "count": 0, 
                            "logs": [],
                            "fingerprint": log.get("fingerprint", "Unknown"),
                            "user_agent": log.get("user_agent", "Unknown")
                        }
                    res["ips"][ip_addr]["count"] += 1
                    res["ips"][ip_addr]["logs"].append(log)
                    res["stats"]["total"] += 1
                except: continue
    return jsonify(res)

# --- TELNET SECTION ---
telnet_commands = defaultdict(list)

def start_telnet():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('0.0.0.0', 2323))
        s.listen(10)
        print("✅ TELNET READY - port 2323")
    except Exception as e:
        print(f"❌ TELNET ERROR: {e}")
        return

    while True:
        c, a = s.accept()
        def handle(conn, addr):
            ip = addr[0]
            try:
                conn.send(b"\r\nUsername: ")
                u = conn.recv(1024).decode(errors='ignore').strip()
                conn.send(b"Password: ")
                p = conn.recv(1024).decode(errors='ignore').strip()
                
                engine.log_event(ip, "TELNET_LOGIN", "FAILED", f"User: {u}, Password: {p}", "TelnetClient")
                
                if u == "admin" and p == "1234":
                    engine.log_event(ip, "TELNET_LOGIN", "SUCCESS", f"User: {u}, Password: {p}", "TelnetClient")
                    conn.send(b"Welcome admin!\r\n")
                    while True:
                        conn.send(b"$ ")
                        d = conn.recv(1024).decode(errors='ignore').strip()
                        if not d or d.lower() in ["exit", "quit"]:
                            break
                        telnet_commands[ip].append(d)
                        engine.log_event(ip, "TELNET_COMMAND", "EXEC", d, "TelnetClient")
                        conn.send(b"command not found\r\n")
                else:
                    conn.send(b"Login failed\r\n")
            except Exception as e:
                engine.log_event(ip, "TELNET", "ERROR", f"Connection error: {str(e)}", "TelnetClient")
            finally: 
                conn.close()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()

# --- FTP SECTION ---
class UltimateFTPHandler(FTPHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client_ip = None
        self.session_id = None
        self.ftp_commands = []
        self._captured_pass = None

    def on_connect(self):
        self.client_ip = self.remote_ip
        self.session_id = f"{self.client_ip}_{int(time.time())}"
        engine.log_event(self.client_ip, "FTP_CONNECT", "START", f"Session: {self.session_id}", "FTPClient")
        super().on_connect()

    def ftp_PASS(self, password):
        self._captured_pass = password
        return super().ftp_PASS(password)

    def on_login(self, username):
        full_p = getattr(self, '_captured_pass', 'N/A')
        engine.log_event(self.client_ip, "FTP_LOGIN", "SUCCESS", f"User: {username}, Password: {full_p}", "FTPClient")
        return super().on_login(username)

    def on_login_failed(self, username, password):
        engine.log_event(self.client_ip, "FTP_LOGIN", "FAILED", f"User: {username}, Password: {password}", "FTPClient")
        return super().on_login_failed(username, password)

    def raw_data_in(self, data):
        try:
            cmd_line = data.decode('utf-8', errors='ignore').rstrip('\r\n')
            if cmd_line:
                parts = cmd_line.split(None, 1)
                cmd = parts[0].upper()
                args = parts[1] if len(parts) > 1 else ""
                self.ftp_commands.append(f"{cmd} {args}".strip())
                
                if cmd != "PASS":
                    status = "POST_AUTH" if self.authenticated else "PRE_AUTH"
                    engine.log_event(
                        self.client_ip, 
                        f"FTP_{cmd}", 
                        status, 
                        f"Command: {cmd}, Args: {args}",
                        "FTPClient"
                    )
        except Exception as e:
            engine.log_event(self.client_ip, f"FTP_ERROR", "PARSE", f"Command parse error: {str(e)}", "FTPClient")
        return super().raw_data_in(data)

    def on_disconnect(self):
        engine.log_event(self.client_ip, "FTP_SESSION", "END", f"Session: {self.session_id}, Commands: {len(self.ftp_commands)}", "FTPClient")
        super().on_disconnect()

def start_ftp():
    os.makedirs("fake_fs", exist_ok=True)
    authorizer = DummyAuthorizer()
    creds = [("admin", "1234"), ("ftp", "1234"), ("user", "1234"), ("root", "1234")]
    for user, pwd in creds:
        authorizer.add_user(user, pwd, "fake_fs", perm="elradfmwMT")
    
    handler = UltimateFTPHandler
    handler.authorizer = authorizer
    handler.banner = "220 FTP Server Ready"
    server = FTPServer(("0.0.0.0", 2121), handler)
    server.serve_forever()

# --- MAIN ---
if __name__ == "__main__":
    print("🚨 HONEYPOT STARTING - MD5 FINGERPRINT + FULL UA")
    threading.Thread(target=start_ftp, daemon=True).start()
    threading.Thread(target=start_telnet, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, debug=False)

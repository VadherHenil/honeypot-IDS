from flask import Flask, request, render_template, redirect
import datetime, threading, os, json, requests, hashlib
import socket, paramiko

from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

app = Flask(__name__)

ATTACK_DB = {}
BLOCKED_IPS = set()
MAX_ATTEMPTS = 300
FTP_ROOT = "ftp_root"
LOG_FILE = "logs.txt"

# -------------------------------
# REAL IP
# -------------------------------
def get_real_ip(req):
    if req.headers.get("X-Forwarded-For"):
        return req.headers.get("X-Forwarded-For").split(",")[0]
    return req.remote_addr

# -------------------------------
# FINGERPRINT
# -------------------------------
def generate_fingerprint(req):
    data = req.headers.get("User-Agent","") + req.headers.get("Accept","")
    return hashlib.md5(data.encode()).hexdigest()

# -------------------------------
# CLASSIFICATION (AI BASIC)
# -------------------------------
def classify_attack(payload, source, success=False):
    payload = payload.lower()

    if success:
        return "Normal Activity"
    if source == "FTP":
        return "FTP Activity"
    if "union" in payload or "select" in payload:
        return "SQL Injection"
    if " or " in payload:
        return "SQL Injection"
    if "fail" in payload:
        return "Brute Force"

    return "Suspicious Input"

# -------------------------------
# LOG SYSTEM
# -------------------------------
def log_attack(ip, payload, severity, source, req=None, success=False):

    if ip in BLOCKED_IPS:
        return

    fingerprint = generate_fingerprint(req) if req else "unknown"
    attack_type = classify_attack(payload, source, success)

    # 🌍 LOCATION
    location = {"country":"Unknown","lat":20,"lon":0}
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        r = res.json()
        if r.get("status") == "success":
            location = {
                "country": r.get("country"),
                "lat": r.get("lat"),
                "lon": r.get("lon")
            }
    except:
        pass

    log_entry = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "payload": payload,
        "severity": severity,
        "source": source,
        "type": attack_type,
        "fingerprint": fingerprint,
        "location": location
    }

    # 🔥 WRITE TO FILE
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

# -------------------------------
# WEB LOGIN
# -------------------------------
@app.route("/", methods=["GET","POST"])
def index():
    ip = get_real_ip(request)

    if request.method == "POST":
        u = request.form.get("username","")
        p = request.form.get("password","")

        if u == "admin" and p == "1234":
            log_attack(ip, f"{u}:{p}", "LOW", "WEB", request, True)
            return redirect("/admin/dashboard")
        else:
            log_attack(ip, f"FAIL {u}:{p}", "HIGH", "WEB", request)

    return render_template("index.html")

# -------------------------------
# ADMIN
# -------------------------------
@app.route("/admin/dashboard")
def admin():
    return "<h1>Admin Panel</h1>"

# -------------------------------
# FTP
# -------------------------------
class HoneypotFTPHandler(FTPHandler):
    def on_login(self, username):
        log_attack(self.remote_ip, f"FTP LOGIN {username}", "LOW", "FTP", success=True)

    def on_login_failed(self, username, password):
        log_attack(self.remote_ip, f"FTP FAIL {username}:{password}", "HIGH", "FTP")

def start_ftp():
    os.makedirs(FTP_ROOT, exist_ok=True)

    auth = DummyAuthorizer()
    auth.add_user("admin","1234",FTP_ROOT,perm="elradfmw")

    handler = HoneypotFTPHandler
    handler.authorizer = auth

    FTPServer(("0.0.0.0",2121),handler).serve_forever()

# -------------------------------
# SSH
# -------------------------------
class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, ip):
        self.ip = ip

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_auth_password(self, username, password):
        log_attack(self.ip, f"SSH {username}:{password}", "HIGH", "SSH")
        return paramiko.AUTH_FAILED

def handle_ssh(client, addr):
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(paramiko.RSAKey.generate(2048))
        transport.start_server(server=FakeSSHServer(addr[0]))
    except:
        pass

def start_ssh():
    sock = socket.socket()
    sock.bind(("0.0.0.0",2222))
    sock.listen(5)

    while True:
        c,a = sock.accept()
        threading.Thread(target=handle_ssh,args=(c,a),daemon=True).start()

# -------------------------------
# MAIN
# -------------------------------
if __name__ == "__main__":
    threading.Thread(target=start_ftp,daemon=True).start()
    threading.Thread(target=start_ssh,daemon=True).start()
    app.run(host="0.0.0.0",port=5000)

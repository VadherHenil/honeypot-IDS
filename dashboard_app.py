from flask import Flask, render_template, jsonify
import json

app = Flask(__name__)

LOG_FILE = "logs.txt"

def read_logs():
    data = {}

    try:
        with open(LOG_FILE,"r") as f:
            for line in f:
                log = json.loads(line.strip())
                ip = log["ip"]

                if ip not in data:
                    data[ip] = {"count":0,"logs":[]}

                data[ip]["count"] += 1
                data[ip]["logs"].append(log)
    except:
        pass

    return data

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/data")
def api():
    return jsonify(read_logs())

@app.route("/attacker/<ip>")
def details(ip):
    data = read_logs()
    logs = data.get(ip, {"logs":[]})["logs"]

    location = {"country":"Unknown","lat":20,"lon":0}
    if logs:
        location = logs[-1].get("location", location)

    return render_template("details.html", ip=ip, data={"logs":logs}, location=location)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000)

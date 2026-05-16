import os
import re
import json  
import sqlite3
import requests
from flask import Flask, render_template, jsonify, request, Response
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
import datetime

app = Flask(__name__)

DB_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "honeypot_events.db")
)


# ===============================
# PAYLOAD CLEANER
# ===============================
def clean_payload(payload, source):
    if payload is None:
        return None

    original = str(payload).strip()
    if not original:
        return None

    # Handle HTTP JSON format variations
    try:
        parsed = json.loads(original)
        if isinstance(parsed, dict):
            post = parsed.get("post_data", {})
            uri = parsed.get("uri_path", "")
            if isinstance(post, dict):
                username = post.get("username")
                password = post.get("password")
                if username and password:
                    return f"{username}:{password}"
            if uri in ["/", "/favicon.ico"]:
                return None
            return uri
    except Exception:
        pass

    # FIXED: Unified parser that seamlessly extracts both failed and successful entries
    m = re.search(
        r'User(?:name)?:\s*([^\s|,]+).*?(?:Password|Pass)[:=]?\s*([^\s|,]+)',
        original,
        re.I
    )
    if m:
        return f"{m.group(1)}:{m.group(2)}"

    # Raw credentials fallback block
    m = re.match(r'^([^:\s]+):([^:\s]+)$', original)
    if m:
        return original

    # FTP post-auth commands cleaner
    if "FTP" in source:
        return (
            original
            .replace("[COMMAND]", "")
            .replace("[FAILED]", "")
            .strip()
        )

    return original

# ===============================
# READ SQLITE LOGS
# ===============================
def read_raw_logs():
    logs = []

    if not os.path.exists(DB_FILE):
        print("DB NOT FOUND:", DB_FILE)
        return logs

    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                ip,
                timestamp as time,
                type,
                severity,
                payload,
                source,
                user_agent,
                fingerprint,
                score
            FROM attack_logs
            ORDER BY id DESC
        """)

        rows = cursor.fetchall()

        for row in rows:
            logs.append(dict(row))

        conn.close()

        print(f"Loaded {len(logs)} attack logs")

    except Exception as e:
        print("DB ERROR:", e)

    return logs


# ===============================
# GEOLOOKUP
# ===============================
def get_location(ip):
    if ip in ["127.0.0.1", "UNKNOWN"] or ip.startswith("10.") or ip.startswith("192.168."):
        return {
            "city": "Local",
            "country": "Internal",
            "lat": 0,
            "lon": 0
        }

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,city,country,lat,lon",
            timeout=2
        )

        data = r.json()

        if data.get("status") == "success":
            return data

    except:
        pass

    return {
        "city": "Unknown",
        "country": "Unknown",
        "lat": 0,
        "lon": 0
    }


# ===============================
# DASHBOARD
# ===============================
@app.route("/")
def index():
    return render_template("dashboard.html")


# ===============================
# API DATA
# ===============================
@app.route("/api/data")
def api():
    raw_logs = read_raw_logs()
    organized = {}

    for log in raw_logs:
        cleaned = clean_payload(
            log.get("payload", ""),
            log.get("source", "")
        )

        if cleaned is None:
            continue

        ip = log.get("ip", "UNKNOWN")

        safe_log = dict(log)
        safe_log["payload"] = cleaned

        if ip not in organized:
            organized[ip] = {
                "count": 0,
                "logs": []
            }

        organized[ip]["count"] += 1
        organized[ip]["logs"].append(safe_log)

    return jsonify(organized)


# ===============================
# ATTACKER DETAILS
# ===============================
@app.route("/attacker/<ip>")
def attacker(ip):
    raw_logs = read_raw_logs()
    ip_logs = []
    fingerprint_history = {}

    for log in raw_logs:
        if log.get("ip") != ip:
            continue

        cleaned = clean_payload(
            log.get("payload", ""),
            log.get("source", "")
        )

        if cleaned is None:
            continue

        safe_log = dict(log)
        safe_log["payload"] = cleaned
        ip_logs.append(safe_log)

        fingerprint = safe_log.get("fingerprint") or "N/A"

        if fingerprint not in fingerprint_history:
            fingerprint_history[fingerprint] = {
                "user_agent": safe_log.get("user_agent", "Unknown"),
                "first_seen": safe_log.get("time", "N/A"),
                "attack_count": 0,
                "sources": set(),
                "sample_payloads": []
            }

        fingerprint_history[fingerprint]["attack_count"] += 1
        fingerprint_history[fingerprint]["sources"].add(
            safe_log.get("source", "Unknown")
        )

        fingerprint_history[fingerprint]["sample_payloads"].append({
            "time": safe_log.get("time", "N/A"),
            "payload": cleaned,
            "source": safe_log.get("source", "Unknown")
        })

    for fp in fingerprint_history.values():
        fp["sources"] = list(fp["sources"])
        fp["sample_payloads"] = fp["sample_payloads"][:3]

    location = get_location(ip)
    fps = list(fingerprint_history.keys())

    context_data = {
        "logs": ip_logs,
        "total_attacks": len(ip_logs),
        "fingerprint_count": len(fps),
        "unique_fingerprints": fps,
        "primary_fingerprint": fps[0] if fps else "N/A",
        "first_seen": ip_logs[0]["time"] if ip_logs else "N/A",
        "fingerprint_history": fingerprint_history,
        "geo_city": location.get("city", "Unknown"),
        "geo_country": location.get("country", "Unknown"),
        "geo_lat": location.get("lat", 0),
        "geo_lon": location.get("lon", 0)
    }

    return render_template(
        "details.html",
        ip=ip,
        data=context_data
    )


# ===============================
# REPORTS
# ===============================
@app.route("/api/report")
def generate_report():
    format_type = request.args.get('format', 'txt').lower()
    raw_logs = read_raw_logs()
    organized = {}
    
    for log in raw_logs:
        cleaned_p = clean_payload(log.get("payload", ""), log.get("source", ""))
        if cleaned_p is None:
            continue
        
        ip = log.get("ip", "UNKNOWN")
        log["payload"] = cleaned_p 
        
        if ip not in organized:
            organized[ip] = {"count": 0, "logs": []}
        
        organized[ip]["count"] += 1
        organized[ip]["logs"].append(log)
    
    total_attacks = sum(ip_data["count"] for ip_data in organized.values())
    unique_ips = len(organized)
    
    if format_type == "txt":
        report_content = f"""
🛡️ Sentinel-Trap: IDS ATTACK REPORT
==================================
Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

SUMMARY STATISTICS:
------------------
Total Tracked Attacks: {total_attacks}
Unique Malicious IPs:  {unique_ips}

ATTACKER ANALYSIS BY IP:
------------------------
"""
        for ip in sorted(organized.keys()):
            ip_data = organized[ip]
            report_content += f"\nIP Address: {ip}\n"
            report_content += f"Total Attempts: {ip_data['count']}\n"
            report_content += f"Captured Event History & Fingerprints:\n"
            for log in ip_data['logs'][:5]:  
                fp = log.get('fingerprint') or log.get('fingerprint_hash') or 'N/A'
                report_content += f"  - [{log.get('time', 'N/A')}] [FP: {fp}] ({log.get('source', 'N/A')}): {log.get('payload', 'N/A')}\n"
            report_content += "-" * 60 + "\n"
        
        return Response(report_content, mimetype='text/plain')
    
    elif format_type == "html":
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>IDS Comprehensive Attack Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #0f172a; color: #e2e8f0; }}
        .header {{ background: #1e293b; color: #00ffcc; padding: 25px; text-align: center; border-radius: 8px; border-bottom: 3px solid #00ffcc; }}
        .summary {{ background: #1e293b; padding: 20px; margin: 20px 0; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; background: #1e293b; }}
        th, td {{ border: 1px solid #334155; padding: 12px; text-align: left; }}
        th {{ background: #0f172a; color: #00ffcc; }}
        tr:nth-child(even) {{ background: #1e293b; }}
        tr:nth-child(odd) {{ background: #1e293b; }}
        .ip-section {{ margin: 20px 0; padding: 20px; background: #1e293b; border-radius: 8px; border-left: 5px solid #00ffcc; }}
        .fp-text {{ font-family: monospace; color: #ffa500; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Sentinel-Trap Attack Report</h1>
        <p>Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Metrics Summary</h2>
        <p><strong>Total Detected Attacks:</strong> {total_attacks}</p>
        <p><strong>Unique Malicious IPs Found:</strong> {unique_ips}</p>
    </div>
    
    <h2>🔍 Forensic Intrusions Breakdown</h2>
"""
        for ip in sorted(organized.keys()):
            ip_data = organized[ip]
            location = get_location(ip)
            html_content += f"""
            <div class="ip-section">
                <h3>IP: <strong>{ip}</strong> ({location.get('city', 'Unknown')}, {location.get('country', 'Unknown')})</h3>
                <p><strong>Total Attacks Checked:</strong> {ip_data['count']}</p>
                <h4>Activity Logs (including Fingerprints):</h4>
                <table>
                    <tr><th>Time</th><th>Fingerprint</th><th>Payload</th><th>Source</th></tr>
"""
            for log in ip_data['logs'][:5]:  
                fp = log.get('fingerprint') or log.get('fingerprint_hash') or 'N/A'
                html_content += f"""
                    <tr>
                        <td>{log.get('time', 'N/A')}</td>
                        <td class="fp-text">{fp}</td>
                        <td>{log.get('payload', 'N/A')}</td>
                        <td>{log.get('source', 'N/A')}</td>
                    </tr>
"""
            html_content += "</table></div>"
        
        html_content += "</body></html>"
        return Response(html_content, mimetype='text/html')
    
    elif format_type == "pdf":
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        title = Paragraph(f"<b>IDS Attack Intelligence Summary Report</b><br/><br/>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        summary_data = [
            ['Security Metric', 'Observed Aggregate Value'],
            ['Total Intrusions Captured', str(total_attacks)],
            ['Unique Malicious IPs Detected', str(unique_ips)]
        ]
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 25))
        
        for ip in sorted(organized.keys()):
            ip_data = organized[ip]
            location = get_location(ip)
            
            story.append(Paragraph(f"<b>IP Target Context: {ip}</b> ({location.get('city', 'Unknown')}, {location.get('country', 'Unknown')})", styles['Heading2']))
            story.append(Paragraph(f"Total Combined Counter Attempts: {ip_data['count']}", styles['Normal']))
            story.append(Spacer(1, 10))
            
            log_data = [['Time', 'Fingerprint', 'Payload', 'Source']]
            for log in ip_data['logs'][:5]:
                fp = log.get('fingerprint') or log.get('fingerprint_hash') or 'N/A'
                short_fp = fp[:10] + '...' if fp != 'N/A' else 'N/A'
                payload_str = str(log.get('payload', 'N/A'))
                short_payload = payload_str[:40] + '...' if len(payload_str) > 40 else payload_str
                
                log_data.append([
                    log.get('time', 'N/A'),
                    short_fp,
                    short_payload,
                    log.get('source', 'N/A')
                ])
            
            log_table = Table(log_data, colWidths=[1.2*72, 1.2*72, 2.4*72, 1.2*72])
            log_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.dimgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            story.append(log_table)
            story.append(Spacer(1, 20))
        
        doc.build(story)
        buffer.seek(0)
        return Response(
            buffer.getvalue(), 
            mimetype='application/pdf', 
            headers={'Content-Disposition': f'attachment; filename=ids-report-{datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}.pdf'}
        )
    
    return jsonify({"error": "Invalid format specified. Use: txt, html, pdf"}), 400


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=7000,
        debug=True
    )

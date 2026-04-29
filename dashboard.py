import os
import json
import re
import requests
from flask import Flask, render_template, jsonify, request, Response
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from io import BytesIO
import datetime

app = Flask(__name__)
LOG_FILE = "logs.txt"

def clean_payload(payload, source):
    original = str(payload)
    
    if "HTTP_PAGEVIEW" in source or "FTP_SESSION" in source:
        return None

    # 1. Look for labeled format: "User: admin, Password: 123"
    user_match = re.search(r'User:\s*([^,\s]+)', original)
    pass_match = re.search(r'Password:\s*([^\s,]+)', original)

    if user_match:
        username = user_match.group(1)
        password = pass_match.group(1) if pass_match else ""
        return f"{username}:{password}" if password else username

    # 2. Fallback for raw format: "[FAILED] admin:1234"
    # This captures everything after the [STATUS] tag if it contains a colon
    raw_match = re.search(r'\$\s*([^:\s]+):([^:\s]+)$', original)
    if raw_match:
        return f"{raw_match.group(1)}:{raw_match.group(2)}"

    # 3. FTP Command handling
    if "FTP_" in source and "LOGIN" not in source:
        return original.split("|")[0].replace("[COMMAND]", "").strip()

    # Cleanup any remaining status tags for display
    return re.sub(r'\$.*?\$\s*', '', original)

def read_raw_logs():
    logs = []
    if not os.path.exists(LOG_FILE):
        return logs
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                logs.append(json.loads(line))
            except: continue
    return logs

def get_location(ip):
    if ip in ["127.0.0.1", "UNKNOWN"] or ip.startswith("10."):
        return {"city": "Local", "country": "Internal", "lat": 0, "lon": 0}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,city,country,lat,lon", timeout=2)
        data = r.json()
        if data.get("status") == "success":
            return data
    except: pass
    return {"city": "Unknown", "country": "Unknown", "lat": 0, "lon": 0}

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/data")
def api(): 
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
    
    return jsonify(organized)

@app.route("/attacker/<ip>")
def attacker(ip):
    raw_logs = read_raw_logs()
    ip_logs = []
    
    # === DETAILED FINGERPRINT HISTORY ===
    fingerprint_history = {}
    
    for log in raw_logs:
        if log.get("ip") == ip:
            cleaned_p = clean_payload(log.get("payload", ""), log.get("source", ""))
            if cleaned_p:
                log["payload"] = cleaned_p
                ip_logs.append(log)
                
                # Extract fingerprint details
                fingerprint = log.get("fingerprint", "N/A")
                user_agent = log.get("user_agent", "Unknown")
                timestamp = log.get("time", "N/A")
                
                if fingerprint not in fingerprint_history:
                    fingerprint_history[fingerprint] = {
                        "user_agent": user_agent,
                        "first_seen": timestamp,
                        "attack_count": 0,
                        "sources": set(),
                        "sample_payloads": []
                    }
                
                fingerprint_history[fingerprint]["attack_count"] += 1
                fingerprint_history[fingerprint]["sources"].add(log.get("source", "Unknown"))
                fingerprint_history[fingerprint]["sample_payloads"].append({
                    "time": timestamp,
                    "payload": cleaned_p,
                    "source": log.get("source", "Unknown")
                })
    
    # Limit sample payloads to 3 per fingerprint
    for fp in fingerprint_history.values():
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
        "fingerprint_history": fingerprint_history,  # NEW: Detailed history
        "geo_city": location.get("city", "Unknown"),
        "geo_country": location.get("country", "Unknown"),
        "geo_lat": location.get("lat", 0),
        "geo_lon": location.get("lon", 0)
    }
    
    return render_template("details.html", ip=ip, data=context_data)

@app.route("/api/report")
def generate_report():
    format_type = request.args.get('format', 'txt').lower()
    
    raw_logs = read_raw_logs()
    organized = {}
    
    # Organize data same as /api/data
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
IDS ATTACK REPORT
================
Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

SUMMARY:
--------
Total Attacks: {total_attacks}
Unique Attackers: {unique_ips}

ATTACKERS:
----------
"""
        for ip in sorted(organized.keys()):
            ip_data = organized[ip]
            report_content += f"\nIP: {ip}\n"
            report_content += f"Attempts: {ip_data['count']}\n"
            report_content += f"Sample Payloads:\n"
            for log in ip_data['logs'][:3]:  # First 3 logs
                report_content += f"  - {log.get('time', 'N/A')}: {log.get('payload', 'N/A')}\n"
            report_content += "-" * 50 + "\n"
        
        return Response(report_content, mimetype='text/plain')
    
    elif format_type == "html":
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>IDS Attack Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .header {{ background: #0b0f14; color: #00ffcc; padding: 20px; text-align: center; }}
        .summary {{ background: #111827; color: white; padding: 20px; margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #00ffcc; color: black; }}
        tr:nth-child(even) {{ background: #f2f2f2; }}
        .ip-section {{ margin: 20px 0; padding: 15px; background: #e3f2fd; border-radius: 8px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡 IDS Attack Report</h1>
        <p>Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total Attacks:</strong> {total_attacks}</p>
        <p><strong>Unique Attackers:</strong> {unique_ips}</p>
    </div>
    
    <h2>🔍 Attack Details</h2>
"""
        
        for ip in sorted(organized.keys()):
            ip_data = organized[ip]
            location = get_location(ip)
            html_content += f"""
            <div class="ip-section">
                <h3>IP: <strong>{ip}</strong> ({location.get('city', 'Unknown')}, {location.get('country', 'Unknown')})</h3>
                <p><strong>Attempts:</strong> {ip_data['count']}</p>
                <h4>Recent Activity:</h4>
                <table>
                    <tr><th>Time</th><th>Payload</th><th>Source</th></tr>
"""
            for log in ip_data['logs'][:5]:  # Show first 5 logs
                html_content += f"""
                    <tr>
                        <td>{log.get('time', 'N/A')}</td>
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
        
        # Title
        title = Paragraph(f"<b>IDS Attack Report</b><br/><br/>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Summary
        summary_data = [
            ['Metric', 'Value'],
            ['Total Attacks', str(total_attacks)],
            ['Unique Attackers', str(unique_ips)]
        ]
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # IP Details
        for ip in sorted(organized.keys()):
            ip_data = organized[ip]
            location = get_location(ip)
            
            story.append(Paragraph(f"<b>IP: {ip}</b> ({location.get('city', 'Unknown')}, {location.get('country', 'Unknown')})", styles['Heading2']))
            story.append(Paragraph(f"Attempts: {ip_data['count']}", styles['Normal']))
            story.append(Spacer(1, 12))
            
            log_data = [['Time', 'Payload', 'Source']]
            for log in ip_data['logs'][:5]:
                log_data.append([
                    log.get('time', 'N/A'),
                    str(log.get('payload', 'N/A'))[:50] + '...' if len(str(log.get('payload', 'N/A'))) > 50 else str(log.get('payload', 'N/A')),
                    log.get('source', 'N/A')
                ])
            
            log_table = Table(log_data, colWidths=[1.5*72, 3*72, 1.5*72])
            log_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
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
    
    return jsonify({"error": "Invalid format. Use: txt, html, pdf"}), 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000, debug=True)

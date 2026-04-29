🛡️ Sentinel-Trap: Hybrid Honeypot & IDS Dashboard

Sentinel-Trap is a multi-vector Honeypot and Intrusion Detection System (IDS). It simulates vulnerable services to lure attackers, captures their behavior through advanced fingerprinting, and provides a real-time visual dashboard for threat intelligence.

🚀 Key Features
🕸️ Honeypot (The Trap)
Multi-Protocol Simulation: Mimics HTTP, FTP (port 2121), and Telnet (port 2323) to catch diverse attack vectors.

Intelligent Security Engine: Uses regex pattern matching to identify SQL Injection, XSS, Path Traversal, and Command Injection.

Unique Fingerprinting: Generates MD5 hashes based on IP, User-Agent, and timestamps to track attacker identity across sessions.

Automated Logging: Captures detailed event data including severity levels (CRITICAL to INFO) and raw payloads.

📊 IDS Dashboard (The Watchtower)

Real-time Visualization: Displays attacker IPs, attack counts, and session details in a clean web interface.   


Geo-IP Integration: Automatically identifies the city and country of attackers using the IP-API service.   


Payload Cleaning: Intelligently parses raw attack data to extract human-readable credentials (e.g., username:password).   


Multi-Format Reporting: Generates professional attack summaries in PDF, HTML, or TXT formats.

Component,Technology
Backend,"Python 3, Flask "
Protocols,"Pyftpdlib (FTP), Socket (Telnet)"
Reporting,ReportLab (PDF generation) 
Security,"MD5 Hashing, Regex Pattern Matching"
Data,JSON-based flat-file logging 


To make your README look professional and modern, you can use these Markdown blocks. Copy and paste the sections below directly into your README.md file.

🛡️ Sentinel-Trap: Hybrid Honeypot & IDS Dashboard

  

Sentinel-Trap is a multi-vector Honeypot and Intrusion Detection System (IDS). It simulates vulnerable services to lure attackers, captures their behavior through advanced fingerprinting, and provides a real-time visual dashboard for threat intelligence.

🚀 Key Features
🕸️ Honeypot (The Trap)
Multi-Protocol Simulation: Mimics HTTP, FTP (port 2121), and Telnet (port 2323) to catch diverse attack vectors.

Intelligent Security Engine: Uses regex pattern matching to identify SQL Injection, XSS, Path Traversal, and Command Injection.

Unique Fingerprinting: Generates MD5 hashes based on IP, User-Agent, and timestamps to track attacker identity across sessions.

Automated Logging: Captures detailed event data including severity levels (CRITICAL to INFO) and raw payloads.

📊 IDS Dashboard (The Watchtower)

Real-time Visualization: Displays attacker IPs, attack counts, and session details in a clean web interface.   


Geo-IP Integration: Automatically identifies the city and country of attackers using the IP-API service.   


Payload Cleaning: Intelligently parses raw attack data to extract human-readable credentials (e.g., username:password).   


Multi-Format Reporting: Generates professional attack summaries in PDF, HTML, or TXT formats.   

🛠️ Tech Stack
Component	Technology
Backend	
Python 3, Flask

Protocols	Pyftpdlib (FTP), Socket (Telnet)
Reporting	
ReportLab (PDF generation)

Security	MD5 Hashing, Regex Pattern Matching
Data	
JSON-based flat-file logging

📦 Installation & Setup
1. Clone the Repository

git clone https://github.com/VadherHenil/Honeypot-IDS.git
cd Honeypot-IDS

2. Install Dependencies

pip install -r requirements.txt

3. Launch the Honeypot

python honeypot.py

Note: This starts the HTTP (5000), FTP (2121), and Telnet (2323) services.

4. Launch the IDS Dashboard
   
python dashboard.py

Note: Access the UI at http://localhost:7000.   

🔍 Architecture Overview

honeypot.py: The "Sensor" that listens for incoming connections and evaluates risk levels using a custom SecurityEngine.


dashboard.py: The "Brain" that aggregates logs.txt, performs forensic analysis, and manages the reporting API.   


logs.txt: The centralized database where all captured attack JSON objects are stored.   

📋 Security Signatures
The system monitors for several critical attack patterns:

SQL Injection: Detects SELECT, UNION, DROP, and other SQL keywords.

XSS: Identifies <script> tags, javascript: calls, and alert functions.

Path Traversal: Flags attempts to access sensitive directories like /etc/ or /bin/.

Brute Force: Tracks login attempts on administrative accounts like admin or root.

📄 License
This project is licensed under the MIT License.

Disclaimer: This tool is for educational and research purposes only. Do not deploy on production networks without proper authorization.

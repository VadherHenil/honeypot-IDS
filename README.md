# 🛡️ Sentinel-Trap: Hybrid Honeypot & IDS Dashboard

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-000000.svg?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

**Sentinel-Trap** is a sophisticated multi-vector **Honeypot** and **Intrusion Detection System (IDS)**. It simulates vulnerable services to lure attackers, captures their behavior through advanced fingerprinting, and provides a real-time visual dashboard for threat intelligence.

---

## Version : 4.0

## 🚀 Key Features

### 🕸️ Honeypot (The Trap)
* **Multi-Protocol Simulation**: Mimics HTTP, FTP (port 2121), and Telnet (port 2323) to catch diverse attack vectors.
* **Intelligent Security Engine**: Uses regex pattern matching to identify SQL Injection, XSS, Path Traversal, and Command Injection.
* **Unique Fingerprinting**: Generates MD5 hashes based on IP, User-Agent, and timestamps to track attacker identity.
* **Automated Logging**: Captures detailed event data including severity levels (CRITICAL to INFO) and raw payloads.

### 📊 IDS Dashboard (The Watchtower)
* **Real-time Visualization**: Displays attacker IPs, attack counts, and session details in a clean web interface.
* **Geo-IP Integration**: Automatically identifies the city and country of attackers using the IP-API service.
* **Payload Cleaning**: Intelligently parses raw attack data to extract human-readable credentials, such as `username:password`.
* **Multi-Format Reporting**: Generates professional attack summaries in **PDF**, **HTML**, or **TXT** formats.

---

## 🛠️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Backend** | Python 3, Flask  |
| **Protocols** | Pyftpdlib (FTP), Socket (Telnet) |
| **Reporting** | ReportLab (PDF generation)  |
| **Security** | MD5 Hashing, Regex Pattern Matching |
| **Data** | JSON-based flat-file logging  |

---
## 🔍 Architecture Overview

* honeypot.py: The "Sensor" that listens for incoming connections and evaluates risk levels using a custom SecurityEngine.

* dashboard.py: The "Brain" that aggregates logs.txt, performs forensic analysis, and manages the reporting API.  

* logs.txt: The centralized database where all captured attack JSON objects are stored.

## 📋 Security Signatures

* The system monitors for several critical attack patterns:

* SQL Injection: Detects SELECT, UNION, DROP, and other SQL keywords.

* XSS: Identifies <script> tags, javascript: calls, and alert functions.

* Path Traversal: Flags attempts to access sensitive directories like /etc/ or /bin/.

* Brute Force: Tracks login attempts on administrative accounts like admin or root.


## 📦 Installation & Setup

### 1. Clone the Repository
```bash

git clone [https://github.com/VadherHenil/Honeypot-IDS.git](https://github.com/VadherHenil/Honeypot-IDS.git)
cd Honeypot-IDS
pip install -r requirements.txt
python honeypot.py
python dashboard.py

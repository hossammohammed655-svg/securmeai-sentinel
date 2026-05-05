# 🔐 SecurMeAI — SENTINEL

### AI-Powered Cybersecurity Incident Response Platform

🚀 A real-time cybersecurity platform for **threat detection, analysis, and automated incident response**, built بالكامل باستخدام Python.

---

## 📌 Overview

**SecurMeAI — SENTINEL** is a full-featured **Incident Response (IR) platform** designed to simulate and handle real-world cyber threats.

It provides:

* 🔍 Real-time threat detection
* 📊 Intelligent analysis with confidence scoring
* ⚡ Automated incident response actions
* 📄 Professional PDF & JSON reporting

The system is built with a **modular, production-ready architecture**, allowing easy integration with real network data sources like Scapy or Zeek. 

---

## 🧠 Key Features

### 🔍 Threat Detection Engine

* Detects **10 categories of cyber threats**:

  * Brute Force
  * DoS / DDoS
  * C2 Beaconing
  * Data Exfiltration
  * Port Scanning
  * SQL Injection
  * Lateral Movement
  * Privilege Escalation
  * Anomalous Traffic
  * Reconnaissance 

* Each event includes:

  * MITRE ATT&CK mapping
  * Confidence score (55%–99%)
  * Severity classification

---

### ⚡ Incident Response Actions

* 🚨 Escalate incident
* 🔒 Isolate IP
* ⛔ Block IP
* 📄 Generate full report

Mapped to real-world equivalents like firewall rules, SOC escalation, and SIEM workflows. 

---

### 🖥️ Real-Time GUI

* Built using **Tkinter**

* 5 main tabs:

  * Live Events
  * Threat Map
  * Network Overview
  * Audit Log
  * Report Viewer 

* Smooth real-time updates using **thread-safe architecture**

---

### 📄 Reporting System

* Generates:

  * 📑 PDF reports (ReportLab)
  * 📦 JSON reports

Includes:

* Executive summary
* Top threats
* Attacker IP ranking
* Security recommendations 

---

## 🏗️ Architecture

The system follows a **3-layer modular architecture**:

* 🎨 Presentation Layer → GUI (Tkinter)
* 🧠 Business Logic → Threat Detection Engine
* 📤 Output Layer → Reporting System

This allows replacing the simulated traffic with real network data **without changing the system design**. 

---

## 🛠️ Tech Stack

* **Language:** Python 3
* **GUI:** Tkinter
* **Concurrency:** threading
* **Reporting:** ReportLab
* **Security Framework:** MITRE ATT&CK
* **Data Handling:** JSON, collections

---

## ▶️ How to Run

```bash
git clone https://github.com/your-username/securmeai-sentinel.git
cd securmeai-sentinel
python run.py
```

---

## 📷 Screenshots

(Add your GUI screenshots here — this is VERY important)

---

## 🚧 Future Improvements

* 🔗 Integration with Scapy / Zeek
* 🔥 Firewall API (iptables / pfSense / Palo Alto)
* 🧠 Machine Learning anomaly detection
* ☁️ SIEM integration (Splunk / Elastic)
* 🌐 Web-based dashboard (Flask + React) 

---

## 👨‍💻 My Role

**Project Lead / Architect**

* Designed system architecture
* Defined IR workflow
* Coordinated development across modules
* Ensured production-ready structure

---

## 🏆 Highlights

* ⚡ Real-time event processing
* 🧠 MITRE ATT&CK integration
* 🧱 Modular, scalable design
* 📊 Full incident lifecycle coverage
* 📄 Professional reporting system

---

## 📫 Contact

Hossam Mohammed
LinkedIn: www.linkedin.com/in/hossam-mohammed-4415a3292

---

⭐ *Built to simulate real-world SOC environments and incident response workflows.*

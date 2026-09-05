# 🛡️ Network Security Traffic Analyzer

A Python-based network traffic analysis tool that captures live IP packets, analyzes network protocols and ports, logs packet information, and detects basic suspicious network activity using rule-based security checks.

---

## 📌 Overview

The **Network Security Traffic Analyzer** is a lightweight network monitoring and security analysis tool built using Python and Scapy.

The application captures live IP traffic and extracts useful information such as:

* Source IP address
* Destination IP address
* Network protocol
* Source and destination ports
* Timestamp

It also applies simple rule-based security checks to identify potential suspicious behavior such as excessive traffic, TCP SYN activity, and possible port-scanning behavior.

---

## ✨ Features

* 🔍 Live IP packet capture using Scapy
* 🌐 TCP, UDP, ICMP and other protocol identification
* 📊 Network traffic statistics
* 📝 Packet logging to a local log file
* 🚨 Rule-based suspicious activity detection
* 🔎 TCP SYN detection
* 🔎 Potential port-scan detection
* 📦 Modular Python project structure
* 🧪 Automated security detection tests

---

## 🏗️ Architecture

```text
                 NETWORK TRAFFIC
                        │
                        ▼
              ┌──────────────────┐
              │  Packet Capture  │
              │      Scapy       │
              └────────┬─────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ Packet Analyzer  │
              │                  │
              │ IP / Protocol    │
              │ Ports / Timestamp│
              └───────┬──────────┘
                      │
             ┌────────┴─────────┐
             │                  │
             ▼                  ▼
      ┌──────────────┐   ┌─────────────────┐
      │ Packet Logger│   │Security Detector│
      └──────┬───────┘   └────────┬────────┘
             │                    │
             ▼                    ▼
      traffic.log              Alerts
                                  │
                                  ▼
                           Traffic Statistics
```

---

## 🧠 How It Works

The application follows a simple processing pipeline:

1. **Packet Capture**
   Scapy captures IP packets from the network interface.

2. **Packet Analysis**
   Each packet is inspected to identify its source, destination, protocol and ports.

3. **Security Detection**
   The packet is passed through rule-based security checks.

4. **Logging**
   Analyzed packet information is stored in `logs/traffic.log`.

5. **Statistics**
   Protocol counts are maintained and displayed after packet capture is completed.

---

## 🚨 Security Detection Rules

The current version implements basic heuristic detection.

### 1. High Traffic Detection

If a single source IP generates 20 packets during the capture session, the analyzer generates a high-traffic alert.

### 2. TCP SYN Detection

TCP SYN packets are identified as connection-initiation attempts.

Example:

```text
TCP SYN: 192.168.1.10 -> 192.168.1.20:80
```

### 3. Potential Port Scan Detection

If a source IP sends TCP SYN packets to 5 or more different destination ports, the analyzer generates a potential port-scan indicator.

> These rules are simple heuristics and should not be considered proof of malicious activity.

---

## 🛠️ Technologies Used

* **Python**
* **Scapy**
* **Pytest**
* **Git & GitHub**
* **VS Code**

---

## 📂 Project Structure

```text
network_security_traffic_analyzer/
│
├── src/
│   ├── main.py
│   ├── packet_capture.py
│   ├── packet_analyzer.py
│   └── security_detector.py
│
├── tests/
│   └── test_security_detector.py
│
├── logs/
│   └── traffic.log
│
├── docs/
│
├── .gitignore
├── README.md
└── requirements.txt
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd network-security-traffic-analyzer
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the virtual environment

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

Run the analyzer from the project root:

```bash
python src/main.py
```

The application captures 50 IP packets and displays their analysis and traffic statistics.

---

## 🧪 Running Tests

Run the automated tests using:

```bash
python -m pytest
```

The test suite currently verifies:

* TCP SYN detection
* Potential port-scan detection

---

## 📊 Example Output

```text
==================================================
   NETWORK SECURITY TRAFFIC ANALYZER
==================================================

Starting packet capture for 50 IP packets...

==================================================
PACKET #1
==================================================
Source=10.226.88.17 |
Destination=10.226.88.151 |
Protocol=UDP |
SourcePort=53 |
DestinationPort=54321

...

==================================================
TRAFFIC STATISTICS
==================================================
UDP: 45
TCP: 5

Total IP Packets Analyzed: 50
```

---

## ⚠️ Limitations

This project is currently intended as a lightweight learning and portfolio project.

Current limitations include:

* Detection rules are heuristic-based.
* High-traffic thresholds are currently fixed.
* Port-scan detection is based on a small number of observed ports.
* The application currently focuses on basic packet-level analysis.
* It does not replace a production intrusion detection system.

---

## 🚀 Future Enhancements

Possible future improvements include:

* Configurable detection thresholds
* Improved port-scan detection
* Packet-per-second monitoring
* Top source and destination analysis
* CSV/JSON report generation
* PCAP file analysis
* Network traffic visualization
* Real-time monitoring dashboard
* Integration with an intrusion detection system such as Snort

---

## 👩‍💻 Project Purpose

This project was developed to understand practical network security concepts including packet inspection, network protocols, traffic monitoring, logging, and rule-based threat detection.

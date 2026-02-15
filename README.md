# network-packet-scanner
A Flask-based web application for analyzing network packet capture (PCAP) files and detecting security vulnerabilities in real-time. This website has been deployed to Render.

Link to website hosted on Render: https://network-packet-scanner.onrender.com/


## 📸 Screenshots

<div align="center">
  <img src="https://github.com/user-attachments/assets/b0fbf0ce-27c1-4e4b-a170-acaaaee8acae" width="45%" />
  <img src="https://github.com/user-attachments/assets/daee7a85-3206-4d31-aafa-f1a8ba3bb180" width="45%" />
</div>

<div align="center">
  <img src="https://github.com/user-attachments/assets/78be7911-fe6a-4563-a3f7-58a9713194a6" width="45%" />
</div>


## 🔍 Comprehensive Vulnerability Detection

Insecure Protocols: Detects HTTP, FTP, Telnet, and deprecated SSL
Port Mismatches: Identifies suspicious port/protocol combinations
Weak Encryption: Flags TLS 1.0 and 1.1 usage
Credential Exposure: Detects plaintext credentials (FTP, Telnet, HTTP Basic Auth, SMTP, POP3, IMAP)

## 📊 Traffic Analysis

Real-time Statistics: Total packets, TCP/UDP breakdown, unique IPs
Protocol Distribution: Interactive Chart.js visualization
Recent Packets: View source, destination, protocol, and timestamp
Color-Coded Severity: Critical (red), high (orange), medium (yellow)

## 🎨 Modern UI/UX

Dark theme with professional styling
Responsive design for mobile and desktop
Interactive charts and visualizations
Clean, intuitive navigation

## 🛠️ Tech Stack

Backend: Flask (Python)
Packet Analysis: PyShark (Wireshark/tshark wrapper)
Frontend: HTML5, CSS3, JavaScript
Deployment: Docker, Render

## 📋 Prerequisites

Python 3.8+
Wireshark/tshark installed
Basic understanding of network protocols

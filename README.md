# Intelligent Cyber Security Toolkit

The **Intelligent Cyber Security Toolkit** is a standalone, lightweight, and comprehensive security analysis application written in Python. It provides a user-friendly, modern Tkinter GUI to perform network port scanning, security analysis, threat modeling, and password strength evaluation.

## ✨ Features

- **🚀 High-Speed Multithreaded Port Scanner**
  Perform fast scans across custom port ranges using a highly concurrent, multithreaded architecture.
- **🎣 Banner Grabbing & Service Detection**
  Automatically grab banners and identify common services (e.g., HTTP, SSH, FTP) running on detected open ports.
- **🛡️ Automated Security Analysis & Threat Modeling**
  Calculates a holistic Risk Score based on standard heuristics and flags highly dangerous open ports (like SMB on port 445 or Telnet on port 23).
- **🔒 Password Strength Checker**
  Evaluate the complexity and strength of your passwords locally without sending data over a network.
- **📄 Complete Report Generation**
  Preview and save highly detailed, structured `.txt` reports outlining scanning duration, detected threats, and robust security recommendations to mitigate identified vulnerabilities.

## 🛠️ Installation

This application relies entirely on standard built-in Python libraries and requires no complicated external dependencies.

1. Ensure you have **Python 3.x** installed on your machine.
2. Clone or download this project folder.
3. You're ready to go!

## 💻 Usage

Run the script directly from your terminal or command prompt:

```bash
python portscanergui.py
```

### Navigating the Toolkit

1. **Scan**: Enter your Target IP or Hostname, set a Start and End Port, and click "Start Scan". Live progress and elapsed time will be displayed safely in the background.
2. **Results**: View live discoveries, including the port number, detected service, and any intercepted banner strings.
3. **Analysis**: Once a scan completes, navigate to the Analysis tab to see a breakdown of the target's security posture, risk score, OS guesses, and specific port-based threat assessments.
4. **Password Tool**: A straightforward utility to gauge the resilience of a typed password against brute-force/dictionary attacks.
5. **Reports**: Preview a complete compilation of the vulnerability scan. Export the detailed summary for your records as a `.txt` file.

## ⚠️ Disclaimer

**For Educational and Authorized Testing Use Only!**

This toolkit is designed strictly for learning cybersecurity concepts, network administration, and authorized vulnerability scanning. **Do not** use this tool to scan networks, systems, or IP addresses that you do not own or have explicit, written permission to test. Unauthorized port scanning can be considered a cyber attack under various jurisdictions. The developers and contributors are not responsible for any misuse, damage, or illegal activities performed with this application.

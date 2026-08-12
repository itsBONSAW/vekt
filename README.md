<div align="center">
# V E K T
### Vector Exploitation & Kill Toolkit

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Web%20UI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20Parrot-darkgreen?logo=linux&logoColor=white)]()
[![UI](https://img.shields.io/badge/UI-Cyberpunk%20Theme-%2300E5FF?logo=tailwindcss&logoColor=white)]()

**A modern, web-driven wireless auditing framework.**

*Stop juggling multiple terminal tabs. Command the airwaves from a single, sleek dashboard.*
</div>

---

## ⚠️ Disclaimer

**VEKT** is designed for authorized security auditing, educational purposes, and CTF challenges only.
Attacking wireless networks without explicit permission from the owner is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program.

---

## 🚀 Overview

Most wireless testing tools require running multiple CLI commands across different terminal tabs (`airodump` here, `aireplay` there, `reaver` somewhere else). **VEKT** solves this by bringing the entire `aircrack-ng` suite and WPS attack vectors into a single, dark-themed, web-based graphical interface.

Built with a decoupled architecture (FastAPI Backend + HTML/JS Frontend) and an **Offline-First design**, VEKT ensures smooth execution without UI freezing, providing real-time terminal logs directly inside the browser. You can run it on a laptop or Raspberry Pi in your backpack and control the attacks from your smartphone!

## 📸 Screenshots

<div align="center">


</div>

---

## ✨ Features

### 🗺️ 1. Recon & Target Intel
- Live scanning of 2.4GHz networks using `airodump-ng` and `wash`.
- Automatic WPS Lock status detection.
- Focused target monitoring: Select a network to instantly discover connected client stations.
- Sortable target list with color-coded signal strength (dBm).

### 🔓 2. WPS Exploitation
- **Pixie-Dust Attack:** Automated offline WPS PIN extraction (`reaver -K 1`).
- **PIN Brute-Force:** Targeted brute-force attacks with lockout detection.
- Real-time logging of the Reaver output directly into the UI.

### 🤝 3. Handshake Capture (WPA/WPA2)
- Targeted network locking and channel hopping.
- Client/Station discovery.
- **Automated Deauth Loop:** Sends continuous deauth packets to targeted clients to force handshake capture.
- Real-time EAPOL detection. Automatically stops the attack once the handshake is captured.
- Exports `.cap` files ready for cracking.

### 🧠 4. Offline Cracking
- One-click conversion of `.cap` files to Hashcat format (`hc22000`) using `hcxpcapngtool`.
- Integrated `hashcat` execution with live progress status directly in the web console.

### 👥 5. Evil Twin (Rogue AP) - 🚧 Work In Progress
- Clones target ESSID and channel using `hostapd`.
- Continuous deauth of the original AP via virtual interfaces to force client migration.
- `dnsmasq` integration for DNS hijacking.
- Built-in Captive Portal to phish WPA passwords.

> **Note:** The Evil Twin feature is currently in the experimental phase and under active development. Due to the complexities of single-interface routing, captive portals, and driver compatibility, it might not perform flawlessly in all environments yet. Use it with caution and expect potential bugs.

---

## 🛠️ Architecture

VEKT uses a modular Producer-Consumer pattern to ensure the Web UI never freezes during intensive wireless operations. The UI runs entirely offline using a local Tailwind CSS engine.

```text
vekt/
├── main.py # FastAPI Web Server, WebSocket Manager & Captive Portal
├── requirements.txt
├── static/
│   ├── index.html # Cyberpunk Web UI (Tailwind CSS + Vanilla JS)
│   └── tailwind.js # Local Tailwind v3 Engine (Offline support)
└── core/ # Backend Engine (The Brains)
    ├── recon.py # Wardriving & Target Scanning logic
    └── attacks/ # Attack Modules
        ├── wps_attack.py
        ├── handshake.py
        ├── cracker.py
        └── evil_twin.py
```

---

## 📦 Installation & Requirements

### Prerequisites
- Linux environment (Kali, Parrot, or Arch recommended)
- Wireless card supporting **Monitor Mode** & **Packet Injection**
- Root privileges

### System Dependencies
You must have the underlying CLI tools installed:

```bash
sudo apt update
sudo apt install aircrack-ng reaver hashcat hcxtools hostapd dnsmasq iw
```

### Python Setup

```bash
git clone https://github.com/itsBONSAW/vekt.git
cd vekt
pip install -r requirements.txt
```

---

## 💻 Usage

Run VEKT with root privileges:

```bash
sudo python3 main.py
```

Once running, open your browser and navigate to:
`http://localhost:8000` (or `http://<your-ip>:8000` to control it remotely).

---

## 🤝 Acknowledgements

I want to be completely transparent about the development process of VEKT. A significant portion of this tool's architecture, backend Python logic, and the cyberpunk-themed frontend were designed and written with the assistance of an AI language model. It acted as an incredible co-pilot, helping to debug complex threading issues, integrate FastAPI with WebSockets, and design the UI.

Thank you to the AI for making this project come to life so rapidly. To human contributors: feel free to fork, modify, and improve upon this foundation.

---

<div align="center">
Made by **itsBONSAW** & AI
<br>
<sub>Happy Hacking.</sub>
</div>

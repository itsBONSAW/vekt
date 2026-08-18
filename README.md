<img width="1280" height="720" alt="b27b6a7e-7971-4adb-97e4-060bb7283f8c" src="https://github.com/user-attachments/assets/8cc6bd8d-71c9-4aba-a377-2d374ecae7bf" />


<div align="center">

# V E K T

### Vector Exploitation & Kill Toolkit

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Web%20UI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Parrot%20%7C%20Linux-darkgreen?logo=linux&logoColor=white)]()
[![UI](https://img.shields.io/badge/UI-Cyberpunk-00E5FF?logo=tailwindcss&logoColor=white)]()

**A modern, web-driven wireless security testing framework.**

*Recon. Target. Analyze. Test. All from one command center.*

</div>

---

## ⚠️ Disclaimer

**VEKT** is designed for authorized security auditing, educational research, private laboratories, and CTF competitions.

Only use VEKT against wireless networks and devices that you own or have explicit permission to test.

The developer assumes no liability for misuse, service disruption, data loss, or any unauthorized activity performed with this software.

---

## 🚀 Overview

Wireless security testing often means jumping between multiple terminal windows, manually managing interfaces, watching several processes, and keeping track of capture files.

**VEKT** brings that workflow into a single operator-focused dashboard.

Built around a **FastAPI backend, WebSocket event system, modular wireless engines, centralized process supervision, and a cyberpunk web interface**, VEKT turns a collection of command-line security utilities into one coherent testing environment.

It is designed to run locally on Linux and can operate entirely without an external cloud service.

---

## ✨ Features

### 🗺️ 1. Recon & Target Intelligence

- Live wireless discovery using `airodump-ng`
- WPS visibility using `wash`
- ESSID, BSSID, channel and signal information
- Color-coded signal strength
- Focused target monitoring
- Connected station discovery
- Real-time dashboard updates through WebSockets
- Session-isolated reconnaissance data

### 🔓 2. WPS Security Testing

- Pixie-Dust workflow
- WPS PIN testing
- Reaver integration
- Live process output
- Automatic result extraction
- Controlled start / stop lifecycle

### 🤝 3. Wireless Capture Workflow

- Target-focused capture sessions
- Channel-specific monitoring
- Session-isolated capture files
- Capture artifact validation
- Real-time capture status
- Automatic process cleanup

### 🧠 4. Offline Password Testing

- `.cap` to `HC22000` conversion through `hcxpcapngtool`
- Hashcat integration
- Wordlist-based testing
- Live process lifecycle tracking
- Result extraction
- Isolated temporary artifacts

### 🛰️ 5. Experimental Rogue AP Lab

- `hostapd` integration
- `dnsmasq` integration
- Dedicated network session
- Interface state tracking
- Automatic restoration
- Experimental driver compatibility layer

> The Rogue AP component is experimental and hardware/driver dependent.

### ⚙️ 6. Engineered Backend

- Centralized controller
- Single operator model
- WebSocket authentication
- Unified process supervision
- Thread-safe engine lifecycle
- Session isolation
- Automatic cleanup
- Network state restoration
- Explicit job states
- Failure-aware shutdown

---

## 📸 Screenshots

<div align="center">

<img width="1920" height="1080" alt="a" src="https://github.com/user-attachments/assets/26fdf1da-ef3c-47ab-a167-d1327950cfbc" />
<img width="1920" height="1080" alt="b" src="https://github.com/user-attachments/assets/41b75966-2443-44e8-a1ce-849dd38d001c" />
<img width="1920" height="1080" alt="c" src="https://github.com/user-attachments/assets/ce71cde8-ff98-46c4-a4f8-a3e81c4b2926" />
<img width="1920" height="1080" alt="d" src="https://github.com/user-attachments/assets/520d93b0-6f02-4ea8-a2f5-07d5066abc2f" />

</div>

---

## 🛠️ Architecture

VEKT uses a compact modular architecture designed to keep the codebase maintainable without splitting every component into its own package.

```text
vekt/
├── main.py
├── requirements.txt
├── .env
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
│
├── static/
│   ├── index.html
│   └── tailwind.js
│
└── core/
    ├── controller.py
    ├── process.py
    ├── network.py
    ├── recon.py
    └── attacks/
        ├── wps_attack.py
        ├── handshake.py
        ├── cracker.py
        └── evil_twin.py
```

### Core Flow

```text
                  ┌─────────────────────┐
                  │     VEKT Web UI      │
                  │  HTML + JavaScript   │
                  └──────────┬──────────┘
                             │
                         WebSocket
                             │
                  ┌──────────▼──────────┐
                  │   VektController     │
                  │ State + Jobs + Flow  │
                  └─────┬─────────┬──────┘
                        │         │
                ┌───────▼───┐ ┌──▼──────────┐
                │  Network  │ │   Process   │
                │  Manager  │ │ Supervisor  │
                └───────┬───┘ └──────┬──────┘
                        │             │
                        └──────┬──────┘
                               │
                    ┌──────────▼──────────┐
                    │    Security Engines │
                    ├─────────────────────┤
                    │ Recon               │
                    │ WPS                 │
                    │ Handshake           │
                    │ Cracker             │
                    │ Rogue AP            │
                    └─────────────────────┘
```

---

## 📦 Installation & Requirements

### Prerequisites

- Linux environment
- Kali Linux, Parrot OS, or another security-focused distribution recommended
- Compatible wireless adapter
- Linux wireless drivers
- Root privileges for operations requiring privileged access

Hardware capabilities vary depending on the workflow.

### System Dependencies

On Debian-based systems:

```bash
sudo apt update
sudo apt install aircrack-ng reaver hashcat hcxtools hostapd dnsmasq iw
```

### Python Setup

```bash
git clone https://github.com/itsBONSAW/vekt.git
cd vekt

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

---

## 🔐 Configuration

Create a `.env` file in the project root:

```env
VEKT_ACCESS_TOKEN=replace_with_a_long_random_token
VEKT_HOST=127.0.0.1
VEKT_PORT=8000
```

---

## 💻 Usage

Start VEKT:

```bash
sudo -E python3 main.py
```

Then open:

```
http://127.0.0.1:8000
```

### Typical Workflow

1. Select wireless interface
2. Start reconnaissance
3. Discover target networks
4. Select a target
5. Monitor connected stations
6. Choose the required testing workflow
7. Monitor live engine output
8. Inspect captured or recovered results
9. Stop the active job
10. Restore network state

---

## 🔄 State & Job Management

VEKT maintains a centralized application state instead of letting each WebSocket connection maintain independent engine instances.

```text
IDLE
  ↓
RECON
  ↓
TARGETED
  ↓
STARTING
  ↓
RUNNING
  ├── SUCCESS
  └── FAILED
        ↓
     STOPPING
        ↓
    RESTORING
        ↓
       IDLE
```

This allows the frontend to display the real backend state instead of guessing whether an operation succeeded.

---

## 🧹 Automatic Cleanup

VEKT treats network and process changes as managed sessions.

When an operation stops or a failure occurs, the framework attempts to:

- terminate active processes
- stop background workers
- restore interface state
- restore network configuration
- remove temporary session artifacts
- release the active operator

This is especially important for workflows that modify wireless interface state.

---

## ⚡ What's New in v2.0?

### 🧠 Centralized Controller

Application state and active jobs are now owned by a single `VektController`.

### 🔒 WebSocket Authentication

The operator channel requires a configurable access token.

### ⚙️ Unified Process Supervision

External security utilities are managed through a shared process abstraction with controlled startup, termination, timeout handling, and cleanup.

### 🧹 Network Restoration

Wireless interface state is captured before managed workflows and restored during cleanup.

### 🧵 Thread-Safe Engine Lifecycle

Long-running operations execute outside the FastAPI event loop so the dashboard remains responsive.

### 📦 Session Isolation

Temporary files are generated inside isolated session directories instead of relying on shared global paths.

### 🎯 Target-Centric Workflow

Reconnaissance and target monitoring are separated into distinct application states.

### 🌐 Real-Time UI

WebSockets provide live logs, target updates, station discovery, job states, and result events.

---

## 🤝 Acknowledgements

VEKT stands on the shoulders of several excellent open-source projects and tools:

- Aircrack-ng
- Reaver
- Hashcat
- hcxtools
- hostapd
- dnsmasq
- FastAPI
- Scapy

A significant portion of VEKT's architecture, refactoring, debugging, and UI development was performed with the assistance of AI as a development copilot.

The project was iteratively designed and reviewed around maintainability, process management, network state handling, and operator experience.

---

<div align="center">

**V E K T**  
*Vector Exploitation & Kill Toolkit*

Built for authorized security testing, private laboratories, research, and CTF environments.

**Made by itsBONSAW & AI**

*Recon. Target. Analyze. Test.*

</div>

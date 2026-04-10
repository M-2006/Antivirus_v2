<div align="center">

<img src="assets/logo.png" alt="Antivirus v2" width="110" />

# Antivirus v2

**A modular, Python-powered security engine that combines signature matching,<br>machine-learning anomaly detection, and real-time filesystem monitoring.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-EF4444?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/M-2006/Antivirus_v2/python-ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/M-2006/Antivirus_v2/actions)
[![Status](https://img.shields.io/badge/status-active-22C55E?style=flat-square)]()

<img src="assets/banner.png" alt="Banner" width="780" />

</div>

---

## Table of Contents

1. [What is Antivirus v2?](#what-is-antivirus-v2)
2. [How it works](#how-it-works)
3. [Features](#features)
4. [Project structure](#project-structure)
5. [Requirements](#requirements)
6. [Installation](#installation)
7. [Running the application](#running-the-application)
8. [Training the ML model](#training-the-ml-model)
9. [Configuration](#configuration)
10. [Contributing](#contributing)
11. [License](#license)

---

## What is Antivirus v2?

Antivirus v2 is a lightweight, fully-Python security toolkit built for developers and researchers who want to understand — and extend — how threat detection actually works under the hood.

It runs three complementary detection layers simultaneously:

- **Signature-based** — SHA-256 hash lookups against a local database that auto-updates on startup.
- **ML-based** — An `IsolationForest` model flags processes whose CPU usage, memory footprint, and executable metadata look anomalous compared to a clean baseline.
- **Cloud-based** — SHA-256 digests of newly-detected files are checked against the [VirusTotal](https://www.virustotal.com) database (70+ AV engines).

All results flow into a live web dashboard (Flask) and a desktop GUI (Tkinter), and every event is logged for offline replay and forensic review.

---

## How it works

```
New file lands on disk
        │
        ▼
   watcher.py          ← watchdog detects the filesystem event
        │
        ├──► signatures.py    check SHA-256 against local DB
        ├──► virustotal.py    check SHA-256 against VT API
        └──► ml_detector.py   IsolationForest anomaly score
                │
                ▼
          responder.py        quarantine / alert / log
                │
        ┌───────┴────────┐
        ▼                ▼
    dashboard.py       gui.py
  (Flask web UI)   (Tkinter desktop)
```

When `main.py` starts it:

1. Calls `signatures.update_signatures()` to pull the latest threat DB.
2. Spawns the Flask web dashboard in a background thread.
3. Starts the `watchdog` file-system watcher on `WATCH_DIRECTORY`.
4. Launches the Tkinter GUI in the main thread.

---

## Features

| | Feature | Details |
|---|---|---|
| 🔍 | Signature detection | SHA-256 hash matching against an auto-updated local database |
| 🤖 | ML anomaly detection | `sklearn` IsolationForest trained on clean process snapshots |
| 👁️ | Real-time watcher | `watchdog` monitors a directory and triggers analysis on every new file |
| 🌐 | VirusTotal integration | File hashes checked against 70+ AV engines via the free VT API |
| 📊 | Web dashboard | Live threat log served by Flask at `localhost:<port>` |
| 🖥️ | Desktop GUI | Tkinter dashboard for scanning and viewing results locally |
| 📁 | Directory scanner | Recursive scan of any folder via `dir_scanner.py` |
| 🔁 | Event replay | Re-analyse past logged events offline with `replay.py` |
| ⚙️ | Single config file | All paths, keys, and thresholds live in `config.py` |

---

## Project structure

```
Antivirus_v2/
│
├── main.py            # Entry point — wires every component together
│
├── Core detection
│   ├── scanner.py         # Enumerates running processes via psutil
│   ├── analyzer.py        # Orchestrates the multi-layer analysis pipeline
│   ├── ml_detector.py     # IsolationForest feature extraction, training & prediction
│   └── signatures.py      # Local signature DB — download, update, lookup
│
├── Monitoring
│   ├── watcher.py         # watchdog listener — fires callback on new/modified files
│   └── monitor.py         # Periodic process-level health monitoring
│
├── Response & replay
│   ├── responder.py       # Automated actions: quarantine, alert, kill process
│   └── replay.py          # Replay stored events for forensic re-analysis
│
├── Interfaces
│   ├── gui.py             # Tkinter desktop dashboard
│   └── dashboard.py       # Flask web dashboard (runs in background thread)
│
├── Shared
│   ├── config.py          # All configuration constants
│   ├── utils.py           # Logging helpers shared across modules
│   └── virustotal.py      # VirusTotal API client (hash lookup)
│
├── requirements.txt
└── assets/
```

---

## Requirements

- **Python 3.8+**
- A free [VirusTotal API key](https://www.virustotal.com/gui/join-us) (2 000 requests/day on the free tier)
- Works on **Windows**, **macOS**, and **Linux**

Dependencies (all in `requirements.txt`):

```
psutil        process enumeration and memory stats
requests      HTTP client for the VirusTotal API
scikit-learn  IsolationForest ML model
numpy         feature vector construction
joblib        model serialisation to disk
watchdog      cross-platform filesystem event monitoring
flask         lightweight web dashboard
```

---

## Installation

**1 — Clone the repository**

```bash
git clone https://github.com/M-2006/Antivirus_v2.git
cd Antivirus_v2
```

**2 — Create a virtual environment**

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python -m venv venv
source venv/bin/activate
```

**3 — Install dependencies**

```bash
pip install -r requirements.txt
```

**4 — Add your VirusTotal API key**

Open `config.py` and set:

```python
VIRUSTOTAL_API_KEY = "your_api_key_here"
```

---

## Running the application

**Full application** (watcher + web dashboard + desktop GUI):

```bash
python main.py
```

The web dashboard will be available at `http://localhost:5000` (or whatever `WEB_DASHBOARD_PORT` is set to in `config.py`).

**Scan a specific directory from the command line:**

```bash
python dir_scanner.py /path/to/scan
```

---

## Training the ML model

The ML detector uses `sklearn`'s `IsolationForest`. It needs to be trained once on a clean baseline before it can flag anomalies. Open a Python shell after installing dependencies:

```python
from scanner import scan_system
from ml_detector import train_model

# Capture the current process list as a clean baseline
train_model(scan_system()["processes"])
```

This saves `model.pkl` to the project root. From that point on, `ml_detector.predict()` will return `True` for any process that looks anomalous relative to the baseline. Re-train periodically as your normal workload changes.

---

## Configuration

Everything lives in `config.py`:

```python
WATCH_DIRECTORY     = "/path/to/watch"   # Directory monitored in real time
WEB_DASHBOARD_PORT  = 5000               # Port for the Flask web dashboard
VIRUSTOTAL_API_KEY  = "..."              # Your VirusTotal API key
LOG_LEVEL           = "INFO"             # Logging verbosity (DEBUG / INFO / WARNING)
```

No environment variables, no hidden files — one place to look for every setting.

---

## Contributing

Contributions are welcome. The codebase is intentionally modular — every component can be developed and tested in isolation.

```bash
# 1. Fork the repo, then clone your fork
git clone https://github.com/<your-username>/Antivirus_v2.git

# 2. Create a feature branch
git checkout -b feature/your-feature

# 3. Make your changes, then commit
git commit -m "Add: short description of what changed and why"

# 4. Push and open a Pull Request
git push origin feature/your-feature
```

Please keep one logical change per PR and add a comment where the logic is non-obvious.

---

## License

Licensed under the [GNU Affero General Public License v3.0](LICENSE). You are free to use, modify, and distribute this software under the same terms.

---

<div align="center">

Built by [Muhamet Maliqi](https://github.com/M-2006) · Crafted with precision ⚙️ and curiosity 🧠

</div>

# 🛡 Secure File Transfer Monitoring System (SFMS)

A Python-based file transfer monitoring toolkit with a real-time web dashboard.

---

## Features

| Feature | Description |
|---|---|
| 📁 Real-time Monitoring | Detects file create, modify, delete, move events instantly |
| 🔐 Integrity Checking | SHA256 hash comparison to detect tampering |
| 🚨 Alert System | HIGH/CRITICAL alerts for sensitive or suspicious transfers |
| 📊 Web Dashboard | Live Flask dashboard with event log and alert feed |
| 📤 Report Export | CSV and JSON audit report export |
| 💻 CLI Mode | Terminal-only monitoring without Flask |

---

## Project Structure

```
sfms/
├── monitor.py          ← Core monitoring engine (watchdog + hashlib)
├── app.py              ← Flask web server + REST API
├── cli_monitor.py      ← Standalone CLI mode
├── requirements.txt    ← Python dependencies
├── templates/
│   └── dashboard.html  ← Web dashboard UI
├── logs/
│   ├── transfers.jsonl ← Persistent event log
│   └── hashes.json     ← File hash database
└── reports/            ← Generated audit reports (CSV/JSON)
```

---

## Setup & Installation

### Step 1: Install dependencies
```bash
pip install -r requirements.txt
```

### Step 2A: Run with Web Dashboard (recommended)
```bash
python app.py
```
Then open → **http://127.0.0.1:5000**

### Step 2B: Run CLI Mode (terminal only)
```bash
python cli_monitor.py                       # monitors default sensitive dirs
python cli_monitor.py /path/to/watch        # monitor a specific directory
```

---

## How It Works

```
START
  ↓
Monitor File System (watchdog)
  ↓
Is File Sensitive? (extension / directory check)
  ↓
Compute SHA256 Hash → Compare with stored hash
  ↓
Is Destination Suspicious? (USB, cloud, network)
  ↓
Classify Severity → LOW / MEDIUM / HIGH / CRITICAL
  ↓
Log Event to JSONL file + in-memory store
  ↓
Trigger Alert if HIGH or CRITICAL
  ↓
Dashboard / CLI displays in real time
  ↓
Export CSV / JSON Audit Report
  ↓
END
```

---

## Severity Levels

| Level | Trigger |
|---|---|
| 🔴 CRITICAL | Sensitive file moved to USB/cloud/network |
| 🟠 HIGH | Suspicious destination OR sensitive file deleted |
| 🟡 MEDIUM | Sensitive file accessed or modified |
| 🟢 LOW | Normal file activity |

---

## Sensitive File Types Monitored
`.pdf .docx .xlsx .txt .csv .db .sql .json .xml .key .pem`

---

## Suspicious Destinations Monitored
- USB drives (`/media`, `/mnt`, `D:\`, `E:\`)
- Cloud folders (Dropbox, Google Drive, OneDrive)

---

## Customization

Edit `monitor.py` to:
- Add more `SENSITIVE_DIRS` paths
- Add more `SENSITIVE_EXTENSIONS`
- Add more `SUSPICIOUS_DESTINATIONS`

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.10+ | Core language |
| `watchdog` | Real-time file system event monitoring |
| `hashlib` | SHA256 file integrity hashing |
| `psutil` | Process/system information (optional) |
| `Flask` | Web dashboard and REST API |
| HTML/CSS/JS | Frontend dashboard |

---

## License
Academic project — Government Engineering College Jamui

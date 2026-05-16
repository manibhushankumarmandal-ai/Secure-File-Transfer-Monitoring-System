"""
Secure File Transfer Monitoring System
Core monitoring engine using watchdog
"""

import os
import hashlib
import json
import time
import threading
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ─── Configuration ────────────────────────────────────────────────────────────

SENSITIVE_DIRS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
]

SENSITIVE_EXTENSIONS = [
    ".pdf", ".docx", ".xlsx", ".txt", ".csv",
    ".db", ".sql", ".json", ".xml", ".key", ".pem"
]

SUSPICIOUS_DESTINATIONS = [
    "/media",           # USB mounts (Linux)
    "/mnt",             # Network/USB mounts
    "D:\\",             # Secondary drive (Windows)
    "E:\\",
    os.path.expanduser("~/Dropbox"),
    os.path.expanduser("~/Google Drive"),
    os.path.expanduser("~/OneDrive"),
]

LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "transfers.jsonl")
HASH_DB  = os.path.join(os.path.dirname(__file__), "logs", "hashes.json")

# ─── In-memory event store (shared with Flask) ────────────────────────────────

events_store = []
alerts_store = []
stats = {
    "total_events": 0,
    "alerts": 0,
    "integrity_failures": 0,
    "start_time": datetime.now().isoformat()
}

_lock = threading.Lock()

# ─── Hashing ──────────────────────────────────────────────────────────────────

def compute_hash(filepath: str, algo="sha256") -> str | None:
    """Compute SHA256 hash of a file. Returns None if file unreadable."""
    try:
        h = hashlib.new(algo)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (IOError, PermissionError, OSError):
        return None

def load_hash_db() -> dict:
    if os.path.exists(HASH_DB):
        with open(HASH_DB, "r") as f:
            return json.load(f)
    return {}

def save_hash_db(db: dict):
    with open(HASH_DB, "w") as f:
        json.dump(db, f, indent=2)

# ─── Classification ───────────────────────────────────────────────────────────

def is_sensitive_file(path: str) -> bool:
    ext = Path(path).suffix.lower()
    if ext in SENSITIVE_EXTENSIONS:
        return True
    for sdir in SENSITIVE_DIRS:
        if path.startswith(sdir):
            return True
    return False

def is_suspicious_destination(path: str) -> bool:
    for dest in SUSPICIOUS_DESTINATIONS:
        if path.startswith(dest):
            return True
    return False

def classify_event(event_type: str, src_path: str, dest_path: str = "") -> dict:
    sensitive = is_sensitive_file(src_path)
    suspicious = is_suspicious_destination(dest_path) if dest_path else False

    if suspicious and sensitive:
        severity = "CRITICAL"
    elif suspicious or (sensitive and event_type in ["deleted", "modified"]):
        severity = "HIGH"
    elif sensitive:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "sensitive": sensitive,
        "suspicious_dest": suspicious,
        "severity": severity
    }

# ─── Logging ──────────────────────────────────────────────────────────────────

def log_event(record: dict):
    with _lock:
        events_store.append(record)
        stats["total_events"] += 1

        if record.get("severity") in ("HIGH", "CRITICAL"):
            alerts_store.append(record)
            stats["alerts"] += 1

        if record.get("integrity_status") == "MISMATCH":
            stats["integrity_failures"] += 1

    # Persist to JSONL file
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

# ─── Event Handler ────────────────────────────────────────────────────────────

class SecureFileHandler(FileSystemEventHandler):

    def __init__(self):
        self.hash_db = load_hash_db()

    def _build_record(self, event_type: str, src: str, dest: str = "") -> dict:
        classification = classify_event(event_type, src, dest)
        file_hash = compute_hash(src) if os.path.isfile(src) else None

        # Integrity check
        integrity_status = "OK"
        prev_hash = self.hash_db.get(src)
        if file_hash:
            if prev_hash and prev_hash != file_hash:
                integrity_status = "MISMATCH"
            self.hash_db[src] = file_hash
            save_hash_db(self.hash_db)

        record = {
            "id": int(time.time() * 1000),
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "src_path": src,
            "dest_path": dest,
            "file_hash": file_hash,
            "integrity_status": integrity_status,
            **classification,
            "alert_message": _build_alert_message(event_type, src, dest, classification, integrity_status)
        }
        return record

    def on_created(self, event):
        if event.is_directory:
            return
        record = self._build_record("created", event.src_path)
        log_event(record)

    def on_modified(self, event):
        if event.is_directory:
            return
        record = self._build_record("modified", event.src_path)
        log_event(record)

    def on_deleted(self, event):
        if event.is_directory:
            return
        record = self._build_record("deleted", event.src_path)
        log_event(record)

    def on_moved(self, event):
        if event.is_directory:
            return
        record = self._build_record("moved", event.src_path, event.dest_path)
        log_event(record)


def _build_alert_message(event_type, src, dest, cls, integrity):
    if integrity == "MISMATCH":
        return f"⚠ Integrity failure: Hash mismatch detected in {os.path.basename(src)}"
    if cls["suspicious_dest"] and cls["sensitive"]:
        return f"🚨 CRITICAL: Sensitive file '{os.path.basename(src)}' moved to suspicious destination"
    if cls["suspicious_dest"]:
        return f"⚠ Suspicious destination: File moved to {dest}"
    if cls["sensitive"] and event_type == "deleted":
        return f"⚠ Sensitive file deleted: {os.path.basename(src)}"
    if cls["sensitive"]:
        return f"ℹ Sensitive file {event_type}: {os.path.basename(src)}"
    return f"File {event_type}: {os.path.basename(src)}"


# ─── Observer control ─────────────────────────────────────────────────────────

_observer = None

def start_monitoring(watch_dirs: list = None):
    global _observer
    if _observer and _observer.is_alive():
        return

    dirs = watch_dirs or SENSITIVE_DIRS
    handler = SecureFileHandler()
    _observer = Observer()

    for d in dirs:
        if os.path.exists(d):
            _observer.schedule(handler, d, recursive=True)

    _observer.start()
    print(f"[SFMS] Monitoring started on: {dirs}")

def stop_monitoring():
    global _observer
    if _observer:
        _observer.stop()
        _observer.join()
        print("[SFMS] Monitoring stopped.")

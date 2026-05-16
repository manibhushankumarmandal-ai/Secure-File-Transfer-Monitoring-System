"""
Secure File Transfer Monitoring System
CLI Mode — run without Flask for terminal-only monitoring
Usage: python cli_monitor.py [directory_to_watch]
"""

import sys
import time
import signal
import os
from monitor import start_monitoring, stop_monitoring, events_store, stats

COLORS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH":     "\033[33m",  # yellow
    "MEDIUM":   "\033[93m",  # bright yellow
    "LOW":      "\033[92m",  # green
    "RESET":    "\033[0m",
    "CYAN":     "\033[96m",
    "BOLD":     "\033[1m",
}

def banner():
    print(f"""
{COLORS['CYAN']}{COLORS['BOLD']}
╔══════════════════════════════════════════════════════╗
║    SECURE FILE TRANSFER MONITORING SYSTEM (SFMS)    ║
║             CLI Mode — Real-time Monitor             ║
╚══════════════════════════════════════════════════════╝
{COLORS['RESET']}""")

def print_event(record):
    sev   = record.get("severity", "LOW")
    col   = COLORS.get(sev, COLORS["RESET"])
    etype = record.get("event_type", "").upper().ljust(8)
    fname = os.path.basename(record.get("src_path", ""))
    ts    = record.get("timestamp", "")[-8:]
    ihash = record.get("integrity_status", "")
    alert = " ⚠ INTEGRITY MISMATCH" if ihash == "MISMATCH" else ""
    msg   = record.get("alert_message", "")

    print(f"{COLORS['RESET']}[{ts}] {col}[{sev}]{COLORS['RESET']} {etype} {fname}{COLORS['91m']}{alert}{COLORS['RESET']}")
    if sev in ("HIGH", "CRITICAL"):
        print(f"         → {col}{msg}{COLORS['RESET']}")

seen = set()

def poll_and_print():
    while True:
        for ev in events_store:
            eid = ev.get("id")
            if eid not in seen:
                seen.add(eid)
                print_event(ev)
        time.sleep(0.5)

def on_exit(sig, frame):
    stop_monitoring()
    print(f"\n{COLORS['CYAN']}[SFMS] Stopped. Summary:{COLORS['RESET']}")
    print(f"  Total Events : {stats['total_events']}")
    print(f"  Alerts       : {stats['alerts']}")
    print(f"  Integrity ✗  : {stats['integrity_failures']}")
    sys.exit(0)

if __name__ == "__main__":
    banner()
    dirs = sys.argv[1:] if len(sys.argv) > 1 else None
    signal.signal(signal.SIGINT, on_exit)
    start_monitoring(dirs)
    print(f"{COLORS['CYAN']}Monitoring active. Press Ctrl+C to stop.{COLORS['RESET']}\n")
    poll_and_print()

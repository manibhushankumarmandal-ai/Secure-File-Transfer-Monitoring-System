"""
Secure File Transfer Monitoring System
Flask Web Dashboard + REST API
"""

import os
import csv
import json
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request, send_file
from monitor import (
    start_monitoring, stop_monitoring,
    events_store, alerts_store, stats,
    SENSITIVE_DIRS, LOG_FILE
)

app = Flask(__name__)

# ─── State ────────────────────────────────────────────────────────────────────

monitoring_active = False
monitor_thread = None

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    return jsonify({
        **stats,
        "monitoring": monitoring_active,
        "watched_dirs": SENSITIVE_DIRS
    })


@app.route("/api/events")
def api_events():
    severity = request.args.get("severity")       # filter by severity
    limit    = int(request.args.get("limit", 100))
    
    data = list(reversed(events_store))           # newest first
    if severity and severity != "ALL":
        data = [e for e in data if e.get("severity") == severity]
    
    return jsonify(data[:limit])


@app.route("/api/alerts")
def api_alerts():
    limit = int(request.args.get("limit", 50))
    return jsonify(list(reversed(alerts_store))[:limit])


@app.route("/api/monitor/start", methods=["POST"])
def api_start():
    global monitoring_active, monitor_thread
    if monitoring_active:
        return jsonify({"status": "already_running"})
    
    monitoring_active = True
    monitor_thread = threading.Thread(target=start_monitoring, daemon=True)
    monitor_thread.start()
    return jsonify({"status": "started", "watched": SENSITIVE_DIRS})


@app.route("/api/monitor/stop", methods=["POST"])
def api_stop():
    global monitoring_active
    stop_monitoring()
    monitoring_active = False
    return jsonify({"status": "stopped"})


@app.route("/api/report/csv")
def download_csv():
    """Generate and download CSV audit report."""
    report_path = os.path.join(os.path.dirname(__file__), "reports", "audit_report.csv")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    with open(report_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "timestamp", "event_type", "severity",
            "src_path", "dest_path", "file_hash",
            "integrity_status", "sensitive",
            "suspicious_dest", "alert_message"
        ])
        writer.writeheader()
        for event in events_store:
            writer.writerow({k: event.get(k, "") for k in writer.fieldnames})

    return send_file(report_path, as_attachment=True, download_name=f"sfms_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")


@app.route("/api/report/json")
def download_json():
    """Download full JSON log."""
    report_path = os.path.join(os.path.dirname(__file__), "reports", "audit_report.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    
    with open(report_path, "w") as f:
        json.dump({
            "generated_at": datetime.now().isoformat(),
            "stats": stats,
            "events": events_store,
            "alerts": alerts_store
        }, f, indent=2)

    return send_file(report_path, as_attachment=True, download_name=f"sfms_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")


@app.route("/api/clear", methods=["POST"])
def api_clear():
    events_store.clear()
    alerts_store.clear()
    stats["total_events"] = 0
    stats["alerts"] = 0
    stats["integrity_failures"] = 0
    return jsonify({"status": "cleared"})


# ─── Run ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    os.makedirs(os.path.join(os.path.dirname(__file__), "logs"), exist_ok=True)
    os.makedirs(os.path.join(os.path.dirname(__file__), "reports"), exist_ok=True)
    print("\n🛡  Secure File Transfer Monitoring System")
    print("   Dashboard → http://127.0.0.1:5000\n")
    app.run(debug=True, use_reloader=False)

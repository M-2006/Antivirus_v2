import json
import os
from datetime import datetime

REPORT_FILE = "report.json"
ACTION_LOG_FILE = "actions.log"


def save_report(result: dict):
    """Append a scan result to the report log (keeps full history)."""
    entry = {
        "timestamp": str(datetime.now()),
        "result": result,
    }

    history = []
    if os.path.exists(REPORT_FILE):
        try:
            with open(REPORT_FILE, "r") as f:
                history = json.load(f)
            if not isinstance(history, list):
                history = [history]
        except (json.JSONDecodeError, ValueError):
            history = []

    history.append(entry)

    with open(REPORT_FILE, "w") as f:
        json.dump(history, f, indent=4)


def log_action(message: str):
    """Append a timestamped action message to the action log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ACTION_LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

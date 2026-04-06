import time
import json
import os

REPORT_FILE = "report.json"


def replay_log(delay: float = 1.0):
    """Replay all saved scan findings from report.json."""
    if not os.path.exists(REPORT_FILE):
        print("No report file found.")
        return

    with open(REPORT_FILE, "r") as f:
        history = json.load(f)

    if not isinstance(history, list):
        history = [history]

    print(f"Replaying {len(history)} scan(s)...\n")

    for i, entry in enumerate(history, 1):
        ts = entry.get("timestamp", "unknown time")
        result = entry.get("result", {})
        verdict = result.get("verdict", "?")
        score = result.get("score", 0)
        findings = result.get("findings", [])

        print(f"[Scan {i}] {ts} — Verdict: {verdict} | Score: {score}")
        for finding in findings:
            print(f"  {finding}")
            time.sleep(delay)
        print()

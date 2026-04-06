from config import (
    CPU_THRESHOLD,
    MEMORY_THRESHOLD_MB,
    RISK_SAFE,
    RISK_SUSPICIOUS,
    SUSPICIOUS_KEYWORDS,
)
from ml_detector import predict as ml_predict


def analyze(data):
    """Analyze scanned process data and return a risk verdict."""
    score = 0
    findings = []
    flagged_pids = []

    for proc in data["processes"]:
        name = proc.get("name") or ""
        name_lower = name.lower()
        exe = (proc.get("exe") or "").lower()
        cpu = proc.get("cpu_percent") or 0
        memory_mb = proc.get("memory_mb") or 0
        pid = proc.get("pid")

        proc_flagged = False

        # High CPU usage
        if cpu > CPU_THRESHOLD:
            score += 20
            findings.append(f"⚠ High CPU ({cpu:.1f}%): {name} [PID {pid}]")
            proc_flagged = True

        # High memory usage
        if memory_mb > MEMORY_THRESHOLD_MB:
            score += 15
            findings.append(f"⚠ High Memory ({memory_mb:.0f} MB): {name} [PID {pid}]")
            proc_flagged = True

        # Suspicious name keywords
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in name_lower:
                score += 30
                findings.append(f"🚨 Suspicious name keyword '{keyword}': {name} [PID {pid}]")
                proc_flagged = True
                break

        # Suspicious path indicators
        suspicious_paths = ["\\temp\\", "/tmp/", "\\appdata\\local\\temp", "\\downloads\\"]
        for sp in suspicious_paths:
            if sp in exe:
                score += 25
                findings.append(f"🚨 Runs from suspicious path: {name} [PID {pid}] → {exe}")
                proc_flagged = True
                break

        # ML anomaly detection
        if ml_predict(proc):
            score += 25
            findings.append(f"🧠 ML anomaly detected: {name} [PID {pid}]")
            proc_flagged = True

        if proc_flagged and pid is not None:
            flagged_pids.append(pid)

    # Clamp score to 100
    score = min(score, 100)

    if score < RISK_SAFE:
        verdict = "SAFE"
    elif score < RISK_SUSPICIOUS:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "flagged_pids": flagged_pids,
        "total_processes": data.get("total", 0),
    }

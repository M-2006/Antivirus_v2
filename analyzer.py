"""
analyzer.py — Per-process threat analysis
Integrates:
  - Heuristic scoring (CPU, RAM, path, keywords)
  - ML anomaly detection with confidence score
  - MalwareBazaar hash lookup (via signatures.py)
"""

from config import (
    CPU_THRESHOLD,
    MEMORY_THRESHOLD_MB,
    RISK_SAFE,
    RISK_SUSPICIOUS,
    SUSPICIOUS_KEYWORDS,
)
from ml_detector import predict_batch
from signatures import check_processes_batch


def analyze(data: dict, check_hashes: bool = True) -> dict:
    """
    Analyze scanned process data. Returns per-process verdicts + summary.

    Args:
        data:          Output of scanner.scan_system()
        check_hashes:  Set False to skip MalwareBazaar lookups (faster, offline)
    """
    processes = data.get("processes", [])
    if not processes:
        return _empty_result()

    # ── Batch operations (efficient) ──────────────────────────
    ml_results = predict_batch(processes)   # [(is_anomaly, confidence), ...]

    hash_results = {}
    if check_hashes:
        hash_results = check_processes_batch(processes, max_checks=30)

    # ── Per-process scoring ───────────────────────────────────
    per_process = []
    total_score  = 0
    all_findings = []
    flagged_pids = []

    for i, proc in enumerate(processes):
        name       = proc.get("name") or ""
        name_lower = name.lower()
        exe        = (proc.get("exe") or "").lower()
        cpu        = proc.get("cpu_percent") or 0
        mem_mb     = proc.get("memory_mb") or 0
        pid        = proc.get("pid")

        proc_score    = 0
        proc_findings = []

        # 1. High CPU
        if cpu > CPU_THRESHOLD:
            proc_score += 20
            proc_findings.append(f"⚠ High CPU ({cpu:.1f}%)")

        # 2. High memory
        if mem_mb > MEMORY_THRESHOLD_MB:
            proc_score += 15
            proc_findings.append(f"⚠ High Memory ({mem_mb:.0f} MB)")

        # 3. Suspicious name keywords
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in name_lower:
                proc_score += 30
                proc_findings.append(f"🚨 Suspicious keyword '{kw}' in name")
                break

        # 4. Suspicious path
        suspicious_paths = ["\\temp\\", "/tmp/", "\\appdata\\local\\temp",
                            "\\downloads\\", "\\recycle", "/var/tmp/"]
        for sp in suspicious_paths:
            if sp in exe:
                proc_score += 25
                proc_findings.append(f"🚨 Runs from suspicious path: {exe}")
                break

        # 5. ML anomaly
        is_anomaly, confidence = ml_results[i]
        if is_anomaly:
            ml_score = int(confidence * 30)  # max +30 from ML
            proc_score += ml_score
            proc_findings.append(f"🧠 ML anomaly (confidence {confidence:.0%})")

        # 6. MalwareBazaar hash match
        hash_result = hash_results.get(pid, {})
        if hash_result.get("malicious"):
            proc_score += 100   # definitive — override everything
            sig = hash_result.get("signature") or "unknown"
            sha = (hash_result.get("sha256") or "")[:16]
            proc_findings.append(f"☠ KNOWN MALWARE: {sig} [{sha}...]")

        # Clamp per-process score to 100
        proc_score = min(proc_score, 100)

        verdict = _score_to_verdict(proc_score)

        entry = {
            "pid":      pid,
            "name":     name,
            "score":    proc_score,
            "verdict":  verdict,
            "findings": proc_findings,
            "exe":      proc.get("exe") or "",
        }
        per_process.append(entry)

        if proc_score > 0:
            flagged_pids.append(pid)
            for f in proc_findings:
                all_findings.append(f"{f}: {name} [PID {pid}]")
            total_score = max(total_score, proc_score)  # global = worst process

    global_verdict = _score_to_verdict(total_score)

    return {
        "score":           total_score,
        "verdict":         global_verdict,
        "findings":        all_findings,
        "flagged_pids":    flagged_pids,
        "total_processes": data.get("total", 0),
        "per_process":     per_process,
        "hash_checked":    len(hash_results),
    }


def _score_to_verdict(score: int) -> str:
    if score < RISK_SAFE:
        return "SAFE"
    if score < RISK_SUSPICIOUS:
        return "SUSPICIOUS"
    return "MALICIOUS"


def _empty_result() -> dict:
    return {
        "score":           0,
        "verdict":         "SAFE",
        "findings":        [],
        "flagged_pids":    [],
        "total_processes": 0,
        "per_process":     [],
        "hash_checked":    0,
    }

"""
ml_detector.py — Process anomaly detection via IsolationForest
Improvements over v1:
  - 12 features instead of 4 (threads, connections, handles, entropy, etc.)
  - Auto-train on first run if no model exists
  - Per-process verdict with confidence score
  - Model versioning (retrain if feature count changes)
  - Thread-safe lazy loading
"""

import os
import threading
import time
import hashlib
import math
import numpy as np
import psutil

MODEL_FILE    = "model.pkl"
MODEL_VERSION = "v2"           # Bump this when features change → forces retrain
VERSION_FILE  = "model.version"

_model      = None
_model_lock = threading.Lock()

# ── Feature extraction ────────────────────────────────────────
def extract_features(proc: dict) -> list[float]:
    """
    12-feature vector per process.
    All features are normalized to floats; missing = 0.0.
    """
    name     = proc.get("name") or ""
    exe      = proc.get("exe") or ""
    cpu      = float(proc.get("cpu_percent") or 0)
    mem_mb   = float(proc.get("memory_mb") or 0)
    pid      = int(proc.get("pid") or 0)
    status   = proc.get("status") or ""

    # Try to get live psutil data for richer features
    threads      = 0
    connections  = 0
    open_files   = 0
    children     = 0
    create_time  = 0.0

    try:
        p = psutil.Process(pid)
        threads     = p.num_threads()
        connections = len(p.net_connections())
        open_files  = len(p.open_files())
        children    = len(p.children())
        create_time = p.create_time()
    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
        pass

    # Process age in minutes (newer processes are more suspicious)
    age_minutes = (time.time() - create_time) / 60 if create_time else 0

    # Name entropy — randomized names (malware) have high entropy
    name_entropy = _shannon_entropy(name)

    # Path suspicion score
    suspicious_paths = ["\\temp\\", "/tmp/", "\\appdata\\local\\temp",
                        "\\downloads\\", "\\recycle", "/var/tmp/"]
    path_suspicious = float(any(sp in exe.lower() for sp in suspicious_paths))

    # No exe path = hidden/injected process
    no_exe = float(not exe)

    return [
        cpu,                    # 1. CPU usage %
        mem_mb,                 # 2. Memory MB
        float(threads),         # 3. Thread count
        float(connections),     # 4. Network connections
        float(open_files),      # 5. Open file handles
        float(children),        # 6. Child processes
        age_minutes,            # 7. Process age (minutes)
        name_entropy,           # 8. Name randomness (entropy)
        float(len(name)),       # 9. Name length
        path_suspicious,        # 10. Runs from suspicious path
        no_exe,                 # 11. No executable path
        float(pid % 1000) / 10, # 12. PID pattern (low PIDs = system, high = suspicious)
    ]

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string — high = random-looking."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

# ── Model management ──────────────────────────────────────────
def _model_version_ok() -> bool:
    """Check if saved model matches current feature version."""
    if not os.path.exists(VERSION_FILE):
        return False
    with open(VERSION_FILE) as f:
        return f.read().strip() == MODEL_VERSION

def _save_model_version() -> None:
    with open(VERSION_FILE, "w") as f:
        f.write(MODEL_VERSION)

def _get_model():
    global _model
    with _model_lock:
        if _model is not None:
            return _model

        # Model exists and is current version → load it
        if os.path.exists(MODEL_FILE) and _model_version_ok():
            import joblib
            _model = joblib.load(MODEL_FILE)
            print(f"[ML] Model loaded from {MODEL_FILE}")
            return _model

        # No model or version mismatch → auto-train on live processes
        print("[ML] No valid model found — auto-training on current processes...")
        procs = _capture_baseline()
        if len(procs) >= 10:
            _train_internal(procs)
        else:
            print("[ML] Not enough processes for training. Skipping.")

        return _model

def _capture_baseline() -> list[dict]:
    """Collect current running processes as baseline (normal state)."""
    processes = []
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'status']):
        try:
            info = p.info.copy()
            try:
                mem = p.memory_info()
                info['memory_mb'] = round(mem.rss / (1024 * 1024), 2)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info['memory_mb'] = 0
            try:
                info['exe'] = p.exe()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                info['exe'] = ""
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Warm up CPU percent (first call returns 0)
    time.sleep(0.5)
    for p_info in processes:
        try:
            p = psutil.Process(p_info['pid'])
            p_info['cpu_percent'] = p.cpu_percent()
        except Exception:
            pass

    return processes

def _train_internal(processes: list[dict]) -> None:
    """Core training logic — called with lock already held."""
    global _model
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler
    import joblib

    X_raw = np.array([extract_features(p) for p in processes])

    # RobustScaler handles outliers better than StandardScaler for this use case
    scaler = RobustScaler()
    X = scaler.fit_transform(X_raw)

    model = IsolationForest(
        contamination=0.05,   # assume ~5% processes are anomalous
        n_estimators=200,     # more trees = more stable
        max_samples="auto",
        random_state=42,
        n_jobs=-1,            # use all CPU cores
    )
    model.fit(X)

    # Bundle model + scaler so predict() always uses same scaling
    bundle = {"model": model, "scaler": scaler, "feature_count": X_raw.shape[1]}
    joblib.dump(bundle, MODEL_FILE)
    _save_model_version()
    _model = bundle

    print(f"[ML] Trained on {len(processes)} processes ({X_raw.shape[1]} features). Saved to {MODEL_FILE}")

# ── Public API ────────────────────────────────────────────────
def train_model(processes: list[dict] | None = None) -> None:
    """
    Train/retrain the model. If processes=None, captures live baseline.
    
    Example:
        from ml_detector import train_model
        train_model()   # auto-capture
    """
    global _model
    with _model_lock:
        if processes is None:
            print("[ML] Capturing live baseline...")
            processes = _capture_baseline()

        if len(processes) < 10:
            print(f"[ML] Need at least 10 processes, got {len(processes)}. Aborting.")
            return

        _train_internal(processes)

def predict(proc: dict) -> tuple[bool, float]:
    """
    Returns (is_anomalous: bool, confidence: float 0.0–1.0).
    confidence = how anomalous (1.0 = maximally suspicious).
    Returns (False, 0.0) if no model available.
    """
    bundle = _get_model()
    if bundle is None:
        return False, 0.0

    model   = bundle["model"]
    scaler  = bundle["scaler"]

    X_raw = np.array([extract_features(proc)])
    X     = scaler.transform(X_raw)

    prediction = model.predict(X)[0]          # -1 = anomaly, 1 = normal
    score      = model.score_samples(X)[0]    # more negative = more anomalous

    # Normalize score to 0–1 confidence
    # IsolationForest scores typically range from ~-0.8 to ~0.2
    confidence = max(0.0, min(1.0, (-score) / 0.8))

    return prediction == -1, round(confidence, 3)

def predict_batch(processes: list[dict]) -> list[tuple[bool, float]]:
    """Batch predict — much faster than calling predict() in a loop."""
    bundle = _get_model()
    if bundle is None:
        return [(False, 0.0)] * len(processes)

    model  = bundle["model"]
    scaler = bundle["scaler"]

    X_raw       = np.array([extract_features(p) for p in processes])
    X           = scaler.transform(X_raw)
    predictions = model.predict(X)
    scores      = model.score_samples(X)

    return [
        (pred == -1, round(max(0.0, min(1.0, (-sc) / 0.8)), 3))
        for pred, sc in zip(predictions, scores)
    ]

def model_info() -> dict:
    """Return info about the current model."""
    bundle = _get_model()
    if bundle is None:
        return {"status": "no model"}
    return {
        "status":        "loaded",
        "version":       MODEL_VERSION,
        "feature_count": bundle.get("feature_count"),
        "model_file":    MODEL_FILE,
    }

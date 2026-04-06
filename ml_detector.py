import os
import numpy as np

MODEL_FILE = "model.pkl"

# Lazy-load sklearn to avoid slow import at startup
_model = None


def _get_model():
    global _model
    if _model is None and os.path.exists(MODEL_FILE):
        import joblib
        _model = joblib.load(MODEL_FILE)
    return _model


def extract_features(proc: dict) -> list:
    """Convert a process dict into a feature vector."""
    return [
        float(proc.get("cpu_percent") or 0),
        float(proc.get("memory_mb") or 0),
        1.0 if not proc.get("exe") else 0.0,   # no executable path = suspicious
        float(len(proc.get("name") or "")),
    ]


def train_model(normal_procs: list[dict]):
    """
    Train an IsolationForest on a list of known-normal process dicts
    and persist the model to disk.

    Call this once with a clean baseline capture, e.g.:
        from scanner import scan_system
        from ml_detector import train_model
        train_model(scan_system()["processes"])
    """
    from sklearn.ensemble import IsolationForest
    import joblib

    X = np.array([extract_features(p) for p in normal_procs])
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(X)
    joblib.dump(model, MODEL_FILE)
    print(f"[ML] Model trained on {len(normal_procs)} processes and saved to {MODEL_FILE}")


def predict(proc: dict) -> bool:
    """
    Returns True if the process looks anomalous.
    Returns False if no model is available (safe default).
    """
    model = _get_model()
    if model is None:
        return False
    X = np.array([extract_features(proc)])
    return model.predict(X)[0] == -1  # -1 = anomaly in IsolationForest

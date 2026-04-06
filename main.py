import threading
from gui import Dashboard
import dashboard as web_dash
from watcher import start_watcher
from signatures import update_signatures
from utils import log_action
from config import WATCH_DIRECTORY, WEB_DASHBOARD_PORT


def on_new_file(path: str):
    """Callback fired by the file watcher when a new file appears."""
    import hashlib
    from virustotal import check_hash
    from ml_detector import predict

    log_action(f"New file detected: {path}")

    # Hash the file
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        digest = h.hexdigest()
    except (PermissionError, OSError):
        return

    # VirusTotal check
    vt_result = check_hash(digest)
    if vt_result and vt_result.get("malicious", 0) > 0:
        log_action(f"VT MALICIOUS: {path} — {vt_result['malicious']} engines flagged")

    # ML anomaly check (using a dummy proc dict for file-based features)
    fake_proc = {"cpu_percent": 0, "memory_mb": 0, "exe": path, "name": path.split("/")[-1]}
    if predict(fake_proc):
        log_action(f"ML ANOMALY detected for new file: {path}")


if __name__ == "__main__":
    # Update signatures on startup
    update_signatures()

    # Start web dashboard in background
    threading.Thread(
        target=web_dash.app.run,
        kwargs={"port": WEB_DASHBOARD_PORT, "use_reloader": False},
        daemon=True,
    ).start()
    print(f"Web dashboard running at http://localhost:{WEB_DASHBOARD_PORT}")

    # Start file watcher
    watcher = start_watcher(WATCH_DIRECTORY, on_new_file)

    # Launch GUI
    app = Dashboard()
    try:
        app.run()
    finally:
        watcher.stop()
        watcher.join()

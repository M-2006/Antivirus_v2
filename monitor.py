import threading
import time

from scanner import scan_system
from analyzer import analyze
from utils import save_report
from signatures import update_signatures
from config import SCAN_INTERVAL, SIGNATURE_UPDATE_INTERVAL

_running = False
_thread: threading.Thread | None = None
_lock = threading.Lock()


def start_monitoring(callback, root=None):
    """
    Start the background monitoring loop.

    Args:
        callback: function(result) called after each scan.
        root: optional tkinter root — if provided, callback is
              scheduled via root.after() so it runs on the UI thread.
    """
    global _running, _thread

    with _lock:
        if _running:
            return  # already running
        _running = True

    def loop():
        global _running
        last_sig_update = 0

        while _running:
            # Periodically refresh the signature database
            now = time.time()
            if now - last_sig_update > SIGNATURE_UPDATE_INTERVAL:
                update_signatures()
                last_sig_update = now

            data = scan_system()
            result = analyze(data)
            save_report(result)

            if root is not None:
                root.after(0, callback, result)
            else:
                callback(result)

            time.sleep(SCAN_INTERVAL)

    _thread = threading.Thread(target=loop, daemon=True, name="MonitorThread")
    _thread.start()


def stop_monitoring():
    """Signal the monitoring loop to stop."""
    global _running
    with _lock:
        _running = False


def is_running() -> bool:
    return _running

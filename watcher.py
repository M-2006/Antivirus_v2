from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from utils import log_action


class _ThreatHandler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self._callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self._callback(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._callback(event.src_path)


def start_watcher(path: str, callback) -> Observer:
    """
    Start watching `path` recursively.
    `callback(file_path: str)` is called on every new/modified file.
    Returns the Observer so the caller can stop it with observer.stop().
    """
    log_action(f"File watcher started on: {path}")
    observer = Observer()
    observer.schedule(_ThreatHandler(callback), path=path, recursive=True)
    observer.start()
    return observer

import os
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import DIR_SCAN_MAX_WORKERS


def hash_file(path: str) -> str | None:
    """Compute SHA-256 hash of a file. Returns None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None


def scan_directory(root: str, known_hashes: set, max_workers: int = DIR_SCAN_MAX_WORKERS) -> list[dict]:
    """
    Recursively scan a directory using a thread pool.
    Returns a list of dicts for files whose hash matches known_hashes.
    """
    files = [
        os.path.join(dp, fname)
        for dp, _, fnames in os.walk(root)
        for fname in fnames
    ]

    findings = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(hash_file, p): p for p in files}
        for future in as_completed(future_to_path):
            path = future_to_path[future]
            digest = future.result()
            if digest and digest in known_hashes:
                findings.append({"path": path, "hash": digest})

    return findings

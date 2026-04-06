import requests
import json
import os
import time

from config import SIGNATURE_URL

LOCAL_SIG_FILE = "signatures.json"
_last_update: float = 0


def update_signatures() -> bool:
    """Fetch the latest signature database from the remote URL."""
    global _last_update
    try:
        r = requests.get(SIGNATURE_URL, timeout=10)
        r.raise_for_status()
        data = r.json()
        with open(LOCAL_SIG_FILE, "w") as f:
            json.dump(data, f, indent=2)
        _last_update = time.time()
        print(f"[Signatures] Updated — {len(data.get('hashes', []))} hashes loaded.")
        return True
    except Exception as e:
        print(f"[Signatures] Update failed: {e}")
        return False


def load_signatures() -> dict:
    """Load signatures from disk, fetching remotely if not present."""
    if not os.path.exists(LOCAL_SIG_FILE):
        update_signatures()
    if not os.path.exists(LOCAL_SIG_FILE):
        # Still not available — return empty
        return {"hashes": [], "keywords": []}
    with open(LOCAL_SIG_FILE) as f:
        return json.load(f)

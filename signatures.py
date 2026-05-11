"""
signatures.py — Hash-based threat detection via MalwareBazaar API
Replaces the broken placeholder SIGNATURE_URL approach.

Usage:
    from signatures import check_file_hash, check_process_exe

MalwareBazaar API: https://bazaar.abuse.ch/api/
No API key required for hash lookups.
"""

import hashlib
import json
import os
import time
import requests

# ── Config ────────────────────────────────────────────────────
BAZAAR_API_URL   = "https://mb-api.abuse.ch/api/v1/"
LOCAL_CACHE_FILE = "hash_cache.json"
CACHE_TTL        = 86400  # 24h — don't re-query known hashes
REQUEST_TIMEOUT  = 8

# ── Cache ─────────────────────────────────────────────────────
_cache: dict = {}
_cache_dirty = False

def _load_cache() -> None:
    global _cache
    if os.path.exists(LOCAL_CACHE_FILE):
        try:
            with open(LOCAL_CACHE_FILE) as f:
                _cache = json.load(f)
        except Exception:
            _cache = {}

def _save_cache() -> None:
    global _cache_dirty
    if _cache_dirty:
        try:
            with open(LOCAL_CACHE_FILE, "w") as f:
                json.dump(_cache, f)
            _cache_dirty = False
        except Exception:
            pass

def _cache_get(sha256: str) -> dict | None:
    entry = _cache.get(sha256)
    if entry and (time.time() - entry["ts"]) < CACHE_TTL:
        return entry["result"]
    return None

def _cache_set(sha256: str, result: dict) -> None:
    global _cache_dirty
    _cache[sha256] = {"ts": time.time(), "result": result}
    _cache_dirty = True

# ── Hash computation ──────────────────────────────────────────
def hash_file(path: str, block_size: int = 65536) -> str | None:
    """SHA-256 of a file. Returns None on error (locked/missing)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(block_size):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None

# ── MalwareBazaar lookup ──────────────────────────────────────
def lookup_hash(sha256: str) -> dict:
    """
    Query MalwareBazaar for a SHA-256 hash.
    Returns:
        {
            "found": bool,
            "malicious": bool,
            "tags": list[str],
            "signature": str | None,
            "first_seen": str | None,
        }
    """
    if not sha256:
        return _empty_result()

    # Check local cache first
    cached = _cache_get(sha256)
    if cached is not None:
        return cached

    result = _empty_result()
    try:
        resp = requests.post(
            BAZAAR_API_URL,
            data={"query": "get_info", "hash": sha256},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") == "ok":
            entry = data["data"][0]
            result = {
                "found":      True,
                "malicious":  True,   # In Bazaar = confirmed malware
                "tags":       entry.get("tags") or [],
                "signature":  entry.get("signature"),
                "first_seen": entry.get("first_seen"),
                "file_type":  entry.get("file_type_mime"),
            }
        # query_status == "hash_not_found" → clean (result stays empty)

    except requests.exceptions.Timeout:
        print(f"[Signatures] Timeout querying MalwareBazaar for {sha256[:16]}...")
    except Exception as e:
        print(f"[Signatures] Lookup error: {e}")

    _cache_set(sha256, result)
    _save_cache()
    return result

def _empty_result() -> dict:
    return {
        "found":      False,
        "malicious":  False,
        "tags":       [],
        "signature":  None,
        "first_seen": None,
        "file_type":  None,
    }

# ── High-level helpers ────────────────────────────────────────
def check_file_hash(path: str) -> dict:
    """
    Hash a file and check it against MalwareBazaar.
    Returns lookup result + sha256 field.
    """
    sha256 = hash_file(path)
    if not sha256:
        return {**_empty_result(), "sha256": None, "error": "unreadable"}
    result = lookup_hash(sha256)
    result["sha256"] = sha256
    return result

def check_process_exe(proc: dict) -> dict:
    """
    Check a process's executable against MalwareBazaar.
    proc must have an 'exe' key (from scanner.py).
    """
    exe = proc.get("exe") or ""
    if not exe or not os.path.isfile(exe):
        return {**_empty_result(), "sha256": None, "skipped": True}
    return check_file_hash(exe)

# ── Batch check ───────────────────────────────────────────────
def check_processes_batch(processes: list[dict], max_checks: int = 30) -> dict[int, dict]:
    """
    Check up to `max_checks` processes with unique exe paths.
    Skips duplicates (same path = same hash).
    Returns {pid: lookup_result}
    """
    _load_cache()
    results: dict[int, dict] = {}
    seen_paths: set[str] = set()
    path_to_result: dict[str, dict] = {}
    checked = 0

    for proc in processes:
        pid = proc.get("pid")
        exe = proc.get("exe") or ""

        if not exe or not os.path.isfile(exe):
            continue

        if exe in seen_paths:
            results[pid] = path_to_result[exe]
            continue

        if checked >= max_checks:
            break

        result = check_file_hash(exe)
        results[pid] = result
        path_to_result[exe] = result
        seen_paths.add(exe)
        checked += 1

        # Rate-limit: Bazaar allows ~20 req/min on free tier
        time.sleep(0.3)

    _save_cache()
    return results

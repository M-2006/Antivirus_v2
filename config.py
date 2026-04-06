import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

CPU_THRESHOLD = 50
MEMORY_THRESHOLD_MB = 500
RISK_SAFE = 30
RISK_SUSPICIOUS = 70

SUSPICIOUS_KEYWORDS = [
    "unknown", "temp", "hidden", "inject", "hook",
    "keylog", "spy", "rat", "payload"
]

SCAN_INTERVAL = 5
MAX_LOG_ENTRIES = 500

# ── API CONFIG ────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

if not VIRUSTOTAL_API_KEY:
    raise ValueError("VIRUSTOTAL_API_KEY not set in environment variables")

# ── OTHER SETTINGS ────────────────────────────────────────────
SIGNATURE_URL = "https://raw.githubusercontent.com/yourrepo/sigs/main/signatures.json"
SIGNATURE_UPDATE_INTERVAL = 3600
WATCH_DIRECTORY = "C:/Users"
WEB_DASHBOARD_PORT = 5000
ML_CONTAMINATION = 0.05
DIR_SCAN_MAX_WORKERS = 8

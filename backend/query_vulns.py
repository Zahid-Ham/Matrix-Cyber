
import sqlite3
import os

db_path = "matrix.db"
scan_id = 43

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    cursor.execute("SELECT vulnerability_type, severity, title FROM vulnerabilities WHERE scan_id = ?;", (scan_id,))
    rows = cursor.fetchall()
    print(f"Findings for Scan {scan_id}:")
    print("-" * 50)
    for row in rows:
        print(f"[{row[1]}] {row[0]}: {row[2]}")
    if not rows:
        print("No findings found.")
except Exception as e:
    print(f"Error querying database: {e}")
finally:
    conn.close()

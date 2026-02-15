
import sqlite3
import os

db_path = "matrix.db"
scan_id = 43

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    cursor.execute("SELECT scan_type, agents_enabled FROM scans WHERE id = ?;", (scan_id,))
    row = cursor.fetchone()
    print(f"Scan {scan_id} Type: {row[0]}")
    print(f"Agents Enabled: {row[1]}")
except Exception as e:
    print(f"Error querying database: {e}")
finally:
    conn.close()

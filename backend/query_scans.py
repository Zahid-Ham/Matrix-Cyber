
import sqlite3
import os

db_path = "matrix.db"
if not os.path.exists(db_path):
    print(f"Database {db_path} not found")
    exit(1)

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    cursor.execute("SELECT id, target_url, status, progress, error_message FROM scans ORDER BY created_at DESC LIMIT 5;")
    rows = cursor.fetchall()
    print("ID | Target URL | Status | Progress | Error")
    print("-" * 50)
    for row in rows:
        print(f"{row[0]} | {row[1]} | {row[2]} | {row[3]}% | {row[4]}")
except Exception as e:
    print(f"Error querying database: {e}")
finally:
    conn.close()

import sqlite3
import os

db_path = "matrix.db"

def check_schema():
    if not os.path.exists(db_path):
        print(f"Database {db_path} not found.")
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = [column[1] for column in cursor.fetchall()]
        print(f"Columns in 'vulnerabilities' table: {columns}")
        
        conn.close()
    except Exception as e:
        print(f"Error checking schema: {e}")

if __name__ == "__main__":
    check_schema()

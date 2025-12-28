import sqlite3
import os

db_path = "matrix.db"

def migrate():
    if not os.path.exists(db_path):
        print(f"Database {db_path} not found.")
        return

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if file_path column exists
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if "file_path" not in columns:
            print(f"Adding 'file_path' column to 'vulnerabilities' table in {db_path}...")
            cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN file_path VARCHAR(1024)")
            cursor.execute("CREATE INDEX idx_vuln_file_path ON vulnerabilities (file_path)")
            conn.commit()
            print("Migration successful.")
        else:
            print("'file_path' column already exists.")
            
        conn.close()
    except Exception as e:
        print(f"Error during migration: {e}")

if __name__ == "__main__":
    migrate()

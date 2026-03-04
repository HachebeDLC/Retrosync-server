import os
import psycopg2
from psycopg2.extras import RealDictCursor

DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "neosync")
DB_USER = os.environ.get("DB_USER", "neosync")
DB_PASS = os.environ.get("DB_PASS", "neosync_secure_password") # Use the default from compose

def get_db_connection():
    return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)

try:
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM users LIMIT 1")
    row = c.fetchone()
    if row:
        print(f"Column names: {list(row.keys())}")
    else:
        print("No users found.")
    conn.close()
except Exception as e:
    print(f"Error: {e}")

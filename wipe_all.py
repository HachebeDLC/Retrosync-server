import os
import psycopg2
import shutil

# --- DB CONFIG ---
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "vaultsync")
DB_USER = os.environ.get("DB_USER", "vaultsync")
DB_PASS = os.environ.get("DB_PASS", "vaultsync_password")
STORAGE_DIR = "/app/storage"

def wipe_all():
    print("🧹 Starting Full Server Wipe...")
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        cursor = conn.cursor()
        
        # 1. Delete ALL records from the database
        cursor.execute("DELETE FROM files")
        conn.commit()
        print("  🗑️ Emptied database 'files' table.")
        
        # 2. Cleanup all physical files
        print("📁 Purging all physical files...")
        if os.path.exists(STORAGE_DIR):
            for item in os.listdir(STORAGE_DIR):
                item_path = os.path.join(STORAGE_DIR, item)
                if os.path.isdir(item_path):
                    for sub_item in os.listdir(item_path):
                        sub_item_path = os.path.join(item_path, sub_item)
                        if os.path.isdir(sub_item_path):
                            shutil.rmtree(sub_item_path)
                        else:
                            os.remove(sub_item_path)
        
        print("✅ Server is now a completely blank slate.")
        conn.close()
        
    except Exception as e:
        print(f"❌ Error during wipe: {e}")

if __name__ == "__main__":
    wipe_all()

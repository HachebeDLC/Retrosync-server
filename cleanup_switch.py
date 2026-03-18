import os
import psycopg2
import shutil

# --- DB CONFIG ---
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "vaultsync")
DB_USER = os.environ.get("DB_USER", "vaultsync")
DB_PASS = os.environ.get("DB_PASS", "vaultsync_password")
STORAGE_DIR = "/app/storage"

def cleanup():
    print("🧹 Starting Switch Pollution Cleanup...")
    try:
        conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
        cursor = conn.cursor()
        
        # 1. Identify polluted records
        # Targeting paths that don't start with a valid 0100 Title ID, or contain system keywords
        cursor.execute("""
            SELECT id, user_id, path FROM files 
            WHERE path LIKE 'switch/%' 
            AND (
                path LIKE 'switch/nand%' OR 
                path LIKE 'switch/config%' OR 
                path LIKE 'switch/gpu_drivers%' OR 
                path LIKE 'switch/files%' OR
                path LIKE 'switch/0000000000000000%' OR
                NOT (substring(path from 8) ~ '^0100[0-9A-Fa-f]{12}')
            )
        """)
        
        polluted = cursor.fetchall()
        print(f"🔍 Found {len(polluted)} polluted database records.")
        
        for record_id, user_id, path in polluted:
            # Delete from DB
            cursor.execute("DELETE FROM files WHERE id = %s", (record_id,))
            print(f"  🗑️ Deleted DB record: {path}")
            
            # Delete from Filesystem
            full_path = os.path.join(STORAGE_DIR, str(user_id), path.lstrip("/"))
            if os.path.exists(full_path):
                if os.path.isfile(full_path):
                    os.remove(full_path)
                else:
                    shutil.rmtree(full_path)
                print(f"  📂 Deleted filesystem entry: {full_path}")

        conn.commit()
        
        # 2. Cleanup empty directories
        print("📁 Cleaning up empty Switch system folders...")
        for user_folder in os.listdir(STORAGE_DIR):
            user_switch_dir = os.path.join(STORAGE_DIR, user_folder, "switch")
            if os.path.exists(user_switch_dir):
                for system_folder in ["nand", "gpu_drivers", "config", "files", "0000000000000000"]:
                    polluted_dir = os.path.join(user_switch_dir, system_folder)
                    if os.path.exists(polluted_dir):
                        shutil.rmtree(polluted_dir)
                        print(f"  🔥 Purged polluted directory: {polluted_dir}")

        print("✅ Cleanup complete.")
        conn.close()
        
    except Exception as e:
        print(f"❌ Error during cleanup: {e}")

if __name__ == "__main__":
    cleanup()

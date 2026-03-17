import time
from psycopg2.extras import RealDictCursor
from cachetools import TTLCache

file_metadata_cache = TTLCache(maxsize=10000, ttl=300)

def get_user_by_email(conn, email: str):
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    return cursor.fetchone()

def create_user(conn, email: str, password_hash: str, username: str, salt: str):
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (email, password_hash, username, salt, created_at) VALUES (%s, %s, %s, %s, %s) RETURNING id", 
        (email, password_hash, username, salt, int(time.time()))
    )
    return cursor.fetchone()[0]

def update_user_recovery(conn, user_id: int, recovery_payload: str, recovery_salt: str):
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET recovery_payload = %s, recovery_salt = %s WHERE id = %s", 
        (recovery_payload, recovery_salt, user_id)
    )

def get_recovery_info(conn, email: str):
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "SELECT recovery_payload, recovery_salt FROM users WHERE email = %s", 
        (email,)
    )
    return cursor.fetchone()

def list_user_files(conn, user_id: int, prefix: str = None):
    cursor = conn.cursor(cursor_factory=RealDictCursor)
    if prefix:
        cursor.execute(
            "SELECT path, hash, size, updated_at, device_name FROM files WHERE user_id = %s AND path LIKE %s", 
            (user_id, f"{prefix}%")
        )
    else:
        cursor.execute(
            "SELECT path, hash, size, updated_at, device_name FROM files WHERE user_id = %s", 
            (user_id,)
        )
    return cursor.fetchall()

def get_file_metadata(conn, user_id: int, path: str):
    cache_key = f"{user_id}:{path}"
    if cache_key in file_metadata_cache:
        return file_metadata_cache[cache_key]

    cursor = conn.cursor(cursor_factory=RealDictCursor)
    cursor.execute(
        "SELECT hash, size, updated_at, device_name, blocks FROM files WHERE user_id = %s AND path = %s", 
        (user_id, path)
    )
    result = cursor.fetchone()
    if result:
        file_metadata_cache[cache_key] = result
    return result

def upsert_file_metadata(conn, user_id: int, path: str, hash: str, size: int, updated_at: int, device_name: str, blocks_json: str):
    file_metadata_cache.pop(f"{user_id}:{path}", None)
    cursor = conn.cursor()
    cursor.execute(
        '''INSERT INTO files (user_id, path, hash, size, updated_at, device_name, blocks) 
           VALUES (%s, %s, %s, %s, %s, %s, %s) 
           ON CONFLICT(user_id, path) DO UPDATE SET 
           hash=EXCLUDED.hash, size=EXCLUDED.size, updated_at=EXCLUDED.updated_at, 
           device_name=EXCLUDED.device_name, blocks=EXCLUDED.blocks''', 
        (user_id, path, hash, size, updated_at, device_name, blocks_json)
    )

def update_file_sync(conn, user_id: int, path: str, hash: str, size: int, updated_at: int, blocks_json: str):
    file_metadata_cache.pop(f"{user_id}:{path}", None)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE files SET hash=%s, size=%s, updated_at=%s, blocks=%s WHERE user_id=%s AND path=%s", 
        (hash, size, updated_at, blocks_json, user_id, path)
    )

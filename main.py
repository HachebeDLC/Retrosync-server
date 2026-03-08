import os
import shutil
import hashlib
import time
import logging
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import List, Optional
from datetime import datetime, timedelta

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, WebSocket, WebSocketDisconnect, Depends, Header, Request, status
from fastapi.responses import JSONResponse, Response, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from starlette.concurrency import run_in_threadpool
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from pydantic import BaseModel
import uvicorn
import json
from jose import JWTError, jwt
from passlib.context import CryptContext

from psycopg2 import pool
from contextlib import contextmanager

# --- Logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("VaultSync")

# --- Configuration ---
SECRET_KEY = os.environ.get("VAULTSYNC_SECRET", "CHANGE_THIS_IN_PROD")
if SECRET_KEY == "CHANGE_THIS_IN_PROD":
    logger.warning("⚠️ CRITICAL SECURITY RISK: SECRET_KEY is set to 'CHANGE_THIS_IN_PROD'. VaultSync will refuse to start in a production-like environment.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30
STORAGE_DIR = os.path.abspath("storage")

# Database Config
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "vaultsync")
DB_USER = os.environ.get("DB_USER", "vaultsync")
DB_PASS = os.environ.get("DB_PASS", "vaultsync_password")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def calculate_file_blocks(file_path: str, chunk_size: int = 1024 * 1024) -> List[str]:
    hashes = []
    if not os.path.exists(file_path): return []
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk: break
            # Using SHA-256 for block-level integrity to match new client standards
            hashes.append(hashlib.sha256(chunk).hexdigest())
    return hashes

def calculate_file_hash(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk: break
            sha256.update(chunk)
    return sha256.hexdigest()

class VersionManager:
    def __init__(self, storage_root: str, max_versions: int = 5):
        self.storage_root = storage_root
        self.max_versions = max_versions

    def get_version_dir(self, user_id: int) -> str:
        d = os.path.join(self.storage_root, str(user_id), ".versions")
        os.makedirs(d, exist_ok=True)
        return d

    def create_version(self, user_id: int, path: str, device_name: str):
        """Moves current file to .versions with a timestamp."""
        source = os.path.normpath(os.path.join(self.storage_root, str(user_id), path.lstrip("/\\")))
        if not os.path.exists(source): return

        v_dir = self.get_version_dir(user_id)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        # Sanitize path for filename
        safe_name = path.replace("/", "_").replace("\\", "_").replace(" ", "_")
        v_filename = f"{safe_name}.~{timestamp}~{device_name}~"
        dest = os.path.join(v_dir, v_filename)
        
        try:
            shutil.copy2(source, dest)
            self._rotate(user_id, path)
            logger.info(f"📦 VERSIONED: {path} -> {v_filename}")
        except Exception as e:
            logger.error(f"Version error: {e}")

    def _rotate(self, user_id: int, path: str):
        """Keep only max_versions for a specific file."""
        v_dir = self.get_version_dir(user_id)
        safe_name = path.replace("/", "_").replace("\\", "_").replace(" ", "_")
        prefix = f"{safe_name}.~"
        versions = sorted([f for f in os.listdir(v_dir) if f.startswith(prefix)])
        while len(versions) > self.max_versions:
            os.remove(os.path.join(v_dir, versions.pop(0)))

    def list_versions(self, user_id: int, path: str) -> List[dict]:
        v_dir = self.get_version_dir(user_id)
        safe_name = path.replace("/", "_").replace("\\", "_").replace(" ", "_")
        prefix = f"{safe_name}.~"
        results = []
        if not os.path.exists(v_dir): return []
        
        versions = sorted([f for f in os.listdir(v_dir) if f.startswith(prefix)], reverse=True)
        for i, v in enumerate(versions):
            full_path = os.path.join(v_dir, v)
            try:
                parts = v.split("~")
                results.append({
                    "version": i + 1,
                    "filename": v,
                    "device_name": parts[2] if len(parts) > 2 else "Unknown",
                    "updated_at": int(os.path.getmtime(full_path) * 1000),
                    "size": os.path.getsize(full_path)
                })
            except: continue
        return results

version_manager = VersionManager(STORAGE_DIR)
limiter = Limiter(key_func=get_remote_address)

# --- Database Connection Pool ---
try:
    db_pool = pool.ThreadedConnectionPool(
        1, 20, 
        host=DB_HOST, 
        database=DB_NAME, 
        user=DB_USER, 
        password=DB_PASS
    )
    logger.info("📡 Database connection pool initialized")
except Exception as e:
    logger.error(f"❌ Could not initialize DB pool: {e}")
    db_pool = None

@contextmanager
def get_db():
    conn = db_pool.getconn()
    try:
        yield conn
    finally:
        db_pool.putconn(conn)

def init_db():
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, 
                username TEXT, encryption_key TEXT, salt TEXT, created_at BIGINT
            )''')
            
            # Migration: Ensure 'salt' column exists for existing tables
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='salt'")
            if not c.fetchone():
                c.execute("ALTER TABLE users ADD COLUMN salt TEXT")
                logger.info("📡 Database migrated: added 'salt' column to 'users'")

            c.execute('''CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), path TEXT NOT NULL, 
                hash TEXT, size BIGINT, updated_at BIGINT, device_name TEXT, blocks TEXT, 
                UNIQUE(user_id, path)
            )''')
            conn.commit()
        logger.info("📡 Database schema verified")
    except Exception as e: 
        logger.error(f"❌ DB Init Error: {e}")

def is_safe_path(user_id: int, path: str) -> bool:
    """Robust path validation to prevent Directory Traversal.
    Allows hidden folders like .versions but prevents escaping user root.
    """
    user_root = os.path.join(STORAGE_DIR, str(user_id))
    # Only lstrip slashes, NOT dots. Stripping dots breaks .versions access.
    requested_path = os.path.abspath(os.path.join(user_root, path.lstrip("/\\")))
    return os.path.commonpath([user_root, requested_path]) == user_root

# ... (VersionManager remains unchanged) ...

app = FastAPI(title="VaultSync Server")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Restrict CORS to localhost and common local IP ranges if possible, or provide a warning
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], # Still permissive for self-hosted ease, but methods are restricted
    allow_credentials=False, 
    allow_methods=["GET", "POST", "DELETE"], 
    allow_headers=["*"]
)
os.makedirs(STORAGE_DIR, exist_ok=True)

class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    username: Optional[str] = None

class FileRequest(BaseModel):
    filename: str

class RestoreRequest(BaseModel):
    remoteFilename: str
    version: int

class BlockCheckRequest(BaseModel):
    path: str
    blocks: List[str]

class FinalizeRequest(BaseModel):
    path: str
    hash: str
    size: Optional[int] = None
    updated_at: int
    device_name: str = "Unknown"

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        with get_db() as conn:
            c = conn.cursor(cursor_factory=RealDictCursor)
            c.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = c.fetchone()
        if user is None: raise HTTPException(status_code=401)
        return user
    except: raise HTTPException(status_code=401)

@app.on_event("shutdown")
def shutdown_db_pool():
    if db_pool:
        db_pool.closeall()
        logger.info("📡 Database connection pool closed")

@app.get("/")
def health_check():
    return {"status": "online", "version": "VaultSync-v1.2-Secure"}

@app.post("/register")
@limiter.limit("5/minute")
def register(request: Request, user: UserRegister):
    hashed_pw = pwd_context.hash(user.password)
    # Generate random 16-byte salt for Zero-Knowledge key derivation
    salt = os.urandom(16).hex()
    
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, password_hash, username, salt, created_at) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                      (user.email, hashed_pw, user.username, salt, int(time.time())))
            user_id = c.fetchone()[0]
            conn.commit()
            token = jwt.encode({"sub": str(user_id), "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}, SECRET_KEY, algorithm=ALGORITHM)
            return {"token": token, "user": {"id": str(user_id), "email": user.email, "salt": salt}}
        except Exception as e:
            conn.rollback()
            logger.error(f"Register error: {e}")
            raise HTTPException(status_code=400, detail="User already exists or data invalid")

@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, credentials: UserLogin):
    with get_db() as conn:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT * FROM users WHERE email = %s", (credentials.email,))
        user = c.fetchone()
    if not user or not pwd_context.verify(credentials.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    token = jwt.encode({"sub": str(user['id']), "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}, SECRET_KEY, algorithm=ALGORITHM)
    
    # Return salt for client-side encryption key derivation. 
    # Fallback to email for legacy users who registered before the salt column was added.
    salt = user['salt'] if user.get('salt') else user['email']
    
    return {"token": token, "user": {"id": str(user['id']), "email": user['email'], "salt": salt}}

@app.get("/auth/me")
def auth_me(current_user = Depends(get_current_user)):
    return {"id": str(current_user['id']), "email": current_user['email']}

@app.get("/api/v1/files")
def list_files(current_user = Depends(get_current_user)):
    with get_db() as conn:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT path, hash, size, updated_at, device_name FROM files WHERE user_id = %s", (current_user['id'],))
        files = c.fetchall()
    return {"files": files}

@app.get("/api/v1/conflicts")
def list_conflicts(current_user = Depends(get_current_user)):
    user_id = current_user['id']
    user_storage = os.path.join(STORAGE_DIR, str(user_id))
    conflicts = []
    
    if os.path.exists(user_storage):
        for root, dirs, files in os.walk(user_storage):
            # Skip the hidden .versions directory
            if ".versions" in root.split(os.sep):
                continue
                
            for file in files:
                if ".sync-conflict-" in file:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, user_storage)
                    parts = file.split("-")
                    device_name = parts[-1] if len(parts) > 1 else "Unknown"
                    conflicts.append({
                        "path": rel_path,
                        "device_name": device_name,
                        "size": os.path.getsize(full_path),
                        "updated_at": int(os.path.getmtime(full_path) * 1000)
                    })
    return {"conflicts": conflicts}

@app.get("/api/v1/versions")
def list_file_versions(path: str, current_user = Depends(get_current_user)):
    if not is_safe_path(current_user['id'], path):
        raise HTTPException(status_code=403, detail="Forbidden path")
    return {"versions": version_manager.list_versions(current_user['id'], path)}

@app.post("/api/v1/versions/restore")
def restore_version(body: RestoreRequest, current_user = Depends(get_current_user)):
    if not is_safe_path(current_user['id'], body.remoteFilename):
        raise HTTPException(status_code=403, detail="Forbidden path")
        
    versions = version_manager.list_versions(current_user['id'], body.remoteFilename)
    if body.version <= 0 or body.version > len(versions): raise HTTPException(status_code=404)
    
    v_info = versions[body.version-1]
    v_path = os.path.join(version_manager.get_version_dir(current_user['id']), v_info['filename'])
    return FileResponse(v_path, media_type="application/octet-stream")

@app.delete("/api/v1/files")
def delete_file(body: FileRequest, current_user = Depends(get_current_user)):
    path = body.filename
    if not is_safe_path(current_user['id'], path):
        raise HTTPException(status_code=403, detail="Forbidden path")
        
    user_id = current_user['id']
    version_manager.create_version(user_id, path, "Server-Delete")
    
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(user_id), path.lstrip("/\\")))
    if os.path.exists(safe_path): os.remove(safe_path)
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM files WHERE user_id = %s AND path = %s", (user_id, path))
        conn.commit()
    return {"message": "Deleted"}

@app.delete("/api/v1/systems/{system_id}")
def delete_system(system_id: str, current_user = Depends(get_current_user)):
    user_id = current_user['id']
    if ".." in system_id or "/" in system_id or "\\" in system_id:
        raise HTTPException(status_code=400, detail="Invalid system ID")

    with get_db() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM files WHERE user_id = %s AND path LIKE %s", (user_id, f"{system_id}/%"))
        conn.commit()
    
    system_dir = os.path.join(STORAGE_DIR, str(user_id), system_id)
    if os.path.exists(system_dir): shutil.rmtree(system_dir)
    return {"message": f"System {system_id} cleared"}

@app.post("/api/v1/blocks/check")
def check_blocks(body: BlockCheckRequest, current_user = Depends(get_current_user)):
    if not is_safe_path(current_user['id'], body.path):
        raise HTTPException(status_code=403)
        
    with get_db() as conn:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT blocks FROM files WHERE user_id = %s AND path = %s", (current_user['id'], body.path))
        row = c.fetchone()
    server_blocks = json.loads(row['blocks']) if row and row['blocks'] else []
    missing = [i for i, h in enumerate(body.blocks) if i >= len(server_blocks) or server_blocks[i] != h]
    return {"missing": missing}

@app.post("/api/v1/upload")
async def upload_fragment(request: Request, current_user = Depends(get_current_user)):
    h = request.headers
    path = h.get("x-vaultsync-path")
    offset = int(h.get("x-vaultsync-offset") or 0)
    
    if not path or not is_safe_path(current_user['id'], path):
        raise HTTPException(status_code=403, detail="Forbidden path")
    
    user_id = current_user['id']
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(user_id), path.lstrip("/\\")))
    os.makedirs(os.path.dirname(safe_path), exist_ok=True)

    if offset == 0 and os.path.exists(safe_path):
        try:
            def get_existing_device():
                with get_db() as conn:
                    c = conn.cursor(cursor_factory=RealDictCursor)
                    c.execute("SELECT device_name FROM files WHERE user_id = %s AND path = %s", (user_id, path))
                    return c.fetchone()
            
            existing = await run_in_threadpool(get_existing_device)
            if existing:
                version_manager.create_version(user_id, path, existing['device_name'])
        except Exception as e:
            logger.error(f"Error in pre-upload versioning: {e}")

    bytes_received = 0
    with open(safe_path, "r+b" if os.path.exists(safe_path) else "wb") as f:
        f.seek(offset)
        async for chunk in request.stream():
            f.write(chunk)
            bytes_received += len(chunk)
            
    return {"message": "Fragment OK", "size": bytes_received}

@app.post("/api/v1/upload/finalize")
def finalize_upload(body: FinalizeRequest, current_user = Depends(get_current_user)):
    if not is_safe_path(current_user['id'], body.path):
        raise HTTPException(status_code=403)
        
    user_id = current_user['id']
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(user_id), body.path.lstrip("/\\")))
    
    if not os.path.exists(safe_path): raise HTTPException(status_code=404)
    
    block_hashes = calculate_file_blocks(safe_path)
    actual_hash = calculate_file_hash(safe_path)
    
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''INSERT INTO files (user_id, path, hash, size, updated_at, device_name, blocks) 
                     VALUES (%s, %s, %s, %s, %s, %s, %s) 
                     ON CONFLICT(user_id, path) DO UPDATE SET 
                     hash=EXCLUDED.hash, size=EXCLUDED.size, updated_at=EXCLUDED.updated_at, device_name=EXCLUDED.device_name, blocks=EXCLUDED.blocks''',
                  (user_id, body.path, actual_hash, body.size or os.path.getsize(safe_path), body.updated_at, body.device_name, json.dumps(block_hashes)))
        conn.commit()
    
    logger.info(f"🏁 FINALIZED: {body.path} (Disk: {os.path.getsize(safe_path)})")
    return {"message": "Success", "disk_size": os.path.getsize(safe_path), "hash": actual_hash}

@app.post("/api/v1/download")
def download_file(body: FileRequest, current_user = Depends(get_current_user)):
    if not is_safe_path(current_user['id'], body.filename):
        raise HTTPException(status_code=403)
        
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(current_user['id']), body.filename.lstrip("/\\")))
    if not os.path.exists(safe_path): raise HTTPException(status_code=404)
    return FileResponse(safe_path, media_type="application/octet-stream")



if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)

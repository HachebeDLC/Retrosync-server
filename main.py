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
from fastapi.responses import JSONResponse, Response, FileResponse, StreamingResponse
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

# Block Protocol Constants
BLOCK_SIZE = 1024 * 1024  # 1MB Plaintext
OVERHEAD = 9 + 16 + 16    # Magic (9) + IV (16) + Padding (16)
ENCRYPTED_BLOCK_SIZE = BLOCK_SIZE + OVERHEAD

def calculate_file_blocks(file_path: str) -> List[str]:
    hashes = []
    if not os.path.exists(file_path): return []
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(BLOCK_SIZE)
            if not chunk: break
            hashes.append(hashlib.sha256(chunk).hexdigest())
    return hashes

def calculate_file_hash(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(BLOCK_SIZE)
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
        source = os.path.normpath(os.path.join(self.storage_root, str(user_id), path.lstrip("/\\")))
        if not os.path.exists(source): return
        v_dir = self.get_version_dir(user_id)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_name = path.replace("/", "_").replace("\\", "_").replace(" ", "_")
        v_filename = f"{safe_name}.~{timestamp}~{device_name}~"
        dest = os.path.join(v_dir, v_filename)
        try:
            shutil.copy2(source, dest)
            self._rotate(user_id, path)
            logger.info(f"📦 VERSIONED: {path} -> {v_filename}")
        except Exception as e: logger.error(f"Version error: {e}")

    def _rotate(self, user_id: int, path: str):
        v_dir = self.get_version_dir(user_id)
        safe_name = path.replace("/", "_").replace("\\", "_").replace(" ", "_")
        prefix = f"{safe_name}.~"
        versions = sorted([f for f in os.listdir(v_dir) if f.startswith(prefix)])
        while len(versions) > self.max_versions: os.remove(os.path.join(v_dir, versions.pop(0)))

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
                results.append({"version": i + 1, "filename": v, "device_name": parts[2] if len(parts) > 2 else "Unknown", "updated_at": int(os.path.getmtime(full_path) * 1000), "size": os.path.getsize(full_path)})
            except: continue
        return results

version_manager = VersionManager(STORAGE_DIR)
limiter = Limiter(key_func=get_remote_address)

try:
    db_pool = pool.ThreadedConnectionPool(1, 20, host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
    logger.info("📡 Database connection pool initialized")
except Exception as e:
    logger.error(f"❌ Could not initialize DB pool: {e}")
    db_pool = None

@contextmanager
def get_db():
    conn = db_pool.getconn()
    try: yield conn
    finally: db_pool.putconn(conn)

def init_db():
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, username TEXT, encryption_key TEXT, salt TEXT, recovery_payload TEXT, recovery_salt TEXT, created_at BIGINT)''')
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='salt'")
            if not c.fetchone(): c.execute("ALTER TABLE users ADD COLUMN salt TEXT")
            c.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='recovery_payload'")
            if not c.fetchone():
                c.execute("ALTER TABLE users ADD COLUMN recovery_payload TEXT")
                c.execute("ALTER TABLE users ADD COLUMN recovery_salt TEXT")
            c.execute('''CREATE TABLE IF NOT EXISTS files (id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), path TEXT NOT NULL, hash TEXT, size BIGINT, updated_at BIGINT, device_name TEXT, blocks TEXT, UNIQUE(user_id, path))''')
            conn.commit()
    except Exception as e: logger.error(f"❌ DB Init Error: {e}")

def is_safe_path(user_id: int, path: str) -> bool:
    user_root = os.path.join(STORAGE_DIR, str(user_id))
    requested_path = os.path.abspath(os.path.join(user_root, path.lstrip("/\\")))
    return os.path.commonpath([user_root, requested_path]) == user_root

app = FastAPI(title="VaultSync Server")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

CORS_ORIGINS = os.environ.get("VAULTSYNC_CORS_ORIGINS", "*").split(",")
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=True if "*" not in CORS_ORIGINS else False, allow_methods=["GET", "POST", "DELETE"], allow_headers=["*"])
os.makedirs(STORAGE_DIR, exist_ok=True)

class UserLogin(BaseModel): email: str; password: str
class UserRegister(BaseModel): email: str; password: str; username: Optional[str] = None
class FileRequest(BaseModel): filename: str
class RestoreRequest(BaseModel): remoteFilename: str; version: int
class BlockCheckRequest(BaseModel): path: str; blocks: List[str]
class BlockDownloadRequest(BaseModel): path: str; indices: List[int]
class FinalizeRequest(BaseModel): path: str; hash: str; size: Optional[int] = None; updated_at: int; device_name: str = "Unknown"
class RecoverySetupRequest(BaseModel): recovery_payload: str; recovery_salt: str
class RecoveryPayloadRequest(BaseModel): email: str

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
    if db_pool: db_pool.closeall()

@app.get("/")
def health_check(): return {"status": "online", "version": "VaultSync-v1.2-Secure"}

@app.post("/register")
@limiter.limit("5/minute")
def register(request: Request, user: UserRegister):
    hashed_pw = pwd_context.hash(user.password)
    salt = os.urandom(16).hex()
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, password_hash, username, salt, created_at) VALUES (%s, %s, %s, %s, %s) RETURNING id", (user.email, hashed_pw, user.username, salt, int(time.time())))
            user_id = c.fetchone()[0]
            conn.commit()
            token = jwt.encode({"sub": str(user_id), "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}, SECRET_KEY, algorithm=ALGORITHM)
            return {"token": token, "user": {"id": str(user_id), "email": user.email, "salt": salt}}
        except Exception as e:
            conn.rollback()
            raise HTTPException(status_code=400, detail="User already exists")

@app.post("/login")
@limiter.limit("5/minute")
def login(request: Request, credentials: UserLogin):
    with get_db() as conn:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT * FROM users WHERE email = %s", (credentials.email,))
        user = c.fetchone()
    if not user or not pwd_context.verify(credentials.password, user['password_hash']): raise HTTPException(status_code=401)
    token = jwt.encode({"sub": str(user['id']), "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token, "user": {"id": str(user['id']), "email": user['email'], "salt": user.get('salt') or user['email']}}

@app.get("/auth/me")
def auth_me(current_user = Depends(get_current_user)): return {"id": str(current_user['id']), "email": current_user['email']}

@app.get("/api/v1/files")
def list_files(current_user = Depends(get_current_user)):
    with get_db() as conn:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT path, hash, size, updated_at, device_name FROM files WHERE user_id = %s", (current_user['id'],))
        return {"files": c.fetchall()}

@app.get("/api/v1/files/manifest")
def get_file_manifest(path: str, current_user = Depends(get_current_user)):
    if not is_safe_path(current_user['id'], path): raise HTTPException(status_code=403)
    with get_db() as conn:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT blocks FROM files WHERE user_id = %s AND path = %s", (current_user['id'], path))
        row = c.fetchone()
    if not row: raise HTTPException(status_code=404)
    return {"path": path, "blocks": json.loads(row['blocks']) if row['blocks'] else []}

@app.post("/api/v1/blocks/check")
def check_blocks(body: BlockCheckRequest, current_user = Depends(get_current_user)):
    if not is_safe_path(current_user['id'], body.path): raise HTTPException(status_code=403)
    with get_db() as conn:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT blocks FROM files WHERE user_id = %s AND path = %s", (current_user['id'], body.path))
        row = c.fetchone()
    server_blocks = json.loads(row['blocks']) if row and row['blocks'] else []
    return {"missing": [i for i, h in enumerate(body.blocks) if i >= len(server_blocks) or server_blocks[i] != h]}

@app.post("/api/v1/blocks/download")
def download_blocks(body: BlockDownloadRequest, current_user = Depends(get_current_user)):
    if not is_safe_path(current_user['id'], body.path): raise HTTPException(status_code=403)
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(current_user['id']), body.path.lstrip("/\\")))
    if not os.path.exists(safe_path): raise HTTPException(status_code=404)

    def iter_blocks():
        with open(safe_path, "rb") as f:
            for index in body.indices:
                offset = index * ENCRYPTED_BLOCK_SIZE
                f.seek(offset)
                chunk = f.read(ENCRYPTED_BLOCK_SIZE)
                if chunk: yield chunk
    return StreamingResponse(iter_blocks(), media_type="application/octet-stream")

@app.post("/api/v1/upload")
async def upload_fragment(request: Request, current_user = Depends(get_current_user)):
    h = request.headers
    path = h.get("x-vaultsync-path")
    offset = int(h.get("x-vaultsync-offset") or 0)
    if not path or not is_safe_path(current_user['id'], path): raise HTTPException(status_code=403)
    user_id = current_user['id']
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(user_id), path.lstrip("/\\")))
    os.makedirs(os.path.dirname(safe_path), exist_ok=True)
    if offset == 0 and os.path.exists(safe_path):
        with get_db() as conn:
            c = conn.cursor(cursor_factory=RealDictCursor)
            c.execute("SELECT device_name FROM files WHERE user_id = %s AND path = %s", (user_id, path))
            row = c.fetchone()
            if row: version_manager.create_version(user_id, path, row['device_name'])
    with open(safe_path, "r+b" if os.path.exists(safe_path) else "wb") as f:
        f.seek(offset)
        async for chunk in request.stream(): f.write(chunk)
    return {"message": "OK"}

@app.post("/api/v1/upload/finalize")
def finalize_upload(body: FinalizeRequest, current_user = Depends(get_current_user)):
    if not is_safe_path(current_user['id'], body.path): raise HTTPException(status_code=403)
    user_id = current_user['id']
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(user_id), body.path.lstrip("/\\")))
    if not os.path.exists(safe_path): raise HTTPException(status_code=404)
    block_hashes = calculate_file_blocks(safe_path)
    actual_hash = calculate_file_hash(safe_path)
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''INSERT INTO files (user_id, path, hash, size, updated_at, device_name, blocks) VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT(user_id, path) DO UPDATE SET hash=EXCLUDED.hash, size=EXCLUDED.size, updated_at=EXCLUDED.updated_at, device_name=EXCLUDED.device_name, blocks=EXCLUDED.blocks''', (user_id, body.path, actual_hash, body.size or os.path.getsize(safe_path), body.updated_at, body.device_name, json.dumps(block_hashes)))
        conn.commit()
    return {"message": "Success", "hash": actual_hash}

@app.post("/api/v1/download")
def download_file(body: FileRequest, current_user = Depends(get_current_user)):
    if not is_safe_path(current_user['id'], body.filename): raise HTTPException(status_code=403)
    safe_path = os.path.abspath(os.path.join(STORAGE_DIR, str(current_user['id']), body.filename.lstrip("/\\")))
    if not os.path.exists(safe_path): raise HTTPException(status_code=404)
    return FileResponse(safe_path, media_type="application/octet-stream")

@app.post("/api/v1/auth/recovery/setup")
def setup_recovery(body: RecoverySetupRequest, current_user = Depends(get_current_user)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET recovery_payload = %s, recovery_salt = %s WHERE id = %s", (body.recovery_payload, body.recovery_salt, current_user['id']))
        conn.commit()
    return {"message": "OK"}

@app.post("/api/v1/auth/recovery/payload")
def get_recovery_payload(body: RecoveryPayloadRequest):
    with get_db() as conn:
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT recovery_payload, recovery_salt FROM users WHERE email = %s", (body.email,))
        user = c.fetchone()
    if not user or not user['recovery_payload']: raise HTTPException(status_code=404)
    return user

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)

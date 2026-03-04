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
from pydantic import BaseModel
import uvicorn
import json
from jose import JWTError, jwt
from passlib.context import CryptContext

# --- Configuration ---
SECRET_KEY = os.environ.get("NEOSYNC_SECRET", "CHANGE_THIS_IN_PROD")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30
STORAGE_DIR = os.path.abspath("storage")

# Database Config
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "neosync")
DB_USER = os.environ.get("DB_USER", "neosync")
DB_PASS = os.environ.get("DB_PASS", "neosync_password")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("NeoSync")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db_connection():
    return psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)

def init_db():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, 
            username TEXT, encryption_key TEXT, created_at BIGINT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY, user_id INTEGER REFERENCES users(id), path TEXT NOT NULL, 
            hash TEXT, size BIGINT, updated_at BIGINT, device_name TEXT, blocks TEXT, 
            UNIQUE(user_id, path)
        )''')
        conn.commit(); conn.close()
        logger.info("📡 Database initialized")
    except Exception as e: logger.error(f"❌ DB Error: {e}")

def calculate_file_blocks(file_path: str, chunk_size: int = 1024 * 1024) -> List[str]:
    hashes = []
    if not os.path.exists(file_path): return []
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk: break
            hashes.append(hashlib.md5(chunk).hexdigest())
    return hashes

app = FastAPI(title="NeoSync Server")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
os.makedirs(STORAGE_DIR, exist_ok=True)

class UserLogin(BaseModel):
    email: str
    password: str

class UserRegister(BaseModel):
    email: str
    password: str
    username: Optional[str] = None

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        conn = get_db_connection()
        c = conn.cursor(cursor_factory=RealDictCursor)
        c.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = c.fetchone()
        conn.close()
        if user is None: raise HTTPException(status_code=401)
        return user
    except: raise HTTPException(status_code=401)

@app.get("/")
async def health_check():
    return {"status": "online", "version": "NeoSync-Syncthing-v11-Full-Auth"}

@app.post("/register")
async def register(user: UserRegister):
    hashed_pw = pwd_context.hash(user.password)
    conn = get_db_connection()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (email, password_hash, username, created_at) VALUES (%s, %s, %s, %s) RETURNING id",
                  (user.email, hashed_pw, user.username, int(time.time())))
        user_id = c.fetchone()[0]
        conn.commit()
        token = jwt.encode({"sub": str(user_id), "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}, SECRET_KEY, algorithm=ALGORITHM)
        return {"token": token, "user": {"id": str(user_id), "email": user.email}}
    except Exception as e:
        conn.rollback()
        logger.error(f"Register error: {e}")
        raise HTTPException(status_code=400, detail="User already exists or data invalid")
    finally: conn.close()

@app.post("/login")
async def login(credentials: UserLogin):
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM users WHERE email = %s", (credentials.email,))
    user = c.fetchone()
    conn.close()
    if not user or not pwd_context.verify(credentials.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = jwt.encode({"sub": str(user['id']), "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"token": token, "user": {"id": str(user['id']), "email": user['email']}}

@app.get("/auth/me")
async def auth_me(current_user = Depends(get_current_user)):
    return {"id": str(current_user['id']), "email": current_user['email']}

@app.get("/api/v1/files")
async def list_files(current_user = Depends(get_current_user)):
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT path, hash, size, updated_at, device_name FROM files WHERE user_id = %s", (current_user['id'],))
    files = c.fetchall(); conn.close()
    return {"files": files}

@app.post("/api/v1/blocks/check")
async def check_blocks(request: Request, current_user = Depends(get_current_user)):
    body = await request.json()
    path = body.get("path")
    client_blocks = body.get("blocks", [])
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT blocks FROM files WHERE user_id = %s AND path = %s", (current_user['id'], path))
    row = c.fetchone(); conn.close()
    server_blocks = json.loads(row['blocks']) if row and row['blocks'] else []
    missing = [i for i, h in enumerate(client_blocks) if i >= len(server_blocks) or server_blocks[i] != h]
    return {"missing": missing}

@app.post("/api/v1/upload")
async def upload_fragment(request: Request, current_user = Depends(get_current_user)):
    h = request.headers
    path = h.get("x-neosync-path")
    offset = int(h.get("x-neosync-offset") or 0)
    
    if not path: raise HTTPException(status_code=422, detail="Path missing")
    
    user_id = current_user['id']
    safe_path = os.path.normpath(os.path.join(STORAGE_DIR, str(user_id), path.lstrip("/\\.")))
    os.makedirs(os.path.dirname(safe_path), exist_ok=True)

    bytes_received = 0
    with open(safe_path, "r+b" if os.path.exists(safe_path) else "wb") as f:
        f.seek(offset)
        async for chunk in request.stream():
            f.write(chunk)
            bytes_received += len(chunk)
            
    return {"message": "Fragment OK", "size": bytes_received}

@app.post("/api/v1/upload/finalize")
async def finalize_upload(request: Request, current_user = Depends(get_current_user)):
    body = await request.json()
    path = body.get("path")
    file_hash = body.get("hash")
    plain_size = body.get("size")
    updated_at = body.get("updated_at")
    device_name = body.get("device_name", "Unknown")

    user_id = current_user['id']
    safe_path = os.path.normpath(os.path.join(STORAGE_DIR, str(user_id), path.lstrip("/\\.")))
    
    if not os.path.exists(safe_path): raise HTTPException(status_code=404)
    
    disk_size = os.path.getsize(safe_path)
    block_hashes = calculate_file_blocks(safe_path)
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''INSERT INTO files (user_id, path, hash, size, updated_at, device_name, blocks) 
                 VALUES (%s, %s, %s, %s, %s, %s, %s) 
                 ON CONFLICT(user_id, path) DO UPDATE SET 
                 hash=EXCLUDED.hash, size=EXCLUDED.size, updated_at=EXCLUDED.updated_at, device_name=EXCLUDED.device_name, blocks=EXCLUDED.blocks''',
              (user_id, path, file_hash, plain_size or disk_size, updated_at, device_name, json.dumps(block_hashes)))
    conn.commit(); conn.close()
    
    logger.info(f"🏁 FINALIZED: {path} (Disk: {disk_size})")
    return {"message": "Success", "disk_size": disk_size}

@app.post("/api/v1/download")
async def download_file(request: Request, current_user = Depends(get_current_user)):
    body = await request.json()
    path = body.get("filename")
    safe_path = os.path.normpath(os.path.join(STORAGE_DIR, str(current_user['id']), path.lstrip("/\\.")))
    if not os.path.exists(safe_path): raise HTTPException(status_code=404)
    return FileResponse(safe_path, media_type="application/octet-stream")

if __name__ == "__main__":
    init_db()
    uvicorn.run(app, host="0.0.0.0", port=8000)

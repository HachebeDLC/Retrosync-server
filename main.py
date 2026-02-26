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
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import uvicorn
import json
from contextlib import asynccontextmanager

from passlib.context import CryptContext
from jose import JWTError, jwt
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError

# --- Configuration ---
SECRET_KEY = os.environ.get("NEOSYNC_SECRET", "CHANGE_THIS_IN_PROD_TO_A_LONG_RANDOM_STRING")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30 # 30 Days
STORAGE_DIR = os.path.abspath("storage")

# Database Config
DB_HOST = os.environ.get("DB_HOST", "db")
DB_NAME = os.environ.get("DB_NAME", "neosync")
DB_USER = os.environ.get("DB_USER", "neosync")
DB_PASS = os.environ.get("DB_PASS", "neosync_password")

# --- Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("server.log"), logging.StreamHandler()]
)
logger = logging.getLogger("NeoSync")

# --- Security ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- Database ---
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise e

def init_db():
    retries = 5
    while retries > 0:
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                username TEXT,
                encryption_key TEXT,
                created_at BIGINT
            )''')
            
            c.execute('''CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                path TEXT NOT NULL,
                hash TEXT,
                size BIGINT,
                updated_at BIGINT,
                blocks TEXT,
                device_name TEXT,
                UNIQUE(user_id, path)
            )''')
            
            try:
                c.execute("ALTER TABLE files ADD COLUMN IF NOT EXISTS blocks TEXT")
                c.execute("ALTER TABLE files ADD COLUMN IF NOT EXISTS device_name TEXT")
            except: pass

            conn.commit()
            conn.close()
            logger.info("Database initialized successfully.")
            break
        except Exception as e:
            logger.warning(f"DB not ready yet, retrying... ({e})")
            time.sleep(2)
            retries -= 1

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize DB
    init_db()
    yield
    # Shutdown: Add cleanup here if needed

app = FastAPI(title="NeoSync Server", description="Secure Self-hosted NeoStation Sync Server", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs(STORAGE_DIR, exist_ok=True)

# --- Access Token Helpers ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = c.fetchone()
    conn.close()
    if user is None:
        raise credentials_exception
    return user

# --- Models ---
class UserRegister(BaseModel):
    email: str
    password: str
    username: Optional[str] = None

class LoginRequest(BaseModel):
    email: str
    password: str

# --- Endpoints ---

@app.get("/health")
async def health():
    try:
        conn = get_db_connection()
        conn.close()
        return {"status": "ok", "version": "4.0.0", "db": "connected", "encryption": "client-side"}
    except:
        return {"status": "error", "db": "disconnected"}

@app.post("/register")
async def register(user: UserRegister):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        hashed_pw = pwd_context.hash(user.password)
        c.execute("INSERT INTO users (email, password_hash, username, created_at) VALUES (%s, %s, %s, %s) RETURNING id",
                  (user.email, hashed_pw, user.username, int(time.time())))
        user_id = c.fetchone()[0]
        conn.commit()
        
        token = create_access_token(data={"sub": str(user_id)})
        return {"token": token, "user": {"id": str(user_id), "email": user.email}}
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Email already exists")
    finally:
        conn.close()

@app.post("/login")
async def login(user: LoginRequest):
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM users WHERE email = %s", (user.email,))
    row = c.fetchone()
    conn.close()
    
    if not row or not pwd_context.verify(user.password, row['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token(data={"sub": str(row['id'])})
    return {
        "token": token,
        "user": {"id": str(row['id']), "email": row['email']}
    }

@app.get("/auth/me")
async def auth_me(current_user = Depends(get_current_user)):
    return {
        "id": str(current_user['id']),
        "email": current_user['email'],
        "username": current_user['username'],
        "plan_id": "gold",
        "is_premium": True
    }

@app.post("/api/v1/files/check")
async def check_files(request: Request, current_user = Depends(get_current_user)):
    try:
        body = await request.json()
    except:
        return {"upload": [], "download": []}

    items = body.get("files", [body]) if isinstance(body, dict) else body
    user_id = current_user['id']
    
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    to_upload = []
    
    for item in items:
        path = item.get("filename") or item.get("path")
        client_hash = item.get("hash")
        if not path: continue
        
        c.execute("SELECT hash FROM files WHERE user_id = %s AND path = %s", (user_id, path))
        row = c.fetchone()
        
        if not row or row['hash'] != client_hash:
            to_upload.append(path)
            
    conn.close()
    return {"upload": to_upload, "download": [], "conflicts": []}

def calculate_blocks(content: bytes) -> List[str]:
    BLOCK_SIZE = 1024 * 1024 # 1MB
    hashes = []
    for i in range(0, len(content), BLOCK_SIZE):
        chunk = content[i:i + BLOCK_SIZE]
        hashes.append(hashlib.md5(chunk).hexdigest())
    return hashes

@app.post("/api/v1/upload")
async def upload_file(request: Request, current_user = Depends(get_current_user)):
    form = await request.form()
    file = form.get("file")
    path = form.get("file_name") or form.get("path") or (file.filename if file else None)
    
    if not file or not path:
        raise HTTPException(status_code=422, detail="Missing data")

    user_id = current_user['id']
    device_name = form.get("device_name", "Unknown Device")
    
    content = await file.read()
    file_hash = hashlib.md5(content).hexdigest()
    block_hashes = calculate_blocks(content)
    
    try:
        incoming_updated_at = int(form.get("updated_at") or (time.time() * 1000))
    except:
        incoming_updated_at = int(time.time() * 1000)
    
    is_forced = form.get("force") == "true"

    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT hash, updated_at FROM files WHERE user_id = %s AND path = %s", (user_id, path))
    existing = c.fetchone()

    if existing and not is_forced:
        if existing['hash'] == file_hash:
            conn.close()
            return {"message": "Already synced", "path": path}
        
        if incoming_updated_at < existing['updated_at']:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            device_slug = "".join(x for x in device_name if x.isalnum())
            path_parts = path.split('.')
            if len(path_parts) > 1:
                ext = path_parts[-1]
                base = ".".join(path_parts[:-1])
                path = f"{base}.sync-conflict-{timestamp}-{device_slug}.{ext}"
            else:
                path = f"{path}.sync-conflict-{timestamp}-{device_slug}"
            logger.warning(f"⚠️ CONFLICT: {path}")

    # No server-side encryption (Zero-Knowledge)
    clean_path = str(path).lstrip("/\\.")
    user_storage = os.path.join(STORAGE_DIR, str(user_id))
    safe_path = os.path.normpath(os.path.join(user_storage, clean_path))
    os.makedirs(os.path.dirname(safe_path), exist_ok=True)
    
    if not ".sync-conflict-" in path and os.path.exists(safe_path):
        versions_dir = os.path.join(user_storage, ".versions", os.path.dirname(clean_path))
        os.makedirs(versions_dir, exist_ok=True)
        version_base_path = os.path.join(versions_dir, os.path.basename(clean_path))
        try:
            for i in range(4, 0, -1):
                v_src = f"{version_base_path}.v{i}"
                v_dst = f"{version_base_path}.v{i+1}"
                if os.path.exists(v_src): shutil.move(v_src, v_dst)
            shutil.copy2(safe_path, f"{version_base_path}.v1")
        except Exception as e: logger.error(f"Versioning error: {e}")

    with open(safe_path, "wb") as f:
        f.write(content)
        
    c.execute('''INSERT INTO files (user_id, path, hash, size, updated_at, device_name, blocks) 
                 VALUES (%s, %s, %s, %s, %s, %s, %s) 
                 ON CONFLICT(user_id, path) DO UPDATE SET 
                 hash=EXCLUDED.hash, size=EXCLUDED.size, updated_at=EXCLUDED.updated_at, device_name=EXCLUDED.device_name, blocks=EXCLUDED.blocks''',
              (user_id, path, file_hash, len(content), incoming_updated_at, device_name, json.dumps(block_hashes)))
    conn.commit()
    conn.close()
    
    logger.info(f"💾 UPLOAD: {path}")
    return {"message": "Saved", "path": path}

@app.post("/api/v1/blocks/check")
async def check_blocks(request: Request, current_user = Depends(get_current_user)):
    try:
        body = await request.json()
        path = body.get("path")
        client_blocks = body.get("blocks", [])
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    user_id = current_user['id']
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT blocks FROM files WHERE user_id = %s AND path = %s", (user_id, path))
    row = c.fetchone()
    conn.close()

    server_blocks = json.loads(row['blocks']) if row and row['blocks'] else []
    missing_indices = [i for i, h in enumerate(client_blocks) if i >= len(server_blocks) or server_blocks[i] != h]
    return {"missing": missing_indices}

@app.post("/api/v1/upload/block")
async def upload_block(request: Request, current_user = Depends(get_current_user)):
    form = await request.form()
    file = form.get("file")
    path = form.get("path")
    index = int(form.get("index", 0))
    total = int(form.get("total", 1))
    file_hash = form.get("hash")
    device_name = form.get("device_name", "Unknown Device")
    
    user_id = current_user['id']
    user_storage = os.path.join(STORAGE_DIR, str(user_id))
    clean_path = str(path).lstrip("/\\.")
    safe_path = os.path.normpath(os.path.join(user_storage, clean_path))
    temp_path = f"{safe_path}.part"
    os.makedirs(os.path.dirname(safe_path), exist_ok=True)
    
    content = await file.read()
    with open(temp_path, "r+b" if os.path.exists(temp_path) else "wb") as f:
        f.seek(index * 1024 * 1024)
        f.write(content)
        
    if index == total - 1:
        with open(temp_path, "rb") as f:
            full_content = f.read()
        block_hashes = calculate_blocks(full_content)
        with open(safe_path, "wb") as f:
            f.write(full_content)
        os.remove(temp_path)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''INSERT INTO files (user_id, path, hash, size, updated_at, device_name, blocks) 
                     VALUES (%s, %s, %s, %s, %s, %s, %s) 
                     ON CONFLICT(user_id, path) DO UPDATE SET 
                     hash=EXCLUDED.hash, size=EXCLUDED.size, updated_at=EXCLUDED.updated_at, device_name=EXCLUDED.device_name, blocks=EXCLUDED.blocks''',
                  (user_id, path, file_hash, len(full_content), int(time.time() * 1000), device_name, json.dumps(block_hashes)))
        conn.commit()
        conn.close()
        
    return {"message": "Block received"}

@app.post("/api/v1/download")
async def download_file(request: Request, current_user = Depends(get_current_user)):
    try:
        body = await request.json()
        path = body.get("filename") or body.get("path")
        version = body.get("version") # Optional
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not path:
        raise HTTPException(status_code=400, detail="Path required")
        
    user_id = current_user['id']
    user_storage = os.path.join(STORAGE_DIR, str(user_id))
    clean_path = str(path).lstrip("/\\.")
    
    if version:
        versions_dir = os.path.join(user_storage, ".versions", os.path.dirname(clean_path))
        safe_path = os.path.join(versions_dir, f"{os.path.basename(clean_path)}.v{version}")
        logger.info(f"📥 DOWNLOAD VERSION {version}: {path}")
    else:
        safe_path = os.path.normpath(os.path.join(user_storage, clean_path))
        logger.info(f"📥 DOWNLOAD: {path}")
    
    if not os.path.exists(safe_path):
        raise HTTPException(status_code=404, detail="File not found")
        
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT hash FROM files WHERE user_id = %s AND path = %s", (user_id, path))
    row = c.fetchone()
    conn.close()
    
    with open(safe_path, "rb") as f:
        data = f.read()
    
    return Response(content=data, media_type="application/octet-stream", headers={"x-file-hash": row['hash'] if row else ""})

@app.get("/api/v1/files/versions")
async def get_versions(path: str, current_user = Depends(get_current_user)):
    user_id = current_user['id']
    user_storage = os.path.join(STORAGE_DIR, str(user_id))
    clean_path = str(path).lstrip("/\\.")
    versions_dir = os.path.join(user_storage, ".versions", os.path.dirname(clean_path))
    version_base_name = os.path.basename(clean_path)
    
    versions = []
    if os.path.exists(versions_dir):
        for i in range(1, 6):
            v_path = os.path.join(versions_dir, f"{version_base_name}.v{i}")
            if os.path.exists(v_path):
                stat = os.stat(v_path)
                versions.append({
                    "version": i,
                    "size": stat.st_size,
                    "updated_at": int(stat.st_mtime * 1000)
                })
    return {"versions": versions}

@app.get("/api/v1/files")
async def list_files(current_user = Depends(get_current_user)):
    user_id = current_user['id']
    user_storage = os.path.join(STORAGE_DIR, str(user_id))
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM files WHERE user_id = %s", (user_id,))
    rows = c.fetchall()
    
    file_list = []
    missing_files = []
    for row in rows:
        db_path = row['path']
        if db_path.startswith((".versions", ".neosync")): continue
        safe_path = os.path.normpath(os.path.join(user_storage, db_path.lstrip("/\\.")))
        if os.path.exists(safe_path):
            file_list.append({"path": db_path, "filename": db_path, "size": row['size'], "hash": row['hash'], "updated_at": row['updated_at'], "device_name": row['device_name'] or "Unknown Device"})
        else:
            missing_files.append(db_path)
    if missing_files:
        for m in missing_files: c.execute("DELETE FROM files WHERE user_id = %s AND path = %s", (user_id, m))
        conn.commit()
    conn.close()
    return {"files": file_list}

@app.delete("/api/v1/files")
async def delete_file(request: Request, current_user=Depends(get_current_user)):
    try:
        body = await request.json()
        path = body.get("filename") or body.get("path")
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    user_id = current_user['id']
    user_storage = os.path.join(STORAGE_DIR, str(user_id))
    safe_path = os.path.normpath(os.path.join(user_storage, str(path).lstrip("/\\.")))
    if os.path.exists(safe_path): os.remove(safe_path)
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM files WHERE user_id = %s AND path = %s", (user_id, path))
    conn.commit()
    conn.close()
    return {"message": "Deleted"}

@app.get("/api/v1/quota")
async def get_quota(current_user=Depends(get_current_user)):
    user_id = current_user['id']
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT SUM(size) as total_used FROM files WHERE user_id = %s", (user_id,))
    row = c.fetchone()
    conn.close()
    total_used = row['total_used'] if row and row['total_used'] else 0
    return {"used": total_used, "max": 1099511627776, "freeSpace": 1099511627776 - total_used}

class ConnectionManager:
    def __init__(self): self.active_connections: List[WebSocket] = []
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    def disconnect(self, websocket: WebSocket): self.active_connections.remove(websocket)
    async def broadcast(self, message: str):
        for connection in self.active_connections: await connection.send_text(message)

manager = ConnectionManager()
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True: await websocket.receive_text()
    except WebSocketDisconnect: manager.disconnect(websocket)

if __name__ == "__main__": uvicorn.run(app, host="0.0.0.0", port=8000)

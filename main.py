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
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import uvicorn
import json

from passlib.context import CryptContext
from jose import JWTError, jwt
from cryptography.fernet import Fernet
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

app = FastAPI(title="NeoSync Server", description="Secure Self-hosted NeoStation Sync Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs(STORAGE_DIR, exist_ok=True)

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
    # Wait for DB to be ready (simple retry logic)
    retries = 5
    while retries > 0:
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            # Users Table
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                username TEXT,
                encryption_key TEXT,
                created_at BIGINT
            )''')
            
            # Files Table
            c.execute('''CREATE TABLE IF NOT EXISTS files (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                path TEXT NOT NULL,
                hash TEXT,
                size BIGINT,
                updated_at BIGINT,
                UNIQUE(user_id, path)
            )''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully.")
            break
        except Exception as e:
            logger.warning(f"DB not ready yet, retrying... ({e})")
            time.sleep(2)
            retries -= 1

# Initialize DB on startup
@app.on_event("startup")
async def startup_event():
    init_db()

# --- Helpers ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_encryption_key(user_id: int) -> bytes:
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT encryption_key FROM users WHERE id = %s", (user_id,))
    row = c.fetchone()
    
    if row and row['encryption_key']:
        conn.close()
        return row['encryption_key'].encode()
        
    # Generate new key
    key = Fernet.generate_key()
    c.execute("UPDATE users SET encryption_key = %s WHERE id = %s", (key.decode(), user_id))
    conn.commit()
    conn.close()
    return key

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
        return {"status": "ok", "version": "3.0.0", "db": "connected"}
    except:
        return {"status": "error", "db": "disconnected"}

@app.post("/register")
async def register(user: UserRegister):
    conn = get_db_connection()
    c = conn.cursor()
    try:
        hashed_pw = get_password_hash(user.password)
        enc_key = Fernet.generate_key().decode()
        
        c.execute("INSERT INTO users (email, password_hash, username, encryption_key, created_at) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                  (user.email, hashed_pw, user.username, enc_key, int(time.time())))
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
    
    if not row or not verify_password(user.password, row['password_hash']):
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
        "encryption_key": current_user['encryption_key'],
        "plan_id": "gold",
        "is_premium": True,
        "plan": {"id": "gold", "name": "Gold", "maxStorage": 1099511627776, "isPremium": True}
    }

# --- File Ops ---

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
        
        c.execute("SELECT * FROM files WHERE user_id = %s AND path = %s", (user_id, path))
        row = c.fetchone()
        
        if not row or row['hash'] != client_hash:
            to_upload.append(path)
            
    conn.close()
    return {"upload": to_upload, "download": [], "conflicts": []}

@app.post("/api/v1/upload")
async def upload_file(request: Request, current_user = Depends(get_current_user)):
    form = await request.form()
    file = form.get("file")
    path = form.get("file_name") or form.get("path") or (file.filename if file else None)
    
    if not file or not path:
        raise HTTPException(status_code=422, detail="Missing data")

    user_id = current_user['id']
    
    # Read & Hash
    content = await file.read()
    file_hash = hashlib.md5(content).hexdigest()
    
    # Encrypt
    key = get_user_encryption_key(user_id)
    fernet = Fernet(key)
    encrypted_content = fernet.encrypt(content)
    
    # Save
    clean_path = str(path).lstrip("/\\.")
    user_storage = os.path.join(STORAGE_DIR, str(user_id))
    safe_path = os.path.normpath(os.path.join(user_storage, clean_path))
    os.makedirs(os.path.dirname(safe_path), exist_ok=True)
    
    # Versioning
    if os.path.exists(safe_path):
        try:
            for i in range(2, 0, -1):
                v_src = f"{safe_path}.v{i}"
                v_dst = f"{safe_path}.v{i+1}"
                if os.path.exists(v_src): shutil.copy2(v_src, v_dst)
            shutil.copy2(safe_path, f"{safe_path}.v1")
        except: pass

    with open(safe_path, "wb") as buffer:
        buffer.write(encrypted_content)
        
    # DB Update
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''INSERT INTO files (user_id, path, hash, size, updated_at) 
                 VALUES (%s, %s, %s, %s, %s) 
                 ON CONFLICT(user_id, path) DO UPDATE SET 
                 hash=EXCLUDED.hash, size=EXCLUDED.size, updated_at=EXCLUDED.updated_at''',
              (user_id, path, file_hash, len(content), int(time.time() * 1000)))
    conn.commit()
    conn.close()
    
    logger.info(f"Upload: {path}")
    return {"message": "Saved", "path": path}

@app.post("/api/v1/download")
async def download_file(request: Request, current_user = Depends(get_current_user)):
    try:
        body = await request.json()
        path = body.get("filename") or body.get("path")
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not path:
        raise HTTPException(status_code=400, detail="Path required")
        
    user_id = current_user['id']
    user_storage = os.path.join(STORAGE_DIR, str(user_id))
    safe_path = os.path.normpath(os.path.join(user_storage, str(path).lstrip("/\\.")))
    
    if not os.path.exists(safe_path):
        raise HTTPException(status_code=404, detail="File not found")
        
    try:
        with open(safe_path, "rb") as f:
            encrypted_data = f.read()
        
        key = get_user_encryption_key(user_id)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        
        from fastapi import Response
        return Response(content=decrypted_data, media_type="application/octet-stream")
        
    except Exception as e:
        logger.error(f"Decrypt error: {e}")
        raise HTTPException(status_code=500, detail="Decryption failed")

@app.get("/api/v1/files")
async def list_files(current_user = Depends(get_current_user)):
    user_id = current_user['id']
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT * FROM files WHERE user_id = %s", (user_id,))
    rows = c.fetchall()
    conn.close()
    
    file_list = []
    for row in rows:
        file_list.append({
            "path": row['path'],
            "filename": row['path'],
            "size": row['size'],
            "hash": row['hash'],
            "updated_at": row['updated_at']
        })
    return {"files": file_list}

@app.delete("/api/v1/files")
async def delete_file(request: Request, current_user=Depends(get_current_user)):
    try:
        body = await request.json()
        path = body.get("filename") or body.get("path")
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    if not path:
        raise HTTPException(status_code=400, detail="Path required")

    user_id = current_user['id']
    user_storage = os.path.join(STORAGE_DIR, str(user_id))
    safe_path = os.path.normpath(os.path.join(user_storage, str(path).lstrip("/\\.")))

    if os.path.exists(safe_path):
        os.remove(safe_path)

    # Versioning cleanup
    for i in range(1, 10):
        v_path = f"{safe_path}.v{i}"
        if os.path.exists(v_path):
            os.remove(v_path)

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM files WHERE user_id = %s AND path = %s", (user_id, path))
    deleted = c.rowcount
    conn.commit()
    conn.close()

    if deleted == 0:
        raise HTTPException(status_code=404, detail="File not found in database")

    logger.info(f"Deleted: {path}")
    return {"message": "File deleted successfully"}

@app.get("/api/v1/quota")
async def get_quota(current_user=Depends(get_current_user)):
    user_id = current_user['id']
    conn = get_db_connection()
    c = conn.cursor(cursor_factory=RealDictCursor)
    c.execute("SELECT SUM(size) as total_used FROM files WHERE user_id = %s", (user_id,))
    row = c.fetchone()
    conn.close()

    total_used = row['total_used'] if row and row['total_used'] else 0
    max_storage = 1099511627776  # 1TB from auth/me mock

    return {
        "used": total_used,
        "max": max_storage,
        "is_exceeded": total_used > max_storage,
        "freeSpace": max_storage - total_used
    }

# --- WS ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
# auth.py - Autenticação sem framework web

import hashlib
import sqlite3
from datetime import datetime, timedelta
from jose import jwt, JWTError

SECRET_KEY = "sua-chave-secreta-muito-longa-e-unica-2025-abc123xyz-mude-isto!"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  

def get_password_hash(password: str) -> str:
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return get_password_hash(plain_password) == hashed_password

def authenticate_user(username: str, password: str):
    conn = sqlite3.connect('logs.db', check_same_thread=False)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ? AND is_active = 1",
        (username,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return None
    
    user_id, username_db, password_hash = user
    if not verify_password(password, password_hash):
        return None
    
    return {"id": user_id, "username": username_db}

def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            return None
        return {"username": username}
    except JWTError:
        return None

def log_activity(user_id: int, action: str, details: str = "", ip_address: str = None):
    conn = sqlite3.connect('logs.db', check_same_thread=False)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO activity_logs (user_id, action, details, ip_address, timestamp)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (user_id, action, details, ip_address))
    
    conn.commit()
    conn.close()

def register_user(username: str, password: str, email: str = None):
    conn = sqlite3.connect('logs.db', check_same_thread=False)
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Utilizador já existe"
    
    password_hash = get_password_hash(password)
    cursor.execute("""
        INSERT INTO users (username, password_hash, email, created_at, is_active)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP, 1)
    """, (username, password_hash, email))
    
    conn.commit()
    conn.close()
    return True, "Utilizador registado com sucesso"
from jose import jwt, JWTError
from datetime import datetime, timedelta
import hashlib
import sqlite3
from fastapi import HTTPException, status
from models import User, TokenData

SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def verify_password(plain_password, hashed_password):
    """Verifica senha usando SHA-256"""
    return hashlib.sha256(plain_password.encode()).hexdigest() == hashed_password

def get_password_hash(password):
    """Gera hash da senha"""
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate_user(username: str, password: str):
    """Autentica usuário"""
    conn = sqlite3.connect('logs.db', check_same_thread=False)
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ? AND is_active = 1', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        return False
    
    user_id, username, password_hash = user
    if not verify_password(password, password_hash):
        return False
    
    return {"id": user_id, "username": username}

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Cria token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    """Verifica token JWT"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        token_data = TokenData(username=username)
        return token_data
    except jwt.PyJWTError:
        return None

def log_activity(user_id: int, action: str, details: str = "", ip_address: str = None):
    """Registra atividade do usuário"""
    conn = sqlite3.connect('logs.db', check_same_thread=False)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO activity_logs (user_id, action, details, ip_address)
        VALUES (?, ?, ?, ?)
    ''', (user_id, action, details, ip_address))
    
    conn.commit()
    conn.close()

def register_user(username: str, password: str, email: str = None):
    """Registra novo usuário"""
    conn = sqlite3.connect('logs.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Verifica se usuário já existe
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return False, "Usuário já existe"
    
    # Insere novo usuário
    password_hash = get_password_hash(password)
    cursor.execute('''
        INSERT INTO users (username, password_hash, email)
        VALUES (?, ?, ?)
    ''', (username, password_hash, email))
    
    conn.commit()
    conn.close()
    return True, "Usuário registrado com sucesso"
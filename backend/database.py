

import sqlite3
import hashlib

def init_db():
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS operation_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            operation_type TEXT NOT NULL,
            original_filename TEXT,
            result_filename TEXT,
            file_size INTEGER,
            operation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'success',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    
    admin_hash = hashlib.sha256('admin123'.encode('utf-8')).hexdigest()
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, password_hash, email)
        VALUES (?, ?, ?)
    ''', ('admin', admin_hash, 'admin@exame.local'))
    
    conn.commit()
    conn.close()

def get_connection():
    return sqlite3.connect('logs.db', check_same_thread=False)


init_db()
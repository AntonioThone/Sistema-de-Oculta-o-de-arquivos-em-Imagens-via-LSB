# app.py - Servidor HTTP simples para esteganografia (sem framework)

import http.server
import socketserver
import json
import os
import sys
import base64
from urllib.parse import urlparse
from http import HTTPStatus
from datetime import datetime, timedelta
import sqlite3

from auth import (
    create_access_token,
    verify_token,
    authenticate_user,
    register_user,
    log_activity,
    SECRET_KEY
)
from steganography import AdvancedLSBSteganography
from database import get_connection

PORT = 8000

print("=== Iniciando o servidor ===")
print("Imports concluídos com sucesso")
print(f"Python version: {sys.version}")
print(f"Diretório atual: {os.getcwd()}")

class StegoHandler(http.server.BaseHTTPRequestHandler):
    def _set_headers(self, status=200, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-type", content_type)
        # CORS completo e explícito
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
        self.send_header("Access-Control-Max-Age", "86400")  # cache preflight por 24h
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(200, "text/plain")
        self.wfile.write(b"OK")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        print(f"GET recebido: {path}")

        if path == "/api/health":
            self._set_headers()
            self.wfile.write(json.dumps({
                "status": "healthy",
                "timestamp": str(datetime.now())
            }).encode())
            return

        if path == "/api/history":
            token = self._get_token()
            if not token:
                self._send_error(401, "Token necessário")
                return

            user = verify_token(token)
            if not user:
                self._send_error(401, "Token inválido")
                return

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (user["username"],))
            row = cursor.fetchone()
            if not row:
                self._send_error(403, "Utilizador não encontrado")
                conn.close()
                return
            user_id = row[0]

            cursor.execute("""
                SELECT id, operation_type, original_filename, result_filename, 
                       file_size, operation_date, status
                FROM operation_history 
                WHERE user_id = ? 
                ORDER BY operation_date DESC LIMIT 50
            """, (user_id,))
            rows = cursor.fetchall()
            conn.close()

            history = [
                {
                    "id": r[0],
                    "operation_type": r[1],
                    "original_filename": r[2],
                    "result_filename": r[3],
                    "file_size": r[4],
                    "operation_date": r[5],
                    "status": r[6]
                } for r in rows
            ]

            self._set_headers()
            self.wfile.write(json.dumps({"history": history}).encode())
            return

        if path == "/api/logs":
            token = self._get_token()
            if not token:
                self._send_error(401, "Token necessário")
                return

            user = verify_token(token)
            if not user or user["username"] != "admin":
                self._send_error(403, "Apenas admin pode ver os logs")
                return

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT al.id, u.username, al.action, al.details, al.timestamp, al.ip_address
                FROM activity_logs al
                LEFT JOIN users u ON al.user_id = u.id
                ORDER BY al.timestamp DESC
                LIMIT 100
            """)
            rows = cursor.fetchall()
            conn.close()

            logs = [
                {
                    "id": r[0],
                    "username": r[1] or "Sistema",
                    "action": r[2],
                    "details": r[3],
                    "timestamp": r[4],
                    "ip_address": r[5]
                } for r in rows
            ]

            self._set_headers()
            self.wfile.write(json.dumps({"logs": logs}).encode())
            return

        self._send_error(404, "Endpoint não encontrado")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        print(f"POST recebido: {path}")

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        content_type = self.headers.get("Content-Type", "")

        if content_type.startswith("multipart/form-data"):
            return self._handle_multipart(path, post_data, content_type)

        try:
            data = json.loads(post_data.decode('utf-8'))
        except Exception as e:
            print(f"Erro ao parsear JSON: {e}")
            data = {}

        if path == "/api/auth/login":
            username = data.get("username")
            password = data.get("password")

            if not username or not password:
                self._send_error(400, "Username e password obrigatórios")
                return

            user = authenticate_user(username, password)
            if not user:
                log_activity(0, "LOGIN_FAILED", f"Tentativa falhada: {username}")
                self._send_error(401, "Credenciais inválidas")
                return

            token = create_access_token({"sub": user["username"]})
            log_activity(user["id"], "LOGIN", "Login com sucesso")

            self._set_headers()
            self.wfile.write(json.dumps({
                "access_token": token,
                "token_type": "bearer",
                "username": user["username"]
            }).encode())
            return

        if path == "/api/auth/register":
            username = data.get("username")
            password = data.get("password")
            email = data.get("email")

            if not username or not password:
                self._send_error(400, "Username e password obrigatórios")
                return

            success, message = register_user(username, password, email)
            self._set_headers()
            self.wfile.write(json.dumps({"success": success, "message": message}).encode())
            return

        self._send_error(404, "Endpoint não encontrado")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path

        print(f"DELETE recebido: {path}")

        if path == "/api/auth/account":
            token = self._get_token()
            if not token:
                self._send_error(401, "Token necessário")
                return

            user = verify_token(token)
            if not user:
                self._send_error(401, "Token inválido")
                return

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM users WHERE username = ?", (user["username"],))
            cursor.execute("DELETE FROM activity_logs WHERE user_id = (SELECT id FROM users WHERE username = ?)", (user["username"],))
            cursor.execute("DELETE FROM operation_history WHERE user_id = (SELECT id FROM users WHERE username = ?)", (user["username"],))
            conn.commit()
            conn.close()

            log_activity(0, "ACCOUNT_DELETED", f"Conta eliminada: {user['username']}")

            self._set_headers()
            self.wfile.write(json.dumps({"success": True, "message": "Conta eliminada com sucesso"}).encode())
            return

        self._send_error(404, "Endpoint não encontrado")

    def _handle_multipart(self, path, post_data, content_type):
        print("Processando multipart/form-data manualmente")

        try:
            if "boundary=" not in content_type:
                raise ValueError("Boundary não encontrado")

            boundary_part = content_type.split("boundary=")[1]
            boundary = boundary_part.strip().encode('utf-8')
            full_boundary = b'--' + boundary

            parts = post_data.split(full_boundary)
            fields = {}

            for part in parts:
                if not part.strip() or part.strip() == b'--':
                    continue

                part = part.lstrip(b'\r\n')
                header_end = part.find(b'\r\n\r\n')
                if header_end == -1:
                    continue

                headers_bytes = part[:header_end]
                body = part[header_end + 4:].rstrip(b'\r\n--')

                content_disposition = b''
                for line in headers_bytes.split(b'\r\n'):
                    if line.lower().startswith(b'content-disposition:'):
                        content_disposition = line.split(b':', 1)[1].strip()

                if not content_disposition:
                    continue

                name = None
                filename = None
                disp_parts = content_disposition.split(b';')
                for disp in disp_parts:
                    disp = disp.strip()
                    if disp.startswith(b'name='):
                        name = disp.split(b'=', 1)[1].strip(b'"').decode('utf-8', errors='ignore')
                    if disp.startswith(b'filename='):
                        filename = disp.split(b'=', 1)[1].strip(b'"').decode('utf-8', errors='ignore')

                if name:
                    value = body.decode('utf-8', errors='ignore')
                    fields[name] = value

            print("Campos extraídos:", list(fields.keys()))

            token = self._get_token()
            if not token:
                self._send_error(401, "Token necessário")
                return

            user = verify_token(token)
            if not user:
                self._send_error(401, "Token inválido")
                return

            conn = get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (user["username"],))
            row = cursor.fetchone()
            if not row:
                self._send_error(403, "Utilizador não encontrado")
                conn.close()
                return
            user_id = row[0]

            if path == "/api/steganography/encode":
                try:
                    cover_b64 = fields.get("cover_image", "")
                    secret_b64 = fields.get("secret_data", "")
                    secret_filename = fields.get("secret_filename", "arquivo_secreto.bin")
                    key = fields.get("key", "")
                    compress = fields.get("compress", "false").lower() == "true"

                    if not all([cover_b64, secret_b64, key]):
                        raise ValueError("Campos obrigatórios em falta")

                    result_b64 = AdvancedLSBSteganography.encode_image(
                        cover_b64, secret_b64, secret_filename, key, compress=compress
                    )

                    cursor.execute("""
                        INSERT INTO operation_history 
                        (user_id, operation_type, original_filename, result_filename, file_size, status)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        user_id, "ENCODE", secret_filename, "esteganografada.png",
                        len(base64.b64decode(result_b64)), "success"
                    ))
                    conn.commit()

                    log_activity(user_id, "ENCODE", f"Ocultou ficheiro {secret_filename}")

                    self._set_headers()
                    self.wfile.write(json.dumps({
                        "success": True,
                        "image": result_b64,
                        "message": "Imagem esteganografada gerada com sucesso"
                    }).encode())

                except Exception as e:
                    conn.rollback()
                    print(f"Erro no encode: {e}")
                    self._send_error(400, str(e))

            elif path == "/api/steganography/decode":
                try:
                    stego_b64 = fields.get("stego_image", "")
                    key = fields.get("key", "")

                    if not all([stego_b64, key]):
                        raise ValueError("Campos obrigatórios em falta: stego_image, key")

                    filename, data_b64, compressed = AdvancedLSBSteganography.decode_image(
                        stego_b64, key
                    )

                    cursor.execute("""
                        INSERT INTO operation_history 
                        (user_id, operation_type, original_filename, result_filename, file_size, status)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        user_id, "DECODE", "imagem_esteganografada.png", filename,
                        len(base64.b64decode(data_b64)), "success"
                    ))
                    conn.commit()

                    log_activity(user_id, "DECODE", f"Extraiu ficheiro {filename}")

                    self._set_headers()
                    self.wfile.write(json.dumps({
                        "success": True,
                        "filename": filename,
                        "data": data_b64,
                        "compressed": compressed,
                        "message": "Ficheiro extraído com sucesso"
                    }).encode())

                except Exception as e:
                    conn.rollback()
                    print(f"Erro no decode: {e}")
                    self._send_error(400, str(e))

            conn.close()

        except Exception as e:
            print(f"Erro geral no parsing multipart: {e}")
            self._send_error(400, f"Erro ao processar multipart: {str(e)}")

    def _get_token(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return None

    def _send_error(self, status_code, message=""):
        self._set_headers(status_code)
        self.wfile.write(json.dumps({
            "error": message or HTTPStatus(status_code).phrase
        }).encode())


if __name__ == "__main__":
    print(f"Iniciando servidor na porta {PORT}...")
    print(f"Aceda a: http://localhost:{PORT}/api/health para testar")
    
    with socketserver.TCPServer(("", PORT), StegoHandler) as httpd:
        print("Servidor ativo! Pressione Ctrl+C para parar.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServidor parado pelo utilizador.")
            httpd.server_close()
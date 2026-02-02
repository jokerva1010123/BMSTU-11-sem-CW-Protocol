#!/usr/bin/env python3
"""
TCP File Server - Сервер для приема файлов с аутентификацией и проверкой целостности
"""
import socket
import threading
import json
import hashlib
import os
import logging
import shutil
import datetime
from config import TCP_PORT, UDP_DATA_PORT, MAX_FILE_SIZE, UPLOAD_DIR
import jwt
from config import JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRATION_HOURS
import os
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import UDP_PLAINTEXT_CHUNK_SIZE

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s TCP-SERVER] %(message)s',
    datefmt='%H:%M:%S'
)

class TCPServer:
    def __init__(self, port=TCP_PORT):
        self.port = port
        self.running = False
        self.server_socket = None
        self.udp_socket = None
        self.clients = []
        self.session_keys = {}
        
        # Загружаем базу пользователей
        self.users = self.load_users()
        
        # Создаем директорию для загрузок
        if not os.path.exists(UPLOAD_DIR):
            os.makedirs(UPLOAD_DIR)
    
    def load_users(self):
        """Загружает пользователей из JSON файла"""
        try:
            if os.path.exists('user_db.json'):
                with open('user_db.json', 'r') as f:
                    return json.load(f)
            else:
                # Создаем тестовых пользователей
                default_users = {
                    'admin': hashlib.sha256(b'admin123').hexdigest(),
                    'user': hashlib.sha256(b'password').hexdigest(),
                    'test': hashlib.sha256(b'test123').hexdigest()
                }
                with open('user_db.json', 'w') as f:
                    json.dump(default_users, f, indent=2)
                return default_users
        except Exception as e:
            logging.error(f"Error loading users: {e}")
            return {}
    
    def verify_jwt(self, token):
        """Verifies JWT token and returns user info"""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None  # Token expired
        except jwt.InvalidTokenError:
            return None  # Invalid token
    
    def _send_json_response(self, conn, response_data: dict, session_info) -> bool:
        """Gửi response dưới dạng JSON mã hóa với AES-GCM"""
        try:
            # Chuyển sang JSON string
            json_str = json.dumps(response_data)
            
            # Mã hóa JSON với AES-GCM
            if session_info and 'aesgcm' in session_info:
                nonce_prefix = session_info.setdefault('response_nonce_prefix', os.urandom(4))
                nonce_counter = session_info.setdefault('response_nonce_counter', 0)
                
                nonce = nonce_prefix + nonce_counter.to_bytes(8, 'big')
                session_info['response_nonce_counter'] = nonce_counter + 1
                
                aesgcm = session_info['aesgcm']
                session_id = session_info['session_id']
                
                ciphertext = aesgcm.encrypt(nonce, json_str.encode(), None)
                encrypted_data = session_id + nonce + ciphertext
                encrypted_b64 = base64.b64encode(encrypted_data).decode()
            else:
                # Base64 nếu chưa có session key
                encrypted_b64 = base64.b64encode(json_str.encode()).decode()
            
            # Gửi dữ liệu mã hóa
            conn.send(encrypted_b64.encode())
            return True
        except Exception as e:
            logging.error(f"Error sending JSON response: {e}")
            return False
    
    def _log_command_to_json(self, command: str, encrypted_command: str, username: str, status: str = 'received', client_ip: str = ''):
        """Ghi lệnh vào file JSON trên server"""
        try:
            log_file = 'commands_received_log.json'
            
            # Tải log hiện tại
            commands_log = []
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    try:
                        commands_log = json.load(f)
                    except:
                        commands_log = []
            
            # Thêm entry mới
            log_entry = {
                'timestamp': datetime.datetime.now().isoformat(),
                'username': username,
                'original_command': command,
                'encrypted_command': encrypted_command,
                'status': status,
                'client_ip': client_ip
            }
            commands_log.append(log_entry)
            
            # Lưu vào file
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(commands_log, f, indent=2, ensure_ascii=False)
            
            logging.info(f"Command logged to {log_file}")
        except Exception as e:
            logging.error(f"Error logging command on server: {e}")
    
    def authenticate(self, conn, addr):
        """Выполняет аутентификацию клиента"""
        try:
            conn.send(b'AUTH_REQUIRED')
            
            # Получаем учетные данные
            auth_data = conn.recv(1024).decode().strip()
            if not auth_data:
                return False, "Empty data"
            
            parts = auth_data.split()
            if len(parts) != 3 or parts[0] != 'AUTH':
                return False, "Invalid format"
            
            username, password_hash = parts[1], parts[2]
            
            # Проверяем пользователя
            if username in self.users:
                stored_hash = self.users[username]
                if stored_hash == password_hash:
                    # Generate JWT token
                    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=JWT_EXPIRATION_HOURS)
                    token_payload = {
                        'username': username,
                        'is_admin': (username == 'admin'),
                        'exp': int(expiration.timestamp())
                    }
                    token = jwt.encode(token_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
                    
                    conn.send(f'AUTH_OK {token}'.encode())
                    logging.info(f"User {username} authenticated from {addr[0]}")
                    return True, username
                else:
                    conn.send(b'AUTH_FAIL:Wrong password')
                    return False, "Wrong password"
            else:
                conn.send(b'AUTH_FAIL:User not found')
                return False, "User not found"
                
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            return False, str(e)

    def perform_handshake(self, conn, addr):
        """3-step X25519 handshake: receive client pub, send server pub, derive AES key"""
        try:
            data = conn.recv(2048).decode().strip()
            if not data.startswith("KEYEX"):
                logging.error(f"Handshake start missing from {addr}")
                return None

            parts = data.split()
            if len(parts) != 2:
                logging.error(f"Invalid KEYEX format from {addr}")
                return None

            client_pub_bytes = base64.b64decode(parts[1])
            client_pub = X25519PublicKey.from_public_bytes(client_pub_bytes)

            server_private = X25519PrivateKey.generate()
            server_public_bytes = server_private.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw
            )

            shared = server_private.exchange(client_pub)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"lftp-x25519-handshake",
            )
            session_key = hkdf.derive(shared)
            aesgcm = AESGCM(session_key)

            session_id = os.urandom(4)
            self.session_keys[session_id] = aesgcm

            resp = f"KEYRESP {base64.b64encode(server_public_bytes).decode()} {session_id.hex()}"
            conn.send(resp.encode())

            confirm = conn.recv(1024)
            if confirm.strip() != b"KEY_OK":
                logging.error(f"Handshake confirmation failed for {addr}")
                return None

            logging.info(f"Handshake complete for {addr}, session {session_id.hex()}")
            return {'aesgcm': aesgcm, 'session_id': session_id}
        except Exception as e:
            logging.error(f"Handshake error with {addr}: {e}")
            return None
        
    def receive_streaming_file(self, conn, client_ip, filename, expected_size, session_info):
        """
        Прием больших файлов потоковым способом
        """
        try:
            file_path = os.path.join(UPLOAD_DIR, filename)
            
            # Уникальное имя файла
            counter = 1
            name, ext = os.path.splitext(filename)
            while os.path.exists(file_path):
                filename = f"{name}_{counter}{ext}"
                file_path = os.path.join(UPLOAD_DIR, filename)
                counter += 1
            
            # Отправляем подтверждение готовности
            ready_stream_response = {"status": "ok", "command": "READY_STREAM"}
            self._send_json_response(conn, ready_stream_response, session_info)
            logging.info(f"Receiving streaming file: {filename} ({expected_size} bytes)")
            
            # Начинаем прием потоковым способом
            bytes_received = 0
            file_hash = hashlib.sha256()
            expected_size_int = int(expected_size)
            
            with open(file_path, 'wb') as f:
                # Устанавливаем таймаут для операций чтения
                conn.settimeout(30.0)
                
                while bytes_received < expected_size_int:
                    try:
                        # Получаем размер следующего чанка (4 байта)
                        header = conn.recv(4)
                        if len(header) < 4:
                            if bytes_received >= expected_size_int:
                                break  # Файл полностью получен
                            else:
                                raise ConnectionError("Incomplete header received")
                        
                        chunk_size = int.from_bytes(header, 'big')
                        
                        # Получаем сам чанк
                        chunk_received = 0
                        chunk_data = bytearray()
                        
                        while chunk_received < chunk_size:
                            remaining = chunk_size - chunk_received
                            # Читаем не более 64KB за раз
                            part = conn.recv(min(65536, remaining))
                            if not part:
                                raise ConnectionError("Connection closed during chunk transfer")
                            
                            chunk_data.extend(part)
                            chunk_received += len(part)
                        
                        # Записываем чанк и обновляем хеш
                        f.write(chunk_data)
                        file_hash.update(chunk_data)
                        bytes_received += chunk_received
                        
                        # Логируем прогресс каждые 100MB
                        if bytes_received % (100 * 1024 * 1024) < chunk_received:
                            progress = (bytes_received / expected_size_int) * 100
                            mb_received = bytes_received / (1024 * 1024)
                            mb_total = expected_size_int / (1024 * 1024)
                            logging.info(f"Received: {mb_received:.1f}/{mb_total:.1f} MB ({progress:.1f}%)")
                            
                    except socket.timeout:
                        logging.warning(f"Socket timeout, received {bytes_received}/{expected_size} bytes")
                        # Проверяем, может файл уже полностью получен?
                        if bytes_received >= expected_size_int:
                            break
                        # Иначе продолжаем попытки
                        continue
            
            # Ждем финальный хеш от клиента
            try:
                hash_data = conn.recv(1024).decode('utf-8', errors='ignore')
            except:
                hash_data = ""
                
            if hash_data.startswith('FILE_HASH'):
                client_hash = hash_data.split()[1]
                server_hash = file_hash.hexdigest()
                
                if client_hash == server_hash:
                    logging.info(f"Streaming file received successfully: {filename}")
                    file_ok_response = {"status": "ok", "command": "FILE_OK", "hash": server_hash[:16]}
                    self._send_json_response(conn, file_ok_response, session_info)
                    return True, f"File received: {bytes_received} bytes"
                else:
                    logging.error(f"Hash mismatch for streaming file {filename}")
                    logging.error(f"Client hash: {client_hash[:32]}...")
                    logging.error(f"Server hash: {server_hash[:32]}...")
                    
                    # Сохраняем файл для анализа, но отмечаем как проблемный
                    corrupted_path = file_path + ".corrupted"
                    os.rename(file_path, corrupted_path)
                    corrupted_response = {"status": "error", "command": "FILE_CORRUPTED", "server_hash": server_hash}
                    self._send_json_response(conn, corrupted_response, session_info)
                    return False, "Hash mismatch - file saved as .corrupted"
            else:
                # Если хеш не получен, вычисляем его из полученного файла
                server_hash = file_hash.hexdigest()
                if bytes_received == expected_size_int:
                    logging.warning(f"No hash received, but file size matches. Hash: {server_hash[:16]}...")
                    file_ok_response = {"status": "ok", "command": "FILE_OK", "hash": server_hash}
                    self._send_json_response(conn, file_ok_response, session_info)
                    return True, f"File received without hash verification: {bytes_received} bytes"
                else:
                    logging.error(f"Incomplete transfer: {bytes_received}/{expected_size_int} bytes")
                    os.remove(file_path)
                    incomplete_response = {"status": "error", "command": "FILE_INCOMPLETE", "received": bytes_received, "expected": expected_size_int}
                    self._send_json_response(conn, incomplete_response, session_info)
                    return False, f"Incomplete transfer: {bytes_received}/{expected_size_int}"
                
        except Exception as e:
            logging.error(f"Streaming file receive error: {e}")
            if 'file_path' in locals() and os.path.exists(file_path):
                os.remove(file_path)
            return False, str(e)
        finally:
            # Восстанавливаем стандартный таймаут
            conn.settimeout(None)
    
    def receive_file(self, conn, client_ip, filename, expected_size, expected_checksum, session_info):
        """Принимает файл и проверяет целостность"""
        try:
            file_path = os.path.join(UPLOAD_DIR, filename)
            
            # Проверяем, не существует ли файл
            counter = 1
            name, ext = os.path.splitext(filename)
            while os.path.exists(file_path):
                filename = f"{name}_{counter}{ext}"
                file_path = os.path.join(UPLOAD_DIR, filename)
                counter += 1
            
            # Gửi READY_UDP dưới dạng JSON mã hóa
            response = {"status": "ok", "command": "READY_UDP"}
            self._send_json_response(conn, response, session_info)
            logging.info(f"Receiving encrypted UDP file: {filename} ({expected_size} bytes)")

            received_data = bytearray()
            bytes_received = 0
            # Must be small enough for UDP
            chunk_size = UDP_PLAINTEXT_CHUNK_SIZE
            self.udp_socket.settimeout(90)
            session_id = session_info['session_id']
            aesgcm = session_info['aesgcm']

            while bytes_received < int(expected_size):
                try:
                    # packet overhead: 4(session) + 12(nonce) + 16(tag) ~= 32 bytes
                    packet, addr = self.udp_socket.recvfrom(chunk_size + 64)
                    if addr[0] != client_ip:
                        continue
                    if not packet.startswith(session_id):
                        continue
                    nonce = packet[4:16]
                    ciphertext = packet[16:]
                    try:
                        chunk = aesgcm.decrypt(nonce, ciphertext, None)
                    except Exception as decrypt_error:
                        logging.error(f"Decrypt error: {decrypt_error}")
                        continue
                    received_data.extend(chunk)
                    bytes_received += len(chunk)
                    # Gửi ACK dưới dạng JSON mã hóa
                    ack_response = {"status": "ok", "command": "ACK", "bytes_received": bytes_received}
                    self._send_json_response(conn, ack_response, session_info)
                except socket.timeout:
                    logging.error("UDP receive timeout")
                    break
            
            # Проверяем целостность
            actual_checksum = hashlib.sha256(received_data).hexdigest()
            
            if actual_checksum == expected_checksum:
                # Сохраняем файл
                with open(file_path, 'wb') as f:
                    f.write(received_data)
                
                # Сохраняем метаданные
                metadata = {
                    'original_name': filename,
                    'size': bytes_received,
                    'checksum': actual_checksum,
                    'received_at': datetime.datetime.now().isoformat()
                }
                
                meta_path = file_path + '.meta'
                with open(meta_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
                logging.info(f"File saved: {file_path}")
                # Gửi FILE_OK dưới dạng JSON mã hóa
                ok_response = {"status": "ok", "command": "FILE_OK", "checksum": actual_checksum}
                self._send_json_response(conn, ok_response, session_info)
                return True, f"File received successfully. Hash: {actual_checksum[:16]}..."
            else:
                logging.error(f"Integrity error. Expected: {expected_checksum[:16]}..., Got: {actual_checksum[:16]}...")
                # Gửi FILE_CORRUPTED dưới dạng JSON mã hóa
                corrupted_response = {"status": "error", "command": "FILE_CORRUPTED", "received_hash": actual_checksum}
                self._send_json_response(conn, corrupted_response, session_info)
                return False, "Data integrity error"
                
        except Exception as e:
            logging.error(f"Error receiving file: {e}")
            # Gửi FILE_ERROR dưới dạng JSON mã hóa
            error_response = {"status": "error", "command": "FILE_ERROR", "message": str(e)}
            self._send_json_response(conn, error_response, session_info)
            return False, str(e)
    
    def handle_client(self, conn, addr):
        """Обрабатывает соединение с клиентом"""
        client_id = f"{addr[0]}:{addr[1]}"
        self.clients.append(client_id)
        username = None
        
        try:
            logging.info(f"New connection from {client_id}")
            
            session_info = self.perform_handshake(conn, addr)
            if not session_info:
                conn.close()
                return

            # Аутентификация
            auth_success, auth_message = self.authenticate(conn, addr)
            if not auth_success:
                logging.warning(f"Authentication failed for {client_id}: {auth_message}")
                return
            
            username = auth_message
            
            # Send UDP data port to client (plain text - before main command loop)
            conn.send(f'UDP_PORT {UDP_DATA_PORT}'.encode())
            logging.info(f"Sent UDP data port {UDP_DATA_PORT} to {client_id}")
            
            # Основной цикл обработки команд (JSON мã hóa)
            while True:
                try:
                    # Получаем JSON данные мã hóa (base64)
                    encrypted_data_b64 = conn.recv(4096).decode().strip()
                    if not encrypted_data_b64:
                        break
                    
                    # Giải mã JSON packet
                    encrypted_data = base64.b64decode(encrypted_data_b64)
                    
                    # Kiểm tra có dùng AES-GCM hay base64 thôi
                    if session_info and 'aesgcm' in session_info:
                        # Giải mã AES-GCM
                        session_id = session_info['session_id']
                        aesgcm = session_info['aesgcm']
                        
                        if len(encrypted_data) < 4 + 12:
                            error_response = {"status": "error", "message": "Invalid encrypted data"}
                            self._send_json_response(conn, error_response, session_info)
                            continue
                        
                        pkt_session = encrypted_data[:4]
                        if pkt_session != session_id:
                            error_response = {"status": "error", "message": "Session mismatch"}
                            self._send_json_response(conn, error_response, session_info)
                            continue
                        
                        nonce = encrypted_data[4:16]
                        ciphertext = encrypted_data[16:]
                        
                        try:
                            json_str = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                        except Exception as e:
                            logging.error(f"Decryption error: {e}")
                            self._log_command_to_json('', encrypted_data_b64, username, 'decryption_failed', addr[0])
                            error_response = {"status": "error", "message": "Decryption failed"}
                            self._send_json_response(conn, error_response, session_info)
                            continue
                    else:
                        # Base64 thôi (chưa có session key)
                        json_str = encrypted_data.decode('utf-8')
                    
                    # Parse JSON
                    json_packet = json.loads(json_str)
                    
                    # Lấy JWT token từ JSON
                    jwt_token = json_packet.get('token', '')
                    command = json_packet.get('command', '')
                    
                    # Xác minh JWT
                    token_payload = self.verify_jwt(jwt_token)
                    if not token_payload:
                        self._log_command_to_json(command, encrypted_data_b64, 'unknown', 'auth_failed', addr[0])
                        error_response = {"status": "error", "message": "Invalid or expired token"}
                        self._send_json_response(conn, error_response, session_info)
                        logging.warning(f"Invalid JWT token from {client_id}")
                        continue
                    
                    username = token_payload['username']
                    is_admin = token_payload.get('is_admin', False)
                    
                    # Log lệnh nhận được
                    self._log_command_to_json(command, encrypted_data_b64, username, 'received', addr[0])
                    logging.info(f"Command from {username}: {command[:50]}...")

                    if command.startswith('FILE'):
                        # Формат: FILE <filename> <size> <checksum>
                        cmd_parts = command.split()
                        if len(cmd_parts) == 4:
                            _, filename, size, checksum = cmd_parts
                            success, message = self.receive_file(conn, addr[0], filename, size, checksum, session_info)
                            if success:
                                logging.info(f"File from {username} processed: {message}")
                            else:
                                logging.error(f"File processing error from {username}: {message}")
                        else:
                            error_response = {"status": "error", "message": "Invalid FILE command format"}
                            self._send_json_response(conn, error_response, session_info)
                    elif command.startswith('STREAM_FILE'):
                        # Формат: STREAM_FILE <filename> <size>
                        cmd_parts = command.split()
                        if len(cmd_parts) == 3:
                            _, filename, size = cmd_parts
                            success, message = self.receive_streaming_file(conn, addr[0], filename, size, session_info)
                            error_response = {"status": "error", "message": "Invalid STREAM_FILE command format"}
                            self._send_json_response(conn, error_response, session_info)

                    elif command.startswith('FOLDER_START'):
                        # Format: FOLDER_START <folder_name> <file_count>
                        cmd_parts = command.split()
                        if len(cmd_parts) == 3:
                            _, folder_name, file_count = cmd_parts
                            success, message = self.handle_folder_transfer(conn, folder_name, file_count, session_info)
                            if success:
                                logging.info(f"Folder from {username} received: {message}")
                            else:
                                logging.error(f"Folder receive error from {username}: {message}")
                        else:
                            error_response = {"status": "error", "message": "Invalid FOLDER_START command"}
                            self._send_json_response(conn, error_response, session_info)

                    elif command.startswith('REL_FILE'):
                        # This is handled within handle_folder_transfer
                        # But we need to acknowledge it
                        ready_response = {"status": "ok", "command": "READY"}
                        self._send_json_response(conn, ready_response, session_info)

                    elif command == 'FOLDER_END':
                        # This is handled within receive_folder
                        pass
                    
                    elif command == 'LIST_FILES':
                        # List all files and folders in uploads directory
                        success, message = self.list_files(conn, session_info)
                        if success:
                            logging.info(f"File list sent to {username}")
                        else:
                            logging.error(f"List files error: {message}")
                    
                    elif command.startswith('DOWNLOAD_FILE'):
                        # Format: DOWNLOAD_FILE <filename>
                        cmd_parts = command.split()
                        if len(cmd_parts) == 2:
                            _, filename = cmd_parts
                            success, message = self.send_file_to_client(conn, filename, session_info)
                            if success:
                                logging.info(f"File {filename} sent to {username}: {message}")
                            else:
                                logging.error(f"File send error to {username}: {message}")
                        else:
                            error_response = {"status": "error", "message": "Invalid DOWNLOAD_FILE command format"}
                            self._send_json_response(conn, error_response, session_info)
                    
                    elif command.startswith('DOWNLOAD_FOLDER'):
                        # Format: DOWNLOAD_FOLDER <folder_name>
                        cmd_parts = command.split()
                        if len(cmd_parts) == 2:
                            _, folder_name = cmd_parts
                            success, message = self.send_folder_to_client(conn, folder_name, session_info)
                            if success:
                                logging.info(f"Folder {folder_name} sent to {username}: {message}")
                            else:
                                logging.error(f"Folder send error to {username}: {message}")
                        else:
                            error_response = {"status": "error", "message": "Invalid DOWNLOAD_FOLDER command format"}
                            self._send_json_response(conn, error_response, session_info)
                    
                    elif command.startswith('DELETE_FILE'):
                        # Format: DELETE_FILE <filename>
                        if not is_admin:
                            error_response = {"status": "error", "message": "Permission denied. Admin only."}
                            self._send_json_response(conn, error_response, session_info)
                            logging.warning(f"User {username} attempted to delete file (admin only)")
                        else:
                            cmd_parts = command.split()
                            if len(cmd_parts) == 2:
                                _, filename = cmd_parts
                                success, message = self.delete_file(filename)
                                if success:
                                    logging.info(f"File {filename} deleted by {username}: {message}")
                                    delete_response = {"status": "ok", "command": "DELETE_OK", "message": message}
                                    self._send_json_response(conn, delete_response, session_info)
                                else:
                                    logging.error(f"Delete file error: {message}")
                                    error_response = {"status": "error", "command": "DELETE_FAIL", "message": message}
                                    self._send_json_response(conn, error_response, session_info)
                            else:
                                error_response = {"status": "error", "message": "Invalid DELETE_FILE command format"}
                                self._send_json_response(conn, error_response, session_info)
                    
                    elif command.startswith('DELETE_FOLDER'):
                        # Format: DELETE_FOLDER <folder_name>
                        if not is_admin:
                            error_response = {"status": "error", "message": "Permission denied. Admin only."}
                            self._send_json_response(conn, error_response, session_info)
                            logging.warning(f"User {username} attempted to delete folder (admin only)")
                        else:
                            cmd_parts = command.split()
                            if len(cmd_parts) == 2:
                                _, folder_name = cmd_parts
                                success, message = self.delete_folder(folder_name)
                                if success:
                                    logging.info(f"Folder {folder_name} deleted by {username}: {message}")
                                    delete_response = {"status": "ok", "command": "DELETE_OK", "message": message}
                                    self._send_json_response(conn, delete_response, session_info)
                                else:
                                    logging.error(f"Delete folder error: {message}")
                                    error_response = {"status": "error", "command": "DELETE_FAIL", "message": message}
                                    self._send_json_response(conn, error_response, session_info)
                            else:
                                error_response = {"status": "error", "message": "Invalid DELETE_FOLDER command format"}
                                self._send_json_response(conn, error_response, session_info)
                    
                    elif command.startswith('RENAME_FILE'):
                        # Format: RENAME_FILE <old_name> <new_name>
                        if not is_admin:
                            error_response = {"status": "error", "message": "Permission denied. Admin only."}
                            self._send_json_response(conn, error_response, session_info)
                            logging.warning(f"User {username} attempted to rename file (admin only)")
                        else:
                            cmd_parts = command.split(maxsplit=2)
                            if len(cmd_parts) == 3:
                                _, old_name, new_name = cmd_parts
                                success, message = self.rename_file(old_name, new_name)
                                if success:
                                    logging.info(f"File {old_name} renamed to {new_name} by {username}: {message}")
                                    rename_response = {"status": "ok", "command": "RENAME_OK", "message": message}
                                    self._send_json_response(conn, rename_response, session_info)
                                else:
                                    logging.error(f"Rename file error: {message}")
                                    error_response = {"status": "error", "command": "RENAME_FAIL", "message": message}
                                    self._send_json_response(conn, error_response, session_info)
                            else:
                                error_response = {"status": "error", "message": "Invalid RENAME_FILE command format"}
                                self._send_json_response(conn, error_response, session_info)
                    
                    elif command.startswith('RENAME_FOLDER'):
                        # Format: RENAME_FOLDER <old_name> <new_name>
                        if not is_admin:
                            error_response = {"status": "error", "message": "Permission denied. Admin only."}
                            self._send_json_response(conn, error_response, session_info)
                            logging.warning(f"User {username} attempted to rename folder (admin only)")
                        else:
                            cmd_parts = command.split(maxsplit=2)
                            if len(cmd_parts) == 3:
                                _, old_name, new_name = cmd_parts
                                success, message = self.rename_folder(old_name, new_name)
                                if success:
                                    logging.info(f"Folder {old_name} renamed to {new_name} by {username}: {message}")
                                    rename_response = {"status": "ok", "command": "RENAME_OK", "message": message}
                                    self._send_json_response(conn, rename_response, session_info)
                                else:
                                    logging.error(f"Rename folder error: {message}")
                                    error_response = {"status": "error", "command": "RENAME_FAIL", "message": message}
                                    self._send_json_response(conn, error_response, session_info)
                            else:
                                error_response = {"status": "error", "message": "Invalid RENAME_FOLDER command format"}
                                self._send_json_response(conn, error_response, session_info)
                    
                    elif command == 'QUIT':
                        goodbye_response = {"status": "ok", "message": "GOODBYE"}
                        self._send_json_response(conn, goodbye_response, session_info)
                        break
                    
                    else:
                        error_response = {"status": "error", "message": "Unknown command"}
                        self._send_json_response(conn, error_response, session_info)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Command processing error: {e}")
                    break
                    
        except Exception as e:
            logging.error(f"Connection error with {client_id}: {e}")
            
        finally:
            if username:
                logging.info(f"Connection with {username} ({client_id}) closed")
            else:
                logging.info(f"Connection with {client_id} closed")
            
            if client_id in self.clients:
                self.clients.remove(client_id)
            conn.close()
    
    def start(self):
        """Запускает TCP сервер"""
        self.running = True
        
        try:
            # Initialize UDP socket for data transfer
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.bind(('0.0.0.0', UDP_DATA_PORT))
            logging.info(f"UDP Data Server started on port {UDP_DATA_PORT}")
            
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            
            logging.info(f"TCP Server started on port {self.port}")
            logging.info(f"Upload directory: {os.path.abspath(UPLOAD_DIR)}")
            logging.info(f"Loaded {len(self.users)} users")
            
            while self.running:
                try:
                    conn, addr = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    logging.error(f"Accept connection error: {e}")
                    
        except Exception as e:
            logging.error(f"Server start error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Останавливает сервер"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logging.info("TCP Server stopped")
    
    def handle_folder_transfer(self, conn, folder_name, file_count, session_info):
        """Handles folder transfer - creates folder and receives files"""
        try:
            # Create unique folder name
            base_folder_name = folder_name
            counter = 1
            while os.path.exists(os.path.join(UPLOAD_DIR, folder_name)):
                folder_name = f"{base_folder_name}_{counter}"
                counter += 1
            
            # Create the folder
            folder_path = os.path.join(UPLOAD_DIR, folder_name)
            os.makedirs(folder_path, exist_ok=True)
            
            folder_ready_response = {"status": "ok", "command": "FOLDER_READY"}
            self._send_json_response(conn, folder_ready_response, session_info)
            logging.info(f"Ready to receive folder '{folder_name}' with {file_count} files")
            
            files_received = 0
            
            while files_received < int(file_count):
                # Receive next command (encrypted JSON)
                try:
                    encrypted_data_b64 = conn.recv(4096).decode().strip()
                    if not encrypted_data_b64:
                        break
                    
                    # Decode from base64
                    encrypted_data = base64.b64decode(encrypted_data_b64)
                    
                    # Decrypt JSON packet
                    if session_info and 'aesgcm' in session_info:
                        session_id = session_info['session_id']
                        aesgcm = session_info['aesgcm']
                        
                        if len(encrypted_data) < 4 + 12:
                            error_response = {"status": "error", "message": "Invalid encrypted data"}
                            self._send_json_response(conn, error_response, session_info)
                            continue
                        
                        pkt_session = encrypted_data[:4]
                        if pkt_session != session_id:
                            error_response = {"status": "error", "message": "Session mismatch"}
                            self._send_json_response(conn, error_response, session_info)
                            continue
                        
                        nonce = encrypted_data[4:16]
                        ciphertext = encrypted_data[16:]
                        
                        try:
                            json_str = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                        except Exception as e:
                            logging.error(f"Decryption error in folder transfer: {e}")
                            error_response = {"status": "error", "message": "Decryption failed"}
                            self._send_json_response(conn, error_response, session_info)
                            continue
                    else:
                        json_str = encrypted_data.decode('utf-8')
                    
                    # Parse JSON
                    json_packet = json.loads(json_str)
                    command = json_packet.get('command', '')
                    
                except (json.JSONDecodeError, ValueError, base64.binascii.Error) as e:
                    logging.error(f"Error parsing folder transfer command: {e}")
                    error_response = {"status": "error", "message": "Invalid command format"}
                    self._send_json_response(conn, error_response, session_info)
                    continue
                
                if command.startswith('REL_FILE'):
                    # Format: REL_FILE <relative_path> <size> <checksum>
                    parts = command.split()
                    if len(parts) == 4:
                        _, rel_path, size, checksum = parts
                        
                        # Create subdirectories if needed
                        full_path = os.path.join(folder_path, rel_path)
                        file_dir = os.path.dirname(full_path)
                        if file_dir:
                            os.makedirs(file_dir, exist_ok=True)
                        
                        # Receive the file
                        success, message = self.receive_file_to_path(conn, full_path, size, checksum, session_info)
                        
                        if success:
                            files_received += 1
                            file_ok_response = {"status": "ok", "command": "FILE_OK", "checksum": checksum}
                            self._send_json_response(conn, file_ok_response, session_info)
                            logging.info(f"Received file {files_received}/{file_count}: {rel_path}")
                        else:
                            file_fail_response = {"status": "error", "command": "FILE_FAIL", "message": message}
                            self._send_json_response(conn, file_fail_response, session_info)
                            return False, f"File {rel_path} failed"
                    else:
                        error_response = {"status": "error", "message": "Invalid REL_FILE command"}
                        self._send_json_response(conn, error_response, session_info)
                        return False, "Invalid command"
                
                elif command.startswith('FOLDER_END'):
                    # Folder transfer complete
                    break
                
                else:
                    error_response = {"status": "error", "message": "Unknown command"}
                    self._send_json_response(conn, error_response, session_info)
                    return False, "Unknown command"
            
            # Send completion
            folder_complete_response = {
                "status": "ok", 
                "command": "FOLDER_COMPLETE", 
                "files_received": files_received
            }
            self._send_json_response(conn, folder_complete_response, session_info)
            return True, f"Folder '{folder_name}' received: {files_received} files"
            
        except Exception as e:
            logging.error(f"Folder receive error: {e}")
            return False, str(e)

    def receive_file_to_path(self, conn, file_path, expected_size, expected_checksum, session_info):
        """Receives a file and saves to specific path"""
        try:
            ready_response = {"status": "ok", "command": "READY"}
            self._send_json_response(conn, ready_response, session_info)
            
            # Receive data
            received_data = b''
            bytes_received = 0
            chunk_size = 4096
            
            while bytes_received < int(expected_size):
                remaining = int(expected_size) - bytes_received
                chunk = conn.recv(min(chunk_size, remaining))
                if not chunk:
                    break
                received_data += chunk
                bytes_received += len(chunk)
            
            # Check integrity
            actual_checksum = hashlib.sha256(received_data).hexdigest()
            
            if actual_checksum == expected_checksum:
                # Save file to specific path
                with open(file_path, 'wb') as f:
                    f.write(received_data)
                return True, f"File saved to {file_path}"
            else:
                logging.error(f"Checksum mismatch for {file_path}")
                return False, "Checksum mismatch"
                
        except Exception as e:
            logging.error(f"Error receiving file {file_path}: {e}")
            return False, str(e)
    
    def list_files(self, conn, session_info):
        """Lists all files and folders in the uploads directory"""
        try:
            files_list = []
            folders_list = []
            
            if not os.path.exists(UPLOAD_DIR):
                empty_response = {"status": "ok", "command": "LIST_EMPTY"}
                self._send_json_response(conn, empty_response, session_info)
                return True, "Upload directory is empty"
            
            # Scan for files and folders
            for item in os.listdir(UPLOAD_DIR):
                item_path = os.path.join(UPLOAD_DIR, item)
                
                # Skip metadata files
                if item.endswith('.meta') or item.endswith('.corrupted'):
                    continue
                
                if os.path.isfile(item_path):
                    file_size = os.path.getsize(item_path)
                    files_list.append({
                        'name': item,
                        'type': 'file',
                        'size': file_size
                    })
                elif os.path.isdir(item_path):
                    # Count files in folder
                    file_count = sum(1 for root, dirs, files in os.walk(item_path) 
                                   for f in files if not f.endswith('.meta'))
                    folders_list.append({
                        'name': item,
                        'type': 'folder',
                        'file_count': file_count
                    })
            
            # Send list
            list_data = {
                'files': files_list,
                'folders': folders_list
            }
            
            # Gửi danh sách file dưới dạng JSON mã hóa
            list_response = {"status": "ok", "command": "LIST_OK", "data": list_data}
            self._send_json_response(conn, list_response, session_info)
            
            return True, f"List sent: {len(files_list)} files, {len(folders_list)} folders"
                
        except Exception as e:
            logging.error(f"List files error: {e}")
            return False, str(e)
    
    def send_file_to_client(self, conn, filename, session_info):
        """Sends a file to the client"""
        try:
            file_path = os.path.join(UPLOAD_DIR, filename)
            
            if not os.path.exists(file_path):
                file_error_response = {"status": "error", "command": "FILE_NOT_FOUND"}
                self._send_json_response(conn, file_error_response, session_info)
                return False, f"File not found: {filename}"
            
            if not os.path.isfile(file_path):
                file_error_response = {"status": "error", "command": "NOT_A_FILE"}
                self._send_json_response(conn, file_error_response, session_info)
                return False, f"Not a file: {filename}"
            
            file_size = os.path.getsize(file_path)
            
            # Calculate checksum
            logging.info(f"Calculating checksum for {filename}...")
            file_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    file_hash.update(chunk)
            checksum = file_hash.hexdigest()
            
            # Send file info: FILE_INFO <filename> <size> <checksum>
            file_info_response = {
                "status": "ok", 
                "command": "FILE_INFO", 
                "filename": filename, 
                "size": file_size, 
                "checksum": checksum
            }
            self._send_json_response(conn, file_info_response, session_info)
            
            # Wait for READY_UDP with client UDP port from client
            # Client sẽ gửi: {"command": "READY_UDP", "port": client_udp_port}
            # Nhưng nhìn code cũ, client gửi "READY_UDP <port>"
            # Ta cần chuyển sang nhận JSON response từ client
            # Tạm để như cũ vì client vẫn có thể gửi plain text READY_UDP
            response = conn.recv(1024).decode().strip()
            if not response.startswith('READY_UDP'):
                return False, f"Client not ready: {response}"
            try:
                client_udp_port = int(response.split()[1])
            except Exception:
                return False, f"Invalid READY_UDP response: {response}"
            
            client_ip = conn.getpeername()[0]
            aesgcm = session_info['aesgcm']
            session_id = session_info['session_id']
            tx_prefix = session_info.setdefault('server_nonce_prefix', os.urandom(4))
            session_info.setdefault('server_tx_counter', 0)

            def next_nonce():
                counter = session_info['server_tx_counter']
                session_info['server_tx_counter'] = counter + 1
                return tx_prefix + counter.to_bytes(8, 'big')
            
            logging.info(f"Sending file {filename} via UDP/AES to {client_ip}:{client_udp_port}")
            bytes_sent = 0

            with open(file_path, 'rb') as f:
                while bytes_sent < file_size:
                    # UDP must stay small to avoid fragmentation / WinError 10040
                    chunk = f.read(UDP_PLAINTEXT_CHUNK_SIZE)
                    if not chunk:
                        break
                    nonce = next_nonce()
                    ciphertext = aesgcm.encrypt(nonce, chunk, None)
                    packet = session_id + nonce + ciphertext
                    self.udp_socket.sendto(packet, (client_ip, client_udp_port))
                    bytes_sent += len(chunk)
            
            # Wait for confirmation
            result = conn.recv(1024).decode().strip()
            if result.startswith('FILE_RECEIVED'):
                return True, f"File sent: {bytes_sent:,} bytes"
            else:
                return False, f"Transfer failed: {result}"
                
        except Exception as e:
            logging.error(f"Send file error: {e}")
            return False, str(e)
    
    def send_folder_to_client(self, conn, folder_name, session_info):
        """Sends a folder to the client"""
        try:
            folder_path = os.path.join(UPLOAD_DIR, folder_name)
            
            if not os.path.exists(folder_path):
                folder_error_response = {"status": "error", "command": "FOLDER_NOT_FOUND"}
                self._send_json_response(conn, folder_error_response, session_info)
                return False, f"Folder not found: {folder_name}"
            
            if not os.path.isdir(folder_path):
                folder_error_response = {"status": "error", "command": "NOT_A_FOLDER"}
                self._send_json_response(conn, folder_error_response, session_info)
                return False, f"Not a folder: {folder_name}"
            
            # Get all files recursively
            all_files = []
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    # Skip metadata files
                    if file.endswith('.meta') or file.endswith('.corrupted'):
                        continue
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, folder_path)
                    all_files.append((full_path, rel_path))
            
            if not all_files:
                folder_empty_response = {"status": "ok", "command": "FOLDER_EMPTY"}
                self._send_json_response(conn, folder_empty_response, session_info)
                return False, "Folder is empty"
            
            # Send folder info: FOLDER_INFO <folder_name> <file_count>
            folder_info_response = {
                "status": "ok", 
                "command": "FOLDER_INFO", 
                "folder_name": folder_name, 
                "file_count": len(all_files)
            }
            self._send_json_response(conn, folder_info_response, session_info)
            
            # Wait for READY
            response = conn.recv(1024).decode().strip()
            if response != 'FOLDER_READY':
                return False, f"Client not ready: {response}"
            
            # Send each file
            files_sent = 0
            total_size = 0
            
            for full_path, rel_path in all_files:
                try:
                    file_size = os.path.getsize(full_path)
                    
                    # Calculate checksum
                    file_hash = hashlib.sha256()
                    with open(full_path, 'rb') as f:
                        while chunk := f.read(8192):
                            file_hash.update(chunk)
                    checksum = file_hash.hexdigest()
                    
                    # Send file info: REL_FILE_INFO <relative_path> <size> <checksum>
                    file_info_response = {
                        "status": "ok", 
                        "command": "REL_FILE_INFO", 
                        "rel_path": rel_path, 
                        "size": file_size, 
                        "checksum": checksum
                    }
                    self._send_json_response(conn, file_info_response, session_info)
                    
                    # Wait for READY - client sẽ gửi JSON response
                    response = conn.recv(1024).decode().strip()
                    if response != 'READY':
                        return False, f"Client not ready for {rel_path}: {response}"
                    
                    # Send file data
                    bytes_sent = 0
                    with open(full_path, 'rb') as f:
                        while bytes_sent < file_size:
                            chunk = f.read(65536)
                            if not chunk:
                                break
                            conn.sendall(chunk)
                            bytes_sent += len(chunk)
                    
                    # Wait for confirmation
                    result = conn.recv(1024).decode().strip()
                    if result.startswith('FILE_RECEIVED'):
                        files_sent += 1
                        total_size += file_size
                        logging.info(f"Sent file {files_sent}/{len(all_files)}: {rel_path}")
                    else:
                        return False, f"File transfer failed: {rel_path} - {result}"
                        
                except Exception as e:
                    logging.error(f"Error sending file {rel_path}: {e}")
                    return False, f"Error sending {rel_path}: {e}"
            
            # Send folder completion
            folder_complete_response = {
                "status": "ok", 
                "command": "FOLDER_COMPLETE", 
                "files_sent": files_sent
            }
            self._send_json_response(conn, folder_complete_response, session_info)
            
            # Wait for final confirmation
            final_response = conn.recv(1024).decode().strip()
            if final_response.startswith('FOLDER_RECEIVED'):
                return True, f"Folder sent: {files_sent} files, {total_size:,} bytes"
            else:
                return False, f"Folder transfer incomplete: {final_response}"
                
        except Exception as e:
            logging.error(f"Send folder error: {e}")
            return False, str(e)
    
    def delete_file(self, filename):
        """Deletes a file from the uploads directory"""
        try:
            file_path = os.path.join(UPLOAD_DIR, filename)
            
            if not os.path.exists(file_path):
                return False, f"File not found: {filename}"
            
            if not os.path.isfile(file_path):
                return False, f"Not a file: {filename}"
            
            # Also delete metadata file if exists
            meta_path = file_path + '.meta'
            if os.path.exists(meta_path):
                os.remove(meta_path)
            
            os.remove(file_path)
            logging.info(f"File deleted: {filename}")
            return True, f"File deleted: {filename}"
            
        except Exception as e:
            logging.error(f"Delete file error: {e}")
            return False, str(e)
    
    def delete_folder(self, folder_name):
        """Deletes a folder from the uploads directory"""
        try:
            folder_path = os.path.join(UPLOAD_DIR, folder_name)
            
            if not os.path.exists(folder_path):
                return False, f"Folder not found: {folder_name}"
            
            if not os.path.isdir(folder_path):
                return False, f"Not a folder: {folder_name}"
            
            # Use shutil to remove directory tree
            shutil.rmtree(folder_path)
            logging.info(f"Folder deleted: {folder_name}")
            return True, f"Folder deleted: {folder_name}"
            
        except Exception as e:
            logging.error(f"Delete folder error: {e}")
            return False, str(e)
    
    def rename_file(self, old_name, new_name):
        """Renames a file in the uploads directory"""
        try:
            old_path = os.path.join(UPLOAD_DIR, old_name)
            new_path = os.path.join(UPLOAD_DIR, new_name)
            
            if not os.path.exists(old_path):
                return False, f"File not found: {old_name}"
            
            if not os.path.isfile(old_path):
                return False, f"Not a file: {old_name}"
            
            if os.path.exists(new_path):
                return False, f"File already exists: {new_name}"
            
            # Rename file
            os.rename(old_path, new_path)
            
            # Rename metadata file if exists
            old_meta = old_path + '.meta'
            new_meta = new_path + '.meta'
            if os.path.exists(old_meta):
                os.rename(old_meta, new_meta)
            
            logging.info(f"File renamed: {old_name} -> {new_name}")
            return True, f"File renamed: {old_name} -> {new_name}"
            
        except Exception as e:
            logging.error(f"Rename file error: {e}")
            return False, str(e)
    
    def rename_folder(self, old_name, new_name):
        """Renames a folder in the uploads directory"""
        try:
            old_path = os.path.join(UPLOAD_DIR, old_name)
            new_path = os.path.join(UPLOAD_DIR, new_name)
            
            if not os.path.exists(old_path):
                return False, f"Folder not found: {old_name}"
            
            if not os.path.isdir(old_path):
                return False, f"Not a folder: {old_name}"
            
            if os.path.exists(new_path):
                return False, f"Folder already exists: {new_name}"
            
            # Rename folder
            os.rename(old_path, new_path)
            
            logging.info(f"Folder renamed: {old_name} -> {new_name}")
            return True, f"Folder renamed: {old_name} -> {new_name}"
            
        except Exception as e:
            logging.error(f"Rename folder error: {e}")
            return False, str(e)

if __name__ == "__main__":
    server = TCPServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nServer stopped by user")
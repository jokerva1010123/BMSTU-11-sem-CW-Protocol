#!/usr/bin/env python3
"""
TCP File Client - Клиент для передачи файлов на сервер
"""
import socket
import os
import hashlib
import time
import logging
import json
import base64
import datetime
import sys
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from config import TCP_PORT, UDP_DATA_PORT, CHUNK_SIZE, UDP_PLAINTEXT_CHUNK_SIZE

logging.basicConfig(
    level=logging.INFO,
    format='[TCP-CLIENT] %(message)s'
)

class TCPClient:
    def __init__(self, server_ip, server_port=TCP_PORT):
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock = None
        self.udp_sock = None
        self.udp_data_port = None
        self.client_udp_port = None
        self.authenticated = False
        self.username = None
        self.jwt_token = None
        self.session_key = None
        self.session_id = None
        self.aesgcm = None
        self.nonce_prefix = os.urandom(4)
        self.nonce_counter = 0
        self.commands_log = []  # Lưu trữ các lệnh
        self.commands_log_file = 'commands_log.json'  # File log lệnh
    
    def connect(self):
        """Устанавливает соединение с сервером с настройками для больших файлов"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Настройки для больших файлов
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)  # 1MB буфер отправки
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)  # 1MB буфер приема
            
            # Большие таймауты для больших файлов
            self.sock.settimeout(30.0)  # 30 секунд на операцию
            
            self.sock.connect((self.server_ip, self.server_port))
            logging.info(f"Connected to {self.server_ip}:{self.server_port}")

            # Выполняем X25519 рукопожатие для получения AES ключа
            if not self.perform_handshake():
                logging.error("Handshake failed")
                return False
            return True
        except Exception as e:
            logging.error(f"Connection error: {e}")
            return False
    
    def authenticate(self, username, password):
        """Аутентифицирует пользователя на сервере"""
        try:
            # Получаем запрос на аутентификацию
            auth_req = self.sock.recv(1024)
            if auth_req != b'AUTH_REQUIRED':
                logging.error("Invalid server response to authentication")
                return False
            
            # Вычисляем хеш пароля
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Отправляем учетные данные
            auth_msg = f"AUTH {username} {password_hash}"
            self.sock.send(auth_msg.encode())
            
            # Получаем ответ
            auth_response = self.sock.recv(1024).decode()
            
            if auth_response.startswith('AUTH_OK'):
                # Parse JWT token
                parts = auth_response.split()
                if len(parts) >= 2:
                    self.jwt_token = parts[1]
                self.authenticated = True
                self.username = username
                
                # Receive UDP data port (plain text - before JSON encryption)
                udp_port_msg = self.sock.recv(1024).decode().strip()
                if udp_port_msg.startswith('UDP_PORT'):
                    self.udp_data_port = int(udp_port_msg.split()[1])
                    # Initialize UDP socket
                    self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self.udp_sock.bind(('0.0.0.0', 0))
                    self.client_udp_port = self.udp_sock.getsockname()[1]
                    logging.info(f"UDP data port: {self.udp_data_port}")
                else:
                    logging.error("Did not receive UDP port")
                    return False
                
                logging.info(f"Authentication successful: {username}")
                return True
            else:
                logging.error(f"Authentication error: {auth_response}")
                return False
                
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            return False

    def perform_handshake(self):
        """3-step X25519 Diffie-Hellman handshake to derive AES key"""
        try:
            client_private = X25519PrivateKey.generate()
            client_public_bytes = client_private.public_key().public_bytes(
                encoding=Encoding.Raw,
                format=PublicFormat.Raw
            )
            client_pub_b64 = base64.b64encode(client_public_bytes).decode()
            self.sock.send(f"KEYEX {client_pub_b64}".encode())

            server_response = self.sock.recv(2048).decode().strip()
            if not server_response.startswith("KEYRESP"):
                logging.error(f"Unexpected handshake response: {server_response}")
                return False

            parts = server_response.split()
            if len(parts) != 3:
                logging.error("Malformed KEYRESP")
                return False

            _, server_pub_b64, session_id_hex = parts
            server_pub_bytes = base64.b64decode(server_pub_b64)
            server_public = X25519PublicKey.from_public_bytes(server_pub_bytes)
            shared_secret = client_private.exchange(server_public)

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"lftp-x25519-handshake",
            )
            self.session_key = hkdf.derive(shared_secret)
            self.aesgcm = AESGCM(self.session_key)
            self.session_id = bytes.fromhex(session_id_hex)
            self.nonce_counter = 0
            self.sock.send(b"KEY_OK")
            logging.info("Handshake complete, AES key derived")
            return True
        except Exception as e:
            logging.error(f"Handshake error: {e}")
            return False

    def _next_nonce(self):
        """Returns unique 12-byte nonce for AES-GCM"""
        nonce = self.nonce_prefix + self.nonce_counter.to_bytes(8, 'big')
        self.nonce_counter += 1
        return nonce

    def _encrypt_chunk(self, chunk: bytes) -> bytes:
        """Encrypts chunk with session AES key, prepending session id and nonce"""
        if not self.aesgcm or not self.session_id:
            raise RuntimeError("Handshake not completed")
        nonce = self._next_nonce()
        ciphertext = self.aesgcm.encrypt(nonce, chunk, None)
        return self.session_id + nonce + ciphertext

    def _decrypt_packet(self, packet: bytes) -> bytes:
        """Decrypts UDP packet that has session id + nonce + ciphertext"""
        if not self.aesgcm or not self.session_id:
            raise RuntimeError("Handshake not completed")
        if len(packet) < 4 + 12:
            raise ValueError("Packet too short for nonce")
        pkt_session = packet[:4]
        if pkt_session != self.session_id:
            raise ValueError("Session mismatch")
        nonce = packet[4:16]
        ciphertext = packet[16:]
        return self.aesgcm.decrypt(nonce, ciphertext, None)
    
    def _encrypt_command(self, command: str) -> str:
        """Deprecated - tất cả lệnh giờ được gửi dưới dạng JSON mã hóa"""
        return None
    
    def _recv_json_response(self):
        """Nhận và giải mã response JSON từ server"""
        try:
            # Nhận dữ liệu base64
            encrypted_data_b64 = self.sock.recv(4096).decode().strip()
            if not encrypted_data_b64:
                return None
            
            # Decode từ base64
            encrypted_data = base64.b64decode(encrypted_data_b64)
            
            # Kiểm tra có dùng AES-GCM hay base64 thôi
            if self.aesgcm and self.session_id:
                # Giải mã AES-GCM
                if len(encrypted_data) < 4 + 12:
                    logging.error("Encrypted data too short")
                    return None
                
                pkt_session = encrypted_data[:4]
                if pkt_session != self.session_id:
                    logging.error("Session mismatch in decryption")
                    return None
                
                # Lấy nonce và ciphertext
                nonce = encrypted_data[4:16]
                ciphertext = encrypted_data[16:]
                
                try:
                    json_str = self.aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                except Exception as e:
                    logging.error(f"Decryption error: {e}")
                    return None
            else:
                # Base64 thôi (chưa có session key)
                json_str = encrypted_data.decode('utf-8')
            
            # Parse JSON
            response_data = json.loads(json_str)
            return response_data
        except Exception as e:
            logging.error(f"Error receiving JSON response: {e}")
            return None
    
    def _log_command_to_json(self, command: str, encrypted_command: str, status: str = 'sent'):
        """Ghi lệnh vào file JSON"""
        try:
            # Tải log hiện tại
            if os.path.exists(self.commands_log_file):
                with open(self.commands_log_file, 'r', encoding='utf-8') as f:
                    try:
                        self.commands_log = json.load(f)
                    except:
                        self.commands_log = []
            
            # Thêm entry mới
            log_entry = {
                'timestamp': datetime.datetime.now().isoformat(),
                'username': self.username,
                'original_command': command,
                'encrypted_command': encrypted_command,
                'status': status,
                'server': f"{self.server_ip}:{self.server_port}"
            }
            self.commands_log.append(log_entry)
            
            # Lưu vào file
            with open(self.commands_log_file, 'w', encoding='utf-8') as f:
                json.dump(self.commands_log, f, indent=2, ensure_ascii=False)
            
            logging.info(f"Command logged to {self.commands_log_file}")
        except Exception as e:
            logging.error(f"Error logging command: {e}")
    
    def _send_json_command(self, command: str, **kwargs):
        """Gửi lệnh dưới dạng JSON mã hóa với AES-GCM"""
        if not self.authenticated or not self.jwt_token:
            return False, "Not authenticated"
        
        try:
            # Tạo JSON packet
            json_packet = {
                'token': self.jwt_token,
                'command': command,
                'timestamp': datetime.datetime.now().isoformat(),
                'username': self.username
            }
            # Thêm các tham số phụ (nếu có)
            json_packet.update(kwargs)
            
            # Chuyển sang JSON string
            json_str = json.dumps(json_packet)
            
            # Mã hóa JSON với AES-GCM
            if self.aesgcm and self.session_id:
                nonce = self._next_nonce()
                ciphertext = self.aesgcm.encrypt(nonce, json_str.encode(), None)
                encrypted_data = self.session_id + nonce + ciphertext
                encrypted_b64 = base64.b64encode(encrypted_data).decode()
            else:
                # Nếu chưa có session key, dùng base64
                encrypted_b64 = base64.b64encode(json_str.encode()).decode()
            
            # Gửi dữ liệu mã hóa
            self.sock.send(encrypted_b64.encode())
            
            # Ghi vào log
            self._log_command_to_json(command, encrypted_b64, 'sent')
            
            logging.info(f"Encrypted JSON command sent: {command}")
            return True, None
        except Exception as e:
            logging.error(f"Error sending JSON command: {e}")
            self._log_command_to_json(command, "", 'failed')
            return False, str(e)
        
    # def send_large_file(self, file_path, progress_callback=None):
    #     """
    #     Оптимизированная передача больших файлов с потоковым хешированием
    #     """
    #     if not self.authenticated:
    #         return False, "Authentication required"
        
    #     if not os.path.exists(file_path):
    #         return False, "File does not exist"
        
    #     try:
    #         file_size = os.path.getsize(file_path)
    #         filename = os.path.basename(file_path)
            
    #         logging.info(f"Preparing to send large file: {filename} ({file_size:,} bytes)")
            
    #         # Шаг 1: Отправляем команду начала потоковой передачи
    #         file_cmd = f"STREAM_FILE {filename} {file_size}"
    #         success, error = self._send_json_command(file_cmd)
    #         if not success:
    #             return False, error
            
    #         # Ждем подтверждения (с таймаутом)
    #         self.sock.settimeout(10.0)
    #         ready_response = self._recv_json_response()
    #         self.sock.settimeout(None)
            
    #         if not ready_response or ready_response.get('command') != 'READY_STREAM':
    #             return False, f"Server not ready for streaming: {ready_response}"
            
    #         # Шаг 2: Потоковая передача с прогрессивным хешированием
    #         bytes_sent = 0
    #         start_time = time.time()
    #         last_update = start_time
            
    #         # Инициализируем хеш
    #         file_hash = hashlib.sha256()
            
    #         # Вычисляем динамический таймаут на основе размера файла
    #         # Минимальная скорость: 100 KB/s (очень медленное соединение)
    #         # Добавляем 50% запас + минимум 60 секунд
    #         min_speed_kbps = 100  # 100 KB/s минимум
    #         estimated_time = (file_size / 1024) / min_speed_kbps  # секунды
    #         dynamic_timeout = max(estimated_time * 1.5, 60)  # минимум 60 секунд, +50% запас
            
    #         # Для очень больших файлов ограничиваем таймаут максимум 2 часа
    #         dynamic_timeout = min(dynamic_timeout, 7200)  # 2 часа максимум
            
    #         logging.info(f"Using dynamic timeout: {dynamic_timeout:.0f} seconds for {file_size / (1024*1024*1024):.2f} GB file")
            
    #         # Для sendall операций отключаем таймаут - они должны блокироваться до завершения
    #         # Таймаут нужен только для recv операций
    #         self.sock.settimeout(None)  # No timeout for sendall - let it block until sent
            
    #         try:
    #             with open(file_path, 'rb') as f:
    #                 while True:
    #                     # Читаем большими чанками (1MB оптимально для больших файлов)
    #                     chunk = f.read(1024 * 1024)  # 1MB
    #                     if not chunk:
    #                         break
                        
    #                     chunk_size = len(chunk)
                        
    #                     # Обновляем хеш
    #                     file_hash.update(chunk)
                        
    #                     # Отправляем размер чанка (4 байта) + данные
    #                     header = chunk_size.to_bytes(4, 'big')
                        
    #                     # Отправляем все сразу (sendall блокируется до полной отправки)
    #                     try:
    #                         self.sock.sendall(header + chunk)
    #                     except (BrokenPipeError, ConnectionResetError, OSError) as e:
    #                         logging.error(f"Connection error during send: {e}")
    #                         raise
                        
    #                     bytes_sent += chunk_size
                        
    #                     # Обновляем прогресс (не слишком часто, чтобы не замедлять)
    #                     current_time = time.time()
    #                     if current_time - last_update > 1.0:  # Каждую секунду
    #                         if progress_callback:
    #                             progress = (bytes_sent / file_size) * 100
    #                             progress_callback(progress, bytes_sent, file_size)
                            
    #                         # Логируем прогресс
    #                         elapsed = current_time - start_time
    #                         if elapsed > 0:
    #                             speed = bytes_sent / elapsed / (1024 * 1024)  # MB/s
    #                             mb_sent = bytes_sent / (1024 * 1024)
    #                             mb_total = file_size / (1024 * 1024)
    #                             progress = (bytes_sent / file_size) * 100
                                
    #                             logging.info(f"Progress: {mb_sent:.1f}/{mb_total:.1f} MB ({progress:.1f}%) - {speed:.2f} MB/s")
    #                         last_update = current_time
                            
    #         finally:
    #             # Восстанавливаем таймаут для recv операций
    #             self.sock.settimeout(dynamic_timeout)
            
    #         # Шаг 3: Отправляем финальный хеш
    #         final_hash = file_hash.hexdigest()
    #         hash_cmd = f"FILE_HASH {final_hash}"
            
    #         # Устанавливаем таймаут для отправки хеша (небольшая операция)
    #         self.sock.settimeout(10.0)
    #         try:
    #             self.sock.send(hash_cmd.encode())
    #         except socket.timeout:
    #             logging.error("Timeout sending hash - connection may be broken")
    #             raise
            
    #         # Шаг 4: Получаем результат с динамическим таймаутом
    #         self.sock.settimeout(dynamic_timeout)
    #         transfer_time = time.time() - start_time
            
    #         try:
    #             result_response = self._recv_json_response()
    #         except socket.timeout:
    #             # Если таймаут произошел при получении ответа, но файл отправлен
    #             if bytes_sent >= file_size:
    #                 logging.warning("Timeout waiting for server response, but file was fully sent")
    #                 return False, "File sent but timeout waiting for server confirmation"
    #             else:
    #                 return False, f"Transfer timeout after {transfer_time:.1f}s - {bytes_sent}/{file_size} bytes sent"
            
    #         if transfer_time > 0:
    #             speed = file_size / transfer_time / (1024 * 1024)  # MB/s
    #         else:
    #             speed = 0
            
    #         if result_response and result_response.get('command') == 'FILE_OK':
    #             return True, f"Large file transferred: {speed:.2f} MB/s, time: {transfer_time:.1f}s"
    #         elif result_response and result_response.get('command') == 'FILE_CORRUPTED':
    #             return False, f"Hash mismatch detected: {result_response}"
    #         else:
    #             return False, f"Transfer failed: {result_response}"
            
    #     except socket.timeout as e:
    #         transfer_time = time.time() - start_time if 'start_time' in locals() else 0
    #         bytes_transferred = bytes_sent if 'bytes_sent' in locals() else 0
    #         return False, f"Transfer timeout after {transfer_time:.1f}s - {bytes_transferred}/{file_size} bytes sent"
    #     except (BrokenPipeError, ConnectionResetError, OSError) as e:
    #         transfer_time = time.time() - start_time if 'start_time' in locals() else 0
    #         bytes_transferred = bytes_sent if 'bytes_sent' in locals() else 0
    #         logging.error(f"Connection error: {e}")
    #         return False, f"Connection broken after {transfer_time:.1f}s - {bytes_transferred}/{file_size} bytes sent"
    #     except Exception as e:
    #         logging.error(f"Large file transfer error: {e}")
    #         return False, str(e)

    def send_file(self, file_path, progress_callback=None):
        """
        Передача файлов по UDP с шифрованием AES-GCM
        """
        try:
            file_size = os.path.getsize(file_path)
        except:
            return False, "Cannot get file size"
        
        return self.send_small_file(file_path, progress_callback)

    def send_small_file(self, file_path, progress_callback=None):
        """
        Зашифрованная передача файла через UDP
        """
        if not self.authenticated:
            return False, "Authentication required"
        
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        try:
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)

            logging.info("Calculating file checksum...")
            checksum_start = time.time()
            file_checksum = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    file_checksum.update(chunk)
            checksum_time = time.time() - checksum_start
            checksum_hex = file_checksum.hexdigest()
            logging.info(f"Checksum calculated in {checksum_time:.2f}s: {checksum_hex[:16]}...")

            file_cmd = f"FILE {filename} {file_size} {checksum_hex}"
            success, error = self._send_json_command(file_cmd)
            if not success:
                return False, error

            # Nhận READY_UDP response (JSON mã hóa)
            response_data = self._recv_json_response()
            if not response_data or response_data.get('command') != 'READY_UDP':
                return False, f"Server not ready: {response_data}"

            logging.info(f"Starting encrypted UDP transfer {filename} ({file_size} bytes)")
            bytes_sent = 0
            transfer_start = time.time()
            self.sock.settimeout(15.0)

            with open(file_path, 'rb') as f:
                while bytes_sent < file_size:
                    # UDP must stay small to avoid fragmentation / WinError 10040
                    chunk = f.read(UDP_PLAINTEXT_CHUNK_SIZE)
                    if not chunk:
                        break

                    packet = self._encrypt_chunk(chunk)
                    self.udp_sock.sendto(packet, (self.server_ip, self.udp_data_port))
                    bytes_sent += len(chunk)

                    try:
                        # Nhận ACK response (JSON mã hóa)
                        ack_response = self._recv_json_response()
                        if ack_response and ack_response.get('command') == 'ACK':
                            pass
                    except socket.timeout:
                        pass

                    if progress_callback:
                        progress = (bytes_sent / file_size) * 100
                        progress_callback(progress, bytes_sent, file_size)

            transfer_time = time.time() - transfer_start
            if transfer_time > 0.001:
                speed = file_size / transfer_time / 1024
                speed_text = f"{speed:.2f} KB/s"
            else:
                speed_text = "very fast"

            logging.info(f"Transfer completed in {transfer_time:.3f} sec ({speed_text}) - Checksum: {checksum_time:.2f}s")

            # Nhận FILE_OK response (JSON mã hóa)
            result_response = self._recv_json_response()

            if result_response and result_response.get('command') == 'FILE_OK':
                return True, f"File transferred successfully ({speed_text})"
            else:
                return False, f"Integrity error: {result_response}"
            
        except Exception as e:
            logging.error(f"File transfer error: {e}")
            return False, str(e)
        
    def send_folder(self, folder_path, progress_callback=None):
        """
        Sends entire folder with structure using JSON commands
        """
        if not os.path.isdir(folder_path):
            return False, "Not a directory"
        
        if not self.authenticated:
            return False, "Authentication required"
        
        try:
            folder_name = os.path.basename(folder_path.rstrip('/\\'))
            
            # Get all files recursively
            all_files = []
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    full_path = os.path.join(root, file)    
                    # Get relative path from the main folder
                    rel_path = os.path.relpath(full_path, folder_path)
                    all_files.append((full_path, rel_path))
            
            if not all_files:
                return False, "Folder is empty"
            
            logging.info(f"Preparing to send folder '{folder_name}' with {len(all_files)} files")
            
            # First, send FOLDER_START command via JSON
            folder_cmd = f"FOLDER_START {folder_name} {len(all_files)}"
            self._send_json_command(folder_cmd)
            
            # Wait for server acknowledgement (JSON response)
            response_data = self._recv_json_response()
            if not response_data or response_data.get('command') != 'FOLDER_READY':
                return False, f"Server not ready for folder: {response_data}"
            
            # Send each file
            files_sent = 0
            total_size = 0
            
            for full_path, rel_path in all_files:
                try:
                    # Send file with its relative path
                    success, message = self._send_single_file(full_path, rel_path, progress_callback)
                    if not success:
                        return False, f"Failed to send {rel_path}: {message}"
                    
                    files_sent += 1
                    file_size = os.path.getsize(full_path)
                    total_size += file_size
                    logging.info(f"Sent {rel_path} ({files_sent}/{len(all_files)})")
                    
                except Exception as e:
                    return False, f"Error sending {rel_path}: {e}"
            
            # Send folder completion via JSON
            folder_end_cmd = f"FOLDER_END {folder_name} {files_sent}"
            self._send_json_command(folder_end_cmd)
            
            # Get final confirmation (JSON response)
            final_response = self._recv_json_response()
            if final_response and final_response.get('command') == 'FOLDER_COMPLETE':
                return True, f"Folder '{folder_name}' sent: {files_sent} files, {total_size} bytes"
            else:
                return False, f"Folder transfer incomplete: {final_response}"
            
        except Exception as e:
            logging.error(f"Folder transfer error: {e}")
            return False, str(e)

    def _send_single_file(self, file_path, rel_path, progress_callback=None):
        """Helper to send a single file with custom filename using JSON"""
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        try:
            # Get file info
            file_size = os.path.getsize(file_path)
            
            # Calculate checksum
            file_checksum = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    file_checksum.update(chunk)
            checksum_hex = file_checksum.hexdigest()
            
            # Send file metadata with RELATIVE path (not JSON, plain text for server parsing)
            rel_file_cmd = f"REL_FILE {rel_path} {file_size} {checksum_hex}"
            
            # Create JSON packet for REL_FILE command
            json_packet = {
                'token': self.jwt_token,
                'command': rel_file_cmd,
                'timestamp': datetime.datetime.now().isoformat(),
                'username': self.username
            }
            json_str = json.dumps(json_packet)
            
            # Encrypt and send
            if self.aesgcm and self.session_id:
                nonce = self._next_nonce()
                ciphertext = self.aesgcm.encrypt(nonce, json_str.encode(), None)
                encrypted_data = self.session_id + nonce + ciphertext
                encrypted_b64 = base64.b64encode(encrypted_data).decode()
            else:
                encrypted_b64 = base64.b64encode(json_str.encode()).decode()
            
            self.sock.send(encrypted_b64.encode())
            
            # Wait for READY response (JSON)
            response_data = self._recv_json_response()
            if not response_data or response_data.get('command') != 'READY':
                return False, f"Server not ready: {response_data}"
            
            # Send file content
            bytes_sent = 0
            with open(file_path, 'rb') as f:
                while bytes_sent < file_size:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    self.sock.sendall(chunk)
                    bytes_sent += len(chunk)
                    
                    # Update progress if callback provided
                    if progress_callback:
                        # For folder transfer, we can't easily show total progress
                        # So just show file progress
                        progress = (bytes_sent / file_size) * 100
                        progress_callback(progress, bytes_sent, file_size)
            
            # Get transfer result (JSON response)
            result_response = self._recv_json_response()
            if result_response and result_response.get('command') == 'FILE_OK':
                return True, "File sent successfully"
            else:
                return False, f"Transfer failed: {result_response}"
            
        except Exception as e:
            return False, str(e)
    
    def list_files(self):
        """Requests and receives list of files and folders from server"""
        if not self.authenticated:
            return False, "Authentication required", None
        
        try:
            # Send LIST_FILES command
            success, error = self._send_json_command('LIST_FILES')
            if not success:
                return False, error, None
            
            # Receive response (JSON-encrypted)
            response_data = self._recv_json_response()
            
            if not response_data:
                return False, "No response from server", None
            
            if response_data.get('command') == 'LIST_EMPTY':
                return True, "No files on server", {'files': [], 'folders': []}
            
            if response_data.get('command') == 'LIST_OK':
                files_list = response_data.get('data', {})
                return True, f"List received: {len(files_list.get('files', []))} files, {len(files_list.get('folders', []))} folders", files_list
            
            return False, f"Invalid response: {response_data}", None
            
        except Exception as e:
            logging.error(f"List files error: {e}")
            return False, str(e), None
    
    def download_file(self, filename, save_path=None, progress_callback=None):
        """Downloads a file from the server"""
        if not self.authenticated:
            return False, "Authentication required"
        
        try:
            # Send DOWNLOAD_FILE command
            download_cmd = f'DOWNLOAD_FILE {filename}'
            success, error = self._send_json_command(download_cmd)
            if not success:
                return False, error
            
            # Receive response (JSON-encrypted)
            response_data = self._recv_json_response()
            
            if not response_data:
                return False, "No response from server"
            
            if response_data.get('command') == 'FILE_NOT_FOUND':
                return False, f"File not found on server: {filename}"
            
            if response_data.get('command') == 'NOT_A_FILE':
                return False, f"Not a file: {filename}"
            
            if response_data.get('command') != 'FILE_INFO':
                return False, f"Invalid response: {response_data}"
            
            # Parse file info from JSON
            server_filename = response_data.get('filename', filename)
            file_size = response_data.get('size', 0)
            expected_checksum = response_data.get('checksum', '')
            
            # Determine save path
            if save_path is None:
                save_path = os.path.basename(server_filename)
            
            # Create directory if needed
            save_dir = os.path.dirname(save_path)
            if save_dir and not os.path.exists(save_dir):
                os.makedirs(save_dir, exist_ok=True)
            
            # Handle duplicate filenames
            counter = 1
            original_path = save_path
            name, ext = os.path.splitext(save_path)
            while os.path.exists(save_path):
                save_path = f"{name}_{counter}{ext}"
                counter += 1
            
            # Send READY
            ready_msg = f'READY_UDP {self.client_udp_port}'
            self.sock.send(ready_msg.encode())
            
            logging.info(f"Downloading (UDP/AES) {filename} ({file_size:,} bytes)...")
            bytes_received = 0
            file_hash = hashlib.sha256()
            start_time = time.time()
            self.udp_sock.settimeout(30.0)
            
            with open(save_path, 'wb') as f:
                while bytes_received < file_size:
                    try:
                        packet, addr = self.udp_sock.recvfrom(65536 + 64)
                        if addr[0] != self.server_ip:
                            continue
                        chunk = self._decrypt_packet(packet)
                        f.write(chunk)
                        file_hash.update(chunk)
                        bytes_received += len(chunk)
                        
                        if progress_callback:
                            progress = (bytes_received / file_size) * 100
                            progress_callback(progress, bytes_received, file_size)
                    except socket.timeout:
                        logging.error("UDP download timeout")
                        break
            
            actual_checksum = file_hash.hexdigest()
            
            if actual_checksum == expected_checksum and bytes_received == file_size:
                self.sock.send(b'FILE_RECEIVED')
                
                transfer_time = time.time() - start_time
                speed = file_size / transfer_time / (1024 * 1024) if transfer_time > 0 else 0
                
                return True, f"File downloaded: {save_path} ({speed:.2f} MB/s)"
            else:
                if os.path.exists(save_path):
                    os.remove(save_path)
                return False, f"Checksum mismatch or incomplete transfer. Expected: {expected_checksum[:16]}..., Got: {actual_checksum[:16]}..., bytes: {bytes_received}/{file_size}"
                
        except Exception as e:
            logging.error(f"Download file error: {e}")
            if 'save_path' in locals() and os.path.exists(save_path):
                os.remove(save_path)
            return False, str(e)
    
    def download_folder(self, folder_name, save_path=None, progress_callback=None):
        """Downloads a folder from the server"""
        if not self.authenticated:
            return False, "Authentication required"
        
        try:
            # Send DOWNLOAD_FOLDER command
            download_cmd = f'DOWNLOAD_FOLDER {folder_name}'
            success, error = self._send_json_command(download_cmd)
            if not success:
                return False, error
            
            # Receive response
            response = self.sock.recv(1024).decode().strip()
            
            if response == 'FOLDER_NOT_FOUND':
                return False, f"Folder not found on server: {folder_name}"
            
            if response == 'NOT_A_FOLDER':
                return False, f"Not a folder: {folder_name}"
            
            if response == 'FOLDER_EMPTY':
                return False, "Folder is empty"
            
            if not response.startswith('FOLDER_INFO'):
                return False, f"Invalid response: {response}"
            
            # Parse folder info: FOLDER_INFO <folder_name> <file_count>
            parts = response.split()
            if len(parts) != 3:
                return False, "Invalid FOLDER_INFO format"
            
            _, server_folder_name, file_count_str = parts
            file_count = int(file_count_str)
            
            # Determine save path
            if save_path is None:
                save_path = server_folder_name
            
            # Handle duplicate folder names
            counter = 1
            original_path = save_path
            while os.path.exists(save_path):
                save_path = f"{original_path}_{counter}"
                counter += 1
            
            # Create folder
            os.makedirs(save_path, exist_ok=True)
            
            # Send READY
            self.sock.send(b'FOLDER_READY')
            
            # Receive each file
            files_received = 0
            total_size = 0
            start_time = time.time()
            
            for i in range(file_count):
                # Receive file info
                file_info = self.sock.recv(1024).decode().strip()
                
                if not file_info.startswith('REL_FILE_INFO'):
                    return False, f"Invalid file info: {file_info}"
                
                # Parse: REL_FILE_INFO <relative_path> <size> <checksum>
                info_parts = file_info.split()
                if len(info_parts) != 4:
                    return False, "Invalid REL_FILE_INFO format"
                
                _, rel_path, file_size_str, expected_checksum = info_parts
                file_size = int(file_size_str)
                
                # Create full path
                full_path = os.path.join(save_path, rel_path)
                file_dir = os.path.dirname(full_path)
                if file_dir:
                    os.makedirs(file_dir, exist_ok=True)
                
                # Send READY
                self.sock.send(b'READY')
                
                # Receive file data
                bytes_received = 0
                file_hash = hashlib.sha256()
                
                with open(full_path, 'wb') as f:
                    while bytes_received < file_size:
                        remaining = file_size - bytes_received
                        chunk = self.sock.recv(min(65536, remaining))
                        if not chunk:
                            break
                        
                        f.write(chunk)
                        file_hash.update(chunk)
                        bytes_received += len(chunk)
                        
                        # Update progress
                        if progress_callback:
                            # For folder, show file progress
                            file_progress = (bytes_received / file_size) * 100
                            overall_progress = ((i + bytes_received / file_size) / file_count) * 100
                            progress_callback(overall_progress, bytes_received, file_size)
                
                # Verify checksum
                actual_checksum = file_hash.hexdigest()
                
                if actual_checksum == expected_checksum:
                    self.sock.send(b'FILE_RECEIVED')
                    files_received += 1
                    total_size += file_size
                    logging.info(f"Received file {files_received}/{file_count}: {rel_path}")
                else:
                    os.remove(full_path)
                    return False, f"Checksum mismatch for {rel_path}"
            
            # Receive folder completion
            folder_complete = self.sock.recv(1024).decode().strip()
            
            # Send final confirmation
            self.sock.send(b'FOLDER_RECEIVED')
            
            transfer_time = time.time() - start_time
            speed = total_size / transfer_time / (1024 * 1024) if transfer_time > 0 else 0
            
            return True, f"Folder downloaded: {save_path} ({files_received} files, {speed:.2f} MB/s)"
            
        except Exception as e:
            logging.error(f"Download folder error: {e}")
            if 'save_path' in locals() and os.path.exists(save_path):
                import shutil
                shutil.rmtree(save_path)
            return False, str(e)
    
    def delete_file(self, filename):
        """Deletes a file from the server"""
        if not self.authenticated:
            return False, "Authentication required"
        
        try:
            # Send DELETE_FILE command
            delete_cmd = f'DELETE_FILE {filename}'
            success, error = self._send_json_command(delete_cmd)
            if not success:
                return False, error
            
            # Receive response (JSON-encrypted)
            response_data = self._recv_json_response()
            
            if not response_data:
                return False, "No response from server"
            
            if response_data.get('command') == 'DELETE_OK':
                return True, response_data.get('message', 'File deleted')
            elif response_data.get('command') == 'DELETE_FAIL':
                return False, response_data.get('message', 'Deletion failed')
            elif response_data.get('status') == 'error':
                return False, response_data.get('message', 'Error')
            else:
                return False, f"Unexpected response: {response_data}"
                
        except Exception as e:
            logging.error(f"Delete file error: {e}")
            return False, str(e)
    
    def delete_folder(self, folder_name):
        """Deletes a folder from the server"""
        if not self.authenticated:
            return False, "Authentication required"
        
        try:
            # Send DELETE_FOLDER command
            delete_cmd = f'DELETE_FOLDER {folder_name}'
            success, error = self._send_json_command(delete_cmd)
            if not success:
                return False, error
            
            # Receive response (JSON-encrypted)
            response_data = self._recv_json_response()
            
            if not response_data:
                return False, "No response from server"
            
            if response_data.get('command') == 'DELETE_OK':
                return True, response_data.get('message', 'Folder deleted')
            elif response_data.get('command') == 'DELETE_FAIL':
                return False, response_data.get('message', 'Deletion failed')
            elif response_data.get('status') == 'error':
                return False, response_data.get('message', 'Error')
            else:
                return False, f"Unexpected response: {response_data}"
                
        except Exception as e:
            logging.error(f"Delete folder error: {e}")
            return False, str(e)
    
    def rename_file(self, old_name, new_name):
        """Renames a file on the server"""
        if not self.authenticated:
            return False, "Authentication required"
        
        try:
            # Send RENAME_FILE command
            rename_cmd = f'RENAME_FILE {old_name} {new_name}'
            success, error = self._send_json_command(rename_cmd)
            if not success:
                return False, error
            
            # Receive response (JSON-encrypted)
            response_data = self._recv_json_response()
            
            if not response_data:
                return False, "No response from server"
            
            if response_data.get('command') == 'RENAME_OK':
                return True, response_data.get('message', 'File renamed')
            elif response_data.get('command') == 'RENAME_FAIL':
                return False, response_data.get('message', 'Rename failed')
            elif response_data.get('status') == 'error':
                return False, response_data.get('message', 'Error')
            else:
                return False, f"Unexpected response: {response_data}"
                
        except Exception as e:
            logging.error(f"Rename file error: {e}")
            return False, str(e)
    
    def rename_folder(self, old_name, new_name):
        """Renames a folder on the server"""
        if not self.authenticated:
            return False, "Authentication required"
        
        try:
            # Send RENAME_FOLDER command
            rename_cmd = f'RENAME_FOLDER {old_name} {new_name}'
            success, error = self._send_json_command(rename_cmd)
            if not success:
                return False, error
            
            # Receive response (JSON-encrypted)
            response_data = self._recv_json_response()
            
            if not response_data:
                return False, "No response from server"
            
            if response_data.get('command') == 'RENAME_OK':
                return True, response_data.get('message', 'Folder renamed')
            elif response_data.get('command') == 'RENAME_FAIL':
                return False, response_data.get('message', 'Rename failed')
            elif response_data.get('status') == 'error':
                return False, response_data.get('message', 'Error')
            else:
                return False, f"Unexpected response: {response_data}"
                
        except Exception as e:
            logging.error(f"Rename folder error: {e}")
            return False, str(e)
    
    def disconnect(self):
        """Закрывает соединение"""
        if self.sock:
            try:
                self.sock.send(b'QUIT')
                self.sock.close()
            except:
                pass
            finally:
                self.sock = None
                self.authenticated = False
                self.username = None
                self.jwt_token = None
        logging.info("Connection closed")
    
if __name__ == "__main__":
    # Тестирование клиента
    import sys
    
    if len(sys.argv) < 5:
        print("Usage: python tcp_client.py <server_ip> <username> <password> <file_path>")
        sys.exit(1)
    
    server_ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    file_path = sys.argv[4]
    
    client = TCPClient(server_ip)
    
    if client.connect():
        if client.authenticate(username, password):
            success, message = client.send_file(file_path)
            print(f"Result: {message}")
        else:
            print("Authentication error")
    else:
        print("Connection error")
    
    client.disconnect()
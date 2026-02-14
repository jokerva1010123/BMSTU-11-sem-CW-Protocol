#!/usr/bin/env python3
import socket
import threading
import json
import hashlib
import os
import logging
import time
import shutil
import datetime
import zipfile
import tempfile
from config import TCP_PORT, UDP_DATA_PORT, UPLOAD_DIR
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
        try:
            with open('user_db.json', 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error loading users: {e}")
            return {}
    
    def verify_jwt(self, token):
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            return payload
        except jwt.ExpiredSignatureError:
            return None  # Token expired
        except jwt.InvalidTokenError:
            return None  # Invalid token
    
    def _send_json_response(self, conn, response_data: dict, session_info) -> bool:
        try:
            json_str = json.dumps(response_data)
            
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
                encrypted_b64 = base64.b64encode(json_str.encode()).decode()
            
            conn.send(encrypted_b64.encode())
            return True
        except Exception as e:
            logging.error(f"Error sending JSON response: {e}")
            return False
        
    def _recv_json_response(self, conn, session_info):
        try:
            encrypted_data_b64 = conn.recv(4096).decode().strip()
            if not encrypted_data_b64:
                return None
            
            encrypted_data = base64.b64decode(encrypted_data_b64)
            
            if session_info and 'aesgcm' in session_info:
                session_id = session_info['session_id']
                aesgcm = session_info['aesgcm']
                
                if len(encrypted_data) < 4 + 12:
                    logging.error("Encrypted data too short")
                    return None
                
                pkt_session = encrypted_data[:4]
                if pkt_session != session_id:
                    logging.error("Session mismatch in decryption")
                    return None
            
                nonce = encrypted_data[4:16]
                ciphertext = encrypted_data[16:]
                
                try:
                    json_str = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                except Exception as e:
                    logging.error(f"Decryption error: {e}")
                    return None
            else:
                json_str = encrypted_data.decode('utf-8')
            
            response_data = json.loads(json_str)
            return response_data
        except Exception as e:
            logging.error(f"Error receiving JSON response from client: {e}")
            return None
    
    def authenticate(self, conn, addr):
        """Выполняет аутентификацию клиента"""
        try:
            conn.send(b'AUTH_REQUIRED')
            
            auth_data = conn.recv(1024).decode().strip()
            if not auth_data:
                return False, "Empty data"
            
            parts = auth_data.split()
            if len(parts) != 3 or parts[0] != 'AUTH':
                return False, "Invalid format"
            
            username, password_hash = parts[1], parts[2]
            
            if username in self.users:
                stored_hash = self.users[username]
                if stored_hash == password_hash:
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
        """3-step X25519 handshake"""
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
    
    def handle_folder_zip(self, conn, client_ip, folder_name, size, checksum, session_info):
        try:
            success, message = self.receive_file(conn, client_ip, f"{folder_name}.zip", size, checksum, session_info)
            if not success:
                return False, message
            
            zip_path = os.path.join(UPLOAD_DIR, f"{folder_name}.zip")
            
            base_folder = folder_name
            counter = 1
            extract_path = os.path.join(UPLOAD_DIR, folder_name)
            while os.path.exists(extract_path):
                folder_name = f"{base_folder}_{counter}"
                extract_path = os.path.join(UPLOAD_DIR, folder_name)
                counter += 1
            
            os.makedirs(extract_path, exist_ok=True)
            
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                zipf.extractall(extract_path)
            
            os.remove(zip_path)
            logging.info(f"Folder {folder_name} unzipped successfully")
            return True, f"Folder received and unzipped: {folder_name}"
        except Exception as e:
            logging.error(f"Folder zip handle error: {e}")
            if os.path.exists(zip_path):
                os.remove(zip_path)
            if os.path.exists(extract_path):
                shutil.rmtree(extract_path)
            return False, str(e)
        
    def receive_file(self, conn, client_ip, filename, expected_size, expected_checksum, session_info):
        try:
            file_path = os.path.join(UPLOAD_DIR, filename)
            counter = 1
            name, ext = os.path.splitext(filename)
            while os.path.exists(file_path):
                filename = f"{name}_{counter}{ext}"
                file_path = os.path.join(UPLOAD_DIR, filename)
                counter += 1

            response = {"status": "ok", "command": "READY_UDP"}
            self._send_json_response(conn, response, session_info)

            logging.info(f"Receiving reliable UDP file: {filename} ({expected_size} bytes)")

            expected_seq = 0
            received_chunks = {}          
            max_received = -1
            bytes_received = 0
            f = open(file_path, 'wb')     

            self.udp_socket.settimeout(40.0)

            while bytes_received < int(expected_size):
                try:
                    packet, addr = self.udp_socket.recvfrom(UDP_PLAINTEXT_CHUNK_SIZE + 64)
                    if addr[0] != client_ip:
                        continue
                    if not packet.startswith(session_info['session_id']):
                        continue

                    seq_bytes = packet[4:8]
                    seq = int.from_bytes(seq_bytes, 'big')

                    if seq == 0xFFFFFFFF:
                        logging.info("Received END marker")
                        break

                    nonce = packet[8:20]
                    ciphertext = packet[20:]

                    try:
                        chunk = session_info['aesgcm'].decrypt(nonce, ciphertext, None)
                    except Exception as e:
                        logging.warning(f"Decrypt error seq {seq}: {e}")
                        continue

                    if seq not in received_chunks:
                        received_chunks[seq] = chunk
                        max_received = max(max_received, seq)
                        bytes_received += len(chunk)

                    while expected_seq in received_chunks:
                        chunk_data = received_chunks.pop(expected_seq)
                        f.write(chunk_data)
                        expected_seq += 1

                    ack_msg = f"ACK {expected_seq - 1}".encode()
                    self.udp_socket.sendto(ack_msg, (client_ip, addr[1])) 

                except socket.timeout:
                    if expected_seq > 0:
                        ack_msg = f"ACK {expected_seq - 1}".encode()
                        self.udp_socket.sendto(ack_msg, (client_ip, self.udp_data_port))

            f.close()

            # Проверка
            if expected_seq * UDP_PLAINTEXT_CHUNK_SIZE >= int(expected_size) or bytes_received >= int(expected_size):
                actual_checksum = hashlib.sha256()
                with open(file_path, 'rb') as f_check:
                    while chunk := f_check.read(8192):
                        actual_checksum.update(chunk)
                actual_hex = actual_checksum.hexdigest()

                if actual_hex == expected_checksum:
                    ok_response = {"status": "ok", "command": "FILE_OK", "checksum": actual_hex}
                    self._send_json_response(conn, ok_response, session_info)
                    return True, "File received reliably"
                else:
                    logging.error(f"Checksum mismatch after reliable transfer")
                    corrupted_response = {"status": "error", "command": "FILE_CORRUPTED"}
                    self._send_json_response(conn, corrupted_response, session_info)
                    return False, "Checksum mismatch"
            else:
                incomplete_response = {"status": "error", "command": "FILE_INCOMPLETE", "received": bytes_received}
                self._send_json_response(conn, incomplete_response, session_info)
                return False, f"Incomplete: {bytes_received}/{expected_size}"
        except Exception as e:
            logging.error(f"Reliable receive error: {e}")
            if 'f' in locals():
                f.close()
            if os.path.exists(file_path):
                os.remove(file_path)
            return False, str(e)
        
    def send_file_to_client(self, conn, filename, session_info, client_ip):
        try:
            file_path = os.path.join(UPLOAD_DIR, filename)
            if not os.path.exists(file_path):
                return False, f"File not found: {filename}"
            if not os.path.isfile(file_path):
                return False, f"Not a file: {filename}"
            
            file_size = os.path.getsize(file_path)
            
            file_checksum = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    file_checksum.update(chunk)
            checksum_hex = file_checksum.hexdigest()
            
            ready_response = {
                "status": "ok",
                "command": "DOWNLOAD_READY",
                "filename": filename,
                "size": file_size,
                "checksum": checksum_hex
            }
            self._send_json_response(conn, ready_response, session_info)
            
            try:
                udp_port_msg = conn.recv(1024).decode().strip()
                if udp_port_msg.startswith('UDP_PORT'):
                    client_udp_port = int(udp_port_msg.split()[1])
                    client_addr = (client_ip, client_udp_port)
                    logging.info(f"Client UDP port for file download: {client_udp_port}")
                else:
                    return False, "Client did not send UDP_PORT"
            except Exception as e:
                logging.error(f"Failed to receive client UDP port: {e}")
                return False, "Failed to get client UDP port"
            
            logging.info(f"Sending file to {client_ip}:{client_udp_port} - {filename} ({file_size} bytes)")
            
            WINDOW_SIZE = 64
            RETRANSMIT_TIMEOUT = 0.5
            MAX_RETRIES_PER_PACKET = 5
            
            with open(file_path, 'rb') as f:
                base = 0
                next_seq = 0
                packets_in_flight = {}
                done = False
                transfer_start = time.time()
                
                def next_nonce():
                    if 'download_nonce_counter' not in session_info:
                        session_info['download_nonce_prefix'] = os.urandom(4)
                        session_info['download_nonce_counter'] = 0
                    prefix = session_info['download_nonce_prefix']
                    cnt = session_info['download_nonce_counter']
                    nonce = prefix + cnt.to_bytes(8, 'big')
                    session_info['download_nonce_counter'] += 1
                    return nonce
                
                def send_packet(seq, data: bytes):
                    nonce = next_nonce()
                    ciphertext = session_info['aesgcm'].encrypt(nonce, data, None)
                    header = session_info['session_id'] + seq.to_bytes(4, 'big')
                    packet = header + nonce + ciphertext
                    self.udp_socket.sendto(packet, client_addr)
                    return time.time()
                
                def retransmit_loop():
                    nonlocal done
                    while not done:
                        time.sleep(0.1)
                        now = time.time()
                        with lock:
                            for seq in list(packets_in_flight.keys()):
                                if seq < base:
                                    continue
                                info = packets_in_flight[seq]
                                if now - info['sent_time'] > RETRANSMIT_TIMEOUT:
                                    if info['retries'] >= MAX_RETRIES_PER_PACKET:
                                        logging.error(f"Max retries exceeded for seq {seq} → aborting")
                                        done = True
                                        return
                                    # Re-send
                                    send_packet(seq, info['data'])
                                    info['sent_time'] = now
                                    info['retries'] += 1
                                    logging.debug(f"Retransmitted seq {seq} (retry {info['retries']})")
                
                lock = threading.Lock()
                retransmit_thread = threading.Thread(target=retransmit_loop, daemon=True)
                retransmit_thread.start()
                
                bytes_sent = 0
                
                while not done:
                    with lock:
                        while next_seq < base + WINDOW_SIZE:
                            chunk = f.read(UDP_PLAINTEXT_CHUNK_SIZE)
                            if not chunk:
                                break
                            sent_time = send_packet(next_seq, chunk)
                            packets_in_flight[next_seq] = {
                                'data': chunk,
                                'sent_time': sent_time,
                                'retries': 0
                            }
                            next_seq += 1
                            bytes_sent += len(chunk)
                    
                    try:
                        self.udp_socket.settimeout(0.05)
                        ack_packet, addr = self.udp_socket.recvfrom(1024)
                        if addr[0] != client_ip:
                            continue
                        
                        ack_str = ack_packet.decode(errors='ignore').strip()
                        if ack_str.startswith('ACK '):
                            try:
                                ack_seq = int(ack_str.split()[1])
                                with lock:
                                    if ack_seq >= base - 1:
                                        base = ack_seq + 1
                                        for s in range(base):
                                            packets_in_flight.pop(s, None)
                            except (ValueError, IndexError):
                                logging.warning(f"Invalid ACK format: {ack_str}")
                    except socket.timeout:
                        pass
                    
                    if bytes_sent >= file_size and base >= next_seq:
                        done = True
                
                end_header = session_info['session_id'] + (0xFFFFFFFF).to_bytes(4, 'big')
                self.udp_socket.sendto(end_header + b'END', client_addr)
                
                retransmit_thread.join(timeout=3.0)
                done = True
                
                transfer_time = time.time() - transfer_start
                speed = file_size / transfer_time / 1024 / 1024 if transfer_time > 0 else 0  # MB/s
                
                complete_response = {
                    "status": "ok",
                    "command": "FILE_OK",
                    "message": f"File sent successfully ({speed:.2f} MB/s)"
                }
                self._send_json_response(conn, complete_response, session_info)
                return True, f"File sent: {filename} ({speed:.2f} MB/s)"
        except Exception as e:
            logging.error(f"send_file_to_client error: {e}", exc_info=True)
            error_response = {"status": "error", "message": str(e)}
            self._send_json_response(conn, error_response, session_info)
            return False, str(e)
    
    def handle_client(self, conn, addr):
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
            
            conn.send(f'UDP_PORT {UDP_DATA_PORT}'.encode())
            logging.info(f"Sent UDP data port {UDP_DATA_PORT} to {client_id}")
            
            while True:
                try:
                    encrypted_data_b64 = conn.recv(4096).decode().strip()
                    if not encrypted_data_b64:
                        break
                    
                    encrypted_data = base64.b64decode(encrypted_data_b64)
                    
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
                            logging.error(f"Decryption error: {e}")
                            error_response = {"status": "error", "message": "Decryption failed"}
                            self._send_json_response(conn, error_response, session_info)
                            continue
                    else:
                        json_str = encrypted_data.decode('utf-8')
                    
                    json_packet = json.loads(json_str)
                    
                    jwt_token = json_packet.get('token', '')
                    command = json_packet.get('command', '')
                    
                    token_payload = self.verify_jwt(jwt_token)
                    if not token_payload:
                        error_response = {"status": "error", "message": "Invalid or expired token"}
                        self._send_json_response(conn, error_response, session_info)
                        logging.warning(f"Invalid JWT token from {client_id}")
                        continue
                    
                    username = token_payload['username']
                    is_admin = token_payload.get('is_admin', False)
                    
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

                    elif command.startswith('FOLDER_ZIP'):
                        # Format: FOLDER_ZIP <folder_name> <size> <checksum>
                        cmd_parts = command.split()
                        if len(cmd_parts) == 4:
                            _, folder_name, size, checksum = cmd_parts
                            success, message = self.handle_folder_zip(conn, addr[0], folder_name, size, checksum, session_info)
                            if success:
                                logging.info(f"Folder from {username} processed: {message}")
                            else:
                                logging.error(f"Folder processing error from {username}: {message}")
                        else:
                            error_response = {"status": "error", "message": "Invalid FOLDER_ZIP command format"}
                            self._send_json_response(conn, error_response, session_info)
                    
                    elif command == 'LIST_FILES':
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
                            success, message = self.send_file_to_client(conn, filename, session_info, addr[0])
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
                            success, message = self.send_folder_to_client(conn, folder_name, session_info, addr[0])
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
                    self.stop()
                    break
                except Exception as e:
                    logging.error(f"Accept connection error: {e}")
        except Exception as e:
            logging.error(f"Server start error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logging.info("TCP Server stopped")
    
    def list_files(self, conn, session_info):
        try:
            files_list = []
            folders_list = []
            
            if not os.path.exists(UPLOAD_DIR):
                empty_response = {"status": "ok", "command": "LIST_EMPTY"}
                self._send_json_response(conn, empty_response, session_info)
                return True, "Upload directory is empty"
            
            for item in os.listdir(UPLOAD_DIR):
                item_path = os.path.join(UPLOAD_DIR, item)
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
                    file_count = sum(1 for root, dirs, files in os.walk(item_path) 
                                   for f in files if not f.endswith('.meta'))
                    folders_list.append({
                        'name': item,
                        'type': 'folder',
                        'file_count': file_count
                    })
            list_data = {
                'files': files_list,
                'folders': folders_list
            }
            
            list_response = {"status": "ok", "command": "LIST_OK", "data": list_data}
            self._send_json_response(conn, list_response, session_info)
            return True, f"List sent: {len(files_list)} files, {len(folders_list)} folders"
        except Exception as e:
            logging.error(f"List files error: {e}")
            return False, str(e)
        
    def _zip_folder(self, folder_path):
        try:
            temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
            temp_zip.close()
            
            folder_name = os.path.basename(folder_path.rstrip('/\\'))
            with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(folder_path):
                    for d in dirs:
                        dir_path = os.path.join(root, d)
                        arcname = os.path.relpath(dir_path, folder_path) + '/'
                        zipf.writestr(arcname, '') 
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, folder_path)
                        zipf.write(file_path, arcname)
            return temp_zip.name
        except Exception as e:
            logging.error(f"Zip folder error: {e}")
            return None
        
    def _send_zip_to_client(self, zip_path, client_addr, session_info):
        try:
            with open(zip_path, 'rb') as f:
                zip_data = f.read()
            
            zip_size = len(zip_data)
            chunk_size = UDP_PLAINTEXT_CHUNK_SIZE
            chunks = [zip_data[i:i+chunk_size] for i in range(0, zip_size, chunk_size)]
            total_chunks = len(chunks)
        
            if 'download_nonce_prefix' not in session_info:
                session_info['download_nonce_prefix'] = os.urandom(4)
                session_info['download_nonce_counter'] = 0
            
            def next_nonce():
                nonce_prefix = session_info['download_nonce_prefix']
                nonce_counter = session_info['download_nonce_counter']
                nonce = nonce_prefix + nonce_counter.to_bytes(8, 'big')
                session_info['download_nonce_counter'] = nonce_counter + 1
                return nonce
            
            WINDOW_SIZE = 64
            TIMEOUT = 0.5
            base = 0
            next_seq = 0
            acked = [False] * total_chunks
            last_ack_time = time.time()
            start_time = time.time()
            
            while next_seq < min(base + WINDOW_SIZE, total_chunks):
                nonce = next_nonce()
                ciphertext = session_info['aesgcm'].encrypt(nonce, chunks[next_seq], None)
                header = session_info['session_id'] + next_seq.to_bytes(4, 'big')
                packet = header + nonce + ciphertext
                self.udp_socket.sendto(packet, client_addr)
                next_seq += 1
            
            while base < total_chunks:
                try:
                    self.udp_socket.settimeout(TIMEOUT)
                    ack_packet, addr = self.udp_socket.recvfrom(1024)
                    if addr[0] != client_addr[0]:
                        continue
                    
                    ack_data = ack_packet.decode(errors='ignore')
                    if ack_data.startswith('ACK '):
                        ack_seq = int(ack_data.split()[1])
                        
                        for seq in range(base, ack_seq + 1):
                            if seq < total_chunks:
                                acked[seq] = True
                        
                        while base < total_chunks and acked[base]:
                            base += 1
                        
                        while next_seq < min(base + WINDOW_SIZE, total_chunks):
                            nonce = next_nonce()
                            ciphertext = session_info['aesgcm'].encrypt(nonce, chunks[next_seq], None)
                            header = session_info['session_id'] + next_seq.to_bytes(4, 'big')
                            packet = header + nonce + ciphertext
                            self.udp_socket.sendto(packet, client_addr)
                            next_seq += 1
                        
                        last_ack_time = time.time()
                except socket.timeout:
                    if time.time() - last_ack_time > TIMEOUT * 3:
                        next_seq = base
                        for seq in range(base, min(base + WINDOW_SIZE, total_chunks)):
                            if seq < total_chunks:
                                nonce = next_nonce()
                                ciphertext = session_info['aesgcm'].encrypt(nonce, chunks[seq], None)
                                header = session_info['session_id'] + seq.to_bytes(4, 'big')
                                packet = header + nonce + ciphertext
                                self.udp_socket.sendto(packet, client_addr)
                        last_ack_time = time.time()
                    continue
            
            end_header = session_info['session_id'] + (0xFFFFFFFF).to_bytes(4, 'big')
            self.udp_socket.sendto(end_header + b'END', client_addr)
            
            transfer_time = time.time() - start_time
            speed = zip_size / transfer_time / 1024 if transfer_time > 0 else 0
            return True, f"ZIP file sent: {speed:.2f} KB/s"
        except Exception as e:
            logging.error(f"Error sending ZIP file: {e}")
            return False, str(e)

    def send_folder_to_client(self, conn, folder_name, session_info, client_ip):
        try:
            folder_path = os.path.join(UPLOAD_DIR, folder_name)
            
            if not os.path.exists(folder_path):
                return False, f"Folder not found: {folder_name}"
            if not os.path.isdir(folder_path):
                return False, f"Not a folder: {folder_name}"
        
            zip_path = self._zip_folder(folder_path)
            if not zip_path:
                return False, "Failed to zip folder"
            
            zip_size = os.path.getsize(zip_path)
            zip_checksum = hashlib.sha256()
            with open(zip_path, 'rb') as f:
                while chunk := f.read(8192):
                    zip_checksum.update(chunk)
            checksum_hex = zip_checksum.hexdigest()
        
            folder_info_response = {
                "status": "ok", 
                "command": "DOWNLOAD_READY", 
                "filename": f"{folder_name}.zip",
                "size": zip_size,
                "checksum": checksum_hex
            }
            self._send_json_response(conn, folder_info_response, session_info)
            
            try:
                udp_port_msg = conn.recv(1024).decode().strip()
                if udp_port_msg.startswith('UDP_PORT'):
                    client_udp_port = int(udp_port_msg.split()[1])
                    client_udp_addr = (client_ip, client_udp_port)
                    logging.info(f"Client UDP port for folder: {client_udp_port}")
                else:
                    os.remove(zip_path)
                    return False, "Client UDP port not received"
            except Exception as e:
                os.remove(zip_path)
                logging.error(f"Failed to get client UDP port: {e}")
                return False, "Failed to get client UDP port"
            
            success, message = self._send_zip_to_client(zip_path, client_udp_addr, session_info)
            os.remove(zip_path)
            
            if success:
                complete_response = {"status": "ok", "command": "FOLDER_OK", "message": message}
                self._send_json_response(conn, complete_response, session_info)
                return True, message
            else:
                return False, message
        except Exception as e:
            logging.error(f"Send folder error: {e}")
            if 'zip_path' in locals() and os.path.exists(zip_path):
                os.remove(zip_path)
            return False, str(e)
    
    def delete_file(self, filename):
        try:
            file_path = os.path.join(UPLOAD_DIR, filename)
            
            if not os.path.exists(file_path):
                return False, f"File not found: {filename}"
            if not os.path.isfile(file_path):
                return False, f"Not a file: {filename}"
            
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
        try:
            folder_path = os.path.join(UPLOAD_DIR, folder_name)
            
            if not os.path.exists(folder_path):
                return False, f"Folder not found: {folder_name}"
            if not os.path.isdir(folder_path):
                return False, f"Not a folder: {folder_name}"
            
            shutil.rmtree(folder_path)
            logging.info(f"Folder deleted: {folder_name}")
            return True, f"Folder deleted: {folder_name}"
        except Exception as e:
            logging.error(f"Delete folder error: {e}")
            return False, str(e)
    
    def rename_file(self, old_name, new_name):
        try:
            old_path = os.path.join(UPLOAD_DIR, old_name)
            new_path = os.path.join(UPLOAD_DIR, new_name)
            
            if not os.path.exists(old_path):
                return False, f"File not found: {old_name}"
            if not os.path.isfile(old_path):
                return False, f"Not a file: {old_name}"
            if os.path.exists(new_path):
                return False, f"File already exists: {new_name}"
            
            os.rename(old_path, new_path)
            
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
        try:
            old_path = os.path.join(UPLOAD_DIR, old_name)
            new_path = os.path.join(UPLOAD_DIR, new_name)
            
            if not os.path.exists(old_path):
                return False, f"Folder not found: {old_name}"
            if not os.path.isdir(old_path):
                return False, f"Not a folder: {old_name}"
            if os.path.exists(new_path):
                return False, f"Folder already exists: {new_name}"
            
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
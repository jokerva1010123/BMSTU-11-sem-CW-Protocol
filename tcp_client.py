#!/usr/bin/env python3
import socket, os
import hashlib
import time
import logging
import json
import base64
import datetime
import sys
import zipfile
import tempfile
import threading
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from config import TCP_PORT, UDP_PLAINTEXT_CHUNK_SIZE

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
    
    def connect(self):
        # Устанавливает соединение с сервером
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024) 
        
            self.sock.settimeout(30.0)
            
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
            
            password_hash = hashlib.sha256(password.encode()).hexdigest()
        
            auth_msg = f"AUTH {username} {password_hash}"
            self.sock.send(auth_msg.encode())
            
            auth_response = self.sock.recv(1024).decode()
            if auth_response.startswith('AUTH_OK'):
                parts = auth_response.split()
                if len(parts) >= 2:
                    self.jwt_token = parts[1]
                self.authenticated = True
                self.username = username
                
                udp_port_msg = self.sock.recv(1024).decode().strip()
                if udp_port_msg.startswith('UDP_PORT'):
                    self.udp_data_port = int(udp_port_msg.split()[1])
                    # UDP socket
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
        """3-step X25519 Diffie-Hellman handshake"""
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
    
    def _send_json_response(self, response_dict: dict):
        try:
            json_str = json.dumps(response_dict)
            
            if self.aesgcm and self.session_id:
                nonce = self._next_nonce()
                ciphertext = self.aesgcm.encrypt(nonce, json_str.encode(), None)
                encrypted_data = self.session_id + nonce + ciphertext
                encrypted_b64 = base64.b64encode(encrypted_data).decode()
            else:
                encrypted_b64 = base64.b64encode(json_str.encode()).decode()
                
            self.sock.send(encrypted_b64.encode())
            return True
        except Exception as e:
            logging.error(f"Error sending JSON response: {e}")
            return False

    def _recv_json_response(self):
        try:
            encrypted_data_b64 = self.sock.recv(4096).decode().strip()
            if not encrypted_data_b64:
                return None

            encrypted_data = base64.b64decode(encrypted_data_b64)
            
            if self.aesgcm and self.session_id:
                if len(encrypted_data) < 4 + 12:
                    logging.error("Encrypted data too short")
                    return None
                
                pkt_session = encrypted_data[:4]
                if pkt_session != self.session_id:
                    logging.error("Session mismatch in decryption")
                    return None
                
                nonce = encrypted_data[4:16]
                ciphertext = encrypted_data[16:]
                
                try:
                    json_str = self.aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                except Exception as e:
                    logging.error(f"Decryption error: {e}")
                    return None
            else:
                json_str = encrypted_data.decode('utf-8')
            
            # Parse JSON
            response_data = json.loads(json_str)
            return response_data
        except Exception as e:
            logging.error(f"Error receiving JSON response: {e}")
            return None
    
    def _send_json_command(self, command: str, **kwargs):
        if not self.authenticated or not self.jwt_token:
            return False, "Not authenticated"
        try:
            # JSON packet
            json_packet = {
                'token': self.jwt_token,
                'command': command,
                'timestamp': datetime.datetime.now().isoformat(),
                'username': self.username
            }
            json_packet.update(kwargs)
            json_str = json.dumps(json_packet)
            
            # JSON with AES-GCM
            if self.aesgcm and self.session_id:
                nonce = self._next_nonce()
                ciphertext = self.aesgcm.encrypt(nonce, json_str.encode(), None)
                encrypted_data = self.session_id + nonce + ciphertext
                encrypted_b64 = base64.b64encode(encrypted_data).decode()
            else:
                encrypted_b64 = base64.b64encode(json_str.encode()).decode()
            
            self.sock.send(encrypted_b64.encode())
            logging.info(f"Encrypted JSON command sent: {command}")
            return True, None
        except Exception as e:
            logging.error(f"Error sending JSON command: {e}")
            return False, str(e)

    def send_file(self, file_path, progress_callback=None):
        if not self.authenticated:
            return False, "Authentication required"
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        try:
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)

            logging.info("Calculating file checksum...")
            file_checksum = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    file_checksum.update(chunk)
            checksum_hex = file_checksum.hexdigest()
            logging.info(f"Checksum: {checksum_hex[:16]}...")

            file_cmd = f"FILE {filename} {file_size} {checksum_hex}"
            success, error = self._send_json_command(file_cmd)
            if not success:
                return False, error

            response_data = self._recv_json_response()
            if not response_data or response_data.get('command') != 'READY_UDP':
                return False, f"Server not ready: {response_data}"

            logging.info(f"Starting reliable UDP transfer {filename} ({file_size} bytes)")

            server_addr = (self.server_ip, self.udp_data_port)
            window_size = 80   
            retransmit_timeout = 0.5
            max_retries = 5

            next_seq = 0
            base = 0
            packets_in_flight = {}
            acked = set()
            done = False
            lock = threading.Lock()

            def next_nonce():
                nonce = self.nonce_prefix + self.nonce_counter.to_bytes(8, 'big')
                self.nonce_counter += 1
                return nonce

            def send_packet(seq, plain_data):
                nonce = next_nonce()
                ciphertext = self.aesgcm.encrypt(nonce, plain_data, None)
                header = self.session_id + seq.to_bytes(4, 'big')
                packet = header + nonce + ciphertext
                self.udp_sock.sendto(packet, server_addr)
                return time.time()

            def retransmit_thread():
                nonlocal done
                while not done:
                    time.sleep(0.1)
                    with lock:
                        now = time.time()
                        for seq in list(packets_in_flight.keys()):
                            if seq < base:
                                continue
                            info = packets_in_flight[seq]
                            if now - info['sent_time'] > retransmit_timeout:
                                if info['retries'] >= max_retries:
                                    done = True
                                    return
                                # retransmit
                                send_packet(seq, info['data'])
                                info['sent_time'] = now
                                info['retries'] += 1

            retransmit_t = threading.Thread(target=retransmit_thread, daemon=True)
            retransmit_t.start()

            bytes_sent = 0
            transfer_start = time.time()
            
            with open(file_path, 'rb') as f:
                while not done:
                    with lock:
                        while next_seq < base + window_size and bytes_sent < file_size:
                            chunk = f.read(UDP_PLAINTEXT_CHUNK_SIZE)
                            if not chunk:
                                break
                            sent_time = send_packet(next_seq, chunk)
                            packets_in_flight[next_seq] = {'data': chunk, 'sent_time': sent_time, 'retries': 0}
                            next_seq += 1
                            bytes_sent += len(chunk)

                            if progress_callback:
                                progress = (bytes_sent / file_size) * 100
                                progress_callback(progress, bytes_sent, file_size)
                    try:
                        self.udp_sock.settimeout(0.05)
                        ack_packet, _ = self.udp_sock.recvfrom(1024)
                        ack_data = ack_packet.decode(errors='ignore')
                        if ack_data.startswith('ACK '):
                            ack_seq = int(ack_data.split()[1])
                            with lock:
                                if ack_seq >= base - 1:
                                    base = ack_seq + 1
                                    for s in range(base):
                                        packets_in_flight.pop(s, None)
                                        acked.add(s)
                    except socket.timeout:
                        pass

                    if bytes_sent >= file_size and base >= next_seq:
                        done = True

            end_header = self.session_id + (0xFFFFFFFF).to_bytes(4, 'big')
            self.udp_sock.sendto(end_header + b'END', server_addr)

            retransmit_t.join(timeout=2.0)
            done = True

            transfer_time = time.time() - transfer_start
            speed = file_size / transfer_time / 1024 if transfer_time > 0 else 0

            result_response = self._recv_json_response()
            if result_response and result_response.get('command') == 'FILE_OK':
                return True, f"File transferred reliably ({speed:.2f} KB/s)"
            else:
                return False, f"Transfer failed: {result_response}"

        except Exception as e:
            logging.error(f"Reliable UDP transfer error: {e}")
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

    def send_folder(self, folder_path, progress_callback=None):
        if not self.authenticated:
            return False, "Authentication required"
        if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
            return False, "Folder does not exist or not a directory"
        
        try:
            # Nén folder thành ZIP tạm
            zip_path = self._zip_folder(folder_path)
            if not zip_path:
                return False, "Failed to zip folder"
            
            folder_name = os.path.basename(folder_path.rstrip('/\\'))
            
            # Tính size và checksum của ZIP
            file_size = os.path.getsize(zip_path)
            logging.info("Calculating ZIP checksum...")
            file_checksum = hashlib.sha256()
            with open(zip_path, 'rb') as f:
                while chunk := f.read(8192):
                    file_checksum.update(chunk)
            checksum_hex = file_checksum.hexdigest()
            logging.info(f"Checksum: {checksum_hex[:16]}...")
            
            folder_cmd = f"FOLDER_ZIP {folder_name} {file_size} {checksum_hex}"
            success, error = self._send_json_command(folder_cmd)
            if not success:
                os.remove(zip_path)
                return False, error
            
            response_data = self._recv_json_response()
            if not response_data or response_data.get('command') != 'READY_UDP':
                os.remove(zip_path)
                return False, f"Server not ready: {response_data}"
            
            logging.info(f"Starting reliable UDP transfer for zipped folder {folder_name} ({file_size} bytes)")
            
            server_addr = (self.server_ip, self.udp_data_port)
            window_size = 64
            retransmit_timeout = 0.6
            max_retries = 5

            next_seq = 0
            base = 0
            packets_in_flight = {}
            acked = set()
            done = False
            lock = threading.Lock()

            def next_nonce():
                nonce = self.nonce_prefix + self.nonce_counter.to_bytes(8, 'big')
                self.nonce_counter += 1
                return nonce

            def send_packet(seq, plain_data):
                nonce = next_nonce()
                ciphertext = self.aesgcm.encrypt(nonce, plain_data, None)
                header = self.session_id + seq.to_bytes(4, 'big')
                packet = header + nonce + ciphertext
                self.udp_sock.sendto(packet, server_addr)
                return time.time()

            def retransmit_thread():
                nonlocal done
                while not done:
                    time.sleep(0.1)
                    with lock:
                        now = time.time()
                        for seq in list(packets_in_flight.keys()):
                            if seq < base:
                                continue
                            info = packets_in_flight[seq]
                            if now - info['sent_time'] > retransmit_timeout:
                                if info['retries'] >= max_retries:
                                    logging.error(f"Max retries exceeded for seq {seq}")
                                    done = True
                                    return
                                send_packet(seq, info['data'])
                                info['sent_time'] = now
                                info['retries'] += 1
                                logging.debug(f"Retransmitted seq {seq} (retry {info['retries']})")

            retransmit_t = threading.Thread(target=retransmit_thread, daemon=True)
            retransmit_t.start()

            bytes_sent = 0
            transfer_start = time.time()
            
            with open(zip_path, 'rb') as f:
                while not done:
                    with lock:
                        while next_seq < base + window_size and bytes_sent < file_size:
                            chunk = f.read(UDP_PLAINTEXT_CHUNK_SIZE)
                            if not chunk:
                                break
                            sent_time = send_packet(next_seq, chunk)
                            packets_in_flight[next_seq] = {'data': chunk, 'sent_time': sent_time, 'retries': 0}
                            next_seq += 1
                            bytes_sent += len(chunk)

                            if progress_callback:
                                progress = (bytes_sent / file_size) * 100
                                progress_callback(progress, bytes_sent, file_size)
                    try:
                        self.udp_sock.settimeout(0.05)
                        ack_packet, _ = self.udp_sock.recvfrom(1024)
                        ack_data = ack_packet.decode(errors='ignore')
                        if ack_data.startswith('ACK '):
                            ack_seq = int(ack_data.split()[1])
                            with lock:
                                if ack_seq >= base - 1:
                                    base = ack_seq + 1
                                    for s in range(base):
                                        packets_in_flight.pop(s, None)
                                        acked.add(s)
                    except socket.timeout:
                        pass

                    if bytes_sent >= file_size and base >= next_seq:
                        done = True

            # Gửi END marker
            end_header = self.session_id + (0xFFFFFFFF).to_bytes(4, 'big')
            self.udp_sock.sendto(end_header + b'END', server_addr)

            retransmit_t.join(timeout=2.0)
            done = True

            transfer_time = time.time() - transfer_start
            speed = file_size / transfer_time / 1024 if transfer_time > 0 else 0

            file_response = self._recv_json_response()
            if not file_response or file_response.get('command') != 'FILE_OK':
                os.remove(zip_path)  # Xóa ZIP tạm nếu lỗi
                return False, f"ZIP transfer failed: {file_response}"

            os.remove(zip_path)
            
            transfer_time = time.time() - transfer_start
            speed = file_size / transfer_time / 1024 if transfer_time > 0 else 0
            return True, f"Folder transferred reliably and unzipped ({speed:.2f} KB/s)"
        except Exception as e:
            logging.error(f"Reliable UDP folder transfer error: {e}")
            if 'zip_path' in locals() and os.path.exists(zip_path):
                os.remove(zip_path)
            return False, str(e)
    
    def list_files(self):
        if not self.authenticated:
            return False, "Authentication required", None
        try:
            success, error = self._send_json_command('LIST_FILES')
            if not success:
                return False, error, None
            
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
    
    def download_file(self, remote_filename, local_save_path=None, progress_callback=None):
        if not self.authenticated:
            return False, "Authentication required"
        try:
            download_cmd = f'DOWNLOAD_FILE {remote_filename}'
            success, error = self._send_json_command(download_cmd)
            if not success:
                return False, error
            
            response_data = self._recv_json_response()
            if not response_data:
                return False, "No response from server"
            if response_data.get('command') != 'DOWNLOAD_READY':
                return False, f"Server not ready: {response_data}"
            
            filename = response_data.get('filename', remote_filename)
            file_size = int(response_data.get('size', 0))
            expected_checksum = response_data.get('checksum', '')
            
            if local_save_path is None:
                local_save_path = filename
            elif os.path.isdir(local_save_path):
                local_save_path = os.path.join(local_save_path, filename)
            
            self.sock.send(f'UDP_PORT {self.client_udp_port}'.encode())
            logging.info(f"Starting download: {filename} ({file_size} bytes)")
            
            expected_seq = 0
            received_chunks = {}
            last_ack_sent = -1
            
            total_chunks = (file_size + UDP_PLAINTEXT_CHUNK_SIZE - 1) // UDP_PLAINTEXT_CHUNK_SIZE
            
            temp_file = local_save_path + '.tmp'
            f = open(temp_file, 'wb')
            
            self.udp_sock.settimeout(5.0)
            server_addr = (self.server_ip, self.udp_data_port)
            
            start_time = time.time()
            last_packet_time = time.time()
            
            while expected_seq < total_chunks:
                try:
                    packet, addr = self.udp_sock.recvfrom(UDP_PLAINTEXT_CHUNK_SIZE + 64)
                    if addr[0] != self.server_ip:
                        continue
                    if not packet.startswith(self.session_id):
                        continue
                    
                    seq_bytes = packet[4:8]
                    seq = int.from_bytes(seq_bytes, 'big')
                    
                    if seq == 0xFFFFFFFF:
                        logging.info("Received END marker")
                        break
                    
                    nonce = packet[8:20]
                    ciphertext = packet[20:]
                    
                    try:
                        chunk = self.aesgcm.decrypt(nonce, ciphertext, None)
                    except Exception as e:
                        logging.warning(f"Decrypt error seq {seq}: {e}")
                        continue
                    
                    last_packet_time = time.time()
                    
                    if seq not in received_chunks:
                        received_chunks[seq] = chunk
                    
                    while expected_seq in received_chunks:
                        chunk_data = received_chunks.pop(expected_seq)
                        f.write(chunk_data)
                        expected_seq += 1
                        
                        if expected_seq - 1 > last_ack_sent:
                            ack_msg = f"ACK {expected_seq - 1}".encode()
                            self.udp_sock.sendto(ack_msg, server_addr)
                            last_ack_sent = expected_seq - 1
                    
                    # Update progress
                    if progress_callback and file_size > 0:
                        bytes_received = expected_seq * UDP_PLAINTEXT_CHUNK_SIZE
                        if expected_seq == total_chunks - 1:
                            bytes_received = file_size  # Last chunk might be smaller
                        progress = min(100, (bytes_received / file_size) * 100)
                        progress_callback(progress, bytes_received, file_size)
                    
                except socket.timeout:
                    if expected_seq > 0 and time.time() - last_packet_time > 1.0:
                        ack_msg = f"ACK {expected_seq - 1}".encode()
                        self.udp_sock.sendto(ack_msg, server_addr)
                        last_packet_time = time.time()
                    continue
            
            f.close()
            
            actual_size = os.path.getsize(temp_file)
            if actual_size != file_size:
                logging.error(f"File size mismatch: {actual_size} vs {file_size}")
                os.remove(temp_file)
                return False, f"File size mismatch: {actual_size}/{file_size}"
            
            actual_checksum = hashlib.sha256()
            with open(temp_file, 'rb') as f_check:
                while chunk := f_check.read(8192):
                    actual_checksum.update(chunk)
            actual_hex = actual_checksum.hexdigest()
            
            if actual_hex == expected_checksum:
                if os.path.exists(local_save_path):
                    os.remove(local_save_path)
                os.rename(temp_file, local_save_path)
                
                final_response = self._recv_json_response()
                transfer_time = time.time() - start_time
                speed = file_size / transfer_time / 1024 if transfer_time > 0 else 0
                
                return True, f"Download complete: {speed:.2f} KB/s"
            else:
                logging.error(f"Checksum mismatch!")
                os.remove(temp_file)
                return False, f"Checksum mismatch"
            
        except Exception as e:
            logging.error(f"Download error: {e}")
            import traceback
            traceback.print_exc()
            if 'temp_file' in locals() and os.path.exists(temp_file):
                os.remove(temp_file)
            return False, str(e)    

    def download_folder(self, remote_folder_name, local_save_path=None, progress_callback=None):
        if not self.authenticated:
            return False, "Authentication required"
        try:
            download_cmd = f'DOWNLOAD_FOLDER {remote_folder_name}'
            success, error = self._send_json_command(download_cmd)
            if not success:
                return False, error
            
            response_data = self._recv_json_response()
            if not response_data:
                return False, "No response from server"
            if response_data.get('command') != 'DOWNLOAD_READY':
                return False, f"Server not ready: {response_data}"
            
            zip_filename = response_data.get('filename', f"{remote_folder_name}.zip")
            file_size = int(response_data.get('size', 0))
            expected_checksum = response_data.get('checksum', '')
            
            if local_save_path is None:
                local_save_path = remote_folder_name
            elif os.path.isfile(local_save_path):
                local_save_path = os.path.dirname(local_save_path)
            
            self.sock.send(f'UDP_PORT {self.client_udp_port}'.encode())
            logging.info(f"Starting download folder: {remote_folder_name} ({file_size} bytes)")
            
            temp_zip = local_save_path + '.zip.tmp'
            expected_seq = 0
            received_chunks = {}
            last_ack_sent = -1
            
            total_chunks = (file_size + UDP_PLAINTEXT_CHUNK_SIZE - 1) // UDP_PLAINTEXT_CHUNK_SIZE
            
            with open(temp_zip, 'wb') as f:
                self.udp_sock.settimeout(5.0)
                server_addr = (self.server_ip, self.udp_data_port)
                start_time = time.time()
                last_packet_time = time.time()
                
                while expected_seq < total_chunks:
                    try:
                        packet, addr = self.udp_sock.recvfrom(UDP_PLAINTEXT_CHUNK_SIZE + 64)
                        if addr[0] != self.server_ip:
                            continue
                        
                        if not packet.startswith(self.session_id):
                            continue
                        
                        seq_bytes = packet[4:8]
                        seq = int.from_bytes(seq_bytes, 'big')
                        
                        if seq == 0xFFFFFFFF:
                            logging.info("Received END marker")
                            break
                        
                        nonce = packet[8:20]
                        ciphertext = packet[20:]
                        
                        try:
                            chunk = self.aesgcm.decrypt(nonce, ciphertext, None)
                        except Exception as e:
                            logging.warning(f"Decrypt error seq {seq}: {e}")
                            continue
                        
                        last_packet_time = time.time()
                        
                        if seq not in received_chunks:
                            received_chunks[seq] = chunk
                        
                        while expected_seq in received_chunks:
                            chunk_data = received_chunks.pop(expected_seq)
                            f.write(chunk_data)
                            expected_seq += 1
                            
                            if expected_seq - 1 > last_ack_sent:
                                ack_msg = f"ACK {expected_seq - 1}".encode()
                                self.udp_sock.sendto(ack_msg, server_addr)
                                last_ack_sent = expected_seq - 1
                        
                        # Update progress
                        if progress_callback and file_size > 0:
                            bytes_received = expected_seq * UDP_PLAINTEXT_CHUNK_SIZE
                            if expected_seq == total_chunks - 1:
                                bytes_received = file_size
                            progress = min(100, (bytes_received / file_size) * 100)
                            progress_callback(progress, bytes_received, file_size)
                    except socket.timeout:
                        if expected_seq > 0 and time.time() - last_packet_time > 1.0:
                            ack_msg = f"ACK {expected_seq - 1}".encode()
                            self.udp_sock.sendto(ack_msg, server_addr)
                            last_packet_time = time.time()
                        continue
        
            actual_size = os.path.getsize(temp_zip)
            if actual_size != file_size:
                os.remove(temp_zip)
                return False, f"File size mismatch: {actual_size}/{file_size}"
            
            actual_checksum = hashlib.sha256()
            with open(temp_zip, 'rb') as f_check:
                while chunk := f_check.read(8192):
                    actual_checksum.update(chunk)
            actual_hex = actual_checksum.hexdigest()
            
            if actual_hex != expected_checksum:
                os.remove(temp_zip)
                return False, "Checksum mismatch"
            
            with zipfile.ZipFile(temp_zip, 'r') as zipf:
                zipf.extractall(local_save_path)
            os.remove(temp_zip)
            
            final_response = self._recv_json_response()
            transfer_time = time.time() - start_time
            speed = file_size / transfer_time / 1024 if transfer_time > 0 else 0
            
            return True, f"Folder downloaded and unzipped: {speed:.2f} KB/s"
        
        except Exception as e:
            logging.error(f"Download folder error: {e}")
            if 'temp_zip' in locals() and os.path.exists(temp_zip):
                os.remove(temp_zip)
            return False, str(e)
    
    def delete_file(self, filename):
        if not self.authenticated:
            return False, "Authentication required"
        try:
            delete_cmd = f'DELETE_FILE {filename}'
            success, error = self._send_json_command(delete_cmd)
            if not success:
                return False, error
            
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
        if not self.authenticated:
            return False, "Authentication required"
        
        try:
            delete_cmd = f'DELETE_FOLDER {folder_name}'
            success, error = self._send_json_command(delete_cmd)
            if not success:
                return False, error
            
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
        if not self.authenticated:
            return False, "Authentication required"
        try:
            rename_cmd = f'RENAME_FILE {old_name} {new_name}'
            success, error = self._send_json_command(rename_cmd)
            if not success:
                return False, error
            
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
        if not self.authenticated:
            return False, "Authentication required"
        try:
            rename_cmd = f'RENAME_FOLDER {old_name} {new_name}'
            success, error = self._send_json_command(rename_cmd)
            if not success:
                return False, error
            
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
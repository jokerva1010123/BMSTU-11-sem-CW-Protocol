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
        
    def receive_streaming_file(self, conn, client_ip, filename, expected_size):
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
            conn.send(b'READY_STREAM')
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
                    conn.send(f'FILE_OK Hash: {server_hash[:16]}...'.encode())
                    return True, f"File received: {bytes_received} bytes"
                else:
                    logging.error(f"Hash mismatch for streaming file {filename}")
                    logging.error(f"Client hash: {client_hash[:32]}...")
                    logging.error(f"Server hash: {server_hash[:32]}...")
                    
                    # Сохраняем файл для анализа, но отмечаем как проблемный
                    corrupted_path = file_path + ".corrupted"
                    os.rename(file_path, corrupted_path)
                    conn.send(f'FILE_CORRUPTED Server hash: {server_hash}'.encode())
                    return False, "Hash mismatch - file saved as .corrupted"
            else:
                # Если хеш не получен, вычисляем его из полученного файла
                server_hash = file_hash.hexdigest()
                if bytes_received == expected_size_int:
                    logging.warning(f"No hash received, but file size matches. Hash: {server_hash[:16]}...")
                    conn.send(f'FILE_OK No hash received, computed: {server_hash}'.encode())
                    return True, f"File received without hash verification: {bytes_received} bytes"
                else:
                    logging.error(f"Incomplete transfer: {bytes_received}/{expected_size_int} bytes")
                    os.remove(file_path)
                    conn.send(f'FILE_INCOMPLETE Received: {bytes_received}, Expected: {expected_size_int}'.encode())
                    return False, f"Incomplete transfer: {bytes_received}/{expected_size_int}"
                
        except Exception as e:
            logging.error(f"Streaming file receive error: {e}")
            if 'file_path' in locals() and os.path.exists(file_path):
                os.remove(file_path)
            return False, str(e)
        finally:
            # Восстанавливаем стандартный таймаут
            conn.settimeout(None)

    def receive_large_file(self, conn, filename, expected_size):
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
            
            conn.send(b'READY_STREAM')
            logging.info(f"Receiving large file: {filename} ({expected_size:,} bytes)")
            
            # Начинаем прием потоковым способом
            bytes_received = 0
            file_hash = hashlib.sha256()
            
            with open(file_path, 'wb') as f:
                while bytes_received < int(expected_size):
                    try:
                        # Получаем размер чанка (4 байта)
                        header = conn.recv(4)
                        if not header:
                            break
                        
                        chunk_size = int.from_bytes(header, 'big')
                        
                        # Получаем сам чанк
                        chunk = b''
                        while len(chunk) < chunk_size:
                            remaining = chunk_size - len(chunk)
                            part = conn.recv(min(65536, remaining))
                            if not part:
                                break
                            chunk += part
                        
                        if not chunk:
                            break
                        
                        # Записываем и обновляем хеш
                        f.write(chunk)
                        file_hash.update(chunk)
                        bytes_received += len(chunk)
                        
                        # Логируем прогресс каждые 100MB
                        if bytes_received % (100 * 1024 * 1024) < len(chunk):
                            progress = (bytes_received / int(expected_size)) * 100
                            logging.info(f"Received: {bytes_received:,}/{expected_size:,} bytes ({progress:.1f}%)")
                            
                    except socket.timeout:
                        logging.warning("Socket timeout during transfer, continuing...")
                        continue
            
            # Ждем финальный хеш от клиента
            hash_data = conn.recv(1024).decode()
            if hash_data.startswith('FILE_HASH'):
                client_hash = hash_data.split()[1]
                server_hash = file_hash.hexdigest()
                
                if client_hash == server_hash:
                    logging.info(f"Large file received successfully: {filename}")
                    conn.send(f'FILE_OK Hash: {server_hash[:16]}...'.encode())
                    return True, f"File received: {bytes_received:,} bytes"
                else:
                    logging.error(f"Hash mismatch for large file {filename}")
                    os.remove(file_path)  # Удаляем поврежденный файл
                    conn.send(f'FILE_CORRUPTED Server hash: {server_hash}'.encode())
                    return False, "Hash mismatch"
            else:
                return False, "No hash received"
                
        except Exception as e:
            logging.error(f"Large file receive error: {e}")
            return False, str(e)    
    def receive_file(self, conn, client_ip, filename, expected_size, expected_checksum):
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
            
            conn.send(b'READY')
            logging.info(f"Receiving file: {filename} ({expected_size} bytes)")
            
            # Принимаем данные через UDP
            received_data = b''
            bytes_received = 0
            chunk_size = 4096
            self.udp_socket.settimeout(10)  # Timeout for UDP receive
            
            while bytes_received < int(expected_size):
                try:
                    data, addr = self.udp_socket.recvfrom(chunk_size)
                    if addr[0] != client_ip:
                        continue  # Ignore data from other clients
                    received_data += data
                    bytes_received += len(data)
                    # Send ACK via TCP
                    conn.send(f'ACK {bytes_received}'.encode())
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
                conn.send(f'FILE_OK {actual_checksum}'.encode())
                return True, f"File received successfully. Hash: {actual_checksum[:16]}..."
            else:
                logging.error(f"Integrity error. Expected: {expected_checksum[:16]}..., Got: {actual_checksum[:16]}...")
                conn.send(f'FILE_CORRUPTED Received hash: {actual_checksum}'.encode())
                return False, "Data integrity error"
                
        except Exception as e:
            logging.error(f"Error receiving file: {e}")
            conn.send(f'FILE_ERROR {str(e)}'.encode())
            return False, str(e)
    
    def handle_client(self, conn, addr):
        """Обрабатывает соединение с клиентом"""
        client_id = f"{addr[0]}:{addr[1]}"
        self.clients.append(client_id)
        username = None
        
        try:
            logging.info(f"New connection from {client_id}")
            
            # Аутентификация
            auth_success, auth_message = self.authenticate(conn, addr)
            if not auth_success:
                logging.warning(f"Authentication failed for {client_id}: {auth_message}")
                return
            
            username = auth_message
            
            # Send UDP data port to client
            conn.send(f'UDP_PORT {UDP_DATA_PORT}'.encode())
            logging.info(f"Sent UDP data port {UDP_DATA_PORT} to {client_id}")
            
            # Основной цикл обработки команд с JWT
            while True:
                try:
                    # Получаем команду с токеном
                    data = conn.recv(1024).decode().strip()
                    if not data:
                        break
                    
                    # Ожидаем формат: TOKEN <jwt_token> <command>
                    parts = data.split(maxsplit=2)
                    if len(parts) < 2 or parts[0] != 'TOKEN':
                        conn.send(b'ERROR:Invalid command format. Expected: TOKEN <jwt> <command>')
                        continue
                    
                    jwt_token = parts[1]
                    command = parts[2] if len(parts) > 2 else ''
                    
                    # Верифицируем JWT
                    token_payload = self.verify_jwt(jwt_token)
                    if not token_payload:
                        conn.send(b'ERROR:Invalid or expired token')
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
                            success, message = self.receive_file(conn, addr[0], filename, size, checksum)
                            if success:
                                logging.info(f"File from {username} processed: {message}")
                            else:
                                logging.error(f"File processing error from {username}: {message}")
                        else:
                            conn.send(b'ERROR:Invalid FILE command format')
                    elif command.startswith('STREAM_FILE'):
                        # Формат: STREAM_FILE <filename> <size>
                        cmd_parts = command.split()
                        if len(cmd_parts) == 3:
                            _, filename, size = cmd_parts
                            success, message = self.receive_streaming_file(conn, addr[0], filename, size)
                            if success:
                                logging.info(f"Streaming file from {username} processed: {message}")
                            else:
                                logging.error(f"Streaming file error from {username}: {message}")
                        else:
                            conn.send(b'ERROR:Invalid STREAM_FILE command format')

                    elif command.startswith('FOLDER_START'):
                        # Format: FOLDER_START <folder_name> <file_count>
                        cmd_parts = command.split()
                        if len(cmd_parts) == 3:
                            _, folder_name, file_count = cmd_parts
                            success, message = self.handle_folder_transfer(conn, folder_name, file_count)
                            if success:
                                logging.info(f"Folder from {username} received: {message}")
                            else:
                                logging.error(f"Folder receive error from {username}: {message}")
                        else:
                            conn.send(b'ERROR:Invalid FOLDER_START command')

                    elif command.startswith('REL_FILE'):
                        # This is handled within handle_folder_transfer
                        # But we need to acknowledge it
                        conn.send(b'READY')

                    elif command == 'FOLDER_END':
                        # This is handled within receive_folder
                        pass
                    
                    elif command == 'LIST_FILES':
                        # List all files and folders in uploads directory
                        success, message = self.list_files(conn)
                        if success:
                            logging.info(f"File list sent to {username}")
                        else:
                            logging.error(f"List files error: {message}")
                    
                    elif command.startswith('DOWNLOAD_FILE'):
                        # Format: DOWNLOAD_FILE <filename>
                        cmd_parts = command.split()
                        if len(cmd_parts) == 2:
                            _, filename = cmd_parts
                            success, message = self.send_file_to_client(conn, filename)
                            if success:
                                logging.info(f"File {filename} sent to {username}: {message}")
                            else:
                                logging.error(f"File send error to {username}: {message}")
                        else:
                            conn.send(b'ERROR:Invalid DOWNLOAD_FILE command format')
                    
                    elif command.startswith('DOWNLOAD_FOLDER'):
                        # Format: DOWNLOAD_FOLDER <folder_name>
                        cmd_parts = command.split()
                        if len(cmd_parts) == 2:
                            _, folder_name = cmd_parts
                            success, message = self.send_folder_to_client(conn, folder_name)
                            if success:
                                logging.info(f"Folder {folder_name} sent to {username}: {message}")
                            else:
                                logging.error(f"Folder send error to {username}: {message}")
                        else:
                            conn.send(b'ERROR:Invalid DOWNLOAD_FOLDER command format')
                    
                    elif command.startswith('DELETE_FILE'):
                        # Format: DELETE_FILE <filename>
                        if not is_admin:
                            conn.send(b'ERROR:Permission denied. Admin only.')
                            logging.warning(f"User {username} attempted to delete file (admin only)")
                        else:
                            cmd_parts = command.split()
                            if len(cmd_parts) == 2:
                                _, filename = cmd_parts
                                success, message = self.delete_file(filename)
                                if success:
                                    logging.info(f"File {filename} deleted by {username}: {message}")
                                    conn.send(f'DELETE_OK {message}'.encode())
                                else:
                                    logging.error(f"Delete file error: {message}")
                                    conn.send(f'DELETE_FAIL {message}'.encode())
                            else:
                                conn.send(b'ERROR:Invalid DELETE_FILE command format')
                    
                    elif command.startswith('DELETE_FOLDER'):
                        # Format: DELETE_FOLDER <folder_name>
                        if not is_admin:
                            conn.send(b'ERROR:Permission denied. Admin only.')
                            logging.warning(f"User {username} attempted to delete folder (admin only)")
                        else:
                            cmd_parts = command.split()
                            if len(cmd_parts) == 2:
                                _, folder_name = cmd_parts
                                success, message = self.delete_folder(folder_name)
                                if success:
                                    logging.info(f"Folder {folder_name} deleted by {username}: {message}")
                                    conn.send(f'DELETE_OK {message}'.encode())
                                else:
                                    logging.error(f"Delete folder error: {message}")
                                    conn.send(f'DELETE_FAIL {message}'.encode())
                            else:
                                conn.send(b'ERROR:Invalid DELETE_FOLDER command format')
                    
                    elif command.startswith('RENAME_FILE'):
                        # Format: RENAME_FILE <old_name> <new_name>
                        if not is_admin:
                            conn.send(b'ERROR:Permission denied. Admin only.')
                            logging.warning(f"User {username} attempted to rename file (admin only)")
                        else:
                            cmd_parts = command.split(maxsplit=2)
                            if len(cmd_parts) == 3:
                                _, old_name, new_name = cmd_parts
                                success, message = self.rename_file(old_name, new_name)
                                if success:
                                    logging.info(f"File {old_name} renamed to {new_name} by {username}: {message}")
                                    conn.send(f'RENAME_OK {message}'.encode())
                                else:
                                    logging.error(f"Rename file error: {message}")
                                    conn.send(f'RENAME_FAIL {message}'.encode())
                            else:
                                conn.send(b'ERROR:Invalid RENAME_FILE command format')
                    
                    elif command.startswith('RENAME_FOLDER'):
                        # Format: RENAME_FOLDER <old_name> <new_name>
                        if not is_admin:
                            conn.send(b'ERROR:Permission denied. Admin only.')
                            logging.warning(f"User {username} attempted to rename folder (admin only)")
                        else:
                            cmd_parts = command.split(maxsplit=2)
                            if len(cmd_parts) == 3:
                                _, old_name, new_name = cmd_parts
                                success, message = self.rename_folder(old_name, new_name)
                                if success:
                                    logging.info(f"Folder {old_name} renamed to {new_name} by {username}: {message}")
                                    conn.send(f'RENAME_OK {message}'.encode())
                                else:
                                    logging.error(f"Rename folder error: {message}")
                                    conn.send(f'RENAME_FAIL {message}'.encode())
                            else:
                                conn.send(b'ERROR:Invalid RENAME_FOLDER command format')
                    
                    elif command == 'QUIT':
                        conn.send(b'GOODBYE')
                        break
                    
                    else:
                        conn.send(b'ERROR:Unknown command')
                        
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
    
    def handle_folder_transfer(self, conn, folder_name, file_count):
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
            
            conn.send(b'FOLDER_READY')
            logging.info(f"Ready to receive folder '{folder_name}' with {file_count} files")
            
            files_received = 0
            
            while files_received < int(file_count):
                # Receive next command
                data = conn.recv(1024).decode().strip()
                
                if data.startswith('REL_FILE'):
                    # Format: REL_FILE <relative_path> <size> <checksum>
                    parts = data.split()
                    if len(parts) == 4:
                        _, rel_path, size, checksum = parts
                        
                        # Create subdirectories if needed
                        full_path = os.path.join(folder_path, rel_path)
                        file_dir = os.path.dirname(full_path)
                        if file_dir:
                            os.makedirs(file_dir, exist_ok=True)
                        
                        # Receive the file
                        success, message = self.receive_file_to_path(conn, full_path, size, checksum)
                        
                        if success:
                            files_received += 1
                            conn.send(f'FILE_OK {checksum}'.encode())
                            logging.info(f"Received file {files_received}/{file_count}: {rel_path}")
                        else:
                            conn.send(f'FILE_FAIL {message}'.encode())
                            return False, f"File {rel_path} failed"
                    else:
                        conn.send(b'ERROR:Invalid REL_FILE command')
                        return False, "Invalid command"
                
                elif data.startswith('FOLDER_END'):
                    # Folder transfer complete
                    break
                
                else:
                    conn.send(b'ERROR:Unknown command')
                    return False, "Unknown command"
            
            # Send completion
            conn.send(f'FOLDER_COMPLETE {files_received} files received'.encode())
            return True, f"Folder '{folder_name}' received: {files_received} files"
            
        except Exception as e:
            logging.error(f"Folder receive error: {e}")
            return False, str(e)

    def receive_file_to_path(self, conn, file_path, expected_size, expected_checksum):
        """Receives a file and saves to specific path"""
        try:
            conn.send(b'READY')
            
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
    
    def list_files(self, conn):
        """Lists all files and folders in the uploads directory"""
        try:
            files_list = []
            folders_list = []
            
            if not os.path.exists(UPLOAD_DIR):
                conn.send(b'LIST_EMPTY')
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
            
            list_json = json.dumps(list_data)
            list_size = len(list_json.encode())
            
            # Send: LIST_START <size>
            conn.send(f'LIST_START {list_size}'.encode())
            
            # Wait for READY
            response = conn.recv(1024).decode().strip()
            if response != 'READY':
                return False, f"Client not ready: {response}"
            
            # Send the list
            conn.sendall(list_json.encode())
            
            # Wait for confirmation
            confirm = conn.recv(1024).decode().strip()
            if confirm.startswith('LIST_OK'):
                return True, f"List sent: {len(files_list)} files, {len(folders_list)} folders"
            else:
                return False, f"List send failed: {confirm}"
                
        except Exception as e:
            logging.error(f"List files error: {e}")
            return False, str(e)
    
    def send_file_to_client(self, conn, filename):
        """Sends a file to the client"""
        try:
            file_path = os.path.join(UPLOAD_DIR, filename)
            
            if not os.path.exists(file_path):
                conn.send(b'FILE_NOT_FOUND')
                return False, f"File not found: {filename}"
            
            if not os.path.isfile(file_path):
                conn.send(b'NOT_A_FILE')
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
            file_info = f'FILE_INFO {filename} {file_size} {checksum}'
            conn.send(file_info.encode())
            
            # Wait for READY
            response = conn.recv(1024).decode().strip()
            if response != 'READY':
                return False, f"Client not ready: {response}"
            
            # Send file data
            logging.info(f"Sending file {filename} ({file_size:,} bytes) to client")
            bytes_sent = 0
            
            with open(file_path, 'rb') as f:
                while bytes_sent < file_size:
                    chunk = f.read(65536)  # 64KB chunks
                    if not chunk:
                        break
                    conn.sendall(chunk)
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
    
    def send_folder_to_client(self, conn, folder_name):
        """Sends a folder to the client"""
        try:
            folder_path = os.path.join(UPLOAD_DIR, folder_name)
            
            if not os.path.exists(folder_path):
                conn.send(b'FOLDER_NOT_FOUND')
                return False, f"Folder not found: {folder_name}"
            
            if not os.path.isdir(folder_path):
                conn.send(b'NOT_A_FOLDER')
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
                conn.send(b'FOLDER_EMPTY')
                return False, "Folder is empty"
            
            # Send folder info: FOLDER_INFO <folder_name> <file_count>
            folder_info = f'FOLDER_INFO {folder_name} {len(all_files)}'
            conn.send(folder_info.encode())
            
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
                    file_info = f'REL_FILE_INFO {rel_path} {file_size} {checksum}'
                    conn.send(file_info.encode())
                    
                    # Wait for READY
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
            conn.send(f'FOLDER_COMPLETE {files_sent} files sent'.encode())
            
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
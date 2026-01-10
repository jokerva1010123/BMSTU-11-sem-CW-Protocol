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
from config import TCP_PORT, UDP_DATA_PORT, CHUNK_SIZE

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
        self.authenticated = False
        self.username = None
        self.jwt_token = None
    
    def connect(self):
        """Устанавливает соединение с сервером"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.server_ip, self.server_port))
            logging.info(f"Connected to {self.server_ip}:{self.server_port}")
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
                
                # Receive UDP data port
                udp_port_msg = self.sock.recv(1024).decode().strip()
                if udp_port_msg.startswith('UDP_PORT'):
                    self.udp_data_port = int(udp_port_msg.split()[1])
                    # Initialize UDP socket
                    self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
    
    def _send_command(self, command):
        """Отправляет команду с JWT токеном"""
        if not self.authenticated or not self.jwt_token:
            return False, "Not authenticated"
        
        try:
            full_command = f"TOKEN {self.jwt_token} {command}"
            self.sock.send(full_command.encode())
            return True, None
        except Exception as e:
            logging.error(f"Error sending command: {e}")
            return False, str(e)
        
    def send_large_file(self, file_path, progress_callback=None):
        """
        Оптимизированная передача больших файлов с потоковым хешированием
        """
        if not self.authenticated:
            return False, "Authentication required"
        
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        try:
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            
            logging.info(f"Preparing to send large file: {filename} ({file_size:,} bytes)")
            
            # Шаг 1: Отправляем команду начала потоковой передачи
            file_cmd = f"STREAM_FILE {filename} {file_size}"
            success, error = self._send_command(file_cmd)
            if not success:
                return False, error
            
            # Ждем подтверждения (с таймаутом)
            self.sock.settimeout(10.0)
            response = self.sock.recv(1024).decode()
            self.sock.settimeout(None)
            
            if response != 'READY_STREAM':
                return False, f"Server not ready for streaming: {response}"
            
            # Шаг 2: Потоковая передача с прогрессивным хешированием
            bytes_sent = 0
            start_time = time.time()
            last_update = start_time
            
            # Инициализируем хеш
            file_hash = hashlib.sha256()
            
            # Устанавливаем таймаут для операций записи
            self.sock.settimeout(30.0)
            
            try:
                with open(file_path, 'rb') as f:
                    while True:
                        # Читаем большими чанками (1MB оптимально для больших файлов)
                        chunk = f.read(1024 * 1024)  # 1MB
                        if not chunk:
                            break
                        
                        chunk_size = len(chunk)
                        
                        # Обновляем хеш
                        file_hash.update(chunk)
                        
                        # Отправляем размер чанка (4 байта) + данные
                        header = chunk_size.to_bytes(4, 'big')
                        
                        # Отправляем все сразу
                        self.sock.sendall(header + chunk)
                        
                        bytes_sent += chunk_size
                        
                        # Обновляем прогресс (не слишком часто, чтобы не замедлять)
                        current_time = time.time()
                        if current_time - last_update > 1.0:  # Каждую секунду
                            if progress_callback:
                                progress = (bytes_sent / file_size) * 100
                                progress_callback(progress, bytes_sent, file_size)
                            
                            # Логируем прогресс
                            elapsed = current_time - start_time
                            speed = bytes_sent / elapsed / (1024 * 1024)  # MB/s
                            mb_sent = bytes_sent / (1024 * 1024)
                            mb_total = file_size / (1024 * 1024)
                            
                            logging.info(f"Progress: {mb_sent:.1f}/{mb_total:.1f} MB ({progress:.1f}%) - {speed:.2f} MB/s")
                            last_update = current_time
                            
            except socket.timeout:
                logging.warning("Socket timeout during send, but may continue...")
                # Проверяем, может файл уже отправлен?
                if bytes_sent >= file_size:
                    logging.info("File appears to be fully sent despite timeout")
                else:
                    raise
            
            finally:
                # Восстанавливаем стандартный таймаут
                self.sock.settimeout(None)
            
            # Шаг 3: Отправляем финальный хеш
            final_hash = file_hash.hexdigest()
            hash_cmd = f"FILE_HASH {final_hash}"
            self.sock.send(hash_cmd.encode())
            
            # Шаг 4: Получаем результат
            transfer_time = time.time() - start_time
            speed = file_size / transfer_time / (1024 * 1024)  # MB/s
            
            result = self.sock.recv(1024).decode()
            
            if result.startswith('FILE_OK'):
                return True, f"Large file transferred: {speed:.2f} MB/s, time: {transfer_time:.1f}s"
            elif result.startswith('FILE_CORRUPTED'):
                return False, f"Hash mismatch detected: {result}"
            else:
                return False, f"Transfer failed: {result}"
            
        except socket.timeout:
            return False, "Transfer timeout - connection too slow or interrupted"
        except Exception as e:
            logging.error(f"Large file transfer error: {e}")
            return False, str(e)

    def send_file(self, file_path, progress_callback=None):
        """
        Умный выбор метода передачи в зависимости от размера файла
        """
        try:
            file_size = os.path.getsize(file_path)
        except:
            return False, "Cannot get file size"
        
        # Для файлов больше 100MB используем потоковый метод
        if file_size > 100 * 1024 * 1024:  # 100 MB
            print(1)
            return self.send_large_file(file_path, progress_callback)
        else:
            print(2)
            return self.send_small_file(file_path, progress_callback)

    def send_small_file(self, file_path, progress_callback=None):
        """
        Оригинальный метод для небольших файлов
        """
        if not self.authenticated:
            return False, "Authentication required"
        
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        try:
            # Получаем информацию о файле
            file_size = os.path.getsize(file_path)
            filename = os.path.basename(file_path)
            
            # Вычисляем контрольную сумму
            logging.info("Calculating file checksum...")
            file_checksum = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    file_checksum.update(chunk)
            checksum_hex = file_checksum.hexdigest()
            
            logging.info(f"Checksum: {checksum_hex[:16]}...")
            
            # Отправляем метаданные
            file_cmd = f"FILE {filename} {file_size} {checksum_hex}"
            success, error = self._send_command(file_cmd)
            if not success:
                return False, error
            
            # Ждем подтверждения от сервера
            response = self.sock.recv(1024).decode()
            if response != 'READY':
                return False, f"Server not ready: {response}"
            
            # Отправляем файл
            logging.info(f"Starting file transfer {filename} ({file_size} bytes)")
            
            bytes_sent = 0
            start_time = time.time()
            
            with open(file_path, 'rb') as f:
                while bytes_sent < file_size:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    
                    self.udp_sock.sendto(chunk, (self.server_ip, self.udp_data_port))
                    bytes_sent += len(chunk)
                    
                    # Receive ACK from TCP
                    try:
                        ack = self.sock.recv(1024).decode().strip()
                        if ack.startswith('ACK'):
                            ack_bytes = int(ack.split()[1])
                            # Optional: check if ack_bytes == bytes_sent
                    except:
                        pass  # For now, ignore
                    
                    # Вызываем callback для обновления прогресса
                    if progress_callback:
                        progress = (bytes_sent / file_size) * 100
                        progress_callback(progress, bytes_sent, file_size)
            
            # Безопасное деление
            transfer_time = time.time() - start_time
            if transfer_time > 0.001:
                speed = file_size / transfer_time / 1024  # KB/s
                speed_text = f"{speed:.2f} KB/s"
            else:
                speed_text = "very fast"
            
            logging.info(f"Transfer completed in {transfer_time:.3f} sec")
            
            # Получаем результат проверки от сервера
            result = self.sock.recv(1024).decode()
            
            if result.startswith('FILE_OK'):
                return True, f"File transferred successfully ({speed_text})"
            else:
                return False, f"Integrity error: {result}"
            
        except Exception as e:
            logging.error(f"File transfer error: {e}")
            return False, str(e)
        
    def send_folder(self, folder_path, progress_callback=None):
        """
        Sends entire folder with structure
        """
        if not os.path.isdir(folder_path):
            return False, "Not a directory"
        
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
            
            # First, send FOLDER_START command
            folder_start_cmd = f"FOLDER_START {folder_name} {len(all_files)}"
            success, error = self._send_command(folder_start_cmd)
            if not success:
                return False, error
            
            # Wait for server acknowledgement
            response = self.sock.recv(1024).decode()
            if response != 'FOLDER_READY':
                return False, f"Server not ready for folder: {response}"
            
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
            
            # Send folder completion
            self.sock.send(f"FOLDER_END {folder_name} {files_sent}".encode())
            
            # Get final confirmation
            final_response = self.sock.recv(1024).decode()
            if final_response.startswith('FOLDER_COMPLETE'):
                return True, f"Folder '{folder_name}' sent: {files_sent} files, {total_size} bytes"
            else:
                return False, f"Folder transfer incomplete: {final_response}"
            
        except Exception as e:
            logging.error(f"Folder transfer error: {e}")
            return False, str(e)

    def _send_single_file(self, file_path, rel_path, progress_callback=None):
        """Helper to send a single file with custom filename"""
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
            
            # Send file metadata with RELATIVE path
            file_cmd = f"REL_FILE {rel_path} {file_size} {checksum_hex}"
            self.sock.send(file_cmd.encode())
            
            # Wait for READY
            response = self.sock.recv(1024).decode()
            if response != 'READY':
                return False, f"Server not ready: {response}"
            
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
            
            # Get transfer result
            result = self.sock.recv(1024).decode()
            if result.startswith('FILE_OK'):
                return True, "File sent successfully"
            else:
                return False, f"Transfer failed: {result}"
            
        except Exception as e:
            return False, str(e)
    
    def list_files(self):
        """Requests and receives list of files and folders from server"""
        if not self.authenticated:
            return False, "Authentication required", None
        
        try:
            # Send LIST_FILES command
            success, error = self._send_command('LIST_FILES')
            if not success:
                return False, error, None
            
            # Receive response
            response = self.sock.recv(1024).decode().strip()
            
            if response == 'LIST_EMPTY':
                return True, "No files on server", {'files': [], 'folders': []}
            
            if not response.startswith('LIST_START'):
                return False, f"Invalid response: {response}", None
            
            # Parse list size
            parts = response.split()
            if len(parts) != 2:
                return False, "Invalid LIST_START format", None
            
            list_size = int(parts[1])
            
            # Send READY
            self.sock.send(b'READY')
            
            # Receive list data
            list_data = b''
            while len(list_data) < list_size:
                chunk = self.sock.recv(min(65536, list_size - len(list_data)))
                if not chunk:
                    break
                list_data += chunk
            
            # Parse JSON
            files_list = json.loads(list_data.decode())
            
            # Send confirmation
            self.sock.send(b'LIST_OK')
            
            return True, f"List received: {len(files_list.get('files', []))} files, {len(files_list.get('folders', []))} folders", files_list
            
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
            success, error = self._send_command(download_cmd)
            if not success:
                return False, error
            
            # Receive response
            response = self.sock.recv(1024).decode().strip()
            
            if response == 'FILE_NOT_FOUND':
                return False, f"File not found on server: {filename}"
            
            if response == 'NOT_A_FILE':
                return False, f"Not a file: {filename}"
            
            if not response.startswith('FILE_INFO'):
                return False, f"Invalid response: {response}"
            
            # Parse file info: FILE_INFO <filename> <size> <checksum>
            parts = response.split()
            if len(parts) != 4:
                return False, "Invalid FILE_INFO format"
            
            _, server_filename, file_size_str, expected_checksum = parts
            file_size = int(file_size_str)
            
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
            self.sock.send(b'READY')
            
            # Receive file data
            logging.info(f"Downloading {filename} ({file_size:,} bytes)...")
            bytes_received = 0
            file_hash = hashlib.sha256()
            start_time = time.time()
            
            with open(save_path, 'wb') as f:
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
                        progress = (bytes_received / file_size) * 100
                        progress_callback(progress, bytes_received, file_size)
            
            # Verify checksum
            actual_checksum = file_hash.hexdigest()
            
            if actual_checksum == expected_checksum:
                # Send confirmation
                self.sock.send(b'FILE_RECEIVED')
                
                transfer_time = time.time() - start_time
                speed = file_size / transfer_time / (1024 * 1024) if transfer_time > 0 else 0
                
                return True, f"File downloaded: {save_path} ({speed:.2f} MB/s)"
            else:
                os.remove(save_path)
                return False, f"Checksum mismatch. Expected: {expected_checksum[:16]}..., Got: {actual_checksum[:16]}..."
                
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
            success, error = self._send_command(download_cmd)
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
            success, error = self._send_command(delete_cmd)
            if not success:
                return False, error
            
            # Receive response
            response = self.sock.recv(1024).decode().strip()
            
            if response.startswith('DELETE_OK'):
                return True, response.replace('DELETE_OK ', '')
            elif response.startswith('DELETE_FAIL'):
                return False, response.replace('DELETE_FAIL ', '')
            elif 'Permission denied' in response:
                return False, "Permission denied: Admin only"
            else:
                return False, f"Unexpected response: {response}"
                
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
            success, error = self._send_command(delete_cmd)
            if not success:
                return False, error
            
            # Receive response
            response = self.sock.recv(1024).decode().strip()
            
            if response.startswith('DELETE_OK'):
                return True, response.replace('DELETE_OK ', '')
            elif response.startswith('DELETE_FAIL'):
                return False, response.replace('DELETE_FAIL ', '')
            elif 'Permission denied' in response:
                return False, "Permission denied: Admin only"
            else:
                return False, f"Unexpected response: {response}"
                
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
            success, error = self._send_command(rename_cmd)
            if not success:
                return False, error
            
            # Receive response
            response = self.sock.recv(1024).decode().strip()
            
            if response.startswith('RENAME_OK'):
                return True, response.replace('RENAME_OK ', '')
            elif response.startswith('RENAME_FAIL'):
                return False, response.replace('RENAME_FAIL ', '')
            elif 'Permission denied' in response:
                return False, "Permission denied: Admin only"
            else:
                return False, f"Unexpected response: {response}"
                
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
            success, error = self._send_command(rename_cmd)
            if not success:
                return False, error
            
            # Receive response
            response = self.sock.recv(1024).decode().strip()
            
            if response.startswith('RENAME_OK'):
                return True, response.replace('RENAME_OK ', '')
            elif response.startswith('RENAME_FAIL'):
                return False, response.replace('RENAME_FAIL ', '')
            elif 'Permission denied' in response:
                return False, "Permission denied: Admin only"
            else:
                return False, f"Unexpected response: {response}"
                
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
            return True
        except Exception as e:
            logging.error(f"Connection error: {e}")
            return False

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
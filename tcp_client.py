#!/usr/bin/env python3
"""
TCP File Client - Клиент для передачи файлов на сервер
"""
import socket
import os
import hashlib
import time
import logging
from config import TCP_PORT, CHUNK_SIZE

logging.basicConfig(
    level=logging.INFO,
    format='[TCP-CLIENT] %(message)s'
)

class TCPClient:
    def __init__(self, server_ip, server_port=TCP_PORT):
        self.server_ip = server_ip
        self.server_port = server_port
        self.sock = None
        self.authenticated = False
        self.username = None
    
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
            
            if auth_response == 'AUTH_OK':
                self.authenticated = True
                self.username = username
                logging.info(f"Authentication successful: {username}")
                return True
            else:
                logging.error(f"Authentication error: {auth_response}")
                return False
                
        except Exception as e:
            logging.error(f"Authentication error: {e}")
            return False
        
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
            self.sock.send(file_cmd.encode())
            
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
            self.sock.send(file_cmd.encode())
            
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
                    
                    self.sock.sendall(chunk)
                    bytes_sent += len(chunk)
                    
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
            self.sock.send(folder_start_cmd.encode())
            
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
#!/usr/bin/env python3
"""
UDP Discovery Server - Сервер обнаружения в локальной сети
"""
import socket
import threading
import time
import logging
from config import UDP_PORT, SERVER_NAME

logging.basicConfig(level=logging.INFO, format='[UDP-SERVER] %(message)s')

class UDPDiscoveryServer:
    def __init__(self, server_name=SERVER_NAME, tcp_port=9435):
        self.server_name = server_name
        self.tcp_port = tcp_port
        self.running = False
        self.sock = None
        
    def get_local_ip(self):
        """Получает локальный IP адрес более надежно"""
        try:
            # Tạo socket tạm và bind vào 0.0.0.0
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            temp_sock.bind(('0.0.0.0', 0))  # bind bất kỳ port nào
            # Lấy IP từ socket name (cách tốt hơn khi có nhiều NIC/VM)
            ip = temp_sock.getsockname()[0]
            temp_sock.close()
            if ip.startswith('127.'):
                return "127.0.0.1"
            return ip
        except Exception:
            try:
                # Fallback cũ
                temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                temp_sock.connect(("8.8.8.8", 80))
                ip = temp_sock.getsockname()[0]
                temp_sock.close()
                return ip
            except:
                return "127.0.0.1"
    
    def start(self):
        """Запускает UDP сервер обнаружения"""
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.sock.bind(('0.0.0.0', UDP_PORT))
            logging.info(f"UDP Discovery Server started on port {UDP_PORT}")
            
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    if data.decode().strip() == 'LFTP_DISCOVERY':
                        local_ip = self.get_local_ip()
                        response = f'LFTP_RESPONSE {self.server_name} {local_ip} {self.tcp_port}'
                        self.sock.sendto(response.encode(), addr)
                        logging.info(f"Responded to request from {addr[0]}:{addr[1]}")
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Request processing error: {e}")
                    
        except Exception as e:
            logging.error(f"Server start error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Останавливает сервер"""
        self.running = False
        if self.sock:
            self.sock.close()
        logging.info("UDP Discovery Server stopped")

if __name__ == "__main__":
    server = UDPDiscoveryServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
        print("\nServer stopped by user")
#!/usr/bin/env python3
"""
UDP Discovery Client - Клиент для обнаружения серверов в локальной сети
"""
import socket
import time
import logging
from config import UDP_PORT, DISCOVERY_TIMEOUT

logging.basicConfig(level=logging.INFO, format='[UDP-CLIENT] %(message)s')

class UDPDiscoveryClient:
    def __init__(self, timeout=DISCOVERY_TIMEOUT):
        self.timeout = timeout
        self.sock = None
        self.discovered_servers = []
    
    def discover(self):
        """
        Выполняет широковещательный запрос для обнаружения серверов
        """
        self.discovered_servers = []
        
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            self.sock.settimeout(self.timeout)
            
            discovery_msg = "LFTP_DISCOVERY"
            broadcast_addr = ('192.168.0.255', UDP_PORT)
            
            logging.info("Sending broadcast request...")
            for i in range(4):
                self.sock.sendto(discovery_msg.encode(), broadcast_addr)
                time.sleep(0.5 if i < 3 else 0)  # Không sleep lần cuối
            
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    decoded_data = data.decode().strip()
                    
                    if decoded_data.startswith('LFTP_RESPONSE'):
                        parts = decoded_data.split()
                        if len(parts) == 4:
                            server_info = {
                                'name': parts[1],
                                'ip': parts[2],
                                'tcp_port': int(parts[3]),
                                'discovery_addr': addr[0]
                            }
                            self.discovered_servers.append(server_info)
                            logging.info(f"Discovered server: {parts[1]} ({parts[2]}:{parts[3]})")
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Response error: {e}")
            
            logging.info(f"Discovered {len(self.discovered_servers)} servers")
            return self.discovered_servers
            
        except Exception as e:
            logging.error(f"Discovery error: {e}")
            return []
        
        finally:
            if self.sock:
                self.sock.close()
    
    def get_server_list(self):
        """Возвращает список серверов в текстовом формате"""
        servers_text = []
        for i, server in enumerate(self.discovered_servers, 1):
            servers_text.append(f"{i}. {server['name']} - {server['ip']}:{server['tcp_port']}")
        return servers_text

if __name__ == "__main__":
    client = UDPDiscoveryClient(timeout=3)
    servers = client.discover()
    
    if servers:
        print("\nDiscovered servers:")
        for server in servers:
            print(f"  • {server['name']} ({server['ip']}:{server['tcp_port']})")
    else:
        print("No servers found")
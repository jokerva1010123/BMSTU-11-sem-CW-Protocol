#!/usr/bin/env python3
"""
Test script for UDP file transfer
"""
import sys
import os
sys.path.append(os.path.dirname(__file__))

from tcp_client import TCPClient

def test_send_file():
    # Get local IP
    import socket
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    temp_sock.connect(("8.8.8.8", 80))
    local_ip = temp_sock.getsockname()[0]
    temp_sock.close()
    
    client = TCPClient(local_ip)
    if client.connect():
        if client.authenticate('admin', 'admin123'):
            # Create a test file
            with open('test_file.txt', 'w') as f:
                f.write('Hello UDP transfer!' * 1000)
            
            success, msg = client.send_file('test_file.txt')
            print(f"Send result: {success} - {msg}")
        else:
            print("Auth failed")
    else:
        print("Connect failed")

if __name__ == '__main__':
    test_send_file()
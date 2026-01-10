#!/usr/bin/env python3
"""
Configuration - Конфигурация проекта LFTP
"""

# Network settings
UDP_PORT = 9434           # Port for UDP discovery
UDP_DATA_PORT = 9436      # Port for UDP data transfer
TCP_PORT = 9435           # Port for TCP transfer
DISCOVERY_TIMEOUT = 5     # Discovery timeout in seconds
MAX_FILE_SIZE = 100 * 1024 * 1024 * 1024  # Maximum file size (100 MB)
LARGE_FILE_THRESHOLD =  100 * 1024 * 1024

# Transfer settings
CHUNK_SIZE = 65536         # Chunk size for transfer
BUFFER_SIZE = 131072          # Buffer size

# Paths
UPLOAD_DIR = "uploads"    # Directory for uploaded files
LOG_DIR = "logs"          # Directory for logs

# Server settings
SERVER_NAME = "LFTP_Server"
MAX_CLIENTS = 10          # Maximum concurrent clients

# Security settings
REQUIRE_AUTHENTICATION = True
ALLOW_ANONYMOUS = False
SESSION_TIMEOUT = 300     # Session timeout in seconds

# JWT settings
JWT_SECRET_KEY = "your-secret-key-change-this-in-production"  # Change this to a secure key
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24  # Token expires in 24 hours

# Integrity settings
CHECKSUM_ALGORITHM = "sha256"  # sha256 or md5
VERIFY_INTEGRITY = True

# Logging settings
LOG_LEVEL = "INFO"        # DEBUG, INFO, WARNING, ERROR
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# GUI colors
COLORS = {
    'primary': '#4a6fa5',
    'secondary': '#6b8cbc',
    'success': '#5cb85c',
    'warning': '#f0ad4e',
    'danger': '#d9534f',
    'light': '#f8f9fa',
    'dark': '#343a40'
}
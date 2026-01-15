#!/usr/bin/env python3
"""
Simple test script for send_file function to measure time with multiple file sizes
"""
import time
import os
import random
import string
import matplotlib.pyplot as plt
from tcp_client import TCPClient
from config import TCP_PORT

def test_send_file_multiple_sizes(server_ip, server_port=TCP_PORT, username="user", password="password"):
    """Test send_file with multiple file sizes and plot results"""

    # File sizes to test
    file_sizes = [
        1024*1024,         # 1MB
        10 * 1024 * 1024,  # 10MB
        50 * 1024 * 1024,  # 50MB
        100 * 1024 * 1024, # 100MB
        200 * 1024 * 1024  # 200MB
        , 500 * 1024 * 1024  # 500MB
        , 1000 * 1024 * 1024  # 1GB
        , 2000 * 1024 * 1024  # 2GB
        , 5000 * 1024 * 1024  # 5GB
    ]

    results = []

    try:
        # Create client
        client = TCPClient(server_ip, server_port)

        # Connect
        print("Connecting to server...")
        if not client.connect():
            print("Failed to connect")
            return

        # Authenticate
        print("Authenticating...")
        if not client.authenticate(username, password):
            print("Authentication failed")
            client.disconnect()
            return

        print("Authentication successful")

        # Test each file size
        for size in file_sizes:
            # Create test file
            test_file = f"test_file_{size//1024}KB.txt"
            print(f"Sending test file: {test_file} ({size} bytes)")

            # with open(test_file, 'w') as f:
            #     # Use simple repeating content instead of random for faster creation
            #     content = "A" * 1024  # 1KB block
            #     remaining = size
            #     while remaining > 0:
            #         chunk = min(len(content), remaining)
            #         f.write(content[:chunk])
            #         remaining -= chunk

            # Send file and measure time
            print(f"Sending {test_file}...")
            start_time = time.time()
            success, message = client.send_file(test_file)
            end_time = time.time()

            duration = end_time - start_time

            if success:
                print(f"File sent successfully in {duration:.2f} seconds")
                results.append({
                    'size_mb': size / (1024 * 1024),
                    'time': duration,
                    'size_bytes': size
                })
            else:
                print(f"Failed to send file: {message}")

            # Clean up file
            # if os.path.exists(test_file):
            #     os.remove(test_file)

        # Disconnect
        client.disconnect()

        # Plot results
        if results:
            plot_results(results)
        else:
            print("No successful transfers to plot")

    except Exception as e:
        print(f"Error: {e}")

def plot_results(results):
    """Plot file size vs send time"""
    # Sort results by size for proper line plot
    sorted_results = sorted(results, key=lambda x: x['size_mb'])
    sizes = [r['size_mb'] for r in sorted_results]
    times = [r['time'] for r in sorted_results]

    # Create larger figure for better visibility
    plt.figure(figsize=(14, 8))
    
    # Plot with better styling
    plt.plot(sizes, times, marker='o', linestyle='-', linewidth=3, markersize=10, 
             color='#d32f2f', markerfacecolor='#ff5252', markeredgecolor='#c62828', 
             markeredgewidth=2, alpha=0.8, zorder=3)
    
    plt.title('File Size vs Send Time', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('File Size (MB)', fontsize=12, fontweight='bold')
    plt.ylabel('Send Time (seconds)', fontsize=12, fontweight='bold')
    
    # Better grid
    plt.grid(True, alpha=0.4, linestyle='--', linewidth=0.8, zorder=0)
    plt.grid(True, which='major', alpha=0.6, linestyle='-', linewidth=1, zorder=1)
    
    # Format x-axis to show values in thousands for better readability
    ax = plt.gca()
    if max(sizes) > 1000:
        # Format x-axis labels (e.g., 1000 -> 1K, 2000 -> 2K)
        def format_xlabel(x, pos):
            if x >= 1000:
                return f'{x/1000:.0f}K' if x % 1000 == 0 else f'{x/1000:.1f}K'
            return f'{x:.0f}'
        ax.xaxis.set_major_formatter(plt.FuncFormatter(format_xlabel))
        ax.set_xlabel('File Size (MB, K=1000)', fontsize=12, fontweight='bold')
    
    # Set axis limits with some padding for better visibility
    x_min, x_max = min(sizes), max(sizes)
    y_min, y_max = min(times), max(times)
    plt.xlim(max(0, x_min - (x_max - x_min) * 0.05), x_max + (x_max - x_min) * 0.05)
    plt.ylim(max(0, y_min - (y_max - y_min) * 0.1), y_max + (y_max - y_min) * 0.1)
    
    # Better tick spacing
    ax.tick_params(axis='both', which='major', labelsize=10, width=1.5, length=6)
    ax.tick_params(axis='both', which='minor', labelsize=8, width=1, length=4)
    
    # Add labels for each point with better formatting
    for i, result in enumerate(sorted_results):
        size_mb = result['size_mb']
        time_sec = result['time']
        
        # Format size label (use GB for large files)
        if size_mb >= 1000:
            size_label = f"{size_mb/1000:.1f}GB"
        else:
            size_label = f"{size_mb:.0f}MB"
        
        # Format time label
        if time_sec >= 60:
            time_label = f"{time_sec/60:.1f}min"
        else:
            time_label = f"{time_sec:.1f}s"
        
        # Position annotation above or below point to avoid overlap
        offset_y = (y_max - y_min) * 0.08 if i % 2 == 0 else -(y_max - y_min) * 0.08
        
        plt.annotate(f"{size_label}\n({time_label})", 
                    (sizes[i], times[i]), 
                    xytext=(0, offset_y), 
                    textcoords='offset points',
                    fontsize=9,
                    ha='center',
                    va='bottom' if i % 2 == 0 else 'top',
                    bbox=dict(boxstyle='round,pad=0.3', facecolor='yellow', alpha=0.7, edgecolor='black', linewidth=1),
                    arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=0', color='black', lw=1))

    plt.tight_layout()
    plt.savefig('send_file_timing.png', dpi=150, bbox_inches='tight')
    plt.show()
    print("Graph saved as send_file_timing.png")

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python test_send_file.py <server_ip> [port] [username] [password]")
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2]) if len(sys.argv) > 2 else TCP_PORT
    username = sys.argv[3] if len(sys.argv) > 3 else "user"
    password = sys.argv[4] if len(sys.argv) > 4 else "password"

    test_send_file_multiple_sizes(server_ip, server_port, username, password)
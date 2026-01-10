#!/usr/bin/env python3
"""
GUI Client - Графический интерфейс для LFTP клиента
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import threading
import os
import time
from udp_discovery_client import UDPDiscoveryClient
from tcp_client import TCPClient

class LFTPClientGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("LFTP Client - Local File Transfer Protocol")
        self.root.geometry("900x750")
        
        # Настройка стилей
        self.setup_styles()
        
        # Переменные
        self.selected_server = None
        self.current_transfer = None
        self.discovery_client = UDPDiscoveryClient(timeout=3)
        self.username = None
        self.password = None
        self.authenticated = False
        self.is_admin = False
        
        # Создание интерфейса
        self.create_widgets()
        
    def setup_styles(self):
        """Настройка стилей виджетов"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Цветовая схема
        self.bg_color = '#f0f0f0'
        self.fg_color = '#333333'
        self.accent_color = '#4a6fa5'
        
        self.root.configure(bg=self.bg_color)
    
    def create_widgets(self):
        """Создание виджетов интерфейса"""
        # Заголовок
        title_frame = tk.Frame(self.root, bg=self.accent_color)
        title_frame.pack(fill='x', padx=10, pady=(10, 5))
        
        title_label = tk.Label(
            title_frame,
            text="LFTP - Local File Transfer Protocol",
            font=('Arial', 16, 'bold'),
            fg='white',
            bg=self.accent_color
        )
        title_label.pack(pady=10)
        
        # Основной контейнер
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Панель устройств
        self.create_device_panel(main_frame)
        
        # Панель передачи
        self.create_transfer_panel(main_frame)
        
        # Панель загрузки
        self.create_download_panel(main_frame)
        
        # Журнал
        self.create_log_panel(main_frame)
        
        # Статус бар
        self.create_status_bar()
    
    def create_device_panel(self, parent):
        """Панель обнаружения устройств"""
        device_frame = ttk.LabelFrame(parent, text="Discovered devices", padding=10)
        device_frame.pack(fill='x', pady=(0, 10))
        
        # Кнопки управления
        button_frame = ttk.Frame(device_frame)
        button_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(
            button_frame,
            text="Scan network",
            command=self.scan_network,
            width=15
        ).pack(side='left', padx=(0, 10))
        
        ttk.Button(
            button_frame,
            text="Refresh",
            command=self.refresh_devices,
            width=10
        ).pack(side='left')
        
        # Список устройств
        list_frame = ttk.Frame(device_frame)
        list_frame.pack(fill='both', expand=True)
        
        # Заголовки столбцов
        columns = ('name', 'ip', 'port')
        self.devices_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show='headings',
            height=6
        )
        
        # Настройка столбцов
        self.devices_tree.heading('name', text='Server name')
        self.devices_tree.heading('ip', text='IP address')
        self.devices_tree.heading('port', text='Port')
        
        self.devices_tree.column('name', width=200)
        self.devices_tree.column('ip', width=150)
        self.devices_tree.column('port', width=80)
        
        # Полоса прокрутки
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=scrollbar.set)
        
        self.devices_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Привязка события выбора
        self.devices_tree.bind('<<TreeviewSelect>>', self.on_server_select)
    
    def create_transfer_panel(self, parent):
        """Панель передачи файлов"""
        transfer_frame = ttk.LabelFrame(parent, text="File transfer", padding=10)
        transfer_frame.pack(fill='x', pady=(0, 10))
        
        # Информация о выбранном сервере
        info_frame = ttk.Frame(transfer_frame)
        info_frame.pack(fill='x', pady=(0, 10))
        
        self.server_info_label = ttk.Label(
            info_frame,
            text="Server not selected",
            font=('Arial', 10)
        )
        self.server_info_label.pack(side='left', anchor='w')
        
        # Login status label
        self.login_status_label = ttk.Label(
            info_frame,
            text="Not logged in",
            font=('Arial', 9),
            foreground='red'
        )
        self.login_status_label.pack(side='right', padx=(10, 0))
        
        # Logout button
        self.logout_btn = ttk.Button(
            info_frame,
            text="Logout",
            command=self.logout,
            width=10,
            state='disabled'
        )
        self.logout_btn.pack(side='right', padx=(5, 0))
        
        # Кнопки передачи
        button_frame = ttk.Frame(transfer_frame)
        button_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(
            button_frame,
            text="Send file",
            command=self.transfer_file,
            width=15,
            state='disabled'
        ).pack(side='left', padx=(0, 10))
        self.transfer_file_btn = button_frame.winfo_children()[0]
        
        ttk.Button(
            button_frame,
            text="Send folder",
            command=self.transfer_folder,
            width=15,
            state='disabled'
        ).pack(side='left')
        self.transfer_folder_btn = button_frame.winfo_children()[1]
        
        # Прогресс бар
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            transfer_frame,
            variable=self.progress_var,
            maximum=100,
            length=400
        )
        self.progress_bar.pack(fill='x', pady=(0, 5))
        
        # Информация о прогрессе
        self.progress_label = ttk.Label(
            transfer_frame,
            text="Ready",
            font=('Arial', 9)
        )
        self.progress_label.pack(anchor='w')
    
    def create_download_panel(self, parent):
        """Панель загрузки файлов с сервера"""
        download_frame = ttk.LabelFrame(parent, text="Download from server", padding=10)
        download_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        # Кнопки управления
        button_frame = ttk.Frame(download_frame)
        button_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(
            button_frame,
            text="Refresh file list",
            command=self.refresh_file_list,
            width=18,
            state='disabled'
        ).pack(side='left', padx=(0, 10))
        self.refresh_files_btn = button_frame.winfo_children()[0]
        
        ttk.Button(
            button_frame,
            text="Download file",
            command=self.download_file,
            width=15,
            state='disabled'
        ).pack(side='left', padx=(0, 10))
        self.download_file_btn = button_frame.winfo_children()[1]
        
        ttk.Button(
            button_frame,
            text="Download folder",
            command=self.download_folder,
            width=15,
            state='disabled'
        ).pack(side='left', padx=(0, 10))
        self.download_folder_btn = button_frame.winfo_children()[2]
        
        # Admin-only buttons
        ttk.Button(
            button_frame,
            text="Delete",
            command=self.delete_selected,
            width=12,
            state='disabled'
        ).pack(side='left', padx=(0, 10))
        self.delete_btn = button_frame.winfo_children()[3]
        
        ttk.Button(
            button_frame,
            text="Rename",
            command=self.rename_selected,
            width=12,
            state='disabled'
        ).pack(side='left')
        self.rename_btn = button_frame.winfo_children()[4]
        
        # Список файлов на сервере
        list_frame = ttk.Frame(download_frame)
        list_frame.pack(fill='both', expand=True)
        
        # Заголовки столбцов
        columns = ('name', 'type', 'size')
        self.files_tree = ttk.Treeview(
            list_frame,
            columns=columns,
            show='headings',
            height=8
        )
        
        # Настройка столбцов
        self.files_tree.heading('name', text='Name')
        self.files_tree.heading('type', text='Type')
        self.files_tree.heading('size', text='Size')
        
        self.files_tree.column('name', width=300)
        self.files_tree.column('type', width=80)
        self.files_tree.column('size', width=150)
        
        # Полоса прокрутки
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.files_tree.yview)
        self.files_tree.configure(yscrollcommand=scrollbar.set)
        
        self.files_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Привязка события выбора
        self.files_tree.bind('<<TreeviewSelect>>', self.on_file_select)
        
        # Переменная для хранения списка файлов
        self.server_files_list = None
    
    def create_log_panel(self, parent):
        """Панель журнала событий"""
        log_frame = ttk.LabelFrame(parent, text="Event log", padding=10)
        log_frame.pack(fill='both', expand=True)
        
        # Текстовое поле журнала
        self.log_text = tk.Text(
            log_frame,
            height=8,
            wrap='word',
            font=('Courier', 9)
        )
        
        # Полоса прокрутки
        scrollbar = ttk.Scrollbar(log_frame, orient='vertical', command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Кнопки очистки журнала
        clear_frame = ttk.Frame(log_frame)
        clear_frame.pack(fill='x', pady=(5, 0))
        
        ttk.Button(
            clear_frame,
            text="Clear log",
            command=self.clear_log,
            width=15
        ).pack(side='right')
    
    def create_status_bar(self):
        """Создание статус бара"""
        self.status_bar = ttk.Label(
            self.root,
            text="Ready",
            relief='sunken',
            anchor='w'
        )
        self.status_bar.pack(side='bottom', fill='x', padx=10, pady=(0, 10))
    
    def scan_network(self):
        """Сканирование сети в отдельном потоке"""
        self.log("Scanning network...")
        self.status_bar.config(text="Scanning network...")
        
        thread = threading.Thread(target=self._scan_network_thread, daemon=True)
        thread.start()
    
    def _scan_network_thread(self):
        """Поток сканирования сети"""
        try:
            servers = self.discovery_client.discover()
            
            # Обновляем интерфейс в основном потоке
            self.root.after(0, self._update_devices_list, servers)
            
            if servers:
                self.log(f"Found {len(servers)} servers")
                self.status_bar.config(text=f"Found {len(servers)} servers")
            else:
                self.log("No servers found")
                self.status_bar.config(text="No servers found")
                
        except Exception as e:
            self.log(f"Scan error: {e}")
            self.status_bar.config(text="Scan error")
    
    def _update_devices_list(self, servers):
        """Обновление списка устройств"""
        # Очищаем текущий список
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        
        # Добавляем обнаруженные серверы
        for server in servers:
            self.devices_tree.insert(
                '',
                'end',
                values=(server['name'], server['ip'], server['tcp_port'])
            )
    
    def refresh_devices(self):
        """Обновление списка устройств"""
        if self.discovery_client.discovered_servers:
            self._update_devices_list(self.discovery_client.discovered_servers)
            self.log("Device list updated")
    
    def on_server_select(self, event):
        """Обработка выбора сервера"""
        selection = self.devices_tree.selection()
        if selection:
            item = self.devices_tree.item(selection[0])
            name, ip, port = item['values']
            
            self.selected_server = {
                'name': name,
                'ip': ip,
                'port': int(port)
            }
            
            self.server_info_label.config(
                text=f"Selected server: {name} ({ip}:{port})"
            )
            
            # Reset authentication when selecting new server
            self.logout()
            
            # Prompt for login immediately
            self.login()
            
            self.log(f"Selected server: {name}")
    
    def transfer_file(self):
        """Передача файла"""
        if not self.selected_server:
            messagebox.showwarning("Warning", "Select a server first")
            return
        
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please login first")
            return
        
        # Диалог выбора файла
        file_path = filedialog.askopenfilename(
            title="Select file to transfer"
        )
        
        if not file_path:
            return
        
        # Запуск передачи в отдельном потоке
        thread = threading.Thread(
            target=self._transfer_file_thread,
            args=(file_path, self.username, self.password),
            daemon=True
        )
        thread.start()
    
    def transfer_folder(self):
        """Передача папки"""
        if not self.selected_server:
            messagebox.showwarning("Warning", "Select a server first")
            return
        
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please login first")
            return
        
        # Диалог выбора папки
        folder_path = filedialog.askdirectory(
            title="Select folder to transfer"
        )
        
        if not folder_path:
            return
        
        # Запуск передачи в отдельном потоке
        thread = threading.Thread(
            target=self._transfer_folder_thread,
            args=(folder_path, self.username, self.password),
            daemon=True
        )
        thread.start()
    
    def login(self):
        """Login to the selected server"""
        if not self.selected_server:
            messagebox.showwarning("Warning", "Select a server first")
            return False
        
        # Get authentication data
        auth_data = self.get_auth_data()
        if not auth_data:
            return False
        
        username, password = auth_data
        
        # Test authentication in a thread
        self.log("Logging in...")
        self.status_bar.config(text="Logging in...")
        
        thread = threading.Thread(
            target=self._login_thread,
            args=(username, password),
            daemon=True
        )
        thread.start()
        
        return True
    
    def _login_thread(self, username, password):
        """Thread for testing login"""
        try:
            # Create a test connection
            client = TCPClient(self.selected_server['ip'], self.selected_server['port'])
            
            if not client.connect():
                self.root.after(0, lambda: messagebox.showerror("Error", "Connection failed"))
                return False
            
            if not client.authenticate(username, password):
                client.disconnect()
                self.root.after(0, lambda: messagebox.showerror("Error", "Authentication failed"))
                return False
            
            # Login successful
            client.disconnect()
            
            # Store credentials
            self.username = username
            self.password = password
            self.authenticated = True
            self.is_admin = (username == 'admin')
            
            # Update UI
            self.root.after(0, self._update_login_status, True, username)
            self.log(f"✓ Logged in as {username}")
            if self.is_admin:
                self.log("Admin privileges enabled")
            self.status_bar.config(text=f"Logged in as {username}")
            
            return True
            
        except Exception as e:
            self.log(f"Login error: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Login error: {e}"))
            return False
    
    def logout(self):
        """Logout from the current server"""
        self.username = None
        self.password = None
        self.authenticated = False
        self.is_admin = False
        self._update_login_status(False, None)
        self.log("Logged out")
    
    def _update_login_status(self, logged_in, username=None):
        """Update login status in UI"""
        if logged_in and username:
            is_admin = (username == 'admin')
            status_text = f"Logged in as: {username}"
            if is_admin:
                status_text += " (Admin)"
            self.login_status_label.config(
                text=status_text,
                foreground='green'
            )
            self.logout_btn.config(state='normal')
            
            # Enable all buttons
            self.transfer_file_btn.config(state='normal')
            self.transfer_folder_btn.config(state='normal')
            self.refresh_files_btn.config(state='normal')
            self.download_file_btn.config(state='normal')
            self.download_folder_btn.config(state='normal')
            
            # Enable admin-only buttons if admin
            if is_admin:
                self.delete_btn.config(state='normal')
                self.rename_btn.config(state='normal')
            else:
                self.delete_btn.config(state='disabled')
                self.rename_btn.config(state='disabled')
        else:
            self.login_status_label.config(
                text="Not logged in",
                foreground='red'
            )
            self.logout_btn.config(state='disabled')
            
            # Disable all operation buttons
            self.transfer_file_btn.config(state='disabled')
            self.transfer_folder_btn.config(state='disabled')
            self.refresh_files_btn.config(state='disabled')
            self.download_file_btn.config(state='disabled')
            self.download_folder_btn.config(state='disabled')
            self.delete_btn.config(state='disabled')
            self.rename_btn.config(state='disabled')
    
    def get_auth_data(self):
        """Получение данных аутентификации"""
        # Создаем диалоговое окно
        auth_dialog = tk.Toplevel(self.root)
        auth_dialog.title("Login")
        auth_dialog.geometry("300x150")
        auth_dialog.resizable(False, False)
        auth_dialog.transient(self.root)
        auth_dialog.grab_set()
        
        # Центрируем окно
        auth_dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - auth_dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - auth_dialog.winfo_height()) // 2
        auth_dialog.geometry(f"+{x}+{y}")
        
        # Переменные
        username_var = tk.StringVar()
        password_var = tk.StringVar()
        result = [None, None]
        
        def on_ok():
            if username_var.get() and password_var.get():
                result[0] = username_var.get()
                result[1] = password_var.get()
                auth_dialog.destroy()
        
        def on_cancel():
            auth_dialog.destroy()
        
        def on_enter(event):
            on_ok()
        
        # Виджеты
        ttk.Label(auth_dialog, text="Username:").pack(pady=(10, 0))
        username_entry = ttk.Entry(auth_dialog, textvariable=username_var, width=25)
        username_entry.pack(pady=5)
        username_entry.bind('<Return>', lambda e: password_entry.focus_set())
        
        ttk.Label(auth_dialog, text="Password:").pack()
        password_entry = ttk.Entry(auth_dialog, textvariable=password_var, show='*', width=25)
        password_entry.pack(pady=5)
        password_entry.bind('<Return>', on_enter)
        
        button_frame = ttk.Frame(auth_dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Login", command=on_ok, width=10).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=on_cancel, width=10).pack(side='left', padx=5)
        
        # Фокус на поле логина
        username_entry.focus_set()
        
        # Ожидание закрытия диалога
        self.root.wait_window(auth_dialog)
        
        return tuple(result) if result[0] and result[1] else None
    
    def _transfer_file_thread(self, file_path, username, password):
        """Поток передачи файла"""
        try:
            filename = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            self.log(f"Starting file transfer: {filename} ({file_size} bytes)")
            self.status_bar.config(text=f"Transferring file: {filename}...")
            
            # Создаем клиент
            client = TCPClient(self.selected_server['ip'], self.selected_server['port'])
            
            # Устанавливаем соединение
            if not client.connect():
                self.log("Connection error")
                return
            
            # Аутентификация
            if not client.authenticate(username, password):
                self.log("Authentication error")
                client.disconnect()
                return
            
            # Callback для обновления прогресса
            def update_progress(progress, bytes_sent, total_bytes):
                self.root.after(0, self._update_progress, progress, bytes_sent, total_bytes)
            
            # Передача файла
            success, message = client.send_file(file_path, update_progress)
            
            if success:
                self.log(f"✓ {message}")
                self.status_bar.config(text="Transfer completed successfully")
                messagebox.showinfo("Success", "File transferred successfully")
            else:
                self.log(f"✗ {message}")
                self.status_bar.config(text="Transfer error")
                messagebox.showerror("Error", message)
            
            client.disconnect()
            
            # Сбрасываем прогресс
            self.root.after(0, self._reset_progress)
            
        except Exception as e:
            self.log(f"Transfer error: {e}")
            self.status_bar.config(text="Transfer error")
            self.root.after(0, self._reset_progress)
    
    def _transfer_folder_thread(self, folder_path, username, password):
        """Поток передачи папки"""
        try:
            folder_name = os.path.basename(folder_path)
            
            self.log(f"Starting folder transfer: {folder_name}")
            self.status_bar.config(text=f"Transferring folder: {folder_name}...")
            
            # В этой демо-версии передаем только первый файл
            client = TCPClient(self.selected_server['ip'], self.selected_server['port'])
            
            if not client.connect():
                self.log("Connection error")
                return
            
            if not client.authenticate(username, password):
                self.log("Authentication error")
                client.disconnect()
                return
            
            success, message = client.send_folder(folder_path)
            
            if success:
                self.log(f"✓ {message}")
                self.status_bar.config(text="Transfer completed successfully")
                messagebox.showinfo("Success", "Folder transferred successfully")
            else:
                self.log(f"✗ {message}")
                self.status_bar.config(text="Transfer error")
                messagebox.showerror("Error", message)
            
            client.disconnect()
            self.root.after(0, self._reset_progress)
            
        except Exception as e:
            self.log(f"Folder transfer error: {e}")
            self.status_bar.config(text="Transfer error")
            self.root.after(0, self._reset_progress)
    
    def _update_progress(self, progress, bytes_sent, total_bytes):
        """Обновление прогресса передачи"""
        self.progress_var.set(progress)
        
        # Форматируем размеры
        if total_bytes < 1024:
            size_text = f"{total_bytes} B"
        elif total_bytes < 1024 * 1024:
            size_text = f"{total_bytes/1024:.1f} KB"
        else:
            size_text = f"{total_bytes/(1024*1024):.1f} MB"
        
        self.progress_label.config(
            text=f"Transfer: {progress:.1f}% ({bytes_sent} / {total_bytes} bytes) [{size_text}]"
        )
    
    def _reset_progress(self):
        """Сброс прогресса"""
        self.progress_var.set(0)
        self.progress_label.config(text="Ready")
    
    def log(self, message):
        """Добавление записи в журнал"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert('end', log_entry)
        self.log_text.see('end')
        
        # Также выводим в консоль
        print(log_entry.strip())
    
    def clear_log(self):
        """Очистка журнала"""
        self.log_text.delete('1.0', 'end')
    
    def refresh_file_list(self):
        """Обновление списка файлов с сервера"""
        if not self.selected_server:
            messagebox.showwarning("Warning", "Select a server first")
            return
        
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please login first")
            return
        
        # Запуск в отдельном потоке
        thread = threading.Thread(
            target=self._refresh_file_list_thread,
            args=(self.username, self.password),
            daemon=True
        )
        thread.start()
    
    def _refresh_file_list_thread(self, username, password):
        """Поток обновления списка файлов"""
        try:
            self.log("Refreshing file list from server...")
            self.status_bar.config(text="Refreshing file list...")
            
            # Создаем клиент
            client = TCPClient(self.selected_server['ip'], self.selected_server['port'])
            
            # Устанавливаем соединение
            if not client.connect():
                self.log("Connection error")
                return
            
            # Аутентификация
            if not client.authenticate(username, password):
                self.log("Authentication error")
                client.disconnect()
                return
            
            # Получаем список файлов
            success, message, files_list = client.list_files()
            
            if success:
                self.server_files_list = files_list
                self.root.after(0, self._update_files_list, files_list)
                self.log(f"✓ {message}")
                self.status_bar.config(text="File list updated")
            else:
                self.log(f"✗ {message}")
                self.status_bar.config(text="Failed to get file list")
            
            client.disconnect()
            
        except Exception as e:
            self.log(f"Refresh file list error: {e}")
            self.status_bar.config(text="Error refreshing file list")
    
    def _update_files_list(self, files_list):
        """Обновление списка файлов в интерфейсе"""
        # Очищаем текущий список
        for item in self.files_tree.get_children():
            self.files_tree.delete(item)
        
        # Добавляем файлы
        for file_info in files_list.get('files', []):
            size_str = self._format_size(file_info['size'])
            self.files_tree.insert(
                '',
                'end',
                values=(file_info['name'], 'File', size_str),
                tags=('file',)
            )
        
        # Добавляем папки
        for folder_info in files_list.get('folders', []):
            file_count = folder_info.get('file_count', 0)
            self.files_tree.insert(
                '',
                'end',
                values=(folder_info['name'], 'Folder', f"{file_count} files"),
                tags=('folder',)
            )
        
        # Активируем кнопки загрузки
        if files_list.get('files') or files_list.get('folders'):
            self.download_file_btn.config(state='normal')
            self.download_folder_btn.config(state='normal')
    
    def _format_size(self, size_bytes):
        """Форматирование размера файла"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
    
    def on_file_select(self, event):
        """Обработка выбора файла/папки"""
        selection = self.files_tree.selection()
        if selection:
            item = self.files_tree.item(selection[0])
            name, file_type, size = item['values']
            self.log(f"Selected: {name} ({file_type})")
    
    def download_file(self):
        """Загрузка файла с сервера"""
        if not self.selected_server:
            messagebox.showwarning("Warning", "Select a server first")
            return
        
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please login first")
            return
        
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a file to download")
            return
        
        item = self.files_tree.item(selection[0])
        name, file_type, size = item['values']
        
        if file_type != 'File':
            messagebox.showwarning("Warning", "Please select a file, not a folder")
            return
        
        # Диалог выбора места сохранения
        save_path = filedialog.asksaveasfilename(
            title="Save file as",
            initialfile=name
        )
        
        if not save_path:
            return
        
        # Запуск загрузки в отдельном потоке
        thread = threading.Thread(
            target=self._download_file_thread,
            args=(name, save_path, self.username, self.password),
            daemon=True
        )
        thread.start()
    
    def download_folder(self):
        """Загрузка папки с сервера"""
        if not self.selected_server:
            messagebox.showwarning("Warning", "Select a server first")
            return
        
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please login first")
            return
        
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a folder to download")
            return
        
        item = self.files_tree.item(selection[0])
        name, file_type, size = item['values']
        
        if file_type != 'Folder':
            messagebox.showwarning("Warning", "Please select a folder, not a file")
            return
        
        # Диалог выбора места сохранения
        save_path = filedialog.askdirectory(
            title="Select folder to save to"
        )
        
        if not save_path:
            return
        
        # Запуск загрузки в отдельном потоке
        thread = threading.Thread(
            target=self._download_folder_thread,
            args=(name, save_path, self.username, self.password),
            daemon=True
        )
        thread.start()
    
    def _download_file_thread(self, filename, save_path, username, password):
        """Поток загрузки файла"""
        try:
            self.log(f"Starting file download: {filename}")
            self.status_bar.config(text=f"Downloading file: {filename}...")
            
            # Создаем клиент
            client = TCPClient(self.selected_server['ip'], self.selected_server['port'])
            
            # Устанавливаем соединение
            if not client.connect():
                self.log("Connection error")
                return
            
            # Аутентификация
            if not client.authenticate(username, password):
                self.log("Authentication error")
                client.disconnect()
                return
            
            # Callback для обновления прогресса
            def update_progress(progress, bytes_received, total_bytes):
                self.root.after(0, self._update_progress, progress, bytes_received, total_bytes)
            
            # Загрузка файла
            success, message = client.download_file(filename, save_path, update_progress)
            
            if success:
                self.log(f"✓ {message}")
                self.status_bar.config(text="Download completed successfully")
                messagebox.showinfo("Success", f"File downloaded successfully!\n{save_path}")
            else:
                self.log(f"✗ {message}")
                self.status_bar.config(text="Download error")
                messagebox.showerror("Error", message)
            
            client.disconnect()
            self.root.after(0, self._reset_progress)
            
        except Exception as e:
            self.log(f"Download error: {e}")
            self.status_bar.config(text="Download error")
            self.root.after(0, self._reset_progress)
    
    def _download_folder_thread(self, folder_name, save_path, username, password):
        """Поток загрузки папки"""
        try:
            self.log(f"Starting folder download: {folder_name}")
            self.status_bar.config(text=f"Downloading folder: {folder_name}...")
            
            # Создаем клиент
            client = TCPClient(self.selected_server['ip'], self.selected_server['port'])
            
            # Устанавливаем соединение
            if not client.connect():
                self.log("Connection error")
                return
            
            # Аутентификация
            if not client.authenticate(username, password):
                self.log("Authentication error")
                client.disconnect()
                return
            
            # Callback для обновления прогресса
            def update_progress(progress, bytes_received, total_bytes):
                self.root.after(0, self._update_progress, progress, bytes_received, total_bytes)
            
            # Загрузка папки
            full_save_path = os.path.join(save_path, folder_name)
            success, message = client.download_folder(folder_name, full_save_path, update_progress)
            
            if success:
                self.log(f"✓ {message}")
                self.status_bar.config(text="Download completed successfully")
                messagebox.showinfo("Success", f"Folder downloaded successfully!\n{full_save_path}")
            else:
                self.log(f"✗ {message}")
                self.status_bar.config(text="Download error")
                messagebox.showerror("Error", message)
            
            client.disconnect()
            self.root.after(0, self._reset_progress)
            
        except Exception as e:
            self.log(f"Folder download error: {e}")
            self.status_bar.config(text="Download error")
            self.root.after(0, self._reset_progress)
    
    def delete_selected(self):
        """Delete selected file or folder from server"""
        if not self.selected_server:
            messagebox.showwarning("Warning", "Select a server first")
            return
        
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please login first")
            return
        
        if not self.is_admin:
            messagebox.showwarning("Warning", "Admin privileges required")
            return
        
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a file or folder to delete")
            return
        
        item = self.files_tree.item(selection[0])
        name, file_type, size = item['values']
        
        # Confirm deletion
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete {file_type.lower()} '{name}'?\n\nThis action cannot be undone!",
            icon='warning'
        )
        
        if not confirm:
            return
        
        # Start deletion in thread
        thread = threading.Thread(
            target=self._delete_thread,
            args=(name, file_type),
            daemon=True
        )
        thread.start()
    
    def _delete_thread(self, name, file_type):
        """Thread for deleting file/folder"""
        try:
            self.log(f"Deleting {file_type.lower()}: {name}...")
            self.status_bar.config(text=f"Deleting {file_type.lower()}...")
            
            # Create client
            client = TCPClient(self.selected_server['ip'], self.selected_server['port'])
            
            if not client.connect():
                self.log("Connection error")
                return
            
            if not client.authenticate(self.username, self.password):
                self.log("Authentication error")
                client.disconnect()
                return
            
            # Delete based on type
            if file_type == 'File':
                success, message = client.delete_file(name)
            else:
                success, message = client.delete_folder(name)
            
            if success:
                self.log(f"✓ {message}")
                self.status_bar.config(text="Delete completed")
                messagebox.showinfo("Success", f"{file_type} deleted successfully")
                # Refresh file list
                self.root.after(0, self.refresh_file_list)
            else:
                self.log(f"✗ {message}")
                self.status_bar.config(text="Delete failed")
                messagebox.showerror("Error", message)
            
            client.disconnect()
            
        except Exception as e:
            self.log(f"Delete error: {e}")
            self.status_bar.config(text="Delete error")
            messagebox.showerror("Error", f"Delete error: {e}")
    
    def rename_selected(self):
        """Rename selected file or folder on server"""
        if not self.selected_server:
            messagebox.showwarning("Warning", "Select a server first")
            return
        
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please login first")
            return
        
        if not self.is_admin:
            messagebox.showwarning("Warning", "Admin privileges required")
            return
        
        selection = self.files_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Select a file or folder to rename")
            return
        
        item = self.files_tree.item(selection[0])
        name, file_type, size = item['values']
        
        # Get new name
        new_name = simpledialog.askstring(
            "Rename",
            f"Enter new name for {file_type.lower()} '{name}':",
            initialvalue=name
        )
        
        if not new_name or new_name == name:
            return
        
        # Validate name
        if '/' in new_name or '\\' in new_name:
            messagebox.showerror("Error", "Invalid name: Cannot contain / or \\")
            return
        
        # Start rename in thread
        thread = threading.Thread(
            target=self._rename_thread,
            args=(name, new_name, file_type),
            daemon=True
        )
        thread.start()
    
    def _rename_thread(self, old_name, new_name, file_type):
        """Thread for renaming file/folder"""
        try:
            self.log(f"Renaming {file_type.lower()}: {old_name} -> {new_name}...")
            self.status_bar.config(text=f"Renaming {file_type.lower()}...")
            
            # Create client
            client = TCPClient(self.selected_server['ip'], self.selected_server['port'])
            
            if not client.connect():
                self.log("Connection error")
                return
            
            if not client.authenticate(self.username, self.password):
                self.log("Authentication error")
                client.disconnect()
                return
            
            # Rename based on type
            if file_type == 'File':
                success, message = client.rename_file(old_name, new_name)
            else:
                success, message = client.rename_folder(old_name, new_name)
            
            if success:
                self.log(f"✓ {message}")
                self.status_bar.config(text="Rename completed")
                messagebox.showinfo("Success", f"{file_type} renamed successfully")
                # Refresh file list
                self.root.after(0, self.refresh_file_list)
            else:
                self.log(f"✗ {message}")
                self.status_bar.config(text="Rename failed")
                messagebox.showerror("Error", message)
            
            client.disconnect()
            
        except Exception as e:
            self.log(f"Rename error: {e}")
            self.status_bar.config(text="Rename error")
            messagebox.showerror("Error", f"Rename error: {e}")
    
    def run(self):
        """Запуск приложения"""
        self.root.mainloop()

if __name__ == "__main__":
    app = LFTPClientGUI()
    app.run()
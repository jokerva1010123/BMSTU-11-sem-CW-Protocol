#!/usr/bin/env python3
"""
GUI Client - Графический интерфейс для LFTP клиента
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import os
import time
from udp_discovery_client import UDPDiscoveryClient
from tcp_client import TCPClient

class LFTPClientGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("LFTP Client - Local File Transfer Protocol")
        self.root.geometry("800x600")
        
        # Настройка стилей
        self.setup_styles()
        
        # Переменные
        self.selected_server = None
        self.current_transfer = None
        self.discovery_client = UDPDiscoveryClient(timeout=3)
        
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
        self.server_info_label.pack(anchor='w')
        
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
            
            # Активируем кнопки передачи
            self.transfer_file_btn.config(state='normal')
            self.transfer_folder_btn.config(state='normal')
            
            self.log(f"Selected server: {name}")
    
    def transfer_file(self):
        """Передача файла"""
        if not self.selected_server:
            messagebox.showwarning("Warning", "Select a server first")
            return
        
        # Диалог выбора файла
        file_path = filedialog.askopenfilename(
            title="Select file to transfer"
        )
        
        if not file_path:
            return
        
        # Диалог аутентификации
        auth_data = self.get_auth_data()
        if not auth_data:
            return
        
        username, password = auth_data
        
        # Запуск передачи в отдельном потоке
        thread = threading.Thread(
            target=self._transfer_file_thread,
            args=(file_path, username, password),
            daemon=True
        )
        thread.start()
    
    def transfer_folder(self):
        """Передача папки"""
        if not self.selected_server:
            messagebox.showwarning("Warning", "Select a server first")
            return
        
        # Диалог выбора папки
        folder_path = filedialog.askdirectory(
            title="Select folder to transfer"
        )
        
        if not folder_path:
            return
        
        # Диалог аутентификации
        auth_data = self.get_auth_data()
        if not auth_data:
            return
        
        username, password = auth_data
        
        # Запуск передачи в отдельном потоке
        thread = threading.Thread(
            target=self._transfer_folder_thread,
            args=(folder_path, username, password),
            daemon=True
        )
        thread.start()
    
    def get_auth_data(self):
        """Получение данных аутентификации"""
        # Создаем диалоговое окно
        auth_dialog = tk.Toplevel(self.root)
        auth_dialog.title("Authentication")
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
        
        # Виджеты
        ttk.Label(auth_dialog, text="Username:").pack(pady=(10, 0))
        username_entry = ttk.Entry(auth_dialog, textvariable=username_var, width=25)
        username_entry.pack(pady=5)
        
        ttk.Label(auth_dialog, text="Password:").pack()
        password_entry = ttk.Entry(auth_dialog, textvariable=password_var, show='*', width=25)
        password_entry.pack(pady=5)
        
        button_frame = ttk.Frame(auth_dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="OK", command=on_ok, width=10).pack(side='left', padx=5)
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
    
    def run(self):
        """Запуск приложения"""
        self.root.mainloop()

if __name__ == "__main__":
    app = LFTPClientGUI()
    app.run()
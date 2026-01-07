#!/usr/bin/env python3
"""
Checksum Utilities - Утилиты для проверки целостности данных
"""
import hashlib
import os
import json
from datetime import datetime

class IntegrityChecker:
    """Класс для проверки целостности файлов и данных"""
    
    @staticmethod
    def compute_sha256(file_path_or_data, is_data=False):
        """
        Вычисляет SHA-256 хеш
        
        Args:
            file_path_or_data: путь к файлу или бинарные данные
            is_data: True если переданы данные, False если путь к файлу
            
        Returns:
            Строка с hex-представлением хеша
        """
        sha256 = hashlib.sha256()
        
        if is_data:
            # Для бинарных данных
            sha256.update(file_path_or_data)
        else:
            # Для файла
            try:
                with open(file_path_or_data, 'rb') as f:
                    while chunk := f.read(8192):
                        sha256.update(chunk)
            except Exception as e:
                raise ValueError(f"File read error: {e}")
        
        return sha256.hexdigest()
    
    @staticmethod
    def compute_md5(file_path_or_data, is_data=False):
        """
        Вычисляет MD5 хеш (для быстрой проверки)
        """
        md5 = hashlib.md5()
        
        if is_data:
            md5.update(file_path_or_data)
        else:
            try:
                with open(file_path_or_data, 'rb') as f:
                    while chunk := f.read(8192):
                        md5.update(chunk)
            except Exception as e:
                raise ValueError(f"File read error: {e}")
        
        return md5.hexdigest()
    
    @staticmethod
    def verify_file_integrity(file_path, expected_checksum, algorithm='sha256'):
        """
        Проверяет целостность файла
        
        Args:
            file_path: путь к файлу
            expected_checksum: ожидаемый хеш
            algorithm: 'sha256' или 'md5'
            
        Returns:
            (bool, str): успех проверки и фактический хеш
        """
        try:
            if algorithm == 'sha256':
                actual_checksum = IntegrityChecker.compute_sha256(file_path)
            elif algorithm == 'md5':
                actual_checksum = IntegrityChecker.compute_md5(file_path)
            else:
                raise ValueError(f"Unknown algorithm: {algorithm}")
            
            return actual_checksum == expected_checksum, actual_checksum
            
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def verify_data_integrity(data, expected_checksum, algorithm='sha256'):
        """
        Проверяет целостность данных в памяти
        """
        try:
            if algorithm == 'sha256':
                actual_checksum = IntegrityChecker.compute_sha256(data, is_data=True)
            elif algorithm == 'md5':
                actual_checksum = IntegrityChecker.compute_md5(data, is_data=True)
            else:
                raise ValueError(f"Unknown algorithm: {algorithm}")
            
            return actual_checksum == expected_checksum, actual_checksum
            
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def create_integrity_report(folder_path, output_file=None):
        """
        Создает отчет о целостности всех файлов в папке
        
        Args:
            folder_path: путь к папке
            output_file: путь для сохранения отчета (JSON)
            
        Returns:
            Словарь с отчетами по файлам
        """
        if not os.path.isdir(folder_path):
            raise ValueError(f"Not a directory: {folder_path}")
        
        report = {
            'generated_at': datetime.now().isoformat(),
            'folder': os.path.abspath(folder_path),
            'files': {}
        }
        
        for root, dirs, files in os.walk(folder_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                try:
                    # Пропускаем скрытые файлы и файлы метаданных
                    if filename.startswith('.') or filename.endswith('.meta'):
                        continue
                    
                    file_stats = os.stat(file_path)
                    checksum_sha256 = IntegrityChecker.compute_sha256(file_path)
                    checksum_md5 = IntegrityChecker.compute_md5(file_path)
                    
                    relative_path = os.path.relpath(file_path, folder_path)
                    
                    report['files'][relative_path] = {
                        'size': file_stats.st_size,
                        'modified': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                        'sha256': checksum_sha256,
                        'md5': checksum_md5,
                        'absolute_path': file_path
                    }
                    
                except Exception as e:
                    report['files'][filename] = {
                        'error': str(e)
                    }
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
            except Exception as e:
                print(f"Error saving report: {e}")
        
        return report
    
    @staticmethod
    def compare_reports(report1, report2):
        """
        Сравнивает два отчета целостности
        
        Returns:
            Словарь с результатами сравнения
        """
        comparison = {
            'identical_files': [],
            'different_files': [],
            'missing_in_report1': [],
            'missing_in_report2': []
        }
        
        files1 = set(report1.get('files', {}).keys())
        files2 = set(report2.get('files', {}).keys())
        
        # Файлы, отсутствующие в одном из отчетов
        comparison['missing_in_report1'] = list(files2 - files1)
        comparison['missing_in_report2'] = list(files1 - files2)
        
        # Общие файлы
        common_files = files1.intersection(files2)
        
        for filename in common_files:
            file1 = report1['files'][filename]
            file2 = report2['files'][filename]
            
            if 'error' in file1 or 'error' in file2:
                comparison['different_files'].append({
                    'file': filename,
                    'reason': 'Error in one of reports'
                })
            elif file1.get('sha256') == file2.get('sha256'):
                comparison['identical_files'].append(filename)
            else:
                comparison['different_files'].append({
                    'file': filename,
                    'size1': file1.get('size'),
                    'size2': file2.get('size'),
                    'sha256_1': file1.get('sha256', '')[:16] + '...',
                    'sha256_2': file2.get('sha256', '')[:16] + '...'
                })
        
        return comparison

# Демонстрация работы
if __name__ == "__main__":
    print("IntegrityChecker demo")
    print("=" * 50)
    
    # Создаем тестовый файл
    test_file = "test_integrity.txt"
    with open(test_file, 'w') as f:
        f.write("This is a test file for data integrity check.\n")
        f.write("Second line of the file.\n")
    
    # Вычисляем хеши
    sha256_hash = IntegrityChecker.compute_sha256(test_file)
    md5_hash = IntegrityChecker.compute_md5(test_file)
    
    print(f"File: {test_file}")
    print(f"SHA-256: {sha256_hash}")
    print(f"MD5: {md5_hash}")
    print()
    
    # Проверяем целостность
    valid, actual_hash = IntegrityChecker.verify_file_integrity(test_file, sha256_hash)
    print(f"Integrity check (SHA-256): {'PASSED' if valid else 'FAILED'}")
    print(f"Actual hash: {actual_hash[:32]}...")
    print()
    
    # Создаем отчет
    print("Creating integrity report for current directory...")
    report = IntegrityChecker.create_integrity_report('.', 'integrity_report.json')
    print(f"Files checked: {len(report['files'])}")
    
    # Удаляем тестовый файл
    os.remove(test_file)
    print(f"\nTest file {test_file} removed")
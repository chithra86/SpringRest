#!/usr/bin/env python3
"""
Approach 4: Database-Native Bulk Loading
Using database-specific COPY, LOAD DATA, BULK INSERT commands
Optimized by the database engine - usually fastest approach
"""

import csv
import psycopg2
import mysql.connector
import pyodbc
import time
import os
from contextlib import contextmanager
from typing import Dict, Any, Union
from abc import ABC, abstractmethod

class DatabaseBulkLoader(ABC):
    """Abstract base class for database-specific bulk loaders"""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
    
    @abstractmethod
    def get_connection(self):
        pass
    
    @abstractmethod
    def bulk_load_csv(self, csv_file_path: str, table_name: str, **kwargs) -> Dict[str, Any]:
        pass
    
    @abstractmethod
    def create_test_table(self, table_name: str):
        pass

class PostgreSQLBulkLoader(DatabaseBulkLoader):
    """PostgreSQL-specific bulk loader using COPY command"""
    
    @contextmanager
    def get_connection(self):
        conn = None
        try:
            conn = psycopg2.connect(self.connection_string)
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def bulk_load_csv(self, csv_file_path: str, table_name: str, 
                     delimiter: str = ',', has_header: bool = True,
                     null_string: str = '', quote_char: str = '"') -> Dict[str, Any]:
        """
        Bulk load CSV using PostgreSQL COPY command
        This is typically the fastest way to load data into PostgreSQL
        """
        start_time = time.time()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Start transaction
                conn.autocommit = False
                
                abs_csv_path = os.path.abspath(csv_file_path)
                print(f"Starting PostgreSQL COPY from {abs_csv_path}")
                
                # Build COPY command
                copy_options = [
                    f"DELIMITER '{delimiter}'",
                    f"NULL '{null_string}'",
                    f"QUOTE '{quote_char}'",
                    "CSV"
                ]
                
                if has_header:
                    copy_options.append("HEADER")
                
                copy_sql = f"""
                    COPY {table_name} FROM '{abs_csv_path}' 
                    WITH ({', '.join(copy_options)})
                """
                
                print(f"Executing: {copy_sql}")
                cursor.execute(copy_sql)
                
                records_loaded = cursor.rowcount
                
                # Commit transaction
                conn.commit()
                
                end_time = time.time()
                duration = end_time - start_time
                
                result = {
                    'success': True,
                    'database': 'PostgreSQL',
                    'method': 'COPY',
                    'records_loaded': records_loaded,
                    'duration_seconds': duration,
                    'load_rate': records_loaded / duration if duration > 0 else 0,
                    'table_name': table_name
                }
                
                print(f"PostgreSQL COPY SUCCESS: {records_loaded} records in {duration:.2f}s")
                print(f"Load rate: {result['load_rate']:.0f} records/second")
                
                return result
                
        except Exception as e:
            print(f"PostgreSQL COPY FAILED: {str(e)}")
            return {
                'success': False,
                'database': 'PostgreSQL',
                'method': 'COPY',
                'error': str(e),
                'records_loaded': 0
            }
    
    def bulk_load_csv_from_memory(self, csv_file_path: str, table_name: str) -> Dict[str, Any]:
        """
        Alternative method: COPY FROM STDIN for more control
        """
        start_time = time.time()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                conn.autocommit = False
                
                print(f"Starting PostgreSQL COPY FROM STDIN")
                
                with open(csv_file_path, 'r') as f:
                    # Skip header
                    next(f)
                    
                    # Use copy_expert for COPY FROM STDIN
                    cursor.copy_expert(f"COPY {table_name} FROM STDIN WITH CSV", f)
                
                records_loaded = cursor.rowcount
                conn.commit()
                
                end_time = time.time()
                duration = end_time - start_time
                
                result = {
                    'success': True,
                    'database': 'PostgreSQL',
                    'method': 'COPY FROM STDIN',
                    'records_loaded': records_loaded,
                    'duration_seconds': duration,
                    'load_rate': records_loaded / duration if duration > 0 else 0
                }
                
                print(f"PostgreSQL COPY FROM STDIN SUCCESS: {records_loaded} records in {duration:.2f}s")
                return result
                
        except Exception as e:
            print(f"PostgreSQL COPY FROM STDIN FAILED: {str(e)}")
            return {
                'success': False,
                'database': 'PostgreSQL',
                'method': 'COPY FROM STDIN',
                'error': str(e),
                'records_loaded': 0
            }
    
    def create_test_table(self, table_name: str):
        """Create PostgreSQL test table"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100),
                    email VARCHAR(100),
                    age INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

class MySQLBulkLoader(DatabaseBulkLoader):
    """MySQL-specific bulk loader using LOAD DATA INFILE"""
    
    @contextmanager
    def get_connection(self):
        conn = None
        try:
            # Parse connection string (simplified for demo)
            # In practice, you'd parse the full connection string
            conn = mysql.connector.connect(
                host='localhost',
                user='user',
                password='password',
                database='testdb'
            )
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def bulk_load_csv(self, csv_file_path: str, table_name: str,
                     delimiter: str = ',', has_header: bool = True,
                     local_file: bool = True) -> Dict[str, Any]:
        """
        Bulk load CSV using MySQL LOAD DATA INFILE
        """
        start_time = time.time()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Start transaction
                conn.autocommit = False
                
                abs_csv_path = os.path.abspath(csv_file_path)
                print(f"Starting MySQL LOAD DATA INFILE from {abs_csv_path}")
                
                # Build LOAD DATA INFILE command
                local_keyword = "LOCAL" if local_file else ""
                
                load_sql = f"""
                    LOAD DATA {local_keyword} INFILE '{abs_csv_path}'
                    INTO TABLE {table_name}
                    FIELDS TERMINATED BY '{delimiter}'
                    LINES TERMINATED BY '\\n'
                """
                
                if has_header:
                    load_sql += " IGNORE 1 LINES"
                
                print(f"Executing: {load_sql}")
                cursor.execute(load_sql)
                
                records_loaded = cursor.rowcount
                
                # Commit transaction
                conn.commit()
                
                end_time = time.time()
                duration = end_time - start_time
                
                result = {
                    'success': True,
                    'database': 'MySQL',
                    'method': 'LOAD DATA INFILE',
                    'records_loaded': records_loaded,
                    'duration_seconds': duration,
                    'load_rate': records_loaded / duration if duration > 0 else 0
                }
                
                print(f"MySQL LOAD DATA SUCCESS: {records_loaded} records in {duration:.2f}s")
                return result
                
        except Exception as e:
            print(f"MySQL LOAD DATA FAILED: {str(e)}")
            return {
                'success': False,
                'database': 'MySQL',
                'method': 'LOAD DATA INFILE',
                'error': str(e),
                'records_loaded': 0
            }
    
    def create_test_table(self, table_name: str):
        """Create MySQL test table"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100),
                    email VARCHAR(100),
                    age INT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

class SQLServerBulkLoader(DatabaseBulkLoader):
    """SQL Server-specific bulk loader using BULK INSERT"""
    
    @contextmanager
    def get_connection(self):
        conn = None
        try:
            # Example connection string for SQL Server
            conn = pyodbc.connect(self.connection_string)
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def bulk_load_csv(self, csv_file_path: str, table_name: str,
                     delimiter: str = ',', has_header: bool = True) -> Dict[str, Any]:
        """
        Bulk load CSV using SQL Server BULK INSERT
        """
        start_time = time.time()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                abs_csv_path = os.path.abspath(csv_file_path)
                print(f"Starting SQL Server BULK INSERT from {abs_csv_path}")
                
                # Build BULK INSERT command
                bulk_options = [
                    f"FIELDTERMINATOR = '{delimiter}'",
                    "ROWTERMINATOR = '\\n'"
                ]
                
                if has_header:
                    bulk_options.append("FIRSTROW = 2")
                
                bulk_sql = f"""
                    BULK INSERT {table_name}
                    FROM '{abs_csv_path}'
                    WITH ({', '.join(bulk_options)})
                """
                
                print(f"Executing: {bulk_sql}")
                cursor.execute(bulk_sql)
                
                # Get record count (SQL Server doesn't return rowcount for BULK INSERT)
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                records_loaded = cursor.fetchone()[0]
                
                conn.commit()
                
                end_time = time.time()
                duration = end_time - start_time
                
                result = {
                    'success': True,
                    'database': 'SQL Server',
                    'method': 'BULK INSERT',
                    'records_loaded': records_loaded,
                    'duration_seconds': duration,
                    'load_rate': records_loaded / duration if duration > 0 else 0
                }
                
                print(f"SQL Server BULK INSERT SUCCESS: {records_loaded} records in {duration:.2f}s")
                return result
                
        except Exception as e:
            print(f"SQL Server BULK INSERT FAILED: {str(e)}")
            return {
                'success': False,
                'database': 'SQL Server',
                'method': 'BULK INSERT',
                'error': str(e),
                'records_loaded': 0
            }
    
    def create_test_table(self, table_name: str):
        """Create SQL Server test table"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='{table_name}' AND xtype='U')
                CREATE TABLE {table_name} (
                    id INT IDENTITY(1,1) PRIMARY KEY,
                    name NVARCHAR(100),
                    email NVARCHAR(100),
                    age INT,
                    created_at DATETIME2 DEFAULT GETDATE()
                )
            """)
            conn.commit()

class UniversalBulkLoader:
    """Universal bulk loader that detects database type and uses appropriate method"""
    
    def __init__(self, connection_string: str, database_type: str = 'postgresql'):
        self.connection_string = connection_string
        self.database_type = database_type.lower()
        self.loader = self._get_loader()
    
    def _get_loader(self) -> DatabaseBulkLoader:
        """Get appropriate loader based on database type"""
        if self.database_type == 'postgresql':
            return PostgreSQLBulkLoader(self.connection_string)
        elif self.database_type == 'mysql':
            return MySQLBulkLoader(self.connection_string)
        elif self.database_type == 'sqlserver':
            return SQLServerBulkLoader(self.connection_string)
        else:
            raise ValueError(f"Unsupported database type: {self.database_type}")
    
    def bulk_load_with_transaction(self, csv_file_path: str, table_name: str) -> Dict[str, Any]:
        """
        Perform bulk load with full transaction semantics (all-or-nothing)
        """
        print(f"Starting bulk load with {self.database_type} loader")
        
        # Create table if needed
        try:
            self.loader.create_test_table(table_name)
        except Exception as e:
            print(f"Warning: Could not create table: {e}")
        
        # Perform bulk load
        result = self.loader.bulk_load_csv(csv_file_path, table_name)
        
        return result
    
    def bulk_load_with_validation(self, csv_file_path: str, table_name: str,
                                 validate_before: bool = True,
                                 validate_after: bool = True) -> Dict[str, Any]:
        """
        Bulk load with pre and post validation
        """
        overall_start_time = time.time()
        
        if validate_before:
            validation_result = self._validate_csv_file(csv_file_path)
            if not validation_result['is_valid']:
                return {
                    'success': False,
                    'error': 'Pre-validation failed',
                    'validation_errors': validation_result['errors']
                }
        
        # Perform bulk load
        load_result = self.bulk_load_with_transaction(csv_file_path, table_name)
        
        if not load_result['success']:
            return load_result
        
        if validate_after:
            post_validation = self._validate_loaded_data(table_name, load_result['records_loaded'])
            if not post_validation['is_valid']:
                return {
                    'success': False,
                    'error': 'Post-validation failed',
                    'load_result': load_result,
                    'validation_errors': post_validation['errors']
                }
        
        overall_end_time = time.time()
        load_result['total_duration_seconds'] = overall_end_time - overall_start_time
        
        return load_result
    
    def _validate_csv_file(self, csv_file_path: str) -> Dict[str, Any]:
        """Validate CSV file before loading"""
        errors = []
        
        try:
            with open(csv_file_path, 'r') as f:
                # Check if file is readable
                first_line = f.readline()
                if not first_line:
                    errors.append("CSV file is empty")
                
                # Basic format validation
                csv_reader = csv.reader(f)
                row_count = 0
                for row in csv_reader:
                    row_count += 1
                    if row_count > 1000:  # Sample first 1000 rows
                        break
                
                if row_count == 0:
                    errors.append("No data rows found in CSV")
                
        except Exception as e:
            errors.append(f"CSV validation error: {str(e)}")
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors
        }
    
    def _validate_loaded_data(self, table_name: str, expected_count: int) -> Dict[str, Any]:
        """Validate data after loading"""
        errors = []
        
        try:
            with self.loader.get_connection() as conn:
                cursor = conn.cursor()
                
                # Check record count
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                actual_count = cursor.fetchone()[0]
                
                if actual_count != expected_count:
                    errors.append(f"Record count mismatch: expected {expected_count}, got {actual_count}")
                
                # Additional validations can be added here
                
        except Exception as e:
            errors.append(f"Post-load validation error: {str(e)}")
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors
        }

def generate_test_csv(filename: str, num_records: int = 100000):
    """Generate test CSV file"""
    import random
    import string
    
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['name', 'email', 'age'])
        
        for i in range(num_records):
            name = ''.join(random.choices(string.ascii_letters, k=10))
            email = f"{name.lower()}{i}@example.com"
            age = random.randint(18, 80)
            writer.writerow([name, email, age])
    
    print(f"Generated {filename} with {num_records} records")

def compare_database_performance():
    """Compare performance across different database engines"""
    
    CSV_FILE = "performance_test.csv"
    TABLE_NAME = "performance_test"
    RECORD_COUNT = 50000
    
    # Generate test data
    generate_test_csv(CSV_FILE, RECORD_COUNT)
    
    # Database configurations
    databases = [
        {
            'name': 'PostgreSQL',
            'type': 'postgresql',
            'connection': 'postgresql://user:password@localhost:5432/testdb'
        },
        # Add other databases as needed
        # {
        #     'name': 'MySQL',
        #     'type': 'mysql',
        #     'connection': 'mysql://user:password@localhost:3306/testdb'
        # }
    ]
    
    results = []
    
    for db_config in databases:
        try:
            print(f"\n{'='*50}")
            print(f"Testing {db_config['name']}")
            print(f"{'='*50}")
            
            loader = UniversalBulkLoader(db_config['connection'], db_config['type'])
            result = loader.bulk_load_with_validation(CSV_FILE, TABLE_NAME)
            
            if result['success']:
                results.append({
                    'database': db_config['name'],
                    'records': result['records_loaded'],
                    'duration': result['duration_seconds'],
                    'rate': result['load_rate']
                })
                
                print(f"{db_config['name']} Results:")
                print(f"  Records: {result['records_loaded']}")
                print(f"  Duration: {result['duration_seconds']:.2f}s")
                print(f"  Rate: {result['load_rate']:.0f} records/second")
            else:
                print(f"{db_config['name']} FAILED: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            print(f"{db_config['name']} ERROR: {str(e)}")
    
    # Print comparison
    if results:
        print(f"\n{'='*50}")
        print("Performance Comparison")
        print(f"{'='*50}")
        
        results.sort(key=lambda x: x['rate'], reverse=True)
        
        for i, result in enumerate(results, 1):
            print(f"{i}. {result['database']}: {result['rate']:.0f} records/second")
    
    # Cleanup
    try:
        os.remove(CSV_FILE)
    except:
        pass

if __name__ == "__main__":
    # Configuration
    CONNECTION_STRING = "postgresql://user:password@localhost:5432/testdb"
    CSV_FILE = "native_bulk_test.csv"
    TABLE_NAME = "native_bulk_test"
    
    # Generate test data
    print("Generating test data...")
    generate_test_csv(CSV_FILE, 100000)
    
    # Test PostgreSQL bulk loading
    print("\n" + "="*60)
    print("Testing PostgreSQL Native Bulk Loading")
    print("="*60)
    
    loader = UniversalBulkLoader(CONNECTION_STRING, 'postgresql')
    result = loader.bulk_load_with_validation(CSV_FILE, TABLE_NAME)
    
    print(f"\nFinal Results:")
    print(f"Success: {result['success']}")
    if result['success']:
        print(f"Records Loaded: {result['records_loaded']}")
        print(f"Duration: {result['duration_seconds']:.2f} seconds")
        print(f"Load Rate: {result['load_rate']:.0f} records/second")
        print(f"Method: {result['method']}")
    else:
        print(f"Error: {result.get('error', 'Unknown error')}")
    
    # Test different methods
    print("\n" + "="*60)
    print("Testing COPY FROM STDIN method")
    print("="*60)
    
    pg_loader = PostgreSQLBulkLoader(CONNECTION_STRING)
    
    # Clear table first
    with pg_loader.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {TABLE_NAME}")
        conn.commit()
    
    stdin_result = pg_loader.bulk_load_csv_from_memory(CSV_FILE, TABLE_NAME)
    
    if stdin_result['success']:
        print(f"COPY FROM STDIN Results:")
        print(f"Records: {stdin_result['records_loaded']}")
        print(f"Duration: {stdin_result['duration_seconds']:.2f}s")
        print(f"Rate: {stdin_result['load_rate']:.0f} records/second")
    
    # Cleanup
    try:
        os.remove(CSV_FILE)
        print(f"\nCleaned up test file: {CSV_FILE}")
    except:
        pass
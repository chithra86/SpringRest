#!/usr/bin/env python3
"""
Approach 2: Batch Processing with Savepoints
Process records in batches with savepoints for granular error handling
"""

import csv
import psycopg2
import time
from contextlib import contextmanager
from typing import List, Dict, Any, Generator

class BatchProcessor:
    def __init__(self, connection_string: str, batch_size: int = 1000):
        self.connection_string = connection_string
        self.batch_size = batch_size
        self.failed_batches = []
        self.successful_batches = 0
        
    @contextmanager
    def get_connection(self):
        conn = None
        try:
            conn = psycopg2.connect(self.connection_string)
            conn.autocommit = False
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def read_csv_in_batches(self, csv_file_path: str) -> Generator[List[Dict], None, None]:
        """Read CSV file and yield batches of records"""
        with open(csv_file_path, 'r') as file:
            csv_reader = csv.DictReader(file)
            batch = []
            
            for row in csv_reader:
                batch.append(row)
                
                if len(batch) >= self.batch_size:
                    yield batch
                    batch = []
            
            # Yield remaining records
            if batch:
                yield batch
    
    def process_batch_with_savepoint(self, cursor, batch: List[Dict], batch_num: int, 
                                   insert_sql: str, columns: List[str]) -> bool:
        """Process a single batch with savepoint for rollback capability"""
        savepoint_name = f"batch_{batch_num}"
        
        try:
            # Create savepoint
            cursor.execute(f"SAVEPOINT {savepoint_name}")
            
            # Prepare batch data
            batch_data = []
            for row in batch:
                record_values = [row.get(col, None) for col in columns]
                batch_data.append(record_values)
            
            # Execute batch insert
            cursor.executemany(insert_sql, batch_data)
            
            # Release savepoint (successful)
            cursor.execute(f"RELEASE SAVEPOINT {savepoint_name}")
            
            return True
            
        except Exception as e:
            # Rollback to savepoint
            cursor.execute(f"ROLLBACK TO SAVEPOINT {savepoint_name}")
            
            print(f"Batch {batch_num} failed: {str(e)}")
            self.failed_batches.append({
                'batch_num': batch_num,
                'error': str(e),
                'record_count': len(batch)
            })
            
            return False
    
    def bulk_insert_with_batches(self, csv_file_path: str, table_name: str, 
                                all_or_nothing: bool = True) -> Dict[str, Any]:
        """
        Insert records in batches with optional all-or-nothing behavior
        
        Args:
            csv_file_path: Path to CSV file
            table_name: Target database table
            all_or_nothing: If True, rollback everything if any batch fails
        
        Returns:
            Dictionary with results summary
        """
        start_time = time.time()
        total_records = 0
        successful_records = 0
        batch_num = 0
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                print(f"Starting batch processing (batch size: {self.batch_size})")
                
                # Get first batch to determine columns
                csv_batches = self.read_csv_in_batches(csv_file_path)
                first_batch = next(csv_batches)
                
                if not first_batch:
                    raise ValueError("CSV file is empty")
                
                columns = list(first_batch[0].keys())
                placeholders = ', '.join(['%s'] * len(columns))
                insert_sql = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"
                
                # Process first batch
                batch_num += 1
                total_records += len(first_batch)
                
                success = self.process_batch_with_savepoint(
                    cursor, first_batch, batch_num, insert_sql, columns
                )
                
                if success:
                    self.successful_batches += 1
                    successful_records += len(first_batch)
                    print(f"Batch {batch_num}: {len(first_batch)} records - SUCCESS")
                else:
                    print(f"Batch {batch_num}: {len(first_batch)} records - FAILED")
                    if all_or_nothing:
                        conn.rollback()
                        return self._build_result_summary(start_time, total_records, 0, 
                                                        failed_due_to_all_or_nothing=True)
                
                # Process remaining batches
                for batch in csv_batches:
                    batch_num += 1
                    total_records += len(batch)
                    
                    success = self.process_batch_with_savepoint(
                        cursor, batch, batch_num, insert_sql, columns
                    )
                    
                    if success:
                        self.successful_batches += 1
                        successful_records += len(batch)
                        print(f"Batch {batch_num}: {len(batch)} records - SUCCESS")
                    else:
                        print(f"Batch {batch_num}: {len(batch)} records - FAILED")
                        if all_or_nothing:
                            conn.rollback()
                            return self._build_result_summary(start_time, total_records, 0, 
                                                            failed_due_to_all_or_nothing=True)
                    
                    # Progress update
                    if batch_num % 10 == 0:
                        print(f"Processed {batch_num} batches, {total_records} total records")
                
                # Commit all successful batches
                if not all_or_nothing or len(self.failed_batches) == 0:
                    conn.commit()
                    print(f"Committed {self.successful_batches} successful batches")
                else:
                    conn.rollback()
                    successful_records = 0
                
                return self._build_result_summary(start_time, total_records, successful_records)
                
        except Exception as e:
            print(f"FATAL ERROR: {str(e)}")
            return self._build_result_summary(start_time, total_records, 0, fatal_error=str(e))
    
    def _build_result_summary(self, start_time: float, total_records: int, 
                            successful_records: int, failed_due_to_all_or_nothing: bool = False,
                            fatal_error: str = None) -> Dict[str, Any]:
        """Build summary of processing results"""
        end_time = time.time()
        duration = end_time - start_time
        
        result = {
            'success': successful_records == total_records and fatal_error is None,
            'total_records': total_records,
            'successful_records': successful_records,
            'failed_records': total_records - successful_records,
            'total_batches': self.successful_batches + len(self.failed_batches),
            'successful_batches': self.successful_batches,
            'failed_batches': len(self.failed_batches),
            'duration_seconds': duration,
            'records_per_second': successful_records / duration if duration > 0 else 0,
            'failed_batch_details': self.failed_batches,
            'all_or_nothing_rollback': failed_due_to_all_or_nothing,
            'fatal_error': fatal_error
        }
        
        return result
    
    def retry_failed_batches(self, csv_file_path: str, table_name: str) -> Dict[str, Any]:
        """Retry only the batches that previously failed"""
        if not self.failed_batches:
            print("No failed batches to retry")
            return {'success': True, 'retried_batches': 0}
        
        print(f"Retrying {len(self.failed_batches)} failed batches...")
        
        # Implementation would read specific failed batches and retry them
        # This is a simplified version for demonstration
        retry_results = {
            'success': False,
            'retried_batches': len(self.failed_batches),
            'newly_successful': 0,
            'still_failed': len(self.failed_batches)
        }
        
        return retry_results

def create_test_table_with_constraints(connection_string: str):
    """Create a test table with constraints that might cause some inserts to fail"""
    with psycopg2.connect(connection_string) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            DROP TABLE IF EXISTS batch_test CASCADE
        """)
        cursor.execute("""
            CREATE TABLE batch_test (
                id SERIAL PRIMARY KEY,
                name VARCHAR(50) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                age INTEGER CHECK (age >= 0 AND age <= 150),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def generate_test_csv_with_some_bad_data(filename: str, num_records: int = 100000):
    """Generate test CSV with some intentionally bad data to test error handling"""
    import random
    import string
    
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['name', 'email', 'age'])
        
        for i in range(num_records):
            # Introduce some bad data occasionally
            if i % 10000 == 0 and i > 0:
                # Bad age (negative)
                name = ''.join(random.choices(string.ascii_letters, k=10))
                email = f"{name.lower()}@example.com"
                age = -1  # Invalid age
                writer.writerow([name, email, age])
            elif i % 15000 == 0 and i > 0:
                # Duplicate email
                writer.writerow(['DuplicateUser', 'duplicate@example.com', 25])
                writer.writerow(['DuplicateUser2', 'duplicate@example.com', 30])  # This will fail
            else:
                # Good data
                name = ''.join(random.choices(string.ascii_letters, k=10))
                email = f"{name.lower()}{i}@example.com"
                age = random.randint(18, 80)
                writer.writerow([name, email, age])
    
    print(f"Generated {filename} with {num_records} records (including some bad data)")

if __name__ == "__main__":
    # Configuration
    CONNECTION_STRING = "postgresql://user:password@localhost:5432/testdb"
    CSV_FILE = "test_data_with_errors.csv"
    TABLE_NAME = "batch_test"
    BATCH_SIZE = 1000
    
    # Setup
    print("Setting up test environment...")
    create_test_table_with_constraints(CONNECTION_STRING)
    generate_test_csv_with_some_bad_data(CSV_FILE, 10000)  # Smaller dataset for demo
    
    # Test with all-or-nothing behavior
    print("\n" + "="*50)
    print("Testing with ALL-OR-NOTHING behavior")
    print("="*50)
    
    processor1 = BatchProcessor(CONNECTION_STRING, BATCH_SIZE)
    result1 = processor1.bulk_insert_with_batches(CSV_FILE, TABLE_NAME, all_or_nothing=True)
    
    print("\nResults Summary:")
    for key, value in result1.items():
        print(f"{key}: {value}")
    
    # Test with partial success behavior
    print("\n" + "="*50)
    print("Testing with PARTIAL SUCCESS behavior")
    print("="*50)
    
    # Clear table first
    with psycopg2.connect(CONNECTION_STRING) as conn:
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {TABLE_NAME}")
        conn.commit()
    
    processor2 = BatchProcessor(CONNECTION_STRING, BATCH_SIZE)
    result2 = processor2.bulk_insert_with_batches(CSV_FILE, TABLE_NAME, all_or_nothing=False)
    
    print("\nResults Summary:")
    for key, value in result2.items():
        print(f"{key}: {value}")
    
    if result2['failed_batches'] > 0:
        print(f"\nFailed batch details:")
        for failed_batch in result2['failed_batch_details']:
            print(f"  Batch {failed_batch['batch_num']}: {failed_batch['error']}")
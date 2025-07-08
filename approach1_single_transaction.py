#!/usr/bin/env python3
"""
Approach 1: Single Large Transaction
All 100k records in one transaction - all or nothing
"""

import csv
import psycopg2
import time
from contextlib import contextmanager
from typing import List, Dict, Any

class SingleTransactionBulkInserter:
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
    
    @contextmanager
    def get_connection(self):
        conn = None
        try:
            conn = psycopg2.connect(self.connection_string)
            conn.autocommit = False  # Important: disable autocommit
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def bulk_insert_from_csv(self, csv_file_path: str, table_name: str) -> bool:
        """
        Insert all records from CSV file in a single transaction
        Returns True if successful, False if any error occurs
        """
        start_time = time.time()
        records_processed = 0
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Start transaction (implicit with autocommit=False)
                print("Starting single large transaction...")
                
                with open(csv_file_path, 'r') as file:
                    csv_reader = csv.DictReader(file)
                    
                    # Build the INSERT statement
                    if not csv_reader.fieldnames:
                        raise ValueError("CSV file has no headers")
                    
                    columns = csv_reader.fieldnames
                    placeholders = ', '.join(['%s'] * len(columns))
                    insert_sql = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"
                    
                    # Collect all records first
                    all_records = []
                    for row in csv_reader:
                        record_values = [row[col] for col in columns]
                        all_records.append(record_values)
                        records_processed += 1
                        
                        if records_processed % 10000 == 0:
                            print(f"Loaded {records_processed} records into memory...")
                    
                    print(f"Executing single transaction with {records_processed} records...")
                    
                    # Execute all inserts in one transaction
                    cursor.executemany(insert_sql, all_records)
                    
                    # Commit everything at once
                    conn.commit()
                    
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    print(f"SUCCESS: Inserted {records_processed} records in {duration:.2f} seconds")
                    print(f"Rate: {records_processed/duration:.2f} records/second")
                    
                    return True
                    
        except Exception as e:
            print(f"ERROR: Transaction failed - {str(e)}")
            print("All records rolled back")
            return False

def create_test_table(connection_string: str):
    """Create a test table for demonstration"""
    with psycopg2.connect(connection_string) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bulk_test (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100),
                email VARCHAR(100),
                age INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def generate_test_csv(filename: str, num_records: int = 100000):
    """Generate a test CSV file with specified number of records"""
    import random
    import string
    
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['name', 'email', 'age'])
        
        for i in range(num_records):
            name = ''.join(random.choices(string.ascii_letters, k=10))
            email = f"{name.lower()}@example.com"
            age = random.randint(18, 80)
            writer.writerow([name, email, age])
    
    print(f"Generated {filename} with {num_records} records")

if __name__ == "__main__":
    # Configuration
    CONNECTION_STRING = "postgresql://user:password@localhost:5432/testdb"
    CSV_FILE = "test_data_100k.csv"
    TABLE_NAME = "bulk_test"
    
    # Setup
    print("Setting up test environment...")
    create_test_table(CONNECTION_STRING)
    generate_test_csv(CSV_FILE, 100000)
    
    # Execute bulk insert
    inserter = SingleTransactionBulkInserter(CONNECTION_STRING)
    success = inserter.bulk_insert_from_csv(CSV_FILE, TABLE_NAME)
    
    if success:
        print("Bulk insert completed successfully!")
    else:
        print("Bulk insert failed - no records were inserted")
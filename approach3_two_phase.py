#!/usr/bin/env python3
"""
Approach 3: Two-Phase Processing with Staging Table
Phase 1: Fast load to staging table (no constraints)
Phase 2: Atomic move to target table with validation
"""

import csv
import psycopg2
import time
import uuid
from contextlib import contextmanager
from typing import Dict, Any, Optional

class TwoPhaseProcessor:
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.staging_table_name = None
        
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
    
    def create_staging_table(self, target_table: str, staging_suffix: str = None) -> str:
        """Create a staging table with same structure as target table"""
        if staging_suffix is None:
            staging_suffix = str(uuid.uuid4()).replace('-', '')[:8]
        
        staging_table = f"{target_table}_staging_{staging_suffix}"
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Drop staging table if exists
            cursor.execute(f"DROP TABLE IF EXISTS {staging_table}")
            
            # Create staging table with same structure but no constraints
            cursor.execute(f"""
                CREATE TABLE {staging_table} AS 
                SELECT * FROM {target_table} WHERE 1=0
            """)
            
            # Remove constraints from staging table
            cursor.execute(f"""
                ALTER TABLE {staging_table} 
                DROP CONSTRAINT IF EXISTS {staging_table}_pkey CASCADE
            """)
            
            conn.commit()
            
        self.staging_table_name = staging_table
        print(f"Created staging table: {staging_table}")
        return staging_table
    
    def load_csv_to_staging_fast(self, csv_file_path: str, staging_table: str) -> Dict[str, Any]:
        """Phase 1: Fast load CSV data to staging table using COPY"""
        start_time = time.time()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get absolute path for COPY command
                import os
                abs_csv_path = os.path.abspath(csv_file_path)
                
                print(f"Starting fast load to staging table: {staging_table}")
                
                # Use COPY for fastest possible load
                with open(csv_file_path, 'r') as f:
                    # Skip header and use COPY FROM
                    next(f)  # Skip header
                    cursor.copy_expert(f"""
                        COPY {staging_table} FROM STDIN WITH CSV
                    """, f)
                
                # Get record count
                cursor.execute(f"SELECT COUNT(*) FROM {staging_table}")
                record_count = cursor.fetchone()[0]
                
                conn.commit()
                
                end_time = time.time()
                duration = end_time - start_time
                
                result = {
                    'success': True,
                    'records_loaded': record_count,
                    'duration_seconds': duration,
                    'load_rate': record_count / duration if duration > 0 else 0,
                    'staging_table': staging_table
                }
                
                print(f"Phase 1 SUCCESS: Loaded {record_count} records in {duration:.2f}s")
                print(f"Load rate: {result['load_rate']:.0f} records/second")
                
                return result
                
        except Exception as e:
            print(f"Phase 1 FAILED: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'records_loaded': 0,
                'staging_table': staging_table
            }
    
    def validate_staging_data(self, staging_table: str, target_table: str) -> Dict[str, Any]:
        """Validate data in staging table before moving to target"""
        validation_results = {
            'is_valid': True,
            'validation_errors': [],
            'total_records': 0,
            'valid_records': 0
        }
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get total record count
                cursor.execute(f"SELECT COUNT(*) FROM {staging_table}")
                total_records = cursor.fetchone()[0]
                validation_results['total_records'] = total_records
                
                print(f"Validating {total_records} records in staging table...")
                
                # Example validations - customize based on your needs
                
                # 1. Check for required fields (assuming name and email are required)
                cursor.execute(f"""
                    SELECT COUNT(*) FROM {staging_table} 
                    WHERE name IS NULL OR name = '' OR email IS NULL OR email = ''
                """)
                null_required_fields = cursor.fetchone()[0]
                
                if null_required_fields > 0:
                    validation_results['is_valid'] = False
                    validation_results['validation_errors'].append(
                        f"{null_required_fields} records have null/empty required fields"
                    )
                
                # 2. Check for duplicate emails within staging data
                cursor.execute(f"""
                    SELECT email, COUNT(*) as cnt 
                    FROM {staging_table} 
                    WHERE email IS NOT NULL 
                    GROUP BY email 
                    HAVING COUNT(*) > 1
                """)
                duplicate_emails = cursor.fetchall()
                
                if duplicate_emails:
                    validation_results['is_valid'] = False
                    validation_results['validation_errors'].append(
                        f"{len(duplicate_emails)} duplicate email addresses found in staging data"
                    )
                
                # 3. Check for invalid age values
                cursor.execute(f"""
                    SELECT COUNT(*) FROM {staging_table} 
                    WHERE age IS NOT NULL AND (age < 0 OR age > 150)
                """)
                invalid_ages = cursor.fetchone()[0]
                
                if invalid_ages > 0:
                    validation_results['is_valid'] = False
                    validation_results['validation_errors'].append(
                        f"{invalid_ages} records have invalid age values"
                    )
                
                # 4. Check for conflicts with existing target table data
                cursor.execute(f"""
                    SELECT COUNT(*) FROM {staging_table} s
                    INNER JOIN {target_table} t ON s.email = t.email
                """)
                email_conflicts = cursor.fetchone()[0]
                
                if email_conflicts > 0:
                    validation_results['is_valid'] = False
                    validation_results['validation_errors'].append(
                        f"{email_conflicts} records have email conflicts with existing data"
                    )
                
                # Calculate valid records (total - all validation errors)
                if validation_results['is_valid']:
                    validation_results['valid_records'] = total_records
                else:
                    # Count records that pass all validations
                    cursor.execute(f"""
                        SELECT COUNT(*) FROM {staging_table} s
                        WHERE (s.name IS NOT NULL AND s.name != '' AND s.email IS NOT NULL AND s.email != '')
                        AND (s.age IS NULL OR (s.age >= 0 AND s.age <= 150))
                        AND NOT EXISTS (
                            SELECT 1 FROM {target_table} t WHERE t.email = s.email
                        )
                        AND s.email NOT IN (
                            SELECT email FROM {staging_table} 
                            WHERE email IS NOT NULL 
                            GROUP BY email 
                            HAVING COUNT(*) > 1
                        )
                    """)
                    validation_results['valid_records'] = cursor.fetchone()[0]
                
                return validation_results
                
        except Exception as e:
            validation_results['is_valid'] = False
            validation_results['validation_errors'].append(f"Validation error: {str(e)}")
            return validation_results
    
    def move_staging_to_target_atomic(self, staging_table: str, target_table: str, 
                                    validation_results: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 2: Atomically move valid data from staging to target table"""
        start_time = time.time()
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Start transaction
                conn.autocommit = False
                
                print(f"Starting atomic move from {staging_table} to {target_table}")
                
                if validation_results['is_valid']:
                    # Move all data if validation passed
                    cursor.execute(f"""
                        INSERT INTO {target_table} (name, email, age)
                        SELECT name, email, age FROM {staging_table}
                    """)
                    records_moved = cursor.rowcount
                    
                else:
                    # Move only valid records if some validations failed
                    print("Moving only valid records (skipping invalid ones)...")
                    cursor.execute(f"""
                        INSERT INTO {target_table} (name, email, age)
                        SELECT name, email, age FROM {staging_table} s
                        WHERE (s.name IS NOT NULL AND s.name != '' AND s.email IS NOT NULL AND s.email != '')
                        AND (s.age IS NULL OR (s.age >= 0 AND s.age <= 150))
                        AND NOT EXISTS (
                            SELECT 1 FROM {target_table} t WHERE t.email = s.email
                        )
                        AND s.email NOT IN (
                            SELECT email FROM {staging_table} 
                            WHERE email IS NOT NULL 
                            GROUP BY email 
                            HAVING COUNT(*) > 1
                        )
                    """)
                    records_moved = cursor.rowcount
                
                # Commit the transaction
                conn.commit()
                
                end_time = time.time()
                duration = end_time - start_time
                
                result = {
                    'success': True,
                    'records_moved': records_moved,
                    'duration_seconds': duration,
                    'move_rate': records_moved / duration if duration > 0 else 0
                }
                
                print(f"Phase 2 SUCCESS: Moved {records_moved} records in {duration:.2f}s")
                
                return result
                
        except Exception as e:
            print(f"Phase 2 FAILED: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'records_moved': 0
            }
    
    def cleanup_staging_table(self, staging_table: str):
        """Clean up staging table after processing"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(f"DROP TABLE IF EXISTS {staging_table}")
                conn.commit()
                print(f"Cleaned up staging table: {staging_table}")
        except Exception as e:
            print(f"Warning: Could not clean up staging table {staging_table}: {str(e)}")
    
    def process_csv_two_phase(self, csv_file_path: str, target_table: str, 
                            cleanup_staging: bool = True, 
                            skip_invalid_records: bool = False) -> Dict[str, Any]:
        """
        Complete two-phase processing of CSV file
        
        Args:
            csv_file_path: Path to CSV file
            target_table: Target database table
            cleanup_staging: Whether to drop staging table after processing
            skip_invalid_records: If True, skip invalid records; if False, fail on any invalid data
        """
        overall_start_time = time.time()
        staging_table = None
        
        try:
            # Phase 1: Create staging table and fast load
            staging_table = self.create_staging_table(target_table)
            
            phase1_result = self.load_csv_to_staging_fast(csv_file_path, staging_table)
            if not phase1_result['success']:
                return phase1_result
            
            # Validation phase
            validation_results = self.validate_staging_data(staging_table, target_table)
            
            if not validation_results['is_valid'] and not skip_invalid_records:
                error_msg = "Validation failed: " + "; ".join(validation_results['validation_errors'])
                return {
                    'success': False,
                    'error': error_msg,
                    'phase1_result': phase1_result,
                    'validation_results': validation_results
                }
            
            # Phase 2: Atomic move to target
            phase2_result = self.move_staging_to_target_atomic(staging_table, target_table, validation_results)
            
            # Overall results
            overall_end_time = time.time()
            overall_duration = overall_end_time - overall_start_time
            
            final_result = {
                'success': phase2_result['success'],
                'total_duration_seconds': overall_duration,
                'phase1_result': phase1_result,
                'validation_results': validation_results,
                'phase2_result': phase2_result,
                'overall_records_processed': phase1_result.get('records_loaded', 0),
                'overall_records_inserted': phase2_result.get('records_moved', 0),
                'overall_rate': phase2_result.get('records_moved', 0) / overall_duration if overall_duration > 0 else 0
            }
            
            return final_result
            
        except Exception as e:
            return {
                'success': False,
                'error': f"Two-phase processing failed: {str(e)}",
                'staging_table': staging_table
            }
        
        finally:
            # Cleanup staging table if requested
            if cleanup_staging and staging_table:
                self.cleanup_staging_table(staging_table)

def create_target_table(connection_string: str):
    """Create the target table with proper constraints"""
    with psycopg2.connect(connection_string) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS two_phase_test (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                age INTEGER CHECK (age >= 0 AND age <= 150),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def generate_csv_with_mixed_data(filename: str, num_records: int = 100000):
    """Generate CSV with mix of good and bad data for testing"""
    import random
    import string
    
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['name', 'email', 'age'])
        
        for i in range(num_records):
            if i % 5000 == 0 and i > 0:
                # Some bad data
                if i % 10000 == 0:
                    # Invalid age
                    writer.writerow(['BadAge', f'badage{i}@example.com', 200])
                else:
                    # Missing required field
                    writer.writerow(['', f'empty{i}@example.com', 25])
            else:
                # Good data
                name = ''.join(random.choices(string.ascii_letters, k=8))
                email = f"{name.lower()}{i}@example.com"
                age = random.randint(18, 80)
                writer.writerow([name, email, age])
    
    print(f"Generated {filename} with {num_records} records (including some invalid data)")

if __name__ == "__main__":
    # Configuration
    CONNECTION_STRING = "postgresql://user:password@localhost:5432/testdb"
    CSV_FILE = "two_phase_test_data.csv"
    TARGET_TABLE = "two_phase_test"
    
    # Setup
    print("Setting up test environment...")
    create_target_table(CONNECTION_STRING)
    generate_csv_with_mixed_data(CSV_FILE, 50000)  # Generate test data
    
    # Test two-phase processing with strict validation
    print("\n" + "="*60)
    print("Testing TWO-PHASE PROCESSING (strict validation)")
    print("="*60)
    
    processor = TwoPhaseProcessor(CONNECTION_STRING)
    result = processor.process_csv_two_phase(
        CSV_FILE, 
        TARGET_TABLE, 
        cleanup_staging=True,
        skip_invalid_records=False
    )
    
    print("\nFinal Results:")
    print(f"Success: {result['success']}")
    print(f"Total Duration: {result.get('total_duration_seconds', 0):.2f} seconds")
    print(f"Records Processed: {result.get('overall_records_processed', 0)}")
    print(f"Records Inserted: {result.get('overall_records_inserted', 0)}")
    print(f"Overall Rate: {result.get('overall_rate', 0):.0f} records/second")
    
    if 'validation_results' in result:
        val_results = result['validation_results']
        print(f"\nValidation Summary:")
        print(f"Valid: {val_results['is_valid']}")
        print(f"Total Records: {val_results['total_records']}")
        print(f"Valid Records: {val_results['valid_records']}")
        if val_results['validation_errors']:
            print("Validation Errors:")
            for error in val_results['validation_errors']:
                print(f"  - {error}")
    
    # Test with skip invalid records
    if not result['success']:
        print("\n" + "="*60)
        print("Testing TWO-PHASE PROCESSING (skip invalid records)")
        print("="*60)
        
        # Clear table first
        with psycopg2.connect(CONNECTION_STRING) as conn:
            cursor = conn.cursor()
            cursor.execute(f"DELETE FROM {TARGET_TABLE}")
            conn.commit()
        
        processor2 = TwoPhaseProcessor(CONNECTION_STRING)
        result2 = processor2.process_csv_two_phase(
            CSV_FILE, 
            TARGET_TABLE, 
            cleanup_staging=True,
            skip_invalid_records=True
        )
        
        print("\nSecond Run Results (skipping invalid):")
        print(f"Success: {result2['success']}")
        print(f"Records Processed: {result2.get('overall_records_processed', 0)}")
        print(f"Records Inserted: {result2.get('overall_records_inserted', 0)}")
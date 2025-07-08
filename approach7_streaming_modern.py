#!/usr/bin/env python3
"""
Approach 7: Modern Streaming Bulk Insert with Progress Monitoring
Memory-efficient streaming with checkpoints, progress tracking, and recovery
"""

import csv
import psycopg2
import time
import json
import hashlib
from pathlib import Path
from contextlib import contextmanager
from typing import Dict, Any, Optional, Generator, List
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ProcessingCheckpoint:
    """Represents a processing checkpoint for recovery"""
    file_path: str
    table_name: str
    records_processed: int
    bytes_processed: int
    file_position: int
    start_time: str
    last_checkpoint_time: str
    batch_size: int
    file_hash: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProcessingCheckpoint':
        return cls(**data)

@dataclass
class ProgressStats:
    """Progress statistics for monitoring"""
    total_records_processed: int
    total_batches_processed: int
    current_batch_size: int
    processing_rate: float  # records per second
    estimated_time_remaining: Optional[float]
    memory_usage_mb: float
    error_count: int
    last_error: Optional[str]

class StreamingBulkInserter:
    """Memory-efficient streaming bulk inserter with progress monitoring"""
    
    def __init__(self, connection_string: str, batch_size: int = 1000,
                 checkpoint_interval: int = 10000, checkpoint_dir: str = ".checkpoints"):
        self.connection_string = connection_string
        self.batch_size = batch_size
        self.checkpoint_interval = checkpoint_interval
        self.checkpoint_dir = Path(checkpoint_dir)
        self.checkpoint_dir.mkdir(exist_ok=True)
        
        # Progress tracking
        self.total_records_processed = 0
        self.total_batches_processed = 0
        self.start_time = None
        self.error_count = 0
        self.last_error = None
        
        # Performance monitoring
        self.processing_times = []
        self.batch_times = []
        
    @contextmanager
    def get_connection(self):
        """Get database connection with proper transaction handling"""
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
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate hash of file for integrity checking"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def _get_checkpoint_file_path(self, csv_file_path: str, table_name: str) -> Path:
        """Get checkpoint file path for this processing job"""
        file_name = f"{Path(csv_file_path).stem}_{table_name}_checkpoint.json"
        return self.checkpoint_dir / file_name
    
    def _save_checkpoint(self, checkpoint: ProcessingCheckpoint) -> None:
        """Save processing checkpoint to disk"""
        checkpoint_file = self._get_checkpoint_file_path(checkpoint.file_path, checkpoint.table_name)
        
        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint.to_dict(), f, indent=2)
        
        logger.info(f"Saved checkpoint: {checkpoint.records_processed} records processed")
    
    def _load_checkpoint(self, csv_file_path: str, table_name: str) -> Optional[ProcessingCheckpoint]:
        """Load existing checkpoint if available"""
        checkpoint_file = self._get_checkpoint_file_path(csv_file_path, table_name)
        
        if not checkpoint_file.exists():
            return None
        
        try:
            with open(checkpoint_file, 'r') as f:
                data = json.load(f)
            
            checkpoint = ProcessingCheckpoint.from_dict(data)
            
            # Verify file hasn't changed
            current_hash = self._calculate_file_hash(csv_file_path)
            if current_hash != checkpoint.file_hash:
                logger.warning("File has changed since checkpoint was created, ignoring checkpoint")
                return None
            
            logger.info(f"Loaded checkpoint: resuming from record {checkpoint.records_processed}")
            return checkpoint
            
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None
    
    def _cleanup_checkpoint(self, csv_file_path: str, table_name: str) -> None:
        """Clean up checkpoint file after successful completion"""
        checkpoint_file = self._get_checkpoint_file_path(csv_file_path, table_name)
        if checkpoint_file.exists():
            checkpoint_file.unlink()
            logger.info("Cleaned up checkpoint file")
    
    def _estimate_file_size(self, csv_file_path: str) -> Dict[str, Any]:
        """Estimate total records and file size for progress tracking"""
        file_size = Path(csv_file_path).stat().st_size
        
        # Sample first few lines to estimate average line size
        with open(csv_file_path, 'r') as f:
            sample_lines = []
            for i, line in enumerate(f):
                if i >= 1000:  # Sample first 1000 lines
                    break
                sample_lines.append(line)
        
        if len(sample_lines) <= 1:  # Only header
            return {'total_records': 0, 'file_size': file_size, 'avg_line_size': 0}
        
        # Calculate average line size (excluding header)
        total_sample_size = sum(len(line.encode('utf-8')) for line in sample_lines[1:])
        avg_line_size = total_sample_size / (len(sample_lines) - 1)
        
        # Estimate total records
        estimated_records = int((file_size - len(sample_lines[0].encode('utf-8'))) / avg_line_size)
        
        return {
            'total_records': estimated_records,
            'file_size': file_size,
            'avg_line_size': avg_line_size
        }
    
    def _read_csv_from_position(self, csv_file_path: str, start_position: int = 0) -> Generator[List[Dict], None, None]:
        """Read CSV file from specific position, yielding batches"""
        with open(csv_file_path, 'r') as f:
            # Move to start position
            if start_position > 0:
                f.seek(start_position)
                # Skip partial line
                f.readline()
            
            csv_reader = csv.DictReader(f)
            batch = []
            
            for row in csv_reader:
                batch.append(row)
                
                if len(batch) >= self.batch_size:
                    yield batch, f.tell()
                    batch = []
            
            # Yield remaining records
            if batch:
                yield batch, f.tell()
    
    def _get_current_stats(self, file_estimates: Dict[str, Any]) -> ProgressStats:
        """Calculate current progress statistics"""
        import psutil
        
        current_time = time.time()
        elapsed_time = current_time - self.start_time if self.start_time else 0
        
        # Calculate processing rate
        processing_rate = self.total_records_processed / elapsed_time if elapsed_time > 0 else 0
        
        # Estimate remaining time
        remaining_records = file_estimates['total_records'] - self.total_records_processed
        estimated_time_remaining = remaining_records / processing_rate if processing_rate > 0 else None
        
        # Get memory usage
        process = psutil.Process()
        memory_usage_mb = process.memory_info().rss / 1024 / 1024
        
        return ProgressStats(
            total_records_processed=self.total_records_processed,
            total_batches_processed=self.total_batches_processed,
            current_batch_size=self.batch_size,
            processing_rate=processing_rate,
            estimated_time_remaining=estimated_time_remaining,
            memory_usage_mb=memory_usage_mb,
            error_count=self.error_count,
            last_error=self.last_error
        )
    
    def _log_progress(self, stats: ProgressStats, file_estimates: Dict[str, Any]) -> None:
        """Log detailed progress information"""
        completion_pct = (stats.total_records_processed / file_estimates['total_records'] * 100) if file_estimates['total_records'] > 0 else 0
        
        eta_str = f"{stats.estimated_time_remaining:.1f}s" if stats.estimated_time_remaining else "Unknown"
        
        logger.info(f"Progress: {stats.total_records_processed:,}/{file_estimates['total_records']:,} "
                   f"({completion_pct:.1f}%) | Rate: {stats.processing_rate:.0f} rec/s | "
                   f"Memory: {stats.memory_usage_mb:.1f}MB | ETA: {eta_str}")
    
    def process_csv_streaming(self, csv_file_path: str, table_name: str, 
                            resume_from_checkpoint: bool = True,
                            progress_callback: Optional[callable] = None) -> Dict[str, Any]:
        """
        Process CSV file using streaming approach with checkpoints
        
        Args:
            csv_file_path: Path to CSV file
            table_name: Target database table
            resume_from_checkpoint: Whether to resume from existing checkpoint
            progress_callback: Optional callback function for progress updates
        """
        
        self.start_time = time.time()
        file_estimates = self._estimate_file_size(csv_file_path)
        
        logger.info(f"Starting streaming processing of {csv_file_path}")
        logger.info(f"Estimated records: {file_estimates['total_records']:,}")
        logger.info(f"File size: {file_estimates['file_size']:,} bytes")
        
        # Load checkpoint if resuming
        checkpoint = None
        start_position = 0
        if resume_from_checkpoint:
            checkpoint = self._load_checkpoint(csv_file_path, table_name)
            if checkpoint:
                start_position = checkpoint.file_position
                self.total_records_processed = checkpoint.records_processed
        
        # Prepare for processing
        records_since_checkpoint = 0
        batch_errors = []
        
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Get first batch to determine columns
                csv_batches = self._read_csv_from_position(csv_file_path, start_position)
                first_batch_data = next(csv_batches)
                first_batch, first_position = first_batch_data
                
                if not first_batch:
                    return {'success': True, 'message': 'No data to process'}
                
                # Prepare SQL
                columns = list(first_batch[0].keys())
                placeholders = ', '.join(['%s'] * len(columns))
                insert_sql = f"INSERT INTO {table_name} ({', '.join(columns)}) VALUES ({placeholders})"
                
                # Process first batch
                batch_start_time = time.time()
                try:
                    batch_data = [[row.get(col, None) for col in columns] for row in first_batch]
                    cursor.executemany(insert_sql, batch_data)
                    conn.commit()
                    
                    self.total_records_processed += len(first_batch)
                    self.total_batches_processed += 1
                    records_since_checkpoint += len(first_batch)
                    
                    batch_time = time.time() - batch_start_time
                    self.batch_times.append(batch_time)
                    
                except Exception as e:
                    self.error_count += 1
                    self.last_error = str(e)
                    batch_errors.append(f"Batch {self.total_batches_processed + 1}: {str(e)}")
                    conn.rollback()
                
                # Process remaining batches
                for batch, current_position in csv_batches:
                    batch_start_time = time.time()
                    
                    try:
                        batch_data = [[row.get(col, None) for col in columns] for row in batch]
                        cursor.executemany(insert_sql, batch_data)
                        conn.commit()
                        
                        self.total_records_processed += len(batch)
                        self.total_batches_processed += 1
                        records_since_checkpoint += len(batch)
                        
                        batch_time = time.time() - batch_start_time
                        self.batch_times.append(batch_time)
                        
                    except Exception as e:
                        self.error_count += 1
                        self.last_error = str(e)
                        batch_errors.append(f"Batch {self.total_batches_processed + 1}: {str(e)}")
                        conn.rollback()
                        continue
                    
                    # Progress reporting
                    if self.total_records_processed % (self.checkpoint_interval // 10) == 0:
                        stats = self._get_current_stats(file_estimates)
                        self._log_progress(stats, file_estimates)
                        
                        if progress_callback:
                            progress_callback(stats)
                    
                    # Save checkpoint
                    if records_since_checkpoint >= self.checkpoint_interval:
                        checkpoint = ProcessingCheckpoint(
                            file_path=csv_file_path,
                            table_name=table_name,
                            records_processed=self.total_records_processed,
                            bytes_processed=current_position,
                            file_position=current_position,
                            start_time=datetime.fromtimestamp(self.start_time).isoformat(),
                            last_checkpoint_time=datetime.now().isoformat(),
                            batch_size=self.batch_size,
                            file_hash=self._calculate_file_hash(csv_file_path)
                        )
                        self._save_checkpoint(checkpoint)
                        records_since_checkpoint = 0
                
                # Final processing results
                end_time = time.time()
                total_duration = end_time - self.start_time
                
                final_stats = self._get_current_stats(file_estimates)
                
                result = {
                    'success': True,
                    'total_records_processed': self.total_records_processed,
                    'total_batches_processed': self.total_batches_processed,
                    'total_duration_seconds': total_duration,
                    'average_processing_rate': self.total_records_processed / total_duration,
                    'error_count': self.error_count,
                    'batch_errors': batch_errors,
                    'final_stats': asdict(final_stats),
                    'performance_metrics': {
                        'avg_batch_time': sum(self.batch_times) / len(self.batch_times) if self.batch_times else 0,
                        'min_batch_time': min(self.batch_times) if self.batch_times else 0,
                        'max_batch_time': max(self.batch_times) if self.batch_times else 0,
                        'total_batches': len(self.batch_times)
                    }
                }
                
                # Cleanup checkpoint on successful completion
                if self.error_count == 0:
                    self._cleanup_checkpoint(csv_file_path, table_name)
                
                logger.info(f"Streaming processing completed successfully!")
                logger.info(f"Processed {self.total_records_processed:,} records in {total_duration:.2f}s")
                logger.info(f"Average rate: {result['average_processing_rate']:.0f} records/second")
                
                return result
                
        except Exception as e:
            logger.error(f"Streaming processing failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'records_processed': self.total_records_processed,
                'batches_processed': self.total_batches_processed
            }

def progress_monitor_callback(stats: ProgressStats) -> None:
    """Example progress callback function"""
    print(f"\n📊 PROGRESS UPDATE:")
    print(f"   Records: {stats.total_records_processed:,}")
    print(f"   Rate: {stats.processing_rate:.0f} rec/s")
    print(f"   Memory: {stats.memory_usage_mb:.1f}MB")
    if stats.estimated_time_remaining:
        print(f"   ETA: {stats.estimated_time_remaining:.0f}s")

def create_test_table(connection_string: str, table_name: str):
    """Create test table for streaming demo"""
    with psycopg2.connect(connection_string) as conn:
        cursor = conn.cursor()
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100),
                email VARCHAR(100),
                age INTEGER,
                department VARCHAR(50),
                salary DECIMAL(10,2),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

def generate_large_csv(filename: str, num_records: int = 1000000):
    """Generate large CSV file for streaming test"""
    import random
    import string
    
    departments = ['Engineering', 'Sales', 'Marketing', 'HR', 'Finance', 'Operations']
    
    print(f"Generating {filename} with {num_records:,} records...")
    
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['name', 'email', 'age', 'department', 'salary'])
        
        for i in range(num_records):
            name = ''.join(random.choices(string.ascii_letters, k=12))
            email = f"{name.lower()}{i}@company.com"
            age = random.randint(22, 65)
            department = random.choice(departments)
            salary = round(random.uniform(40000, 150000), 2)
            
            writer.writerow([name, email, age, department, salary])
            
            # Progress for large files
            if (i + 1) % 100000 == 0:
                print(f"  Generated {i + 1:,} records...")
    
    print(f"✅ Generated {filename} with {num_records:,} records")

if __name__ == "__main__":
    # Configuration
    CONNECTION_STRING = "postgresql://user:password@localhost:5432/testdb"
    CSV_FILE = "streaming_test_large.csv"
    TABLE_NAME = "streaming_test"
    BATCH_SIZE = 5000
    CHECKPOINT_INTERVAL = 50000
    
    # Setup
    print("Setting up streaming test environment...")
    create_test_table(CONNECTION_STRING, TABLE_NAME)
    
    # Generate large test file (adjust size as needed)
    generate_large_csv(CSV_FILE, 500000)  # 500K records for demo
    
    # Test streaming processing
    print("\n" + "="*70)
    print("🚀 STARTING STREAMING BULK INSERT WITH MONITORING")
    print("="*70)
    
    streamer = StreamingBulkInserter(
        CONNECTION_STRING, 
        batch_size=BATCH_SIZE,
        checkpoint_interval=CHECKPOINT_INTERVAL
    )
    
    result = streamer.process_csv_streaming(
        CSV_FILE, 
        TABLE_NAME,
        resume_from_checkpoint=True,
        progress_callback=progress_monitor_callback
    )
    
    print(f"\n{'='*70}")
    print("📈 FINAL RESULTS")
    print(f"{'='*70}")
    print(f"Success: {result['success']}")
    
    if result['success']:
        print(f"Records Processed: {result['total_records_processed']:,}")
        print(f"Total Duration: {result['total_duration_seconds']:.2f}s")
        print(f"Average Rate: {result['average_processing_rate']:.0f} records/second")
        print(f"Batches Processed: {result['total_batches_processed']}")
        print(f"Errors: {result['error_count']}")
        
        metrics = result['performance_metrics']
        print(f"\n📊 Performance Metrics:")
        print(f"  Average Batch Time: {metrics['avg_batch_time']:.3f}s")
        print(f"  Min Batch Time: {metrics['min_batch_time']:.3f}s")
        print(f"  Max Batch Time: {metrics['max_batch_time']:.3f}s")
        
        if result['error_count'] > 0:
            print(f"\n❌ Batch Errors:")
            for error in result['batch_errors'][:5]:  # Show first 5 errors
                print(f"  {error}")
    else:
        print(f"Error: {result.get('error', 'Unknown error')}")
    
    # Cleanup test file
    import os
    try:
        os.remove(CSV_FILE)
        print(f"\n🧹 Cleaned up test file: {CSV_FILE}")
    except:
        pass
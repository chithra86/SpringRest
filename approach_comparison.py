#!/usr/bin/env python3
"""
Bulk Insert Approach Comparison Tool
Compares different approaches and provides recommendations based on your requirements
"""

import time
import csv
import psycopg2
import tempfile
import os
from typing import Dict, Any, List
from dataclasses import dataclass
import random
import string

@dataclass
class BenchmarkResult:
    """Results from benchmarking an approach"""
    approach_name: str
    success: bool
    records_processed: int
    duration_seconds: float
    records_per_second: float
    memory_usage_mb: float
    error_message: str = ""
    
    def __str__(self):
        if self.success:
            return (f"{self.approach_name}: {self.records_processed:,} records in {self.duration_seconds:.2f}s "
                   f"({self.records_per_second:.0f} rec/s, {self.memory_usage_mb:.1f}MB)")
        else:
            return f"{self.approach_name}: FAILED - {self.error_message}"

class ApproachBenchmark:
    """Benchmark different bulk insert approaches"""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.results: List[BenchmarkResult] = []
    
    def create_test_table(self, table_name: str):
        """Create test table for benchmarking"""
        with psycopg2.connect(self.connection_string) as conn:
            cursor = conn.cursor()
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
            cursor.execute(f"""
                CREATE TABLE {table_name} (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100),
                    email VARCHAR(100),
                    age INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
    
    def generate_test_data(self, num_records: int) -> str:
        """Generate test CSV data and return file path"""
        temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv')
        
        with temp_file:
            writer = csv.writer(temp_file)
            writer.writerow(['name', 'email', 'age'])
            
            for i in range(num_records):
                name = ''.join(random.choices(string.ascii_letters, k=8))
                email = f"{name.lower()}{i}@test.com"
                age = random.randint(18, 80)
                writer.writerow([name, email, age])
        
        return temp_file.name
    
    def get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024
        except ImportError:
            return 0.0
    
    def benchmark_single_transaction(self, csv_file: str, table_name: str, num_records: int) -> BenchmarkResult:
        """Benchmark single large transaction approach"""
        start_time = time.time()
        start_memory = self.get_memory_usage()
        
        try:
            with psycopg2.connect(self.connection_string) as conn:
                cursor = conn.cursor()
                conn.autocommit = False
                
                # Read all data into memory
                records = []
                with open(csv_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        records.append((row['name'], row['email'], int(row['age'])))
                
                # Single transaction
                cursor.executemany(
                    f"INSERT INTO {table_name} (name, email, age) VALUES (%s, %s, %s)",
                    records
                )
                conn.commit()
                
                end_time = time.time()
                duration = end_time - start_time
                end_memory = self.get_memory_usage()
                
                return BenchmarkResult(
                    approach_name="Single Transaction",
                    success=True,
                    records_processed=len(records),
                    duration_seconds=duration,
                    records_per_second=len(records) / duration,
                    memory_usage_mb=end_memory - start_memory
                )
                
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            return BenchmarkResult(
                approach_name="Single Transaction",
                success=False,
                records_processed=0,
                duration_seconds=duration,
                records_per_second=0,
                memory_usage_mb=0,
                error_message=str(e)
            )
    
    def benchmark_batch_processing(self, csv_file: str, table_name: str, num_records: int, 
                                  batch_size: int = 1000) -> BenchmarkResult:
        """Benchmark batch processing approach"""
        start_time = time.time()
        start_memory = self.get_memory_usage()
        
        try:
            with psycopg2.connect(self.connection_string) as conn:
                cursor = conn.cursor()
                conn.autocommit = False
                
                records_processed = 0
                batch = []
                
                with open(csv_file, 'r') as f:
                    reader = csv.DictReader(f)
                    
                    for row in reader:
                        batch.append((row['name'], row['email'], int(row['age'])))
                        
                        if len(batch) >= batch_size:
                            cursor.executemany(
                                f"INSERT INTO {table_name} (name, email, age) VALUES (%s, %s, %s)",
                                batch
                            )
                            records_processed += len(batch)
                            batch = []
                    
                    # Process remaining records
                    if batch:
                        cursor.executemany(
                            f"INSERT INTO {table_name} (name, email, age) VALUES (%s, %s, %s)",
                            batch
                        )
                        records_processed += len(batch)
                
                conn.commit()
                
                end_time = time.time()
                duration = end_time - start_time
                end_memory = self.get_memory_usage()
                
                return BenchmarkResult(
                    approach_name=f"Batch Processing ({batch_size})",
                    success=True,
                    records_processed=records_processed,
                    duration_seconds=duration,
                    records_per_second=records_processed / duration,
                    memory_usage_mb=end_memory - start_memory
                )
                
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            return BenchmarkResult(
                approach_name=f"Batch Processing ({batch_size})",
                success=False,
                records_processed=0,
                duration_seconds=duration,
                records_per_second=0,
                memory_usage_mb=0,
                error_message=str(e)
            )
    
    def benchmark_copy_command(self, csv_file: str, table_name: str, num_records: int) -> BenchmarkResult:
        """Benchmark PostgreSQL COPY command"""
        start_time = time.time()
        start_memory = self.get_memory_usage()
        
        try:
            with psycopg2.connect(self.connection_string) as conn:
                cursor = conn.cursor()
                
                # Use COPY FROM
                with open(csv_file, 'r') as f:
                    next(f)  # Skip header
                    cursor.copy_expert(f"COPY {table_name} (name, email, age) FROM STDIN WITH CSV", f)
                
                conn.commit()
                
                end_time = time.time()
                duration = end_time - start_time
                end_memory = self.get_memory_usage()
                
                return BenchmarkResult(
                    approach_name="PostgreSQL COPY",
                    success=True,
                    records_processed=num_records,
                    duration_seconds=duration,
                    records_per_second=num_records / duration,
                    memory_usage_mb=end_memory - start_memory
                )
                
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            return BenchmarkResult(
                approach_name="PostgreSQL COPY",
                success=False,
                records_processed=0,
                duration_seconds=duration,
                records_per_second=0,
                memory_usage_mb=0,
                error_message=str(e)
            )
    
    def benchmark_two_phase(self, csv_file: str, table_name: str, num_records: int) -> BenchmarkResult:
        """Benchmark two-phase processing (staging table)"""
        start_time = time.time()
        start_memory = self.get_memory_usage()
        
        staging_table = f"{table_name}_staging"
        
        try:
            with psycopg2.connect(self.connection_string) as conn:
                cursor = conn.cursor()
                
                # Create staging table
                cursor.execute(f"DROP TABLE IF EXISTS {staging_table}")
                cursor.execute(f"""
                    CREATE TABLE {staging_table} AS 
                    SELECT * FROM {table_name} WHERE 1=0
                """)
                
                # Phase 1: Fast load to staging
                with open(csv_file, 'r') as f:
                    next(f)  # Skip header
                    cursor.copy_expert(f"COPY {staging_table} (name, email, age) FROM STDIN WITH CSV", f)
                
                # Phase 2: Atomic move
                cursor.execute(f"""
                    INSERT INTO {table_name} (name, email, age)
                    SELECT name, email, age FROM {staging_table}
                """)
                
                # Cleanup
                cursor.execute(f"DROP TABLE {staging_table}")
                
                conn.commit()
                
                end_time = time.time()
                duration = end_time - start_time
                end_memory = self.get_memory_usage()
                
                return BenchmarkResult(
                    approach_name="Two-Phase Processing",
                    success=True,
                    records_processed=num_records,
                    duration_seconds=duration,
                    records_per_second=num_records / duration,
                    memory_usage_mb=end_memory - start_memory
                )
                
        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            return BenchmarkResult(
                approach_name="Two-Phase Processing",
                success=False,
                records_processed=0,
                duration_seconds=duration,
                records_per_second=0,
                memory_usage_mb=0,
                error_message=str(e)
            )
    
    def run_comprehensive_benchmark(self, num_records: int = 50000) -> List[BenchmarkResult]:
        """Run comprehensive benchmark of all approaches"""
        print(f"🔄 Running comprehensive benchmark with {num_records:,} records...")
        print("="*70)
        
        # Generate test data
        csv_file = self.generate_test_data(num_records)
        table_name = "benchmark_test"
        
        approaches = [
            ("PostgreSQL COPY", self.benchmark_copy_command),
            ("Two-Phase Processing", self.benchmark_two_phase),
            ("Batch Processing (1000)", lambda f, t, n: self.benchmark_batch_processing(f, t, n, 1000)),
            ("Batch Processing (5000)", lambda f, t, n: self.benchmark_batch_processing(f, t, n, 5000)),
            ("Single Transaction", self.benchmark_single_transaction),
        ]
        
        results = []
        
        for approach_name, benchmark_func in approaches:
            print(f"\n🧪 Testing {approach_name}...")
            
            # Clean table before each test
            self.create_test_table(table_name)
            
            try:
                result = benchmark_func(csv_file, table_name, num_records)
                results.append(result)
                print(f"   ✅ {result}")
            except Exception as e:
                result = BenchmarkResult(
                    approach_name=approach_name,
                    success=False,
                    records_processed=0,
                    duration_seconds=0,
                    records_per_second=0,
                    memory_usage_mb=0,
                    error_message=str(e)
                )
                results.append(result)
                print(f"   ❌ {result}")
        
        # Cleanup
        try:
            os.unlink(csv_file)
        except:
            pass
        
        self.results = results
        return results
    
    def print_performance_ranking(self):
        """Print performance ranking of approaches"""
        if not self.results:
            print("No benchmark results available")
            return
        
        print(f"\n{'='*70}")
        print("📊 PERFORMANCE RANKING")
        print(f"{'='*70}")
        
        # Sort by records per second (successful only)
        successful_results = [r for r in self.results if r.success]
        successful_results.sort(key=lambda x: x.records_per_second, reverse=True)
        
        for i, result in enumerate(successful_results, 1):
            print(f"{i}. {result.approach_name}")
            print(f"   Rate: {result.records_per_second:,.0f} records/second")
            print(f"   Duration: {result.duration_seconds:.2f}s")
            print(f"   Memory: {result.memory_usage_mb:.1f}MB")
            print()
        
        # Show failed approaches
        failed_results = [r for r in self.results if not r.success]
        if failed_results:
            print("❌ Failed Approaches:")
            for result in failed_results:
                print(f"   {result.approach_name}: {result.error_message}")
    
    def get_recommendation(self, file_size_mb: int, memory_limit_mb: int, 
                          complexity_tolerance: str) -> str:
        """Get recommendation based on requirements"""
        
        recommendations = []
        
        if file_size_mb < 100:  # Small files
            if complexity_tolerance == "low":
                recommendations.append("✅ PostgreSQL COPY - Fastest and simplest for small files")
                recommendations.append("✅ Single Transaction - Simple all-or-nothing approach")
            else:
                recommendations.append("✅ Two-Phase Processing - Good validation capabilities")
                recommendations.append("✅ Batch Processing - Good balance of features")
        
        elif file_size_mb < 1000:  # Medium files
            recommendations.append("✅ PostgreSQL COPY - Still fastest option")
            recommendations.append("✅ Two-Phase Processing - Excellent for data validation")
            recommendations.append("⚠️  Batch Processing - Consider larger batch sizes")
            recommendations.append("❌ Single Transaction - May hit memory/timeout limits")
        
        else:  # Large files
            recommendations.append("✅ Two-Phase Processing - Best for large files")
            recommendations.append("✅ Streaming with Checkpoints - Memory efficient, resumable")
            recommendations.append("⚠️  PostgreSQL COPY - Fast but less control")
            recommendations.append("❌ Single Transaction - Will likely fail")
        
        if memory_limit_mb < 512:
            recommendations.append("\n💡 Memory Considerations:")
            recommendations.append("   - Avoid Single Transaction approach")
            recommendations.append("   - Use smaller batch sizes (500-1000)")
            recommendations.append("   - Consider Streaming approach")
        
        return "\n".join(recommendations)

def interactive_recommendation():
    """Interactive recommendation system"""
    print("🎯 BULK INSERT APPROACH RECOMMENDER")
    print("="*50)
    
    # Gather requirements
    try:
        file_size_mb = int(input("📁 Estimated file size in MB: "))
        record_count = int(input("📊 Estimated number of records: "))
        memory_limit_mb = int(input("💾 Available memory limit in MB: "))
        
        print("\n🔧 Complexity tolerance:")
        print("1. Low (simple solutions preferred)")
        print("2. Medium (balanced approach)")
        print("3. High (advanced features okay)")
        complexity_choice = input("Choose (1-3): ")
        
        complexity_map = {"1": "low", "2": "medium", "3": "high"}
        complexity_tolerance = complexity_map.get(complexity_choice, "medium")
        
        print("\n🎯 RECOMMENDATIONS")
        print("="*50)
        
        benchmark = ApproachBenchmark("")  # Don't need connection for recommendations
        recommendation = benchmark.get_recommendation(file_size_mb, memory_limit_mb, complexity_tolerance)
        print(recommendation)
        
        print(f"\n📋 IMPLEMENTATION PRIORITY:")
        if file_size_mb < 100 and complexity_tolerance == "low":
            print("1. Try PostgreSQL COPY first")
            print("2. Fallback to Single Transaction")
            print("3. Consider Batch Processing if constraints needed")
        elif file_size_mb < 1000:
            print("1. Start with PostgreSQL COPY for speed")
            print("2. Use Two-Phase if validation needed")
            print("3. Batch Processing for error handling")
        else:
            print("1. Implement Streaming with Checkpoints")
            print("2. Two-Phase as alternative")
            print("3. Avoid Single Transaction")
            
    except (ValueError, KeyboardInterrupt):
        print("\nExiting recommendation system.")

if __name__ == "__main__":
    print("🚀 BULK INSERT APPROACH ANALYZER")
    print("="*50)
    
    choice = input("Choose option:\n1. Run performance benchmark\n2. Get recommendation\n3. Both\nChoice (1-3): ")
    
    if choice in ["1", "3"]:
        connection_string = input("\n🔗 Enter PostgreSQL connection string: ")
        if not connection_string:
            connection_string = "postgresql://user:password@localhost:5432/testdb"
            print(f"Using default: {connection_string}")
        
        try:
            benchmark = ApproachBenchmark(connection_string)
            results = benchmark.run_comprehensive_benchmark(25000)  # 25K records for demo
            benchmark.print_performance_ranking()
        except Exception as e:
            print(f"❌ Benchmark failed: {e}")
            print("Make sure PostgreSQL is running and connection string is correct")
    
    if choice in ["2", "3"]:
        print("\n" + "="*70)
        interactive_recommendation()
    
    print("\n✨ Analysis complete!")
    print("\n📚 For detailed implementations, check the individual approach files:")
    print("   - approach1_single_transaction.py")
    print("   - approach2_batch_processing.py") 
    print("   - approach3_two_phase.py")
    print("   - approach4_database_native.py")
    print("   - approach7_streaming_modern.py")
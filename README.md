# Bulk Database Insert Approaches: Complete Implementation Guide

This repository contains **comprehensive implementations** of different approaches for bulk database operations with **all-or-nothing guarantees**. Perfect for handling 100k+ records with transactional safety.

## 🚀 Quick Start

1. **Get Recommendations**: Run the comparison tool to find the best approach for your needs
   ```bash
   python approach_comparison.py
   ```

2. **Choose Your Approach**: Based on your requirements, pick one of the detailed implementations below

3. **Run Performance Tests**: Benchmark different approaches with your actual data

## 📊 Available Approaches

### 1. Single Large Transaction (`approach1_single_transaction.py`)
**Best for:** Small files, simple requirements, guaranteed all-or-nothing

```python
# ✅ Pros: Simple, true ACID compliance, easy to implement
# ❌ Cons: High memory usage, timeout risks, blocking operations

inserter = SingleTransactionBulkInserter(connection_string)
success = inserter.bulk_insert_from_csv("data.csv", "target_table")
```

**Use when:**
- File size < 100MB
- Simple data without complex validation
- Strong consistency requirements
- Development/testing environments

### 2. Batch Processing with Savepoints (`approach2_batch_processing.py`)
**Best for:** Medium files, error handling, granular control

```python
# ✅ Pros: Memory efficient, granular error handling, recoverable
# ❌ Cons: More complex, savepoint overhead

processor = BatchProcessor(connection_string, batch_size=1000)
result = processor.bulk_insert_with_batches("data.csv", "target_table", all_or_nothing=True)
```

**Use when:**
- Need detailed error reporting
- Want to retry failed batches
- Balancing performance and reliability
- Production environments with monitoring

### 3. Two-Phase Processing (`approach3_two_phase.py`)
**Best for:** Data validation, large files, staging workflows

```python
# ✅ Pros: Fast initial load, excellent validation, atomic final commit
# ❌ Cons: Requires extra storage, two-step process

processor = TwoPhaseProcessor(connection_string)
result = processor.process_csv_two_phase("data.csv", "target_table", skip_invalid_records=True)
```

**Use when:**
- Need comprehensive data validation
- Working with external data sources
- ETL pipelines
- Data quality is critical

### 4. Database-Native Bulk Loading (`approach4_database_native.py`)
**Best for:** Maximum performance, database-optimized operations

```python
# ✅ Pros: Fastest performance, database-optimized, built-in error handling
# ❌ Cons: Database-specific, less customization

loader = UniversalBulkLoader(connection_string, 'postgresql')
result = loader.bulk_load_with_validation("data.csv", "target_table")
```

**Use when:**
- Performance is top priority
- File format is standardized
- Using PostgreSQL, MySQL, or SQL Server
- Minimal custom validation needed

### 5. Modern Streaming with Checkpoints (`approach7_streaming_modern.py`)
**Best for:** Very large files, progress monitoring, resumable operations

```python
# ✅ Pros: Memory efficient, resumable, progress tracking, enterprise-ready
# ❌ Cons: Most complex implementation

streamer = StreamingBulkInserter(connection_string, batch_size=5000, checkpoint_interval=50000)
result = streamer.process_csv_streaming("data.csv", "target_table", progress_callback=my_callback)
```

**Use when:**
- Files > 1GB
- Need progress monitoring
- Long-running operations
- Recovery from failures is important

## 🎯 Decision Matrix

| Approach | Performance | Memory Usage | Complexity | Error Handling | Best For |
|----------|-------------|--------------|------------|----------------|----------|
| Single Transaction | Medium | High | Low | Basic | Small files, simple needs |
| Batch Processing | Good | Low | Medium | Excellent | Balanced requirements |
| Two-Phase | Good | Medium | Medium | Excellent | Validation-heavy |
| Database-Native | Excellent | Low | Low | Good | Pure performance |
| Streaming | Good | Very Low | High | Excellent | Large files, monitoring |

## 🛠️ Installation & Setup

### Prerequisites
```bash
pip install psycopg2-binary  # PostgreSQL
pip install mysql-connector-python  # MySQL (optional)
pip install pyodbc  # SQL Server (optional)
pip install psutil  # Memory monitoring
```

### Database Setup
```sql
-- Create test database
CREATE DATABASE bulk_insert_test;

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE bulk_insert_test TO your_user;
```

### Configuration
Update connection strings in the example files:
```python
CONNECTION_STRING = "postgresql://user:password@localhost:5432/your_db"
```

## 📈 Performance Benchmarks

Run comprehensive benchmarks:
```bash
python approach_comparison.py
```

**Typical Results** (25,000 records):
1. **PostgreSQL COPY**: ~15,000 records/second
2. **Two-Phase Processing**: ~12,000 records/second  
3. **Batch Processing (5000)**: ~8,000 records/second
4. **Batch Processing (1000)**: ~6,000 records/second
5. **Single Transaction**: ~5,000 records/second

*Results vary based on hardware, network, and data complexity*

## 🔧 Customization Examples

### Custom Validation (Two-Phase)
```python
def custom_validation(staging_table: str, target_table: str) -> Dict[str, Any]:
    # Add your custom validation logic
    errors = []
    
    # Example: Check business rules
    cursor.execute(f"""
        SELECT COUNT(*) FROM {staging_table} 
        WHERE email NOT LIKE '%@%.%'
    """)
    invalid_emails = cursor.fetchone()[0]
    
    if invalid_emails > 0:
        errors.append(f"{invalid_emails} invalid email formats")
    
    return {'is_valid': len(errors) == 0, 'errors': errors}
```

### Progress Monitoring (Streaming)
```python
def progress_callback(stats: ProgressStats):
    print(f"Progress: {stats.total_records_processed:,} records")
    print(f"Rate: {stats.processing_rate:.0f} rec/s")
    print(f"ETA: {stats.estimated_time_remaining:.0f}s")
    
    # Send to monitoring system
    send_metrics_to_dashboard(stats)
```

### Error Handling (Batch Processing)
```python
def handle_batch_errors(failed_batches: List[Dict]):
    for batch in failed_batches:
        logger.error(f"Batch {batch['batch_num']} failed: {batch['error']}")
        
        # Send to dead letter queue
        send_to_dlq(batch['records'])
        
        # Alert operations team
        send_alert(f"Batch processing error: {batch['error']}")
```

## 🏗️ Production Deployment

### Docker Example
```dockerfile
FROM python:3.9-slim

RUN pip install psycopg2-binary psutil

COPY . /app
WORKDIR /app

CMD ["python", "approach4_database_native.py"]
```

### Environment Variables
```bash
# .env file
DB_CONNECTION_STRING=postgresql://user:pass@db:5432/production
BATCH_SIZE=5000
CHECKPOINT_INTERVAL=100000
LOG_LEVEL=INFO
```

### Monitoring Integration
```python
# Add to your implementations
import logging
from prometheus_client import Counter, Histogram

records_processed = Counter('bulk_insert_records_total')
processing_time = Histogram('bulk_insert_duration_seconds')

@processing_time.time()
def process_batch(batch):
    # Your processing logic
    records_processed.inc(len(batch))
```

## 🚨 Error Handling Patterns

### Retry Logic
```python
def exponential_backoff_retry(func, max_retries=3):
    for attempt in range(max_retries):
        try:
            return func()
        except (ConnectionError, TimeoutError) as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(2 ** attempt)
```

### Circuit Breaker
```python
class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
```

## 📋 Best Practices

### 1. **Choose the Right Approach**
- Start with database-native for simplicity
- Use batch processing for production
- Consider streaming for very large files

### 2. **Optimize Performance**
- Disable indexes during bulk load
- Use appropriate batch sizes (1000-5000)
- Consider connection pooling
- Monitor memory usage

### 3. **Handle Errors Gracefully**
- Implement proper logging
- Use dead letter queues for failed records
- Plan for partial failures
- Test recovery scenarios

### 4. **Monitor Operations**
- Track processing rates
- Monitor memory usage
- Set up alerts for failures
- Log detailed metrics

## 🧪 Testing

### Unit Tests
```bash
python -m pytest tests/
```

### Load Testing
```bash
# Generate large test file
python generate_test_data.py --records 1000000

# Run performance test
python approach_comparison.py --benchmark-only
```

### Integration Testing
```bash
# Test with real database
python test_integration.py --database postgresql://...
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## 📄 License

MIT License - feel free to use in your projects!

## 🆘 Troubleshooting

### Common Issues

**Memory errors with large files:**
- Use streaming approach
- Reduce batch size
- Check available RAM

**Connection timeouts:**
- Increase connection timeout
- Use connection pooling
- Implement retry logic

**Performance issues:**
- Check database indexes
- Monitor disk I/O
- Consider hardware upgrades

**Transaction deadlocks:**
- Reduce batch size
- Add retry logic
- Check table constraints

### Getting Help

1. Check the detailed implementation comments
2. Run the benchmark tool to identify bottlenecks
3. Review error logs for specific issues
4. Consider your specific use case requirements

---

🎉 **Ready to process your 100k records?** Start with `approach_comparison.py` to find your perfect approach!
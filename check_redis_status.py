import os
import sys
from redis import Redis
from rq import Queue, Worker

def check_redis():
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
    print(f"Connecting to Redis: {redis_url}")
    
    try:
        redis_conn = Redis.from_url(redis_url)
        redis_conn.ping()
        print("Successfully connected to Redis")
        
        # Check queues
        queues = Queue.all(connection=redis_conn)
        print(f"Queues ({len(queues)}): {[q.name for q in queues]}")
        
        for q in queues:
            print(f"Queue '{q.name}' length: {len(q)}")
            
        # Check registries
        q_scans = Queue('scans', connection=redis_conn)
        registries = {
            "Started": q_scans.started_job_registry,
            "Failed": q_scans.failed_job_registry,
            "Deferred": q_scans.deferred_job_registry,
            "Scheduled": q_scans.scheduled_job_registry,
            "Finished": q_scans.finished_job_registry,
        }
        
        for name, registry in registries.items():
            ids = registry.get_job_ids()
            print(f"{name} jobs ({len(ids)}):")
            for jid in ids:
                try:
                    from rq.job import Job
                    job = Job.fetch(jid, connection=redis_conn)
                    print(f"  - {jid}: Status={job.get_status()}, Enqueued={job.enqueued_at}")
                    if name == "Failed":
                        print(f"    Error Trace: {job.exc_info}")
                except Exception as e:
                    print(f"  - {jid}: Error fetching job: {e}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_redis()

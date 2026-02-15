from redis import Redis
from rq import Queue
import os

def check_queue():
    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
    redis_conn = Redis.from_url(redis_url)
    
    q = Queue('scans', connection=redis_conn)
    
    print(f"Queue 'scans' count: {len(q)}")
    
    # Check pending jobs
    jobs = q.get_job_ids()
    if jobs:
        print(f"Pending Job IDs: {jobs}")
        for job_id in jobs[:5]:
            job = q.fetch_job(job_id)
            if job:
                print(f"  Job {job_id}: Status={job.get_status()}, Created={job.created_at}")
    else:
        print("No pending jobs found.")
        
    # Check registries
    started_registry = q.started_job_registry
    print(f"Started jobs: {started_registry.count}")
    
    failed_registry = q.failed_job_registry
    print(f"Failed jobs: {failed_registry.count}")
    
    finished_registry = q.finished_job_registry
    print(f"Finished jobs: {finished_registry.count}")

if __name__ == "__main__":
    check_queue()

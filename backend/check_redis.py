import os
import redis
from rq import Queue

# Connect to Redis using the remote URL from .env
REDIS_URL = "rediss://red-d681ov248b3s73abvrdg:EZcgEvmHTeyCoLHNcmdU8qnxG2HeiU1n@oregon-keyvalue.render.com:6379"

try:
    print(f"Connecting to Redis: {REDIS_URL.split('@')[1]}...")
    conn = redis.from_url(REDIS_URL, ssl_cert_reqs=None, ssl_ca_certs=None, ssl_check_hostname=False)
    q = Queue(connection=conn)
    
    print(f"Queue Size: {len(q)}")
    print(f"Job IDs in Queue: {q.job_ids}")
    
    # Check for failed jobs
    from rq.registry import FailedJobRegistry
    registry = FailedJobRegistry(queue=q)
    print(f"Failed Jobs Count: {len(registry)}")
    for job_id in registry.get_job_ids()[:5]:
        print(f"Failed Job ID: {job_id}")

except Exception as e:
    print(f"Error: {e}")

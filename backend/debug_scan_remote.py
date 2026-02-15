import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

async def debug_scan():
    print(f"Connecting to: {DATABASE_URL.split('@')[1] if '@' in DATABASE_URL else DATABASE_URL}...")
    
    engine = create_async_engine(DATABASE_URL)
    AsyncSessionLocal = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with AsyncSessionLocal() as session:
        try:
            # 1. Check if users exist (Foreign Key Constraint)
            print("Checking users...")
            result = await session.execute(text("SELECT id, email FROM users LIMIT 1"))
            user = result.fetchone()
            if not user:
                print("❌ NO USERS FOUND. Scans require a valid user_id.")
                return

            print(f"✅ Found User: {user.email} (ID: {user.id})")
            user_id = user.id

            # 1.5 Check enum values in this session
            print("Checking enum values in current session...")
            enum_res = await session.execute(text("SELECT unnest(enum_range(NULL::scantype))"))
            enum_vals = enum_res.scalars().all()
            print(f"Enum Values in Session: {enum_vals}")
            
            repo_val = next((v for v in enum_vals if v == 'repo'), None)
            full_val = next((v for v in enum_vals if v == 'FULL'), None)
            
            target_val = repo_val if repo_val else full_val
            print(f"Using target scan_type: '{target_val}'")

            stmt = text("""
                INSERT INTO scans 
                (user_id, target_url, scan_type, status, created_at, updated_at) 
                VALUES (:uid, 'http://test-debug.com', :stype, 'pending', NOW(), NOW())
                RETURNING id
            """)
            result = await session.execute(stmt, {"uid": user_id, "stype": target_val})
            scan_id = result.scalar()
            await session.commit()
            print(f"✅ Scan ID {scan_id} created successfully.")
            
            # 4. Push to Redis
            import redis
            from rq import Queue
            
            REDIS_URL = os.getenv("REDIS_URL")
            if not REDIS_URL:
                 print("❌ REDIS_URL not found in env.")
                 return

            print(f"Connecting to Redis: {REDIS_URL.split('@')[1] if '@' in REDIS_URL else 'local'}...")
            
            # Fix for Python 3.12+ SSL changes 
            if REDIS_URL.startswith("rediss://"):
                conn = redis.from_url(REDIS_URL, ssl_cert_reqs=None, ssl_ca_certs=None, ssl_check_hostname=False)
            else:
                 conn = redis.from_url(REDIS_URL)

            q = Queue('scans', connection=conn)
            job = q.enqueue('rq_tasks.run_scan_job', scan_id, job_timeout='1h')
            print(f"✅ Job {job.id} enqueued for Scan {scan_id}")

        except Exception as e:
            print(f"❌ CRITICAL ERROR: {e}")
            await session.rollback()
        finally:
            await session.close()

if __name__ == "__main__":
    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(debug_scan())

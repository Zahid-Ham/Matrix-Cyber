
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text, select, func, desc, Column, Integer, String, Numeric, TIMESTAMP
from sqlalchemy.orm import declarative_base
import os

Base = declarative_base()

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    marketplace_value_avg = Column(Numeric)
    marketplace_last_analyzed = Column(TIMESTAMP)

async def check_db():
    db_url = None
    try:
        with open(r"C:\Users\ZAHID\Desktop\security\Matrix-Cyber\backend\.env", "r") as f:
            for line in f:
                if line.startswith("DATABASE_URL="):
                    db_url = line.split("=", 1)[1].strip()
                    break
    except Exception as e:
        print(f"Error reading .env: {e}")
    
    if not db_url:
        print("DATABASE_URL not found")
        return

    print(f"Connecting to {db_url}")
    try:
        engine = create_async_engine(db_url)
        async with engine.connect() as conn:
            # Simulate get_dashboard_stats logic
            res = await conn.execute(
                select(
                    func.count(Vulnerability.id),
                    func.sum(Vulnerability.marketplace_value_avg)
                ).select_from(Vulnerability).where(Vulnerability.marketplace_value_avg > 0)
            )
            count, total_value = res.one()
            print(f"Dashboard Stats - Count: {count}, Total Value: {total_value}")
            
            recent_stmt = select(Vulnerability.title, Vulnerability.marketplace_value_avg).where(
                Vulnerability.marketplace_value_avg > 0
            ).order_by(desc(Vulnerability.marketplace_last_analyzed)).limit(5)
            
            recent_result = await conn.execute(recent_stmt)
            print("Recent Valuations:")
            for row in recent_result:
                print(row)

    except Exception as e:
        print(f"Database error: {e}")

if __name__ == "__main__":
    asyncio.run(check_db())

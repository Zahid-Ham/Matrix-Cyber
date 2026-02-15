import asyncio
from core.database import engine, Base
from models.user import User, Organization, OrganizationMember, APIToken, UserActivity
from models.scan import Scan
from models.vulnerability import Vulnerability

async def reset_db():
    print("Resetting database...")
    async with engine.begin() as conn:
        # Drop all tables
        print("Dropping tables...")
        await conn.run_sync(Base.metadata.drop_all)
        
        # Create all tables
        print("Creating tables...")
        await conn.run_sync(Base.metadata.create_all)
    
    print("Database reset complete!")

if __name__ == "__main__":
    asyncio.run(reset_db())

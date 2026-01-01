"""Test PostgreSQL connection for the Matrix application."""
import asyncio
import sys

async def test_connection():
    """Test if we can connect to PostgreSQL and create tables."""
    try:
        # Import the database config which will initialize the engine
        from core.database import db_config, init_db, Base
        from models import User, Scan, Vulnerability
        
        print("Testing PostgreSQL connection...")
        
        # Check health
        is_healthy = await db_config.health_check()
        if is_healthy:
            print("✓ Database connection successful!")
        else:
            print("✗ Database connection failed!")
            return False
        
        # Initialize tables
        print("Creating database tables...")
        await init_db()
        print("✓ Database tables created successfully!")
        
        # Get pool status
        pool_status = await db_config.get_connection_pool_status()
        print(f"✓ Connection pool status: {pool_status}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = asyncio.run(test_connection())
    sys.exit(0 if success else 1)

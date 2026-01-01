import asyncio
from sqlalchemy import text
from core.database import engine

async def get_user_columns():
    async with engine.connect() as conn:
        result = await conn.execute(text("""
            SELECT column_name, ordinal_position, data_type
            FROM information_schema.columns
            WHERE table_name = 'users'
            ORDER BY ordinal_position
        """))
        for row in result:
            print(f"{row[1]:>2}: {row[0]:<30} | {row[2]}")

if __name__ == "__main__":
    asyncio.run(get_user_columns())

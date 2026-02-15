import asyncio
from sqlalchemy import text
from core.database import engine

async def inspect_pg_schema():
    print("Inspecting PostgreSQL schema...")
    report = "Inspecting ALL tables for naive timestamps...\n"
    async with engine.connect() as conn:
        result = await conn.execute(text("""
            SELECT table_name, column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = 'public'
            AND data_type = 'timestamp without time zone'
            ORDER BY table_name, column_name;
        """))
        rows = result.fetchall()
        if not rows:
            report += "No naive timestamp columns found in any table.\n"
        else:
            report += f"Found {len(rows)} naive timestamp columns:\n"
            report += "{:<25} | {:<25} | {:<25}\n".format("Table", "Column", "Type")
            report += "-" * 80 + "\n"
            for row in rows:
                report += f"{row[0]:<25} | {row[1]:<25} | {row[2]}\n"
            
    with open("pg_schema_report.txt", "w") as f:
        f.write(report)
    print("Report written to pg_schema_report.txt")

if __name__ == "__main__":
    asyncio.run(inspect_pg_schema())

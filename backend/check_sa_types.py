import asyncio
from core.database import Base, get_table_info
from models.user import User, APIToken, UserActivity
from models.scan import Scan
from models.vulnerability import Vulnerability

async def check_sqlalchemy_types():
    print("Checking SQLAlchemy model types...")
    tables = await get_table_info()
    
    report = "SQLAlchemy Model Types Audit:\n"
    for table in tables:
        report += f"\nTable: {table['name']}\n"
        for col in table['columns']:
            if "DATETIME" in col['type'].upper() or "TIMESTAMP" in col['type'].upper():
                report += f"  {col['name']:<30} | {col['type']}\n"
                
    with open("sqlalchemy_types_report.txt", "w") as f:
        f.write(report)
    print("Report written to sqlalchemy_types_report.txt")

if __name__ == "__main__":
    asyncio.run(check_sqlalchemy_types())

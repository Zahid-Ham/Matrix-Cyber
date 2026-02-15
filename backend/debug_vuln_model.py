import sys
import os
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from models.vulnerability import Vulnerability, Severity, VulnerabilityType, Base
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    print("Imports successful.")
    
    # Setup in-memory DB
    engine = create_engine('sqlite:///:memory:')
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    v = Vulnerability(
        scan_id=1,
        vulnerability_type="sql_injection",
        severity="high",
        title="Test",
        description="Test",
        url="http://test.com"
    )
    session.add(v)
    session.commit()
    print("Commit successful.")
    print(f"Detected at: {v.detected_at}")
    print(f"Severity Enum: {v.severity} ({type(v.severity)})")
    
except Exception as e:
    print(f"CRASHED: {e}")
    import traceback
    traceback.print_exc()

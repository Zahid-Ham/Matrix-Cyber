from sqlalchemy import Column, Integer, Numeric, TIMESTAMP, ForeignKey
from sqlalchemy.sql import func
from core.database import Base

class VulnerabilityValuation(Base):
    __tablename__ = "vulnerability_valuation"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=True) # Assuming vulnerabilities table exists and has id
    calculated_min = Column(Numeric(12, 2), nullable=True)
    calculated_max = Column(Numeric(12, 2), nullable=True)
    calculated_avg = Column(Numeric(12, 2), nullable=True)
    confidence_score = Column(Numeric(5, 2), nullable=True) # 0 to 100
    severity_multiplier = Column(Numeric(5, 2), nullable=True)
    industry_multiplier = Column(Numeric(5, 2), nullable=True)
    scale_multiplier = Column(Numeric(5, 2), nullable=True)
    complexity_multiplier = Column(Numeric(5, 2), nullable=True)
    total_financial_impact_min = Column(Numeric(15, 2), nullable=True)
    total_financial_impact_max = Column(Numeric(15, 2), nullable=True)
    total_financial_impact_avg = Column(Numeric(15, 2), nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

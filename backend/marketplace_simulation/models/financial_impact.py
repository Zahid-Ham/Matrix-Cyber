from sqlalchemy import Column, Integer, String, Numeric, Text, TIMESTAMP
from sqlalchemy.sql import func
from core.database import Base

class FinancialImpact(Base):
    __tablename__ = "financial_impact"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cost_category = Column(String(100), nullable=True)
    industry = Column(String(100), nullable=True)
    company_size = Column(String(50), nullable=True)
    min_cost = Column(Numeric(15, 2), nullable=True)
    max_cost = Column(Numeric(15, 2), nullable=True)
    avg_cost = Column(Numeric(15, 2), nullable=True)
    calculation_method = Column(Text, nullable=True)
    real_world_example = Column(Text, nullable=True)
    source = Column(String(200), nullable=True)
    year = Column(Integer, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

-- Exploit Pricing Table
CREATE TABLE IF NOT EXISTS exploit_pricing (
    id SERIAL PRIMARY KEY,
    vulnerability_type VARCHAR(100),
    severity VARCHAR(10), -- ENUM('Critical', 'High', 'Medium', 'Low')
    target_industry VARCHAR(100),
    min_usd DECIMAL(12, 2),
    max_usd DECIMAL(12, 2),
    avg_usd DECIMAL(12, 2),
    complexity VARCHAR(50),
    buyer_type VARCHAR(100),
    trend VARCHAR(50),
    reference VARCHAR(200),
    updated INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Financial Impact Table
CREATE TABLE IF NOT EXISTS financial_impact (
    id SERIAL PRIMARY KEY,
    cost_category VARCHAR(100),
    industry VARCHAR(100),
    company_size VARCHAR(50),
    min_cost DECIMAL(15, 2),
    max_cost DECIMAL(15, 2),
    avg_cost DECIMAL(15, 2),
    calculation_method TEXT,
    real_world_example TEXT,
    source VARCHAR(200),
    year INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerability Valuation Table
CREATE TABLE IF NOT EXISTS vulnerability_valuation (
    id SERIAL PRIMARY KEY,
    vulnerability_id INTEGER REFERENCES vulnerabilities(id),
    calculated_min DECIMAL(12, 2),
    calculated_max DECIMAL(12, 2),
    calculated_avg DECIMAL(12, 2),
    confidence_score DECIMAL(5, 2),
    severity_multiplier DECIMAL(5, 2),
    industry_multiplier DECIMAL(5, 2),
    scale_multiplier DECIMAL(5, 2),
    complexity_multiplier DECIMAL(5, 2),
    total_financial_impact_min DECIMAL(15, 2),
    total_financial_impact_max DECIMAL(15, 2),
    total_financial_impact_avg DECIMAL(15, 2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

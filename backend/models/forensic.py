"""
Forensic Models for Digital Forensics & Evidence Layer.
"""
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, JSON, 
    Boolean, Float, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from core.database import Base

class ForensicRecord(Base):
    """
    Main forensic record for a scan.
    Links a scan to its forensic metadata, hash manifests, and integrity status.
    """
    __tablename__ = "forensic_records"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    # Globally Unique Evidence ID for the scan
    evidence_id = Column(String(64), default=lambda: f"EVID-SCAN-{uuid.uuid4().hex[:12].upper()}", unique=True, nullable=False, index=True)
    
    # Forensic context
    operator_id = Column(String(255), nullable=True) # Could link to user or system ID
    system_version = Column(String(50), nullable=True)
    environment_metadata = Column(JSON, default=dict) # OS, Python version, etc.
    
    # Integrity metrics
    is_tampered = Column(Boolean, default=False)
    integrity_status = Column(String(50), default="VALID") # VALID, WARNING, TAMPERED
    
    # Cryptographic Manifest
    hash_manifest = Column(JSON, default=dict) # Map of finding/artifact IDs to SHA-256 hashes
    scan_hash = Column(String(64), nullable=True) # SHA-256 hash of the entire scan metadata
    
    # Export status
    bundle_path = Column(String(512), nullable=True)
    last_exported_at = Column(DateTime(timezone=True), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), 
                       onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    scan = relationship("Scan", backref="forensic_record")
    timeline = relationship("ForensicTimeline", back_populates="forensic_record", cascade="all, delete-orphan", lazy="dynamic")
    artifacts = relationship("ForensicArtifact", back_populates="forensic_record", cascade="all, delete-orphan", lazy="dynamic")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "evidence_id": self.evidence_id,
            "integrity_status": self.integrity_status,
            "is_tampered": self.is_tampered,
            "scan_hash": self.scan_hash,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }

class ForensicTimeline(Base):
    """
    Chronological, immutable record of every major event in a scan.
    """
    __tablename__ = "forensic_timeline"

    id = Column(Integer, primary_key=True, index=True)
    forensic_record_id = Column(Integer, ForeignKey("forensic_records.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Unique ID for this specific timeline entry
    event_id = Column(String(64), default=lambda: f"EVT-{uuid.uuid4().hex[:8].upper()}", unique=True, index=True)
    
    # Event details
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    event_type = Column(String(100), nullable=False) # SCAN_START, FINDING_DETECTED, ARTIFACT_COLLECTED, AGENT_STEP
    source_module = Column(String(255), nullable=False) # e.g. "sql_injection_agent", "orchestrator"
    description = Column(Text, nullable=False)
    
    # Optional references
    vulnerability_id = Column(Integer, nullable=True)
    artifact_id = Column(Integer, nullable=True)
    
    # Immutable Hash
    event_hash = Column(String(64), nullable=False) # SHA-256 of the event data (excluding this field)

    # Relationships
    forensic_record = relationship("ForensicRecord", back_populates="timeline")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "source_module": self.source_module,
            "description": self.description,
            "vulnerability_id": self.vulnerability_id,
            "artifact_id": self.artifact_id
        }

class ForensicArtifact(Base):
    """
    Store for raw data and artifacts collected during a scan.
    """
    __tablename__ = "forensic_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    forensic_record_id = Column(Integer, ForeignKey("forensic_records.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Unique Evidence ID for the artifact
    artifact_evidence_id = Column(String(64), default=lambda: f"ARTI-{uuid.uuid4().hex[:8].upper()}", unique=True, index=True)
    
    # Artifact metadata
    name = Column(String(255), nullable=False)
    artifact_type = Column(String(50), nullable=False) # HTTP_REQUEST, HTTP_RESPONSE, SOURCE_CODE, SCREENSHOT
    content_type = Column(String(100), default="application/octet-stream")
    
    # Storage (Actual data can be in JSON or separately in files)
    raw_data = Column(Text, nullable=True) 
    metadata_json = Column(JSON, default=dict)
    
    # Integrity
    sha256_hash = Column(String(64), nullable=False, index=True)
    collection_time = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    forensic_record = relationship("ForensicRecord", back_populates="artifacts")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_evidence_id": self.artifact_evidence_id,
            "name": self.name,
            "artifact_type": self.artifact_type,
            "sha256_hash": self.sha256_hash,
            "collection_time": self.collection_time.isoformat(),
            "metadata": self.metadata_json,
            "raw_data": self.raw_data
        }

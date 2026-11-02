from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Enum as SQLEnum
from sqlalchemy.sql import func
from database import Base
import enum

class Role(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"
    AUDITOR = "auditor"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(SQLEnum(Role), default=Role.USER, nullable=False)
    phone_encrypted = Column(Text, nullable=True)
    id_card_encrypted = Column(Text, nullable=True)
    bank_card_encrypted = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(100), nullable=False)
    resource = Column(String(100), nullable=False)
    ip_address = Column(String(50), nullable=False)
    result = Column(String(20), nullable=False)  # success, failure
    details = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
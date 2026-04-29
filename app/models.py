from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from datetime import datetime

from app.database import Base


# USERS TABLE
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    public_key = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)



# DATA LOGS TABLE
class DataLog(Base):
    __tablename__ = "data_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    payload = Column(String)
    is_valid = Column(Boolean)  # True = valid, False = tampered
    created_at = Column(DateTime, default=datetime.utcnow)
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func
from pydantic import BaseModel
from datetime import datetime
from server.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, unique=True, index=True)
    user_api_key = Column(String, unique=True)
    user_public_key = Column(String)
    password_img    = Column(Integer, nullable=True)
    password_wm     = Column(Integer, nullable=True)
    watermark_length = Column(Integer, nullable=True)
    create_dt = Column(DateTime(timezone=True), server_default=func.now())
    update_dt = Column(DateTime(timezone=True), onupdate=func.now())

class UserCreate(BaseModel):
    user_id: str
    user_public_key: str | None = None

class UserResponse(BaseModel):
    user_id: str
    user_api_key: str
    create_dt: datetime

class UserKeyUpdate(BaseModel):
    app_key: str
    user_public_key: str
    password_img: int
    password_wm: int


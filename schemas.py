"""
Database Schemas for PG Buddy

Each Pydantic model corresponds to a MongoDB collection whose name is the lowercase of the class name.
- User -> "user"
- College -> "college"
- Pg -> "pg"
- Review -> "review"
- Inquiry -> "inquiry"
"""

from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Literal
from datetime import datetime


class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    role: Literal["student", "owner"] = Field(..., description="User role")
    phone: Optional[str] = Field(None, description="Phone number for WhatsApp/contact")
    password_hash: Optional[str] = Field(None, description="BCrypt password hash (server-side only)")
    is_active: bool = Field(True, description="Whether user is active")


class College(BaseModel):
    name: str
    city: str


class Pg(BaseModel):
    name: str
    owner_id: str = Field(..., description="Owner user's ID")
    college: str = Field(..., description="College name")
    city: Optional[str] = Field(None, description="City where PG located")
    address: Optional[str] = None
    rent: int = Field(..., ge=0)
    facilities: List[str] = Field(default_factory=list)
    gender: Literal["male", "female", "unisex"] = "unisex"
    images: List[str] = Field(default_factory=list)
    location: Optional[dict] = Field(default=None, description="{lat, lng}")
    views: int = 0
    inquiries_count: int = 0


class Review(BaseModel):
    pg_id: str
    user_id: str
    rating: int = Field(..., ge=1, le=5)
    comment: Optional[str] = None


class Inquiry(BaseModel):
    pg_id: str
    name: str
    email: EmailStr
    message: Optional[str] = None
    phone: Optional[str] = None


# Response helpers
class PgWithMeta(BaseModel):
    id: str
    name: str
    owner_id: str
    college: str
    city: Optional[str] = None
    address: Optional[str] = None
    rent: int
    facilities: List[str]
    gender: str
    images: List[str]
    location: Optional[dict] = None
    views: int = 0
    inquiries_count: int = 0
    avg_rating: float = 0.0
    reviews_count: int = 0
    owner_phone: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

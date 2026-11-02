from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime
from models import Role
import re

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern="^[a-zA-Z0-9_]+$")
    email: EmailStr
    full_name: str = Field(..., min_length=1, max_length=100)

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)
    phone: Optional[str] = None
    id_card: Optional[str] = None
    bank_card: Optional[str] = None
    
    @field_validator('phone')
    def validate_phone(cls, v):
        if v and not re.match(r'^1[3-9]\d{9}$', v):
            raise ValueError('手机号格式不正确')
        return v
    
    @field_validator('id_card')
    def validate_id_card(cls, v):
        if v and not re.match(r'^[1-9]\d{5}(18|19|20)\d{2}((0[1-9])|(1[0-2]))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$', v):
            raise ValueError('身份证格式不正确')
        return v
    
    @field_validator('bank_card')
    def validate_bank_card(cls, v):
        if v and not re.match(r'^\d{16,19}$', v):
            raise ValueError('银行卡格式不正确')
        return v

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(UserBase):
    id: int
    role: Role
    is_active: bool
    last_login: Optional[datetime] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

class UserProfile(UserResponse):
    phone: Optional[str] = None
    id_card: Optional[str] = None
    bank_card: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)

class EncryptRequest(BaseModel):
    data: str
    field_type: str = Field(..., pattern="^(phone|id_card|bank_card|email)$")

class EncryptResponse(BaseModel):
    encrypted: str
    masked: str

class DecryptRequest(BaseModel):
    encrypted: str

class DecryptResponse(BaseModel):
    decrypted: str

class AuditLogEntry(BaseModel):
    id: int
    user_id: Optional[int] = None
    action: str
    resource: str
    ip_address: str
    result: str
    details: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True

class ErrorResponse(BaseModel):
    status: int
    message: str
    request_id: str
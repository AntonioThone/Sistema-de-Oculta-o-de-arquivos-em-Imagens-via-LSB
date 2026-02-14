from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    username: str
    email: Optional[str] = None
    password: str

class UserInDB(User):
    id: int
    created_at: datetime
    is_active: bool = True

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str

class TokenData(BaseModel):
    username: Optional[str] = None

class EncodeRequest(BaseModel):
    cover_image: str  # Base64
    secret_data: str  # Base64
    secret_filename: str
    key: str

class DecodeRequest(BaseModel):
    stego_image: str  # Base64
    key: str

class OperationLog(BaseModel):
    id: int
    user_id: int
    action: str
    details: str
    timestamp: datetime
    ip_address: Optional[str]

class HistoryEntry(BaseModel):
    id: int
    operation_type: str
    original_filename: str
    result_filename: str
    file_size: int
    operation_date: datetime
    status: str
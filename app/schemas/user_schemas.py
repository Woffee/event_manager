from builtins import ValueError, any, bool, str
from pydantic import BaseModel, EmailStr, Field, validator, root_validator
from typing import Optional, List
from datetime import datetime
from enum import Enum
import uuid
import re

from app.utils.nickname_gen import generate_nickname

class UserRole(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    AUTHENTICATED = "AUTHENTICATED"
    MANAGER = "MANAGER"
    ADMIN = "ADMIN"

def validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    url_regex = r'^https?:\/\/[^\s/$.?#].[^\s]*$'
    if not re.match(url_regex, url):
        raise ValueError('Invalid URL format')
    return url

def github_validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    github_url_regex = r'^https?:\/\/(www\.)?github\.com\/[a-zA-Z0-9-_]+\/?$'

    if not re.match(github_url_regex, url):
        raise ValueError('Invalid GitHub profile URL. It should match: https://github.com/<username>.')
    
    return url

def linkedin_validate_url(url: Optional[str]) -> Optional[str]:
    if url is None:
        return url
    linkedin_url_regex = r'^https?:\/\/(www\.)?linkedin\.com\/in\/[a-zA-Z0-9-_]+\/?$'

    if not re.match(linkedin_url_regex, url):
        raise ValueError('Invalid LinkedIn profile URL. It should match: https://linkedin.com/in/<username>.')
    
    return url

def validate_nickname(nickname: Optional[str]) -> Optional[str]:
    if nickname is None:
        return nickname
    
    if len(nickname) < 3 or len(nickname) > 20:
        raise ValueError(f"Nickname must be between 3 and 20 characters.")

    nickname_regex = r'^[a-z0-9_-]+$'
    if not re.match(nickname_regex, nickname):
        raise ValueError("Nickname can only contain lowercase letters, numbers, underscores, and hyphens.")

    return nickname

def validate_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    
    has_uppercase = False
    has_lowercase = False
    for i in password:
        if i.isupper():
            has_uppercase = True
        if i.islower():
            has_lowercase = True
        if has_lowercase and has_uppercase:
            break
    
    if not has_uppercase or not has_lowercase:
        raise ValueError("Password must contain at least one uppercase and lowercase letter.")
    
    has_digit = False
    for i in password:
        if i.isdigit():
            has_digit = True
            break
    if not has_digit:
        raise ValueError("Password must contain at least one number.")
        
    return password

class UserBase(BaseModel):
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(None, example=generate_nickname())
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] =Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")

    _validate_nickname = validator('nickname', pre=True, allow_reuse=True)(validate_nickname)

    _validate_urls = validator('profile_picture_url', 'linkedin_profile_url', 'github_profile_url', pre=True, allow_reuse=True)(validate_url)
    _validate_github_url = validator('github_profile_url', pre=True, allow_reuse=True)(github_validate_url)
    _validate_linkedin_url = validator('linkedin_profile_url', pre=True, allow_reuse=True)(linkedin_validate_url)

    class Config:
        from_attributes = True

class UserCreate(UserBase):
    email: EmailStr = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")
    _validate_password = validator('password', pre=True, allow_reuse=True)(validate_password)

class UserUpdate(UserBase):
    email: Optional[EmailStr] = Field(None, example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example="john_doe123")
    first_name: Optional[str] = Field(None, example="John")
    last_name: Optional[str] = Field(None, example="Doe")
    bio: Optional[str] = Field(None, example="Experienced software developer specializing in web applications.")
    profile_picture_url: Optional[str] = Field(None, example="https://example.com/profiles/john.jpg")
    linkedin_profile_url: Optional[str] =Field(None, example="https://linkedin.com/in/johndoe")
    github_profile_url: Optional[str] = Field(None, example="https://github.com/johndoe")

    @root_validator(pre=True)
    def check_at_least_one_value(cls, values):
        if not any(values.values()):
            raise ValueError("At least one field must be provided for update")
        return values

class UserResponse(UserBase):
    id: uuid.UUID = Field(..., example=uuid.uuid4())
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    email: EmailStr = Field(..., example="john.doe@example.com")
    nickname: Optional[str] = Field(None, min_length=3, pattern=r'^[\w-]+$', example=generate_nickname())    
    role: UserRole = Field(default=UserRole.AUTHENTICATED, example="AUTHENTICATED")
    is_professional: Optional[bool] = Field(default=False, example=True)

class LoginRequest(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="Secure*1234")

class ErrorResponse(BaseModel):
    error: str = Field(..., example="Not Found")
    details: Optional[str] = Field(None, example="The requested resource was not found.")

class UserListResponse(BaseModel):
    items: List[UserResponse] = Field(..., example=[{
        "id": uuid.uuid4(), "nickname": generate_nickname(), "email": "john.doe@example.com",
        "first_name": "John", "bio": "Experienced developer", "role": "AUTHENTICATED",
        "last_name": "Doe", "bio": "Experienced developer", "role": "AUTHENTICATED",
        "profile_picture_url": "https://example.com/profiles/john.jpg", 
        "linkedin_profile_url": "https://linkedin.com/in/johndoe", 
        "github_profile_url": "https://github.com/johndoe"
    }])
    total: int = Field(..., example=100)
    page: int = Field(..., example=1)
    size: int = Field(..., example=10)

"""Authentication and authorization module"""

from datetime import datetime, timedelta
from typing import Optional, Dict
import secrets
import hashlib
from jose import jwt, JWTError
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# Configuration
SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
API_KEY_LENGTH = 32

# Security scheme
security = HTTPBearer()


class User(BaseModel):
    """User model"""
    user_id: str
    username: str
    email: str
    is_active: bool = True
    is_admin: bool = False
    created_at: str


class UserCreate(BaseModel):
    """User creation model"""
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    """User login model"""
    username: str
    password: str


class Token(BaseModel):
    """Token response model"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class APIKey(BaseModel):
    """API key model"""
    key_id: str
    key: str
    name: str
    created_at: str
    expires_at: Optional[str] = None


# In-memory storage (replace with database in production)
users_db: Dict[str, Dict] = {}
api_keys_db: Dict[str, Dict] = {}


def hash_password(password: str) -> str:
    """
    Hash a password using SHA-256.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password
    """
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        plain_password: Plain text password
        hashed_password: Hashed password
        
    Returns:
        True if password matches
    """
    return hash_password(plain_password) == hashed_password


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Data to encode in the token
        expires_delta: Token expiration time
        
    Returns:
        Encoded JWT token
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    """
    Decode and verify a JWT access token.
    
    Args:
        token: JWT token
        
    Returns:
        Decoded token data
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError as e:
        if "expired" in str(e).lower():
            raise HTTPException(status_code=401, detail="Token has expired")
        raise HTTPException(status_code=401, detail="Invalid token")


def generate_api_key() -> str:
    """
    Generate a random API key.
    
    Returns:
        Random API key string
    """
    return secrets.token_urlsafe(API_KEY_LENGTH)


def register_user(user_data: UserCreate) -> User:
    """
    Register a new user.
    
    Args:
        user_data: User registration data
        
    Returns:
        Created user
        
    Raises:
        HTTPException: If username already exists
    """
    # Check if username exists
    if any(u["username"] == user_data.username for u in users_db.values()):
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Check if email exists
    if any(u["email"] == user_data.email for u in users_db.values()):
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Create user
    user_id = secrets.token_urlsafe(16)
    user = {
        "user_id": user_id,
        "username": user_data.username,
        "email": user_data.email,
        "password_hash": hash_password(user_data.password),
        "is_active": True,
        "is_admin": False,
        "created_at": datetime.now().isoformat()
    }
    
    users_db[user_id] = user
    
    return User(
        user_id=user["user_id"],
        username=user["username"],
        email=user["email"],
        is_active=user["is_active"],
        is_admin=user["is_admin"],
        created_at=user["created_at"]
    )


def authenticate_user(username: str, password: str) -> Optional[User]:
    """
    Authenticate a user with username and password.
    
    Args:
        username: Username
        password: Password
        
    Returns:
        User if authentication successful, None otherwise
    """
    user = next((u for u in users_db.values() if u["username"] == username), None)
    
    if not user:
        return None
    
    if not verify_password(password, user["password_hash"]):
        return None
    
    if not user["is_active"]:
        return None
    
    return User(
        user_id=user["user_id"],
        username=user["username"],
        email=user["email"],
        is_active=user["is_active"],
        is_admin=user["is_admin"],
        created_at=user["created_at"]
    )


def login(login_data: UserLogin) -> Token:
    """
    Login a user and return an access token.
    
    Args:
        login_data: Login credentials
        
    Returns:
        Access token
        
    Raises:
        HTTPException: If authentication fails
    """
    user = authenticate_user(login_data.username, login_data.password)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    # Create access token
    access_token = create_access_token(
        data={"sub": user.user_id, "username": user.username}
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


def create_api_key(user_id: str, name: str, expires_days: Optional[int] = None) -> APIKey:
    """
    Create an API key for a user.
    
    Args:
        user_id: User ID
        name: API key name
        expires_days: Optional expiration in days
        
    Returns:
        Created API key
    """
    key_id = secrets.token_urlsafe(16)
    key = generate_api_key()
    
    expires_at = None
    if expires_days:
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat()
    
    api_key_data = {
        "key_id": key_id,
        "key": key,
        "user_id": user_id,
        "name": name,
        "created_at": datetime.now().isoformat(),
        "expires_at": expires_at
    }
    
    api_keys_db[key] = api_key_data
    
    return APIKey(
        key_id=key_id,
        key=key,
        name=name,
        created_at=api_key_data["created_at"],
        expires_at=expires_at
    )


def validate_api_key(api_key: str) -> Optional[str]:
    """
    Validate an API key and return the associated user ID.
    
    Args:
        api_key: API key to validate
        
    Returns:
        User ID if valid, None otherwise
    """
    key_data = api_keys_db.get(api_key)
    
    if not key_data:
        return None
    
    # Check expiration
    if key_data["expires_at"]:
        expires_at = datetime.fromisoformat(key_data["expires_at"])
        if datetime.now() > expires_at:
            return None
    
    return key_data["user_id"]


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> User:
    """
    Dependency to get the current authenticated user from JWT token.
    
    Args:
        credentials: HTTP authorization credentials
        
    Returns:
        Current user
        
    Raises:
        HTTPException: If authentication fails
    """
    token = credentials.credentials
    
    # Try JWT token first
    try:
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = users_db.get(user_id)
        
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(
            user_id=user["user_id"],
            username=user["username"],
            email=user["email"],
            is_active=user["is_active"],
            is_admin=user["is_admin"],
            created_at=user["created_at"]
        )
    except HTTPException:
        # Try API key
        user_id = validate_api_key(token)
        
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = users_db.get(user_id)
        
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return User(
            user_id=user["user_id"],
            username=user["username"],
            email=user["email"],
            is_active=user["is_active"],
            is_admin=user["is_admin"],
            created_at=user["created_at"]
        )


async def get_current_admin_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency to get the current authenticated admin user.
    
    Args:
        current_user: Current user from get_current_user
        
    Returns:
        Current admin user
        
    Raises:
        HTTPException: If user is not an admin
    """
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    return current_user

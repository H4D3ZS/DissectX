"""Authentication API endpoints"""

from fastapi import APIRouter, Depends, HTTPException
from typing import List

from src.vulnchain.core.auth import (
    User, UserCreate, UserLogin, Token, APIKey,
    register_user, login, create_api_key,
    get_current_user, get_current_admin_user
)

router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.post("/register", response_model=User)
async def register(user_data: UserCreate):
    """
    Register a new user.
    
    Args:
        user_data: User registration data
        
    Returns:
        Created user
    """
    return register_user(user_data)


@router.post("/login", response_model=Token)
async def login_endpoint(login_data: UserLogin):
    """
    Login and receive an access token.
    
    Args:
        login_data: Login credentials
        
    Returns:
        Access token
    """
    return login(login_data)


@router.get("/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    """
    Get current user information.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Current user
    """
    return current_user


@router.post("/api-keys", response_model=APIKey)
async def create_api_key_endpoint(
    name: str,
    expires_days: int = None,
    current_user: User = Depends(get_current_user)
):
    """
    Create a new API key for the current user.
    
    Args:
        name: API key name
        expires_days: Optional expiration in days
        current_user: Current authenticated user
        
    Returns:
        Created API key
    """
    return create_api_key(current_user.user_id, name, expires_days)


@router.get("/test-protected")
async def test_protected_endpoint(current_user: User = Depends(get_current_user)):
    """
    Test endpoint that requires authentication.
    
    Args:
        current_user: Current authenticated user
        
    Returns:
        Success message
    """
    return {
        "message": "You are authenticated!",
        "user": current_user.username
    }


@router.get("/test-admin")
async def test_admin_endpoint(current_user: User = Depends(get_current_admin_user)):
    """
    Test endpoint that requires admin access.
    
    Args:
        current_user: Current authenticated admin user
        
    Returns:
        Success message
    """
    return {
        "message": "You have admin access!",
        "user": current_user.username
    }

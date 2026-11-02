from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.jwt_handler import jwt_handler
from models import Role
from typing import Optional

security = HTTPBearer()

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """从JWT令牌获取当前用户"""
    token = credentials.credentials
    payload = jwt_handler.verify_token(token)
    
    if not payload:
        raise HTTPException(
            status_code=401,
            detail="无效或过期的令牌"
        )
    
    user_id = int(payload.get("sub"))
    role = Role(payload.get("role"))
    
    return {
        "user_id": user_id,
        "role": role
    }

def require_role(*required_roles):
    """要求特定角色的依赖"""
    async def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in required_roles:
            raise HTTPException(
                status_code=403,
                detail="权限不足"
            )
        return current_user
    return role_checker

async def optional_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """如果提供了令牌，则获取当前用户"""
    if not credentials:
        return None
    
    token = credentials.credentials
    payload = jwt_handler.verify_token(token)
    
    if not payload:
        return None
    
    user_id = int(payload.get("sub"))
    role = Role(payload.get("role"))
    
    return {
        "user_id": user_id,
        "role": role
    }
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from database import get_db
from models import User, Role
from schemas import UserCreate, UserLogin, TokenResponse, RefreshTokenRequest, ChangePassword
from auth.jwt_handler import jwt_handler
from auth.rbac import get_current_user
from security.csrf import csrf_protection
from security.encryption import encryption_service
from security.mask import mask_sensitive_data
from security.rate_limiter import sensitive_rate_limit
import bcrypt
import time
from datetime import datetime

router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/register", response_model=TokenResponse)
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    response: Response = None
):
    """注册新用户"""
    existing_user = await db.execute(
        select(User).where(
            (User.username == user_data.username) | (User.email == user_data.email)
        )
    )
    if existing_user.scalar():
        raise HTTPException(status_code=400, detail="用户名或邮箱已存在")

    password_hash = bcrypt.hashpw(user_data.password.encode('utf-8'), bcrypt.gensalt(10)).decode('utf-8')

    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=password_hash,
        full_name=user_data.full_name
    )

    if user_data.phone:
        user.phone_encrypted = encryption_service.encrypt(user_data.phone)
    if user_data.id_card:
        user.id_card_encrypted = encryption_service.encrypt(user_data.id_card)
    if user_data.bank_card:
        user.bank_card_encrypted = encryption_service.encrypt(user_data.bank_card)

    db.add(user)
    await db.commit()
    await db.refresh(user)

    access_token = jwt_handler.create_access_token(user.id, user.role)
    refresh_token = jwt_handler.create_refresh_token(user.id)

    csrf_token = csrf_protection.generate_token()
    csrf_protection.set_token_cookie(response, csrf_token)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "csrf_token": csrf_token
    }

@router.post("/login", response_model=TokenResponse)
async def login(
    login_data: UserLogin,
    db: AsyncSession = Depends(get_db),
    response: Response = None
):
    """用户登录"""
    try:
        result = await db.execute(select(User).where(User.username == login_data.username))
        user = result.scalar()

        if not user:
            raise HTTPException(status_code=401, detail="用户名或密码错误")

        if not bcrypt.checkpw(login_data.password.encode('utf-8'), user.password_hash.encode('utf-8')):
            raise HTTPException(status_code=401, detail="用户名或密码错误")

        user.last_login = datetime.utcnow()
        await db.commit()

        access_token = jwt_handler.create_access_token(user.id, user.role)
        refresh_token = jwt_handler.create_refresh_token(user.id)

        csrf_token = csrf_protection.generate_token()
        csrf_protection.set_token_cookie(response, csrf_token)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "csrf_token": csrf_token
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="登录失败")

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    refresh_data: Optional[RefreshTokenRequest] = None,
    db: AsyncSession = Depends(get_db)
):
    """刷新访问令牌"""
    refresh_token_value = request.cookies.get("refresh_token")
    if not refresh_token_value and refresh_data:
        refresh_token_value = refresh_data.refresh_token

    if not refresh_token_value:
        raise HTTPException(status_code=400, detail="需要刷新令牌")

    payload = jwt_handler.verify_refresh_token(refresh_token_value)
    if not payload:
        raise HTTPException(status_code=401, detail="无效或过期的刷新令牌")

    user_id = int(payload.get("sub"))
    token_family = payload.get("token_family")

    user = await db.execute(select(User).where(User.id == user_id))
    user = user.scalar()

    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")

    access_token = jwt_handler.create_access_token(user.id, user.role)
    new_refresh_token = jwt_handler.rotate_refresh_token(user_id, token_family)

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@router.post("/logout")
async def logout(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """用户登出"""
    return {"message": "登出成功"}

@router.post("/change-password")
async def change_password(
    password_data: ChangePassword,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """修改密码"""
    user_id = current_user["user_id"]

    user = await db.execute(select(User).where(User.id == user_id))
    user = user.scalar()

    if not bcrypt.checkpw(password_data.current_password.encode('utf-8'), user.password_hash.encode('utf-8')):
        raise HTTPException(status_code=400, detail="当前密码错误")

    user.password_hash = bcrypt.hashpw(password_data.new_password.encode('utf-8'), bcrypt.gensalt(10)).decode('utf-8')

    await db.commit()

    return {"message": "密码修改成功"}

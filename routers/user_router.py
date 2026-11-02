from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from database import get_db
from models import User
from schemas import UserResponse, UserProfile, EncryptRequest, EncryptResponse, DecryptRequest, DecryptResponse
from auth.rbac import get_current_user, require_role
from security.encryption import encryption_service
from security.mask import mask_sensitive_data, mask_phone, mask_id_card, mask_bank_card, mask_email
from security.csrf import csrf_protection
from models import Role

router = APIRouter(prefix="/api/users", tags=["users"])

@router.get("/me", response_model=UserProfile)
async def get_current_user_profile(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取当前用户信息"""
    user_id = current_user["user_id"]
    
    # 获取用户
    user = await db.execute(select(User).where(User.id == user_id))
    user = user.scalar()
    
    if not user:
        raise HTTPException(
            status_code=404,
            detail="用户不存在"
        )
    
    # 解密敏感数据
    phone = None
    id_card = None
    bank_card = None
    
    if user.phone_encrypted:
        try:
            phone = encryption_service.decrypt(user.phone_encrypted)
        except:
            phone = "[解密错误]"
    
    if user.id_card_encrypted:
        try:
            id_card = encryption_service.decrypt(user.id_card_encrypted)
        except:
            id_card = "[解密错误]"
    
    if user.bank_card_encrypted:
        try:
            bank_card = encryption_service.decrypt(user.bank_card_encrypted)
        except:
            bank_card = "[解密错误]"
    
    return UserProfile(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        last_login=user.last_login,
        created_at=user.created_at,
        phone=phone,
        id_card=id_card,
        bank_card=bank_card
    )

@router.get("/me/masked", response_model=UserProfile)
async def get_masked_user_profile(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """获取当前用户信息（脱敏）"""
    user_id = current_user["user_id"]
    
    # 获取用户
    user = await db.execute(select(User).where(User.id == user_id))
    user = user.scalar()
    
    if not user:
        raise HTTPException(
            status_code=404,
            detail="用户不存在"
        )
    
    # 解密并脱敏敏感数据
    phone = None
    id_card = None
    bank_card = None
    
    if user.phone_encrypted:
        try:
            phone = encryption_service.decrypt(user.phone_encrypted)
            phone = mask_phone(phone)
        except:
            phone = "[解密错误]"
    
    if user.id_card_encrypted:
        try:
            id_card = encryption_service.decrypt(user.id_card_encrypted)
            id_card = mask_id_card(id_card)
        except:
            id_card = "[解密错误]"
    
    if user.bank_card_encrypted:
        try:
            bank_card = encryption_service.decrypt(user.bank_card_encrypted)
            bank_card = mask_bank_card(bank_card)
        except:
            bank_card = "[解密错误]"
    
    return UserProfile(
        id=user.id,
        username=user.username,
        email=mask_email(user.email),
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        last_login=user.last_login,
        created_at=user.created_at,
        phone=phone,
        id_card=id_card,
        bank_card=bank_card
    )

@router.get("/", response_model=list[UserResponse])
async def get_users(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_role(Role.ADMIN))
):
    """获取所有用户（仅管理员）"""
    users = await db.execute(select(User))
    users = users.scalars().all()
    
    return users

@router.post("/encrypt", response_model=EncryptResponse)
async def encrypt_data(
    encrypt_data: EncryptRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """加密敏感数据并保存到用户档案"""
    user_id = current_user["user_id"]

    user = await db.execute(select(User).where(User.id == user_id))
    user = user.scalar()

    encrypted = encryption_service.encrypt(encrypt_data.data)
    masked = mask_sensitive_data(encrypt_data.data, encrypt_data.field_type)

    field_type = encrypt_data.field_type.lower() if encrypt_data.field_type else ""
    if "phone" in field_type or "手机" in field_type:
        user.phone_encrypted = encrypted
    elif "id_card" in field_type or "身份证" in field_type:
        user.id_card_encrypted = encrypted
    elif "bank_card" in field_type or "银行卡" in field_type:
        user.bank_card_encrypted = encrypted

    await db.commit()

    return EncryptResponse(
        encrypted=encrypted,
        masked=masked
    )

@router.post("/decrypt", response_model=DecryptResponse)
async def decrypt_data(
    decrypt_data: DecryptRequest,
    current_user: dict = Depends(get_current_user)
):
    """解密敏感数据"""
    try:
        decrypted = encryption_service.decrypt(decrypt_data.encrypted)
        return DecryptResponse(decrypted=decrypted)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail="解密失败"
        )
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from config import settings
import secrets
from models import Role

class JwtHandler:
    def __init__(self):
        """初始化JWT处理器"""
        # 使用内存存储 refresh token 信息
        self.refresh_tokens = {}
    
    def create_access_token(self, user_id: int, role: str) -> str:
        """创建访问令牌"""
        payload = {
            "sub": str(user_id),
            "role": role,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=15)
        }
        return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")
    
    def create_refresh_token(self, user_id: int) -> str:
        """创建刷新令牌（带token family）"""
        # 生成 token family 和 ID
        token_family = secrets.token_hex(32)
        token_id = secrets.token_hex(32)
        
        # 存储 token family
        key = f"refresh_token:{user_id}"
        self.refresh_tokens[key] = {
            "family": token_family,
            "current_token": token_id,
            "expires_at": datetime.utcnow() + timedelta(days=7)
        }
        
        # 创建刷新令牌
        payload = {
            "sub": str(user_id),
            "token_family": token_family,
            "token_id": token_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=7)
        }
        return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """验证JWT令牌"""
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
            return payload
        except:
            return None
    
    def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """验证刷新令牌并检查重用"""
        payload = self.verify_token(token)
        if not payload:
            return None
        
        user_id = int(payload.get("sub"))
        token_family = payload.get("token_family")
        token_id = payload.get("token_id")
        
        if not user_id or not token_family or not token_id:
            return None
        
        # 检查令牌是否有效
        key = f"refresh_token:{user_id}"
        if key not in self.refresh_tokens:
            return None
        
        stored_data = self.refresh_tokens[key]
        if stored_data["family"] != token_family:
            # Token family 改变，可能是重用
            return None
        
        if stored_data["current_token"] != token_id:
            # Token 被重用，使整个 family 失效
            del self.refresh_tokens[key]
            return None
        
        if stored_data["expires_at"] < datetime.utcnow():
            # 令牌过期
            del self.refresh_tokens[key]
            return None
        
        return payload
    
    def rotate_refresh_token(self, user_id: int, old_token_family: str) -> str:
        """轮换刷新令牌"""
        # 生成新的 token ID
        new_token_id = secrets.token_hex(32)
        
        # 更新存储
        key = f"refresh_token:{user_id}"
        if key in self.refresh_tokens:
            self.refresh_tokens[key]["current_token"] = new_token_id
        
        # 创建新的刷新令牌
        payload = {
            "sub": str(user_id),
            "token_family": old_token_family,
            "token_id": new_token_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=7)
        }
        return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")

# 创建实例
jwt_handler = JwtHandler()
from typing import List
import os
from pathlib import Path

class Settings:
    def __init__(self):
        # 从.env文件加载环境变量
        env_path = Path(".env")
        if env_path.exists():
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip()
                        if key not in os.environ:
                            os.environ[key] = value
        
        # 数据库配置
        self.DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./security.db")
        
        # JWT配置
        self.JWT_SECRET = os.environ.get("JWT_SECRET", "your-secret-key-here")
        self.JWT_EXPIRES_IN = "15m"
        self.JWT_REFRESH_EXPIRES_IN = "7d"
        
        # 加密配置
        self.CURRENT_KEY = os.environ.get("ENCRYPTION_KEY_CURRENT", "your-encryption-key-here")
        old_keys = os.environ.get("ENCRYPTION_KEY_OLD", "")
        self.OLD_KEYS = [key.strip() for key in old_keys.split(",") if key.strip()]
        
        # Redis配置
        self.REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        
        # CORS配置
        cors_origins = os.environ.get("CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000")
        self.CORS_ORIGINS = [origin.strip() for origin in cors_origins.split(",")]
        
        # 安全配置
        self.CSRF_SECRET = os.environ.get("SECRET_KEY", "your-csrf-secret-here")
        self.RATE_LIMIT_GENERAL = int(os.environ.get("RATE_LIMIT_PER_MINUTE", "100"))
        self.RATE_LIMIT_SENSITIVE = int(os.environ.get("RATE_LIMIT_LOGIN_PER_MINUTE", "5"))
        
        # 日志配置
        self.LOG_LEVEL = "INFO"
        self.LOG_FILE = "app.log"

# 创建设置实例
settings = Settings()
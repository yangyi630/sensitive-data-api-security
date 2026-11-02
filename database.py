from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from config import settings

# 创建异步引擎
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True
)

# 创建异步会话生成器
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# ORM 模型基类
Base = declarative_base()

async def get_db():
    """获取数据库会话的依赖"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
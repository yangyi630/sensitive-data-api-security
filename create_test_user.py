import asyncio
import bcrypt
from datetime import datetime
from database import engine, get_db
from models import User, Base

async def create_test_user():
    # 创建数据库表
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # 创建测试用户
    username = "testuser"
    password = "123456"
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(10)).decode('utf-8')
    
    async for db in get_db():
        # 检查用户是否已存在
        from sqlalchemy import select
        result = await db.execute(select(User).where(User.username == username))
        existing_user = result.scalar()
        
        if existing_user:
            print(f"用户 '{username}' 已存在")
            return
        
        # 创建新用户
        user = User(
            username=username,
            email="testuser@example.com",
            full_name="Test User",
            password_hash=hashed_password,
            role="user",
            is_active=True,
            created_at=datetime.utcnow()
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        print(f"测试用户创建成功！")
        print(f"用户名: {username}")
        print(f"密码: {password}")
        print("请使用此账号登录测试")
        break

if __name__ == "__main__":
    asyncio.run(create_test_user())

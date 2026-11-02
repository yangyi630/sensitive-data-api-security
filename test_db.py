import asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.sql import text

async def test_db():
    try:
        # 测试数据库连接
        engine = create_async_engine('sqlite+aiosqlite:///./secure_db.db')
        
        async with engine.begin() as conn:
            # 测试连接
            result = await conn.execute(text("SELECT 1"))
            print(f"Database connection test: {result.scalar()}")
            
            # 测试用户表
            result = await conn.execute(text("SELECT * FROM users WHERE username = 'testuser'"))
            user = result.fetchone()
            if user:
                print(f"User found: {user}")
            else:
                print("User not found")
                
        await engine.dispose()
        print("Database test completed successfully")
        
    except Exception as e:
        print(f"Database test failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_db())
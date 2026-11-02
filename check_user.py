import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from database import engine, get_db
from models import User
from sqlalchemy import select

async def check_user():
    async with AsyncSession(engine) as session:
        try:
            # 检查是否存在testuser用户
            result = await session.execute(
                select(User).where(User.username == "testuser")
            )
            user = result.scalar()
            
            if user:
                print(f"User found: {user.username}")
                print(f"Role: {user.role}")
                print(f"Email: {user.email}")
            else:
                print("User not found")
                
            # 检查所有用户
            all_users = await session.execute(select(User))
            users = all_users.scalars().all()
            print(f"Total users: {len(users)}")
            for u in users:
                print(f"  - {u.username} ({u.role})")
                
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(check_user())
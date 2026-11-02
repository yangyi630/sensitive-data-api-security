import jwt
from datetime import datetime, timedelta
from config import settings

print("Testing JWT...")
print(f"JWT_SECRET: {settings.JWT_SECRET}")
print(f"JWT_SECRET length: {len(settings.JWT_SECRET)}")

# 测试JWT签名
try:
    payload = {
        "sub": "1",
        "role": "user",
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(minutes=15)
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")
    print(f"Generated token: {token}")
    
    # 测试JWT解码
    decoded = jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
    print(f"Decoded payload: {decoded}")
    print("JWT test passed!")
except Exception as e:
    print(f"JWT test failed: {e}")
    import traceback
    traceback.print_exc()
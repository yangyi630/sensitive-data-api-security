import asyncio
import aiohttp
import json
import uuid
import time

async def test_login():
    url = "http://127.0.0.1:8006/api/auth/login"
    headers = {
        "Content-Type": "application/json",
        "X-Nonce": str(uuid.uuid4()),
        "X-Timestamp": str(int(time.time() * 1000))
    }
    data = {
        "username": "test",
        "password": "test1234"
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, headers=headers, json=data) as response:
                status = response.status
                text = await response.text()
                print(f"Status: {status}")
                print(f"Response: {text}")
                print(f"Headers: {dict(response.headers)}")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_login())
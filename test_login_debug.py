import requests
import json
import uuid
import time

url = "http://127.0.0.1:8005/api/auth/login"
headers = {
    "Content-Type": "application/json",
    "X-Nonce": str(uuid.uuid4()),
    "X-Timestamp": str(int(time.time() * 1000))
}
data = {
    "username": "test",
    "password": "test1234"
}

response = requests.post(url, headers=headers, json=data)
print(f"Status Code: {response.status_code}")
print(f"Response Text: {response.text}")
print(f"Headers: {dict(response.headers)}")
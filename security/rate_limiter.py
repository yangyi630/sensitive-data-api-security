from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from config import settings
from utils.attack_counter import attack_counter
import time
from collections import defaultdict

rate_limit_store = defaultdict(list)

class RateLimitMiddleware:
    def __init__(self, app, max_requests: int = 15, window_seconds: int = 10):
        self.app = app
        self.max_requests = max_requests
        self.window_seconds = window_seconds

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client_ip = None
        for header_name, header_value in scope.get("headers", []):
            if header_name == b"x-forwarded-for":
                client_ip = header_value.decode().split(",")[0].strip()
                break
        if not client_ip:
            client_ip = scope.get("client", (None, None))[0]

        path = scope.get("path", "")
        whitelist_paths = ["/", "/dashboard", "/health", "/favicon.ico", "/docs", "/openapi.json"]
        if any(path.startswith(w) for w in ["/static", "/redoc", "/api/stats"]) or path in whitelist_paths:
            await self.app(scope, receive, send)
            return

        current_time = time.time()

        rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if current_time - t < self.window_seconds]

        if len(rate_limit_store[client_ip]) >= self.max_requests:
            attack_counter.increment_rate_limit()
            response = JSONResponse(
                status_code=429,
                content={"status": 429, "message": "请求过于频繁，请稍后再试"}
            )
            await response(scope, receive, send)
            return

        rate_limit_store[client_ip].append(current_time)

        await self.app(scope, receive, send)

def setup_rate_limiter(app: FastAPI):
    app.add_middleware(RateLimitMiddleware, max_requests=15, window_seconds=10)

rate_limit_store = defaultdict(list)

def rate_limit(max_requests: int, window_seconds: int = 60):
    def decorator(func):
        async def wrapper(request: Request, *args, **kwargs):
            client_ip = request.client.host
            current_time = time.time()

            rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if current_time - t < window_seconds]

            if len(rate_limit_store[client_ip]) >= max_requests:
                attack_counter.increment_rate_limit()
                return JSONResponse(
                    status_code=429,
                    content={"status": 429, "message": "请求过于频繁，请稍后再试"}
                )

            rate_limit_store[client_ip].append(current_time)

            return await func(request, *args, **kwargs)
        return wrapper
    return decorator

def general_rate_limit():
    return rate_limit(settings.RATE_LIMIT_GENERAL, 60)

def sensitive_rate_limit():
    return rate_limit(settings.RATE_LIMIT_SENSITIVE, 60)

import secrets
from config import settings
from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

class CsrfProtectionMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.csrf_tokens = {}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        whitelist_paths = ["/", "/dashboard", "/health", "/favicon.ico", "/docs", "/openapi.json"]
        csrf_whitelist = ["/api/auth/login", "/api/auth/register", "/api/auth/refresh", "/api/users/me", "/api/users/me/masked", "/api/users/encrypt", "/api/users/decrypt", "/api/users/", "/api/stats"]
        
        if any(path.startswith(w) for w in ["/static", "/redoc"]) or path in whitelist_paths or path in csrf_whitelist:
            return await call_next(request)

        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            header_token = request.headers.get("X-CSRF-Token")
            cookie_token = request.cookies.get("csrf_token")

            if not header_token or not cookie_token or header_token != cookie_token:
                return JSONResponse(
                    status_code=403,
                    content={"status": 403, "message": "CSRF 验证失败"}
                )

        return await call_next(request)

class CsrfProtection:
    def __init__(self):
        self.secret = settings.CSRF_SECRET.encode('utf-8')
        self.tokens = {}

    def generate_token(self) -> str:
        return secrets.token_hex(32)

    def set_token_cookie(self, response, token: str) -> None:
        response.set_cookie(
            key="csrf_token",
            value=token,
            httponly=False,
            secure=False,
            samesite="lax",
            max_age=86400
        )

    def validate_token(self, request: Request) -> bool:
        header_token = request.headers.get("X-CSRF-Token")
        if not header_token:
            return False

        cookie_token = request.cookies.get("csrf_token")
        if not cookie_token:
            return False

        return header_token == cookie_token

csrf_protection = CsrfProtection()

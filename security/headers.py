from fastapi import Request, Response
from typing import Optional

class SecurityHeaders:
    async def __call__(self, request: Request, call_next):
        """安全头中间件"""
        # 处理请求
        response = await call_next(request)
        
        # 添加安全头
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # HSTS (仅在生产环境启用)
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # CSP (非 API 端点使用)
        path = request.url.path
        if not path.startswith("/api"):
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data:"
        
        return response

# 创建实例
security_headers = SecurityHeaders()
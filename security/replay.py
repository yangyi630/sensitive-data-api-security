import time
import uuid
from fastapi import Request, HTTPException, Header
from fastapi.responses import JSONResponse
from typing import Optional
from config import settings
from utils.attack_counter import attack_counter

class ReplayProtection:
    def __init__(self):
        """初始化防重放攻击保护"""
        self.nonce_store = {}

    async def __call__(self, request: Request, call_next):
        """防重放攻击中间件"""
        # 获取头信息
        nonce = request.headers.get("X-Nonce")
        timestamp = request.headers.get("X-Timestamp")
        referer = request.headers.get("Referer", "")

        # 对于不需要安全头的路径，跳过检查
        path = request.url.path
        if (path in ["/", "/dashboard", "/health", "/favicon.ico"] or 
            path.startswith("/static") or 
            path.startswith("/docs") or 
            path.startswith("/redoc") or 
            path.startswith("/openapi.json") or
            path.startswith("/api/stats")):
            response = await call_next(request)
            return response

        # 如果没有安全头，检查是否是来自/docs的测试请求
        if not nonce or not timestamp:
            # 如果请求来自/docs（Swagger UI的Try it out），允许通过
            if "/docs" in referer or request.headers.get("X-Test-Request") == "true":
                response = await call_next(request)
                return response
            # 否则返回错误
            return JSONResponse(
                status_code=400,
                content={"status": 400, "message": "缺少必要的安全头: X-Nonce 和 X-Timestamp"}
            )

        # 验证时间戳
        try:
            request_time = int(timestamp)
            current_time = int(time.time() * 1000)
            time_diff = abs(current_time - request_time)

            if time_diff > 180000:  # 3分钟
                return JSONResponse(
                    status_code=400,
                    content={"status": 400, "message": "请求时间戳超出可接受范围"}
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"status": 400, "message": "无效的时间戳格式"}
            )

        # 验证 nonce
        if nonce in self.nonce_store:
            # 增加重放攻击计数
            attack_counter.increment_replay_attack()
            return JSONResponse(
                status_code=409,
                content={"status": 409, "message": "Nonce 已被使用（检测到重放攻击）"}
            )

        # 存储 nonce 并设置过期时间
        self.nonce_store[nonce] = time.time()

        # 清理过期的 nonce
        current_time = time.time()
        to_remove = []
        for key, value in self.nonce_store.items():
            if current_time - value > 300:  # 5分钟过期
                to_remove.append(key)
        for key in to_remove:
            del self.nonce_store[key]

        # 处理请求
        response = await call_next(request)
        return response

# 创建实例
replay_protection = ReplayProtection()
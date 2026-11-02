from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from contextlib import asynccontextmanager
import uuid

from config import settings
from database import engine, Base
from auth.auth_router import router as auth_router
from routers.user_router import router as user_router
from security.replay import replay_protection
from security.headers import security_headers
from security.rate_limiter import setup_rate_limiter
from security.csrf import CsrfProtectionMiddleware
from utils.logger import logger

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    logger.info("Starting application")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    logger.info("Shutting down application")

app = FastAPI(
    title="Secure API",
    description="Sensitive data encryption and API security protection",
    version="1.0.0",
    lifespan=lifespan
)

setup_rate_limiter(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(CsrfProtectionMiddleware)
app.middleware("http")(replay_protection)
app.middleware("http")(security_headers)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    request_id = str(uuid.uuid4())
    logger.error(f"Unhandled exception: {exc}", extra={"request_id": request_id})

    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "status": exc.status_code,
                "message": exc.detail,
                "request_id": request_id
            }
        )

    return JSONResponse(
        status_code=500,
        content={
            "status": 500,
            "message": "Internal server error",
            "request_id": request_id
        }
    )

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(auth_router)
app.include_router(user_router)

@app.get("/dashboard")
async def dashboard():
    return FileResponse("static/index.html")

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/api/stats/attacks")
async def get_attack_stats():
    from utils.attack_counter import attack_counter
    return attack_counter.get_stats()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

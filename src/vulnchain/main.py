"""Main FastAPI application entry point"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.vulnchain.core.config import settings
from src.vulnchain.core.rate_limiter import rate_limit_middleware
from src.vulnchain.api import targets, modules, workspaces, findings, sessions, websocket, auth, tasks

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Advanced CTF web exploitation framework",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add rate limiting middleware
app.middleware("http")(rate_limit_middleware)

# Register API routers
app.include_router(auth.router)
app.include_router(targets.router)
app.include_router(modules.router)
app.include_router(workspaces.router)
app.include_router(findings.router)
app.include_router(sessions.router)
app.include_router(tasks.router)
app.include_router(websocket.router)


@app.get("/")
async def root() -> dict:
    """Root endpoint"""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
    }


@app.get("/health")
async def health_check() -> JSONResponse:
    """Health check endpoint"""
    return JSONResponse(
        status_code=200,
        content={"status": "healthy", "version": settings.APP_VERSION},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
    )

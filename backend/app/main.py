"""
PhishGuard AI - Main FastAPI Application
Coordinates API routing, database lifecycle, CORS policy, and frontend hosting.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.database import db_manager
from app.routes.scan import router as scan_router
from app.routes.history import router as history_router
from app.routes.stats import router as stats_router
from app.routes.health import router as health_router
from app.routes.threats import router as threats_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages startup and shutdown events."""
    # Startup: Connect to MongoDB
    await db_manager.connect()
    yield
    # Shutdown: Close connections
    await db_manager.close()


app = FastAPI(
    title="PhishGuard AI API",
    description="Intelligent Phishing URL & Fake Website Detection System",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(scan_router, prefix="/api/v1")
app.include_router(history_router, prefix="/api/v1")
app.include_router(stats_router, prefix="/api/v1")
app.include_router(health_router, prefix="/api/v1")
app.include_router(threats_router, prefix="/api/v1")

# Also alias at /api for convenience
app.include_router(scan_router, prefix="/api")
app.include_router(history_router, prefix="/api")
app.include_router(stats_router, prefix="/api")
app.include_router(health_router, prefix="/api")
app.include_router(threats_router, prefix="/api")


# Disable aggressive browser caching on static HTML/JS/CSS so UI updates apply immediately
@app.middleware("http")
async def disable_static_cache(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.endswith((".html", ".js", ".css")):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response


# Global Exception Handler for Unhandled Errors to prevent server crash
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "message": "An internal server error occurred.",
            "detail": str(exc)
        }
    )


# Mount Frontend directory for static web serving
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

# app/main.py

# !! MUST BE FIRST - loads .env before any service imports read os.getenv() !!
import app.config  # noqa: F401 - triggers load_dotenv() immediately

import logging
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes_ioc import router as ioc_router
from app.api.web import router as web_router
from app.api.auth_routes import router as auth_router, get_current_user
from app.api.routes_siem import router as siem_router
from app.database import engine
from app.models.user import User       # noqa - registers model with Base
from app.models.api_key import APIKey  # noqa - registers model with Base
import app.models.user
import app.models.api_key
from app.database import Base

# Create tables on startup
Base.metadata.create_all(bind=engine)

# =========================
# Logging
# =========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# =========================
# FastAPI App
# =========================
app = FastAPI(
    title="OSINT IOC Intelligence Platform",
    description="Multi-source IOC enrichment and analysis platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://osint-platform-wkjt.onrender.com",  
],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth routes - public (no JWT required)
app.include_router(auth_router)

# Protected routes - require valid JWT
app.include_router(ioc_router,  dependencies=[Depends(get_current_user)])
app.include_router(web_router)  # /web/status is public; chat+feed require auth below

# SIEM integration - API key auth (machine-to-machine)
# /siem/enrich uses X-API-Key header
# /siem/keys management uses JWT (browser users)
# /siem/health is public
app.include_router(siem_router)

@app.get("/health")
async def health_check():
    from app.config import settings
    return {
        "status": "ok",
        "service": "osint-ioc-platform",
        "keys_loaded": {
            "VT":        bool(settings.vt_api_key),
            "AbuseIPDB": bool(settings.abuseipdb_api_key),
            "OTX":       bool(settings.otx_api_key),
            "Anthropic": bool(settings.anthropic_api_key),
        }
    }

@app.get("/")
async def root():
    return {"message": "OSINT IOC Platform running", "docs": "/docs"}

# -- Serve React frontend ------------------------------------------------------
import os
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

_dist = os.path.join(os.path.dirname(__file__), "..", "frontend", "dist")
if os.path.exists(_dist):
    app.mount("/assets", StaticFiles(directory=os.path.join(_dist, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str):
        return FileResponse(os.path.join(_dist, "index.html"))
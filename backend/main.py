# FILE: backend/main.py
# PURPOSE: FastAPI application entry-point — mounts all routers, runs migrations on startup
# SECURITY NOTE: CORS is restricted to FRONTEND_URL; never use wildcard origins in production

import subprocess
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from middleware.security_mode import SecurityModeMiddleware
from routers import auth, comments, csrf_demo, scans, scenarios, uploads


@asynccontextmanager
async def lifespan(app: FastAPI):
    subprocess.run(["alembic", "upgrade", "head"], check=False)
    yield


app = FastAPI(title="VulnLab API", lifespan=lifespan)

app.add_middleware(SecurityModeMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url, "http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(comments.router)
app.include_router(uploads.router)
app.include_router(csrf_demo.router)
app.include_router(scenarios.router)
app.include_router(scans.router)


@app.get("/health")
async def health():
    return {"status": "ok"}

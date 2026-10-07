from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.config import settings
from backend.database import Base, engine, SessionLocal
from backend.models import Alert
from backend.routes import (
    stats_router,
    alerts_router,
    incidents_router,
    simulation_router,
    copilot_router,
    agent_router,
    cockpit_router,
    auth_router,
    ssh_router
)
from backend.routes.simulation import run_3000_simulation

# Initialize Database Schema
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-seed database with 3,000 alert firehose if empty on initial startup
    db = SessionLocal()
    try:
        count = db.query(Alert).count()
        if count == 0:
            print("[INFO] Initializing Dealers SOC Database with 3,000 alert firehose simulation...")
            await run_3000_simulation(db)
            print("[INFO] Initialization complete: 3,000 alerts correlated into consolidated incidents.")
    finally:
        db.close()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Dealers AI SOC Triage Backend: NetworkX Graph Correlation + Autonomous AI SOC Agent + SSH Remote DFIR",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# CORS Middleware for API clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API Routers
app.include_router(stats_router, prefix=settings.API_PREFIX)
app.include_router(alerts_router, prefix=settings.API_PREFIX)
app.include_router(incidents_router, prefix=settings.API_PREFIX)
app.include_router(simulation_router, prefix=settings.API_PREFIX)
app.include_router(copilot_router, prefix=settings.API_PREFIX)
app.include_router(agent_router, prefix=settings.API_PREFIX)
app.include_router(cockpit_router, prefix=settings.API_PREFIX)
app.include_router(auth_router, prefix=settings.API_PREFIX)
app.include_router(ssh_router, prefix=settings.API_PREFIX)

@app.get("/")
def api_root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "documentation": "/docs",
        "redoc": "/redoc",
        "endpoints": {
            "stats": f"{settings.API_PREFIX}/stats",
            "cockpit_summary": f"{settings.API_PREFIX}/cockpit/summary",
            "cockpit_stream": f"{settings.API_PREFIX}/cockpit/stream",
            "auth_me": f"{settings.API_PREFIX}/auth/me",
            "auth_roles": f"{settings.API_PREFIX}/auth/roles",
            "ssh_hosts": f"{settings.API_PREFIX}/ssh/hosts",
            "ssh_execute": f"{settings.API_PREFIX}/ssh/execute",
            "ssh_audit": f"{settings.API_PREFIX}/ssh/audit",
            "incidents": f"{settings.API_PREFIX}/incidents",
            "alerts": f"{settings.API_PREFIX}/alerts",
            "agent_investigate": f"{settings.API_PREFIX}/agent/investigate/{{incident_id}}",
            "agent_feedback": f"{settings.API_PREFIX}/agent/feedback",
            "simulate": f"{settings.API_PREFIX}/simulate/run-3000",
            "copilot": f"{settings.API_PREFIX}/copilot/chat"
        }
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "database": "connected",
        "correlation_window_minutes": settings.CORRELATION_WINDOW_MINUTES
    }

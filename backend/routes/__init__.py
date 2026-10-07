from backend.routes.stats import router as stats_router
from backend.routes.alerts import router as alerts_router
from backend.routes.incidents import router as incidents_router
from backend.routes.simulation import router as simulation_router
from backend.routes.copilot import router as copilot_router
from backend.routes.agent import router as agent_router
from backend.routes.cockpit import router as cockpit_router
from backend.routes.auth import router as auth_router
from backend.routes.ssh import router as ssh_router

__all__ = [
    "stats_router",
    "alerts_router",
    "incidents_router",
    "simulation_router",
    "copilot_router",
    "agent_router",
    "cockpit_router",
    "auth_router",
    "ssh_router"
]




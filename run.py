#!/usr/bin/env python3
"""
Dealers AI SOC Triage System - Backend API Server Launcher
"""
import uvicorn
from backend.config import settings

if __name__ == "__main__":
    print("\n" + "="*70)
    print(f"🛡️  {settings.PROJECT_NAME} v{settings.VERSION}")
    print("📡 FastAPI Backend listening on: http://0.0.0.0:8000")
    print("📖 Interactive Swagger API Docs: http://localhost:8000/docs")
    print("📑 ReDoc Documentation:          http://localhost:8000/redoc")
    print("="*70 + "\n")
    uvicorn.run("backend.app:app", host="0.0.0.0", port=8000, reload=True)

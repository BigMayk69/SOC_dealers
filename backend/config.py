import os
from pydantic import BaseModel

class Settings(BaseModel):
    PROJECT_NAME: str = "Dealers AI SOC Triage System"
    VERSION: str = "2.0.0"
    API_PREFIX: str = "/api"
    
    # Database configuration (Defaults to local SQLite for instant zero-dependency execution, or PostgreSQL via ENV)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./soc_triage.db")
    
    # Correlation Engine Configuration
    CORRELATION_WINDOW_MINUTES: int = int(os.getenv("CORRELATION_WINDOW_MINUTES", "60"))
    GRAPH_SIMILARITY_THRESHOLD: float = float(os.getenv("GRAPH_SIMILARITY_THRESHOLD", "0.45"))
    
    # Ollama / LLM Configuration
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3")
    OLLAMA_FALLBACK_MODEL: str = os.getenv("OLLAMA_FALLBACK_MODEL", "mistral")
    AZURE_OPENAI_ENDPOINT: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    AZURE_OPENAI_API_KEY: str = os.getenv("AZURE_OPENAI_API_KEY", "")

    # Target Benchmarks
    TARGET_REDUCTION_PCT: float = 90.0
    TARGET_MTTT_SECONDS: int = 180  # 3 minutes

settings = Settings()

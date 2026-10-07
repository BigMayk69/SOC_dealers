# Multi-Stage Production Dockerfile for Dealers AI SOC Triage
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY run.py .

EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL="sqlite:///./soc_triage.db"
ENV OLLAMA_BASE_URL="http://ollama:11434"
ENV OLLAMA_MODEL="llama3"

CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000"]

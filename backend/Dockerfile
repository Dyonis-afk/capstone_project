# AEGIS Backend - Production Dockerfile
# Deploys FastAPI + ChromaDB for RAG-powered security analysis

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHON_ENV=production \
    AEGIS_LOG_MODE=production \
    VECTOR_DB_PATH=/app/aegis_vector_db

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for Docker layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Remove unnecessary files
RUN rm -rf __pycache__ .pytest_cache .git venv tests *.pyc

# Create directory for vector database (will be mounted as persistent disk)
RUN mkdir -p /app/aegis_vector_db

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run with gunicorn for production (multiple workers)
# - 3 workers for handling concurrent requests
# - 300s timeout for long RAG queries (DeepSeek can be slow)
# - UvicornWorker for async support
CMD ["gunicorn", "app:app", \
     "-w", "3", \
     "-k", "uvicorn.workers.UvicornWorker", \
     "-b", "0.0.0.0:8000", \
     "--timeout", "300", \
     "--graceful-timeout", "30", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]

import logging
import time
import os
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Load .env FIRST before any imports that depend on env vars (TAVILY_API_KEY, etc.)
from dotenv import load_dotenv
_env_file = Path(__file__).resolve().parent.parent / ".env"  # capstone_project/.env
if not _env_file.exists():
    _env_file = Path(__file__).resolve().parent / ".env"  # backend/.env
load_dotenv(_env_file)

# Configure logging FIRST
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    force=True  # Force reconfiguration to ensure handler is added
)

# Import and initialize log buffer handler AFTER basicConfig
from routers.logs import initialize_log_handler
initialize_log_handler()

# ✅ FIXED: Import reports along with your existing routers
from routers import query, bloodhound, neo4j_query, remediation, logs, reports, attack_paths, chat, vector_db

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="AEGIS Backend API",
    description="AI-Enhanced Guardian for Enterprise Infrastructure Security",
    version="1.0.0"
)

# CORS middleware - allows frontend to communicate with backend
# Using allow_origins=["*"] for development to support Electron apps
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=False,  # Must be False when using "*"
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Request logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all incoming requests with details"""
    start_time = time.time()
    
    # Log request details
    logger.info(f"→ {request.method} {request.url.path}")
    if request.query_params:
        logger.info(f"  Query params: {dict(request.query_params)}")
    logger.info(f"  Client: {request.client.host if request.client else 'unknown'}")
    
    # Process request
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Log response details
        status_emoji = "✓" if response.status_code < 400 else "✗"
        logger.info(f"{status_emoji} {request.method} {request.url.path} - Status: {response.status_code} - Time: {process_time:.3f}s")
        
        return response
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(f"✗ {request.method} {request.url.path} - Exception: {str(e)} - Time: {process_time:.3f}s", exc_info=True)
        raise

# ✅ ROUTERS - Include all your existing routers plus the new reports router
try:
    app.include_router(query.router, prefix="/api/query", tags=["Query"])
    logger.info("✓ Query router registered")
except Exception as e:
    logger.error(f"✗ Failed to register query router: {e}", exc_info=True)

try:
    app.include_router(bloodhound.router, prefix="/api/bloodhound", tags=["BloodHound"])
    logger.info("✓ BloodHound router registered")
except Exception as e:
    logger.error(f"✗ Failed to register bloodhound router: {e}", exc_info=True)

try:
    app.include_router(neo4j_query.router, prefix="/api/neo4j", tags=["Neo4j"])
    logger.info("✓ Neo4j router registered")
except Exception as e:
    logger.error(f"✗ Failed to register neo4j router: {e}", exc_info=True)

try:
    app.include_router(remediation.router, prefix="/api/remediation", tags=["Remediation"])
    logger.info("✓ Remediation router registered")
except Exception as e:
    logger.error(f"✗ Failed to register remediation router: {e}", exc_info=True)

try:
    app.include_router(logs.router, prefix="/api", tags=["Logs"])
    logger.info("✓ Logs router registered")
except Exception as e:
    logger.error(f"✗ Failed to register logs router: {e}", exc_info=True)

try:
    app.include_router(reports.router, prefix="/api", tags=["Reports"])
    logger.info("✓ Reports router registered")
    # Log all routes in reports router for debugging
    for route in reports.router.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            methods = ', '.join(route.methods) if route.methods else 'N/A'
            logger.info(f"  → {methods} {route.path}")
except Exception as e:
    logger.error(f"✗ Failed to register reports router: {e}", exc_info=True)

try:
    app.include_router(attack_paths.router, prefix="/api/attack-paths", tags=["Attack Path Analysis"])
    logger.info("✓ Attack Paths router registered")
    # Log all routes in attack-paths router for debugging
    for route in attack_paths.router.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            methods = ', '.join(route.methods) if route.methods else 'N/A'
            logger.info(f"  → {methods} {route.path}")
except Exception as e:
    logger.error(f"✗ Failed to register attack-paths router: {e}", exc_info=True)

try:
    app.include_router(chat.router, prefix="/api/chat", tags=["Intelligent Chat"])
    logger.info("✓ Chat router registered")
    for route in chat.router.routes:
        if hasattr(route, 'path') and hasattr(route, 'methods'):
            methods = ', '.join(route.methods) if route.methods else 'N/A'
            logger.info(f"  → {methods} {route.path}")
except Exception as e:
    logger.error(f"✗ Failed to register chat router: {e}", exc_info=True)

try:
    app.include_router(vector_db.router, tags=["Vector Database"])
    logger.info("✓ Vector DB router registered")
except Exception as e:
    logger.error(f"✗ Failed to register vector_db router: {e}", exc_info=True)

@app.get("/")
def root():
    logger.info("Root endpoint accessed")
    return {
        "message": "AEGIS Backend API",
        "version": "1.0.0",
        "status": "running",
        "features": {
            "query": "RAG-powered security analysis",
            "bloodhound": "BloodHound data processing",
            "neo4j": "Graph database queries",
            "remediation": "Security remediation guidance",
            "reports": "Structured JSON-first security reports",
            "attack_paths": "RAG-powered attack path intelligence",
            "chat": "Intelligent natural language queries with intent classification"
        }
    }
    
# health check endpoint
@app.get("/health")
def health_check():
    logger.info("Health check endpoint accessed")
    return {"status": "API is operational."}
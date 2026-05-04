"""
Logs Router
Provides access to backend logs for real-time monitoring

Features:
- LOG_MODE: 'debug' (verbose) or 'production' (stage progression only)
- File logging: Complete logs written to logs/aegis.log
- Terminal buffer: Filtered logs for UI display
"""

import logging
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from fastapi import APIRouter, Query
from typing import List, Dict, Any
from datetime import datetime
import threading

router = APIRouter()

# ==================== LOG MODE CONFIGURATION ====================
# Set AEGIS_LOG_MODE=debug for verbose logging, otherwise production (filtered)
LOG_MODE = os.getenv("AEGIS_LOG_MODE", "production").lower()
IS_DEBUG_MODE = LOG_MODE == "debug"

# Log file configuration
LOG_DIR = Path(__file__).parent.parent / "logs"
LOG_FILE = LOG_DIR / "aegis.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10 MB
BACKUP_COUNT = 5  # Keep 5 backup files

# In-memory log buffer (stores last 500 log entries)
log_buffer: List[Dict[str, Any]] = []
log_buffer_lock = threading.Lock()
log_id_counter = 0

class LogBufferHandler(logging.Handler):
    """Custom logging handler that stores logs in memory for terminal display"""

    # Patterns to ALWAYS filter (health checks, HTTP noise)
    ALWAYS_FILTERED_PATTERNS = [
        '→ GET /api/logs',
        '→ GET /api/attack-paths/logs',
        '✓ GET /api/logs',
        '✓ GET /api/attack-paths/logs',
        '/health',
        '/api/health',
        'Query params:',
        'Client: 127.0.0.1',
        'Client: localhost',
        'HTTP/1.1" 200 OK',
        'HTTP/1.1" 404',
    ]

    # Patterns to filter in PRODUCTION mode only (detailed service logs)
    PRODUCTION_FILTERED_PATTERNS = [
        'Processing RAG query:',
        'Retrieving relevant documents',
        'AI response generated',
        'Querying RAG for remediation',
        'RAG response received',
        'Parsing remediation response',
    ]

    # Loggers to always filter (too noisy for UI)
    FILTERED_LOGGERS = ['uvicorn.access', 'uvicorn.error']

    def _should_filter(self, record) -> bool:
        """Check if this log should be filtered out from the UI"""
        # Filter specific noisy loggers
        if record.name in self.FILTERED_LOGGERS:
            return True

        # Get the message
        try:
            msg = record.getMessage()
        except:
            return False

        # Always filter health checks and HTTP noise
        for pattern in self.ALWAYS_FILTERED_PATTERNS:
            if pattern in msg:
                return True

        # In production mode, also filter detailed service logs
        if not IS_DEBUG_MODE:
            for pattern in self.PRODUCTION_FILTERED_PATTERNS:
                if pattern in msg:
                    return True

        # Filter uvicorn access logs
        if 'INFO:' in msg and ('127.0.0.1' in msg or 'HTTP/1.1' in msg):
            return True

        return False

    def emit(self, record):
        global log_id_counter
        try:
            # Filter out noisy logs based on mode
            if self._should_filter(record):
                return

            with log_buffer_lock:
                global log_buffer
                log_id_counter += 1

                # Get the actual message content
                msg = record.getMessage()

                # Clean up special characters for better display
                msg = msg.replace('→', '->').replace('←', '<-')

                log_entry = {
                    'id': log_id_counter,
                    'timestamp': datetime.fromtimestamp(record.created).isoformat(),
                    'level': record.levelname,
                    'message': msg,
                    'logger': record.name
                }
                log_buffer.append(log_entry)
                # Keep only last 500 entries
                if len(log_buffer) > 500:
                    log_buffer.pop(0)
        except Exception as e:
            import sys
            print(f"LogBufferHandler error: {e}", file=sys.stderr)


class FileLogHandler(logging.Handler):
    """Custom handler that writes ALL logs to file (excluding health checks)"""

    # Only filter health checks from file logs
    HEALTH_CHECK_PATTERNS = [
        '/health',
        '/api/health',
        '→ GET /api/logs',
        '→ GET /api/attack-paths/logs',
        '✓ GET /api/logs',
        '✓ GET /api/attack-paths/logs',
        'HTTP/1.1" 200 OK',
    ]

    def __init__(self, file_handler: RotatingFileHandler):
        super().__init__()
        self.file_handler = file_handler

    def _is_health_check(self, record) -> bool:
        """Check if this is a health check log"""
        try:
            msg = record.getMessage()
            for pattern in self.HEALTH_CHECK_PATTERNS:
                if pattern in msg:
                    return True
        except:
            pass
        return False

    def emit(self, record):
        try:
            # Only filter health checks, log everything else
            if self._is_health_check(record):
                return
            self.file_handler.emit(record)
        except Exception as e:
            import sys
            print(f"FileLogHandler error: {e}", file=sys.stderr)

# Set up the log handlers (only once)
_log_handler_initialized = False
_log_buffer_handler = None
_file_log_handler = None


def initialize_log_handler():
    """Initialize the log buffer handler (and file handler in debug mode only)"""
    global _log_handler_initialized, _log_buffer_handler, _file_log_handler

    if not _log_handler_initialized:
        root_logger = logging.getLogger()

        # ==================== FILE HANDLER (DEBUG MODE ONLY) ====================
        # Only create file logs in debug mode - not needed in production
        if IS_DEBUG_MODE:
            try:
                # Create logs directory if it doesn't exist
                LOG_DIR.mkdir(parents=True, exist_ok=True)

                # Set up timed rotating file handler (new file per day, keep 7 days)
                rotating_file_handler = TimedRotatingFileHandler(
                    LOG_FILE,
                    when='midnight',
                    interval=1,
                    backupCount=7,
                    encoding='utf-8'
                )
                rotating_file_handler.suffix = '%Y-%m-%d'
                rotating_file_handler.setFormatter(
                    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                )
                rotating_file_handler.setLevel(logging.DEBUG)

                # Wrap with our custom filter (excludes health checks only)
                _file_log_handler = FileLogHandler(rotating_file_handler)
                _file_log_handler.setLevel(logging.DEBUG)

                # Remove existing file handlers to avoid duplicates
                for handler in root_logger.handlers[:]:
                    if isinstance(handler, (FileLogHandler, RotatingFileHandler)):
                        root_logger.removeHandler(handler)
                root_logger.addHandler(_file_log_handler)

                print(f"   📁 File logging enabled: {LOG_FILE}")
            except Exception as e:
                print(f"   ⚠️ File logging disabled (error: {e})")
                _file_log_handler = None

        # ==================== BUFFER HANDLER (Terminal) ====================
        _log_buffer_handler = LogBufferHandler()
        _log_buffer_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )

        # Remove existing LogBufferHandler if it exists to avoid duplicates
        for handler in root_logger.handlers[:]:
            if isinstance(handler, LogBufferHandler):
                root_logger.removeHandler(handler)
        root_logger.addHandler(_log_buffer_handler)

        # Set root logger level
        root_logger.setLevel(logging.DEBUG)
        root_logger.propagate = True
        _log_handler_initialized = True

        # ==================== CHILD LOGGERS ====================
        # Add handlers to common loggers to ensure they're captured
        common_loggers = [
            'routers.attack_paths',
            'services.attack_path_service',
            'services.neo4j_service',
            'services.rag_service',
            'services.smart_query_builder',
            'services.remediation_service',
            'services.graph_extractor'
        ]
        for logger_name in common_loggers:
            child_logger = logging.getLogger(logger_name)
            child_logger.setLevel(logging.DEBUG)
            # Let logs propagate to root logger (which has the handlers)
            # Don't add handlers directly to child loggers - this causes duplicates
            child_logger.propagate = True

        # ==================== SUPPRESS NOISY LOGGERS ====================
        # OpenAI
        logging.getLogger("openai").setLevel(logging.CRITICAL)
        logging.getLogger("openai._base_client").setLevel(logging.CRITICAL)
        logging.getLogger("httpx").setLevel(logging.CRITICAL)
        logging.getLogger("httpcore").setLevel(logging.CRITICAL)

        # Neo4j
        logging.getLogger("neo4j").setLevel(logging.WARNING)
        logging.getLogger("neo4j.pool").setLevel(logging.WARNING)
        logging.getLogger("neo4j.io").setLevel(logging.WARNING)
        logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)

        # Other noisy loggers
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
        logging.getLogger("posthog").setLevel(logging.WARNING)
        logging.getLogger("chromadb").setLevel(logging.WARNING)
        logging.getLogger("langchain").setLevel(logging.WARNING)

        # ==================== CONFIRMATION ====================
        mode_str = "DEBUG (verbose + file logging)" if IS_DEBUG_MODE else "PRODUCTION (filtered, no file)"
        print(f"✅ Log handlers initialized")
        print(f"   📋 Mode: {mode_str}")

        logging.info(f"Log system initialized - Mode: {LOG_MODE}")

# Don't initialize on import - let app.py do it after basicConfig
# initialize_log_handler()

@router.get("/logs")
async def get_logs(since: int = Query(0, description="Get logs after this ID")):
    """
    Get backend logs for real-time monitoring.
    
    Returns logs that have been generated since the specified log ID.
    Useful for polling to get new logs.
    """
    with log_buffer_lock:
        if since == 0:
            # Return last 50 logs for initial load
            recent_logs = log_buffer[-50:] if log_buffer else []
        else:
            # Return logs after the specified ID (only new logs)
            recent_logs = [log for log in log_buffer if log.get('id', 0) > since]
        
        last_id = log_buffer[-1]['id'] if log_buffer else 0
        
        # Log this request for debugging (but don't include it in the response to avoid recursion)
        if len(log_buffer) == 0:
            # Use print instead of logging to avoid recursion
            import sys
            print("⚠️ Log buffer is empty - no logs are being captured", file=sys.stderr)
        
        return {
            "logs": recent_logs,
            "last_id": last_id,
            "total_logs": len(log_buffer),
            "since_param": since  # Debug: include the since parameter in response
        }

@router.get("/logs/status")
async def get_logs_status():
    """Get current log system status and configuration"""
    return {
        "mode": LOG_MODE,
        "is_debug": IS_DEBUG_MODE,
        "file_logging": {
            "enabled": True,
            "path": str(LOG_FILE),
            "max_size_mb": MAX_LOG_SIZE // (1024 * 1024),
            "backup_count": BACKUP_COUNT,
            "exists": LOG_FILE.exists() if LOG_FILE else False,
            "size_bytes": LOG_FILE.stat().st_size if LOG_FILE.exists() else 0
        },
        "buffer": {
            "size": len(log_buffer),
            "max_size": 500,
            "last_id": log_buffer[-1]['id'] if log_buffer else 0
        },
        "handler_initialized": _log_handler_initialized
    }


@router.get("/logs/debug")
async def get_logs_debug():
    """Debug endpoint to check log buffer status"""
    import logging as log_module
    root_logger = log_module.getLogger()

    # Test log to verify handler is working
    log_module.info("DEBUG: Test log from /logs/debug endpoint")

    with log_buffer_lock:
        # Check handler status
        root_handlers = [type(h).__name__ for h in root_logger.handlers]
        has_buffer_handler = any(isinstance(h, LogBufferHandler) for h in root_logger.handlers)
        has_file_handler = any(isinstance(h, FileLogHandler) for h in root_logger.handlers)

        # Get info about common loggers
        logger_info = {}
        for logger_name in ['routers.attack_paths', 'services.attack_path_service', 'services.neo4j_service']:
            logger = log_module.getLogger(logger_name)
            logger_info[logger_name] = {
                "level": logging.getLevelName(logger.level),
                "handlers": [type(h).__name__ for h in logger.handlers],
                "propagate": logger.propagate,
                "has_buffer_handler": any(isinstance(h, LogBufferHandler) for h in logger.handlers),
                "has_file_handler": any(isinstance(h, FileLogHandler) for h in logger.handlers)
            }

        return {
            "log_mode": LOG_MODE,
            "is_debug_mode": IS_DEBUG_MODE,
            "buffer_size": len(log_buffer),
            "last_id": log_buffer[-1]['id'] if log_buffer else 0,
            "handler_initialized": _log_handler_initialized,
            "file_log": {
                "path": str(LOG_FILE),
                "exists": LOG_FILE.exists(),
                "size_bytes": LOG_FILE.stat().st_size if LOG_FILE.exists() else 0
            },
            "root_logger": {
                "level": logging.getLevelName(root_logger.level),
                "handlers": root_handlers,
                "has_buffer_handler": has_buffer_handler,
                "has_file_handler": has_file_handler,
                "propagate": root_logger.propagate
            },
            "logger_info": logger_info,
            "sample_logs": log_buffer[-10:] if log_buffer else []
        }


# ==================== HELPER FUNCTIONS ====================

def get_log_mode() -> str:
    """Get current log mode"""
    return LOG_MODE


def is_debug_mode() -> bool:
    """Check if debug mode is enabled"""
    return IS_DEBUG_MODE


def get_log_file_path() -> Path:
    """Get the log file path"""
    return LOG_FILE


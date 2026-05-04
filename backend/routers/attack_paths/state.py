"""
Global state management for Attack Path Router
Location: backend/routers/attack_paths/state.py

Contains:
- LogBuffer for real-time log streaming
- Global service instances (singleton pattern)
- Analysis progress tracking
"""

import logging
import threading
from datetime import datetime
from collections import deque
from typing import Optional, Dict, Any

from fastapi import HTTPException

logger = logging.getLogger(__name__)


# ==================== IN-MEMORY LOG BUFFER ====================

class LogBuffer:
    """Thread-safe circular buffer for storing logs"""

    def __init__(self, max_size: int = 1000):
        self.logs: deque = deque(maxlen=max_size)
        self.lock = threading.Lock()
        self.log_id_counter = 0

    def add_log(self, level: str, message: str, logger_name: str = "aegis"):
        """Add a log entry to the buffer"""
        with self.lock:
            self.log_id_counter += 1
            log_entry = {
                "id": self.log_id_counter,
                "timestamp": datetime.now().isoformat(),
                "level": level.upper(),
                "message": message,
                "logger": logger_name
            }
            self.logs.append(log_entry)
            return log_entry

    def get_logs_since(self, since_id: int = 0) -> tuple:
        """Get all logs with ID greater than since_id"""
        with self.lock:
            if since_id == 0:
                # Return last 50 logs for initial load
                logs_list = list(self.logs)[-50:]
            else:
                logs_list = [log for log in self.logs if log["id"] > since_id]

            last_id = self.log_id_counter
            return logs_list, last_id

    def clear(self):
        """Clear all logs and reset ID counter for a fresh session"""
        with self.lock:
            self.logs.clear()
            self.log_id_counter = 0


# Global log buffer instance
log_buffer = LogBuffer()


def is_debug_mode():
    """Check if debug mode is enabled"""
    try:
        from routers.logs import is_debug_mode as logs_is_debug_mode
        return logs_is_debug_mode()
    except ImportError:
        import os
        return os.getenv("AEGIS_LOG_MODE", "production").lower() == "debug"


def add_log(level: str, message: str, debug_only: bool = False):
    """
    Helper function to add a log to the buffer AND regular logger.

    Args:
        level: Log level (INFO, WARNING, ERROR, DEBUG)
        message: Log message
        debug_only: If True, only show in terminal when AEGIS_LOG_MODE=debug
                   (still written to log file regardless)
    """
    # DEBUG-level logs are always debug-only (skip buffer in production)
    if level.upper() == "DEBUG":
        debug_only = True

    # Skip terminal display in production mode if debug_only=True
    if debug_only and not is_debug_mode():
        # Still log to file via standard logger, just skip the buffer
        level_upper = level.upper()
        if level_upper == "ERROR":
            logger.error(message)
        elif level_upper == "WARNING":
            logger.warning(message)
        elif level_upper == "DEBUG":
            logger.debug(message)
        else:
            logger.info(message)
        return

    # Add to buffer (shown in terminal)
    log_buffer.add_log(level, message)

    # Also log to standard logger (goes to file)
    level_upper = level.upper()
    if level_upper == "ERROR":
        logger.error(message)
    elif level_upper == "WARNING":
        logger.warning(message)
    elif level_upper == "DEBUG":
        logger.debug(message)
    else:
        logger.info(message)


# ==================== GLOBAL STATE ====================

# Global state for tracking analysis progress
analysis_progress: Dict[str, Dict[str, Any]] = {}


def update_progress(analysis_id: str, step: str, progress: int, message: str, status: str = "processing"):
    """Update progress tracking for analysis"""
    if analysis_id not in analysis_progress:
        analysis_progress[analysis_id] = {
            "analysis_id": analysis_id,
            "created_at": datetime.now().isoformat()
        }

    analysis_progress[analysis_id].update({
        "status": status,
        "step": step,
        "progress": progress,
        "message": message,
        "updated_at": datetime.now().isoformat()
    })

    # Add to log buffer for TerminalLogViewer
    add_log("INFO", f"[{step}] {progress}% - {message}")


# ==================== SERVICE SINGLETONS ====================

_rag_service = None
_remediation_service = None
_neo4j_service = None


def get_neo4j_service():
    """Get Neo4j service instance (singleton) for graph queries"""
    from services.neo4j_service import Neo4jService

    global _neo4j_service
    if _neo4j_service is None:
        try:
            add_log("DEBUG", "Initializing Neo4j service for report generation...", debug_only=True)
            _neo4j_service = Neo4jService()
            # Check if driver actually connected (it silently sets driver=None on failure)
            if not _neo4j_service.driver:
                add_log("DEBUG", "Neo4j not available (no local connection) - ad-hoc queries disabled", debug_only=True)
                _neo4j_service = None
                return None
            add_log("DEBUG", "Neo4j service initialized successfully", debug_only=True)
        except Exception as e:
            add_log("WARNING", f"Neo4j service not available: {e}")
            return None
    return _neo4j_service


def get_rag_service():
    """Get RAG service instance (singleton)"""
    from services.rag_service import RAGService

    global _rag_service
    if _rag_service is None:
        try:
            add_log("INFO", "Initializing RAG service...")
            _rag_service = RAGService()
            add_log("INFO", "RAG service initialized successfully")
        except Exception as e:
            add_log("ERROR", f"Failed to initialize RAG service: {e}")
            raise HTTPException(
                status_code=503,
                detail=f"RAG service unavailable: {str(e)}"
            )
    return _rag_service


def get_remediation_service():
    """Get remediation service instance (singleton) with terminal logging support"""
    from services.remediation_service import RemediationService

    global _remediation_service
    if _remediation_service is None:
        try:
            # Pass add_log as callback so remediation logs appear in TerminalLogViewer
            _remediation_service = RemediationService(log_callback=add_log)
            add_log("INFO", "Remediation service initialized with terminal logging")
        except Exception as e:
            add_log("WARNING", f"Remediation service not available: {e}")

    # ALWAYS ensure callback is set (in case service was created before or callback changed)
    if _remediation_service is not None:
        _remediation_service.set_log_callback(add_log)

    return _remediation_service


def estimate_time_remaining(progress_data: Dict[str, Any]) -> str:
    """Estimate remaining time based on progress"""
    progress = progress_data.get("progress", 0)
    if progress >= 100:
        return "Complete"
    elif progress >= 80:
        return "< 1 minute"
    elif progress >= 50:
        return "1-2 minutes"
    elif progress >= 20:
        return "2-3 minutes"
    else:
        return "3-5 minutes"

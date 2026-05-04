"""
Attack Paths Module
Location: backend/routers/attack_paths/__init__.py

This module provides attack path analysis functionality for AEGIS.
It has been refactored from a single 6700+ line file into a modular structure.

Module Structure:
- models.py: Pydantic models (FindingsSummary, EnvironmentInfo, etc.)
- state.py: Global state, logging (LogBuffer, add_log, service singletons)
- utils.py: Helper functions (parse_llm_json, format_results_for_rag, etc.)
- constants/: Static data
  - edge_templates.py: EDGE_TYPE_QUERY_TEMPLATES (40+ attack patterns)
  - static_queries.py: CORE_STATIC_QUERIES (21 always-run queries)
  - priority.py: EDGE_PRIORITY_ORDER, ATTACK_CATEGORY_MAP
- services/: Business logic (placeholder for future extraction)
- rag/: RAG content generation (placeholder for future extraction)

Usage:
    from routers.attack_paths import (
        EDGE_TYPE_QUERY_TEMPLATES,
        CORE_STATIC_QUERIES,
        EDGE_PRIORITY_ORDER,
        add_log,
        log_buffer,
    )
"""

# Re-export models
from .models import (
    FindingsSummary,
    EnvironmentInfo,
    GenerateQueriesRequest,
    GeneratedQuery,
    GenerateQueriesResponse,
    QueryResult,
    AnalyzeResultsRequest,
    AnalyzeResultsResponse,
)

# Re-export state management
from .state import (
    log_buffer,
    LogBuffer,
    add_log,
    is_debug_mode,
    analysis_progress,
    update_progress,
    get_rag_service,
    get_remediation_service,
    estimate_time_remaining,
)

# Re-export constants
from .constants import (
    EDGE_TYPE_QUERY_TEMPLATES,
    CORE_STATIC_QUERIES,
    EDGE_PRIORITY_ORDER,
    ATTACK_CATEGORY_MAP,
)

from .constants.priority import (
    get_attack_complexity,
    get_primary_category,
    determine_severity,
)

# Re-export utilities
from .utils import (
    format_entity_type,
    get_node_name,
    parse_llm_json,
    extract_section,
    format_results_for_rag,
    build_affected_entities,
)

# Import and expose the router (for FastAPI)
from .router import router

__all__ = [
    # Router
    'router',
    # Models
    'FindingsSummary',
    'EnvironmentInfo',
    'GenerateQueriesRequest',
    'GeneratedQuery',
    'GenerateQueriesResponse',
    'QueryResult',
    'AnalyzeResultsRequest',
    'AnalyzeResultsResponse',
    # State
    'log_buffer',
    'LogBuffer',
    'add_log',
    'is_debug_mode',
    'analysis_progress',
    'update_progress',
    'get_rag_service',
    'get_remediation_service',
    'estimate_time_remaining',
    # Constants
    'EDGE_TYPE_QUERY_TEMPLATES',
    'CORE_STATIC_QUERIES',
    'EDGE_PRIORITY_ORDER',
    'ATTACK_CATEGORY_MAP',
    'get_attack_complexity',
    'get_primary_category',
    'determine_severity',
    # Utilities
    'format_entity_type',
    'get_node_name',
    'parse_llm_json',
    'extract_section',
    'format_results_for_rag',
    'build_affected_entities',
]

"""
Services package initializer.
"""

# Lazy import RAGService to avoid startup errors if chromadb isn't available
def _get_rag_service():
    try:
        from .rag_service import RAGService
        return RAGService
    except Exception as e:
        print(f"Warning: Could not import RAGService: {e}")
        return None

from .bloodhound_parser import BloodHoundParser
from .neo4j_service import Neo4jService
from .remediation_service import RemediationService
from .report_service import ReportService
# Export RAGService as a function that returns the class
RAGService = _get_rag_service()

__all__ = ["RAGService", "BloodHoundParser", "Neo4jService", "RemediationService", "ReportService"]
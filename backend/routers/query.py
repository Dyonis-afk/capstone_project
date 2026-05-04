"""
Query Router for handling query-related endpoints.
"""

import logging
from fastapi import APIRouter, HTTPException, Query as QueryParam
from models.request_models import QueryRequest
from models.response_model import QueryResponse

logger = logging.getLogger(__name__)
router = APIRouter()

# Lazy load RAGService to allow server to start even if chromadb isn't available
rag_service = None

def get_rag_service():
    """Lazy initialization of RAGService"""
    global rag_service
    if rag_service is None:
        try:
            logger.info("Initializing RAGService...")
            from services.rag_service import RAGService
            rag_service = RAGService()
            logger.info("RAGService initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing RAGService: {e}", exc_info=True)
            rag_service = None
    return rag_service

@router.post("/", response_model=QueryResponse)
@router.post("", response_model=QueryResponse)  # Also handle without trailing slash
async def query_rag(
    request: QueryRequest,
    project_id: str = QueryParam(None, description="Project ID for context (optional)")
):
    """
    Handle query requests using the RAG service.
    Uses async query method to prevent blocking.
    """
    logger.info(f"RAG Query received: {request.question[:100]}... (project: {project_id or 'NONE'})")
    
    service = get_rag_service()
    if service is None:
        logger.error("RAG Service not available")
        raise HTTPException(status_code=500, detail="RAG Service is not available. Please ensure chromadb is properly installed.")
    
    try:
        logger.info("Processing RAG query...")
        # Use async query method to prevent blocking
        result = await service.query_async(request.question)
        
        # Validate result structure
        if not result or 'result' not in result:
            logger.error(f"Invalid result structure from RAG query: {result}")
            raise HTTPException(status_code=500, detail="Invalid response from RAG service")
        
        # Extract sources from documents
        source_docs = result.get("source_documents", [])
        sources = []
        for doc in source_docs:
            try:
                if hasattr(doc, 'metadata') and doc.metadata:
                    source = doc.metadata.get("source", "Unknown Source")
                    sources.append(source)
                elif isinstance(doc, dict) and 'metadata' in doc:
                    source = doc['metadata'].get("source", "Unknown Source")
                    sources.append(source)
            except Exception as e:
                logger.warning(f"Error extracting source from document: {e}")
                sources.append("Unknown Source")
        
        logger.info(f"RAG Query completed. Answer length: {len(result.get('result', ''))} chars, Sources: {len(sources)}")
        
        # Return response with answer and sources
        return QueryResponse(answer=result['result'], sources=sources)
    except RuntimeError as e:
        # Handle timeout and other runtime errors
        error_msg = str(e)
        logger.error(f"RAG Query RuntimeError: {error_msg}", exc_info=True)
        if "timeout" in error_msg.lower():
            raise HTTPException(status_code=504, detail=f"Query timed out: {error_msg}")
        raise HTTPException(status_code=500, detail=f"Error processing query: {error_msg}")
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        # Log the full exception with traceback
        logger.error(f"RAG Query Unexpected Exception: {type(e).__name__}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500, 
            detail=f"Error processing query: {type(e).__name__}: {str(e)}"
        )
    
    
@router.get("/health")
async def health_check():
    """
    Health check endpoint to verify RAG service availability.
    """
    service = get_rag_service()
    if service is None:
        raise HTTPException(status_code=500, detail="RAG Service is not available. Please ensure chromadb is properly installed.")
    
    return {"status": "RAG Service is operational."}
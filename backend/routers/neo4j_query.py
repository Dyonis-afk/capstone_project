"""
Neo4j Router
Handles Neo4j query endpoints for BloodHound graph database
"""

import logging
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from models.neo4j_models import (
    NaturalLanguageQueryRequest,
    CypherQueryRequest,
    Neo4jQueryResponse,
    Neo4jConnectionTest
)
from services.neo4j_service import Neo4jService
from services.remediation_service import RemediationService

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize services (singleton pattern)
neo4j_service: Optional[Neo4jService] = None
remediation_service: Optional[RemediationService] = None

def get_neo4j_service() -> Neo4jService:
    """Get or create Neo4j service instance"""
    global neo4j_service
    if neo4j_service is None:
        try:
            # Create new service instance - will attempt connection
            neo4j_service = Neo4jService()
            # If connection failed during init, driver will be None but service exists
            # This allows retry on first use
        except Exception as e:
            logger.error(f"❌ Failed to initialize Neo4j service: {str(e)}")
            # Don't raise here - allow lazy connection
            neo4j_service = Neo4jService()
    return neo4j_service

def get_remediation_service() -> RemediationService:
    """Get or create remediation service instance"""
    global remediation_service
    if remediation_service is None:
        remediation_service = RemediationService()
    return remediation_service


@router.get("/test", response_model=Neo4jConnectionTest)
async def test_neo4j_connection():
    """
    Test connection to Neo4j database.
    
    Returns database statistics if connected successfully.
    """
    try:
        service = get_neo4j_service()
        result = service.test_connection()
        return Neo4jConnectionTest(**result)
    except HTTPException:
        raise
    except Exception as e:
        return Neo4jConnectionTest(
            connected=False,
            database=None,
            node_count=None,
            relationship_count=None,
            error=str(e)
        )


# ==================== PROJECT DATA MANAGEMENT ====================

@router.get("/project/{project_id}/status")
async def get_project_neo4j_status(project_id: str):
    """
    Get Neo4j data status for a specific project.
    
    Returns node/relationship counts and data statistics for the project.
    """
    try:
        service = get_neo4j_service()
        status = service.check_project_data(project_id)
        return status
    except Exception as e:
        logger.error(f"Error checking project status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/project/{project_id}/clear")
async def clear_project_neo4j_data(
    project_id: str,
    confirm: bool = Query(False, description="Must be true to confirm deletion")
):
    """
    Clear all Neo4j data for a specific project.
    
    Only deletes nodes/relationships tagged with this project_id.
    Other projects' data remains untouched.
    """
    if not confirm:
        raise HTTPException(
            status_code=400,
            detail="Must set confirm=true to clear project data"
        )
    
    try:
        service = get_neo4j_service()
        result = service.clear_project_data(project_id)
        
        if result["success"]:
            return {
                "message": f"Project {project_id} Neo4j data cleared",
                **result
            }
        else:
            raise HTTPException(status_code=500, detail=result.get("error"))
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error clearing project data: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/natural", response_model=Neo4jQueryResponse)
async def query_natural_language(
    request: NaturalLanguageQueryRequest,
    project_id: str = Query(None, description="Project ID for data filtering")
):
    """
    Execute a natural language query against Neo4j.
    
    Converts natural language to Cypher, executes it, and provides AI explanation.
    
    Examples:
    - "Find all paths to Domain Admins"
    - "Show me users with DCSync rights"
    - "Which users are Kerberoastable?"
    - "Find all local admin relationships"
    """
    try:
        service = get_neo4j_service()
        
        # Execute query with explanation
        result = service.query_with_explanation(
            question=request.question,
            limit=100
        )
        
        # Generate remediation if requested
        remediations = None
        if request.include_remediation and result['results']:
            remediations = []
            remediation_svc = get_remediation_service()
            
            # Try to extract edge relationships from results
            for item in result['results'][:10]:  # Limit to first 10 for performance
                # This is a simplified extraction - adjust based on your query structure
                if 'r' in item:  # If relationship is in result
                    # Extract source and target from path
                    # This is query-dependent and may need adjustment
                    pass
        
        return Neo4jQueryResponse(
            question=result['question'],
            cypher_query=result['cypher_query'],
            results=result['results'],
            count=result['count'],
            explanation=result['explanation'],
            remediations=remediations
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error executing query: {str(e)}"
        )


@router.post("/cypher", response_model=Neo4jQueryResponse)
async def execute_cypher_query(
    request: CypherQueryRequest,
    project_id: str = Query(None, description="Project ID for data filtering")
):
    """
    Execute a direct Cypher query against Neo4j.
    
    Only read-only queries are allowed (MATCH, RETURN, etc.).
    Queries with CREATE, DELETE, SET, etc. will be rejected.
    """
    try:
        service = get_neo4j_service()
        
        # Validate query is read-only
        cypher_upper = request.cypher.upper()
        write_keywords = ['CREATE', 'DELETE', 'SET', 'REMOVE', 'MERGE', 'DROP']
        for keyword in write_keywords:
            if keyword in cypher_upper:
                raise HTTPException(
                    status_code=400,
                    detail=f"Write operations ({keyword}) are not allowed. Use read-only queries."
                )
        
        # Execute query with optional project filtering
        results = service.run_cypher_query(
            request.cypher,
            project_id=project_id  # This triggers middleware filtering
        )
        
        return Neo4jQueryResponse(
            question=None,
            cypher_query=request.cypher,
            results=results[:request.limit] if request.limit else results,
            count=len(results),
            explanation=None,
            remediations=None
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error executing Cypher query: {str(e)}"
        )


@router.get("/common-queries")
async def get_common_queries():
    """
    Get a list of common BloodHound Cypher queries.
    
    Useful for users who want to run standard queries.
    """
    try:
        service = get_neo4j_service()
        queries = service.get_common_queries()
        return {
            "queries": queries,
            "count": len(queries)
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving common queries: {str(e)}"
        )


@router.post("/execute-common/{query_name}")
async def execute_common_query(
    query_name: str,
    project_id: str = Query(None, description="Project ID for data filtering")
):
    """
    Execute a common query by name.
    
    Available queries:
    - paths-to-domain-admins
    - users-with-dcsync
    - kerberoastable-users
    - local-admin-rights
    - unconstrained-delegation
    - high-privilege-groups
    - asrep-roastable
    - owned-principals
    """
    try:
        service = get_neo4j_service()
        common_queries = service.get_common_queries()
        
        # Find query by name (convert kebab-case to title case for matching)
        query_name_normalized = query_name.replace('-', ' ').title()
        query = None
        for q in common_queries:
            if q['name'].replace(' ', '').lower() == query_name.replace('-', '').lower():
                query = q
                break
        
        if not query:
            raise HTTPException(
                status_code=404,
                detail=f"Query '{query_name}' not found. Use /common-queries to see available queries."
            )
        
        # Execute query with project filtering
        results = service.run_cypher_query(query['cypher'], project_id=project_id)
        
        return {
            "query_name": query['name'],
            "description": query['description'],
            "cypher": query['cypher'],
            "project_id": project_id,
            "results": results,
            "count": len(results)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error executing common query: {str(e)}"
        )


@router.get("/statistics")
async def get_database_statistics(
    project_id: str = Query(None, description="Project ID to get stats for (optional)")
):
    """
    Get detailed statistics about the BloodHound database.
    
    Returns counts for each node type and relationship type.
    """
    try:
        service = get_neo4j_service()
        
        if project_id:
            # Project-specific statistics
            return service.check_project_data(project_id)
        else:
            # Global statistics
            stats = service.get_database_statistics()
            return stats
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving statistics: {str(e)}"
        )


@router.get("/health")
async def neo4j_health_check():
    """
    Quick health check for Neo4j connection.
    """
    try:
        service = get_neo4j_service()
        test_result = service.test_connection()
        
        if test_result['connected']:
            return {
                "status": "healthy",
                "database": test_result['database'],
                "nodes": test_result['node_count'],
                "relationships": test_result['relationship_count']
            }
        else:
            raise HTTPException(
                status_code=503,
                detail=f"Neo4j unhealthy: {test_result['error']}"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Neo4j health check failed: {str(e)}"
        )

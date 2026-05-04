"""
Pydantic models for Attack Path Router
Location: backend/routers/attack_paths/models.py
"""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class FindingsSummary(BaseModel):
    """Summary of BloodHound findings from frontend parser"""
    high_risk: List[Dict[str, Any]] = Field(default_factory=list, description="High risk findings")
    medium_risk: List[Dict[str, Any]] = Field(default_factory=list, description="Medium risk findings")
    low_risk: List[Dict[str, Any]] = Field(default_factory=list, description="Low risk findings")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Statistics summary")


class DomainInfo(BaseModel):
    """Domain info from BloodHound Domain node"""
    name: Optional[str] = None
    functional_level: Optional[str] = Field(default=None, alias="functionalLevel")
    forest: Optional[str] = None

    class Config:
        populate_by_name = True  # Accept both snake_case and camelCase


class EnvironmentInfo(BaseModel):
    """Environment info discovered from local Neo4j"""
    domain_names: List[str] = Field(default_factory=list)
    domain_info: Optional[DomainInfo] = Field(default=None, alias="domainInfo")
    domain_admin_groups: List[str] = Field(default_factory=list)
    high_value_groups: List[str] = Field(default_factory=list)
    service_accounts: List[str] = Field(default_factory=list)
    computers: List[str] = Field(default_factory=list)
    total_nodes: int = 0
    total_relationships: int = 0
    users_count: int = 0
    groups_count: int = 0
    computers_count: int = 0

    class Config:
        populate_by_name = True  # Accept both snake_case and camelCase


class GenerateQueriesRequest(BaseModel):
    """Request to generate Cypher queries based on findings"""
    findings_summary: FindingsSummary
    environment_info: Optional[EnvironmentInfo] = None
    options: Optional[Dict[str, Any]] = None


class GeneratedQuery(BaseModel):
    """A generated Cypher query"""
    id: str
    name: str
    description: str
    cypher: str
    attack_type: str
    priority: str
    edges_used: List[str] = Field(default_factory=list)


class GenerateQueriesResponse(BaseModel):
    """Response with generated queries"""
    analysis_id: str
    queries: List[GeneratedQuery]
    environment_analysis: Dict[str, Any]
    message: str


class QueryResult(BaseModel):
    """Result from executing a query on local Neo4j"""
    query_id: str
    query_name: str
    cypher: str
    results: List[Dict[str, Any]]
    result_count: int
    execution_time_ms: Optional[float] = None
    error: Optional[str] = None


class ContextQuery(BaseModel):
    """A context-enrichment Cypher query for the client to execute locally"""
    id: str
    finding_index: int = Field(description="Index of the finding this query enriches (-1 for global)")
    query_type: str = Field(description="Type of context query (e.g. group_members, spns, dc_detection)")
    cypher: str
    entity_name: Optional[str] = None


class GenerateContextQueriesRequest(BaseModel):
    """Request to generate context-enrichment queries for local execution"""
    analysis_id: str
    query_results: List[QueryResult]
    findings_summary: Optional[FindingsSummary] = None
    environment_info: Optional[EnvironmentInfo] = None


class GenerateContextQueriesResponse(BaseModel):
    """Response with context queries for the client to execute"""
    analysis_id: str
    context_queries: List[ContextQuery]
    message: str


class ContextQueryResult(BaseModel):
    """Result from executing a context query on local Neo4j"""
    query_id: str
    finding_index: int
    query_type: str
    entity_name: Optional[str] = None
    results: List[Dict[str, Any]] = Field(default_factory=list)
    result_count: int = 0


class AnalyzeResultsRequest(BaseModel):
    """Request to analyze query results and generate report"""
    analysis_id: str
    findings_summary: FindingsSummary
    environment_info: Optional[EnvironmentInfo] = None
    query_results: List[QueryResult]
    options: Optional[Dict[str, Any]] = None
    tier0_config: Optional[Dict[str, Any]] = None  # T0 config for classifying findings
    context_query_results: Optional[List[ContextQueryResult]] = None
    dc_hostname: Optional[str] = None
    # Chain discovery results from weighted path queries
    chain_results: Optional[List[Dict[str, Any]]] = None
    chain_source_info: Optional[List[Dict[str, Any]]] = None


class AnalyzeResultsResponse(BaseModel):
    """Response with complete attack path report"""
    analysis_id: str
    status: str
    report: Dict[str, Any]
    message: str


# Chain discovery models
class ChainQueryRequest(BaseModel):
    """Request to generate weighted path queries for source/target pairs"""
    sources: List[Dict[str, Any]]  # [{name, type, compromise_method, properties}]
    targets: List[Dict[str, Any]]  # [{name, type}]


class ChainQueryResponse(BaseModel):
    """Response with weighted path Cypher queries"""
    chain_queries: List[Dict[str, Any]]  # [{source, target, cypher, params}]
    reverse_chain_queries: List[Dict[str, Any]]  # [{target, cypher, params}]
    total_pairs: int
    total_reverse: int

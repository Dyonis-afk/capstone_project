"""Pydantic request/response schemas for the attack-path analysis API."""

from pydantic import BaseModel, Field, validator, model_validator
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum


class AttackPathOptions(BaseModel):
    """Optional parameters for attack path analysis"""
    
    max_paths_per_query: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum number of paths to analyze per query type (1-20)"
    )
    
    include_medium_risk: bool = Field(
        default=True,
        description="Include medium risk findings in analysis"
    )
    
    include_low_risk: bool = Field(
        default=False,
        description="Include low risk findings in analysis"
    )
    
    custom_queries: Optional[List[Dict[str, str]]] = Field(
        default=None,
        description="Custom Cypher queries to include in analysis"
    )
    
    environment_context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional environment context for RAG analysis"
    )
    
    use_existing_data: bool = Field(
        default=False,
        description="If True, analyze existing Neo4j data instead of importing new BloodHound data"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "max_paths_per_query": 3,
                "include_medium_risk": True,
                "include_low_risk": False,
                "custom_queries": [
                    {
                        "name": "Custom Domain Admin Query",
                        "cypher": "MATCH (u:User)-[:AdminTo]->(c:Computer) RETURN u, c LIMIT 5"
                    }
                ]
            }
        }


class AttackPathRequest(BaseModel):
    """Request model for attack path analysis"""
    
    bloodhound_data: Optional[Union[str, Dict[str, Any]]] = Field(
        default=None,
        description="BloodHound analysis data (JSON string or object). Required unless use_existing_data is True in options."
    )
    
    options: Optional[Union[AttackPathOptions, Dict[str, Any]]] = Field(
        default=None,
        description="Optional analysis parameters (may include use_existing_data: true)"
    )
    
    project_id: Optional[str] = Field(
        default=None,
        description="Project ID for data isolation. All imported data will be tagged with this ID."
    )
    
    @validator('bloodhound_data')
    def validate_bloodhound_data(cls, v):
        """Validate BloodHound data structure"""
        import json
        
        # If None, will be validated by root_validator
        if v is None:
            return None
        
        # Convert string to dict if needed
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON format in BloodHound data")
        
        # Validate required structure
        required_fields = ['high_risk', 'medium_risk', 'low_risk', 'summary']
        if not isinstance(v, dict):
            raise ValueError("BloodHound data must be a JSON object")
            
        missing_fields = [field for field in required_fields if field not in v]
        if missing_fields:
            raise ValueError(f"BloodHound data missing required fields: {missing_fields}")
        
        return v
    
    @model_validator(mode='after')
    def validate_request(self):
        """Validate the entire request"""
        bloodhound_data = self.bloodhound_data
        options = self.options
        
        # Handle both dict and AttackPathOptions object
        if options is None:
            use_existing = False
        elif isinstance(options, dict):
            use_existing = options.get('use_existing_data', False)
        else:
            use_existing = getattr(options, 'use_existing_data', False)
        
        # If using existing data, bloodhound_data can be None
        if use_existing:
            return self
        
        # If not using existing data, bloodhound_data must be provided
        if bloodhound_data is None:
            raise ValueError("BloodHound data is required when use_existing_data is not True")
        
        return self
    
    class Config:
        json_schema_extra = {
            "example": {
                "bloodhound_data": {
                    "high_risk": [
                        {
                            "source": "john.doe@contoso.local",
                            "target": "DOMAIN ADMINS@CONTOSO.LOCAL",
                            "edge_type": "GenericAll",
                            "risk_level": "High"
                        }
                    ],
                    "medium_risk": [],
                    "low_risk": [],
                    "summary": {
                        "total_nodes": 1000,
                        "high_risk_count": 5
                    }
                },
                "options": {
                    "max_paths_per_query": 3,
                    "include_medium_risk": True
                },
                "project_id": "proj_abc123"
            }
        }


class AttackPathStatus(str, Enum):
    """Enum for attack path analysis status"""
    PENDING = "pending"
    STARTED = "started"
    INITIALIZING = "initializing"
    IMPORTING = "importing"
    VERIFYING = "verifying"
    ANALYZING_ENVIRONMENT = "analyzing_environment"
    GENERATING_QUERIES = "generating_queries"
    EXECUTING_QUERIES = "executing_queries"
    EXECUTING_ANALYSIS = "executing_analysis"
    ANALYZING_SCENARIOS = "analyzing_scenarios"
    GENERATING_INTELLIGENCE = "generating_intelligence"
    FORMATTING = "formatting"
    FORMATTING_REPORT = "formatting_report"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    ERROR = "error"


class AttackPathResponse(BaseModel):
    """Response model for attack path analysis request"""
    
    analysis_id: str = Field(
        ...,
        description="Unique identifier for this analysis"
    )
    
    status: AttackPathStatus = Field(
        ...,
        description="Current analysis status"
    )
    
    message: str = Field(
        ...,
        description="Human-readable status message"
    )
    
    progress: int = Field(
        ...,
        ge=0,
        le=100,
        description="Analysis progress percentage (0-100)"
    )
    
    estimated_time_remaining: Optional[str] = Field(
        default=None,
        description="Estimated time remaining for completion"
    )
    
    started_at: Optional[str] = Field(
        default=None,
        description="ISO timestamp when analysis started"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
                "status": "processing",
                "message": "Attack path analysis in progress",
                "progress": 25,
                "estimated_time_remaining": "3-4 minutes",
                "started_at": "2024-12-24T14:30:00Z"
            }
        }


class AnalysisProgressResponse(BaseModel):
    """Response model for analysis progress checks"""
    
    analysis_id: str = Field(
        ...,
        description="Unique identifier for this analysis"
    )
    
    status: AttackPathStatus = Field(
        ...,
        description="Current analysis status"
    )
    
    step: Optional[str] = Field(
        default=None,
        description="Current step identifier for UI mapping"
    )
    
    progress: int = Field(
        ...,
        ge=0,
        le=100,
        description="Analysis progress percentage (0-100)"
    )
    
    message: str = Field(
        ...,
        description="Human-readable status message"
    )
    
    started_at: Optional[str] = Field(
        default=None,
        description="ISO timestamp when analysis started"
    )
    
    completed_at: Optional[str] = Field(
        default=None,
        description="ISO timestamp when analysis completed"
    )
    
    estimated_time_remaining: Optional[str] = Field(
        default=None,
        description="Estimated time remaining for completion"
    )
    
    error: Optional[str] = Field(
        default=None,
        description="Error message if analysis failed"
    )


class PathOverview(BaseModel):
    """Model for attack path overview and risk metrics"""
    
    path_length: int = Field(
        ...,
        ge=1,
        description="Number of hops in the attack path"
    )
    
    attack_complexity: str = Field(
        ...,
        description="Attack complexity assessment (Easy/Medium/Hard)"
    )
    
    cvss_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="CVSS risk score (0.0-10.0)"
    )
    
    business_impact: str = Field(
        ...,
        description="Business impact assessment"
    )
    
    estimated_exploitation_time: str = Field(
        ...,
        description="Estimated time for successful exploitation"
    )
    
    priority: str = Field(
        ...,
        description="Remediation priority (High/Medium/Low)"
    )


class GraphNode(BaseModel):
    """Model for graph visualization nodes"""
    
    id: str = Field(..., description="Unique node identifier")
    label: str = Field(..., description="Display name for the node")
    type: str = Field(..., description="Node type (user/group/computer/domain)")
    risk_level: str = Field(..., description="Risk level (High/Medium/Low)")
    properties: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional node properties"
    )


class GraphEdge(BaseModel):
    """Model for graph visualization edges"""
    
    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    relationship: str = Field(..., description="Relationship type")
    risk_level: str = Field(..., description="Edge risk level")
    properties: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional edge properties"
    )


class GraphData(BaseModel):
    """Model for graph visualization data"""
    
    nodes: List[GraphNode] = Field(..., description="List of graph nodes")
    edges: List[GraphEdge] = Field(..., description="List of graph edges")
    layout: str = Field(
        default="hierarchical",
        description="Preferred layout algorithm"
    )


class AttackCommand(BaseModel):
    """Model for individual attack commands"""
    
    step_number: int = Field(..., ge=1, description="Step number in attack sequence")
    description: str = Field(..., description="Description of this attack step")
    commands: List[str] = Field(..., description="PowerShell/command line commands")
    expected_output: str = Field(..., description="Expected command output")
    tools_required: Optional[List[str]] = Field(
        default=None,
        description="Required tools for this step"
    )
    warnings: Optional[List[str]] = Field(
        default=None,
        description="Warnings about this attack step"
    )


class RemediationStep(BaseModel):
    """Model for remediation steps"""
    
    step_number: int = Field(..., ge=1, description="Step number in remediation")
    title: str = Field(..., description="Remediation step title")
    description: str = Field(..., description="Detailed remediation instructions")
    powershell_commands: Optional[List[str]] = Field(
        default=None,
        description="PowerShell commands for remediation"
    )
    verification_steps: Optional[List[str]] = Field(
        default=None,
        description="Steps to verify remediation success"
    )
    impact_warning: Optional[str] = Field(
        default=None,
        description="Warning about potential service impact"
    )


class AttackPathAnalysis(BaseModel):
    """Model for complete attack path analysis"""
    
    scenario_number: int = Field(..., ge=1, description="Attack scenario number (1-6)")
    title: str = Field(..., description="Attack path title")
    attack_type: str = Field(..., description="Type of attack (e.g., Privilege Escalation)")
    
    # Core analysis sections
    path_overview: PathOverview = Field(..., description="Path overview and risk metrics")
    graph_data: GraphData = Field(..., description="Graph visualization data")
    
    # Intelligence sections
    technical_analysis: str = Field(
        ...,
        description="Technical explanation of the attack path"
    )
    
    attack_scenario: List[AttackCommand] = Field(
        ...,
        description="Step-by-step attack commands"
    )
    
    mitre_mapping: List[str] = Field(
        ...,
        description="MITRE ATT&CK technique mappings"
    )
    
    remediation_strategy: List[RemediationStep] = Field(
        ...,
        description="Remediation steps to fix this attack path"
    )
    
    detection_methods: List[str] = Field(
        ...,
        description="Methods to detect this attack"
    )
    
    # Metadata
    generated_at: str = Field(..., description="ISO timestamp when analysis was generated")
    confidence_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence in analysis accuracy (0.0-1.0)"
    )


class EnvironmentAnalysis(BaseModel):
    """Model for environment analysis results"""
    
    domain_names: List[str] = Field(..., description="Discovered domain names")
    domain_admin_groups: List[str] = Field(..., description="Domain admin groups found")
    high_value_groups: List[str] = Field(..., description="High-value security groups")
    service_accounts: List[str] = Field(..., description="Service accounts with SPNs")
    critical_computers: List[str] = Field(..., description="Critical servers/computers")
    
    security_assessment: str = Field(
        ...,
        description="Overall security posture assessment"
    )
    
    key_risks: List[str] = Field(..., description="Key risk factors identified")
    analysis_method: str = Field(..., description="Analysis method used")


class AttackPathReport(BaseModel):
    """Model for complete attack path intelligence report"""
    
    # Report metadata
    report_id: str = Field(..., description="Unique report identifier")
    generated_at: str = Field(..., description="ISO timestamp when report was generated")
    environment_analyzed: bool = Field(..., description="Whether environment was analyzed")
    total_paths_analyzed: int = Field(..., description="Total number of attack paths analyzed")
    analysis_method: str = Field(..., description="Analysis methodology used")
    
    # Report sections
    executive_summary: str = Field(
        ...,
        description="Executive summary of findings"
    )
    
    environment_analysis: EnvironmentAnalysis = Field(
        ...,
        description="Environment analysis results"
    )
    
    critical_attack_paths: List[AttackPathAnalysis] = Field(
        ...,
        description="List of critical attack paths (up to 6)"
    )
    
    strategic_recommendations: List[str] = Field(
        ...,
        description="High-level strategic recommendations"
    )
    
    # Statistics
    statistics: Dict[str, Any] = Field(
        default_factory=dict,
        description="Analysis statistics and metrics"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "report_id": "550e8400-e29b-41d4-a716-446655440000",
                "generated_at": "2024-12-24T14:30:00Z",
                "environment_analyzed": True,
                "total_paths_analyzed": 6,
                "analysis_method": "RAG-powered context-aware discovery",
                "executive_summary": "Critical security vulnerabilities found...",
                "critical_attack_paths": [
                    {
                        "scenario_number": 1,
                        "title": "Standard User → Domain Admin",
                        "attack_type": "Privilege Escalation",
                        "path_overview": {
                            "path_length": 2,
                            "attack_complexity": "Easy",
                            "cvss_score": 9.8,
                            "business_impact": "Complete domain compromise",
                            "estimated_exploitation_time": "< 30 minutes",
                            "priority": "High"
                        }
                    }
                ]
            }
        }


class ServiceStatus(BaseModel):
    """Model for service status responses"""
    
    status: str = Field(..., description="Service status")
    message: str = Field(..., description="Status message")
    timestamp: Optional[str] = Field(
        default=None,
        description="Status check timestamp"
    )


class ConnectionTestResponse(BaseModel):
    """Model for service connection test responses"""
    
    neo4j: ServiceStatus = Field(..., description="Neo4j service status")
    rag: ServiceStatus = Field(..., description="RAG service status")
    overall: ServiceStatus = Field(..., description="Overall system status")
    ready: bool = Field(..., description="Whether system is ready for analysis")


class AnalysisListResponse(BaseModel):
    """Model for listing all analyses"""
    
    total_analyses: int = Field(..., description="Total number of analyses")
    analyses: List[Dict[str, Any]] = Field(..., description="List of analysis summaries")


class ErrorResponse(BaseModel):
    """Model for error responses"""
    
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional error details"
    )
    timestamp: str = Field(..., description="Error timestamp")
    
    class Config:
        json_schema_extra = {
            "example": {
                "error": "ValidationError",
                "message": "Invalid BloodHound data format",
                "details": {
                    "field": "bloodhound_data",
                    "issue": "Missing required field: high_risk"
                },
                "timestamp": "2024-12-24T14:30:00Z"
            }
        }


# Utility models for common response patterns

class SuccessResponse(BaseModel):
    """Generic success response model"""
    
    success: bool = Field(default=True, description="Operation success status")
    message: str = Field(..., description="Success message")
    data: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional response data"
    )


class PaginationParams(BaseModel):
    """Model for pagination parameters"""
    
    page: int = Field(default=1, ge=1, description="Page number (1-based)")
    limit: int = Field(default=10, ge=1, le=100, description="Items per page (1-100)")
    sort_by: Optional[str] = Field(default=None, description="Sort field")
    sort_order: str = Field(default="asc", pattern="^(asc|desc)$", description="Sort order")
"""
Chat Models for Intelligent Query System
Defines request/response models for the chat interface with intent classification,
safety gates, and multiple response types.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from enum import Enum


class QueryIntent(str, Enum):
    """Classification of user query intent"""
    OFF_TOPIC = "OFF_TOPIC"
    GREETING = "GREETING"
    SUGGESTION = "SUGGESTION"
    EDUCATIONAL = "EDUCATIONAL"
    ATTACK = "ATTACK"
    REMEDIATION = "REMEDIATION"
    DATA_QUERY = "DATA_QUERY"
    PATH_QUERY = "PATH_QUERY"
    GRAPH_EXPLAIN = "GRAPH_EXPLAIN"


class ResponseType(str, Enum):
    """Type of response to return"""
    TEXT = "text"
    MARKDOWN = "markdown"
    TABLE = "table"
    GRAPH = "graph"
    ERROR = "error"


class ChatQueryRequest(BaseModel):
    """Request model for intelligent chat queries"""

    query: str = Field(
        ...,
        description="User's natural language query",
        min_length=1
    )

    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Optional context including previous messages, current graph state, etc."
    )

    project_id: Optional[str] = Field(
        default=None,
        description="Project ID for Neo4j data filtering"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "query": "Show me all kerberoastable users",
                "context": {
                    "previousMessages": ["What is Kerberoasting?"]
                },
                "project_id": "project-123"
            }
        }


class IntentClassification(BaseModel):
    """Result of intent classification"""

    intent: QueryIntent = Field(
        ...,
        description="Classified intent category"
    )

    confidence: float = Field(
        ...,
        description="Confidence score (0.0 to 1.0)",
        ge=0.0,
        le=1.0
    )

    entities: List[str] = Field(
        default_factory=list,
        description="Extracted entities from the query (e.g., usernames, group names)"
    )


class GraphData(BaseModel):
    """Graph visualization data"""

    nodes: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Graph nodes"
    )

    edges: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Graph edges/relationships"
    )


class ChatQueryResponse(BaseModel):
    """Response model for chat queries"""

    intent: QueryIntent = Field(
        ...,
        description="Classified intent of the query"
    )

    content: str = Field(
        ...,
        description="Response content (markdown, table markdown, or plain text)"
    )

    response_type: ResponseType = Field(
        ...,
        description="Type of response for frontend rendering"
    )

    cypher_query: Optional[str] = Field(
        default=None,
        description="Generated Cypher query (if applicable)"
    )

    result_count: Optional[int] = Field(
        default=None,
        description="Number of results returned"
    )

    raw_results: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Raw query results for further processing"
    )

    graph_data: Optional[GraphData] = Field(
        default=None,
        description="Graph data for visualization (if applicable)"
    )

    classification: Optional[IntentClassification] = Field(
        default=None,
        description="Full intent classification details"
    )


class GenerateFindingRequest(BaseModel):
    """Request to generate a full Finding structure for Report Format view"""

    query: str = Field(
        ...,
        description="Original user query"
    )

    intent: QueryIntent = Field(
        ...,
        description="Classified intent"
    )

    results: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Query results to base the finding on"
    )

    cypher_query: Optional[str] = Field(
        default=None,
        description="Cypher query that was executed"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "query": "List all kerberoastable users",
                "intent": "DATA_QUERY",
                "results": [{"name": "SVC_SQL@CORP.LOCAL", "hasspn": True}],
                "cypher_query": "MATCH (u:User) WHERE u.hasspn = true RETURN u.name"
            }
        }


# Finding structure matching the frontend pentest_finding format

class OpsecOption(BaseModel):
    """Individual OPSEC option within an attack step.
    Represents one way to accomplish the step with different OPSEC profiles.
    """
    opsec_level: Literal["safe", "risky"]  # 'safe' = Native PowerShell/offline, 'risky' = known tools
    tool_name: str  # "Native PowerShell", "PowerView", "Rubeus", "Hashcat (Offline)"
    command: str    # The actual command
    explanation: str  # Why this approach is OPSEC-safe or risky, and what it does


class AttackStep(BaseModel):
    """Single step in an attack chain.
    Supports both legacy single-command format and new OPSEC-aware multi-option format.
    """
    step_number: int
    title: str
    category: Optional[str] = None  # "Discovery", "Credential Access", "Lateral Movement"
    description: Optional[str] = None  # What this step accomplishes overall

    # New OPSEC-aware format: multiple options per step
    opsec_options: Optional[List[OpsecOption]] = None

    # Legacy single-command format (for backward compatibility)
    tool: Optional[str] = None
    command: Optional[str] = None
    explanation: Optional[str] = None


class AffectedEntity(BaseModel):
    """Entity affected by a finding"""
    principal: str
    type: str  # User, Group, Computer
    risk: Optional[str] = None  # High, Medium, Low
    target_group: Optional[str] = None
    spn: Optional[str] = None
    path: Optional[str] = None


class Reference(BaseModel):
    """External reference for a finding"""
    tag: str  # MITRE, BLOG, TOOL, etc.
    title: str
    url: str


class EventId(BaseModel):
    """Windows Event ID for detection - matches frontend"""
    id: str
    description: str


class DetectionQuery(BaseModel):
    """Detection query for SIEM platforms"""
    platform: str  # "Splunk", "KQL (Microsoft Sentinel)"
    query: str


class Detection(BaseModel):
    """Detection and monitoring information - matches frontend FindingDetection"""
    event_ids: List[EventId] = Field(default_factory=list)
    indicators_of_compromise: List[str] = Field(default_factory=list)
    proactive_measures: List[str] = Field(default_factory=list)
    queries: List[DetectionQuery] = Field(default_factory=list)


class UnderstandingItem(BaseModel):
    """Q&A style explanation for understanding section - matches frontend AttackExplanation"""
    question: str  # e.g., "What is Kerberoasting?"
    answer: str    # Detailed explanation


class Finding(BaseModel):
    """Complete finding structure matching frontend pentest_finding format"""

    # Header - matches frontend Finding interface
    finding_number: int = 0  # Default to 0 for chat-generated findings
    title: str
    severity: Literal["Critical", "High", "Medium", "Low"]
    category: str
    attack_complexity: Literal["Low", "Medium", "High"]

    # Observation
    observation: str  # Markdown

    # Understanding the Attack - uses Q&A format matching frontend
    understanding: List[UnderstandingItem] = Field(default_factory=list)

    # Affected Entities
    affected_entities: List[AffectedEntity] = Field(default_factory=list)

    # Attack Commands
    attack_intro: Optional[str] = None
    attack_steps: List[AttackStep] = Field(default_factory=list)

    # Evidence
    cypher_query: str = ""  # Required in frontend, default empty string
    edges_used: List[str] = Field(default_factory=list)
    graph_data: Optional[Dict[str, Any]] = None  # For embedded graph visualization

    # Risk
    risk_title: str = "Security Risk"
    risk_description: str = ""  # Markdown

    # Remediation
    remediation_steps: List[str] = Field(default_factory=list)
    remediation_script: Optional[str] = None

    # References
    references: List[Reference] = Field(default_factory=list)

    # Detection & Monitoring - matches frontend FindingDetection
    detection: Detection = Field(default_factory=Detection)


class GenerateFindingResponse(BaseModel):
    """Response containing generated Finding structure"""

    success: bool
    finding: Optional[Finding] = None
    error: Optional[str] = None

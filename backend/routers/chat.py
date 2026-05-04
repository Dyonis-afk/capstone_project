"""
Chat Router - Simplified Query Execution System

This router handles two types of inputs:
1. Raw Cypher queries → Execute directly
2. Natural language → Generate Cypher → Execute

For non-query inputs (educational, attack, remediation questions),
it suggests a relevant query and points to Report Format for details.
"""

import logging
import re
import json
import time
from typing import Optional, List, Dict, Any, Union
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from enum import Enum

from services.neo4j_service import Neo4jService
from services.graph_extractor import AttackPathGraphExtractor

# Import OPSEC templates for dynamic prompt injection
try:
    from routers.attack_paths.constants.opsec_templates import get_opsec_attack_steps
except ImportError:
    get_opsec_attack_steps = None

# Import log buffer from attack_paths for real-time log streaming
try:
    from routers.attack_paths import log_buffer, add_log
except ImportError:
    # Fallback if attack_paths not available
    log_buffer = None
    def add_log(level: str, message: str, debug_only: bool = False):
        pass

logger = logging.getLogger(__name__)
router = APIRouter()

# Lazy loaded services
rag_service = None
neo4j_service: Optional[Neo4jService] = None

# In-memory set of cancelled request IDs with timestamps for cleanup.
# Checked by generators before starting each LLM call to avoid wasting API tokens.
# Scales to single instance; swap to Redis for multi-instance deployments.
_cancelled_requests: Dict[str, float] = {}  # {request_id: cancelled_at_timestamp}
_CANCEL_TTL = 600  # 10 minutes — auto-cleanup


def is_request_cancelled(request_id: Optional[str]) -> bool:
    """Check if a request has been cancelled. Also cleans up expired entries."""
    if not request_id:
        return False
    # Cleanup expired entries (lazy, on each check)
    now = time.time()
    expired = [rid for rid, ts in _cancelled_requests.items() if now - ts > _CANCEL_TTL]
    for rid in expired:
        _cancelled_requests.pop(rid, None)
    return request_id in _cancelled_requests


def get_rag_service():
    """Lazy initialization of RAGService"""
    global rag_service
    if rag_service is None:
        try:
            from services.rag_service import RAGService
            rag_service = RAGService()
            logger.info("RAGService initialized for chat router")
        except Exception as e:
            logger.error(f"Error initializing RAGService: {e}")
            rag_service = None
    return rag_service


def get_neo4j_service() -> Neo4jService:
    """Get or create Neo4j service instance"""
    global neo4j_service
    if neo4j_service is None:
        neo4j_service = Neo4jService()
    return neo4j_service


# =============================================================================
# DYNAMIC ATTACK TYPE DETECTION
# =============================================================================

# Mapping of keywords/patterns to edge types for opsec_templates
ATTACK_TYPE_PATTERNS = {
    'Kerberoastable': ['kerberoast', 'spn', 'service principal', 'hasspn', 'tgs'],
    'ASREPRoastable': ['asrep', 'as-rep', 'preauth', 'dontreqpreauth', 'getnpusers'],
    'DCSync': ['dcsync', 'replication', 'getchanges', 'secretsdump', 'krbtgt'],
    'GenericAll': ['genericall', 'full control'],
    'GenericWrite': ['genericwrite', 'write permission'],
    'WriteDacl': ['writedacl', 'dacl', 'modify permissions'],
    'ForceChangePassword': ['forcechangepassword', 'reset password', 'change password'],
    'AdminTo': ['adminto', 'local admin', 'admin access', 'localadmin'],
    'AddKeyCredentialLink': ['shadow credentials', 'keycredential', 'whisker', 'msds-keycredentiallink'],
    'HasSession': ['hassession', 'session', 'logged in'],
    'CanPSRemote': ['psremote', 'winrm', 'powershell remote'],
    'CanRDP': ['canrdp', 'rdp', 'remote desktop'],
    'AllowedToDelegate': ['delegation', 'constrained delegation', 'allowedtodelegate', 's4u'],
    'AllowedToAct': ['rbcd', 'resource-based', 'allowedtoact', 'msds-allowedtoactonbehalfof'],
}


def detect_attack_type(query: str, cypher: str = "", results: List[Dict] = None) -> Optional[str]:
    """
    Detect the attack type from query, cypher, or results to select appropriate opsec template.

    Returns the edge type key for opsec_templates or None if no match.
    """
    # Combine all context for detection
    context = f"{query} {cypher}".lower()

    # Also check results for node properties that indicate attack type
    if results:
        for result in results[:5]:  # Check first 5 results
            result_str = json.dumps(result, default=str).lower()
            context += f" {result_str}"

    # Check each attack type pattern
    for edge_type, patterns in ATTACK_TYPE_PATTERNS.items():
        for pattern in patterns:
            if pattern in context:
                logger.debug(f"Detected attack type: {edge_type} (matched: {pattern})")
                return edge_type

    return None


def format_opsec_template_for_prompt(edge_type: str, domain: str = "DOMAIN.LOCAL",
                                      source: str = "<user>", target: str = "<target>") -> str:
    """
    Format opsec template steps as reference for the LLM prompt.
    Returns a formatted string showing correct command syntax.
    """
    if not get_opsec_attack_steps:
        return ""

    try:
        steps = get_opsec_attack_steps(edge_type, domain, source, target)
        if not steps:
            return ""

        # Format as reference for the model
        lines = [f"\n=== VERIFIED COMMAND TEMPLATES FOR {edge_type.upper()} ==="]
        lines.append("Use these EXACT command formats (adapt entity names from results):\n")

        for step in steps:
            lines.append(f"### Step {step['step_number']}: {step['title']}")
            lines.append(f"Category: {step.get('category', 'N/A')}")

            for opt in step.get('opsec_options', []):
                level = "OPSEC-SAFE" if opt['opsec_level'] == 'safe' else "May trigger AV/EDR"
                lines.append(f"\n[{level}] {opt['tool_name']}:")
                # Show command with proper formatting
                cmd = opt['command'].replace('\n', '\n  ')
                lines.append(f"  {cmd}")
            lines.append("")

        lines.append("=== END TEMPLATES ===\n")
        return "\n".join(lines)
    except Exception as e:
        logger.debug(f"Error formatting opsec template: {e}")
        return ""


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class QueryType(str, Enum):
    CYPHER = "cypher"
    NATURAL_LANGUAGE = "natural_language"
    SUGGESTION = "suggestion"
    INVALID = "invalid"


class ViewMode(str, Enum):
    NORMAL = "normal"
    REPORT = "report"


class QueryRequest(BaseModel):
    query: str
    query_type: Optional[QueryType] = None
    output_format: ViewMode = ViewMode.NORMAL
    project_id: Optional[str] = None


class SuggestedQuery(BaseModel):
    name: str
    description: str
    cypher: str
    category: str


class EnvironmentContext(BaseModel):
    """Environment context from frontend's local Neo4j"""
    kerberoastable_users: List[str] = []
    asrep_roastable_users: List[str] = []
    unconstrained_delegation: List[str] = []
    domain_admins: List[str] = []
    total_users: int = 0
    total_computers: int = 0
    total_groups: int = 0
    domains: List[str] = []
    high_value_targets: List[str] = []


class SuggestionsRequest(BaseModel):
    """Request for suggestions with optional environment context from frontend"""
    project_id: Optional[str] = None
    include_ai: bool = True
    environment_context: Optional[EnvironmentContext] = None


class GraphNode(BaseModel):
    id: str
    label: str
    name: str
    type: str
    color: Optional[str] = None
    riskLevel: Optional[str] = None
    inAttackPath: bool = False
    pathIndex: int = 0
    properties: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    type: str
    color: Optional[str] = None
    riskLevel: Optional[str] = None
    inAttackPath: bool = False
    pathIndex: int = 0
    attack_type: Optional[str] = None
    description: Optional[str] = None
    properties: Dict[str, Any] = {}


class GraphData(BaseModel):
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    paths: List[Dict[str, Any]] = []


class OpsecOption(BaseModel):
    opsec_level: str  # 'safe' or 'risky'
    tool_name: str
    command: str
    explanation: str


class AttackStep(BaseModel):
    step_number: int
    title: str
    # New OPSEC-aware format
    category: Optional[str] = None
    objective: Optional[str] = None
    prerequisites: Optional[List[str]] = None
    opsec_options: Optional[List[OpsecOption]] = None
    # Legacy format (for backward compatibility)
    tool: Optional[str] = None
    command: Optional[str] = None
    explanation: Optional[str] = None


class QueryResponse(BaseModel):
    success: bool
    query_type: QueryType
    cypher_query: Optional[str] = None
    results: Optional[List[Dict[str, Any]]] = None
    result_count: int = 0
    # Normal mode content
    explanation: Optional[str] = None
    understanding: Optional[List[Dict[str, str]]] = None  # Q&A explanations
    attack_steps: Optional[List[AttackStep]] = None  # Structured attack steps
    remediation: Optional[str] = None
    # Report mode content (Finding structure)
    finding: Optional[Dict[str, Any]] = None
    # Graph data
    graph_data: Optional[GraphData] = None
    has_graph: bool = False
    # Suggested query (for non-query inputs)
    suggested_query: Optional[str] = None
    # Error
    error: Optional[str] = None


class SuggestionsResponse(BaseModel):
    suggestions: List[SuggestedQuery] = []
    ai_suggestions: List[SuggestedQuery] = []
    environment_summary: Optional[str] = None


# =============================================================================
# SAFETY GATE
# =============================================================================

DANGEROUS_PATTERNS = [
    r'\bDELETE\b',
    r'\bDETACH\s+DELETE\b',
    r'\bCREATE\b',
    r'\bMERGE\b',
    r'\bSET\b',
    r'\bREMOVE\b',
    r'\bDROP\b',
    r'\bCALL\s+\{',
]


def is_safe_query(cypher: str) -> bool:
    """Check if a Cypher query is safe (read-only)"""
    if not cypher:
        return False
    cypher_upper = cypher.upper()
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, cypher_upper):
            logger.warning(f"Dangerous pattern detected: {pattern}")
            return False
    return True


# Common tool name misspellings and their corrections
TOOL_NAME_CORRECTIONS = {
    # Mimikatz variations
    r'\bimikatz\b': 'mimikatz',
    r'\bmimkatz\b': 'mimikatz',
    r'\bmimicatz\b': 'mimikatz',
    r'\bmimikat\b': 'mimikatz',
    # Rubeus variations
    r'\brubues\b': 'Rubeus',
    r'\brubus\b': 'Rubeus',
    r'\brubeus\b': 'Rubeus',
    # Impacket variations
    r'\bimpaket\b': 'Impacket',
    r'\bimpactet\b': 'Impacket',
    r'\bimpackt\b': 'Impacket',
    # BloodHound variations
    r'\bbloodhund\b': 'BloodHound',
    r'\bbloodhond\b': 'BloodHound',
    # SharpHound variations
    r'\bsharphund\b': 'SharpHound',
    r'\bsharpound\b': 'SharpHound',
    # PowerView variations
    r'\bpowerveiw\b': 'PowerView',
    r'\bpowerviw\b': 'PowerView',
    # CrackMapExec variations
    r'\bcrackmapexe\b': 'CrackMapExec',
    r'\bcrackmaexec\b': 'CrackMapExec',
    # secretsdump variations
    r'\bsecretdump\b': 'secretsdump',
    r'\bsecretsdmp\b': 'secretsdump',
    r'\bsecretdumps\b': 'secretsdump',
    # GetUserSPNs variations
    r'\bgetuserspn\b': 'GetUserSPNs',
    r'\bgetUserSpns\b': 'GetUserSPNs',
    r'\bgetuserspns\b': 'GetUserSPNs',
    # GetNPUsers variations
    r'\bgetnpuser\b': 'GetNPUsers',
    r'\bgetnpusers\b': 'GetNPUsers',
    # PsExec variations
    r'\bpsexe\b': 'PsExec',
    r'\bpexec\b': 'PsExec',
    r'\bpsexce\b': 'PsExec',
    # Certify variations
    r'\bcertfy\b': 'Certify',
    r'\bcertifi\b': 'Certify',
    # Certipy variations
    r'\bcertipy\b': 'Certipy',
    r'\bcertpy\b': 'Certipy',
    # Kerberoast variations
    r'\bkerberoast\b': 'Kerberoast',
    r'\bkerbrost\b': 'Kerberoast',
}


def fix_tool_name_spelling(text: str) -> str:
    """Fix common misspellings of security tool names"""
    if not text:
        return text

    result = text
    for pattern, replacement in TOOL_NAME_CORRECTIONS.items():
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)

    return result


# =============================================================================
# QUERY DETECTION
# =============================================================================

def is_raw_cypher(query: str) -> bool:
    """Check if query is raw Cypher"""
    q = query.strip().upper()
    return (
        q.startswith('MATCH') or
        q.startswith('OPTIONAL MATCH') or
        q.startswith('WITH') or
        q.startswith('CALL') or
        q.startswith('UNWIND')
    )


def is_data_query(query: str) -> bool:
    """Check if natural language is asking for data (can generate Cypher)"""
    q = query.lower()

    # Entity keywords
    entities = ['user', 'users', 'group', 'groups', 'computer', 'computers',
                'domain', 'admin', 'admins', 'kerberoast', 'asrep', 'delegation',
                'dcsync', 'session', 'permission', 'path', 'paths', 'member',
                'spn', 'service', 'account', 'accounts', 'target', 'targets']

    # Action keywords that indicate data retrieval
    actions = ['list', 'show', 'find', 'get', 'who', 'what', 'which', 'how many',
               'count', 'display', 'query', 'search', 'all', 'return', 'give me']

    # Broad security questions — these should trigger data queries
    # e.g., "What are the vulnerabilities?", "Show attack paths", "Security risks?"
    broad_security_terms = ['vulnerability', 'vulnerabilities', 'risk', 'risks',
                           'security posture', 'attack surface', 'weakness',
                           'misconfiguration', 'exposure', 'threat']

    has_entity = any(e in q for e in entities)
    has_action = any(a in q for a in actions)
    has_broad_security = any(t in q for t in broad_security_terms)

    # Special case: queries about paths are data queries even without explicit action
    is_path_query = ('path' in q or 'paths' in q) and ('to' in q or 'from' in q)

    # Special case: queries with "and their" indicate relationship exploration
    is_relationship_query = 'and their' in q or 'with their' in q

    # Broad security questions should generate Cypher to show overview data
    is_broad_security = has_broad_security or ('attack' in q and 'path' in q)

    return (has_entity and has_action) or is_path_query or (has_entity and is_relationship_query) or is_broad_security


def is_off_topic(query: str) -> bool:
    """Check if query is completely off-topic"""
    q = query.lower()

    # Security/AD related keywords - if present, not off-topic
    security_keywords = [
        'user', 'group', 'computer', 'domain', 'admin', 'kerberos', 'ldap',
        'active directory', 'bloodhound', 'permission', 'acl', 'dacl',
        'attack', 'exploit', 'hack', 'compromise', 'privilege', 'escalation',
        'lateral', 'movement', 'credential', 'password', 'hash', 'ntlm',
        'spn', 'delegation', 'dcsync', 'golden', 'silver', 'ticket',
        'mimikatz', 'rubeus', 'impacket', 'powerview', 'sharphound',
        'remediation', 'fix', 'secure', 'protect', 'harden', 'mitigate',
        'vulnerability', 'vulnerabilities', 'risk', 'risks', 'posture',
        'weakness', 'exposure', 'misconfiguration', 'threat', 'surface',
        'writedacl', 'genericall', 'genericwrite', 'forcechangepassword',
        'owns', 'memberof', 'session', 'logon', 'certificate', 'adcs',
        'gpo', 'ou', 'forest', 'trust', 'sid', 'rid', 'sam', 'lsass',
        'cypher', 'match', 'return', 'query', 'path', 'paths', 'bloodhound'
    ]

    # Check if any security keyword is present
    found_keywords = [kw for kw in security_keywords if kw in q]
    is_security_related = len(found_keywords) > 0

    logger.info(f"OFF-TOPIC CHECK: query='{q[:50]}...' | found_keywords={found_keywords} | is_security_related={is_security_related}")

    return not is_security_related


# =============================================================================
# CYPHER GENERATION
# =============================================================================

CYPHER_GENERATION_PROMPT = """Convert this natural language request into a Cypher query for BloodHound CE.

Node types: User, Group, Computer, Domain, GPO, OU, Container
Edge types: MemberOf, AdminTo, HasSession, GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, ForceChangePassword, CanRDP, CanPSRemote, ExecuteDCOM, AllowedToDelegate, AllowedToAct, AddMember, AddSelf, ReadLAPSPassword, ReadGMSAPassword, DCSync, GetChanges, GetChangesAll, WriteSPN, AddKeyCredentialLink, AllExtendedRights, CoerceToTGT, SQLAdmin, HasSIDHistory

{domain_context}

Request: "{query}"

SYNTAX RULES (MANDATORY):
1. NEVER use inline property filters like {{hasspn: true}} — they fail when properties are NULL
   WRONG: MATCH (u:User {{hasspn: true}})
   CORRECT: MATCH (u:User) WHERE u.hasspn = true
2. For enabled checks: WHERE (u.enabled = true OR u.enabled IS NULL)
3. Do NOT use {{owned:true}} unless user specifically asks about owned nodes
4. Do NOT hardcode computer names — use flexible patterns
5. For Domain Admins: WHERE g.objectid ENDS WITH '-512'
6. Use domain "{domain}" for entity names when available
7. NEVER use example domains like "MARVEL.LOCAL" or "CONTOSO.COM"
8. When using shortestPath, ALWAYS add WHERE n <> m to prevent start=end errors
9. NEVER declare the same variable twice — use p1, p2 if needed
10. For broad security overview queries, return multiple common attack paths:
    Kerberoastable users, AS-REP roastable, DCSync rights, dangerous groups

Return ONLY valid Cypher starting with MATCH. No explanation. No markdown. No attack steps. No ### headers. Just the Cypher query. Add LIMIT 100 if not specified."""


CYPHER_GENERATION_PROMPT_NO_DOMAIN = """Convert this natural language request into a Cypher query for BloodHound CE.

Node types: User, Group, Computer, Domain, GPO, OU, Container
Edge types: MemberOf, AdminTo, HasSession, GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, ForceChangePassword, CanRDP, CanPSRemote, ExecuteDCOM, AllowedToDelegate, AllowedToAct, AddMember, AddSelf, ReadLAPSPassword, ReadGMSAPassword, DCSync, GetChanges, GetChangesAll, WriteSPN, AddKeyCredentialLink, AllExtendedRights, CoerceToTGT, SQLAdmin, HasSIDHistory

Request: "{query}"

SYNTAX RULES (MANDATORY):
1. NEVER use inline property filters like {{hasspn: true}} — they fail when properties are NULL
   WRONG: MATCH (u:User {{hasspn: true}})
   CORRECT: MATCH (u:User) WHERE u.hasspn = true
2. For enabled checks: WHERE (u.enabled = true OR u.enabled IS NULL)
3. Do NOT use {{owned:true}} unless user specifically asks about owned nodes
4. Do NOT hardcode computer names or domain names
5. For Domain Admins: WHERE g.objectid ENDS WITH '-512'
6. When using shortestPath, ALWAYS add WHERE n <> m to prevent start=end errors
7. NEVER declare the same variable twice — use p1, p2 if needed
8. For broad security overview queries, return common attack indicators:
   Kerberoastable, AS-REP roastable, DCSync, dangerous group memberships

Return ONLY valid Cypher starting with MATCH. No explanation. No markdown. No attack steps. No ### headers. Just the Cypher query. Add LIMIT 100 if not specified."""


def fix_duplicate_path_variables(cypher: str) -> str:
    """Fix duplicate path variable declarations in Cypher queries.

    LLMs sometimes generate queries like:
    MATCH p=(a)-[]->(b) MATCH p=(b)-[]->(c)

    This function renames duplicate path variables to p1, p2, etc.
    """
    # Find all path variable assignments: "varname = " or "varname="
    pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:shortestPath\s*)?\('
    matches = list(re.finditer(pattern, cypher, re.IGNORECASE))

    # Track which variables we've seen
    seen_vars = {}
    replacements = []

    for match in matches:
        var_name = match.group(1)
        var_lower = var_name.lower()

        if var_lower in seen_vars:
            # This is a duplicate - mark for renaming
            seen_vars[var_lower] += 1
            new_var = f"{var_name}{seen_vars[var_lower]}"
            replacements.append((match.start(1), match.end(1), new_var, var_name))
        else:
            seen_vars[var_lower] = 1

    # Apply replacements in reverse order to preserve positions
    result = cypher
    for start, end, new_var, old_var in reversed(replacements):
        result = result[:start] + new_var + result[end:]
        # Also replace RETURN clause references if they exist
        # Find RETURN clause and replace the duplicated variable
        return_match = re.search(r'\bRETURN\b(.*)$', result, re.IGNORECASE | re.DOTALL)
        if return_match:
            return_clause = return_match.group(1)
            # Replace old_var references in RETURN clause with new_var
            new_return = re.sub(r'\b' + re.escape(old_var) + r'\b', new_var, return_clause)
            if new_return != return_clause:
                result = result[:return_match.start(1)] + new_return

    return result


async def generate_cypher(query: str, rag_svc, domain: Optional[str] = None) -> Union[str, List[Dict[str, str]], None]:
    """
    Generate Cypher from natural language.

    Returns:
    - str: single Cypher query
    - List[Dict]: multiple named queries [{"name": "...", "cypher": "..."}]
    - None: generation failed
    """
    try:
        if domain and domain.strip() and domain.upper() not in ['UNKNOWN', 'ACTIVE DIRECTORY']:
            domain_context = f"Target Domain: {domain.upper()}"
            prompt = CYPHER_GENERATION_PROMPT.format(
                query=query,
                domain=domain.upper(),
                domain_context=domain_context
            )
        else:
            prompt = CYPHER_GENERATION_PROMPT_NO_DOMAIN.format(query=query)

        result = await rag_svc.query_fast_async(prompt)
        cypher = result.get('result', '').strip()

        # Clean up markdown if present
        cypher = re.sub(r'^```(?:cypher)?\s*', '', cypher)
        cypher = re.sub(r'\s*```$', '', cypher)
        cypher = cypher.strip()

        # Validate output is actually Cypher, not attack steps or markdown
        if cypher and not cypher.upper().lstrip().startswith('MATCH'):
            match = re.search(r'(MATCH\s+.+?RETURN\s+.+?)(?:\n|$)', cypher, re.IGNORECASE | re.DOTALL)
            if match:
                cypher = match.group(1).strip()
                logger.info("Extracted Cypher from mixed LLM output")
            else:
                logger.warning(f"LLM returned non-Cypher output: {cypher[:100]}")
                return None

        # Check for multi-statement Cypher (broad queries generate multiple MATCH...RETURN)
        # Split on newline boundaries where a new MATCH starts
        statements = re.split(r'\n(?=MATCH\s)', cypher, flags=re.IGNORECASE)
        statements = [s.strip() for s in statements if s.strip() and s.strip().upper().startswith('MATCH')]

        if len(statements) > 1:
            # Multi-query: name each query based on its content
            named_queries = []
            for stmt in statements:
                stmt = fix_duplicate_path_variables(stmt)
                if 'LIMIT' not in stmt.upper():
                    stmt += ' LIMIT 50'
                name = _infer_query_name(stmt)
                if is_safe_query(stmt):
                    named_queries.append({"name": name, "cypher": stmt})

            if named_queries:
                logger.info(f"Multi-query generated: {len(named_queries)} queries")
                return named_queries

        # Single query
        cypher = fix_duplicate_path_variables(cypher)
        if cypher and 'LIMIT' not in cypher.upper():
            cypher += ' LIMIT 100'

        return cypher if cypher else None
    except Exception as e:
        logger.error(f"Cypher generation error: {e}")
        return None


def _infer_query_name(cypher: str) -> str:
    """Infer a human-readable name from a Cypher query."""
    c = cypher.upper()
    if 'HASSPN' in c or 'SERVICEPRINCIPALNAME' in c:
        return 'Kerberoastable Users'
    if 'DONTREQPREAUTH' in c:
        return 'AS-REP Roastable Accounts'
    if "'-512'" in c or 'DOMAIN ADMINS' in c:
        return 'Domain Admin Members'
    if "'-519'" in c or 'ENTERPRISE ADMINS' in c:
        return 'Enterprise Admin Members'
    if "'-518'" in c or 'SCHEMA ADMINS' in c:
        return 'Schema Admin Members'
    if 'DCSYNC' in c or 'GETCHANGES' in c:
        return 'DCSync Rights'
    if 'UNCONSTRAINEDDELEGATION' in c:
        return 'Unconstrained Delegation'
    if 'ALLOWEDTODELEGATE' in c:
        return 'Constrained Delegation'
    if 'GENERICALL' in c or 'GENERICWRITE' in c or 'WRITEDACL' in c or 'WRITEOWNER' in c:
        return 'ACL Abuse Paths'
    if 'ADMINTO' in c or 'CANRDP' in c or 'CANPSREMOTE' in c:
        return 'Lateral Movement Access'
    if 'HASSESSION' in c:
        return 'Active Sessions'
    if 'READLAPSPASSWORD' in c:
        return 'LAPS Password Access'
    if 'READGMSAPASSWORD' in c:
        return 'gMSA Password Access'
    if 'SQLADMIN' in c:
        return 'SQL Admin Access'
    # Fallback: extract edge types
    edges = re.findall(r':([A-Za-z]+)', cypher)
    edges = [e for e in edges if e not in ('User', 'Group', 'Computer', 'Domain', 'GPO', 'OU')]
    if edges:
        return f'{edges[0]} Relationships'
    return 'Attack Path Query'


# =============================================================================
# QUERY SUGGESTION FOR NON-QUERY INPUTS
# =============================================================================

SUGGEST_QUERY_PROMPT = """The user asked a question that isn't a direct data query.
Generate a relevant Cypher query they can run to explore this topic.

User question: "{query}"

Respond with ONLY a JSON object (no markdown):
{{"suggested_query": "MATCH ... RETURN ... LIMIT 50", "explanation": "Brief explanation of what to do"}}

IMPORTANT: Write queries that work for ANY domain. Do NOT hardcode domain names like "MARVEL.LOCAL" or "CONTOSO.COM".
Use pattern matching or omit domain suffixes when possible.

The explanation should:
1. Acknowledge their question
2. Explain this is a query execution interface
3. Suggest they toggle "Report Format" for attack/remediation details
4. Provide the query they can run"""


async def generate_query_suggestion(query: str, rag_svc) -> tuple[Optional[str], Optional[str]]:
    """Generate a suggested query for non-query inputs, enhanced with GraphRAG intent understanding"""
    try:
        # Use GraphRAG to understand the user's intent if available
        graph_context = ""
        if hasattr(rag_svc, 'graphrag') and rag_svc.graphrag:
            try:
                intent_result = await rag_svc.graphrag.local_query(
                    f"What Active Directory security topics and attack techniques relate to: {query}? "
                    f"What data would help investigate this?"
                )
                if intent_result.get('result'):
                    graph_context = f"\n\nTOPIC CONTEXT (from knowledge graph):\n{intent_result['result'][:800]}"
                    logger.debug("Added GraphRAG intent context for query suggestion")
            except Exception as e:
                logger.debug(f"GraphRAG intent lookup failed: {e}")

        prompt = SUGGEST_QUERY_PROMPT.format(query=query) + graph_context
        result = await rag_svc.query_fast_async(prompt)
        response = result.get('result', '')

        # Extract JSON
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            data = json.loads(json_match.group())
            return data.get('suggested_query'), data.get('explanation')
    except Exception as e:
        logger.warning(f"Query suggestion error: {e}")

    return None, None


# =============================================================================
# RESULT FORMATTING
# =============================================================================

def format_results_as_markdown(results: List[Dict], max_rows: int = 30) -> str:
    """Format results as markdown table"""
    if not results:
        return "No results found."

    headers = list(results[0].keys())
    lines = []

    # Header
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

    # Rows
    for row in results[:max_rows]:
        values = []
        for h in headers:
            val = row.get(h, "")
            if val is None:
                val = "-"
            elif isinstance(val, (dict, list)):
                val = str(val)[:40] + "..." if len(str(val)) > 40 else str(val)
            else:
                val = str(val).replace("|", "\\|")
            values.append(val)
        lines.append("| " + " | ".join(values) + " |")

    if len(results) > max_rows:
        lines.append(f"\n*Showing {max_rows} of {len(results)} results*")

    return "\n".join(lines)


def get_node_type_from_labels(labels: List[str]) -> str:
    """Get node type from Neo4j labels"""
    if not labels:
        return 'Unknown'
    # Filter out 'Base' and return the first meaningful label
    meaningful = [l for l in labels if l != 'Base']
    return meaningful[0] if meaningful else 'Unknown'


def get_risk_level_for_edge(edge_type: str) -> str:
    """Determine risk level based on edge type"""
    critical_edges = ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'DCSync', 'GetChanges', 'GetChangesAll']
    high_edges = ['ForceChangePassword', 'AddMember', 'GenericWrite', 'AllowedToDelegate', 'ReadLAPSPassword']
    medium_edges = ['CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'AdminTo', 'HasSession']

    if edge_type in critical_edges:
        return 'Critical'
    elif edge_type in high_edges:
        return 'High'
    elif edge_type in medium_edges:
        return 'Medium'
    return 'Low'


def get_node_color(node_type: str) -> str:
    """Get color for node type"""
    colors = {
        'User': '#3b82f6',
        'Group': '#22c55e',
        'Computer': '#ef4444',
        'Domain': '#a855f7',
        'GPO': '#f97316',
        'OU': '#ec4899',
    }
    return colors.get(node_type, '#6b7280')


def extract_graph_data(results: List[Dict]) -> Optional[GraphData]:
    """
    Extract graph nodes and edges from raw query results.
    Uses AttackPathGraphExtractor for consistent node ID generation and edge matching.
    """
    if not results:
        return None

    # Debug: Log what we're processing
    logger.debug(f"[extract_graph_data] Processing {len(results)} results")
    if results:
        first_result = results[0]
        logger.debug(f"[extract_graph_data] First result keys: {list(first_result.keys())}")
        for key, value in first_result.items():
            if isinstance(value, dict):
                logger.debug(f"[extract_graph_data] Key '{key}' has dict with keys: {list(value.keys())}")

    # Use the AttackPathGraphExtractor for consistent graph extraction
    extractor = AttackPathGraphExtractor()

    # Wrap raw results in the format expected by the extractor
    # The extractor's _parse_cypher_result handles various path formats
    wrapped_attack_path = {
        'query_info': {
            'name': 'Chat Query',
            'description': 'Results from chat query',
            'attack_type': 'query',
            'priority': 'Medium'
        },
        'results': results,
        'result_count': len(results)
    }

    try:
        # Use the extractor to process the results
        graph_data = extractor.extract_graph_from_attack_paths([wrapped_attack_path], f"chat-{id(results)}")

        nodes_list = graph_data.get('graph', {}).get('nodes', [])
        edges_list = graph_data.get('graph', {}).get('edges', [])

        logger.debug(f"[extract_graph_data] Extractor returned {len(nodes_list)} nodes, {len(edges_list)} edges")

        # Only return graph data if we have edges (paths) - single nodes are better shown as tables
        if not edges_list:
            logger.debug("[extract_graph_data] No edges found, returning None")
            return None

        # Convert to GraphData format expected by the chat response
        return GraphData(
            nodes=[GraphNode(
                id=n['id'],
                label=n.get('label', n.get('name', 'Unknown')),
                name=n.get('name', n.get('label', 'Unknown')),
                type=n.get('type', 'Unknown'),
                color=n.get('color', '#9B9B9B'),
                riskLevel=n.get('riskLevel', 'Medium'),
                inAttackPath=n.get('inAttackPath', True),
                pathIndex=n.get('pathIndex', 0),
                properties=n.get('properties', {})
            ) for n in nodes_list],
            edges=[GraphEdge(
                id=e['id'],
                source=e['source'],
                target=e['target'],
                label=e.get('label', e.get('type', 'RELATED_TO')),
                type=e.get('type', 'RELATED_TO'),
                color=e.get('color', '#757575'),
                riskLevel=e.get('riskLevel', 'Medium'),
                inAttackPath=e.get('inAttackPath', True),
                pathIndex=e.get('pathIndex', 0),
                attack_type=e.get('attack_type', 'unknown'),
                description=e.get('description', ''),
                properties=e.get('properties', {})
            ) for e in edges_list],
            paths=[{
                'id': 'path-1',
                'name': 'Query Results',
                'description': 'Results from chat query',
                'attack_type': 'query',
                'priority': 'medium',
                'risk_level': 'Medium',
                'result_count': len(nodes_list),
                'scenario_number': 1,
                'color': '#58a6ff'
            }]
        )

    except Exception as e:
        logger.error(f"[extract_graph_data] Error using graph extractor: {e}")
        return None


# =============================================================================
# MAIN QUERY ENDPOINT
# =============================================================================

@router.post("/query", response_model=QueryResponse)
async def execute_query(
    request: QueryRequest,
    project_id: str = Query(None)
):
    """
    Execute a query (Cypher or natural language).

    - Raw Cypher: Executed directly
    - Natural language data query: Generates Cypher, then executes
    - Other questions: Suggests a relevant query + points to Report Format
    - Off-topic: Rejected
    """
    query = request.query.strip()
    effective_project_id = request.project_id or project_id

    # Clear log buffer at the start of each new query to prevent showing old logs
    if log_buffer is not None:
        log_buffer.clear()

    logger.info("=" * 60)
    logger.info(f"CHAT QUERY RECEIVED: '{query}'")
    logger.info("=" * 60)

    # Log to terminal viewer
    add_log("INFO", f"📝 Received query: {query[:60]}{'...' if len(query) > 60 else ''}")
    add_log("INFO", f"🔍 Classifying query intent...")

    # Get services
    rag_svc = get_rag_service()
    neo4j_svc = get_neo4j_service()

    # Empty query
    if not query:
        logger.info("REJECTED: Empty query")
        add_log("WARNING", "Query rejected: Empty query")
        return QueryResponse(
            success=False,
            query_type=QueryType.INVALID,
            error="Please enter a Cypher query or describe what data you want to find."
        )

    # Check if completely off-topic
    off_topic = is_off_topic(query)
    logger.info(f"OFF-TOPIC RESULT: {off_topic}")

    if off_topic:
        logger.info(f">>> REJECTING AS OFF-TOPIC: '{query[:50]}...'")
        add_log("WARNING", "Query rejected: Off-topic (not AD security related)")
        return QueryResponse(
            success=False,
            query_type=QueryType.INVALID,
            error="I can only help with Active Directory security analysis. Try asking about users, groups, attack paths, or permissions."
        )

    cypher_to_execute = None
    is_direct_cypher = False

    # Case 1: Raw Cypher query
    if is_raw_cypher(query):
        cypher_to_execute = query
        is_direct_cypher = True
        logger.info(">>> CASE 1: Raw Cypher query")
        add_log("INFO", "📊 Intent: Direct Cypher query")

    # Case 2: Natural language data query
    elif is_data_query(query):
        logger.info(">>> CASE 2: Natural language data query - generating Cypher")
        add_log("INFO", "🗣️ Intent: Natural language data query")
        add_log("INFO", "⚙️ Generating Cypher query...")
        if rag_svc:
            cypher_to_execute = await generate_cypher(query, rag_svc)
            logger.info(f"Generated Cypher: {cypher_to_execute}")
            if cypher_to_execute:
                add_log("SUCCESS", f"Generated Cypher: {cypher_to_execute[:80]}{'...' if len(cypher_to_execute) > 80 else ''}")

        if not cypher_to_execute:
            return QueryResponse(
                success=False,
                query_type=QueryType.INVALID,
                error="Couldn't generate a query. Try being more specific, e.g., 'List all Domain Admins' or 'Find Kerberoastable users'."
            )

    # Case 3: Security question but not a data query (educational, attack, remediation)
    else:
        logger.info(">>> CASE 3: Security question - generating suggestion")
        if rag_svc:
            suggested_cypher, explanation = await generate_query_suggestion(query, rag_svc)

            if suggested_cypher and explanation:
                return QueryResponse(
                    success=True,
                    query_type=QueryType.NATURAL_LANGUAGE,
                    explanation=explanation,
                    suggested_query=suggested_cypher,
                    result_count=0,
                    has_graph=False
                )

        # Fallback suggestion
        return QueryResponse(
            success=True,
            query_type=QueryType.NATURAL_LANGUAGE,
            explanation=f"I execute queries against BloodHound data. For detailed attack techniques and remediation steps, toggle **Report Format** before running a query.\n\nTry running a query like:\n```cypher\nMATCH (n)-[r:WriteDacl]->(m) RETURN n.name, type(r), m.name LIMIT 50\n```",
            suggested_query="MATCH (n)-[r]->(m) WHERE type(r) IN ['WriteDacl', 'GenericAll', 'Owns', 'WriteOwner'] RETURN n.name AS source, type(r) AS relationship, m.name AS target LIMIT 50",
            result_count=0,
            has_graph=False
        )

    # Safety check
    if not is_safe_query(cypher_to_execute):
        add_log("WARNING", "Query rejected: Contains write operations (safety violation)")
        return QueryResponse(
            success=False,
            query_type=QueryType.INVALID,
            error="Query rejected for safety. Only read-only queries (MATCH...RETURN) are allowed."
        )

    # Execute query
    try:
        add_log("INFO", "🚀 Executing Cypher query on Neo4j...")
        results = neo4j_svc.run_cypher_query(cypher_to_execute, project_id=effective_project_id)
        result_count = len(results) if results else 0
        add_log("SUCCESS", f"✅ Query executed: {result_count} results found")

        # Check for graph data
        graph_data = extract_graph_data(results) if results else None
        has_graph = graph_data is not None and len(graph_data.nodes) > 0
        if has_graph:
            add_log("INFO", f"📊 Graph data extracted: {len(graph_data.nodes)} nodes, {len(graph_data.edges)} edges")

        # Generate explanation based on output format
        explanation = None
        understanding = None
        finding = None
        attack_steps = None
        remediation = None

        if request.output_format == ViewMode.REPORT and rag_svc and result_count > 0:
            # Report mode: Generate full finding structure
            add_log("INFO", "📋 Report Format: Generating full security finding...")
            add_log("INFO", "🔬 Analyzing attack techniques...")
            finding = await generate_finding(query, cypher_to_execute, results, rag_svc)
            explanation = f"**{result_count} results found**"
            add_log("SUCCESS", "✅ Security finding generated")
        elif rag_svc and result_count > 0:
            # Normal mode: Generate brief explanation with understanding Q&A, attack/remediation info
            add_log("INFO", "💬 Chat Mode: Generating explanation...")
            add_log("INFO", "🧠 RAG analyzing results...")
            explanation, understanding, attack_steps, remediation = await generate_explanation(
                query, cypher_to_execute, results, rag_svc
            )
            add_log("SUCCESS", "✅ Explanation generated")
        else:
            # No RAG or no results
            explanation = f"**{result_count} results found**" if result_count > 0 else "No results found for this query."
            if result_count == 0:
                add_log("INFO", "ℹ️ No results found for this query")

        add_log("SUCCESS", "🎉 Query complete!")

        return QueryResponse(
            success=True,
            query_type=QueryType.CYPHER if is_direct_cypher else QueryType.NATURAL_LANGUAGE,
            cypher_query=cypher_to_execute,
            results=results,
            result_count=result_count,
            explanation=explanation,
            understanding=understanding,
            attack_steps=attack_steps,
            remediation=remediation,
            finding=finding,
            graph_data=graph_data,
            has_graph=has_graph
        )

    except Exception as e:
        logger.error(f"Query execution error: {e}")
        add_log("ERROR", f"❌ Query execution failed: {str(e)}")
        return QueryResponse(
            success=False,
            query_type=QueryType.CYPHER if is_direct_cypher else QueryType.NATURAL_LANGUAGE,
            cypher_query=cypher_to_execute,
            error=f"Query execution failed: {str(e)}"
        )


# =============================================================================
# EXPLANATION GENERATION (for Normal/Chat Mode)
# Both generate_explanation and generate_finding now use the report pipeline
# generators (rag_generators.py) directly — no standalone prompts needed.
# =============================================================================


async def generate_explanation(
    query: str,
    cypher: str,
    results: List[Dict],
    rag_svc,
    dc_hostname: str = '',
    request_id: str = ''
) -> tuple[str, Optional[List[Dict]], Optional[List[Dict]], Optional[str]]:
    """
    Generate explanation, understanding Q&A, and attack steps for chat mode.

    Uses the same generators as the report pipeline for consistent quality.
    Uses the fast model for observation/QA (speed) and R1 for attack chain (quality).
    """
    try:
        from routers.attack_paths.services.result_converter import (
            _convert_path_result_to_finding,
            _extract_edges_from_results,
            _infer_edges_used_from_query,
        )
        from routers.attack_paths.services.rag_context_builder import build_enriched_rag_context
        from routers.attack_paths.services.rag_generators import (
            generate_observation_rag,
            generate_understanding_qa,
            generate_attack_chain_r1,
        )
        from services.edge_data_service import get_edge_data_service
        import asyncio

        # Convert raw results to standard finding format
        converted = []
        for rec in results:
            finding = _convert_path_result_to_finding(rec, query)
            converted.append(finding)

        if not converted:
            return f"**{len(results)} results found**", None, None, None

        # Extract edges
        edges_used = _extract_edges_from_results(converted)
        if not edges_used or edges_used == ['Unknown']:
            edges_used = _infer_edges_used_from_query(query, cypher)

        # Extract domain and DC hostname
        domain = ''
        for f in converted:
            for field in ['source', 'target']:
                val = f.get(field, '')
                if '@' in val:
                    domain = val.split('@')[-1]
                    break
            if domain:
                break

        # Use passed dc_hostname if available, otherwise derive from results
        if not dc_hostname:
            dc_hostname = f'DC.{domain}' if domain else ''
            for f in converted:
                for field in ['target', 'source']:
                    val = f.get(field, '')
                    ftype = f.get(f'{field}_type', '')
                    if ftype == 'Computer' and val:
                        dc_hostname = val.split('@')[0] if '@' in val else val
                        break
                if dc_hostname and not dc_hostname.startswith('DC.'):
                    break

        sources = list(set(f.get('source', '').split('@')[0] for f in converted if f.get('source')))
        targets = list(set(f.get('target', '').split('@')[0] for f in converted if f.get('target')))

        # Build enriched context (same as report pipeline)
        edge_service = get_edge_data_service()
        finding_context = build_enriched_rag_context(
            query_name=query,
            query_description='',
            domain=domain,
            edges_used=edges_used,
            findings=converted,
            sources=sources[:5],
            targets=targets[:5],
            severity='High',
            edge_service=edge_service,
            dc_hostname=dc_hostname,
        )
        finding_context['t0_target_assets'] = []
        finding_context['environment_analysis'] = {}
        finding_context['is_chain_discovery'] = False

        # Check cancellation before expensive LLM calls
        if is_request_cancelled(request_id):
            logger.info(f"Request {request_id[:8]}... cancelled — skipping LLM generation")
            return f"**Request cancelled**", None, None, None

        # Generate in parallel: observation + QA (fast model), attack chain (R1)
        obs_task = asyncio.to_thread(generate_observation_rag, finding_context, rag_svc)
        qa_task = asyncio.to_thread(generate_understanding_qa, finding_context, rag_svc)
        attack_task = asyncio.to_thread(generate_attack_chain_r1, converted, finding_context, rag_svc)

        observation, understanding, attack_steps = await asyncio.gather(
            obs_task, qa_task, attack_task, return_exceptions=True
        )

        # Handle exceptions gracefully
        explanation = observation if isinstance(observation, str) else f"**{len(results)} results found**"
        if isinstance(understanding, Exception):
            understanding = None
        if isinstance(attack_steps, Exception):
            attack_steps = None

        return explanation, understanding, attack_steps, None

    except Exception as e:
        logger.warning(f"Explanation generation error: {e}", exc_info=True)

    return f"**{len(results)} results found**", None, None, None


# =============================================================================
# FINDING GENERATION (for Report Format)
# Uses the same generators as the report pipeline (rag_generators.py)
# =============================================================================


def fix_finding_tool_names(obj: Any) -> Any:
    """Recursively fix tool name misspellings in a finding object"""
    if isinstance(obj, str):
        return fix_tool_name_spelling(obj)
    elif isinstance(obj, dict):
        return {k: fix_finding_tool_names(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [fix_finding_tool_names(item) for item in obj]
    return obj


async def generate_finding(query: str, cypher: str, results: List[Dict], rag_svc, dc_hostname: str = '', request_id: str = '') -> Optional[Dict]:
    """
    Generate Finding structure for Report Format.

    Uses the same generators as the report pipeline (rag_generators.py) so that
    chat findings have identical quality: correct DC hostnames, OPSEC rules,
    credential placeholders, and technique-specific prompts.
    """
    try:
        from routers.attack_paths.services.result_converter import (
            _convert_path_result_to_finding,
            _extract_edges_from_results,
            _infer_edges_used_from_query,
        )
        from routers.attack_paths.services.rag_context_builder import build_enriched_rag_context
        from routers.attack_paths.services.rag_generators import (
            generate_observation_rag,
            generate_understanding_qa,
            generate_attack_chain_r1,
        )
        from services.edge_data_service import get_edge_data_service
        import asyncio

        # Convert raw Neo4j results to standard finding format
        converted = []
        for rec in results:
            finding = _convert_path_result_to_finding(rec, query)
            converted.append(finding)

        if not converted:
            return None

        # Extract edges from results or infer from cypher
        edges_used = _extract_edges_from_results(converted)
        if not edges_used or edges_used == ['Unknown']:
            edges_used = _infer_edges_used_from_query(query, cypher)

        # Extract domain and DC hostname from results
        domain = ''
        for f in converted:
            for field in ['source', 'target']:
                val = f.get(field, '')
                if '@' in val:
                    domain = val.split('@')[-1]
                    break
            if domain:
                break

        # Use passed dc_hostname if available, otherwise derive from results
        if not dc_hostname:
            dc_hostname = f'DC.{domain}' if domain else ''
            # Try to find actual DC from results (Computer type)
            for f in converted:
                for field in ['target', 'source']:
                    val = f.get(field, '')
                    ftype = f.get(f'{field}_type', '')
                    if ftype == 'Computer' and val:
                        dc_hostname = val.split('@')[0] if '@' in val else val
                        break
                if dc_hostname and not dc_hostname.startswith('DC.'):
                    break

        # Extract sources/targets
        sources = list(set(
            f.get('source', '').split('@')[0]
            for f in converted if f.get('source')
        ))
        targets = list(set(
            f.get('target', '').split('@')[0]
            for f in converted if f.get('target')
        ))

        # Build enriched context (same as report pipeline)
        edge_service = get_edge_data_service()
        finding_context = build_enriched_rag_context(
            query_name=query,
            query_description='',
            domain=domain,
            edges_used=edges_used,
            findings=converted,
            sources=sources[:5],
            targets=targets[:5],
            severity='High',
            edge_service=edge_service,
            dc_hostname=dc_hostname,
        )
        finding_context['t0_target_assets'] = []
        finding_context['environment_analysis'] = {}
        finding_context['is_chain_discovery'] = False

        # Check cancellation before expensive LLM calls
        if is_request_cancelled(request_id):
            logger.info(f"Request {request_id[:8]}... cancelled — skipping finding generation")
            return None

        # Generate all components in parallel (same as report pipeline)
        observation_task = asyncio.to_thread(generate_observation_rag, finding_context, rag_svc)
        qa_task = asyncio.to_thread(generate_understanding_qa, finding_context, rag_svc)
        attack_task = asyncio.to_thread(generate_attack_chain_r1, converted, finding_context, rag_svc)

        observation, understanding, attack_steps = await asyncio.gather(
            observation_task, qa_task, attack_task, return_exceptions=True
        )

        # Handle exceptions
        if isinstance(observation, Exception):
            logger.warning(f"Observation generation failed: {observation}")
            observation = f"Analysis of {domain} identified {len(converted)} instances related to {query}."
        if isinstance(understanding, Exception):
            logger.warning(f"Understanding generation failed: {understanding}")
            understanding = []
        if isinstance(attack_steps, Exception):
            logger.warning(f"Attack chain generation failed: {attack_steps}")
            attack_steps = []

        # Build affected entities
        affected_entities = []
        for f in converted[:10]:
            affected_entities.append({
                'principal': f.get('source', 'Unknown'),
                'type': f.get('source_type', 'Unknown'),
                'target_group': f.get('target', ''),
                'path': f.get('edge_type', ''),
            })

        # Assemble finding in the same structure as the report
        finding = {
            'title': query,
            'severity': 'High',
            'category': finding_context.get('attack_category', 'Privilege Escalation'),
            'attack_complexity': 'Medium',
            'observation': observation,
            'understanding': understanding if isinstance(understanding, list) else [],
            'affected_entities': affected_entities,
            'attack_intro': '',
            'attack_steps': attack_steps if isinstance(attack_steps, list) else [],
            'risk_title': 'Security Impact',
            'risk_description': f'This finding affects {len(converted)} entities in the {domain} domain.',
            'remediation_steps': [],
            'remediation_script': '',
            'references': [],
            'detection': {'event_ids': [], 'indicators_of_compromise': [], 'queries': []},
            'cypher_query': cypher,
            'edges_used': edges_used,
        }

        # Fix tool name misspellings
        finding = fix_finding_tool_names(finding)
        return finding

    except Exception as e:
        logger.warning(f"Finding generation error: {e}", exc_info=True)

    return None


def extract_edges_from_cypher(cypher: str) -> List[str]:
    """Extract edge types from Cypher"""
    if not cypher:
        return []
    matches = re.findall(r'\[:\s*([A-Za-z_|]+)\s*\]', cypher)
    edges = set()
    for m in matches:
        for e in m.split('|'):
            edges.add(e.strip())
    return list(edges)


# =============================================================================
# SUGGESTIONS ENDPOINT
# =============================================================================

@router.get("/suggestions", response_model=SuggestionsResponse)
async def get_suggestions(
    project_id: str = Query(None),
    include_ai: bool = Query(False)
):
    """Get query suggestions based on environment"""
    neo4j_svc = get_neo4j_service()
    rag_svc = get_rag_service()

    # Gather environment context
    ctx = await gather_environment_context(neo4j_svc, project_id)

    # Build suggestions
    suggestions = build_suggestions(ctx)

    # AI suggestions (optional, slower)
    ai_suggestions = []
    if include_ai and rag_svc:
        ai_suggestions = await generate_ai_suggestions(ctx, rag_svc)

    env_summary = f"{ctx.get('total_users', 0)} users, {ctx.get('total_computers', 0)} computers, {ctx.get('total_groups', 0)} groups"

    return SuggestionsResponse(
        suggestions=suggestions,
        ai_suggestions=ai_suggestions,
        environment_summary=env_summary
    )


@router.post("/suggestions", response_model=SuggestionsResponse)
async def post_suggestions(request: SuggestionsRequest):
    """
    Get query suggestions using environment context from frontend.

    This is the local-first version - the frontend gathers Neo4j context
    from the user's local machine and sends it here. This allows the
    backend to generate AI suggestions without needing its own Neo4j instance.
    """
    rag_svc = get_rag_service()

    # Use provided context or empty defaults
    if request.environment_context:
        ctx = {
            'kerberoastable_users': request.environment_context.kerberoastable_users,
            'asrep_roastable_users': request.environment_context.asrep_roastable_users,
            'unconstrained_delegation': request.environment_context.unconstrained_delegation,
            'domain_admins': request.environment_context.domain_admins,
            'total_users': request.environment_context.total_users,
            'total_computers': request.environment_context.total_computers,
            'total_groups': request.environment_context.total_groups,
            'domains': request.environment_context.domains,
            'high_value_targets': request.environment_context.high_value_targets,
        }
        logger.info(f"📋 Suggestions using frontend context: {ctx.get('total_users', 0)} users, {ctx.get('total_computers', 0)} computers")
    else:
        # No context provided - use empty defaults (predefined suggestions only)
        ctx = {
            'kerberoastable_users': [],
            'asrep_roastable_users': [],
            'unconstrained_delegation': [],
            'domain_admins': [],
            'total_users': 0,
            'total_computers': 0,
            'total_groups': 0,
            'domains': [],
            'high_value_targets': [],
        }
        logger.info("📋 Suggestions without context (predefined only)")

    # Build suggestions
    suggestions = build_suggestions(ctx)

    # AI suggestions (optional, slower)
    ai_suggestions = []
    if request.include_ai and rag_svc and ctx.get('total_users', 0) > 0:
        ai_suggestions = await generate_ai_suggestions(ctx, rag_svc)

    env_summary = f"{ctx.get('total_users', 0)} users, {ctx.get('total_computers', 0)} computers, {ctx.get('total_groups', 0)} groups"

    return SuggestionsResponse(
        suggestions=suggestions,
        ai_suggestions=ai_suggestions,
        environment_summary=env_summary
    )


async def gather_environment_context(neo4j_svc: Neo4jService, project_id: Optional[str]) -> Dict[str, Any]:
    """Query Neo4j for environment context"""
    ctx = {
        'kerberoastable_users': [],
        'asrep_roastable_users': [],
        'unconstrained_delegation': [],
        'domain_admins': [],
        'total_users': 0,
        'total_computers': 0,
        'total_groups': 0,
        'domains': [],
        'high_value_targets': [],
    }

    try:
        # Kerberoastable
        kerb = neo4j_svc.run_cypher_query(
            "MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u.name AS name LIMIT 5",
            project_id=project_id
        )
        ctx['kerberoastable_users'] = [r['name'] for r in kerb if r.get('name')]

        # AS-REP
        asrep = neo4j_svc.run_cypher_query(
            "MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u.name AS name LIMIT 5",
            project_id=project_id
        )
        ctx['asrep_roastable_users'] = [r['name'] for r in asrep if r.get('name')]

        # Unconstrained delegation
        ud = neo4j_svc.run_cypher_query(
            "MATCH (c:Computer) WHERE c.unconstraineddelegation = true RETURN c.name AS name LIMIT 5",
            project_id=project_id
        )
        ctx['unconstrained_delegation'] = [r['name'] for r in ud if r.get('name')]

        # Domain Admins
        da = neo4j_svc.run_cypher_query(
            "MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.name =~ '(?i).*DOMAIN ADMINS.*' RETURN DISTINCT u.name AS name LIMIT 5",
            project_id=project_id
        )
        ctx['domain_admins'] = [r['name'] for r in da if r.get('name')]

        # Counts
        counts = neo4j_svc.run_cypher_query(
            "MATCH (u:User) WITH count(u) as users MATCH (c:Computer) WITH users, count(c) as computers MATCH (g:Group) RETURN users, computers, count(g) as groups",
            project_id=project_id
        )
        if counts:
            ctx['total_users'] = counts[0].get('users', 0)
            ctx['total_computers'] = counts[0].get('computers', 0)
            ctx['total_groups'] = counts[0].get('groups', 0)

        # Domains - query all domains for multi-domain detection
        domains = neo4j_svc.run_cypher_query(
            "MATCH (d:Domain) RETURN d.name AS name",
            project_id=project_id
        )
        ctx['domains'] = [r['name'] for r in domains if r.get('name')]
        if len(ctx['domains']) > 1:
            logger.info(f"🌐 Multi-domain environment detected: {ctx['domains']}")

        # High value targets
        hvt = neo4j_svc.run_cypher_query(
            "MATCH (n) WHERE n.highvalue = true RETURN n.name AS name LIMIT 10",
            project_id=project_id
        )
        ctx['high_value_targets'] = [r['name'] for r in hvt if r.get('name')]

    except Exception as e:
        logger.warning(f"Context gathering error: {e}")

    return ctx


def build_suggestions(ctx: Dict[str, Any]) -> List[SuggestedQuery]:
    """Build predefined suggestions"""
    suggestions = [
        SuggestedQuery(
            name="Domain Admins",
            description="List all Domain Admin members",
            cypher="MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.name =~ '(?i).*DOMAIN ADMINS.*' RETURN DISTINCT u.name AS user LIMIT 50",
            category="Privileged Access"
        ),
        SuggestedQuery(
            name="High Value Targets",
            description="Groups marked as high value",
            cypher="MATCH (g:Group) WHERE g.highvalue = true RETURN g.name AS group LIMIT 50",
            category="Privileged Access"
        ),
    ]

    if ctx.get('kerberoastable_users'):
        suggestions.append(SuggestedQuery(
            name="Kerberoastable Users",
            description=f"{len(ctx['kerberoastable_users'])} users with SPNs",
            cypher="MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u.name AS user, u.serviceprincipalnames AS spns LIMIT 50",
            category="Credential Access"
        ))

    if ctx.get('asrep_roastable_users'):
        suggestions.append(SuggestedQuery(
            name="AS-REP Roastable",
            description=f"{len(ctx['asrep_roastable_users'])} users without preauth",
            cypher="MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u.name AS user LIMIT 50",
            category="Credential Access"
        ))

    if ctx.get('unconstrained_delegation'):
        suggestions.append(SuggestedQuery(
            name="Unconstrained Delegation",
            description=f"{len(ctx['unconstrained_delegation'])} systems",
            cypher="MATCH (c:Computer) WHERE c.unconstraineddelegation = true RETURN c.name AS computer LIMIT 50",
            category="Delegation"
        ))

    suggestions.append(SuggestedQuery(
        name="Dangerous Permissions",
        description="GenericAll, WriteDacl, Owns relationships",
        cypher="MATCH (n)-[r]->(m) WHERE type(r) IN ['GenericAll', 'WriteDacl', 'Owns', 'WriteOwner'] RETURN n.name AS source, type(r) AS permission, m.name AS target LIMIT 50",
        category="ACL Abuse"
    ))

    suggestions.append(SuggestedQuery(
        name="Attack Paths to DA",
        description="Shortest paths to Domain Admin",
        cypher="MATCH p=shortestPath((u:User)-[*1..5]->(g:Group)) WHERE g.name =~ '(?i).*DOMAIN ADMINS.*' AND u.enabled = true RETURN p LIMIT 10",
        category="Attack Paths"
    ))

    # =========================================================================
    # TIER 0 SUGGESTIONS - Paths to critical assets
    # =========================================================================
    suggestions.append(SuggestedQuery(
        name="Paths to Tier 0 Assets",
        description="Attack paths to Domain Admins, Enterprise Admins, DCs",
        cypher="MATCH p=shortestPath((u:User)-[*1..5]->(t)) WHERE u.enabled = true AND (t.name =~ '(?i).*DOMAIN ADMINS.*' OR t.name =~ '(?i).*ENTERPRISE ADMINS.*' OR t:Computer AND t.name =~ '(?i).*DC.*') RETURN p LIMIT 15",
        category="Tier 0"
    ))

    suggestions.append(SuggestedQuery(
        name="Tier 0 Assets",
        description="List Domain Admins, Enterprise Admins, KRBTGT, DCs",
        cypher="MATCH (n) WHERE n.name =~ '(?i).*(DOMAIN ADMINS|ENTERPRISE ADMINS|KRBTGT).*' OR (n:Computer AND (n.name =~ '(?i).*DC.*' OR n.objectid ENDS WITH '-1000')) RETURN n.name AS asset, labels(n)[0] AS type LIMIT 50",
        category="Tier 0"
    ))

    suggestions.append(SuggestedQuery(
        name="DCSync Capable",
        description="Principals with DCSync rights (GetChanges)",
        cypher="MATCH (n)-[:GetChanges|GetChangesAll]->(d:Domain) RETURN n.name AS principal, labels(n)[0] AS type LIMIT 50",
        category="Tier 0"
    ))

    suggestions.append(SuggestedQuery(
        name="Paths to Domain Controllers",
        description="Attack paths to domain controller computers",
        cypher="MATCH p=shortestPath((u:User)-[*1..5]->(c:Computer)) WHERE u.enabled = true AND (c.objectid ENDS WITH '-1000' OR c.name =~ '(?i).*DC.*') AND c.name IS NOT NULL RETURN p LIMIT 10",
        category="Tier 0"
    ))

    # =========================================================================
    # MULTI-DOMAIN SUGGESTIONS - Only when multiple domains detected
    # =========================================================================
    domains = ctx.get('domains', [])
    if len(domains) > 1:
        suggestions.append(SuggestedQuery(
            name="Domain Trust Relationships",
            description=f"Trust relationships between {len(domains)} domains",
            cypher="MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain) RETURN d1.name AS trusting_domain, d2.name AS trusted_domain, r.trusttype AS trust_type LIMIT 50",
            category="Cross-Domain"
        ))

        suggestions.append(SuggestedQuery(
            name="Cross-Domain Paths to DA",
            description="Attack paths traversing domain trusts",
            cypher="MATCH p=shortestPath((u:User)-[*1..7]->(g:Group)) WHERE g.name =~ '(?i).*DOMAIN ADMINS.*' AND u.enabled = true AND NOT u.name ENDS WITH '@' + split(g.name, '@')[1] RETURN p LIMIT 10",
            category="Cross-Domain"
        ))

        suggestions.append(SuggestedQuery(
            name="Foreign Group Members",
            description="Users in groups from another domain",
            cypher="MATCH (u:User)-[:MemberOf]->(g:Group) WHERE split(u.name, '@')[1] <> split(g.name, '@')[1] RETURN u.name AS user, g.name AS group LIMIT 50",
            category="Cross-Domain"
        ))

        suggestions.append(SuggestedQuery(
            name="Cross-Domain Admin Rights",
            description="Admin access across domain boundaries",
            cypher="MATCH (u:User)-[:AdminTo]->(c:Computer) WHERE split(u.name, '@')[1] <> split(c.name, '@')[1] RETURN u.name AS admin, c.name AS computer LIMIT 50",
            category="Cross-Domain"
        ))

        suggestions.append(SuggestedQuery(
            name="Kerberoastable Across Trusts",
            description="SPNs accessible via trust relationships",
            cypher="MATCH (d1:Domain)-[:TrustedBy]->(d2:Domain) WITH d2 MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true AND u.name ENDS WITH '@' + d2.name RETURN u.name AS user, u.serviceprincipalnames AS spns LIMIT 50",
            category="Cross-Domain"
        ))

        suggestions.append(SuggestedQuery(
            name="Users with Multi-Domain Access",
            description="Users with permissions across domains",
            cypher="MATCH (u:User)-[r]->(t) WHERE type(r) IN ['GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns', 'AdminTo'] WITH u, collect(DISTINCT split(t.name, '@')[1]) AS target_domains WHERE size(target_domains) > 1 RETURN u.name AS user, target_domains LIMIT 50",
            category="Cross-Domain"
        ))

    return suggestions


async def generate_ai_suggestions(ctx: Dict[str, Any], rag_svc) -> List[SuggestedQuery]:
    """Generate AI-powered suggestions enhanced with GraphRAG attack chain context"""
    suggestions = []

    try:
        context_parts = []
        if ctx.get('total_users'):
            context_parts.append(f"{ctx['total_users']} users")
        if ctx.get('kerberoastable_users'):
            context_parts.append(f"{len(ctx['kerberoastable_users'])} Kerberoastable")
        if ctx.get('domain_admins'):
            context_parts.append(f"DAs: {', '.join(ctx['domain_admins'][:2])}")

        # Add predefined attack chain suggestions based on environment (fast, no API calls)
        if ctx.get('kerberoastable_users'):
            suggestions.append(SuggestedQuery(
                name="Kerberoast Group Membership",
                description="Groups that Kerberoastable users belong to",
                cypher="MATCH (u:User)-[:MemberOf]->(g:Group) WHERE u.hasspn = true AND u.enabled = true RETURN u.name AS user, g.name AS group LIMIT 50",
                category="Attack Chain"
            ))
            # T0 path from Kerberoastable users
            suggestions.append(SuggestedQuery(
                name="Kerberoast to DA Path",
                description="Attack paths from Kerberoastable users to Domain Admins",
                cypher="MATCH p=shortestPath((u:User)-[*1..5]->(g:Group)) WHERE u.hasspn = true AND u.enabled = true AND g.name CONTAINS 'ADMIN' RETURN p LIMIT 10",
                category="Tier 0"
            ))

        if ctx.get('unconstrained_delegation'):
            suggestions.append(SuggestedQuery(
                name="Delegation Sessions",
                description="Sessions on unconstrained delegation systems",
                cypher="MATCH (c:Computer)<-[:HasSession]-(u:User) WHERE c.unconstraineddelegation = true RETURN u.name AS user, c.name AS computer LIMIT 50",
                category="Attack Chain"
            ))

        # Always add a general T0 path query
        suggestions.append(SuggestedQuery(
            name="Paths to High Value",
            description="Any user paths to high-value groups",
            cypher="MATCH p=shortestPath((u:User)-[*1..4]->(g:Group)) WHERE u.enabled = true AND g.highvalue = true RETURN p LIMIT 15",
            category="Tier 0"
        ))

        # Skip GraphRAG for suggestions - too slow (adds 30+ seconds)
        # GraphRAG is still used for explanations and findings where quality matters more than speed
        graph_context = ""

        # Generate additional AI suggestions with enriched context
        prompt = f"""Based on this AD environment, suggest 4 Cypher queries for BloodHound CE.

Environment: {', '.join(context_parts)}
{graph_context}

Generate a MIX of:
1. ONE simple reconnaissance query (users, groups, permissions)
2. ONE lateral movement query (admin rights, sessions)
3. TWO Tier 0 / attack path queries (paths to Domain Admins, DCs, high value targets)

RULES for Cypher queries:
1. Use common edge types: MemberOf, AdminTo, HasSession, GenericAll, WriteDacl, Owns, CanRDP, ForceChangePassword
2. Always include LIMIT (10 for path queries, 50 for list queries)
3. Do NOT use toupper(), split(), or complex string functions
4. Do NOT hardcode domain names
5. For attack paths, use shortestPath with reasonable depth (*1..5)

GOOD T0/attack path examples:
- MATCH p=shortestPath((u:User)-[*1..5]->(g:Group)) WHERE u.enabled = true AND g.highvalue = true RETURN p LIMIT 10
- MATCH (u:User)-[r:GenericAll|WriteDacl|WriteOwner]->(g:Group) WHERE g.highvalue = true RETURN u.name, type(r), g.name LIMIT 50
- MATCH p=shortestPath((u:User)-[*1..4]->(c:Computer)) WHERE u.hasspn = true AND c.unconstraineddelegation = true RETURN p LIMIT 10

GOOD simple examples:
- MATCH (u:User)-[:AdminTo]->(c:Computer) WHERE u.enabled = true RETURN u.name, c.name LIMIT 50
- MATCH (u:User)-[:MemberOf]->(g:Group) WHERE g.highvalue = true RETURN u.name, g.name LIMIT 50

Return JSON array only:
[{{"name": "Short Name", "description": "Brief description", "cypher": "MATCH...", "category": "Category"}}]

Categories to use: "Reconnaissance", "Lateral Movement", "Tier 0 Attack Path", "Privilege Escalation", "ACL Abuse\""""

        result = await rag_svc.query_fast_async(prompt)
        response = result.get('result', '')

        json_match = re.search(r'\[[\s\S]*\]', response)
        if json_match:
            data = json.loads(json_match.group())
            # Add AI-generated suggestions, avoiding duplicates
            existing_names = {s.name for s in suggestions}
            for s in data[:3]:
                if s.get('name') not in existing_names:
                    suggestions.append(SuggestedQuery(**s))

    except Exception as e:
        logger.warning(f"AI suggestions error: {e}")

    return suggestions[:5]  # Limit to 5 total suggestions


# =============================================================================
# LOCAL-FIRST QUERY ENDPOINTS
# =============================================================================

class PrepareQueryRequest(BaseModel):
    query: str
    project_id: Optional[str] = None
    domain: Optional[str] = None  # Actual domain name from user's Neo4j data


class NamedQuery(BaseModel):
    """A single named Cypher query for multi-query responses"""
    name: str
    cypher: str

class PrepareQueryResponse(BaseModel):
    success: bool
    query_type: QueryType
    cypher_query: Optional[str] = None
    cypher_queries: Optional[List[NamedQuery]] = None  # Multi-query: named queries array
    is_safe: bool = True
    suggested_query: Optional[str] = None
    explanation: Optional[str] = None
    error: Optional[str] = None


class FormatResultsRequest(BaseModel):
    query: str
    cypher_query: str
    results: List[Dict[str, Any]]
    output_format: ViewMode = ViewMode.NORMAL
    project_id: Optional[str] = None
    dc_hostname: Optional[str] = None
    request_id: Optional[str] = None


class FormatResultsResponse(BaseModel):
    success: bool
    explanation: Optional[str] = None
    understanding: Optional[List[Dict[str, str]]] = None
    attack_steps: Optional[List[AttackStep]] = None
    remediation: Optional[str] = None
    finding: Optional[Dict[str, Any]] = None
    graph_data: Optional[GraphData] = None
    has_graph: bool = False
    error: Optional[str] = None


@router.post("/prepare-query", response_model=PrepareQueryResponse)
async def prepare_query(request: PrepareQueryRequest):
    """
    Prepare a query for local execution.

    This endpoint classifies the query and generates Cypher if needed,
    but does NOT execute it. The frontend should execute the query
    locally via Electron's Neo4j service.

    Flow:
    1. Frontend sends query text
    2. Backend classifies and generates Cypher (if natural language)
    3. Backend returns Cypher query for local execution
    4. Frontend executes locally via window.neo4j.runQuery()
    5. Frontend sends results to /format-results for explanation
    """
    query = request.query.strip()

    # Clear log buffer
    if log_buffer is not None:
        log_buffer.clear()

    logger.info("=" * 60)
    logger.info(f"PREPARE QUERY: '{query}'")
    logger.info("=" * 60)

    add_log("INFO", f"📝 Preparing query: {query[:60]}{'...' if len(query) > 60 else ''}")

    # Get RAG service for Cypher generation
    rag_svc = get_rag_service()

    # Empty query
    if not query:
        return PrepareQueryResponse(
            success=False,
            query_type=QueryType.INVALID,
            is_safe=False,
            error="Please enter a Cypher query or describe what data you want to find."
        )

    # Check if off-topic
    if is_off_topic(query):
        add_log("WARNING", "Query rejected: Off-topic")
        return PrepareQueryResponse(
            success=False,
            query_type=QueryType.INVALID,
            is_safe=False,
            error="I can only help with Active Directory security analysis. Try asking about users, groups, attack paths, or permissions."
        )

    cypher_to_execute = None
    is_direct_cypher = False

    # Case 1: Raw Cypher query
    if is_raw_cypher(query):
        cypher_to_execute = query
        is_direct_cypher = True
        add_log("INFO", "📊 Intent: Direct Cypher query")

    # Case 2: Natural language data query - generate Cypher
    elif is_data_query(query):
        add_log("INFO", "🗣️ Intent: Natural language data query")
        add_log("INFO", "⚙️ Generating Cypher query...")
        if rag_svc:
            cypher_result = await generate_cypher(query, rag_svc, domain=request.domain)

            # Multi-query response (broad security questions)
            if isinstance(cypher_result, list):
                add_log("SUCCESS", f"Generated {len(cypher_result)} named queries")
                return PrepareQueryResponse(
                    success=True,
                    query_type=QueryType.NATURAL_LANGUAGE,
                    cypher_queries=[NamedQuery(name=q['name'], cypher=q['cypher']) for q in cypher_result],
                    is_safe=True
                )

            # Single query
            cypher_to_execute = cypher_result
            if cypher_to_execute:
                add_log("SUCCESS", f"Generated Cypher: {cypher_to_execute[:80]}{'...' if len(cypher_to_execute) > 80 else ''}")

        if not cypher_to_execute:
            return PrepareQueryResponse(
                success=False,
                query_type=QueryType.INVALID,
                is_safe=False,
                error="Couldn't generate a query. Try being more specific, e.g., 'List all Domain Admins' or 'Find Kerberoastable users'."
            )

    # Case 3: Security question but not a data query - return suggestion
    else:
        add_log("INFO", "💡 Intent: Security question - returning suggestion")
        if rag_svc:
            suggested_cypher, explanation = await generate_query_suggestion(query, rag_svc)
            if suggested_cypher and explanation:
                return PrepareQueryResponse(
                    success=True,
                    query_type=QueryType.SUGGESTION,
                    suggested_query=suggested_cypher,
                    explanation=explanation,
                    is_safe=True
                )

        # Fallback
        return PrepareQueryResponse(
            success=True,
            query_type=QueryType.SUGGESTION,
            explanation="I execute queries against BloodHound data. For detailed attack techniques and remediation steps, toggle **Report Format** before running a query.\n\nTry running a query like:\n```cypher\nMATCH (n)-[r:WriteDacl]->(m) RETURN n.name, type(r), m.name LIMIT 50\n```",
            suggested_query="MATCH (n)-[r]->(m) WHERE type(r) IN ['WriteDacl', 'GenericAll', 'Owns', 'WriteOwner'] RETURN n.name AS source, type(r) AS relationship, m.name AS target LIMIT 50",
            is_safe=True
        )

    # Safety check
    is_safe = is_safe_query(cypher_to_execute)
    if not is_safe:
        add_log("WARNING", "Query contains write operations - marked as unsafe")
        return PrepareQueryResponse(
            success=False,
            query_type=QueryType.INVALID,
            cypher_query=cypher_to_execute,
            is_safe=False,
            error="Query rejected for safety. Only read-only queries (MATCH...RETURN) are allowed."
        )

    add_log("SUCCESS", "✅ Query prepared for local execution")

    return PrepareQueryResponse(
        success=True,
        query_type=QueryType.CYPHER if is_direct_cypher else QueryType.NATURAL_LANGUAGE,
        cypher_query=cypher_to_execute,
        is_safe=True
    )


@router.post("/cancel-request/{request_id}")
async def cancel_request(request_id: str):
    """Cancel an in-flight chat request. Prevents remaining generators from starting."""
    _cancelled_requests[request_id] = time.time()
    add_log("INFO", f"Request {request_id[:8]}... cancelled by user")
    logger.info(f"Request cancelled: {request_id}")
    return {"success": True, "request_id": request_id}


@router.post("/format-results", response_model=FormatResultsResponse)
async def format_results(request: FormatResultsRequest):
    """
    Format query results with RAG-generated explanation.

    This endpoint takes query results executed locally by the frontend
    and generates explanation, understanding, attack steps, etc.

    Flow:
    1. Frontend executed query locally via window.neo4j.runQuery()
    2. Frontend sends results to this endpoint
    3. Backend generates RAG explanation/finding
    4. Frontend displays formatted results
    """
    logger.info("=" * 60)
    logger.info(f"FORMAT RESULTS: {len(request.results)} results")
    logger.info("=" * 60)

    add_log("INFO", f"📊 Formatting {len(request.results)} results...")

    rag_svc = get_rag_service()
    results = request.results
    result_count = len(results)

    # Extract graph data
    graph_data = extract_graph_data(results) if results else None
    has_graph = graph_data is not None and len(graph_data.nodes) > 0
    if has_graph:
        add_log("INFO", f"📊 Graph data extracted: {len(graph_data.nodes)} nodes, {len(graph_data.edges)} edges")

    # Generate explanation based on output format
    explanation = None
    understanding = None
    finding = None
    attack_steps = None
    remediation = None

    try:
        if request.output_format == ViewMode.REPORT and rag_svc and result_count > 0:
            # Report mode: Generate full finding structure
            add_log("INFO", "📋 Report Format: Generating full security finding...")
            finding = await generate_finding(request.query, request.cypher_query, results, rag_svc, dc_hostname=request.dc_hostname or '', request_id=request.request_id or '')
            explanation = f"**{result_count} results found**"
            add_log("SUCCESS", "✅ Security finding generated")
        elif rag_svc and result_count > 0:
            # Normal mode: Generate brief explanation with understanding Q&A
            add_log("INFO", "💬 Chat Mode: Generating explanation...")
            explanation, understanding, attack_steps, remediation = await generate_explanation(
                request.query, request.cypher_query, results, rag_svc, dc_hostname=request.dc_hostname or '', request_id=request.request_id or ''
            )
            add_log("SUCCESS", "✅ Explanation generated")
        else:
            # No RAG or no results
            explanation = f"**{result_count} results found**" if result_count > 0 else "No results found for this query."
            if result_count == 0:
                add_log("INFO", "ℹ️ No results found for this query")

        add_log("SUCCESS", "🎉 Results formatted!")

        return FormatResultsResponse(
            success=True,
            explanation=explanation,
            understanding=understanding,
            attack_steps=attack_steps,
            remediation=remediation,
            finding=finding,
            graph_data=graph_data,
            has_graph=has_graph
        )

    except Exception as e:
        logger.error(f"Format results error: {e}")
        add_log("ERROR", f"❌ Formatting failed: {str(e)}")
        return FormatResultsResponse(
            success=False,
            error=f"Failed to format results: {str(e)}"
        )


# =============================================================================
# HEALTH CHECK
# =============================================================================

@router.get("/health")
async def health_check():
    """Health check"""
    rag_ok = get_rag_service() is not None
    neo4j_ok = False

    try:
        neo4j_svc = get_neo4j_service()
        test = neo4j_svc.test_connection()
        neo4j_ok = test.get('connected', False)
    except:
        pass

    return {
        "status": "healthy" if rag_ok else "degraded",
        "rag_service": "available" if rag_ok else "unavailable",
        "neo4j_service": "available" if neo4j_ok else "unavailable"
    }


# =============================================================================
# LOGS ENDPOINT (for ChatTerminalLogViewer)
# =============================================================================

@router.get("/logs")
async def get_chat_logs(since: int = Query(0, description="Return logs with ID greater than this value")):
    """
    Get logs for real-time streaming to ChatTerminalLogViewer.
    Reuses the same log buffer as attack_paths for unified logging.
    """
    if log_buffer is None:
        return {"logs": [], "last_id": 0, "count": 0}

    logs_list, last_id = log_buffer.get_logs_since(since)
    return {
        "logs": logs_list,
        "last_id": last_id,
        "count": len(logs_list)
    }

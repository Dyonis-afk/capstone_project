"""
Query Generation Services for Attack Path Analysis
Location: backend/routers/attack_paths/services/query_generator.py

Functions for generating Cypher queries:
- Environment analysis for query generation
- Entity extraction from findings
- RAG-based query generation
- Static query assembly
"""

import json
import re
from typing import Dict, Any, List, Optional, Set

from services.rag_service import RAGService

from ..models import FindingsSummary, EnvironmentInfo, GeneratedQuery
from ..state import add_log
from ..constants import EDGE_TYPE_QUERY_TEMPLATES, CORE_STATIC_QUERIES, DISCOVERY_QUERIES, TARGET_DISCOVERY_QUERIES


def _validate_environment_analysis(
    raw_analysis: str,
    rich_summary: Dict[str, Any],
    add_log_fn: callable = None
) -> str:
    """
    Validate RAG-generated environment analysis against actual data.
    Corrects factual errors like "absence of kerberoastable" when kerberoastable users exist.
    """
    if not raw_analysis:
        return raw_analysis

    corrections_made = []

    # Check Kerberoastable users
    kerberoastable_count = len(rich_summary.get('kerberoastable_users', []))
    if kerberoastable_count > 0:
        # Check for false claims about absence
        false_claims = [
            'absence of kerberoastable',
            'no kerberoastable',
            'lack of kerberoastable',
            'without kerberoastable',
            'kerberoastable accounts were not',
            'no service accounts with spns',
        ]
        for claim in false_claims:
            if claim.lower() in raw_analysis.lower():
                # Replace the false claim
                raw_analysis = re.sub(
                    rf'(?i){re.escape(claim)}[^.]*\.',
                    f'{kerberoastable_count} kerberoastable service accounts were identified, representing potential credential theft opportunities.',
                    raw_analysis
                )
                corrections_made.append(f"Corrected false claim about kerberoastable (actual: {kerberoastable_count})")

    # Check DCSync capable principals
    dcsync_count = len(rich_summary.get('dcsync_capable_principals', []))
    if dcsync_count > 0:
        false_claims = [
            'absence of dcsync',
            'no dcsync',
            'no principals with dcsync',
        ]
        for claim in false_claims:
            if claim.lower() in raw_analysis.lower():
                raw_analysis = re.sub(
                    rf'(?i){re.escape(claim)}[^.]*\.',
                    f'{dcsync_count} principals with DCSync capability were identified.',
                    raw_analysis
                )
                corrections_made.append(f"Corrected false claim about DCSync (actual: {dcsync_count})")

    # Remove any SharpHound/BloodHound collection recommendations that slipped through
    sharphound_patterns = [
        r'run sharphound[^.]*\.',
        r'sharphound\.exe[^.]*\.',
        r'bloodhound-python[^.]*\.',
        r'collect.*bloodhound.*data[^.]*\.',
        r'\./sharphound[^.]*\.',
    ]
    for pattern in sharphound_patterns:
        if re.search(pattern, raw_analysis, re.IGNORECASE):
            raw_analysis = re.sub(pattern, '', raw_analysis, flags=re.IGNORECASE)
            corrections_made.append("Removed SharpHound/BloodHound collection recommendation")

    if corrections_made and add_log_fn:
        add_log_fn("INFO", f"🔄 Environment analysis corrections: {', '.join(corrections_made)}")

    return raw_analysis


def extract_entities_from_findings(findings_summary: FindingsSummary) -> Dict[str, Any]:
    """
    Extract actual entity names from ALL BloodHound findings.
    Processes entire dataset for comprehensive coverage.
    """
    entities = {
        'domains': set(),
        'domain_admin_groups': set(),
        'high_value_groups': set(),
        'service_accounts': set(),
        'computers': set(),
        'users': set(),
        'edge_types': set()
    }

    all_findings = findings_summary.high_risk + findings_summary.medium_risk + findings_summary.low_risk

    for finding in all_findings:
        source = finding.get('source', '') or ''
        target = finding.get('target', '') or ''
        edge_type = finding.get('edge_type') or finding.get('edgeType', '')
        source_type = finding.get('source_type', '')
        target_type = finding.get('target_type', '')

        # Extract domains from @domain patterns
        for entity in [source, target]:
            if '@' in entity:
                domain = entity.split('@')[-1]
                if domain and '.' in domain:
                    entities['domains'].add(domain)

        # Track ALL edge types
        if edge_type:
            entities['edge_types'].add(edge_type)

        # Identify Domain Admin groups
        target_upper = target.upper()
        source_upper = source.upper()
        if any(x in target_upper for x in ['DOMAIN ADMIN', 'ENTERPRISE ADMIN', 'SCHEMA ADMIN', 'ADMINISTRATORS@']):
            entities['domain_admin_groups'].add(target)
        if any(x in source_upper for x in ['DOMAIN ADMIN', 'ENTERPRISE ADMIN', 'SCHEMA ADMIN', 'ADMINISTRATORS@']):
            entities['domain_admin_groups'].add(source)

        # Identify high-value groups
        if edge_type in ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'AddMember', 'ForceChangePassword', 'DCSync', 'GetChanges', 'GetChangesAll']:
            if target_type == 'Group' or '@' in target:
                entities['high_value_groups'].add(target)

        if 'ADMIN' in target_upper and target_type == 'Group':
            entities['high_value_groups'].add(target)

        # Identify service accounts
        for entity in [source, target]:
            entity_upper = entity.upper()
            if any(pattern in entity_upper for pattern in ['SVC_', 'SVC-', 'SERVICE', '_SA@', '-SA@',
                                                           'SQLSERVICE', 'IISAPPPOOL', 'KRBTGT',
                                                           'MSOL_', 'AAD_', 'HEALTH', 'EXCHANGE']):
                entities['service_accounts'].add(entity)

        # Collect computers
        if source_type == 'Computer' or source.endswith('$'):
            entities['computers'].add(source.rstrip('$'))
        if target_type == 'Computer' or target.endswith('$'):
            entities['computers'].add(target.rstrip('$'))

        # Collect users
        if source_type == 'User' and '@' in source:
            entities['users'].add(source)
        if target_type == 'User' and '@' in target:
            entities['users'].add(target)

    # Convert sets to sorted lists
    result = {}
    for k, v in entities.items():
        if k == 'edge_types':
            result[k] = sorted(list(v))
        else:
            result[k] = sorted(list(v))[:100]
    return result


def generate_rich_findings_summary(findings_summary: FindingsSummary) -> Dict[str, Any]:
    """
    Generate a comprehensive summary of findings for RAG context.
    """
    all_findings = findings_summary.high_risk + findings_summary.medium_risk + findings_summary.low_risk

    # Edge type distribution
    edge_type_counts: Dict[str, int] = {}
    for finding in all_findings:
        edge_type = finding.get('edge_type') or finding.get('edgeType', 'Unknown')
        edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1

    sorted_edge_types = sorted(edge_type_counts.items(), key=lambda x: x[1], reverse=True)

    # High-value targets
    target_risk_score: Dict[str, int] = {}
    dangerous_edges = {'GenericAll', 'WriteDacl', 'WriteOwner', 'DCSync', 'GetChanges', 'GetChangesAll',
                       'ForceChangePassword', 'AddMember', 'AllExtendedRights', 'Owns'}

    for finding in all_findings:
        edge_type = finding.get('edge_type') or finding.get('edgeType', '')
        target = finding.get('target', '')
        if edge_type in dangerous_edges and target:
            weight = 3 if finding in findings_summary.high_risk else (2 if finding in findings_summary.medium_risk else 1)
            target_risk_score[target] = target_risk_score.get(target, 0) + weight

    top_targets = sorted(target_risk_score.items(), key=lambda x: x[1], reverse=True)[:15]

    # Users with dangerous permissions
    user_attack_potential: Dict[str, List[str]] = {}
    for finding in findings_summary.high_risk:
        source = finding.get('source', '')
        source_type = finding.get('source_type', '')
        edge_type = finding.get('edge_type') or finding.get('edgeType', '')

        if source_type == 'User' and edge_type in dangerous_edges:
            if source not in user_attack_potential:
                user_attack_potential[source] = []
            user_attack_potential[source].append(edge_type)

    top_attackers = sorted(user_attack_potential.items(), key=lambda x: len(x[1]), reverse=True)[:10]

    # Kerberoastable users (HasSPN or Kerberoastable edge)
    kerberoastable_users = set()
    for finding in all_findings:
        edge_type = finding.get('edge_type') or finding.get('edgeType', '')
        source = finding.get('source', '')
        if edge_type in ('HasSPN', 'Kerberoastable', 'HasSPNConfigured'):
            kerberoastable_users.add(source)

    # AS-REP roastable users (DontReqPreAuth / ASREPRoastable)
    asrep_roastable_users = set()
    for finding in all_findings:
        edge_type = finding.get('edge_type') or finding.get('edgeType', '')
        source = finding.get('source', '')
        if edge_type in ('ASREPRoastable', 'DontReqPreAuth'):
            asrep_roastable_users.add(source)

    # DCSync capable
    dcsync_principals = set()
    for finding in all_findings:
        edge_type = finding.get('edge_type') or finding.get('edgeType', '')
        source = finding.get('source', '')
        if edge_type in ['DCSync', 'GetChanges', 'GetChangesAll']:
            dcsync_principals.add(source)

    # Sessions
    sessions_on_computers: Dict[str, List[str]] = {}
    for finding in all_findings:
        edge_type = finding.get('edge_type') or finding.get('edgeType', '')
        if edge_type == 'HasSession':
            user = finding.get('source', '')
            computer = finding.get('target', '')
            if computer not in sessions_on_computers:
                sessions_on_computers[computer] = []
            sessions_on_computers[computer].append(user)

    computers_with_priv_sessions = {
        comp: users for comp, users in sessions_on_computers.items()
        if any('ADMIN' in u.upper() for u in users)
    }

    return {
        "total_findings": len(all_findings),
        "high_risk_count": len(findings_summary.high_risk),
        "medium_risk_count": len(findings_summary.medium_risk),
        "low_risk_count": len(findings_summary.low_risk),
        "edge_type_distribution": dict(sorted_edge_types[:20]),
        "top_attacked_targets": [{"target": t, "risk_score": s} for t, s in top_targets],
        "users_with_dangerous_permissions": [{"user": u, "permissions": p} for u, p in top_attackers],
        "kerberoastable_users": list(kerberoastable_users)[:20],
        "asrep_roastable_users": list(asrep_roastable_users)[:20],
        "dcsync_capable_principals": list(dcsync_principals),
        "computers_with_privileged_sessions": {k: v[:5] for k, v in list(computers_with_priv_sessions.items())[:10]}
    }


def analyze_environment_for_queries(
    findings_summary: FindingsSummary,
    environment_info: Optional[EnvironmentInfo],
    rag_service: RAGService
) -> Dict[str, Any]:
    """Analyze environment context for query generation"""

    env_summary = {}
    domain_info = None  # From BloodHound Domain node (includes functional_level)

    if environment_info:
        env_summary = {
            "domain_names": environment_info.domain_names,
            "domain_admin_groups": environment_info.domain_admin_groups,
            "high_value_groups": environment_info.high_value_groups,
            "service_accounts": environment_info.service_accounts,
            "computers": environment_info.computers
        }
        # Extract domain_info with functional_level from environment_info
        if environment_info.domain_info:
            domain_info = {
                "name": environment_info.domain_info.name,
                "functionalLevel": environment_info.domain_info.functional_level,
                "forest": environment_info.domain_info.forest
            }
            add_log("INFO", f"📊 Domain info from environment: {domain_info.get('name')}, Level: {domain_info.get('functionalLevel')}")

    stats = findings_summary.summary or {}

    # Extract domains from ALL findings
    domains = set()
    if env_summary.get("domain_names"):
        for domain in env_summary["domain_names"]:
            if domain:
                domains.add(domain.upper())

    all_findings = findings_summary.high_risk + findings_summary.medium_risk + findings_summary.low_risk
    for finding in all_findings:
        source = finding.get('source', '')
        target = finding.get('target', '')
        if '@' in source:
            domain = source.split('@')[-1].upper()
            if domain:
                domains.add(domain)
        if '@' in target:
            domain = target.split('@')[-1].upper()
            if domain:
                domains.add(domain)

    env_summary["domain_names"] = list(domains)

    # Graph statistics (from findings_summary.summary) for the model - includes domain_controllers
    graph_stats = {
        "total_nodes": stats.get("total_nodes", 0),
        "total_edges": stats.get("total_edges", 0),
        "total_users": stats.get("total_users", 0),
        "total_groups": stats.get("total_groups", 0),
        "total_computers": stats.get("total_computers", 0),
        "domain_controllers": stats.get("domain_controllers", 0),
        "total_ous": stats.get("total_ous", 0),
        "total_gpos": stats.get("total_gpos", 0),
    }

    add_log("INFO", f"Environment: {len(domains)} domain(s) detected, {len(all_findings)} total findings")

    rich_summary = generate_rich_findings_summary(findings_summary)

    add_log("INFO", f"Rich summary: {rich_summary['total_findings']} total findings, {len(rich_summary['edge_type_distribution'])} edge types")

    environment_query = f"""
Analyze this Active Directory environment from BloodHound data to identify attack paths:

**Environment Summary:**
{json.dumps(env_summary, indent=2)}

**Graph Statistics (BloodHound CE):**
{json.dumps(graph_stats, indent=2)}

**Comprehensive Findings Analysis:**
- Total Findings: {rich_summary['total_findings']}
- High-Risk: {rich_summary['high_risk_count']} | Medium-Risk: {rich_summary['medium_risk_count']} | Low-Risk: {rich_summary['low_risk_count']}

**Edge Type Distribution (Attack Vectors Present):**
{json.dumps(rich_summary['edge_type_distribution'], indent=2)}

**Top Attacked Targets (By Risk Score):**
{json.dumps(rich_summary['top_attacked_targets'][:15], indent=2)}

**Users with Dangerous Permissions:**
{json.dumps(rich_summary['users_with_dangerous_permissions'][:15], indent=2)}

**Kerberoastable Service Accounts:**
{json.dumps(rich_summary['kerberoastable_users'], indent=2)}

**AS-REP Roastable Users (no pre-auth required):**
{json.dumps(rich_summary.get('asrep_roastable_users', []), indent=2)}

**DCSync Capable Principals:**
{json.dumps(rich_summary['dcsync_capable_principals'], indent=2)}

Based on this comprehensive analysis, identify:
1. Domain name(s) and structure
2. Most critical attack paths based on edge type distribution
3. High-value targets that should be prioritized
4. Key attack vectors
5. Service accounts and delegation risks
6. Principals with DCSync capability
7. Credential theft opportunities
8. Overall security posture assessment

IMPORTANT CONSTRAINTS:
- The BloodHound data has ALREADY been collected and imported. DO NOT suggest running SharpHound, BloodHound, or any data collection tools.
- Focus on ANALYZING the existing data, not collecting more.
- DO NOT include commands like "./SharpHound.exe" or "BloodHound-python".
"""

    try:
        add_log("INFO", "RAG analyzing environment context...")
        rag_response = rag_service.query(environment_query)
        add_log("INFO", "RAG environment analysis complete")

        # Validate and correct RAG output against actual data
        raw_analysis = rag_response.get('result', '')
        raw_analysis = _validate_environment_analysis(
            raw_analysis,
            rich_summary,
            add_log
        )

        # Env summary for RAG: include dcsync_principals so _build_available_attack_vectors can use it
        env_summary_for_rag = {**env_summary}
        if rich_summary.get('dcsync_capable_principals'):
            env_summary_for_rag['dcsync_principals'] = rich_summary['dcsync_capable_principals']
        return {
            "raw_analysis": raw_analysis,
            "environment_summary": env_summary_for_rag,
            "bloodhound_stats": stats,
            "domains": list(domains),
            "domain_info": domain_info,  # From BloodHound Domain node (includes functional_level)
            "high_risk_count": len(findings_summary.high_risk),
            "medium_risk_count": len(findings_summary.medium_risk),
            "low_risk_count": len(findings_summary.low_risk),
            "rich_summary": rich_summary,
            "edge_type_distribution": rich_summary['edge_type_distribution'],
            "top_attacked_targets": rich_summary['top_attacked_targets'],
            "kerberoastable_users": rich_summary['kerberoastable_users'],
            "asrep_roastable_users": rich_summary.get('asrep_roastable_users', []),
            "dcsync_capable": rich_summary['dcsync_capable_principals']
        }
    except Exception as e:
        add_log("WARNING", f"RAG environment analysis failed: {e}")
        env_summary_for_rag = {**env_summary}
        if rich_summary.get('dcsync_capable_principals'):
            env_summary_for_rag['dcsync_principals'] = rich_summary['dcsync_capable_principals']
        return {
            "raw_analysis": "",
            "environment_summary": env_summary_for_rag,
            "bloodhound_stats": stats,
            "domains": list(domains),
            "domain_info": domain_info,  # From BloodHound Domain node (includes functional_level)
            "high_risk_count": len(findings_summary.high_risk),
            "medium_risk_count": len(findings_summary.medium_risk),
            "low_risk_count": len(findings_summary.low_risk),
            "rich_summary": rich_summary,
            "edge_type_distribution": rich_summary['edge_type_distribution'],
            "top_attacked_targets": rich_summary['top_attacked_targets'],
            "kerberoastable_users": rich_summary['kerberoastable_users'],
            "asrep_roastable_users": rich_summary.get('asrep_roastable_users', []),
            "dcsync_capable": rich_summary['dcsync_capable_principals']
        }


def generate_cypher_queries_with_rag(
    extracted_entities: Dict[str, Any],
    edge_types: Set[str],
    rag_service: RAGService
) -> List[GeneratedQuery]:
    """
    Generate dynamic Cypher queries using RAG.
    Uses DeepSeek Chat (fast, deterministic at temp 0.0) seeded with actual
    environment entities for targeted query generation.
    """
    queries = []
    edge_list = list(edge_types)[:15]

    add_log("INFO", f"Asking RAG to generate environment-specific Cypher queries...")
    add_log("INFO", f"   Edge types found: {edge_list[:8]}")

    # Build list of ALL discovery query names so the LLM knows exactly what's covered
    static_query_names = [q["name"] for q in DISCOVERY_QUERIES]
    static_names_list = "\n".join(f"  - {name}" for name in static_query_names)

    # Filter noisy entities before sending to LLM
    # These dominate the entity list but add no value for query generation
    NOISY_ENTITY_PATTERNS = {
        'HEALTHMAILBOX', 'DEFAULTACCOUNT', 'GUEST', 'KRBTGT',
        '$', 'MSOL_', 'AAD_', 'SM_', 'SYSTEMMAIL', 'DISCOVERYSEARCH',
        'FEDERATEDEMAIL', 'MIGRATION.',
    }

    def _is_noisy(name: str) -> bool:
        upper = name.upper().split('@')[0]
        return any(p in upper for p in NOISY_ENTITY_PATTERNS) or upper.startswith('$')

    users = sorted(u.split('@')[0] for u in extracted_entities.get('users', set()) if not _is_noisy(u))[:15]
    computers = sorted(c.split('@')[0] for c in extracted_entities.get('computers', set()) if not _is_noisy(c))[:10]
    groups = sorted(g.split('@')[0] for g in extracted_entities.get('high_value_groups', set()) if not _is_noisy(g))[:10]
    service_accounts = sorted(s.split('@')[0] for s in extracted_entities.get('service_accounts', set()) if not _is_noisy(s))[:10]
    domains = sorted(extracted_entities.get('domains', set()))[:3]

    entity_context = ""
    if users:
        entity_context += f"\nUSERS: {', '.join(users)}"
    if computers:
        entity_context += f"\nCOMPUTERS: {', '.join(computers)}"
    if groups:
        entity_context += f"\nHIGH-VALUE GROUPS: {', '.join(groups)}"
    if service_accounts:
        entity_context += f"\nSERVICE ACCOUNTS: {', '.join(service_accounts)}"
    if domains:
        entity_context += f"\nDOMAINS: {', '.join(domains)}"

    add_log("INFO", f"   Entities for RAG: {len(users)} users, {len(computers)} computers, {len(groups)} groups, {len(service_accounts)} svc accounts")

    cypher_generation_prompt = f"""You are a BloodHound CE Cypher query expert. Generate 8-10 Cypher queries targeting attack paths specific to THIS environment.

## ALREADY COVERED BY STATIC QUERIES (do NOT regenerate these):
{static_names_list}
Additionally, dynamic chain discovery runs weighted shortest-path queries between all sources and high-value targets.

## YOUR JOB
Generate queries that find attack paths the static queries MISS. Focus on:
- Multi-hop ACL chains combining 2+ different edge types
- Paths through specific service accounts or Exchange groups
- Group-mediated privilege escalation (User → Group → ACL → Target)
- Paths that cross between different privilege tiers

## THIS ENVIRONMENT
EDGE TYPES PRESENT: {', '.join(edge_list)}
{entity_context}

## CYPHER SYNTAX RULES (MANDATORY — QUERIES WILL FAIL IF VIOLATED)
1. Every query MUST use `MATCH p=` and `RETURN p LIMIT N`
2. ONLY use these edge types: MemberOf, GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, ForceChangePassword, AddMember, AddSelf, AllExtendedRights, AddKeyCredentialLink, WriteSPN, GetChanges, GetChangesAll, AdminTo, CanPSRemote, CanRDP, ExecuteDCOM, SQLAdmin, ReadGMSAPassword, ReadLAPSPassword, AllowedToDelegate, AllowedToAct, HasSession, CoerceToTGT, ManageCA, Enroll, GPLink, Contains, TrustedBy, HasSIDHistory
3. NEVER use property filters in node pattern like `{{hasspn: true}}` or `{{admincount: False}}` — always use WHERE
4. NEVER use `allShortestPaths` or `shortestPath` — use regular MATCH with explicit edge patterns instead
5. NEVER use `[*1..10]` wildcard — always specify explicit edge types in brackets
6. WHERE clause goes AFTER the MATCH pattern closing parenthesis, NEVER inside it
7. For domain admins: `g.objectid ENDS WITH '-512'`
8. For enabled checks: `(u.enabled = true OR u.enabled IS NULL)`
9. Always add T0 source exclusion: `AND NOT u.objectid ENDS WITH '-500' AND NOT u.objectid ENDS WITH '-512' AND NOT u.objectid ENDS WITH '-519'`
10. Max variable-length: `*1..4`

## EXAMPLES (CORRECT — follow these patterns exactly)
Multi-hop group to ACL:
`MATCH p=(u:User)-[:MemberOf*1..3]->(g:Group)-[:WriteDacl]->(d:Domain) WHERE (u.enabled = true OR u.enabled IS NULL) AND NOT u.objectid ENDS WITH '-500' AND NOT u.objectid ENDS WITH '-512' RETURN p LIMIT 50`

Two-edge ACL chain:
`MATCH p=(u:User)-[:AddMember]->(g:Group)-[:GenericAll]->(t:User) WHERE u <> t AND (u.enabled = true OR u.enabled IS NULL) AND NOT u.objectid ENDS WITH '-500' AND NOT u.objectid ENDS WITH '-512' RETURN p LIMIT 50`

Service account path:
`MATCH p=(u:User)-[:MemberOf*1..2]->(g:Group)-[:GetChanges]->(d:Domain) WHERE (u.enabled = true OR u.enabled IS NULL) AND NOT u.objectid ENDS WITH '-500' AND NOT u.objectid ENDS WITH '-512' RETURN p LIMIT 50`

Return ONLY a valid JSON array, no markdown code blocks:
[
  {{
    "name": "Query name",
    "description": "What this query finds",
    "cypher": "MATCH p=... RETURN p LIMIT N",
    "attack_type": "privilege_escalation|credential_access|lateral_movement|persistence",
    "priority": "Critical|High|Medium",
    "edges_used": ["EdgeType1", "EdgeType2"]
  }}
]"""

    try:
        # Use fast model (DeepSeek Chat at temp 0.0) for deterministic query generation
        response = rag_service.query_fast(cypher_generation_prompt)
        raw_result = response.get('result', '')

        add_log("INFO", f"   RAG response length: {len(raw_result)} chars")

        queries = parse_rag_generated_queries(raw_result, extracted_entities)

        if queries:
            add_log("INFO", f"RAG generated {len(queries)} Cypher queries")
        else:
            add_log("WARNING", "RAG did not generate valid queries")

    except Exception as e:
        add_log("ERROR", f"RAG Cypher generation failed: {str(e)}")

    return queries


def normalize_edges_used(cypher: str, name: str, description: str, edges_used: List[str]) -> List[str]:
    """
    Normalize edges_used to use canonical attack type names.

    This ensures that queries about Kerberoasting, AS-REP Roasting, etc.
    use the correct edge type names that match our templates in opsec_templates.py
    and prompt_templates.py.
    """
    cypher_lower = cypher.lower()
    name_lower = name.lower()
    desc_lower = description.lower()
    combined = f"{cypher_lower} {name_lower} {desc_lower}"

    normalized = list(edges_used)  # Copy original

    # Detect Kerberoasting patterns
    kerberoast_indicators = [
        'hasspn' in cypher_lower,
        'kerberoast' in combined,
        'spn' in name_lower and 'service' in name_lower,
        'serviceprincipalname' in cypher_lower,
    ]
    if any(kerberoast_indicators):
        # Ensure Kerberoastable is in edges_used
        if 'Kerberoastable' not in normalized:
            normalized.insert(0, 'Kerberoastable')
        # Remove generic edge types that would override our specific template
        for generic in ['HasSPN', 'MemberOf']:
            if generic in normalized and 'Kerberoastable' in normalized:
                # Keep MemberOf only if it's the only edge (pure group membership query)
                if len([e for e in normalized if e not in ['HasSPN', 'MemberOf']]) > 0:
                    pass  # Keep it, there are other edges

    # Detect AS-REP Roasting patterns
    asrep_indicators = [
        'dontreqpreauth' in cypher_lower,
        'asreproast' in combined,
        'as-rep' in combined,
        'preauth' in combined and 'roast' in combined,
    ]
    if any(asrep_indicators):
        if 'ASREPRoastable' not in normalized:
            normalized.insert(0, 'ASREPRoastable')

    # Detect DCSync patterns
    dcsync_indicators = [
        'dcsync' in combined,
        'getchanges' in cypher_lower,
        'replication' in combined,
    ]
    if any(dcsync_indicators):
        if 'DCSync' not in normalized:
            normalized.insert(0, 'DCSync')

    return normalized


def parse_rag_generated_queries(raw_response: str, extracted_entities: Dict[str, Any]) -> List[GeneratedQuery]:
    """Parse RAG JSON response into GeneratedQuery objects"""
    queries = []

    try:
        cleaned = raw_response.strip()

        # Remove markdown code blocks
        if '```' in cleaned:
            code_match = re.search(r'```(?:json)?\s*([\s\S]*?)```', cleaned)
            if code_match:
                cleaned = code_match.group(1).strip()

        # Find JSON array
        json_match = re.search(r'\[\s*\{[\s\S]*\}\s*\]', cleaned)
        if json_match:
            cleaned = json_match.group(0)

        parsed_queries = json.loads(cleaned)

        if not isinstance(parsed_queries, list):
            add_log("WARNING", "RAG response is not a JSON array")
            return []

        for i, q in enumerate(parsed_queries):
            if not isinstance(q, dict):
                continue

            cypher = q.get('cypher', '')
            if not cypher or 'MATCH' not in cypher.upper():
                continue

            # Validate relationship pattern
            has_relationship = bool(re.search(r'-\[.*?\]->', cypher) or re.search(r'<-\[.*?\]-', cypher) or
                                    re.search(r'-\[.*?\*', cypher) or 'shortestPath' in cypher.lower())
            if not has_relationship:
                continue

            # Validate path pattern
            cypher_upper = cypher.upper()
            has_path_variable = 'MATCH P=' in cypher_upper or 'MATCH P =' in cypher_upper
            returns_path = 'RETURN P' in cypher_upper

            if not has_path_variable or not returns_path:
                # Try to fix
                if 'MATCH (' in cypher and 'MATCH P=' not in cypher_upper:
                    cypher = cypher.replace('MATCH (', 'MATCH p=(', 1)

                if 'RETURN P' not in cypher.upper():
                    limit_match = re.search(r'(LIMIT\s+\d+)', cypher, re.IGNORECASE)
                    limit_clause = limit_match.group(1) if limit_match else 'LIMIT 50'
                    cypher = re.sub(r'RETURN\s+.*$', f'RETURN p {limit_clause}', cypher, flags=re.IGNORECASE)

                if 'RETURN P' not in cypher.upper():
                    continue

            if 'LIMIT' not in cypher.upper():
                cypher = cypher.rstrip().rstrip(';') + '\nLIMIT 25'

            # Get query metadata
            name = q.get('name', f'Attack Query {i+1}')
            description = q.get('description', '')
            raw_edges_used = q.get('edges_used', [])

            # Normalize edges_used to use canonical attack type names
            normalized_edges = normalize_edges_used(cypher, name, description, raw_edges_used)

            query = GeneratedQuery(
                id=f"query_{i}",
                name=name,
                description=description,
                cypher=cypher.strip(),
                attack_type=q.get('attack_type', 'unknown'),
                priority=q.get('priority', 'High'),
                edges_used=normalized_edges
            )
            queries.append(query)

        return queries

    except json.JSONDecodeError as e:
        add_log("ERROR", f"Failed to parse RAG JSON: {str(e)}")
        return []
    except Exception as e:
        add_log("ERROR", f"Query parsing error: {str(e)}")
        return []


MAX_RAG_QUERIES = 8

# Edge types already covered comprehensively by static queries.
# RAG queries using ONLY these edges are likely duplicates even if names differ.
_STATIC_EDGE_SETS = None

def _get_static_edge_sets() -> List[frozenset]:
    """Build a cache of edge-type sets from static queries for dedup."""
    global _STATIC_EDGE_SETS
    if _STATIC_EDGE_SETS is None:
        _STATIC_EDGE_SETS = []
        for sq in DISCOVERY_QUERIES:
            edges = frozenset(e.lower() for e in sq.get("edges_used", []) if e)
            if edges:
                _STATIC_EDGE_SETS.append(edges)
    return _STATIC_EDGE_SETS


def _is_edge_duplicate(rag_edges: List[str]) -> bool:
    """
    Check if a RAG query's edge set is already fully covered by a static query.
    Returns True if any static query uses the exact same edges or a superset.
    """
    if not rag_edges:
        return False
    rag_set = frozenset(e.lower() for e in rag_edges if e)
    if not rag_set:
        return False
    for static_set in _get_static_edge_sets():
        if rag_set == static_set:
            return True
        # Also catch subset: if RAG uses {GenericAll} and static already covers {GenericAll}
        if rag_set.issubset(static_set) and len(rag_set) <= 2:
            return True
    return False


def generate_attack_queries(
    environment_analysis: Dict[str, Any],
    findings_summary: FindingsSummary,
    rag_service: RAGService
) -> List[GeneratedQuery]:
    """
    Generate context-aware Cypher queries for attack path discovery.

    HYBRID APPROACH:
    1. ALWAYS add core static queries (comprehensive baseline)
    2. Add up to MAX_RAG_QUERIES environment-specific RAG queries
    3. Deduplicate RAG queries against static set by fuzzy name matching
    """
    add_log("INFO", "Generating attack queries (HYBRID: Static + RAG)...")

    extracted_entities = extract_entities_from_findings(findings_summary)
    env_summary = environment_analysis.get('environment_summary', {})

    domain_names = extracted_entities['domains'] or env_summary.get('domain_names', [])
    edge_types = set(extracted_entities['edge_types'])

    add_log("INFO", f"Extracted: {len(domain_names)} domains, {len(edge_types)} edge types")

    env_edge_distribution = environment_analysis.get('edge_type_distribution', {})
    if env_edge_distribution:
        edge_types = edge_types.union(set(env_edge_distribution.keys()))

    queries = []
    existing_names = set()
    query_id = 0

    # Add discovery queries (property-based + service detection)
    # Chain discovery handles path-based queries dynamically
    add_log("INFO", "Adding discovery queries (property-based + service detection)...")

    for static_query in DISCOVERY_QUERIES:
        query = GeneratedQuery(
            id=f"static_{query_id}",
            name=static_query["name"],
            description=static_query["description"],
            cypher=static_query["cypher"],
            attack_type=static_query["attack_type"],
            priority=static_query["priority"],
            edges_used=static_query["edges_used"]
        )
        queries.append(query)
        existing_names.add(static_query["name"].lower())
        query_id += 1

    # Add target discovery queries (for chain discovery)
    for tq in TARGET_DISCOVERY_QUERIES:
        query = GeneratedQuery(
            id=f"target_{query_id}",
            name=tq["name"],
            description=tq["description"],
            cypher=tq["cypher"],
            attack_type="target_discovery",
            priority="High",
            edges_used=[]
        )
        queries.append(query)
        existing_names.add(tq["name"].lower())
        query_id += 1

    add_log("INFO", f"Added {len(queries)} queries ({len(DISCOVERY_QUERIES)} discovery + {len(TARGET_DISCOVERY_QUERIES)} target discovery)")

    # Add RAG-generated environment-specific queries (capped independently of static count)
    if rag_service:
        try:
            add_log("INFO", "Generating RAG-based environment-specific queries...")
            rag_queries = generate_cypher_queries_with_rag(
                extracted_entities=extracted_entities,
                edge_types=edge_types,
                rag_service=rag_service
            )

            if rag_queries:
                add_log("INFO", f"RAG generated {len(rag_queries)} queries")

                rag_added = 0
                rag_skipped_name = 0
                rag_skipped_edge = 0
                for rq in rag_queries:
                    if rag_added >= MAX_RAG_QUERIES:
                        break

                    if rq.name.lower() in existing_names:
                        rag_skipped_name += 1
                        continue

                    # Layer 1: fuzzy name dedup
                    is_name_dup = False
                    for existing in existing_names:
                        rq_words = set(rq.name.lower().split())
                        existing_words = set(existing.split())
                        if len(rq_words & existing_words) / max(len(rq_words), 1) > 0.6:
                            is_name_dup = True
                            break

                    if is_name_dup:
                        rag_skipped_name += 1
                        continue

                    # Layer 2: edge-type dedup (catches same-intent queries with different names)
                    if _is_edge_duplicate(rq.edges_used):
                        rag_skipped_edge += 1
                        continue

                    rq.id = f"rag_{rag_added}"
                    queries.append(rq)
                    existing_names.add(rq.name.lower())
                    rag_added += 1

                add_log("INFO", f"Added {rag_added} unique RAG queries (skipped: {rag_skipped_name} name-dup, {rag_skipped_edge} edge-dup)")

        except Exception as e:
            add_log("WARNING", f"RAG query generation failed: {str(e)}")

    discovery_count = len(DISCOVERY_QUERIES) + len(TARGET_DISCOVERY_QUERIES)
    rag_count = len(queries) - discovery_count
    add_log("INFO", f"HYBRID QUERY SUMMARY: {discovery_count} discovery + {rag_count} RAG = {len(queries)} total")

    return queries

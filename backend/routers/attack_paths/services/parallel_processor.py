"""
Parallel Processing Functions for Attack Path Analysis
Location: backend/routers/attack_paths/services/parallel_processor.py

Enables concurrent RAG calls for faster report generation.
- Level 1: Parallel within findings (observation, understanding, attack_steps, risk in parallel)
- Level 2: Parallel across findings (multiple findings processed concurrently)
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional

from models.tier0_models import Tier0Config
from services.edge_data_service import get_edge_data_service

from ..constants import get_opsec_attack_steps, extract_dc_hostname
from ..constants.priority import get_attack_complexity, get_primary_category, determine_severity
from ..state import add_log, update_progress
from ..utils import extract_section, format_results_for_rag, build_affected_entities

from .obfuscation_helpers import apply_obfuscation_to_attack_steps
from .structured_data import (
    get_remediation_from_structured_data,
    get_detection_from_structured_data,
    get_references_from_structured_data,
)
from .rag_context_builder import build_enriched_rag_context
from .rag_generators import (
    generate_observation_rag,
    generate_understanding_qa,
    generate_attack_chain_r1,
    generate_risk_description_rag,
)

logger = logging.getLogger(__name__)



# =============================================================================
# DYNAMIC ATTACK INTRO GENERATION
# =============================================================================

def generate_attack_intro(query_name: str, edges_used: List[str], category: str, targets: List[str]) -> str:
    """
    Generate a finding-specific attack intro based on the attack type and edges.
    Avoids the generic hardcoded intro that doesn't match the finding context.
    """
    edges_lower = {e.lower() for e in edges_used}
    query_lower = query_name.lower()

    # Kerberoasting attacks
    if 'kerberoast' in query_lower or 'hasspn' in query_lower:
        return "An attacker can request service tickets (TGS) for these accounts and attempt offline password cracking:"

    # AS-REP Roasting attacks
    if 'asrep' in query_lower or 'dontreqpreauth' in query_lower:
        return "An attacker can request encrypted AS-REP responses without authentication and crack them offline:"

    # DCSync attacks
    if 'dcsync' in edges_lower or 'getchanges' in edges_lower:
        return "An attacker with these privileges can perform DCSync to extract all domain password hashes:"

    # ACL abuse (GenericAll, WriteDacl, etc.)
    acl_edges = {'genericall', 'genericwrite', 'writedacl', 'writeowner', 'forcechangepassword'}
    if edges_lower & acl_edges:
        return "An attacker can abuse these misconfigured ACL permissions to escalate privileges:"

    # Delegation attacks
    if 'delegation' in query_lower or 'trustedtoauth' in query_lower:
        return "An attacker can abuse these delegation configurations to impersonate privileged users:"

    # AdminTo / Local Admin paths
    if 'adminto' in edges_lower or 'localadmin' in query_lower:
        return "An attacker can leverage these local administrator rights to move laterally:"

    # Group-mediated paths
    if 'group' in query_lower or 'memberof' in edges_lower:
        return "An attacker can exploit these group membership chains to reach privileged targets:"

    # MSSQL attacks
    if 'mssql' in query_lower or 'sqladmin' in edges_lower:
        return "An attacker can abuse SQL Server access to execute commands or harvest credentials:"

    # ADCS attacks
    if 'adcs' in query_lower or 'esc' in query_lower:
        return "An attacker can exploit these certificate template misconfigurations to obtain privileged certificates:"

    # Session-based attacks
    if 'session' in query_lower or 'hassession' in edges_lower:
        return "An attacker can target these active sessions to harvest credentials or hijack tokens:"

    # GPO abuse
    if 'gpo' in query_lower or 'gpoabuse' in edges_lower:
        return "An attacker can modify these Group Policy Objects to execute code on affected systems:"

    # Coercion attacks
    if 'coerce' in query_lower:
        target_str = targets[0] if targets else "target systems"
        return f"An attacker can coerce authentication from {target_str} to capture or relay credentials:"

    # Default fallback - use category for context
    category_intros = {
        'Credential Access': "An attacker can harvest or crack credentials using:",
        'Privilege Escalation': "An attacker can escalate privileges through:",
        'Lateral Movement': "An attacker can move laterally using:",
        'Persistence': "An attacker can establish persistence via:",
    }

    return category_intros.get(category, "An attacker with domain access could exploit these paths:")


def _parse_rag_content_to_steps(rag_content: str) -> List[str]:
    """
    Parse RAG-generated remediation/detection content into a list of steps.
    The RAG content is typically bullet points or numbered lists with entity-specific details.
    """
    import re

    if not rag_content:
        return []

    steps = []

    # Split on common list markers (-, *, 1., 2., etc.) but preserve content
    lines = rag_content.strip().split('\n')
    current_step = ""

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Check if line starts with list marker
        list_match = re.match(r'^[-*•]\s*(.+)$', line)
        num_match = re.match(r'^\d+[.)]\s*(.+)$', line)

        if list_match:
            if current_step:
                steps.append(current_step.strip())
            current_step = list_match.group(1)
        elif num_match:
            if current_step:
                steps.append(current_step.strip())
            current_step = num_match.group(1)
        elif current_step:
            # Continuation of previous step
            current_step += " " + line
        else:
            # First non-list line becomes a step
            current_step = line

    # Don't forget the last step
    if current_step:
        steps.append(current_step.strip())

    # If no structured list found, try splitting by sentences
    if not steps and rag_content:
        # Split on sentence boundaries
        sentences = re.split(r'(?<=[.!?])\s+', rag_content.strip())
        steps = [s.strip() for s in sentences if s.strip() and len(s.strip()) > 20]

    # Limit to reasonable number of steps
    return steps[:8] if steps else []


# =============================================================================
# ASYNC WRAPPERS FOR RAG GENERATORS
# =============================================================================

async def _generate_observation_rag_async(finding_context: Dict, rag_service, add_log_fn=None) -> str:
    """Async wrapper for observation generation - runs in thread pool."""
    return await asyncio.to_thread(
        generate_observation_rag,
        finding_context,
        rag_service,
        add_log_fn
    )


async def _generate_understanding_qa_async(finding_context: Dict, rag_service, add_log_fn=None) -> List[Dict]:
    """Async wrapper for understanding Q&A generation - runs in thread pool."""
    return await asyncio.to_thread(
        generate_understanding_qa,
        finding_context,
        rag_service,
        add_log_fn
    )


async def _generate_attack_chain_r1_async(
    findings: List[Dict[str, Any]],
    finding_context: Dict,
    rag_service,
    add_log_fn=None,
    live_graph_data: str = ""
) -> List[Dict]:
    """Async wrapper for attack chain generation - runs in thread pool."""
    return await asyncio.to_thread(
        generate_attack_chain_r1,
        findings,
        finding_context,
        rag_service,
        add_log_fn,
        live_graph_data
    )


async def _generate_risk_description_rag_async(finding_context: Dict, rag_service, add_log_fn=None) -> str:
    """Async wrapper for risk description generation - runs in thread pool."""
    return await asyncio.to_thread(
        generate_risk_description_rag,
        finding_context,
        rag_service,
        add_log_fn
    )


# =============================================================================
# PARALLEL PENTEST FINDING GENERATION
# =============================================================================

async def generate_pentest_finding_parallel(
    query_info: Dict[str, Any],
    findings: List[Dict[str, Any]],
    finding_number: int,
    rag_service=None,
    add_log_fn: callable = None,
    tier0_config: Optional[Tier0Config] = None,
    live_graph_data: str = "",
    environment_analysis: Dict[str, Any] = None,
    dc_hostname: str = None
) -> Dict[str, Any]:
    """
    Generate a single pentest-style finding with PARALLEL LLM calls.

    This is the async version that runs observation, understanding, attack_steps,
    and risk_description generation concurrently using asyncio.gather().

    Args:
        live_graph_data: Pre-fetched context data string from client-side Neo4j queries
        dc_hostname: Optional DC hostname (e.g., 'DC01.SEQUEL.HTB') from Neo4j query

    Performance improvement: ~2x faster per finding (17s -> 8s typical)
    """
    query_name = query_info.get('name', 'Unknown Query')
    query_description = query_info.get('description', '')
    cypher_query = query_info.get('cypher_query', query_info.get('cypher', ''))
    attack_type = query_info.get('attack_type', 'Unknown')

    # Get edge data service for structured data
    edge_service = get_edge_data_service()

    # Use edges_used from query_info first (from EDGE_TYPE_QUERY_TEMPLATES)
    # This ensures Kerberoastable, ASREPRoastable, etc. are correctly identified
    # Only fall back to extracting from findings if edges_used is not defined
    edges_used = query_info.get('edges_used', [])
    if not edges_used:
        # Fall back to extracting edge types from findings
        edges_used = list(set(f.get('edge_type', '') for f in findings if isinstance(f, dict) and f.get('edge_type')))

    # Determine severity and category
    severity = determine_severity(findings, edges_used)
    category = get_primary_category(edges_used)
    complexity = get_attack_complexity(edges_used)

    # Build affected entities list
    affected_entities = build_affected_entities(findings)

    # Extract context - PRIORITY: environment_analysis > findings > empty (never use placeholder)
    domain = ""
    sources = []
    targets = []
    source_types = []
    target_types = []

    # Priority 1: Get domain from environment_analysis (most reliable)
    if environment_analysis:
        domains = environment_analysis.get('domains', [])
        if domains:
            domain = domains[0]
        elif environment_analysis.get('domain_info', {}).get('name'):
            domain = environment_analysis['domain_info']['name']

    # Priority 2: Extract from findings (both source AND target)
    for f in findings:
        if not isinstance(f, dict):
            continue
        s = f.get('source', '')
        t = f.get('target', '')
        s_type = f.get('source_type', '')
        t_type = f.get('target_type', '')

        # Extract domain from source
        if '@' in s:
            if not domain:
                domain = s.split('@')[-1]
            sources.append(s.split('@')[0])
        elif s:
            sources.append(s)
        # Extract domain from target (if source didn't have it)
        if '@' in t:
            if not domain:
                domain = t.split('@')[-1]
            targets.append(t.split('@')[0])
        elif t:
            targets.append(t)

        # Collect entity types for context-aware remediation
        if s_type:
            source_types.append(s_type)
        if t_type:
            target_types.append(t_type)

    sources = list(set(sources))[:5]
    targets = list(set(targets))[:5]
    source_types = list(set(source_types))[:3]
    target_types = list(set(target_types))[:3]
    # NOTE: Never use placeholder like 'TARGET.LOCAL' - empty string is safer than fake domain

    # Extract computer names, SPNs, and all names for DC hostname detection
    computers = []
    spns = []
    all_names = []

    for f in findings:
        if not isinstance(f, dict):
            continue
        source = f.get('source', '')
        target = f.get('target', '')

        # Collect all names (could contain DC patterns like "$DC01")
        if source:
            all_names.append(source)
        if target:
            all_names.append(target)

        # Check source type for computers
        if f.get('source_type', '').upper() == 'COMPUTER':
            computers.append(source)
        # Check target type for computers
        if f.get('target_type', '').upper() == 'COMPUTER':
            computers.append(target)

        # Extract SPNs from source/target properties (BloodHound CE stores SPNs here)
        source_props = f.get('source_properties', {})
        target_props = f.get('target_properties', {})

        if source_props.get('serviceprincipalnames'):
            spn_list = source_props['serviceprincipalnames']
            if isinstance(spn_list, list):
                spns.extend(spn_list)
            elif isinstance(spn_list, str):
                spns.append(spn_list)

        if target_props.get('serviceprincipalnames'):
            spn_list = target_props['serviceprincipalnames']
            if isinstance(spn_list, list):
                spns.extend(spn_list)
            elif isinstance(spn_list, str):
                spns.append(spn_list)

    computers = list(set(computers))
    spns = list(set(spns))
    all_names = list(set(all_names))

    # Use DC hostname from parameter (Neo4j query) if provided, otherwise extract from findings
    if not dc_hostname:
        dc_hostname = extract_dc_hostname(domain, computers, spns, all_names)

    # Build ENRICHED context for RAG (using EdgeDataService for accurate edge data)
    finding_context = build_enriched_rag_context(
        query_name=query_name,
        query_description=query_description,
        domain=domain,
        edges_used=edges_used,
        findings=findings,
        sources=sources,
        targets=targets,
        severity=severity,
        edge_service=edge_service,
        dc_hostname=dc_hostname
    )

    # T0-AWARE ENRICHMENT (targets only -- used by executive summary for [T0 TARGET] markers)
    t0_target_assets = []
    targets_t0 = False

    # BUILT-IN T0 DETECTION RULES (apply regardless of tier0_config)
    # These are universally T0 assets in Active Directory
    DCSYNC_EDGES = {'dcsync', 'getchanges', 'getchangesall', 'getchangesinfilteredset'}
    DC_PATTERNS = {'DC', 'DC0', 'DC1', 'DC2', 'DC3', 'DC01', 'DC02', 'PDC', 'BDC'}

    edges_lower = {e.lower() for e in edges_used}
    has_dcsync_edge = bool(edges_lower & DCSYNC_EDGES)

    # Check each finding for built-in T0 targets
    for f in findings:
        if not isinstance(f, dict):
            continue
        target = f.get('target', '')
        target_type = f.get('target_type', '').upper()
        target_name = target.split('@')[0].upper() if '@' in target else target.upper()

        is_builtin_t0 = False
        reason = ""

        # Rule 1: KRBTGT is always T0
        if 'KRBTGT' in target_name:
            is_builtin_t0 = True
            reason = "KRBTGT account"

        # Rule 2: Domain object is always T0
        elif target_type == 'DOMAIN':
            is_builtin_t0 = True
            reason = "Domain object"

        # Rule 3: DCSync/GetChanges edges target T0 by definition
        elif has_dcsync_edge:
            is_builtin_t0 = True
            reason = "DCSync target"

        # Rule 4: DC computer accounts (pattern matching)
        elif target_type == 'COMPUTER':
            # Check if computer name matches DC patterns
            target_base = target_name.rstrip('$')  # Remove trailing $ for comparison
            if any(target_base == pat or target_base.startswith(pat) for pat in DC_PATTERNS):
                is_builtin_t0 = True
                reason = "Domain Controller"

        # Rule 5: CoerceToTGT queries targeting DCs
        if 'COERCE' in query_name.upper() and target_type == 'COMPUTER':
            # CoerceToTGT targets are typically DCs
            target_base = target_name.rstrip('$')
            if any(target_base == pat or target_base.startswith(pat) for pat in DC_PATTERNS):
                is_builtin_t0 = True
                reason = "DC (CoerceToTGT target)"

        if is_builtin_t0:
            clean_target = target.split('@')[0] if '@' in target else target
            if clean_target not in t0_target_assets:
                t0_target_assets.append(clean_target)
                if add_log_fn:
                    add_log_fn("INFO", f"  🛡️ Built-in T0 detected: {clean_target} ({reason})", debug_only=True)

    # Also check user-configured T0 assets
    if tier0_config and tier0_config.enabled:
        for target in targets:
            full_target = f"{target}@{domain}" if '@' not in target else target
            if tier0_config.is_t0_asset(full_target) or tier0_config.is_t0_asset(target):
                if target not in t0_target_assets:
                    t0_target_assets.append(target)

    targets_t0 = len(t0_target_assets) > 0

    # Set context fields
    finding_context['t0_enabled'] = (tier0_config and tier0_config.enabled) or targets_t0
    finding_context['t0_target_assets'] = t0_target_assets
    finding_context['targets_t0'] = targets_t0

    if t0_target_assets and add_log_fn:
        add_log_fn("INFO", f"  🛡️ T0 targets: {', '.join(t0_target_assets)}", debug_only=True)

    # Add environment analysis for attack vector context
    if environment_analysis:
        finding_context['environment_analysis'] = environment_analysis

    # Pass consolidation metadata so LLM knows to give more depth
    consolidated_from = query_info.get('consolidated_from', [])
    if consolidated_from and len(consolidated_from) > 1:
        finding_context['consolidated_from'] = consolidated_from
        finding_context['consolidated_count'] = len(consolidated_from)

    # Pass chain discovery metadata into finding_context so RAG generators
    # can correctly attribute edges to intermediate nodes (not just entry points)
    if query_info.get('is_chain_discovery'):
        finding_context['is_chain_discovery'] = True
        finding_context['chain_rag_context'] = query_info.get('rag_context', '')
        finding_context['chain_data'] = query_info.get('chain_data', {})

        # For chain discoveries, identify the entry point and rights holder
        # but do NOT reorder sources — the chain-specific prompt handles attribution.
        # Reordering sources confused the observation generator (it thought the rights
        # holder was the primary vulnerable entity instead of the entry point).
        if findings:
            first_finding = findings[0]
            intermediate = first_finding.get('intermediate_nodes', [])
            path_edges = first_finding.get('path_edges', [])
            if intermediate and path_edges and len(path_edges) > 1:
                rights_holder = intermediate[-1].split('@')[0] if '@' in intermediate[-1] else intermediate[-1]
                entry_point = sources[0] if sources else ''
                finding_context['chain_entry_point'] = entry_point
                finding_context['chain_rights_holder'] = rights_holder
                if add_log_fn:
                    add_log_fn("DEBUG", f"  Chain context: entry_point={entry_point}, rights_holder={rights_holder}", debug_only=True)

    # STRUCTURED DATA (fast, no LLM) - now context-aware
    remediation_steps, remediation_script = get_remediation_from_structured_data(
        edges_used=edges_used,
        edge_service=edge_service,
        sources=sources,
        targets=targets,
        domain=domain,
        source_types=source_types,
        target_types=target_types,
        query_name=query_name
    )

    detection_data = get_detection_from_structured_data(
        edges_used=edges_used,
        edge_service=edge_service,
        query_name=query_name
    )

    references = get_references_from_structured_data(
        edges_used=edges_used,
        edge_service=edge_service,
        query_name=query_name
    )

    # RAG/R1 CONTENT - RUN IN PARALLEL
    observation = ""
    understanding = []
    risk_description = ""
    attack_steps = []

    if rag_service:
        try:
            if add_log_fn:
                add_log_fn("INFO", f"  🚀 Generating AI content in parallel for finding {finding_number}...", debug_only=True)

            results = await asyncio.gather(
                _generate_observation_rag_async(finding_context, rag_service, add_log_fn),
                _generate_understanding_qa_async(finding_context, rag_service, add_log_fn),
                _generate_attack_chain_r1_async(findings, finding_context, rag_service, add_log_fn, live_graph_data),
                _generate_risk_description_rag_async(finding_context, rag_service, add_log_fn),
                return_exceptions=True  # Don't fail all if one fails
            )

            # Unpack results, handling any exceptions
            observation_result, understanding_result, attack_steps_result, risk_result = results

            # Handle observation
            if isinstance(observation_result, Exception):
                if add_log_fn:
                    add_log_fn("WARNING", f"  ⚠️ Observation generation failed: {observation_result}", debug_only=True)
                observation = f"During analysis of {domain}, {len(findings)} instances of {query_name} were identified."
            else:
                observation = observation_result

            # Handle understanding
            if isinstance(understanding_result, Exception):
                if add_log_fn:
                    add_log_fn("WARNING", f"  ⚠️ Understanding Q&A generation failed: {understanding_result}", debug_only=True)
                primary_edge = edges_used[0] if edges_used else 'this relationship'
                understanding = [
                    {'question': f'What is {query_name}?', 'answer': f'This finding involves {primary_edge} relationships that could be exploited.'},
                    {'question': 'Why is it dangerous?', 'answer': 'It enables attackers to escalate privileges or move laterally.'},
                    {'question': 'How does it apply here?', 'answer': f'In {domain}, affected principals have exploitable relationships.'}
                ]
            else:
                understanding = understanding_result

            # Handle attack steps
            if isinstance(attack_steps_result, Exception):
                if add_log_fn:
                    add_log_fn("WARNING", f"  ⚠️ Attack chain generation failed: {attack_steps_result}", debug_only=True)
                attack_steps = get_opsec_attack_steps(
                    edge_type=edges_used[0] if edges_used else 'Unknown',
                    domain=domain,
                    source=sources[0] if sources else '<user>',
                    target=targets[0] if targets else '<target>',
                    dc_hostname=dc_hostname,
                    computers=computers,
                    spns=spns
                )
            else:
                attack_steps = attack_steps_result

            # Handle risk description
            if isinstance(risk_result, Exception):
                if add_log_fn:
                    add_log_fn("WARNING", f"  ⚠️ Risk description generation failed: {risk_result}", debug_only=True)
                risk_description = f"This {severity.lower()} severity finding involves {', '.join(edges_used)} relationships that could be exploited by attackers."
            else:
                risk_description = risk_result

        except Exception as e:
            if add_log_fn:
                add_log_fn("WARNING", f"⚠️ Parallel AI content generation failed: {e}")
            # Use minimal fallbacks
            primary_edge = edges_used[0] if edges_used else 'Unknown'
            observation = f"During analysis of {domain}, {len(findings)} instances of {query_name} were identified."
            understanding = [
                {'question': f'What is {query_name}?', 'answer': f'This finding involves {primary_edge} relationships that could be exploited.'},
                {'question': 'Why is it dangerous?', 'answer': 'It enables attackers to escalate privileges or move laterally.'},
                {'question': 'How does it apply here?', 'answer': f'In {domain}, affected principals have exploitable relationships.'}
            ]
            attack_steps = get_opsec_attack_steps(
                edge_type=primary_edge,
                domain=domain,
                source=sources[0] if sources else '<user>',
                target=targets[0] if targets else '<target>',
                dc_hostname=dc_hostname,
                computers=computers,
                spns=spns
            )
            risk_description = f"This {severity.lower()} severity finding involves {', '.join(edges_used)} relationships."
    else:
        # No RAG service - use minimal fallbacks
        primary_edge = edges_used[0] if edges_used else 'Unknown'
        observation = f"During analysis of {domain}, {len(findings)} instances of {query_name} were identified."
        understanding = [
            {'question': f'What is {query_name}?', 'answer': f'This finding involves {primary_edge} relationships that could be exploited.'},
            {'question': 'Why is it dangerous?', 'answer': 'It enables attackers to escalate privileges or move laterally.'},
            {'question': 'How does it apply here?', 'answer': f'In {domain}, affected principals have exploitable relationships.'}
        ]
        attack_steps = get_opsec_attack_steps(
            edge_type=primary_edge,
            domain=domain,
            source=sources[0] if sources else '<user>',
            target=targets[0] if targets else '<target>',
            dc_hostname=dc_hostname,
            computers=computers
        )
        risk_description = f"This {severity.lower()} severity finding involves {', '.join(edges_used)} relationships."

    # Apply obfuscation to PowerShell commands in attack steps
    attack_steps = apply_obfuscation_to_attack_steps(attack_steps, obfuscation_level="medium")

    # Calculate hop_count from path data
    hop_count = 1  # Default
    for f in findings:
        if not isinstance(f, dict):
            continue
        path_len = f.get('path_length', 0)
        if path_len and path_len > hop_count:
            hop_count = path_len

    # Build the complete finding
    attack_intro = generate_attack_intro(query_name, edges_used, category, targets)
    risk_title = f"{severity} Business Impact"

    finding = {
        'finding_number': finding_number,
        'severity': severity,
        'title': query_name,
        'attack_complexity': complexity,
        'category': category,
        'hop_count': hop_count,  # Number of steps in attack path (for sorting)
        'observation': observation,
        'understanding': understanding,
        'affected_entities': affected_entities,
        'attack_steps': attack_steps,
        'attack_intro': attack_intro,
        'cypher_query': cypher_query,
        'edges_used': edges_used,
        'risk_title': risk_title,
        'risk_description': risk_description,
        'remediation_steps': remediation_steps,
        'remediation_script': remediation_script,
        'references': references,
        'detection': detection_data or {
            'event_ids': [],
            'indicators_of_compromise': [],
            'proactive_measures': [],
            'queries': []
        },
        'targets_t0': targets_t0,
        't0_target_assets': t0_target_assets
    }

    return finding


async def process_scenario_parallel(
    scenario: Dict[str, Any],
    idx: int,
    total_scenarios: int,
    rag_service,
    analysis_id: Optional[str],
    tier0_config: Optional[Tier0Config],
    semaphore: asyncio.Semaphore,
    finding_context_map: Optional[Dict[int, str]] = None,
    environment_analysis: Dict[str, Any] = None,
    dc_hostname: str = None
) -> Dict[str, Any]:
    """
    Process a single attack scenario with parallel LLM calls.

    This function handles:
    1. Initial RAG query for scenario analysis (path overview, technical analysis, etc.)
    2. Parallel pentest finding generation

    Args:
        finding_context_map: Dict mapping finding_index -> pre-fetched live graph data string
        dc_hostname: Optional DC hostname (e.g., 'DC01.SEQUEL.HTB') from Neo4j query

    Uses semaphore to control concurrency across scenarios.
    """
    async with semaphore:
        try:
            query_info = scenario.get('query_info', {})
            results = scenario.get('results', [])
            query_name = query_info.get('name', 'Unknown')
            attack_type = query_info.get('attack_type', 'unknown')

            if not results:
                add_log("INFO", f"⏭️ [{idx+1}/{total_scenarios}] Skipping {query_name} - no results", debug_only=True)
                return None

            add_log("INFO", f"🔍 [{idx+1}/{total_scenarios}] Processing: {query_name}")

            # Extract entity information (same as original)
            source_entities = []
            target_entities = []
            relationship_types = set()
            sample_entities = []

            for r in results[:10]:
                if not isinstance(r, dict):
                    continue
                if r.get('source'):
                    source_entities.append(str(r['source']))
                if r.get('target'):
                    target_entities.append(str(r['target']))
                if r.get('edge_type'):
                    relationship_types.add(str(r['edge_type']))
                elif r.get('rel_type'):
                    relationship_types.add(str(r['rel_type']))
                for key in ['principal', 'user', 'source', 'computer', 'name', 'target']:
                    if key in r and r[key]:
                        sample_entities.append(str(r[key]))
                        break

            primary_entity = source_entities[0] if source_entities else (sample_entities[0] if sample_entities else "TARGET_ENTITY")
            secondary_entity = target_entities[0] if target_entities else (sample_entities[1] if len(sample_entities) > 1 else "SECONDARY_TARGET")

            edges_used = query_info.get('edges_used', [])
            if not edges_used and relationship_types:
                edges_used = list(relationship_types)

            # Build tool context
            tool_context = "Use appropriate tools (Mimikatz, Rubeus, PowerView, Impacket)"

            # Get domain
            domain = ""
            for entity in (source_entities + target_entities)[:5]:
                if '@' in entity:
                    domain = entity.split('@')[-1]
                    break

            # Build scenario prompt (same as original)
            scenario_prompt = f"""
You are analyzing a BloodHound attack path. Provide a comprehensive, environment-specific security assessment.

FORMATTING RULES:
- Use ## for section headers only
- Do NOT use **bold** markers in your response - use plain text instead
- Use ``` code blocks for commands and scripts
- Use numbered lists (1. 2. 3.) for steps
- Use dashes (-) for bullet points

## Environment Context
- Domain: {domain or 'Target Domain'}
- Source Entities Found: {', '.join(source_entities[:5]) if source_entities else primary_entity}
- Target Entities Found: {', '.join(target_entities[:5]) if target_entities else secondary_entity}

## Attack Path Details
- Attack Query: {query_name}
- Attack Type: {attack_type}
- Priority: {query_info.get('priority', 'High')}
- Edge Types: {', '.join(edges_used) if edges_used else 'Various'}

## Relevant Attack Techniques & Tools
{tool_context}

## Query Results ({len(results)} affected entities)
{format_results_for_rag(results)}

---

Provide your analysis using these EXACT section headers:

## Path Overview
Brief description of the attack path (2-3 sentences).

## Technical Analysis
Explain the AD misconfiguration enabling this attack (2-3 sentences).

## Remediation Strategy
High-level remediation approach (2-3 bullet points).

## Detection Methods
Key detection strategies (2-3 bullet points).
"""

            # Run scenario RAG query in thread
            rag_response = await asyncio.to_thread(
                rag_service.query,
                scenario_prompt
            )
            analysis_text = rag_response.get('result', '')

            # Parse into sections (removed dead fields: attack_scenario, mitre_mapping)
            path_overview = extract_section(analysis_text, "Path Overview")
            technical_analysis = extract_section(analysis_text, "Technical Analysis")
            rag_remediation = extract_section(analysis_text, "Remediation Strategy")
            detection_methods = extract_section(analysis_text, "Detection Methods")

            # Build analyzed scenario
            analyzed_scenario = {
                **scenario,
                "path_overview": path_overview,
                "technical_analysis": technical_analysis,
                "detection_methods": detection_methods,
                "remediation_strategy": rag_remediation,
                "raw_analysis": analysis_text,
                "query_info": query_info,
                "cypher_query": query_info.get('cypher_query') or query_info.get('cypher') or scenario.get('cypher_query', ''),
                "results": results,
                "result_count": len(results)
            }

            # Generate pentest finding in parallel
            if results and len(results) >= 1:
                try:
                    # Look up pre-fetched context for this finding
                    finding_live_data = (finding_context_map or {}).get(idx, "")

                    pentest_finding = await generate_pentest_finding_parallel(
                        query_info=query_info,
                        findings=results,
                        finding_number=idx + 1,
                        rag_service=rag_service,
                        add_log_fn=add_log,
                        tier0_config=tier0_config,
                        live_graph_data=finding_live_data,
                        environment_analysis=environment_analysis,
                        dc_hostname=dc_hostname
                    )

                    # ENHANCEMENT: Use path-level RAG content to improve structured fields
                    # The RAG content is entity-specific and better than generic structured data
                    if rag_remediation:
                        # Parse RAG remediation into bullet points for remediation_steps
                        rag_steps = _parse_rag_content_to_steps(rag_remediation)
                        if rag_steps:
                            pentest_finding['remediation_steps'] = rag_steps

                    if detection_methods:
                        # Enhance detection with RAG-generated content
                        if pentest_finding.get('detection'):
                            pentest_finding['detection']['detection_guidance'] = detection_methods
                        else:
                            pentest_finding['detection'] = {'detection_guidance': detection_methods}

                    analyzed_scenario['pentest_finding'] = pentest_finding
                    add_log("INFO", f"✅ [{idx+1}/{total_scenarios}] {query_name}: {pentest_finding.get('severity')} - {pentest_finding.get('category')}")
                except Exception as pf_error:
                    add_log("WARNING", f"⚠️ [{idx+1}/{total_scenarios}] Finding generation failed: {pf_error}")
                    analyzed_scenario['pentest_finding'] = None
            else:
                analyzed_scenario['pentest_finding'] = None

            return analyzed_scenario

        except Exception as e:
            add_log("ERROR", f"❌ [{idx+1}/{total_scenarios}] Failed to process scenario: {e}")
            return {
                **scenario,
                "path_overview": "Analysis unavailable",
                "technical_analysis": "",
                "remediation_strategy": "",
                "detection_methods": "",
                "raw_analysis": "",
                "error": str(e)
            }


async def analyze_attack_scenarios_parallel(
    attack_scenarios: List[Dict[str, Any]],
    environment_analysis: Dict[str, Any],
    findings_summary,
    rag_service,
    analysis_id: Optional[str] = None,
    tier0_config: Optional[Tier0Config] = None,
    max_concurrent: int = 3,
    finding_context_map: Optional[Dict[int, str]] = None,
    dc_hostname: str = None
) -> List[Dict[str, Any]]:
    """
    Analyze attack scenarios with PARALLEL processing.

    This is the async version that:
    - Processes multiple scenarios concurrently (Level 2 parallelization)
    - Each scenario's LLM calls run in parallel (Level 1 parallelization)
    - Uses semaphore to limit concurrent scenarios (default: 3)

    Args:
        finding_context_map: Dict mapping finding_index -> pre-fetched live graph data string
        dc_hostname: Optional DC hostname (e.g., 'DC01.SEQUEL.HTB') from Neo4j query

    Performance improvement:
    - Sequential: 10 findings x 17s = 170s
    - Parallel: ceil(10/3) x 8s = 32s (~5x faster)
    """
    total_scenarios = len(attack_scenarios)
    add_log("INFO", f"🚀 Starting PARALLEL analysis of {total_scenarios} scenarios (max {max_concurrent} concurrent)...")
    if dc_hostname:
        add_log("INFO", f"🖥️ Using DC hostname: {dc_hostname}")

    # Semaphore to control concurrent scenario processing
    semaphore = asyncio.Semaphore(max_concurrent)

    # Create tasks for all scenarios
    tasks = [
        process_scenario_parallel(
            scenario=scenario,
            idx=idx,
            total_scenarios=total_scenarios,
            rag_service=rag_service,
            analysis_id=analysis_id,
            tier0_config=tier0_config,
            semaphore=semaphore,
            finding_context_map=finding_context_map,
            environment_analysis=environment_analysis,
            dc_hostname=dc_hostname
        )
        for idx, scenario in enumerate(attack_scenarios)
    ]

    # Update progress
    if analysis_id:
        update_progress(
            analysis_id,
            "parallel_analysis",
            35,
            f"Processing {total_scenarios} scenarios in parallel..."
        )

    # Run all tasks concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out None results and exceptions, preserve order
    analyzed_paths = []
    for idx, result in enumerate(results):
        if isinstance(result, Exception):
            add_log("ERROR", f"❌ Scenario {idx+1} failed with exception: {result}")
            # Add error placeholder
            analyzed_paths.append({
                "path_overview": "Analysis failed",
                "error": str(result)
            })
        elif result is not None:
            analyzed_paths.append(result)

    add_log("INFO", f"✅ Parallel analysis complete: {len(analyzed_paths)} paths analyzed")
    return analyzed_paths

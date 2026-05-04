"""
Report Assembly Functions for Attack Path Analysis
Location: backend/routers/attack_paths/services/report_assembler.py

Assembles the final comprehensive report with executive summary and recommendations.
"""

import json
import re
import uuid
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

from services.graph_extractor import AttackPathGraphExtractor
from models.tier0_models import Tier0Config

from ..state import add_log
from ..models import FindingsSummary, QueryResult
from ..constants.edge_templates import AMSI_BYPASS_TECHNIQUES
from .rag_generators import validate_remediation_targets
from .deduplicator import Deduplicator, Finding
from .validation_layer import ValidationLayer, ValidationResult
from .amsi_injector import AMSIInjector

logger = logging.getLogger(__name__)


# =============================================================================
# ATTACK CHAIN SYNTHESIS - O(n) algorithm to detect connected findings
# =============================================================================

# Edge types that indicate exploitation (high value for chaining)
EXPLOITATION_EDGES = {
    'GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDacl', 'Owns',
    'ForceChangePassword', 'AddMember', 'AddSelf', 'AllExtendedRights',
    'DCSync', 'GetChanges', 'GetChangesAll', 'GetChangesInFilteredSet',
    'ReadLAPSPassword', 'ReadGMSAPassword', 'AddKeyCredentialLink',
    'WriteSPN', 'AddAllowedToAct', 'WriteAccountRestrictions',
    'SQLAdmin', 'CanPSRemote', 'CanRDP', 'ExecuteDCOM',
    'HasSession', 'AdminTo', 'CoerceToTGT',
    # ADCS edges
    'ADCSESC1', 'ADCSESC2', 'ADCSESC3', 'ADCSESC4', 'ADCSESC5',
    'ADCSESC6', 'ADCSESC7', 'ADCSESC8', 'ADCSESC9', 'ADCSESC10',
    'ADCSESC13', 'ManageCA', 'ManageCertificates', 'Enroll', 'AutoEnroll',
    # Credential access
    'Kerberoastable', 'ASREPRoastable', 'HasSPN', 'DontReqPreAuth',
}

# Edge types that are informational only (low value for chaining)
INFORMATIONAL_EDGES = {'MemberOf', 'Contains', 'GPLink', 'TrustedBy'}

# Built-in/common groups that create noise when used as chain links
NOISY_LINK_ENTITIES = {
    'DOMAIN USERS', 'DOMAIN COMPUTERS', 'DOMAIN ADMINS', 'ENTERPRISE ADMINS',
    'ADMINISTRATORS', 'ACCOUNT OPERATORS', 'BACKUP OPERATORS', 'PRINT OPERATORS',
    'SERVER OPERATORS', 'AUTHENTICATED USERS', 'EVERYONE', 'USERS',
    'KEY ADMINS', 'ENTERPRISE KEY ADMINS', 'CERT PUBLISHERS',
    'SCHEMA ADMINS', 'GROUP POLICY CREATOR OWNERS', 'DNSADMINS',
    'RAS AND IAS SERVERS', 'ALLOWED RODC PASSWORD REPLICATION GROUP',
    'DENIED RODC PASSWORD REPLICATION GROUP', 'READ-ONLY DOMAIN CONTROLLERS',
    'ENTERPRISE READ-ONLY DOMAIN CONTROLLERS', 'CLONEABLE DOMAIN CONTROLLERS',
    'PROTECTED USERS', 'DCS', 'DOMAIN CONTROLLERS',
}


# =============================================================================
# AMSI APPENDIX GENERATION
# =============================================================================

def generate_amsi_appendix(used_families: set = None) -> Dict[str, Any]:
    """
    Generate AMSI bypass appendix for the report.

    Args:
        used_families: Optional set of bypass families to include.
                      If None, includes all techniques.

    Returns:
        Dictionary with appendix structure for report JSON.
    """
    techniques = []

    for key, bypass in AMSI_BYPASS_TECHNIQUES.items():
        family = bypass.get('family', 'reflection')

        # Filter by used families if specified
        if used_families and family not in used_families:
            continue

        techniques.append({
            'name': bypass['name'],
            'family': family,
            'description': bypass.get('description', ''),
            'code': bypass['code'],
        })

    # Sort by family for consistent ordering
    techniques.sort(key=lambda t: t['family'])

    return {
        'title': 'AMSI Bypass Reference',
        'description': 'Run one of these bypasses in your PowerShell session before loading offensive tools. Choose a technique that matches your target environment.',
        'techniques': techniques,
    }


def _get_edge_weight(edge_type: str) -> float:
    """Get weight for an edge type. Higher = more valuable for chaining."""
    edge_upper = edge_type.upper() if edge_type else ''

    # DCSync and ADCS are highest value
    if 'DCSYNC' in edge_upper or 'GETCHANGES' in edge_upper:
        return 1.0
    if 'ADCSESC' in edge_upper or 'MANAGECA' in edge_upper:
        return 0.95

    # Direct exploitation edges
    for exp_edge in EXPLOITATION_EDGES:
        if exp_edge.upper() in edge_upper:
            return 0.8

    # Credential access
    if 'KERBEROAST' in edge_upper or 'ASREPROAST' in edge_upper:
        return 0.7
    if 'GMSA' in edge_upper or 'LAPS' in edge_upper:
        return 0.75

    # Informational edges (low weight)
    for inf_edge in INFORMATIONAL_EDGES:
        if inf_edge.upper() in edge_upper:
            return 0.2

    return 0.5  # Default


def _get_entity_specificity(entity: str) -> float:
    """Get specificity score for an entity. Higher = more specific/valuable."""
    entity_upper = entity.upper() if entity else ''

    # Built-in groups are low specificity (appear in many findings)
    if entity_upper in NOISY_LINK_ENTITIES:
        return 0.1

    # Domain controllers
    if entity_upper.startswith('DC') or 'DOMAIN CONTROLLER' in entity_upper:
        return 0.4

    # Service accounts (valuable targets)
    if '_SVC' in entity_upper or 'SVC_' in entity_upper or '$' in entity_upper:
        return 0.8

    # Named users/specific entities
    if '.' in entity_upper or '_' in entity_upper:
        return 0.9

    # Groups ending in common suffixes
    if entity_upper.endswith('S') and len(entity_upper) > 5:
        return 0.5  # Likely a group

    return 0.7  # Default for specific entities


def synthesize_attack_chains(paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Synthesize attack chains by identifying findings where A's target == B's source.

    IMPROVED VERSION with:
    1. Semantic matching (group membership awareness)
    2. MemberOf-only chain filtering
    3. Full result checking (not just first 5)
    4. Confidence scoring based on edge types and entity specificity
    5. Low-confidence chain filtering

    Args:
        paths: List of analyzed paths with pentest_finding data

    Returns:
        Same paths list with chain_info added to findings that are part of chains
    """
    if not paths:
        return paths

    from collections import defaultdict

    # Step 1: Extract ALL unique source/target entities from each finding - O(n)
    # Maps normalized entity name -> list of finding info
    source_index = defaultdict(list)
    target_index = defaultdict(list)
    finding_edges = {}  # scenario_num -> primary edge type

    for path in paths:
        scenario_num = path.get('scenario_number', 0)
        pf = path.get('pentest_finding', {})
        if not isinstance(pf, dict):
            continue

        edges = path.get('query_info', {}).get('edges_used', [])
        primary_edge = edges[0] if edges else pf.get('category', 'Unknown')
        finding_edges[scenario_num] = primary_edge

        # Check ALL results (not just first 5) for unique entities
        results = path.get('results', [])
        seen_sources = set()
        seen_targets = set()

        for result in results:  # Check ALL results
            if not isinstance(result, dict):
                continue
            src = result.get('source', '')
            target = result.get('target', '')
            edge_type = result.get('edge_type', primary_edge)

            if src:
                src_normalized = src.upper().split('@')[0]
                if src_normalized not in seen_sources:
                    seen_sources.add(src_normalized)
                    source_index[src_normalized].append({
                        'scenario_number': scenario_num,
                        'edge_type': edge_type or primary_edge,
                        'title': pf.get('title', ''),
                        'original_entity': src
                    })

            if target:
                target_normalized = target.upper().split('@')[0]
                if target_normalized not in seen_targets:
                    seen_targets.add(target_normalized)
                    target_index[target_normalized].append({
                        'scenario_number': scenario_num,
                        'edge_type': edge_type or primary_edge,
                        'title': pf.get('title', ''),
                        'original_entity': target
                    })

    # Step 2: Find chain connections with confidence scoring - O(n)
    chain_links = []  # List of (from, to, link_entity, confidence)

    for path in paths:
        scenario_num = path.get('scenario_number', 0)
        from_edge = finding_edges.get(scenario_num, 'Unknown')
        results = path.get('results', [])

        seen_links = set()  # Avoid duplicate links from same finding

        for result in results:
            if not isinstance(result, dict):
                continue
            target = result.get('target', '')
            if not target:
                continue

            target_normalized = target.upper().split('@')[0]

            # Skip noisy link entities unless edge is high-value
            if target_normalized in NOISY_LINK_ENTITIES:
                if _get_edge_weight(from_edge) < 0.7:
                    continue

            # Check if this target is a source in another finding
            if target_normalized in source_index:
                for next_finding in source_index[target_normalized]:
                    to_num = next_finding['scenario_number']
                    if to_num == scenario_num:
                        continue

                    link_key = (scenario_num, to_num)
                    if link_key in seen_links:
                        continue
                    seen_links.add(link_key)

                    to_edge = next_finding['edge_type']

                    # Calculate confidence score
                    from_weight = _get_edge_weight(from_edge)
                    to_weight = _get_edge_weight(to_edge)
                    entity_spec = _get_entity_specificity(target_normalized)

                    # Penalize MemberOf→MemberOf chains heavily
                    if 'MEMBEROF' in from_edge.upper() and 'MEMBEROF' in to_edge.upper():
                        confidence = 0.1  # Very low confidence
                    else:
                        # Combined confidence: edge weights + entity specificity
                        confidence = (from_weight * 0.3 + to_weight * 0.4 + entity_spec * 0.3)

                    chain_links.append({
                        'from': scenario_num,
                        'to': to_num,
                        'link_entity': target_normalized,
                        'confidence': confidence,
                        'from_edge': from_edge,
                        'to_edge': to_edge
                    })

    # Step 3: Filter and sort links by confidence - O(n log n)
    if not chain_links:
        add_log("INFO", "🔗 No attack chains detected")
        return paths

    # Sort by confidence (highest first)
    chain_links.sort(key=lambda x: x['confidence'], reverse=True)

    # Filter low-confidence links (threshold: 0.3)
    MIN_CONFIDENCE = 0.3
    high_conf_links = [l for l in chain_links if l['confidence'] >= MIN_CONFIDENCE]

    if not high_conf_links:
        add_log("INFO", f"🔗 {len(chain_links)} potential links found but all below confidence threshold")
        return paths

    add_log("INFO", f"🔗 {len(high_conf_links)} high-confidence links (of {len(chain_links)} total)")

    # Step 4: Build chains from high-confidence links - O(n)
    # Build adjacency list (prefer higher confidence links)
    next_finding = {}  # scenario_num -> (next_num, confidence, link_entity)
    prev_finding = {}  # scenario_num -> prev_num

    for link in high_conf_links:
        from_num = link['from']
        to_num = link['to']
        conf = link['confidence']

        # Only keep highest confidence link from each finding
        if from_num not in next_finding or next_finding[from_num][1] < conf:
            next_finding[from_num] = (to_num, conf, link['link_entity'])

        if to_num not in prev_finding:
            prev_finding[to_num] = from_num

    # Find chain starts (findings with no predecessor in our filtered links)
    all_from = set(next_finding.keys())
    all_to = set(n[0] for n in next_finding.values())
    chain_starts = all_from - set(prev_finding.keys())

    # If no clear starts, use findings that only appear as 'from'
    if not chain_starts:
        chain_starts = all_from - all_to

    # Build complete chains with confidence tracking
    chains = []
    used_findings = set()

    for start in sorted(chain_starts):  # Sort for deterministic order
        if start in used_findings:
            continue

        chain = [start]
        chain_confidence = []
        current = start
        visited = {start}

        while current in next_finding:
            next_num, conf, link_entity = next_finding[current]
            if next_num in visited:  # Avoid cycles
                break
            chain.append(next_num)
            chain_confidence.append(conf)
            visited.add(next_num)
            current = next_num

        if len(chain) >= 2:  # Only count chains with 2+ findings
            avg_confidence = sum(chain_confidence) / len(chain_confidence) if chain_confidence else 0
            chains.append({
                'findings': chain,
                'avg_confidence': avg_confidence,
                'link_count': len(chain_confidence)
            })
            used_findings.update(chain)

    if not chains:
        add_log("INFO", "🔗 No complete attack chains found after filtering")
        return paths

    # Sort chains by average confidence
    chains.sort(key=lambda x: x['avg_confidence'], reverse=True)

    add_log("INFO", f"🔗 Detected {len(chains)} attack chain(s)")

    # Step 5: Add chain_info to each finding - O(n)
    # Create lookup: scenario_number -> path
    path_lookup = {p.get('scenario_number', 0): p for p in paths}

    for chain_idx, chain_data in enumerate(chains):
        chain = chain_data['findings']
        avg_conf = chain_data['avg_confidence']
        chain_id = f"chain_{chain_idx + 1}"
        total_steps = len(chain)

        # Build chain_steps array with info from each finding
        chain_steps = []
        for scenario_num in chain:
            p = path_lookup.get(scenario_num, {})
            pf = p.get('pentest_finding', {})
            edges = p.get('query_info', {}).get('edges_used', [])
            chain_steps.append({
                'finding_id': scenario_num,
                'edge_type': edges[0] if edges else (pf.get('category', 'Unknown') if isinstance(pf, dict) else 'Unknown'),
                'title': pf.get('title', '') if isinstance(pf, dict) else ''
            })

        # Detect chain goal from final target
        final_path = path_lookup.get(chain[-1], {})
        final_results = final_path.get('results', [])
        chain_goal = "Domain Admin"  # Default

        if final_results and isinstance(final_results[0], dict):
            final_target = final_results[0].get('target', '')
            target_upper = final_target.upper()
            if 'DOMAIN ADMIN' in target_upper or 'DA' in target_upper:
                chain_goal = "Domain Admin"
            elif 'ENTERPRISE ADMIN' in target_upper:
                chain_goal = "Enterprise Admin"
            elif 'DC' in target_upper or 'DOMAIN CONTROLLER' in target_upper:
                chain_goal = "Domain Controller"
            elif 'ADMIN' in target_upper:
                chain_goal = "Administrator"
            else:
                chain_goal = final_target.split('@')[0][:20]  # Truncate long names

        # Add chain_info to each finding in this chain
        for position, scenario_num in enumerate(chain, 1):
            path = path_lookup.get(scenario_num)
            if not path:
                continue

            pf = path.get('pentest_finding', {})
            if not isinstance(pf, dict):
                continue

            # Build previous/next references
            prev_info = None
            next_info = None

            if position > 1:
                prev_num = chain[position - 2]
                prev_path = path_lookup.get(prev_num, {})
                prev_pf = prev_path.get('pentest_finding', {})
                prev_edges = prev_path.get('query_info', {}).get('edges_used', [])
                prev_info = {
                    'finding_id': prev_num,
                    'edge_type': prev_edges[0] if prev_edges else (prev_pf.get('category', 'Unknown') if isinstance(prev_pf, dict) else 'Unknown'),
                    'title': prev_pf.get('title', '') if isinstance(prev_pf, dict) else ''
                }

            if position < total_steps:
                next_num = chain[position]
                next_path = path_lookup.get(next_num, {})
                next_pf = next_path.get('pentest_finding', {})
                next_edges = next_path.get('query_info', {}).get('edges_used', [])
                next_info = {
                    'finding_id': next_num,
                    'edge_type': next_edges[0] if next_edges else (next_pf.get('category', 'Unknown') if isinstance(next_pf, dict) else 'Unknown'),
                    'title': next_pf.get('title', '') if isinstance(next_pf, dict) else ''
                }

            pf['chain_info'] = {
                'is_in_chain': True,
                'chain_id': chain_id,
                'position': position,
                'total_steps': total_steps,
                'chain_steps': chain_steps,
                'previous': prev_info,
                'next': next_info,
                'chain_goal': chain_goal,
                'confidence': avg_conf  # Include confidence score
            }

        add_log("INFO", f"  🔗 Chain {chain_idx + 1} (conf={avg_conf:.2f}): {' → '.join([f'#{s}' for s in chain])} → {chain_goal}")

    return paths


def assemble_hybrid_report(
    analyzed_paths: List[Dict[str, Any]],
    environment_analysis: Dict[str, Any],
    findings_summary: FindingsSummary,
    query_results: List[QueryResult],
    rag_service,
    tier0_config: Optional[Tier0Config] = None,
    deduplicator: Optional[Deduplicator] = None,
    validation_layer: Optional[ValidationLayer] = None
) -> Dict[str, Any]:
    """Assemble the final comprehensive report.

    T0 config enriches executive summary with target markers.
    Deduplicator and validation_layer enable Ground-Truth Anchoring for report quality.
    """

    add_log("INFO", "📋 Generating executive summary...")

    # Shared AMSI injector to track all used bypass families across paths
    amsi_injector = AMSIInjector()

    # Extract domain statistics from findings_summary.summary (actual graph stats)
    add_log("INFO", "🏢 Extracting domain statistics from graph data...")

    # Priority 1: Get domain info directly from BloodHound Domain node (most reliable)
    domain_info = environment_analysis.get("domain_info")
    domain_name = None
    forest_name = None
    functional_level = None

    if domain_info:
        domain_name = domain_info.get("name")
        forest_name = domain_info.get("forest") or domain_name
        functional_level = domain_info.get("functionalLevel")
        add_log("INFO", f"🏢 Domain info from BloodHound: {domain_name}, Level: {functional_level}, Forest: {forest_name}")

    # Priority 2: Try domain_names array from environment_analysis
    all_domains = (
        environment_analysis.get("domains", []) or
        environment_analysis.get("domain_names", []) or
        environment_analysis.get("environment_summary", {}).get("domain_names", [])
    )
    if not domain_name and all_domains:
        domain_name = all_domains[0]

    # Priority 3: Extract domain from analyzed paths (regex fallback)
    if not domain_name or domain_name == "Unknown":
        domain_pattern = re.compile(r'([A-Z0-9-]+\.(LOCAL|COM|NET|ORG|CORP|AD|INTERNAL|DOMAIN|IO|CO))', re.IGNORECASE)

        for path in analyzed_paths[:10]:
            path_str = json.dumps(path)
            match = domain_pattern.search(path_str)
            if match:
                domain_name = match.group(1).upper()
                add_log("INFO", f"🏢 Domain extracted from attack paths: {domain_name}")
                break

        if not domain_name:
            for finding_list in [findings_summary.high_risk[:20], findings_summary.medium_risk[:10]]:
                for finding in finding_list:
                    finding_str = json.dumps(finding)
                    match = domain_pattern.search(finding_str)
                    if match:
                        domain_name = match.group(1).upper()
                        add_log("INFO", f"🏢 Domain extracted from findings: {domain_name}")
                        break
                if domain_name:
                    break

    if not domain_name:
        domain_name = "Unknown"

    # Set defaults for forest and functional level if not found
    if not forest_name:
        forest_name = domain_name
    if not functional_level:
        functional_level = "Unknown"

    add_log("INFO", f"🏢 Final domain info: {domain_name}, Level: {functional_level}, Forest: {forest_name}")

    # Get actual stats from findings_summary (extracted from Neo4j graph)
    stats = findings_summary.summary or {}

    domain_stats = {
        "domain_name": domain_name,
        "forest_name": forest_name,
        "functional_level": functional_level,
        "total_users": stats.get("total_users", 0) or stats.get("total_nodes", 0),
        "total_groups": stats.get("total_groups", 0),
        "total_computers": stats.get("total_computers", 0),
        "domain_controllers": stats.get("domain_controllers", 0),
        "total_ous": stats.get("total_ous", 0),
        "total_gpos": stats.get("total_gpos", 0),
        "collection_method": "BloodHound CE",
        # Include all domains for multi-domain environments
        "all_domains": list(all_domains) if all_domains else [domain_name] if domain_name else [],
        "domain_count": len(all_domains) if all_domains else (1 if domain_name else 0)
    }

    add_log("INFO", f"📊 Domain stats: {domain_stats['total_users']} users, {domain_stats['total_groups']} groups, {domain_stats['total_computers']} computers")

    # NOTE: Executive summary is generated AFTER paths are processed and sorted
    # to ensure severity counts are accurate. See below after statistics calculation.

    # Calculate total findings (result counts from queries)
    total_findings = sum(qr.result_count for qr in query_results if not qr.error)

    # Process analyzed paths to ensure RAG analysis is properly preserved
    # If section extraction failed but raw_analysis exists, use raw_analysis as fallback
    processed_paths = []
    for i, path in enumerate(analyzed_paths):
        processed_path = dict(path)  # Copy to avoid mutation
        raw_analysis = path.get('raw_analysis', '')

        # Ensure all section fields exist with fallback to raw analysis
        # Note: removed dead fields (attack_scenario, mitre_mapping, detailed_remediations)
        section_fields = ['path_overview', 'technical_analysis', 'remediation_strategy', 'detection_methods']

        for field in section_fields:
            current_value = processed_path.get(field, '')
            if not current_value or current_value == 'Analysis unavailable':
                # If raw_analysis exists and section is empty, use raw for that section
                if raw_analysis and field == 'path_overview':
                    # Extract first paragraph as overview fallback
                    first_para = raw_analysis.split('\n\n')[0] if raw_analysis else ''
                    processed_path[field] = first_para[:500] if first_para else current_value

        # Always preserve raw_analysis for frontend fallback rendering
        processed_path['raw_analysis'] = raw_analysis

        # Ensure proper structure for critical_attack_paths
        processed_path['scenario_number'] = i + 1
        processed_path['title'] = path.get('query_info', {}).get('name', f'Attack Path {i+1}')
        processed_path['query_info'] = path.get('query_info', {})
        processed_path['results'] = path.get('results', [])
        processed_path['result_count'] = path.get('result_count', 0)
        processed_path['cypher_query'] = path.get('cypher_query', '')

        # Extract graph for THIS finding (per-finding approach like chat.py)
        results = processed_path['results']
        if results:
            try:
                finding_extractor = AttackPathGraphExtractor()
                wrapped_path = {
                    'query_info': processed_path.get('query_info', {}),
                    'results': results,
                    'scenario_number': i + 1
                }
                finding_graph = finding_extractor.extract_graph_from_attack_paths(
                    [wrapped_path],
                    f"finding-{i+1}"
                )
                processed_path['graph'] = finding_graph
                nodes_count = finding_graph.get('metadata', {}).get('total_nodes', 0)
                edges_count = finding_graph.get('metadata', {}).get('total_edges', 0)
                add_log("DEBUG", f"📊 Finding {i+1} graph: {nodes_count} nodes, {edges_count} edges")
            except Exception as graph_error:
                add_log("WARNING", f"⚠️ Graph extraction failed for finding {i+1}: {graph_error}")
                processed_path['graph'] = None
        else:
            processed_path['graph'] = None

        processed_paths.append(processed_path)

    actionable_paths = processed_paths
    t0_enabled = tier0_config is not None and tier0_config.enabled

    if t0_enabled:
        add_log("INFO", f"🛡️ T0 Config enabled with {tier0_config.get_asset_count()} assets (used for noise filtering and T0 markers)")

    # ==================== FILTER 0-STEP FINDINGS ====================
    # Remove findings with no attack_steps BEFORE sorting and chain synthesis
    # This ensures chain references only point to findings that will appear in the UI
    def has_attack_steps(path):
        """Check if finding has at least one attack step."""
        pentest_finding = path.get('pentest_finding', {})
        if not isinstance(pentest_finding, dict):
            return False
        steps = pentest_finding.get('attack_steps', [])
        return isinstance(steps, list) and len(steps) > 0

    original_count = len(actionable_paths)
    actionable_paths = [p for p in actionable_paths if has_attack_steps(p)]
    filtered_count = original_count - len(actionable_paths)

    if filtered_count > 0:
        add_log("INFO", f"🔍 Filtered out {filtered_count} findings with 0 attack steps")

    # ==================== HELPER: DC DETECTION ====================
    # Uses BloodHound properties and tier0_config (from auto-detection) - NO hardcoding

    def is_dc_from_result(result: dict, t0_config: Optional[Tier0Config] = None) -> bool:
        """
        Check if target is a Domain Controller using:
        1. BloodHound's isDC property (most reliable)
        2. BloodHound labels (DomainController)
        3. tier0_config (auto-detected DCs are added as T0 assets with type=Computer)

        Does NOT use hardcoded name patterns - relies on BloodHound data.
        """
        target_type = result.get('target_type', '').upper()
        if target_type != 'COMPUTER':
            return False

        # 1. Check BloodHound's isDC property (preferred method)
        target_props = result.get('target_properties', {})
        if isinstance(target_props, dict):
            if target_props.get('isdc') or target_props.get('isDC') or target_props.get('is_dc'):
                return True

        # 2. Check if marked as DC in labels
        labels = result.get('target_labels', [])
        if 'DomainController' in labels or 'DC' in labels:
            return True

        # 3. Check if target is in tier0_config as a Computer (DCs are auto-detected)
        target_name = result.get('target', '')
        if t0_config and t0_config.enabled and target_name:
            # DCs are added to tier0_config during auto-detection with type=Computer
            # If the computer is in T0 config, it's likely a DC
            if t0_config.is_t0_asset(target_name):
                # Verify it's a Computer type in the config
                for domain_config in t0_config.domains.values():
                    for asset in domain_config.assets:
                        if asset.name.upper() == target_name.upper() and asset.type.value == 'Computer':
                            return True

        return False

    # ==================== FILTER T0-ONLY SOURCE FINDINGS (NOISE REDUCTION) ====================
    # Remove findings where ALL sources are T0 assets and target is also T0.
    # Uses tier0_config from auto-detection - NO hardcoded lists.
    #
    # This filters expected AD behavior:
    # - "DOMAIN ADMINS can write to DC" → expected (both are T0)
    # - "KEY ADMINS can add Shadow Credentials to DC" → expected
    #
    # Only flag findings where at least ONE source is NOT a T0 asset.

    def is_t0_noise_finding(path, t0_config: Optional[Tier0Config] = None):
        """
        Check if a finding is T0 noise (all sources are T0 assets
        and target is also a T0 asset).

        Uses tier0_config from auto-detection for multi-domain support.
        Returns True if this is noise that should be filtered OUT.
        """
        # If T0 config not provided or disabled, no filtering
        if not t0_config or not t0_config.enabled:
            return False

        results = path.get('results', [])
        if not results:
            return False

        # Get unique sources and targets from results (with full domain names)
        sources = set()
        targets = set()
        source_is_t0 = []
        target_is_t0 = []

        for result in results:
            if not isinstance(result, dict):
                continue
            source = result.get('source', '')
            target = result.get('target', '')

            if source:
                sources.add(source)
                source_is_t0.append(t0_config.is_t0_asset(source))
            if target:
                targets.add(target)
                target_is_t0.append(t0_config.is_t0_asset(target))

        # If no sources found, don't filter
        if not sources:
            return False

        # Check if ALL sources are T0 assets
        all_sources_t0 = all(source_is_t0) if source_is_t0 else False

        if not all_sources_t0:
            # At least one source is NOT a T0 asset - keep this finding
            return False

        # All sources are T0 - now check if target is also T0
        # This filters: "DOMAIN ADMINS@DOMAIN.LOCAL → DC@DOMAIN.LOCAL", etc.
        any_target_t0 = any(target_is_t0) if target_is_t0 else False

        # Also check if target is a DC (DCs might not be in config but BloodHound marks them)
        any_target_dc = any(
            is_dc_from_result(result, t0_config)
            for result in results
            if isinstance(result, dict)
        )

        # Filter if: all sources are T0 AND (target is T0 or target is DC)
        if any_target_t0 or any_target_dc:
            add_log("DEBUG", f"🛡️ T0 noise: {list(sources)[:2]} → {list(targets)[:2]} (all T0)")
            return True

        return False

    pre_t0_filter_count = len(actionable_paths)
    actionable_paths = [p for p in actionable_paths if not is_t0_noise_finding(p, tier0_config)]
    t0_noise_filtered = pre_t0_filter_count - len(actionable_paths)

    if t0_noise_filtered > 0:
        t0_asset_count = tier0_config.get_asset_count() if tier0_config else 0
        add_log("INFO", f"🛡️ Filtered out {t0_noise_filtered} T0-only findings (expected AD behavior, checked against {t0_asset_count} T0 assets)")

    # ==================== CIRCULAR LOGIC DETECTION ====================
    # Filter findings where the attack requires admin access on the target to execute.
    # Example: CoerceToTGT on a DC requires DC admin to coerce the DC - circular.
    # These attacks only make sense if targeting something OTHER than the goal.
    # Uses tier0_config and BloodHound properties - NO hardcoded DC patterns.
    #
    # AGGRESSIVE MODE: CoerceToTGT is almost always circular since you need access
    # to the target to coerce it. We filter more aggressively for this edge type.

    CIRCULAR_LOGIC_EDGES = {
        'COERCETOTGT', 'ABUSETGTDELEGATION', 'COERCEANDRELAYNTLMTOSMB',
        'COERCEANDRELAYNTLMTOLDAP', 'COERCEANDRELAYNTLMTOADCS',
    }

    # DC name patterns for fallback detection when isDC property not set
    DC_NAME_PATTERNS = {'DC', 'DC0', 'DC1', 'DC2', 'DC01', 'DC02', 'PDC', 'BDC'}

    def is_circular_logic_finding(path, t0_config: Optional[Tier0Config] = None):
        """
        Detect circular logic: attack requires target access to attack target.
        Example: CoerceToTGT on DC requires DC access, but DC access is the goal.

        Uses BloodHound isDC property and tier0_config for DC detection.
        Also applies aggressive filtering for CoerceToTGT since it almost always
        has circular logic (you need target access to monitor/capture TGT).
        """
        edges_used = path.get('query_info', {}).get('edges_used', [])
        edges_upper = {e.upper() for e in edges_used}
        query_name = path.get('query_info', {}).get('name', '').upper()

        # Only check findings with circular-prone edge types
        if not edges_upper.intersection(CIRCULAR_LOGIC_EDGES):
            return False

        results = path.get('results', [])
        if not results:
            return False

        # AGGRESSIVE: CoerceToTGT is almost always circular
        # The attack requires being on the target to monitor/capture TGT tickets
        is_coerce_tgt = 'COERCETOTGT' in edges_upper or 'COERCETOTGT' in query_name

        for result in results:
            if not isinstance(result, dict):
                continue
            target = result.get('target', '')
            target_type = result.get('target_type', '').upper()

            if target_type != 'COMPUTER':
                continue

            # 1. Check using BloodHound properties and tier0_config
            if is_dc_from_result(result, t0_config):
                add_log("DEBUG", f"🔄 Circular logic detected: {path.get('query_info', {}).get('name', '')} targets DC {target}")
                return True

            # 2. Fallback: Check DC name patterns
            target_name = target.upper().split('@')[0].rstrip('$')
            if any(target_name == pat or target_name.startswith(pat) for pat in DC_NAME_PATTERNS):
                add_log("DEBUG", f"🔄 Circular logic detected (name pattern): {path.get('query_info', {}).get('name', '')} targets {target}")
                return True

            # 3. AGGRESSIVE: CoerceToTGT targeting ANY computer is likely circular
            # because you need to be on that computer to capture the TGT
            if is_coerce_tgt:
                add_log("DEBUG", f"🔄 CoerceToTGT is circular by nature: {path.get('query_info', {}).get('name', '')} targets {target}")
                return True

        return False

    pre_circular_count = len(actionable_paths)
    actionable_paths = [p for p in actionable_paths if not is_circular_logic_finding(p, tier0_config)]
    circular_filtered = pre_circular_count - len(actionable_paths)

    if circular_filtered > 0:
        add_log("INFO", f"🔄 Filtered out {circular_filtered} circular logic findings (require target access to attack target)")

    # ==================== CROSS-FINDING DEDUPLICATION (Ground-Truth Anchoring) ====================
    # Remove duplicate findings where the same (source, target, edge_type) appears
    # in multiple query contexts. Keep the first occurrence (typically higher priority).
    # Example: "GenericAll from SUPPORT ACCOUNTS → DC" shouldn't appear as both
    # "Group-Mediated ACL Abuse" and "WriteDacl/GenericAll Abuse".
    #
    # Uses Deduplicator's edge normalization for consistent categorization.

    # Initialize deduplicator if not provided
    if deduplicator is None:
        deduplicator = Deduplicator()

    def get_finding_signature_gt(path, dedup: Deduplicator):
        """
        Generate a unique signature using Ground-Truth Deduplicator's edge normalization.
        """
        results = path.get('results', [])
        if not results:
            return None

        # Get unique source-target-edge combinations
        signatures = set()
        for result in results[:10]:  # Check first 10 results
            if not isinstance(result, dict):
                continue
            source = result.get('source', '').upper().split('@')[0].strip()
            target = result.get('target', '').upper().split('@')[0].strip()
            edge = result.get('edge_type', '').upper().strip()

            if source and target:
                # Use Deduplicator's edge normalization (Ground-Truth Anchoring)
                normalized_edge = dedup._normalize_edge(edge)
                signatures.add((source, target, normalized_edge))

        return frozenset(signatures) if signatures else None

    seen_signatures = {}
    deduplicated_paths = []

    for path in actionable_paths:
        sig = get_finding_signature_gt(path, deduplicator)

        if sig is None:
            # No valid signature, keep it
            deduplicated_paths.append(path)
            continue

        if sig in seen_signatures:
            # Duplicate found - log and skip
            original_name = seen_signatures[sig]
            current_name = path.get('query_info', {}).get('name', 'Unknown')
            add_log("DEBUG", f"🔁 Duplicate finding skipped: '{current_name}' duplicates '{original_name}'")
            continue

        # New unique finding
        seen_signatures[sig] = path.get('query_info', {}).get('name', 'Unknown')
        deduplicated_paths.append(path)

    dedup_filtered = len(actionable_paths) - len(deduplicated_paths)
    actionable_paths = deduplicated_paths

    if dedup_filtered > 0:
        add_log("INFO", f"🔁 [Ground-Truth] Filtered out {dedup_filtered} duplicate findings (same source→target→edge)")

    # ==================== VALIDATE REMEDIATION TARGETS ====================
    # Ensure remediation commands target compromisable entities, not T0 groups
    # that aren't actually vulnerable in this specific attack path
    if tier0_config and tier0_config.enabled:
        validation_count = 0
        for path in actionable_paths:
            pentest_finding = path.get('pentest_finding', {})
            remediation_steps = pentest_finding.get('remediation_steps', [])

            if remediation_steps:
                # Extract compromisable entities from this path's results
                results = path.get('results', [])
                compromisable_entities = []
                for result in results:
                    # Skip non-dict results (some may be strings)
                    if not isinstance(result, dict):
                        continue
                    source = result.get('source', '')
                    target = result.get('target', '')
                    if source:
                        compromisable_entities.append(source)
                    if target:
                        compromisable_entities.append(target)

                # Validate and update remediation steps
                validated_steps = validate_remediation_targets(
                    remediation_steps,
                    compromisable_entities,
                    tier0_config
                )
                pentest_finding['remediation_steps'] = validated_steps

                # Count warnings added
                for step in validated_steps:
                    if isinstance(step, dict) and step.get('validation_warning'):
                        validation_count += 1

        if validation_count > 0:
            add_log("INFO", f"⚠️ Added {validation_count} remediation validation warnings (T0 targets not in attack path)")

    # ==================== VALIDATION LAYER TYPO CORRECTIONS (Ground-Truth Anchoring) ====================
    # Apply typo corrections from ValidationLayer to fix common LLM errors
    # Examples: "Impacted" → "Impacket", "Rubens" → "Rubeus", etc.
    if validation_layer:
        typo_fix_count = 0
        for path in actionable_paths:
            pentest_finding = path.get('pentest_finding', {})
            if not isinstance(pentest_finding, dict):
                continue

            # Apply typo fixes to observation
            observation = pentest_finding.get('observation', '')
            if observation:
                fixed_observation = validation_layer._apply_typo_fixes(observation)
                if fixed_observation != observation:
                    pentest_finding['observation'] = fixed_observation
                    typo_fix_count += 1

            # Apply typo fixes to attack steps
            attack_steps = pentest_finding.get('attack_steps', [])
            for step in attack_steps:
                if isinstance(step, dict):
                    for field in ['description', 'title']:
                        if field in step:
                            fixed = validation_layer._apply_typo_fixes(step[field])
                            if fixed != step[field]:
                                step[field] = fixed
                                typo_fix_count += 1

            # Apply typo fixes to opsec_options commands and explanations
            for step in attack_steps:
                for option in step.get('opsec_options', []):
                    if 'command' in option and option['command']:
                        fixed_cmd = validation_layer._apply_typo_fixes(option['command'])
                        # Fix evil-winrm invalid Kerberos flags (-K -t ccache → export KRB5CCNAME + -r)
                        fixed_cmd = re.sub(
                            r'evil-winrm\s+-i\s+(\S+)\s+-u\s+(\S+)\s+-K\s+-t\s+(\S+)',
                            r'export KRB5CCNAME=\3 && evil-winrm -i \1 -u \2 -r DOMAIN',
                            fixed_cmd
                        )
                        # Fix bloodyAD set rbcd (doesn't exist) → impacket-rbcd
                        fixed_cmd = re.sub(
                            r"bloodyAD\s+.*?set\s+rbcd\s+'?(\S+?)'?\s+'?(\S+?)'?",
                            r"impacket-rbcd -delegate-to '\1' -delegate-from '\2' -action 'write'",
                            fixed_cmd
                        )
                        # Fix old .py Impacket tool names → modern impacket- prefix
                        py_to_impacket = {
                            'GetNPUsers.py': 'impacket-GetNPUsers',
                            'GetUserSPNs.py': 'impacket-GetUserSPNs',
                            'secretsdump.py': 'impacket-secretsdump',
                            'psexec.py': 'impacket-psexec',
                            'wmiexec.py': 'impacket-wmiexec',
                            'smbexec.py': 'impacket-smbexec',
                            'atexec.py': 'impacket-atexec',
                            'getST.py': 'impacket-getST',
                            'getTGT.py': 'impacket-getTGT',
                            'ticketer.py': 'impacket-ticketer',
                            'addcomputer.py': 'impacket-addcomputer',
                            'rbcd.py': 'impacket-rbcd',
                            'dacledit.py': 'impacket-dacledit',
                            'owneredit.py': 'impacket-owneredit',
                            'dcomexec.py': 'impacket-dcomexec',
                        }
                        for old_name, new_name in py_to_impacket.items():
                            fixed_cmd = fixed_cmd.replace(old_name, new_name)
                        # Fix GetNPUsers invalid -user flag → inline DOMAIN/USER
                        # Handles: impacket-GetNPUsers DOMAIN/ ... -user 'USER' → DOMAIN/USER ...
                        user_match = re.search(r"-user\s+['\"]?(\S+?)['\"]?(?:\s|$)", fixed_cmd)
                        if user_match and 'GetNPUsers' in fixed_cmd:
                            username = user_match.group(1).strip("'\"")
                            # Remove the -user flag and its value
                            fixed_cmd = re.sub(r"\s+-user\s+['\"]?\S+?['\"]?", '', fixed_cmd)
                            # Insert username after DOMAIN/
                            fixed_cmd = re.sub(r'((?:HTB\.LOCAL|SUPPORT\.HTB|EGOTISTICAL-BANK\.LOCAL|\S+\.(?:LOCAL|HTB|COM))/)\s', rf'\1{username} ', fixed_cmd)
                        # Replace impacket-smbclient with impacket-wmiexec in auth/shell steps
                        if 'impacket-smbclient' in fixed_cmd:
                            fixed_cmd = fixed_cmd.replace('impacket-smbclient', 'impacket-wmiexec')
                        if fixed_cmd != option['command']:
                            option['command'] = fixed_cmd
                            typo_fix_count += 1
                    if 'explanation' in option and option['explanation']:
                        fixed_exp = validation_layer._apply_typo_fixes(option['explanation'])
                        if fixed_exp != option['explanation']:
                            option['explanation'] = fixed_exp
                            typo_fix_count += 1
                    if 'tool_name' in option and option['tool_name']:
                        fixed_tool = validation_layer._apply_typo_fixes(option['tool_name'])
                        if fixed_tool != option['tool_name']:
                            option['tool_name'] = fixed_tool
                            typo_fix_count += 1

            # Inject AMSI bypasses for PowerShell tools (use shared injector)
            pentest_finding['attack_steps'] = amsi_injector.process_attack_steps(attack_steps)

            # Apply typo fixes to remediation steps
            remediation_steps = pentest_finding.get('remediation_steps', [])
            for step in remediation_steps:
                if isinstance(step, dict):
                    for field in ['description', 'title']:
                        if field in step:
                            fixed = validation_layer._apply_typo_fixes(step[field])
                            if fixed != step[field]:
                                step[field] = fixed
                                typo_fix_count += 1

            # Apply typo fixes to risk description
            risk_desc = pentest_finding.get('risk_description', '')
            if risk_desc:
                fixed_risk = validation_layer._apply_typo_fixes(risk_desc)
                if fixed_risk != risk_desc:
                    pentest_finding['risk_description'] = fixed_risk
                    typo_fix_count += 1

        if typo_fix_count > 0:
            add_log("INFO", f"✏️ [Ground-Truth] Applied {typo_fix_count} typo corrections (Impacted→Impacket, etc.)")

    # ==================== SORT BY SEVERITY ====================
    # Sort paths by severity (Critical first, then High, Medium, Low)
    def get_severity_priority(path):
        """Sort findings by severity: Critical first, then High, Medium, Low."""
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        severity = path.get('pentest_finding', {}).get('severity', 'Medium')
        return severity_order.get(severity, 2)

    actionable_paths.sort(key=get_severity_priority)

    # Re-number findings after sorting
    for i, path in enumerate(actionable_paths):
        path['scenario_number'] = i + 1
        pf = path.get('pentest_finding')
        if isinstance(pf, dict):
            pf['finding_number'] = i + 1

    add_log("INFO", f"📊 Paths sorted by severity (Critical first), {len(actionable_paths)} findings remaining")

    # ==================== CHAIN SYNTHESIS ====================
    # Detect connected findings where A's target == B's source
    # This enables the "Attack Chain" visualization in the frontend
    # actionable_paths = synthesize_attack_chains(actionable_paths)  # Chain linking disabled

    # Calculate statistics based on ACTUAL pentest_finding.severity values (not query priority)
    # This ensures statistics match what the user sees in the report
    def get_severity(p):
        pf = p.get('pentest_finding', {})
        if not isinstance(pf, dict):
            return ''
        return pf.get('severity', '').lower()

    critical_paths = [p for p in actionable_paths if get_severity(p) == 'critical']
    high_paths = [p for p in actionable_paths if get_severity(p) == 'high']
    medium_paths = [p for p in actionable_paths if get_severity(p) == 'medium']
    low_paths = [p for p in actionable_paths if get_severity(p) == 'low']

    add_log("INFO", f"📊 Stats by severity: {len(critical_paths)} critical, {len(high_paths)} high, {len(medium_paths)} medium, {len(low_paths)} low")

    # Generate executive summary AFTER paths are processed and severity counts are known
    # This ensures the summary accurately reflects the findings
    exec_summary = generate_executive_summary(
        actionable_paths,  # Use processed paths with severity set
        findings_summary,
        rag_service,
        domain_name=domain_name
    )

    # Generate AMSI appendix with only the used bypass families
    amsi_appendix = None
    if amsi_injector.used_families:
        amsi_appendix = generate_amsi_appendix(amsi_injector.used_families)
        add_log("INFO", f"📖 Generated AMSI appendix with {len(amsi_appendix['techniques'])} techniques")

    report = {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now().isoformat(),
        "executive_summary": exec_summary,
        "environment_overview": environment_analysis.get('raw_analysis', ''),
        "domain_overview": domain_stats,
        "statistics": {
            "total_attack_paths": len(processed_paths),
            "actionable_paths": len(actionable_paths),
            "critical_paths": len(critical_paths),
            "high_risk_paths": len(high_paths),
            "total_findings": total_findings,
            "queries_executed": len(query_results),
            "findings_by_severity": {
                "critical": len(critical_paths),
                "high": len(high_paths),
                "medium": len(medium_paths),
                "low": len(low_paths)
            }
        },
        "tier0_statistics": {
            "enabled": t0_enabled,
            "assets_count": tier0_config.get_asset_count() if tier0_config else 0,
            "actionable_count": len(actionable_paths)
        },
        # Note: removed redundant "critical_attack_paths" (was identical to "paths")
        "paths": actionable_paths,
        "all_paths": processed_paths,  # All paths for reference (including filtered)
        # Fix: use actionable_paths not analyzed_paths to avoid referencing filtered findings
        # recommendations removed — did not add value, saves LLM generation time
        "data_source": "local_neo4j",
        "amsi_appendix": amsi_appendix,  # AMSI bypass techniques for PowerShell tools
    }

    # Graph data is now per-finding (stored in each path's 'graph' field)
    # Aggregate stats for report metadata
    total_nodes = sum(
        p.get('graph', {}).get('metadata', {}).get('total_nodes', 0)
        for p in actionable_paths if p.get('graph')
    )
    total_edges = sum(
        p.get('graph', {}).get('metadata', {}).get('total_edges', 0)
        for p in actionable_paths if p.get('graph')
    )
    add_log("INFO", f"📊 Per-finding graphs: {total_nodes} total nodes, {total_edges} total edges across {len(actionable_paths)} findings")

    add_log("INFO", "✅ Report assembly complete")
    return report


def generate_executive_summary(
    analyzed_paths: List[Dict[str, Any]],
    findings_summary: FindingsSummary,
    rag_service,
    domain_name: str = None
) -> str:
    """Generate executive summary with RAG - CONCISE format with key concerns"""

    # Ensure domain_name is set
    domain_name = domain_name or "the target domain"

    # Count actual attack scenarios found (not raw Neo4j findings)
    # This matches what's shown in the Findings Overview table
    total_attack_scenarios = len(analyzed_paths)

    # Count by ACTUAL pentest_finding.severity (not query priority)
    # This ensures exec summary matches the statistics shown in the report
    def safe_get_severity(p):
        pf = p.get('pentest_finding', {})
        if not isinstance(pf, dict):
            return ''
        return pf.get('severity', '').lower()

    critical_count = sum(1 for p in analyzed_paths if safe_get_severity(p) == 'critical')
    high_count = sum(1 for p in analyzed_paths if safe_get_severity(p) == 'high')
    medium_count = sum(1 for p in analyzed_paths if safe_get_severity(p) == 'medium')

    # Count T0-targeting findings
    t0_targeting_count = 0
    t0_targeting_paths = []
    for path in analyzed_paths:
        pf = path.get('pentest_finding', {})
        if isinstance(pf, dict) and pf.get('targets_t0'):
            t0_targeting_count += 1
            t0_targeting_paths.append(pf.get('title', path.get('query_info', {}).get('name', 'Unknown')))

    # Extract key concerns from analyzed paths with their result counts - use markdown list format
    key_concerns = []
    for path in analyzed_paths[:8]:
        query_info = path.get('query_info', {})
        result_count = path.get('result_count', 0)
        if result_count > 0:
            name = query_info.get('name', 'Unknown')
            pf = path.get('pentest_finding', {})
            t0_marker = " ⚠️ **[T0 TARGET]**" if isinstance(pf, dict) and pf.get('targets_t0') else ""
            key_concerns.append(f"- {result_count} {name.lower()}{t0_marker}")

    key_concerns_text = "\n".join(key_concerns) if key_concerns else "- No critical findings identified"

    # T0 context for the prompt
    t0_context = ""
    if t0_targeting_count > 0:
        t0_context = f"""
TIER 0 CONTEXT:
- {t0_targeting_count} attack paths directly target Tier 0 (critical) assets
- T0 assets include: Domain Admins, Enterprise Admins, Domain Controllers, KRBTGT
- Compromise of these assets means COMPLETE DOMAIN TAKEOVER
- These findings should be treated as HIGHEST PRIORITY"""

    # Build the prompt for a CONCISE executive summary
    summary_prompt = f"""Generate a CONCISE executive summary for a BloodHound Active Directory security assessment.
{t0_context}

DOMAIN: **{domain_name}**

CRITICAL OUTPUT RULES:
- Output ONLY the executive summary text - no labels, no headers
- Keep it SHORT - 2 paragraphs of overview text, then a PROPER MARKDOWN bullet list
- Do NOT use markdown headers (no # or ##)
- Use **bold** for key terms only (always use the actual domain name **{domain_name}**, NEVER use placeholder text like "<DOMAIN>")
- IMPORTANT: The bullet list MUST use markdown format with each bullet on its own line
- IMPORTANT: Always ensure there is a SPACE after bold markers (e.g., "**{domain_name}** environment" NOT "**{domain_name}**environment")

STRUCTURE:

First paragraph (2-3 sentences):
Brief overview of the BloodHound graph-based security assessment of the **{domain_name}** environment. State that {total_attack_scenarios} distinct attack path categories were identified, with {critical_count} critical and {high_count} high severity findings.{f" **CRITICAL: {t0_targeting_count} paths directly target Tier 0 assets (Domain Admins, DCs) - this represents the highest risk of complete domain compromise.**" if t0_targeting_count > 0 else ""}

Second paragraph (2-3 sentences):
Summarize the risk - these findings represent exploitable privilege relationships and attack vectors that could lead to domain compromise.{" **Tier 0-targeting paths are especially critical as they lead directly to the most privileged assets in the domain.**" if t0_targeting_count > 0 else ""} Mention attack complexity is low for most vectors.

Then write "Key concerns include:" followed by a PROPER markdown bullet list (each on a new line):
{key_concerns_text}

End with 1-2 sentences on immediate remediation priorities ({"**prioritizing Tier 0 protection,** " if t0_targeting_count > 0 else ""}tier-zero protection, least-privilege review).

VERY IMPORTANT FORMATTING:
- The bullet list MUST be a proper markdown list with each item on its OWN LINE
- Do NOT put bullets inline in a paragraph
- Use "- " or "• " at the start of each line for bullets
- Keep total output under 250 words"""

    try:
        add_log("INFO", "🤖 RAG generating executive summary...")
        response = rag_service.query(summary_prompt)
        summary = response.get('result', '')

        # If RAG fails or returns empty, generate a structured fallback
        if not summary or len(summary) < 50:
            summary = generate_fallback_executive_summary(
                total_attack_scenarios, critical_count, high_count, medium_count, analyzed_paths, domain_name
            )
        else:
            # Post-process to fix spacing issues around bold markers
            summary = _fix_markdown_spacing(summary)

        add_log("INFO", "✅ Executive summary generated")
        return summary
    except Exception as e:
        add_log("ERROR", f"Failed to generate executive summary: {e}")
        return generate_fallback_executive_summary(
            total_attack_scenarios, critical_count, high_count, medium_count, analyzed_paths, domain_name
        )


def _fix_markdown_spacing(text: str) -> str:
    """Fix spacing issues around markdown bold markers.

    Ensures there's always a space before and after **bold** text when adjacent to words.
    This prevents text like "**GetChangesAll**permissions" from rendering incorrectly.
    """
    if not text:
        return text

    # Use a function-based replacement to handle both before and after spacing in one pass
    text = re.sub(r'(.)?(\*\*)([^*]+?)(\*\*)(.)?',
                  lambda m: (m.group(1) or '') +
                            (' ' if m.group(1) and m.group(1).isalpha() else '') +
                            '**' + m.group(3) + '**' +
                            (' ' if m.group(5) and m.group(5).isalpha() else '') +
                            (m.group(5) or ''),
                  text)

    # Fix double spaces that might have been introduced
    text = re.sub(r' {2,}', ' ', text)

    return text


def generate_fallback_executive_summary(
    total_scenarios: int,
    critical_count: int,
    high_count: int,
    medium_count: int,
    analyzed_paths: List[Dict[str, Any]],
    domain_name: str = None
) -> str:
    """Generate a structured fallback executive summary if RAG fails"""

    domain_name = domain_name or "the target domain"

    # Build key concerns from paths with results - use markdown list format
    concerns = []
    for path in analyzed_paths[:6]:
        result_count = path.get('result_count', 0)
        if result_count > 0:
            name = path.get('query_info', {}).get('name', 'Unknown vulnerability')
            concerns.append(f"- {result_count} {name.lower()}")

    concerns_text = "\n".join(concerns) if concerns else "- Security misconfigurations requiring review"

    return f"""This BloodHound graph-based security assessment of the **{domain_name}** environment identified **{total_scenarios} distinct attack path categories**, with {critical_count} critical and {high_count} high severity findings.

These findings represent exploitable privilege relationships and attack vectors that could enable domain compromise with low attack complexity.

**Key concerns include:**

{concerns_text}

Immediate remediation should focus on protecting tier-zero assets and implementing least-privilege principles for identified excessive permissions."""



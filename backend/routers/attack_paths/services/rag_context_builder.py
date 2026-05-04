"""
RAG Context Builder for Attack Path Analysis
Location: backend/routers/attack_paths/services/rag_context_builder.py

Builds enriched context for RAG model with detailed attack information.
"""

import logging
from typing import List, Dict, Any

from ..constants import ATTACK_CATEGORY_MAP
from .structured_data import derive_attack_chain

logger = logging.getLogger(__name__)


def extract_compromisable_entities(findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """
    Extract entities by role from findings.

    Returns dict with:
    - compromisable_entities: List of entities that can be attacked (need remediation)
    - privilege_targets: List of groups/resources gained via compromise
    """
    compromisable = set()
    privilege_targets = set()

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        source = finding.get('source', '')
        target = finding.get('target', '')
        source_role = finding.get('source_role', 'unknown')
        target_role = finding.get('target_role', 'unknown')

        # Collect compromisable entities
        if source_role == 'compromisable_entity' and source:
            # Strip domain suffix for cleaner display
            compromisable.add(source.split('@')[0] if '@' in source else source)
        if target_role == 'compromisable_entity' and target:
            compromisable.add(target.split('@')[0] if '@' in target else target)

        # Collect privilege targets
        if target_role == 'privilege_target' and target:
            privilege_targets.add(target.split('@')[0] if '@' in target else target)

    return {
        'compromisable_entities': list(compromisable),
        'privilege_targets': list(privilege_targets)
    }


def build_enriched_rag_context(
    query_name: str,
    query_description: str,
    domain: str,
    edges_used: List[str],
    findings: List[Dict[str, Any]],
    sources: List[str],
    targets: List[str],
    severity: str,
    edge_service=None,
    dc_hostname: str = None
) -> Dict[str, Any]:
    """
    Build enriched context for RAG model with detailed attack information.

    This provides RAG with much richer context than just edge types and names,
    including attack technique descriptions, target analysis, and impact assessment.

    Uses EdgeDataService for accurate edge data from bloodhound_edges_enhanced.json.
    """

    # Identify high-value targets
    high_value_groups = {'DOMAIN ADMINS', 'ENTERPRISE ADMINS', 'ADMINISTRATORS', 'SCHEMA ADMINS',
                          'ACCOUNT OPERATORS', 'BACKUP OPERATORS', 'SERVER OPERATORS', 'PRINT OPERATORS'}

    high_value_targets = []
    for t in targets:
        t_upper = t.upper()
        if any(hv in t_upper for hv in high_value_groups):
            high_value_targets.append(t)

    # Build attack technique info from EdgeDataService
    primary_edge = edges_used[0] if edges_used else 'Unknown'

    if edge_service:
        # Get rich data from bloodhound_edges_enhanced.json via EdgeDataService
        edge_description = edge_service.get_description(primary_edge)
        edge_abuse = edge_service.get_abuse_info(primary_edge)
        technique_info = {
            # Use query_name as the attack technique name - it already has proper naming
            # e.g., "DCSync Attack Capability", "Shadow Credentials on Domain Controllers"
            'name': query_name,
            'description': edge_description,
            'impact': edge_abuse,
            'attack_chain': derive_attack_chain(primary_edge, edge_service)
        }
    else:
        # Fallback if edge_service not provided
        technique_info = {
            'name': query_name,
            'description': f'Exploitation of {primary_edge} relationships in Active Directory',
            'impact': 'Potential privilege escalation or lateral movement',
            'attack_chain': 'Varies based on target configuration'
        }

    # Build sample attack paths (first 3 findings) with ATTACK PROPERTIES
    sample_paths = []
    attack_indicators = []  # Collect attack vector indicators

    for f in findings[:3]:
        if not isinstance(f, dict):
            continue
        source = f.get('source', '')
        target = f.get('target', '')
        edge = f.get('edge_type', '')
        source_type = f.get('source_type', 'Unknown')
        target_type = f.get('target_type', 'Unknown')
        source_props = f.get('source_properties', {})
        target_props = f.get('target_properties', {})

        if source and target and edge:
            # Build path description showing full chain if available
            path_edges = f.get('path_edges', [])
            intermediate = f.get('intermediate_nodes', [])
            if path_edges and len(path_edges) > 1 and intermediate:
                # Multi-hop chain description
                chain_parts = [source.split('@')[0] if '@' in source else source]
                for j, edge_name in enumerate(path_edges):
                    if j < len(intermediate):
                        mid = intermediate[j].split('@')[0] if '@' in intermediate[j] else intermediate[j]
                        chain_parts.append(f"-[{edge_name}]-> {mid}")
                    else:
                        chain_parts.append(f"-[{edge_name}]-> {target.split('@')[0] if '@' in target else target}")
                if not chain_parts[-1].endswith(target.split('@')[0] if '@' in target else target):
                    chain_parts.append(f"-> {target.split('@')[0] if '@' in target else target}")
                path_desc = ' '.join(chain_parts)
            else:
                path_desc = f"{source_type} '{source.split('@')[0]}' has {edge} rights on {target_type} '{target.split('@')[0]}'"

            sample_paths.append({
                'source': source.split('@')[0] if '@' in source else source,
                'source_type': source_type,
                'edge': edge,
                'target': target.split('@')[0] if '@' in target else target,
                'target_type': target_type,
                'source_properties': source_props,
                'target_properties': target_props,
                'path_edges': path_edges,
                'intermediate_nodes': intermediate,
                'path_description': path_desc,
            })

            # Detect attack indicators from node properties
            if source_props.get('hasspn'):
                attack_indicators.append(f"{source.split('@')[0]} has SPNs set (Kerberoastable)")
                if source_props.get('serviceprincipalnames'):
                    spns = source_props['serviceprincipalnames']
                    if isinstance(spns, list):
                        attack_indicators.append(f"  SPNs: {', '.join(spns[:3])}")
            if source_props.get('dontreqpreauth'):
                attack_indicators.append(f"{source.split('@')[0]} has no Kerberos pre-auth (AS-REP Roastable)")
            if source_props.get('unconstraineddelegation'):
                attack_indicators.append(f"{source.split('@')[0]} has unconstrained delegation")
            if source_props.get('trustedtoauth'):
                attack_indicators.append(f"{source.split('@')[0]} has constrained delegation (S4U)")
            if target_props.get('isdc'):
                attack_indicators.append(f"{target.split('@')[0]} is a Domain Controller")

    # Use ATTACK_CATEGORY_MAP from constants instead of hardcoded local map
    attack_category = ATTACK_CATEGORY_MAP.get(primary_edge, 'Privilege Escalation')

    # Detect entity types
    source_types = list(set(f.get('source_type', 'Unknown') for f in findings if isinstance(f, dict) and f.get('source_type')))
    target_types = list(set(f.get('target_type', 'Unknown') for f in findings if isinstance(f, dict) and f.get('target_type')))

    # Extract entity roles from findings
    entity_roles = extract_compromisable_entities(findings)
    compromisable_entities = entity_roles['compromisable_entities']
    privilege_targets = entity_roles['privilege_targets']

    # CRITICAL: Also add entities with attack-indicating properties (hasspn, dontreqpreauth)
    # These may have edge_type=MemberOf which doesn't set source_role='compromisable_entity'
    # but the NODE PROPERTIES indicate they are vulnerable
    property_based_compromisable = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        source = f.get('source', '')
        source_props = f.get('source_properties', {})
        if not isinstance(source_props, dict):
            source_props = {}

        # Users with hasspn=true are Kerberoastable (compromisable)
        if source_props.get('hasspn'):
            clean_source = source.split('@')[0] if '@' in source else source
            property_based_compromisable.add(clean_source)

        # Users with dontreqpreauth=true are AS-REP Roastable (compromisable)
        if source_props.get('dontreqpreauth'):
            clean_source = source.split('@')[0] if '@' in source else source
            property_based_compromisable.add(clean_source)

    # Merge property-based compromisable entities with role-based ones
    all_compromisable = set(compromisable_entities) | property_based_compromisable
    compromisable_entities = list(all_compromisable)

    return {
        # Basic info
        'query_name': query_name,
        'query_description': query_description,
        'domain': domain,
        'severity': severity,
        'finding_count': len(findings),

        # Edge and technique info
        'edges': edges_used,
        'primary_edge': primary_edge,
        'attack_technique_name': technique_info['name'],
        'attack_technique_description': technique_info['description'],
        'attack_impact': technique_info['impact'],
        'attack_chain': technique_info['attack_chain'],
        'attack_category': attack_category,

        # Entity info
        'sources': sources,
        'targets': targets,
        'source_types': source_types,
        'target_types': target_types,
        'high_value_targets': high_value_targets,
        'targets_domain_admin': any('DOMAIN ADMIN' in t.upper() or 'ENTERPRISE ADMIN' in t.upper() for t in targets),

        # Entity role information (compromisable vs privilege targets)
        'compromisable_entities': compromisable_entities,
        'privilege_targets': privilege_targets,
        'remediation_targets': compromisable_entities,  # Alias for clarity in prompts

        # Sample paths for context
        'sample_paths': sample_paths,
        'sample_path_descriptions': [p['path_description'] for p in sample_paths],

        # CRITICAL: Attack indicators from node properties (for RAG to identify attack vectors)
        'attack_indicators': attack_indicators,

        # For prompts
        'key_source': sources[0] if sources else 'affected principals',
        'key_target': targets[0] if targets else 'target objects',

        # DC hostname for command generation
        'dc_hostname': dc_hostname or f'DC.{domain}',
    }

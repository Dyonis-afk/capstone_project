"""
Result Conversion Services for Attack Path Analysis
Location: backend/routers/attack_paths/services/result_converter.py

Functions for converting Neo4j query results to finding format:
- Path result parsing
- Entity name extraction
- Attack type/priority inference
- Scenario conversion
"""

import logging
from typing import Dict, Any, List, Tuple

from ..models import QueryResult
from ..state import add_log

logger = logging.getLogger(__name__)


# =============================================================================
# ENTITY ROLE MAPPING - Determines which entity needs remediation
# =============================================================================
# Role definitions:
# - compromisable_entity: Account that can be attacked (needs remediation)
# - privilege_target: Group/resource gained via compromise (not directly remediated)
# - access_holder: Entity that has access to something
# - attack_vector: The vulnerability itself
# - unknown: Edge type not mapped (safe default)

EDGE_ROLE_MAPPING = {
    # Credential attacks - SOURCE is compromisable (Kerberoast the user, not the SPN)
    'KERBEROASTABLE': ('compromisable_entity', 'attack_vector'),
    'ASREPROASTABLE': ('compromisable_entity', 'attack_vector'),
    'HASSPN': ('compromisable_entity', 'attack_vector'),
    'DONTREQPREAUTH': ('compromisable_entity', 'attack_vector'),

    # Group membership - TARGET is the privilege (you gain group access)
    'MEMBEROF': ('access_holder', 'privilege_target'),
    'ADMINTO': ('access_holder', 'privilege_target'),
    'CANRDP': ('access_holder', 'privilege_target'),
    'CANPSREMOTE': ('access_holder', 'privilege_target'),
    'EXECUTEDCOM': ('access_holder', 'privilege_target'),
    'SQLADMIN': ('access_holder', 'privilege_target'),

    # ACL abuse - TARGET is compromisable (you can modify the target)
    'GENERICALL': ('access_holder', 'compromisable_entity'),
    'GENERICWRITE': ('access_holder', 'compromisable_entity'),
    'WRITEDACL': ('access_holder', 'compromisable_entity'),
    'WRITEOWNER': ('access_holder', 'compromisable_entity'),
    'FORCECHANGEPASSWORD': ('access_holder', 'compromisable_entity'),
    'ADDMEMBER': ('access_holder', 'compromisable_entity'),
    'ADDSELF': ('access_holder', 'compromisable_entity'),
    'ADDKEYCREDENTIALLINK': ('access_holder', 'compromisable_entity'),
    'WRITESPN': ('access_holder', 'compromisable_entity'),
    'OWNS': ('access_holder', 'compromisable_entity'),
    'ALLEXTENDEDRIGHTS': ('access_holder', 'compromisable_entity'),

    # DCSync - SOURCE has excessive rights (remove the rights from source)
    'DCSYNC': ('compromisable_entity', 'privilege_target'),
    'GETCHANGES': ('compromisable_entity', 'privilege_target'),
    'GETCHANGESALL': ('compromisable_entity', 'privilege_target'),
    'GETCHANGESINFILEREDSET': ('compromisable_entity', 'privilege_target'),

    # Delegation - SOURCE can impersonate (fix delegation on source)
    'ALLOWEDTODELEGATE': ('compromisable_entity', 'privilege_target'),
    'ALLOWEDTOACTONBEHALFOFOTHERIDENTITY': ('compromisable_entity', 'privilege_target'),
    'TRUSTEDTOAUTH': ('compromisable_entity', 'attack_vector'),
    'UNCONSTRAINEDDELEGATION': ('compromisable_entity', 'attack_vector'),

    # Coercion - TARGET gets coerced
    'COERCETOTGT': ('access_holder', 'compromisable_entity'),

    # Session - Shows where creds are
    'HASSESSION': ('compromisable_entity', 'privilege_target'),

    # ADCS - All ESC attack variants (ESC1-ESC15)
    'ADCSESC1': ('access_holder', 'compromisable_entity'),
    'ADCSESC2': ('access_holder', 'compromisable_entity'),
    'ADCSESC3': ('access_holder', 'compromisable_entity'),
    'ADCSESC4': ('access_holder', 'compromisable_entity'),
    'ADCSESC5': ('access_holder', 'compromisable_entity'),
    'ADCSESC6': ('access_holder', 'compromisable_entity'),
    'ADCSESC7': ('access_holder', 'compromisable_entity'),
    'ADCSESC8': ('access_holder', 'compromisable_entity'),
    'ADCSESC9': ('access_holder', 'compromisable_entity'),
    'ADCSESC10': ('access_holder', 'compromisable_entity'),
    'ADCSESC11': ('access_holder', 'compromisable_entity'),
    'ADCSESC12': ('access_holder', 'compromisable_entity'),
    'ADCSESC13': ('access_holder', 'compromisable_entity'),
    'ADCSESC14': ('access_holder', 'compromisable_entity'),
    'ADCSESC15': ('access_holder', 'compromisable_entity'),
    'ENROLL': ('access_holder', 'attack_vector'),
    'AUTOENROLL': ('access_holder', 'attack_vector'),
    'MANAGECA': ('access_holder', 'compromisable_entity'),
    'MANAGECERTIFICATES': ('access_holder', 'compromisable_entity'),
    'GOLDENCERT': ('access_holder', 'compromisable_entity'),

    # GPO
    'GPLINK': ('access_holder', 'privilege_target'),
    'CONTAINS': ('access_holder', 'privilege_target'),
}


def get_entity_roles(edge_type: str) -> tuple:
    """
    Get (source_role, target_role) for an edge type.
    Returns ('unknown', 'unknown') for unmapped edges.
    """
    if not edge_type:
        return ('unknown', 'unknown')
    return EDGE_ROLE_MAPPING.get(edge_type.upper(), ('unknown', 'unknown'))


def _get_node_name(node: Dict[str, Any]) -> str:
    """
    Extract node name from various possible BloodHound property names.
    BloodHound CE may use different properties depending on node type.

    Node structure can be:
    1. Direct properties: {'name': 'USER@DOMAIN', ...}
    2. Nested in 'properties': {'id': ..., 'labels': [...], 'properties': {'name': 'USER@DOMAIN', ...}}
    """
    # Try common property names in order of preference
    name_properties = ['name', 'samaccountname', 'displayname', 'distinguishedname', 'objectid']

    # First, check if properties are nested (BloodHound CE format)
    props = node.get('properties', node)  # Use 'properties' if exists, else use node directly

    for prop in name_properties:
        value = props.get(prop)
        if value and isinstance(value, str) and value.strip():
            return value.strip()

    # Also check at top level in case of mixed format
    if props is not node:
        for prop in name_properties:
            value = node.get(prop)
            if value and isinstance(value, str) and value.strip():
                return value.strip()

    # Last resort: try to find any string value that looks like an AD name
    for key, value in props.items():
        if isinstance(value, str) and '@' in value:
            return value

    return 'Unknown'


def _extract_attack_properties(node: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract attack-relevant properties from a Neo4j node.

    These properties are CRITICAL for the model to identify available attack vectors:
    - hasspn: true → Kerberoastable
    - dontreqpreauth: true → AS-REP roastable
    - serviceprincipalnames: [...] → SPNs to target
    - unconstraineddelegation: true → Unconstrained delegation attack
    - trustedtoauth: true → Constrained delegation (S4U2Self/Proxy)
    - enabled: true/false → Whether account is active
    - admincount: 1 → Admin-protected account
    """
    props = node.get('properties', node)  # Handle nested properties

    attack_props = {}

    # Key attack vector indicators
    attack_relevant_keys = [
        'hasspn',                    # Kerberoastable
        'serviceprincipalnames',     # SPNs for Kerberoasting
        'dontreqpreauth',            # AS-REP roastable
        'unconstraineddelegation',   # Unconstrained delegation
        'trustedtoauth',             # Constrained delegation
        'allowedtodelegate',         # Delegation targets
        'enabled',                   # Account active status
        'admincount',                # Admin-protected
        'pwdlastset',                # Password age
        'lastlogon',                 # Activity indicator
        'description',               # May contain sensitive info
        'isdc',                      # Is Domain Controller
        'highvalue',                 # BloodHound high-value flag
        'owned',                     # BloodHound owned flag
    ]

    for key in attack_relevant_keys:
        # Check both lowercase and original case
        value = props.get(key) or props.get(key.lower())
        if value is not None:
            attack_props[key] = value

    return attack_props


def _extract_edges_from_results(results: List[Dict]) -> List[str]:
    """
    Extract actual edge types from converted results.
    This is more accurate than inferring from query name, especially for
    shortestPath queries that can contain various edge types.
    """
    edges = set()
    for result in results:
        # Check edge_type field (primary)
        edge_type = result.get('edge_type', '')
        if edge_type and edge_type not in ['Unknown', '', 'MemberOf']:
            edges.add(edge_type)

        # Check path_edges for multi-hop paths
        path_edges = result.get('path_edges', [])
        for edge in path_edges:
            if edge and edge not in ['Unknown', '', 'MemberOf']:
                edges.add(edge)

        # Check relationship field
        rel = result.get('relationship', '')
        if rel and rel not in ['Unknown', '', 'MemberOf']:
            edges.add(rel)

    # Convert to list, prioritize actionable edges
    edge_list = list(edges)

    # If we only have MemberOf or empty, return that
    if not edge_list:
        for result in results:
            edge_type = result.get('edge_type', '')
            if edge_type and edge_type != 'Unknown':
                edge_list.append(edge_type)
                break

    return edge_list if edge_list else ['Unknown']


def _infer_edges_used_from_query(query_name: str, cypher: str = "") -> List[str]:
    """
    Infer canonical edges_used from query name and cypher.
    Returns CANONICAL attack type names (Kerberoastable, ASREPRoastable, DCSync, etc.)
    that map to OPSEC templates and edge templates.
    """
    query_lower = query_name.lower()
    cypher_lower = cypher.lower() if cypher else ""

    # Check query name and cypher for attack patterns
    # Return canonical names that match opsec_templates.py

    # Kerberoasting detection
    if 'kerberoast' in query_lower or 'hasspn' in query_lower or 'spn' in query_lower:
        return ['Kerberoastable']
    if 'hasspn' in cypher_lower or '{hasspn: true}' in cypher_lower:
        return ['Kerberoastable']

    # AS-REP Roasting detection
    if 'asrep' in query_lower or 'as-rep' in query_lower or 'dontreqpreauth' in query_lower:
        return ['ASREPRoastable']
    if 'dontreqpreauth' in cypher_lower or '{dontreqpreauth: true}' in cypher_lower:
        return ['ASREPRoastable']

    # DCSync detection
    if 'dcsync' in query_lower or 'getchanges' in query_lower:
        return ['DCSync', 'GetChanges', 'GetChangesAll']
    if 'getchanges' in cypher_lower or 'getchangesall' in cypher_lower:
        return ['DCSync', 'GetChanges', 'GetChangesAll']

    # RBCD detection
    if 'rbcd' in query_lower or 'allowedtoact' in query_lower or 'resource-based' in query_lower:
        return ['AllowedToAct']

    # Constrained Delegation detection
    if 'delegation' in query_lower and 'constrained' in query_lower:
        return ['AllowedToDelegate']
    elif 'delegation' in query_lower:
        return ['AllowedToDelegate']

    # AdminTo detection
    if 'local admin' in query_lower or 'adminto' in query_lower:
        return ['AdminTo']

    # ACL attacks
    if 'genericall' in query_lower:
        return ['GenericAll']
    if 'genericwrite' in query_lower:
        return ['GenericWrite']
    if 'writedacl' in query_lower:
        return ['WriteDacl']
    if 'writeowner' in query_lower:
        return ['WriteOwner']
    if 'addmember' in query_lower:
        return ['AddMember']

    # ADCS attacks
    if 'esc1' in query_lower or 'esc2' in query_lower or 'esc3' in query_lower or 'adcs' in query_lower:
        return ['ADCS']

    # Session detection
    if 'session' in query_lower:
        return ['HasSession']

    # Group membership
    if 'group' in query_lower or 'nested' in query_lower or 'memberof' in query_lower:
        return ['MemberOf']

    # Shadow Credentials
    if 'shadow' in query_lower or 'keycredential' in query_lower:
        return ['AddKeyCredentialLink']

    return ['Unknown']


def _infer_edge_type_from_query(query_name: str, finding: Dict[str, Any]) -> str:
    """Infer edge type from query name if not in finding"""
    query_lower = query_name.lower()

    # Check finding first for relationship info
    if finding.get('path_edges'):
        edges = finding.get('path_edges', [])
        if edges:
            return edges[-1]  # Last edge is usually the critical one

    # Use the same canonical names as _infer_edges_used_from_query
    if 'kerberoast' in query_lower or 'hasspn' in query_lower:
        return 'Kerberoastable'
    elif 'asrep' in query_lower or 'as-rep' in query_lower:
        return 'ASREPRoastable'
    elif 'dcsync' in query_lower or 'getchanges' in query_lower:
        return 'DCSync'
    elif 'admin' in query_lower and 'local' in query_lower:
        return 'AdminTo'
    elif 'delegation' in query_lower:
        return 'AllowedToDelegate'
    elif 'genericall' in query_lower or 'acl' in query_lower:
        return 'GenericAll'
    elif 'session' in query_lower:
        return 'HasSession'
    elif 'group' in query_lower or 'nested' in query_lower:
        return 'MemberOf'
    else:
        return 'Unknown'


def _convert_path_result_to_finding(result: Dict[str, Any], query_name: str = "") -> Dict[str, Any]:
    """
    Convert a path-based query result (RETURN p) to standard finding format.

    Path results can have two structures:
    1. {'p': {'nodes': [...], 'relationships': [...], 'length': N}}
    2. {'p': {'start': {...}, 'end': {...}, 'segments': [...]}}  (BloodHound CE format)

    We need to extract: source, target, edge_type, source_type, target_type
    """
    # Check if this is a path result
    path_data = result.get('p') or result.get('path')

    if path_data and isinstance(path_data, dict):
        # Handle BloodHound CE format: {'start': {...}, 'end': {...}, 'segments': [...]}
        if 'start' in path_data and 'end' in path_data:
            source_node = path_data['start']
            target_node = path_data['end']
            segments = path_data.get('segments', [])

            # Use robust name extraction
            source_name = _get_node_name(source_node)
            target_name = _get_node_name(target_node)

            # Get types from labels (may be 'labels' or '_labels')
            source_labels = source_node.get('labels', source_node.get('_labels', []))
            target_labels = target_node.get('labels', target_node.get('_labels', []))

            source_type = next((l for l in source_labels if l != 'Base' and not l.startswith('Tag_')), 'Unknown')
            target_type = next((l for l in target_labels if l != 'Base' and not l.startswith('Tag_')), 'Unknown')

            # Extract ALL edges from segments (for multi-hop chain display)
            all_edges = []
            intermediate_nodes = []
            if segments:
                for idx, seg in enumerate(segments):
                    rel_data = seg.get('relationship', seg)
                    if isinstance(rel_data, dict):
                        all_edges.append(rel_data.get('type', rel_data.get('relType', 'Unknown')))
                    else:
                        all_edges.append('Unknown')
                    # Collect intermediate node names (not first source, not last target)
                    if idx < len(segments) - 1:
                        end_node = seg.get('end', {})
                        end_props = end_node.get('properties', end_node)
                        mid_name = end_props.get('name', '')
                        if mid_name:
                            intermediate_nodes.append(mid_name)

            # Pick the last non-MemberOf edge as primary edge_type
            non_memberof = [e for e in all_edges if e.upper() != 'MEMBEROF']
            edge_type = non_memberof[-1] if non_memberof else (all_edges[0] if all_edges else 'Unknown')

            add_log("DEBUG", f"Converted (start/end format): source={source_name}, target={target_name}, edge={edge_type}, hops={len(all_edges)}")

            # Extract attack-relevant properties from nodes
            source_props = _extract_attack_properties(source_node)
            target_props = _extract_attack_properties(target_node)

            # Get entity roles based on edge type
            source_role, target_role = get_entity_roles(edge_type)

            return {
                'source': source_name,
                'target': target_name,
                'edge_type': edge_type,
                'source_type': source_type,
                'target_type': target_type,
                'source_role': source_role,
                'target_role': target_role,
                'path_length': len(segments),
                'raw_path': path_data,
                # CRITICAL: Include attack-relevant node properties
                'source_properties': source_props,
                'target_properties': target_props,
                # Multi-hop chain data
                'path_edges': all_edges,
                'intermediate_nodes': intermediate_nodes,
            }

        # Handle standard format: {'nodes': [...], 'relationships': [...]}
        elif 'nodes' in path_data:
            nodes = path_data.get('nodes', [])
            relationships = path_data.get('relationships', [])

            # Debug: Log what we're processing
            add_log("DEBUG", f"Converting path result: {len(nodes)} nodes, {len(relationships)} relationships")
            if nodes and len(nodes) > 0:
                first_node = nodes[0]
                add_log("DEBUG", f"First node keys: {list(first_node.keys())}")
                # Log actual values to understand structure
                add_log("DEBUG", f"First node name: {first_node.get('name', 'NOT_FOUND')}")
                add_log("DEBUG", f"First node _labels: {first_node.get('_labels', [])}")

            if len(nodes) >= 2:
                # Get source (first node) and target (last node)
                source_node = nodes[0]
                target_node = nodes[-1]

                # Use robust name extraction
                source_name = _get_node_name(source_node)
                target_name = _get_node_name(target_node)

                logger.debug(f"Extracted: source={source_name}, target={target_name}")

                # Get types from _labels
                source_labels = source_node.get('_labels', [])
                target_labels = target_node.get('_labels', [])

                source_type = next((l for l in source_labels if l != 'Base' and not l.startswith('Tag_')), 'Unknown')
                target_type = next((l for l in target_labels if l != 'Base' and not l.startswith('Tag_')), 'Unknown')

                # Extract ALL edge types from relationships
                all_edges = []
                intermediate_nodes = []
                for r in relationships:
                    all_edges.append(r.get('type', 'Unknown') if isinstance(r, dict) else 'Unknown')
                # Collect intermediate node names (middle nodes)
                for mid_node in nodes[1:-1]:
                    mid_name = _get_node_name(mid_node)
                    if mid_name:
                        intermediate_nodes.append(mid_name)

                # Pick the last non-MemberOf edge as primary edge_type
                non_memberof = [e for e in all_edges if e.upper() != 'MEMBEROF']
                edge_type = non_memberof[-1] if non_memberof else (all_edges[0] if all_edges else 'Unknown')

                # Extract attack-relevant properties from nodes
                source_props = _extract_attack_properties(source_node)
                target_props = _extract_attack_properties(target_node)

                # Get entity roles based on edge type
                source_role, target_role = get_entity_roles(edge_type)

                converted = {
                    'source': source_name,
                    'target': target_name,
                    'edge_type': edge_type,
                    'source_type': source_type,
                    'target_type': target_type,
                    'source_role': source_role,
                    'target_role': target_role,
                    'path_length': len(nodes) - 1,
                    'raw_path': path_data,
                    # CRITICAL: Include attack-relevant node properties
                    'source_properties': source_props,
                    'target_properties': target_props,
                    # Multi-hop chain data
                    'path_edges': all_edges,
                    'intermediate_nodes': intermediate_nodes,
                }
                logger.debug(f"Converted result: source={source_name}, target={target_name}, edge={edge_type}")
                return converted

            elif len(nodes) == 1:
                # Single node result (e.g., Kerberoastable users)
                node = nodes[0]
                node_labels = node.get('_labels', [])
                node_type = next((l for l in node_labels if l != 'Base' and not l.startswith('Tag_')), 'Unknown')
                node_name = _get_node_name(node)

                # Extract attack-relevant properties
                node_props = _extract_attack_properties(node)

                # Infer edge type from query for single node results
                inferred_edge = _infer_edge_type_from_query(query_name, {})
                source_role, target_role = get_entity_roles(inferred_edge)

                return {
                    'source': node_name,
                    'target': node.get('domain', 'Unknown'),
                    'edge_type': inferred_edge,
                    'source_type': node_type,
                    'target_type': 'Domain',
                    'source_role': source_role,
                    'target_role': target_role,
                    'path_length': 0,
                    'raw_path': path_data,
                    # CRITICAL: Include attack-relevant node properties
                    'source_properties': node_props,
                    'target_properties': {},
                }

    # Check for raw node results from chat queries (e.g., {'u': {'labels': [...], 'properties': {...}}})
    # These come from queries like RETURN u (not RETURN p)
    for key, val in result.items():
        if isinstance(val, dict) and 'labels' in val and 'properties' in val:
            node = val
            node_name = _get_node_name(node)
            node_labels = node.get('labels', [])
            node_type = next((l for l in node_labels if l != 'Base' and not l.startswith('Tag_')), 'Unknown')
            node_props = _extract_attack_properties(node)

            # Infer edge type from query name
            inferred_edge = _infer_edge_type_from_query(query_name, {})
            source_role, target_role = get_entity_roles(inferred_edge)

            # Extract domain from node name
            domain = node_name.split('@')[-1] if '@' in node_name else ''

            return {
                'source': node_name,
                'target': domain or 'Unknown',
                'edge_type': inferred_edge,
                'source_type': node_type,
                'target_type': 'Domain',
                'source_role': source_role,
                'target_role': target_role,
                'path_length': 0,
                'raw_path': None,
                'source_properties': node_props,
                'target_properties': {},
                'path_edges': [],
                'intermediate_nodes': [],
            }

    # Not a path or node result, return as-is with defaults
    # Extract edge_type from result for role determination
    edge_type = result.get('edge_type', result.get('rel_type', result.get('relationship', 'Unknown')))
    source_role, target_role = get_entity_roles(edge_type)

    return {
        'source': result.get('source', result.get('user', result.get('name', 'Unknown'))),
        'target': result.get('target', result.get('computer', result.get('group', 'Unknown'))),
        'edge_type': edge_type,
        'source_type': result.get('source_type', 'Unknown'),
        'target_type': result.get('target_type', 'Unknown'),
        'source_role': source_role,
        'target_role': target_role,
        **result  # Preserve any other fields
    }


def _infer_attack_type(query_name: str) -> str:
    """Infer attack type from query name"""
    name_lower = query_name.lower()
    if 'kerberos' in name_lower or 'dcsync' in name_lower or 'roast' in name_lower:
        return "credential_access"
    elif 'admin' in name_lower or 'lateral' in name_lower or 'session' in name_lower:
        return "lateral_movement"
    elif 'delegation' in name_lower or 'genericall' in name_lower or 'writedacl' in name_lower:
        return "privilege_escalation"
    else:
        return "unknown"


def _infer_priority(query_name: str, results: List[Dict]) -> str:
    """Infer priority from query name and results"""
    name_lower = query_name.lower()
    if 'domain admin' in name_lower or 'dcsync' in name_lower:
        return "Critical"
    elif 'kerberos' in name_lower or 'delegation' in name_lower or 'genericall' in name_lower:
        return "High"
    else:
        return "Medium"


def _convert_results_to_scenarios(query_results: List[QueryResult]) -> List[Dict[str, Any]]:
    """Convert query results to attack scenario format"""
    scenarios = []

    # Log details about each query result for debugging
    for i, qr in enumerate(query_results, 1):
        add_log("DEBUG", f"  Query {i}: '{qr.query_name}' - results: {qr.result_count}, error: {qr.error or 'None'}")

    for i, qr in enumerate(query_results, 1):
        # Skip failed queries or empty results
        if qr.error:
            add_log("WARNING", f"  ⚠️ Query '{qr.query_name}' failed: {qr.error}")
            continue
        if qr.result_count == 0:
            add_log("INFO", f"  ⏭️ Query '{qr.query_name}' returned 0 results (skipping)")
            continue

        # Skip info/summary queries
        if 'summary' in qr.query_name.lower() or qr.query_name == 'Edge Type Summary':
            continue

        # Skip target discovery queries — these are utility queries for chain
        # discovery, not attack findings (they return groups/domains/DCs as targets)
        TARGET_DISCOVERY_NAMES = {'High-Value Target Groups', 'Domain Objects', 'Domain Controllers'}
        if qr.query_name in TARGET_DISCOVERY_NAMES:
            add_log("INFO", f"  ⏭️ Query '{qr.query_name}' is target discovery (skipping scenario conversion)")
            continue

        # Convert path results to standard finding format
        converted_results = []

        # Log first result structure for debugging
        if qr.results:
            first_result = qr.results[0]
            add_log("INFO", f"🔍 First result structure for '{qr.query_name}':")
            add_log("INFO", f"   Keys: {list(first_result.keys())}")
            if 'p' in first_result:
                p_val = first_result['p']
                add_log("INFO", f"   'p' type: {type(p_val).__name__}")
                if isinstance(p_val, dict):
                    add_log("INFO", f"   'p' keys: {list(p_val.keys())}")
                    # Handle BloodHound CE format: start/end/segments
                    if 'start' in p_val:
                        start_node = p_val['start']
                        add_log("INFO", f"   'start' node keys: {list(start_node.keys()) if isinstance(start_node, dict) else 'NOT DICT'}")
                        if isinstance(start_node, dict):
                            # Check nested properties for name
                            props = start_node.get('properties', {})
                            add_log("INFO", f"   'start' properties keys: {list(props.keys()) if isinstance(props, dict) else 'N/A'}")
                            add_log("INFO", f"   'start' name (from properties): {props.get('name', 'NOT FOUND') if isinstance(props, dict) else 'N/A'}")
                            add_log("INFO", f"   'start' labels: {start_node.get('labels', start_node.get('_labels', 'NOT FOUND'))}")
                    # Handle standard format: nodes/relationships
                    elif 'nodes' in p_val and p_val['nodes']:
                        add_log("INFO", f"   First node keys: {list(p_val['nodes'][0].keys())}")
                        add_log("INFO", f"   First node name: {p_val['nodes'][0].get('name', 'NOT FOUND')}")
            else:
                add_log("INFO", f"   No 'p' key! Full result: {str(first_result)[:400]}")

        for result in qr.results:
            converted = _convert_path_result_to_finding(result, qr.query_name)
            converted_results.append(converted)

        # Log conversion success
        if converted_results:
            sample = converted_results[0]
            add_log("DEBUG", f"  📊 Converted {len(converted_results)} results for '{qr.query_name}'")
            add_log("DEBUG", f"     Sample: source={sample.get('source', 'N/A')}, target={sample.get('target', 'N/A')}, edge={sample.get('edge_type', 'N/A')}")

        # CRITICAL: Extract edges from actual results first, then fall back to query inference
        edges_used = _extract_edges_from_results(converted_results)
        if not edges_used or edges_used == ['Unknown']:
            # Fall back to query name inference
            edges_used = _infer_edges_used_from_query(qr.query_name, qr.cypher)
            add_log("INFO", f"   📋 Inferred edges_used from query: {edges_used}")
        else:
            add_log("INFO", f"   📋 Extracted edges_used from results: {edges_used}")

        scenario = {
            "scenario_number": i,
            "query_info": {
                "name": qr.query_name,
                "description": "",
                "cypher_query": qr.cypher,
                "cypher": qr.cypher,  # Alias for compatibility
                "attack_type": _infer_attack_type(qr.query_name),
                "priority": _infer_priority(qr.query_name, converted_results),
                "edges_used": edges_used  # CRITICAL: Canonical attack type names for template selection
            },
            "results": converted_results,  # Use converted results
            "result_count": qr.result_count,
            "query": qr.cypher,
            "cypher_query": qr.cypher
        }
        scenarios.append(scenario)

    return scenarios


def split_disconnected_scenarios(scenarios: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Split scenarios with disconnected result subgraphs into separate scenarios.

    When a query like "Outbound Object Control" returns:
      OLIVIA → MICHAEL (GenericAll)
      MICHAEL → BENJAMIN (ForceChangePassword)
      EMILY → ETHAN (GenericWrite)

    The first two form a connected chain (MICHAEL appears as both target and source).
    EMILY → ETHAN is disconnected. Sending all 3 in one scenario confuses the LLM.

    This splits them into:
      Scenario A: OLIVIA → MICHAEL, MICHAEL → BENJAMIN (connected chain)
      Scenario B: EMILY → ETHAN (separate finding)

    Only splits scenarios with multiple DIFFERENT edge types (mixed ACL findings).
    Single-edge-type scenarios (e.g., all MemberOf) are left alone.
    """
    output = []

    for scenario in scenarios:
        results = scenario.get('results', [])
        edges_used = scenario.get('query_info', {}).get('edges_used', [])

        # Only split scenarios with multiple edge types and multiple results
        # Single-edge scenarios (all MemberOf, all GenericAll) stay together
        unique_edges = set(e for e in edges_used if e.upper() != 'MEMBEROF')
        if len(unique_edges) <= 1 or len(results) <= 1:
            output.append(scenario)
            continue

        # Build connected components using Union-Find on entity overlap
        # Two results are connected if they share an entity (target of one = source of another)
        n = len(results)
        parent = list(range(n))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        # Extract entity sets per result
        def _entity_name(name: str) -> str:
            return name.upper().split('@')[0].strip() if name else ''

        result_entities = []
        for r in results:
            entities = set()
            s = _entity_name(r.get('source', ''))
            t = _entity_name(r.get('target', ''))
            if s:
                entities.add(s)
            if t:
                entities.add(t)
            result_entities.append(entities)

        # Union results that share entities (connected in the graph)
        for i in range(n):
            for j in range(i + 1, n):
                if result_entities[i] & result_entities[j]:
                    union(i, j)

        # Group results by component
        components: Dict[int, List[int]] = {}
        for i in range(n):
            root = find(i)
            components.setdefault(root, []).append(i)

        # If only one component, no split needed
        if len(components) <= 1:
            output.append(scenario)
            continue

        # Split into separate scenarios with descriptive titles
        base_name = scenario['query_info']['name']
        for comp_indices in components.values():
            comp_results = [results[i] for i in comp_indices]
            comp_edges = list(dict.fromkeys(
                r.get('edge_type', '') for r in comp_results
                if r.get('edge_type', '')
            ))

            # Build descriptive suffix showing chain start → end
            # For multi-result components, find the chain start (source not a target)
            all_targets = {r.get('target', '').upper().split('@')[0] for r in comp_results}
            chain_start = comp_results[0]
            for r in comp_results:
                src_name = r.get('source', '').upper().split('@')[0]
                if src_name not in all_targets:
                    chain_start = r
                    break

            src = chain_start.get('source', '').split('@')[0]
            tgt = chain_start.get('target', '').split('@')[0]
            edge = chain_start.get('edge_type', '')
            if len(comp_results) > 1:
                # Multi-hop chain: show start → final target
                final = comp_results[-1] if comp_results[-1] != chain_start else comp_results[0]
                final_tgt = final.get('target', '').split('@')[0]
                suffix = f"{src} → {final_tgt} ({', '.join(comp_edges)})"
            else:
                suffix = f"{src} → {tgt} ({edge})"

            split_scenario = {
                "scenario_number": scenario["scenario_number"],
                "query_info": {
                    **scenario["query_info"],
                    "name": f"{base_name} — {suffix}",
                    "edges_used": comp_edges,
                },
                "results": comp_results,
                "result_count": len(comp_results),
                "query": scenario.get("query", ""),
                "cypher_query": scenario.get("cypher_query", ""),
            }
            output.append(split_scenario)

        add_log("INFO", f"  ✂️ Split '{scenario['query_info']['name']}' into {len(components)} sub-scenarios ({len(results)} results → {[len(v) for v in components.values()]})")

    # Renumber
    for i, s in enumerate(output, 1):
        s["scenario_number"] = i

    return output

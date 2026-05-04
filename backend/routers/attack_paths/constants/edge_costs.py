"""
Edge Cost Model for Weighted Attack Path Discovery
Location: backend/routers/attack_paths/constants/edge_costs.py

Implements autobloody's exploitation cost model for ranking attack paths
by difficulty. Lower cost = easier to exploit = higher risk.

Cost tiers:
  0       — Free (MemberOf group inheritance)
  1-5     — Trivial (direct domain compromise: DCSync, ADCS ESC, ACL abuse)
  10-20   — Easy (credential reads, lateral movement with admin)
  50-100  — Moderate (group manipulation, delegation abuse, enrollment)
  200-600 — Hard (user/computer takeover via ACL, OU manipulation)
  10K-12K — Very hard (GPO manipulation)
  50K     — Noisiest (password change, can break services)

Source: https://github.com/CravateRouge/autobloody
"""

from typing import List


# Autobloody's cost model — maps (edge_types, target_label) to exploitation cost
# EVERY edge in EXPLOITABLE_EDGES must have at least one cost entry here,
# otherwise it defaults to 9,999,999 penalty (effectively blocked).
EDGE_COSTS = [
    # =========================================================================
    # Free — group membership inheritance
    # =========================================================================
    {"cost": 0, "edges": "MemberOf", "endnode": "Group"},

    # =========================================================================
    # Trivial — direct domain compromise (cost 1-5)
    # =========================================================================
    {"cost": 1, "edges": "DCSync|GetChanges|GetChangesAll|GenericAll|AllExtendedRights", "endnode": "Domain"},
    {"cost": 2, "edges": "WriteDacl|Owns", "endnode": "Domain"},
    {"cost": 3, "edges": "WriteOwner", "endnode": "Domain"},

    # ADCS ESC edges: certificate abuse for domain compromise
    # BloodHound CE v5+ shortcut edges — prerequisites already confirmed by BH.
    # Costs reflect EXECUTION difficulty given that prerequisites are met.
    #
    # Tier 1 (cost 5): Single command, direct exploitation
    #   ESC1  — certipy req with SAN → instant DA (most common)
    #   ESC6  — EDITF_ATTRIBUTESUBJECTALTNAME2 flag → SAN in any request
    #   ESC9  — no security extension → UPN swap + cert request
    #   ESC16 — CA-wide ESC9 override → same as ESC9 but all templates
    {"cost": 5, "edges": "ADCSESC1|ADCSESC6|ADCSESC9|ADCSESC16", "endnode": "Domain"},
    {"cost": 5, "edges": "ADCSESC1|ADCSESC6|ADCSESC9|ADCSESC16", "endnode": ""},
    #
    # Tier 2 (cost 10): Multi-step but straightforward
    #   ESC2  — Any Purpose EKU, use cert for auth
    #   ESC3  — enrollment agent template, two cert requests
    #   ESC13 — issuance policy OID grants group membership via cert
    #   ESC15 — v1 template application policy override (CVE-2024-49019)
    {"cost": 10, "edges": "ADCSESC2|ADCSESC3|ADCSESC13|ADCSESC15", "endnode": "Domain"},
    {"cost": 10, "edges": "ADCSESC2|ADCSESC3|ADCSESC13|ADCSESC15", "endnode": ""},
    #
    # Tier 3 (cost 25): Requires modifying AD objects (noisier)
    #   ESC4  — modify template flags → exploit as ESC1 → cleanup
    #   ESC5  — modify CA config or create template → exploit
    #   ESC10 — weak cert mapping, write altSecurityIdentities
    #   ESC14 — advanced cert mapping, shadow creds + cert
    {"cost": 25, "edges": "ADCSESC4|ADCSESC5|ADCSESC10|ADCSESC14", "endnode": "Domain"},
    {"cost": 25, "edges": "ADCSESC4|ADCSESC5|ADCSESC10|ADCSESC14", "endnode": ""},
    #
    # Tier 4 (cost 50): Requires relay infrastructure or CA admin
    #   ESC7  — ManageCA → modify CA settings → approve/issue certs
    #   ESC8  — NTLM relay to ADCS HTTP enrollment endpoint
    #   ESC11 — RPC relay (unencrypted ICPR requests)
    {"cost": 50, "edges": "ADCSESC7|ADCSESC8|ADCSESC11", "endnode": "Domain"},
    {"cost": 50, "edges": "ADCSESC7|ADCSESC8|ADCSESC11", "endnode": ""},
    #
    # Tier 5 (cost 100): Requires CA server compromise
    #   ESC12 — extract CA private key → forge golden certificate
    {"cost": 100, "edges": "ADCSESC12", "endnode": "Domain"},
    {"cost": 100, "edges": "ADCSESC12", "endnode": ""},
    # ADCS administration — ManageCA enables ESC7-style attacks
    {"cost": 50, "edges": "ManageCA|ManageCertificates", "endnode": ""},
    # Certificate enrollment — part of ADCS attack chains
    {"cost": 50, "edges": "Enroll|AutoEnroll", "endnode": ""},

    # =========================================================================
    # Easy — credential reads, lateral movement with admin (cost 10-20)
    # =========================================================================
    {"cost": 10, "edges": "ReadGMSAPassword", "endnode": ""},
    {"cost": 10, "edges": "ReadLAPSPassword", "endnode": ""},
    {"cost": 15, "edges": "AdminTo", "endnode": ""},
    {"cost": 15, "edges": "SQLAdmin", "endnode": ""},
    {"cost": 20, "edges": "CanPSRemote|CanRDP|ExecuteDCOM", "endnode": ""},
    {"cost": 20, "edges": "HasSIDHistory", "endnode": ""},
    # Session on computer — need admin on the computer to dump credentials
    {"cost": 20, "edges": "HasSession", "endnode": ""},
    # Filtered DCSync — partial replication rights
    {"cost": 5, "edges": "GetChangesInFilteredSet", "endnode": "Domain"},

    # =========================================================================
    # Moderate — group manipulation, delegation, coercion (cost 50-300)
    # =========================================================================
    {"cost": 50, "edges": "AllowedToDelegate|AllowedToAct", "endnode": ""},
    {"cost": 50, "edges": "CoerceToTGT", "endnode": ""},
    # NTLM relay — BH CE shortcut edges for coercion + relay chains
    {"cost": 50, "edges": "CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS|CoerceAndRelayNTLMToADCS", "endnode": ""},
    # RBCD setup — write msDS-AllowedToActOnBehalfOfOtherIdentity
    {"cost": 100, "edges": "WriteAccountRestrictions", "endnode": ""},
    {"cost": 100, "edges": "AddSelf|AddMember|GenericAll|GenericWrite|AllExtendedRights", "endnode": "Group"},
    {"cost": 100, "edges": "AddKeyCredentialLink", "endnode": ""},
    {"cost": 100, "edges": "WriteSPN", "endnode": ""},
    {"cost": 200, "edges": "WriteDacl|Owns", "endnode": "Group"},
    {"cost": 300, "edges": "WriteOwner", "endnode": "Group"},

    # =========================================================================
    # Hard — OU manipulation (cost 400-600)
    # =========================================================================
    {"cost": 400, "edges": "GenericWrite|GenericAll", "endnode": "OU"},
    {"cost": 500, "edges": "WriteDacl|Owns", "endnode": "OU"},
    {"cost": 600, "edges": "WriteOwner", "endnode": "OU"},

    # =========================================================================
    # Very hard — GPO manipulation (cost 10K-12K)
    # =========================================================================
    {"cost": 10000, "edges": "GenericWrite|GenericAll", "endnode": "GPO"},
    {"cost": 10000, "edges": "GPLink", "endnode": ""},
    {"cost": 11000, "edges": "WriteDacl|Owns", "endnode": "GPO"},
    {"cost": 12000, "edges": "WriteOwner", "endnode": "GPO"},
    # Cross-domain trust abuse
    {"cost": 500, "edges": "TrustedBy", "endnode": ""},

    # =========================================================================
    # User/Computer takeover via ACL abuse (cost 200-600)
    # GenericAll/GenericWrite on User enables Shadow Credentials (certipy shadow auto)
    # — a single-command, reliable technique. NOT 100K difficulty.
    # =========================================================================
    {"cost": 200, "edges": "GenericAll", "endnode": "User"},
    {"cost": 200, "edges": "GenericAll", "endnode": "Computer"},
    {"cost": 250, "edges": "GenericWrite|AllExtendedRights", "endnode": "User"},
    {"cost": 250, "edges": "GenericWrite|AllExtendedRights", "endnode": "Computer"},
    # NOTE: Contains → User/Computer removed. Contains is structural (AD hierarchy),
    # not exploitable. Domain→Contains→User doesn't give you control over the user.
    # OU→Contains→User is only exploitable WITH GenericAll/WriteDacl on the OU (separate edge).
    {"cost": 400, "edges": "WriteDacl|Owns", "endnode": "User"},
    {"cost": 400, "edges": "WriteDacl|Owns", "endnode": "Computer"},
    {"cost": 600, "edges": "WriteOwner", "endnode": "User"},
    {"cost": 600, "edges": "WriteOwner", "endnode": "Computer"},

    # =========================================================================
    # Noisiest — password change (can disrupt services)
    # =========================================================================
    {"cost": 50000, "edges": "ForceChangePassword", "endnode": ""},
]

# All exploitable edge types (for MATCH pattern filtering)
# Every edge here MUST have a cost entry in EDGE_COSTS above
EXPLOITABLE_EDGES = [
    # ACL abuse
    "MemberOf", "GenericAll", "WriteDacl", "WriteOwner", "Owns",
    "AddMember", "AddSelf", "AllExtendedRights", "ForceChangePassword",
    "GenericWrite", "AddKeyCredentialLink", "WriteSPN",
    "WriteAccountRestrictions",
    # Credential access
    "ReadGMSAPassword", "ReadLAPSPassword", "DCSync",
    "GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
    # ADCS exploitation — all 16 BloodHound CE v5+ ESC variants
    "ADCSESC1", "ADCSESC2", "ADCSESC3", "ADCSESC4", "ADCSESC5",
    "ADCSESC6", "ADCSESC7", "ADCSESC8", "ADCSESC9", "ADCSESC10",
    "ADCSESC11", "ADCSESC12", "ADCSESC13", "ADCSESC14", "ADCSESC15", "ADCSESC16",
    # ADCS administration and enrollment
    "ManageCA", "ManageCertificates", "Enroll", "AutoEnroll",
    # Lateral movement
    "SQLAdmin", "CanPSRemote", "CanRDP", "AdminTo", "ExecuteDCOM",
    # Delegation
    "AllowedToDelegate", "AllowedToAct",
    # NTLM relay (BH CE shortcut edges)
    "CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToLDAP",
    "CoerceAndRelayNTLMToLDAPS", "CoerceAndRelayNTLMToADCS",
    # Sessions and trust
    "HasSession", "TrustedBy",
    # Miscellaneous
    "HasSIDHistory", "CoerceToTGT", "GPLink",
    # NOTE: Contains removed from exploitable edges. It's structural (AD hierarchy),
    # not an attack relationship. Domain→Contains→Group doesn't mean you can join that group.
]

# Max hops for variable-length path traversal
# Keep low (6) to avoid combinatorial explosion in Neo4j's BFS
MAX_PATH_HOPS = 6

# Max sources and targets for chain queries
MAX_SOURCES = 15
MAX_TARGETS = 8



def generate_chain_query(source_name: str, target_name: str) -> str:
    """
    Generate a weighted shortest-path query between a source and target.

    Uses allShortestPaths (BFS) instead of variable-length *1..N to avoid
    combinatorial explosion. Costs are computed in Python after extraction.
    """
    edge_pattern = "|".join(EXPLOITABLE_EDGES)

    return f"""MATCH p = allShortestPaths((s)-[:{edge_pattern}*1..{MAX_PATH_HOPS}]->(t))
WHERE s.name = $source AND t.name = $target
AND s <> t
RETURN p
LIMIT 3"""


def generate_reverse_chain_query(target_name: str) -> str:
    """
    Generate a reverse BFS query: find all shortest paths from ANY non-T0
    User/Computer to a specific high-value target.

    Unlike generate_chain_query (which anchors both source and target),
    this only anchors the target — Neo4j finds all reachable sources.
    """
    edge_pattern = "|".join(EXPLOITABLE_EDGES)

    return f"""MATCH p = allShortestPaths((s)-[:{edge_pattern}*1..{MAX_PATH_HOPS}]->(t))
WHERE t.name = $target AND s <> t
AND (s:User OR s:Computer)
AND NOT s.objectid ENDS WITH '-500'
AND NOT s.objectid ENDS WITH '-502'
AND NOT s.objectid ENDS WITH '-512'
AND NOT s.objectid ENDS WITH '-519'
RETURN p
LIMIT 15"""


def get_cost_for_edge(edge_type: str, target_label: str) -> int:
    """
    Look up the exploitation cost for an edge type + target label combination.
    Used by backend scoring when processing path results.
    """
    edge_upper = edge_type.upper()
    target_upper = target_label.upper() if target_label else ""

    for entry in EDGE_COSTS:
        entry_edges = {e.upper() for e in entry["edges"].split("|")}
        entry_endnode = entry["endnode"].upper()

        if edge_upper in entry_edges:
            if not entry_endnode or entry_endnode == target_upper:
                return entry["cost"]

    # Unknown edge — assign max cost
    return 9999999


def classify_cost(total_cost: int) -> str:
    """Classify a path's total cost into a human-readable difficulty level."""
    if total_cost <= 3:
        return "Trivial"
    elif total_cost <= 100:
        return "Easy"
    elif total_cost <= 1000:
        return "Moderate"
    elif total_cost <= 100000:
        return "Hard"
    else:
        return "Very Hard"

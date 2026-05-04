"""
Prompt Helper Functions for Attack Path Report Generation
Location: backend/routers/attack_paths/constants/prompt_templates.py

Helper functions for building prompt context (remediation targeting, T0 context, attack path formatting).
The actual prompt templates are in dynamic_prompts.py — see get_prompt_for_edges() for edge-specific selection.
"""

from typing import List


# =============================================================================
# REMEDIATION TARGETING - Ensures LLM targets correct entities
# =============================================================================

REMEDIATION_CONTEXT_TEMPLATE = """
## Remediation Targets (CRITICAL - READ CAREFULLY)

The following entities are COMPROMISABLE and MUST be the focus of remediation:
{compromisable_entities_list}

The following are PRIVILEGE TARGETS (groups/resources) - do NOT remediate these directly:
{privilege_targets_list}

MANDATORY RULES FOR REMEDIATION:
1. Remediation scripts MUST target the COMPROMISABLE entities listed above
2. NEVER generate commands like: Set-ADAccountPassword -Identity 'DOMAIN ADMINS'
   (DOMAIN ADMINS is a group, not a user account)
3. For Kerberoastable accounts: Remove the SPN or convert to gMSA
4. For ACL abuse: Remove excessive permissions FROM the source entity
5. The COMPROMISABLE entity is the one with the vulnerability - fix IT, not the group it belongs to
"""


def format_remediation_context(compromisable_entities: List[str], privilege_targets: List[str]) -> str:
    """Format the remediation context for injection into prompts.

    Args:
        compromisable_entities: List of entities that are vulnerable and need remediation
                               (e.g., Kerberoastable users, accounts with weak ACLs)
        privilege_targets: List of high-value targets the attacker gains access to
                          (e.g., Domain Admins group, domain controllers)

    Returns:
        Formatted string to inject into RAG prompts, or empty string if no entities
    """
    if not compromisable_entities:
        return ""

    comp_list = "\n".join(f"  - {e}" for e in compromisable_entities[:5])
    priv_list = "\n".join(f"  - {t}" for t in privilege_targets[:5]) if privilege_targets else "  - (none identified)"

    return REMEDIATION_CONTEXT_TEMPLATE.format(
        compromisable_entities_list=comp_list,
        privilege_targets_list=priv_list
    )


# =============================================================================
# HELPER: Build T0 context string
# =============================================================================
def build_t0_context(t0_assets: list) -> str:
    """Build T0 context string for prompts."""
    if not t0_assets:
        return ""
    return f"\n⚠️ **CRITICAL - TIER 0 ASSETS AT RISK:** {', '.join(t0_assets)}\nThis finding enables direct path to domain compromise."


# =============================================================================
# HELPER: Format attack path for prompt
# =============================================================================
def format_attack_path(findings: list) -> str:
    """Format findings into readable attack path."""
    if not findings:
        return "Unknown path"

    path_parts = []
    for f in findings[:5]:
        source = f.get('source', f.get('start_node', '?'))
        target = f.get('target', f.get('end_node', '?'))
        edge = f.get('edge_type', f.get('relationship', '?'))
        path_parts.append(f"{source} --[{edge}]--> {target}")

    return " → ".join(path_parts) if len(path_parts) <= 3 else "\n".join(path_parts)

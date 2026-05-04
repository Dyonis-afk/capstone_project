"""
Constants for Attack Path Router
"""

from .edge_costs import (
    EDGE_COSTS,
    EXPLOITABLE_EDGES,
    generate_chain_query,
    generate_reverse_chain_query,
    get_cost_for_edge,
    classify_cost,
    MAX_SOURCES,
    MAX_TARGETS,
    MAX_PATH_HOPS,
)
from .edge_templates import (
    EDGE_TYPE_QUERY_TEMPLATES,
    AMSI_BYPASS_TECHNIQUES,
    ETW_BYPASS_TECHNIQUES,
    CLM_BYPASS_TECHNIQUES,
    EVASION_TECHNIQUES,
    # Evasion helpers (Fix 3)
    get_amsi_bypass,
    get_etw_bypass,
    get_evasion_context_for_prompt,
    reset_evasion_tracking,
)
from .static_queries import CORE_STATIC_QUERIES, DISCOVERY_QUERIES, TARGET_DISCOVERY_QUERIES
from .priority import EDGE_PRIORITY_ORDER, ATTACK_CATEGORY_MAP
from .opsec_templates import get_opsec_attack_steps, has_opsec_template, AMSI_BYPASS_ONELINER, extract_dc_hostname
from .prompt_templates import (
    build_t0_context,
    format_attack_path,
    format_remediation_context,
)
# Dynamic prompts - edge-specific prompt selection
from .dynamic_prompts import (
    EDGE_SPECIFIC_PROMPTS,
    EDGE_PRIORITY,
    get_prompt_for_edges,
    get_attack_category,
)

__all__ = [
    # Edge templates
    'EDGE_TYPE_QUERY_TEMPLATES',
    # Evasion techniques (Fix 3: Diversified)
    'AMSI_BYPASS_TECHNIQUES',
    'ETW_BYPASS_TECHNIQUES',
    'CLM_BYPASS_TECHNIQUES',
    'EVASION_TECHNIQUES',
    'get_amsi_bypass',
    'get_etw_bypass',
    'get_evasion_context_for_prompt',
    'reset_evasion_tracking',
    # Edge costs (chain discovery)
    'EDGE_COSTS',
    'EXPLOITABLE_EDGES',
    'generate_chain_query',
    'generate_reverse_chain_query',
    'get_cost_for_edge',
    'classify_cost',
    'MAX_SOURCES',
    'MAX_TARGETS',
    'MAX_PATH_HOPS',
    # Static queries
    'CORE_STATIC_QUERIES',
    'DISCOVERY_QUERIES',
    'TARGET_DISCOVERY_QUERIES',
    # Priority
    'EDGE_PRIORITY_ORDER',
    'ATTACK_CATEGORY_MAP',
    # OPSEC templates (template-first approach)
    'get_opsec_attack_steps',
    'has_opsec_template',
    'AMSI_BYPASS_ONELINER',
    'extract_dc_hostname',
    # Prompt helper functions
    'build_t0_context',
    'format_attack_path',
    'format_remediation_context',
    # Dynamic prompts (edge-specific selection - preferred)
    'EDGE_SPECIFIC_PROMPTS',
    'EDGE_PRIORITY',
    'get_prompt_for_edges',
    'get_attack_category',
]

"""
Services for Attack Path Analysis
Location: backend/routers/attack_paths/services/__init__.py

This module contains service functions for:
- query_generator: RAG-based query generation
- result_converter: Converting Neo4j results to scenarios
- scenario_analyzer: Analyzing attack scenarios with RAG
- obfuscation_helpers: PowerShell command detection and obfuscation
- structured_data: EdgeDataService interactions for remediation/detection
- rag_context_builder: Building enriched context for RAG prompts
- rag_generators: RAG-powered content generation
- parallel_processor: Async parallel processing for findings
- report_assembler: Report assembly and executive summary

Ground-Truth Anchoring components:
- result_store: Ground-truth data storage for Neo4j results
- entity_resolver: Type-safe entity resolution and validation
- finding_factory: Traceable finding creation
- deduplicator: Redundancy elimination
- validation_layer: Final sanity checks
"""

# Query generation functions
from .query_generator import (
    extract_entities_from_findings,
    generate_rich_findings_summary,
    analyze_environment_for_queries,
    generate_cypher_queries_with_rag,
    parse_rag_generated_queries,
    generate_attack_queries,
)

# Result conversion functions
from .result_converter import (
    _get_node_name,
    _convert_path_result_to_finding,
    _convert_results_to_scenarios,
    _infer_attack_type,
    _infer_priority,
    _infer_edge_type_from_query,
)

# Scenario analysis functions
from .scenario_analyzer import (
    _format_results_for_rag,
    _extract_section,
)

# Obfuscation helpers
from .obfuscation_helpers import (
    is_powershell_command,
    apply_obfuscation_to_attack_steps,
)

# Structured data helpers
from .structured_data import (
    get_remediation_from_structured_data,
    get_detection_from_structured_data,
    get_references_from_structured_data,
    derive_attack_chain,
)

# RAG context builder
from .rag_context_builder import (
    build_enriched_rag_context,
)

# RAG generators (simplified - model knows AD security)
from .rag_generators import (
    generate_observation_rag,
    generate_understanding_qa,
    generate_attack_chain_r1,
    generate_risk_description_rag,
)

# Query executor for ad-hoc Neo4j queries during generation
from .query_executor import (
    QueryExecutor,
    get_query_instruction,
)

# Parallel processor
from .parallel_processor import (
    generate_pentest_finding_parallel,
    process_scenario_parallel,
    analyze_attack_scenarios_parallel,
)

# Report assembler
from .report_assembler import (
    assemble_hybrid_report,
    generate_executive_summary,
    generate_fallback_executive_summary,
)

# Ground-Truth Anchoring components
from .result_store import ResultStore, StoredResult
from .entity_resolver import EntityResolver, ResolvedEntity, ALLOWED_OPERATIONS
from .finding_factory import FindingFactory
from .deduplicator import Deduplicator, Finding
from .validation_layer import ValidationLayer, ValidationResult, TYPO_CORRECTIONS

__all__ = [
    # Query generation
    'extract_entities_from_findings',
    'generate_rich_findings_summary',
    'analyze_environment_for_queries',
    'generate_cypher_queries_with_rag',
    'parse_rag_generated_queries',
    'generate_attack_queries',
    # Result conversion
    '_get_node_name',
    '_convert_path_result_to_finding',
    '_convert_results_to_scenarios',
    '_infer_attack_type',
    '_infer_priority',
    '_infer_edge_type_from_query',
    # Scenario analysis
    '_format_results_for_rag',
    '_extract_section',
    # Obfuscation helpers
    'is_powershell_command',
    'apply_obfuscation_to_attack_steps',
    # Structured data
    'get_remediation_from_structured_data',
    'get_detection_from_structured_data',
    'get_references_from_structured_data',
    'derive_attack_chain',
    # RAG context builder
    'build_enriched_rag_context',
    # RAG generators
    'generate_observation_rag',
    'generate_understanding_qa',
    'generate_attack_chain_r1',
    'generate_risk_description_rag',
    # Parallel processor
    'generate_pentest_finding_parallel',
    'process_scenario_parallel',
    'analyze_attack_scenarios_parallel',
    # Report assembler
    'assemble_hybrid_report',
    'generate_executive_summary',
    'generate_fallback_executive_summary',
    # Ground-Truth Anchoring
    'ResultStore',
    'StoredResult',
    'EntityResolver',
    'ResolvedEntity',
    'ALLOWED_OPERATIONS',
    'FindingFactory',
    'Deduplicator',
    'Finding',
    'ValidationLayer',
    'ValidationResult',
    'TYPO_CORRECTIONS',
]

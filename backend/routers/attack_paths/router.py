"""
Attack Path Router for AEGIS - Hybrid Flow Version
Location: backend/routers/attack_paths/router.py

This router supports the hybrid architecture where:
- Electron app imports data to LOCAL Neo4j
- Backend generates Cypher queries (no execution)
- Electron executes queries on LOCAL Neo4j
- Backend analyzes results with RAG and generates report

Includes:
- /generate-queries - Generate Cypher queries for local execution
- /analyze-results - Analyze query results with RAG
- /logs - Real-time log streaming for TerminalLogViewer
- Progress tracking endpoints

This file follows the thin controller pattern - all business logic
is delegated to service modules.
"""

import logging
import asyncio
import uuid
import traceback
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Query

# Import external models
from models.attack_path_model import (
    AttackPathRequest,
    AttackPathResponse,
    AttackPathStatus,
    AnalysisProgressResponse
)

# Import services
from services.rag_service import RAGService

# Import T0 models
from models.tier0_models import Tier0Config

# =============================================================================
# IMPORTS FROM REFACTORED SUBMODULES
# =============================================================================

# Constants
from .constants import (
    get_opsec_attack_steps,
)

# Edge costs for chain discovery
from .constants.edge_costs import (
    generate_chain_query,
    MAX_SOURCES,
    MAX_TARGETS,
)

# State management (from state.py)
from .state import (
    log_buffer,
    add_log,
    is_debug_mode,
    analysis_progress,
    update_progress,
    get_rag_service,
    get_remediation_service,
    estimate_time_remaining,
)

# Models (from models.py)
from .models import (
    FindingsSummary,
    EnvironmentInfo,
    GenerateQueriesRequest,
    GeneratedQuery,
    GenerateQueriesResponse,
    QueryResult,
    AnalyzeResultsRequest,
    AnalyzeResultsResponse,
    ContextQuery,
    GenerateContextQueriesRequest,
    GenerateContextQueriesResponse,
    ChainQueryRequest,
    ChainQueryResponse,
)

# Query generator services
from .services.query_generator import (
    analyze_environment_for_queries,
    generate_attack_queries as generate_attack_queries_service,
)

# Result converter services
from .services.result_converter import (
    _convert_results_to_scenarios,
)

# Parallel processor services
from .services.parallel_processor import (
    analyze_attack_scenarios_parallel,
)

# Report assembler services
from .services.report_assembler import (
    assemble_hybrid_report,
)

# Ground-Truth Anchoring components
from .services.result_store import ResultStore
from .services.entity_resolver import EntityResolver
from .services.deduplicator import Deduplicator
from .services.validation_layer import ValidationLayer

logger = logging.getLogger(__name__)
router = APIRouter()


# ==================== LOGS ENDPOINT ====================

@router.get("/logs")
async def get_logs(since: int = Query(0, description="Return logs with ID greater than this value")):
    """
    Get logs for real-time streaming to TerminalLogViewer.

    Poll this endpoint to get new logs as they are generated.
    The 'since' parameter allows incremental fetching.
    """
    logs_list, last_id = log_buffer.get_logs_since(since)

    return {
        "logs": logs_list,
        "last_id": last_id,
        "count": len(logs_list)
    }


@router.delete("/logs")
async def clear_logs():
    """Clear all logs from the buffer"""
    log_buffer.clear()
    return {"message": "Logs cleared", "success": True}


# ==================== HYBRID FLOW ENDPOINTS ====================

@router.post("/generate-queries", response_model=GenerateQueriesResponse)
async def generate_attack_queries(
    request: GenerateQueriesRequest,
    rag_service: RAGService = Depends(get_rag_service)
):
    """
    Generate Cypher queries based on BloodHound findings.

    This endpoint:
    1. Analyzes findings summary with RAG to understand environment
    2. Generates context-specific Cypher queries
    3. Returns queries for frontend to execute on LOCAL Neo4j

    The frontend should:
    1. Execute these queries on its local Neo4j
    2. Send results back to /analyze-results endpoint
    """
    # Clear old logs so TerminalLogViewer starts fresh for each report
    log_buffer.clear()

    add_log("INFO", "🔵 [HYBRID] Generate queries request received")

    # Generate unique analysis ID
    analysis_id = str(uuid.uuid4())

    # Initialize progress tracking
    analysis_progress[analysis_id] = {
        "analysis_id": analysis_id,
        "status": "generating_queries",
        "step": "generating_queries",
        "progress": 10,
        "message": "Analyzing environment context...",
        "created_at": datetime.now().isoformat()
    }

    try:
        # Step 1: Analyze environment context with RAG
        # Run in thread pool to avoid blocking event loop
        add_log("INFO", "🔍 [HYBRID] Analyzing environment with RAG...")
        update_progress(analysis_id, "analyzing_environment", 20, "RAG analyzing environment context...")

        environment_analysis = await asyncio.to_thread(
            analyze_environment_for_queries,
            request.findings_summary,
            request.environment_info,
            rag_service
        )

        # Step 2: Generate context-aware queries
        # Run in thread pool to avoid blocking event loop
        add_log("INFO", "⚡ [HYBRID] Generating context-aware Cypher queries...")
        update_progress(analysis_id, "generating_queries", 50, "Generating attack path queries...")

        queries = await asyncio.to_thread(
            generate_attack_queries_service,
            environment_analysis,
            request.findings_summary,
            rag_service
        )

        # Store state for later analysis
        analysis_progress[analysis_id].update({
            "status": "queries_generated",
            "step": "queries_generated",
            "progress": 100,
            "message": f"Generated {len(queries)} attack path queries",
            "environment_analysis": environment_analysis,
            "findings_summary": request.findings_summary.model_dump(),
            "queries": [q.model_dump() for q in queries]
        })

        add_log("INFO", f"✅ [HYBRID] Generated {len(queries)} queries for analysis {analysis_id[:8]}...")

        # Log each query for debugging (only in debug mode)
        from routers.logs import is_debug_mode
        if is_debug_mode():
            add_log("INFO", "=" * 60)
            add_log("INFO", "📋 GENERATED CYPHER QUERIES:")
            add_log("INFO", "=" * 60)
            for i, q in enumerate(queries, 1):
                add_log("INFO", f"\n--- Query {i}: {q.name} ---")
                add_log("INFO", f"Priority: {q.priority}")
                add_log("INFO", f"Cypher:\n{q.cypher}")
                add_log("INFO", "-" * 40)
            add_log("INFO", "=" * 60)

        return GenerateQueriesResponse(
            analysis_id=analysis_id,
            queries=queries,
            environment_analysis=environment_analysis,
            message=f"Generated {len(queries)} attack path queries. Execute on local Neo4j and send results to /analyze-results."
        )

    except Exception as e:
        add_log("ERROR", f"❌ [HYBRID] Query generation failed: {str(e)}")
        analysis_progress[analysis_id].update({
            "status": "failed",
            "step": "error",
            "progress": 0,
            "message": f"Query generation failed: {str(e)}"
        })
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate queries: {str(e)}"
        )


@router.post("/generate-context-queries", response_model=GenerateContextQueriesResponse)
async def generate_context_queries(request: GenerateContextQueriesRequest):
    """
    Generate context-enrichment Cypher queries for client-side execution.

    After the client executes the main attack path queries (Step 3),
    this endpoint generates additional queries to enrich the LLM prompt
    with concrete entity names (group members, SPNs, DC hostname, etc.).

    The client executes these queries locally and sends results back
    in the /analyze-results request.
    """
    from .services.query_executor import QueryExecutor

    add_log("INFO", "🔵 [HYBRID] Generate context queries request received")

    try:
        # Convert query results to attack scenarios to extract edges/sources/targets
        attack_scenarios = _convert_results_to_scenarios(request.query_results)
        add_log("INFO", f"🔄 [HYBRID] Processing {len(attack_scenarios)} scenarios for context queries")

        all_queries = []
        seen_cyphers = set()  # Deduplicate by cypher text

        for idx, scenario in enumerate(attack_scenarios):
            query_info = scenario.get('query_info', {})
            results = scenario.get('results', [])

            if not results:
                continue

            # Extract edges, sources, targets, domain from this scenario
            edges_used = query_info.get('edges_used', [])
            sources = []
            targets = []
            domain = ""

            for r in results[:10]:
                if not isinstance(r, dict):
                    continue
                s = r.get('source', '')
                t = r.get('target', '')

                if s:
                    if '@' in s:
                        if not domain:
                            domain = s.split('@')[-1]
                        sources.append(s.split('@')[0])
                    else:
                        sources.append(s)
                if t:
                    if '@' in t:
                        if not domain:
                            domain = t.split('@')[-1]
                        targets.append(t.split('@')[0])
                    else:
                        targets.append(t)

                # Extract edge types from results if not in query_info
                edge = r.get('edge_type') or r.get('rel_type', '')
                if edge and edge not in edges_used:
                    edges_used.append(edge)

            sources = list(set(sources))[:5]
            targets = list(set(targets))[:5]

            # Also try domain from environment_info
            if not domain and request.environment_info:
                env_domains = request.environment_info.domain_names
                if env_domains:
                    domain = env_domains[0]

            if not domain:
                continue

            # Generate context queries for this scenario
            scenario_queries = QueryExecutor.generate_context_queries(
                edges=edges_used,
                sources=sources,
                targets=targets,
                domain=domain,
                finding_index=idx,
            )

            # Deduplicate across findings
            for q in scenario_queries:
                if q['cypher'] not in seen_cyphers:
                    seen_cyphers.add(q['cypher'])
                    all_queries.append(q)

        add_log("INFO", f"✅ [HYBRID] Generated {len(all_queries)} context queries (deduplicated)")

        # Convert to response models
        context_queries = [
            ContextQuery(
                id=q['id'],
                finding_index=q['finding_index'],
                query_type=q['query_type'],
                cypher=q['cypher'],
                entity_name=q.get('entity_name'),
            )
            for q in all_queries
        ]

        return GenerateContextQueriesResponse(
            analysis_id=request.analysis_id,
            context_queries=context_queries,
            message=f"Generated {len(context_queries)} context queries for local execution."
        )

    except Exception as e:
        add_log("ERROR", f"❌ [HYBRID] Context query generation failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate context queries: {str(e)}"
        )


@router.post("/analyze-results", response_model=AnalyzeResultsResponse)
async def analyze_query_results(
    request: AnalyzeResultsRequest,
    rag_service: RAGService = Depends(get_rag_service)
):
    """
    Analyze query results and generate comprehensive attack path report.

    This endpoint:
    1. Receives query results from frontend (executed on local Neo4j)
    2. Uses RAG to analyze each attack scenario
    3. Generates comprehensive report with remediation

    This is the final step in the hybrid flow.

    NOTE: Heavy operations run in thread pool to avoid blocking the event loop,
    allowing /logs endpoint to respond during long-running analysis.
    """
    add_log("INFO", f"🔵 [HYBRID] Analyze results request for {request.analysis_id[:8]}...")

    # Parse T0 config if provided
    tier0_config = None
    if request.tier0_config:
        try:
            tier0_config = Tier0Config(**request.tier0_config)
            add_log("INFO", f"🛡️ [HYBRID] T0 Config enabled: {tier0_config.get_asset_count()} assets defined")
        except Exception as e:
            add_log("WARN", f"⚠️ [HYBRID] Failed to parse T0 config: {e}")

    try:
        # Initialize/update progress tracking
        if request.analysis_id not in analysis_progress:
            analysis_progress[request.analysis_id] = {
                "analysis_id": request.analysis_id,
                "created_at": datetime.now().isoformat()
            }

        update_progress(request.analysis_id, "initializing", 5, "Initializing analysis...")

        # Use DC hostname from client-side context query results
        dc_hostname = request.dc_hostname
        if dc_hostname:
            add_log("INFO", f"🖥️ [HYBRID] DC hostname from client: {dc_hostname}")

        # Store DC hostname in analysis state for downstream use
        analysis_progress[request.analysis_id] = analysis_progress.get(request.analysis_id, {})
        analysis_progress[request.analysis_id]['dc_hostname'] = dc_hostname

        # Retrieve stored state if exists
        stored_state = analysis_progress.get(request.analysis_id, {})
        environment_analysis = stored_state.get("environment_analysis", {})

        # If no stored state, rebuild environment analysis
        # Run in thread pool to avoid blocking event loop
        if not environment_analysis and request.environment_info:
            update_progress(request.analysis_id, "analyzing_environment", 10, "Analyzing environment context...")
            add_log("INFO", "🔍 [HYBRID] Rebuilding environment analysis...")
            environment_analysis = await asyncio.to_thread(
                analyze_environment_for_queries,
                request.findings_summary,
                request.environment_info,
                rag_service
            )

        # Step 0: Initialize Ground-Truth Anchoring system
        # This ensures all entity data comes from actual Neo4j results
        add_log("INFO", "🔒 [HYBRID] Initializing Ground-Truth Anchoring system...")
        result_store = ResultStore()

        # Store all query results in ground-truth store
        for qr in request.query_results:
            if qr.results:
                query_name = qr.query_name if hasattr(qr, 'query_name') else qr.name
                result_store.store(query_name, qr.results)

        entity_count = len(result_store.get_all_entities())
        add_log("INFO", f"🔒 [HYBRID] Ground-truth store initialized: {len(result_store.results)} results, {entity_count} unique entities")

        # Initialize entity resolver for type-safe operations
        entity_resolver = EntityResolver(result_store)

        # Initialize deduplicator for redundancy elimination
        deduplicator = Deduplicator()

        # Initialize validation layer for final sanity checks
        validation_layer = ValidationLayer(entity_resolver)

        # Step 1: Convert query results to attack scenarios
        update_progress(request.analysis_id, "converting_results", 20, "Processing query results...")
        add_log("INFO", f"🔄 [HYBRID] Processing {len(request.query_results)} query results...")
        attack_scenarios = _convert_results_to_scenarios(request.query_results)
        add_log("INFO", f"🔄 [HYBRID] Created {len(attack_scenarios)} attack scenarios")

        # Step 1.2: Split disconnected multi-edge scenarios into separate findings
        # e.g., "Outbound Object Control" with OLIVIA→MICHAEL + EMILY→ETHAN
        # becomes two scenarios so the LLM can describe each accurately
        from .services.result_converter import split_disconnected_scenarios
        pre_split = len(attack_scenarios)
        attack_scenarios = split_disconnected_scenarios(attack_scenarios)
        if pre_split != len(attack_scenarios):
            add_log("INFO", f"✂️ [HYBRID] Split disconnected scenarios: {pre_split} → {len(attack_scenarios)}")

        # Step 1.5: Process chain discovery results if present
        if request.chain_results:
            from .services.chain_discovery import (
                extract_path_data,
                score_and_deduplicate_chains,
                build_chain_scenario,
            )

            # Extract and score chain paths
            extracted_chains = []
            source_info = {}
            if request.chain_source_info:
                source_info = {s['name']: s for s in request.chain_source_info}

            for cr in request.chain_results:
                extracted = extract_path_data(cr)
                if extracted:
                    extracted_chains.append(extracted)

            add_log("INFO", f"🔗 [HYBRID] Extracted {len(extracted_chains)} chain paths from {len(request.chain_results)} results")

            # Deduplicate and score
            deduped_chains = score_and_deduplicate_chains(extracted_chains, source_info, add_log)

            # Cap chain scenarios to avoid overwhelming LLM with redundant analysis
            MAX_CHAIN_SCENARIOS = 10
            if len(deduped_chains) > MAX_CHAIN_SCENARIOS:
                add_log("INFO", f"🔗 [HYBRID] Capping chain scenarios from {len(deduped_chains)} to {MAX_CHAIN_SCENARIOS}")
                deduped_chains = deduped_chains[:MAX_CHAIN_SCENARIOS]

            # Convert chains to scenarios and append
            chain_scenario_start = len(attack_scenarios) + 1
            for i, chain in enumerate(deduped_chains):
                scenario = build_chain_scenario(chain, chain_scenario_start + i)
                attack_scenarios.append(scenario)

            add_log("INFO", f"🔗 [HYBRID] Added {len(deduped_chains)} chain scenarios (total scenarios: {len(attack_scenarios)})")

        # Step 1.7: Consolidate related scenarios (pre-LLM dedup)
        from .services.scenario_consolidator import consolidate_scenarios
        pre_consolidation_count = len(attack_scenarios)
        attack_scenarios = consolidate_scenarios(attack_scenarios, add_log)
        if pre_consolidation_count != len(attack_scenarios):
            add_log("INFO", f"🔗 Consolidated {pre_consolidation_count} scenarios → {len(attack_scenarios)} (saved {pre_consolidation_count - len(attack_scenarios)} LLM calls)")

        # Step 1.8: Pre-LLM T0 noise filtering
        # Remove scenarios where ALL sources are T0 assets (or T0 group members) targeting T0 objects
        # This saves expensive LLM calls on findings that would be filtered post-LLM anyway
        if tier0_config and tier0_config.enabled:
            # Use explicitly configured T0 assets PLUS built-in admin accounts.
            # Do NOT expand by group membership — a user who is a member of a T0 group
            # (e.g., SVC-ALFRESCO in ACCOUNT OPERATORS) is a compromisable path TO T0,
            # not T0 itself.
            t0_expanded = set()
            for name in tier0_config.get_all_asset_names():
                t0_expanded.add(name.upper())

            # Built-in admin accounts are always T0 regardless of config.
            # These are default AD accounts that exist in every domain — reporting
            # "ADMINISTRATOR can control DOMAIN ADMINS" is expected behaviour.
            BUILTIN_ADMIN_PREFIXES = {
                'ADMINISTRATOR@',   # RID 500 — built-in domain admin
                'KRBTGT@',          # RID 502 — Kerberos TGT service account
            }
            BUILTIN_ADMIN_SUFFIXES = {
                '-500',   # Built-in Administrator (by objectid)
                '-502',   # KRBTGT
                '-512',   # Domain Admins
                '-519',   # Enterprise Admins
            }

            def is_builtin_admin(entity_name):
                """Check if entity is a built-in admin account (always T0)."""
                upper = entity_name.upper()
                for prefix in BUILTIN_ADMIN_PREFIXES:
                    if upper.startswith(prefix):
                        return True
                if upper == 'ADMINISTRATOR':
                    return True
                return False

            # Built-in T0 groups that have control over everything by design.
            # Findings where ALL sources are these groups are always noise —
            # regardless of whether the target is T0 or not.
            # "ADMINISTRATORS has WriteOwner on USER" is expected AD behaviour.
            BUILTIN_T0_GROUPS = {
                'ADMINISTRATORS', 'DOMAIN ADMINS', 'ENTERPRISE ADMINS',
                'SCHEMA ADMINS', 'KEY ADMINS', 'ENTERPRISE KEY ADMINS',
            }

            def is_builtin_t0_group(entity_name):
                """Check if entity is a built-in T0 group (has control over everything by design)."""
                upper = entity_name.upper()
                # Strip domain suffix for matching
                name_only = upper.split('@')[0] if '@' in upper else upper
                return name_only in BUILTIN_T0_GROUPS

            pre_t0_count = len(attack_scenarios)
            filtered_scenarios = []
            for scenario in attack_scenarios:
                results = scenario.get('results', [])
                if not results:
                    filtered_scenarios.append(scenario)
                    continue

                # Filter 1: ALL sources are built-in T0 groups (noise regardless of target)
                # "ADMINISTRATORS → WriteOwner → STEPH.COOPER" is expected behaviour
                all_sources_builtin_t0 = all(
                    is_builtin_t0_group(r.get('source', ''))
                    for r in results if isinstance(r, dict) and r.get('source')
                )
                if all_sources_builtin_t0 and len(results) > 0:
                    name = scenario.get('query_info', {}).get('name', '?')
                    add_log("DEBUG", f"  🛡️ Pre-LLM T0 filter: skipping '{name}' (all sources are built-in T0 groups)")
                    continue

                # Filter 2: ALL sources are T0 assets or built-in admins AND target is T0
                all_sources_t0 = True
                any_target_t0 = False
                for r in results:
                    source = r.get('source', '').upper()
                    target = r.get('target', '').upper()
                    source_is_t0 = (source in t0_expanded) or is_builtin_admin(source)
                    if source and not source_is_t0:
                        all_sources_t0 = False
                        break
                    if target and target in t0_expanded:
                        any_target_t0 = True

                if all_sources_t0 and any_target_t0 and len(results) > 0:
                    name = scenario.get('query_info', {}).get('name', '?')
                    add_log("DEBUG", f"  🛡️ Pre-LLM T0 filter: skipping '{name}' (all sources T0, target T0)")
                    continue

                filtered_scenarios.append(scenario)

            attack_scenarios = filtered_scenarios
            t0_filtered = pre_t0_count - len(attack_scenarios)
            if t0_filtered > 0:
                add_log("INFO", f"🛡️ Pre-LLM T0 filter: removed {t0_filtered} T0-only scenarios (saved {t0_filtered} LLM calls)")

        # Step 2: RAG analyzes each attack scenario - PARALLEL PROCESSING
        # Uses Level 1 (parallel within findings) + Level 2 (parallel across findings)
        # This provides ~5x speedup compared to sequential processing
        update_progress(request.analysis_id, "rag_analysis", 30, f"RAG analyzing {len(attack_scenarios)} attack scenarios (parallel)...")
        add_log("INFO", "🚀 [HYBRID] RAG analyzing attack scenarios with PARALLEL processing...")

        # Build finding_context_map from client-executed context query results
        finding_context_map = None
        if request.context_query_results:
            from .services.query_executor import QueryExecutor
            context_dicts = [cr.model_dump() for cr in request.context_query_results]
            finding_context_map = QueryExecutor.format_context_results(context_dicts)
            add_log("INFO", f"📊 [HYBRID] Built context map for {len(finding_context_map)} findings from {len(context_dicts)} context query results")

        analyzed_paths = await analyze_attack_scenarios_parallel(
            attack_scenarios,
            environment_analysis,
            request.findings_summary,
            rag_service,
            request.analysis_id,
            tier0_config,
            max_concurrent=5,  # Process up to 5 scenarios concurrently
            finding_context_map=finding_context_map,  # Pre-fetched context from client-side queries
            dc_hostname=dc_hostname  # Inject actual DC hostname into commands
        )

        # Step 3: Generate comprehensive report
        # Also run in thread pool as it may involve RAG calls
        # Pass ground-truth components for validation and deduplication
        update_progress(request.analysis_id, "generating_report", 85, "Assembling final report...")
        add_log("INFO", "📄 [HYBRID] Assembling final report with Ground-Truth validation...")
        report = await asyncio.to_thread(
            assemble_hybrid_report,
            analyzed_paths,
            environment_analysis,
            request.findings_summary,
            request.query_results,
            rag_service,
            tier0_config,
            deduplicator=deduplicator,
            validation_layer=validation_layer
        )

        # Mark as completed
        update_progress(request.analysis_id, "completed", 100, "Analysis complete", "completed")

        # Update stored state with final report
        analysis_progress[request.analysis_id].update({
            "status": "completed",
            "progress": 100,
            "step": "completed",
            "message": "Analysis complete",
            "report": report,
            "completed_at": datetime.now().isoformat()
        })

        add_log("INFO", f"✅ [HYBRID] Report generated: {len(analyzed_paths)} attack paths analyzed")

        return AnalyzeResultsResponse(
            analysis_id=request.analysis_id,
            status="completed",
            report=report,
            message=f"Analysis complete. Found {len(analyzed_paths)} critical attack paths."
        )

    except Exception as e:
        tb = traceback.format_exc()
        add_log("ERROR", f"❌ [HYBRID] Result analysis failed: {str(e)}")
        add_log("ERROR", f"Traceback:\n{tb}")
        update_progress(request.analysis_id, "error", 0, f"Analysis failed: {str(e)}", "failed")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to analyze results: {str(e)}"
        )


# ==================== CHAIN DISCOVERY ENDPOINTS ====================

@router.post("/generate-chain-queries", response_model=ChainQueryResponse)
async def generate_chain_queries(request: ChainQueryRequest):
    """Generate weighted shortest-path queries for each (source, target) pair."""
    sources = request.sources[:MAX_SOURCES]
    targets = request.targets[:MAX_TARGETS]

    chain_queries = []
    for source in sources:
        for target in targets:
            source_name = source.get('name', '')
            target_name = target.get('name', '')
            if not source_name or not target_name:
                continue
            # Skip self-pairs (source = target)
            if source_name.upper() == target_name.upper():
                continue

            cypher = generate_chain_query(source_name, target_name)
            chain_queries.append({
                "source": source_name,
                "target": target_name,
                "cypher": cypher,
                "params": {"source": source_name, "target": target_name},
            })

    # Generate reverse chain queries (one per target)
    from .constants.edge_costs import generate_reverse_chain_query

    reverse_queries = []
    for target in targets:
        target_name = target.get('name', '')
        if not target_name:
            continue
        cypher = generate_reverse_chain_query(target_name)
        reverse_queries.append({
            "target": target_name,
            "cypher": cypher,
            "params": {"target": target_name},
        })

    add_log("INFO", f"🔗 [CHAIN] Generated {len(chain_queries)} forward + {len(reverse_queries)} reverse chain queries")
    return ChainQueryResponse(
        chain_queries=chain_queries,
        reverse_chain_queries=reverse_queries,
        total_pairs=len(chain_queries),
        total_reverse=len(reverse_queries),
    )




# ==================== PROGRESS ENDPOINTS ====================

@router.get("/analyze/{analysis_id}/progress", response_model=AnalysisProgressResponse)
async def get_analysis_progress(analysis_id: str):
    """
    Get real-time progress of an attack path analysis.

    Returns progress data including status, step, percentage, and message.
    """
    if analysis_id in analysis_progress:
        progress_data = analysis_progress[analysis_id]

        step = progress_data.get("step", progress_data.get("status", "processing"))
        status = progress_data.get("status", "processing")

        return AnalysisProgressResponse(
            analysis_id=analysis_id,
            status=status,
            step=step,
            progress=progress_data.get("progress", 0),
            message=progress_data.get("message", "Processing..."),
            started_at=progress_data.get("created_at"),
            completed_at=progress_data.get("completed_at"),
            estimated_time_remaining=estimate_time_remaining(progress_data)
        )

    # Analysis not found - return pending status
    return AnalysisProgressResponse(
        analysis_id=analysis_id,
        status="pending",
        step="pending",
        progress=0,
        message="Analysis is starting...",
        started_at=None,
        completed_at=None,
        estimated_time_remaining="Starting soon..."
    )


@router.get("/analyze/{analysis_id}/status", response_model=AnalysisProgressResponse)
async def get_analysis_status(analysis_id: str):
    """Get the status of an analysis (alias for /progress)"""
    return await get_analysis_progress(analysis_id)


@router.get("/analyze/{analysis_id}/report")
async def get_analysis_report(analysis_id: str):
    """
    Get the complete attack path analysis report.

    Returns the full report once analysis is completed.
    """
    if analysis_id not in analysis_progress:
        raise HTTPException(status_code=404, detail=f"Analysis ID {analysis_id} not found")

    progress_data = analysis_progress[analysis_id]

    if progress_data["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Analysis not completed. Current status: {progress_data['status']}"
        )

    if "report" not in progress_data:
        raise HTTPException(status_code=500, detail="Analysis completed but report not available")

    report = progress_data["report"]
    if isinstance(report, dict):
        report["analysis_id"] = analysis_id

    return {
        "analysis_id": analysis_id,
        "status": "completed",
        "report": report,
        "completed_at": progress_data.get("completed_at")
    }


@router.get("/analyze")
async def list_analyses():
    """List all current analyses and their status."""
    analyses = []
    for analysis_id, data in analysis_progress.items():
        analyses.append({
            "analysis_id": analysis_id,
            "status": data.get("status", "unknown"),
            "progress": data.get("progress", 0),
            "message": data.get("message", ""),
            "started_at": data.get("created_at"),
            "completed_at": data.get("completed_at")
        })

    return {"total_analyses": len(analyses), "analyses": analyses}


@router.delete("/analyze/{analysis_id}")
async def delete_analysis(analysis_id: str):
    """Delete an analysis and clean up resources."""
    if analysis_id not in analysis_progress:
        raise HTTPException(status_code=404, detail=f"Analysis ID {analysis_id} not found")

    del analysis_progress[analysis_id]
    return {"message": f"Analysis {analysis_id} deleted successfully", "analysis_id": analysis_id}


# ==================== UTILITY ENDPOINTS ====================

@router.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {
        "status": "healthy",
        "service": "attack_path_analysis",
        "mode": "hybrid",
        "timestamp": datetime.now().isoformat(),
        "active_analyses": len(analysis_progress)
    }


@router.post("/test-connection")
async def test_services_connection():
    """Test connectivity to RAG service (Neo4j is now local-only)."""
    service_status = {
        "rag": {"status": "unknown", "message": ""},
        "overall": {"status": "unknown", "ready": False}
    }

    # Test RAG connection
    try:
        rag_service = get_rag_service()
        test_result = rag_service.query("Test connection")
        if test_result and 'result' in test_result:
            service_status["rag"] = {"status": "connected", "message": "RAG service operational"}
        else:
            service_status["rag"] = {"status": "failed", "message": "RAG service test failed"}
    except Exception as e:
        service_status["rag"] = {"status": "error", "message": f"RAG error: {str(e)}"}

    # Overall status (Neo4j is now local-only, so just check RAG)
    if service_status["rag"]["status"] == "connected":
        service_status["overall"] = {
            "status": "ready",
            "ready": True,
            "message": "Backend ready for hybrid analysis (Neo4j is handled locally)"
        }
    else:
        service_status["overall"] = {
            "status": "not_ready",
            "ready": False,
            "message": "RAG service unavailable"
        }

    return service_status

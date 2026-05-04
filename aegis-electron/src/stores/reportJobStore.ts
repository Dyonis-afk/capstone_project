/**
 * Report Job Store using Zustand
 * Location: src/stores/reportJobStore.ts
 *
 * Manages background report generation so users can navigate away
 * while the pipeline runs. Only ONE job can run at a time due to
 * BloodHound CE's single-project architecture.
 *
 * Pipeline Steps:
 * 1. checking_connection - Verify Neo4j connection, get environment info
 * 2. generating_queries - Send findings to backend, get Cypher queries
 * 3. executing_queries - Run queries on BloodHound CE
 * 4. analyzing - Send results to backend for RAG analysis
 * 5. creating_project - Create project in database, navigate to chat
 */

import { create } from 'zustand';
import type { BloodHoundAnalysis } from '../types';
import { API_URL } from '../config/api';
import { useProjectStore } from './projectStore';
import { useUploadStore } from './uploadStore';

// ==================== TYPES ====================

interface ParsedFindings {
    high_risk: any[];
    medium_risk: any[];
    low_risk: any[];
    summary: {
        total_nodes: number;
        total_edges: number;
        high_risk_count: number;
        medium_risk_count: number;
        low_risk_count: number;
        files_processed?: number;
    };
}

interface LocalAnalysis {
    findings: ParsedFindings;
    filename: string;
}

interface ReportProgress {
    step: string;
    percentage: number;
    message: string;
    timestamp: string;
}

interface LocalProgress {
    step: string;
    message: string;
    percentage: number;
}

interface GeneratedQuery {
    id: string;
    name: string;
    description: string;
    cypher: string;
    attack_type: string;
    priority: string;
    edges_used: string[];
}

interface QueryResult {
    query_id: string;
    query_name: string;
    cypher: string;
    results: any[];
    result_count: number;
    execution_time_ms?: number;
    error?: string;
}

export type PipelineStep =
    | 'idle'
    | 'checking_connection'
    | 'generating_queries'
    | 'executing_queries'
    | 'analyzing'
    | 'creating_project'
    | 'completed'
    | 'error';

interface JobInput {
    fileName: string;
    localAnalysis?: LocalAnalysis;
    analysis?: BloodHoundAnalysis;
    existingProjectId?: string;
    tier0Config?: any;  // Tier 0 configuration for classifying findings
}

interface ReportJobStore {
    // Job state
    isRunning: boolean;
    fileName: string | null;
    currentStep: PipelineStep;
    progress: ReportProgress | null;
    localProgress: LocalProgress | null;
    error: string | null;

    // Timer state (persists when user navigates away so timers keep running)
    jobStartedAt: number | null;
    currentStepStartedAt: number | null;
    elapsedSeconds: number;
    stepElapsedSeconds: number;
    tickTimers: () => void;

    // Pipeline data
    analysisId: string;
    projectId: string;
    generatedQueries: GeneratedQuery[];
    queryResults: QueryResult[];
    environmentInfo: any;
    reportData: any;

    // Input data (stored when job starts)
    jobInput: JobInput | null;

    // Navigation callback (set by App.tsx)
    navigateToChat: ((projectId: string, state: any) => void) | null;
    setNavigateCallback: (callback: (projectId: string, state: any) => void) => void;

    // Actions
    startJob: (input: JobInput) => Promise<void>;
    cancelJob: () => void;
    reset: () => void;
}

function now(): number {
    return Date.now();
}

// ==================== HELPER: Generate Report Summary ====================

function generateReportSummary(
    report: any,
    analysis: BloodHoundAnalysis | undefined,
    localAnalysis: LocalAnalysis | undefined,
    environmentInfo: any
): string {
    // Extract domain from multiple possible sources
    let domain = report.domain_name ||
        report.domains?.[0] ||
        report.domain ||
        analysis?.domain ||
        environmentInfo?.domain_names?.[0] ||
        environmentInfo?.domains?.[0] ||
        (localAnalysis?.findings?.summary as any)?.domain_name ||
        '';

    // Clean up domain name
    if (!domain || domain === 'Unknown' || domain === 'Unknown Domain' || domain.trim() === '') {
        const dataToSearch = [
            localAnalysis?.findings?.high_risk,
            localAnalysis?.findings?.medium_risk,
            report?.paths || report?.critical_attack_paths,
            report?.attack_scenarios
        ].filter(Boolean).flat();

        for (const item of dataToSearch) {
            if (item) {
                const text = JSON.stringify(item);
                const domainMatch = text.match(/([A-Z0-9-]+\.(LOCAL|COM|NET|ORG|CORP|AD|INTERNAL|DOMAIN))/i);
                if (domainMatch) {
                    domain = domainMatch[1].toUpperCase();
                    break;
                }
            }
        }
    }

    if (!domain || domain.trim() === '') {
        domain = 'Active Directory';
    }

    // Build attack paths array (prefer paths, fallback to critical_attack_paths for backwards compat)
    const reportPaths = report.paths || report.critical_attack_paths || [];
    const attackPaths: Array<{ title: string; risk: string; count: number }> = [];
    if (reportPaths.length) {
        reportPaths.forEach((path: any) => {
            const finding = path.pentest_finding;
            const name = finding?.title || path.query_info?.name || path.title || 'Attack Path';
            const severitySource = (
                finding?.severity ||
                path.query_info?.priority ||
                path.risk_rating ||
                'Medium'
            ).toLowerCase();

            let risk = 'Medium';
            if (severitySource.includes('critical')) risk = 'Critical';
            else if (severitySource.includes('high')) risk = 'High';
            else if (severitySource.includes('low')) risk = 'Low';

            attackPaths.push({
                title: name,
                risk,
                count: path.result_count || 0
            });
        });
    }

    const criticalCount = attackPaths.filter(p => p.risk === 'Critical').length;
    const highCount = attackPaths.filter(p => p.risk === 'High').length;
    const mediumCount = attackPaths.filter(p => p.risk === 'Medium').length;
    const lowCount = attackPaths.filter(p => p.risk === 'Low').length;

    // Build key concerns
    const keyConcerns: Array<{ count: number; text: string; highlight: string }> = [];
    if (reportPaths.length > 0) {
        const kerberoastPaths = attackPaths.filter(p =>
            p.title.toLowerCase().includes('kerberoast') ||
            p.title.toLowerCase().includes('service account')
        );
        if (kerberoastPaths.length > 0) {
            const totalCount = kerberoastPaths.reduce((sum, p) => sum + p.count, 0);
            keyConcerns.push({
                count: totalCount,
                text: 'Kerberoastable service accounts',
                highlight: 'credential theft'
            });
        }

        const dcsyncPaths = attackPaths.filter(p => p.title.toLowerCase().includes('dcsync'));
        if (dcsyncPaths.length > 0) {
            const totalCount = dcsyncPaths.reduce((sum, p) => sum + p.count, 0);
            keyConcerns.push({
                count: totalCount,
                text: 'Principals with DCSync rights',
                highlight: 'domain replication'
            });
        }

        const permissionPaths = attackPaths.filter(p =>
            p.title.toLowerCase().includes('permission') ||
            p.title.toLowerCase().includes('genericall') ||
            p.title.toLowerCase().includes('writedacl')
        );
        if (permissionPaths.length > 0) {
            const totalCount = permissionPaths.reduce((sum, p) => sum + p.count, 0);
            keyConcerns.push({
                count: totalCount,
                text: 'Dangerous permissions on admin groups',
                highlight: 'GenericAll, WriteDacl'
            });
        }
    }

    const totalFindings = attackPaths.reduce((sum, p) => sum + p.count, 0);

    const summaryData = {
        domain: domain.toUpperCase(),
        date: new Date().toLocaleDateString(),
        executiveSummary: report.executive_summary || undefined,
        totalFindings,
        highRiskCount: criticalCount + highCount,
        mediumRiskCount: mediumCount,
        lowRiskCount: lowCount,
        keyConcerns: keyConcerns.length > 0 ? keyConcerns : undefined,
        attackPaths
    };

    return `$$REPORT_SUMMARY$$${JSON.stringify(summaryData)}`;
}

// ==================== STORE ====================

export const useReportJobStore = create<ReportJobStore>((set, get) => ({
    // Initial state
    isRunning: false,
    fileName: null,
    currentStep: 'idle',
    progress: null,
    localProgress: null,
    error: null,
    jobStartedAt: null,
    currentStepStartedAt: null,
    elapsedSeconds: 0,
    stepElapsedSeconds: 0,
    tickTimers: () => {
        const state = get();
        const startedAt = state.jobStartedAt;
        const stepStartedAt = state.currentStepStartedAt;
        if (startedAt == null) return;
        const total = Math.floor((now() - startedAt) / 1000);
        const step = stepStartedAt != null ? Math.floor((now() - stepStartedAt) / 1000) : 0;
        set({ elapsedSeconds: total, stepElapsedSeconds: step });
    },
    analysisId: '',
    projectId: '',
    generatedQueries: [],
    queryResults: [],
    environmentInfo: null,
    reportData: null,
    jobInput: null,
    navigateToChat: null,

    setNavigateCallback: (callback) => set({ navigateToChat: callback }),

    startJob: async (input: JobInput) => {
        const state = get();

        // Prevent starting if already running
        if (state.isRunning) {
            console.warn('[ReportJobStore] Job already running, ignoring start request');
            return;
        }

        console.log('[ReportJobStore] Starting background report generation');

        const startTime = now();
        // Initialize job state FIRST (synchronous)
        set({
            isRunning: true,
            fileName: input.fileName,
            currentStep: 'checking_connection' as const,
            progress: null,
            localProgress: {
                step: 'checking_connection',
                message: 'Starting report generation...',
                percentage: 0
            },
            error: null,
            analysisId: '',
            projectId: `aegis-${startTime}`,
            generatedQueries: [],
            queryResults: [],
            environmentInfo: null,
            reportData: null,
            jobInput: input,
            jobStartedAt: startTime,
            currentStepStartedAt: startTime,
            elapsedSeconds: 0,
            stepElapsedSeconds: 0
        });

        // Run pipeline in a separate async context to ensure state is committed
        // before any awaits. This allows React to see isRunning=true immediately.
        const runPipeline = async () => {
        try {
            // ==================== STEP 1: CHECK CONNECTION ====================
            set({
                currentStep: 'checking_connection',
                currentStepStartedAt: now(),
                localProgress: {
                    step: 'checking_connection',
                    message: 'Connecting to BloodHound CE...',
                    percentage: 10
                }
            });

            if (!window.neo4j) {
                throw new Error('Neo4j API not available');
            }

            const connectionResult = await window.neo4j.testConnection();
            if (!connectionResult.connected) {
                throw new Error('BloodHound CE not connected. Please ensure it is running.');
            }

            set({
                localProgress: {
                    step: 'checking_connection',
                    message: 'Connected! Fetching environment info...',
                    percentage: 50
                }
            });

            // Fetch environment info
            let envInfo: any = null;
            if (window.neo4j.getEnvironmentInfo) {
                const info = await window.neo4j.getEnvironmentInfo();
                envInfo = {
                    domain_names: info.domains || [],
                    domain_info: info.domainInfo || null,
                    domain_admin_groups: info.domainAdminGroups || [],
                    high_value_groups: info.highValueGroups || [],
                    service_accounts: info.serviceAccounts || [],
                    computers: info.computers || [],
                    edge_types: info.edgeTypes || []
                };
            } else {
                const domainResult = await window.neo4j.runQuery(
                    'MATCH (d:Domain) RETURN d.name as name LIMIT 10'
                );
                const domains = (domainResult.records || []).map((r: any) => r.name).filter(Boolean);
                envInfo = { domain_names: domains };
            }

            set({
                environmentInfo: envInfo,
                localProgress: {
                    step: 'checking_connection',
                    message: 'BloodHound CE ready',
                    percentage: 100
                }
            });

            await new Promise(r => setTimeout(r, 300));

            // ==================== STEP 2: GENERATE QUERIES ====================
            set({
                currentStep: 'generating_queries',
                currentStepStartedAt: now(),
                localProgress: {
                    step: 'generating_queries',
                    message: 'Sending findings to backend for query generation...',
                    percentage: 5
                }
            });

            const { localAnalysis, analysis } = input;
            const findings = localAnalysis?.findings || {
                high_risk: analysis?.highRiskFindings || [],
                medium_risk: analysis?.mediumRiskFindings || [],
                low_risk: analysis?.lowRiskFindings || [],
                summary: analysis?.summary || {}
            };

            const queryResponse = await fetch(`${API_URL}/api/attack-paths/generate-queries`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    findings_summary: findings,
                    environment_info: get().environmentInfo,
                    options: {}
                })
            });

            if (!queryResponse.ok) {
                const errorText = await queryResponse.text();
                throw new Error(`Failed to generate queries: ${queryResponse.status} - ${errorText}`);
            }

            const queryResult = await queryResponse.json();
            console.log('[ReportJobStore] Generated queries:', queryResult.queries.length);

            set({
                analysisId: queryResult.analysis_id,
                generatedQueries: queryResult.queries,
                localProgress: {
                    step: 'generating_queries',
                    message: `Generated ${queryResult.queries.length} attack path queries`,
                    percentage: 100
                }
            });

            await new Promise(r => setTimeout(r, 300));

            // ==================== STEP 3: EXECUTE QUERIES ====================
            set({ currentStep: 'executing_queries', currentStepStartedAt: now() });

            const queries = queryResult.queries as GeneratedQuery[];
            const results: QueryResult[] = [];

            for (let i = 0; i < queries.length; i++) {
                const query = queries[i];

                set({
                    localProgress: {
                        step: 'executing_queries',
                        message: `Executing query ${i + 1}/${queries.length}: ${query.name}`,
                        percentage: Math.round((i / queries.length) * 100)
                    }
                });

                try {
                    const startTime = Date.now();
                    const neo4jResponse = await window.neo4j.runQuery(query.cypher, {});
                    const executionTime = Date.now() - startTime;

                    let records: any[];
                    let resultCount: number;

                    if (Array.isArray(neo4jResponse)) {
                        records = neo4jResponse;
                        resultCount = neo4jResponse.length;
                    } else if (neo4jResponse && typeof neo4jResponse === 'object') {
                        records = neo4jResponse.records || [];
                        resultCount = neo4jResponse.count ?? records.length;
                    } else {
                        records = [];
                        resultCount = 0;
                    }

                    results.push({
                        query_id: query.id,
                        query_name: query.name,
                        cypher: query.cypher,
                        results: records,
                        result_count: resultCount,
                        execution_time_ms: executionTime
                    });

                    console.log(`[ReportJobStore] Query "${query.name}": ${resultCount} results`);

                } catch (err: any) {
                    console.error(`[ReportJobStore] Query "${query.name}" failed:`, err);
                    results.push({
                        query_id: query.id,
                        query_name: query.name,
                        cypher: query.cypher,
                        results: [],
                        result_count: 0,
                        error: err.message
                    });
                }
            }

            set({
                queryResults: results,
                localProgress: {
                    step: 'executing_queries',
                    message: `Executed ${queries.length} queries on BloodHound CE`,
                    percentage: 100
                }
            });

            await new Promise(r => setTimeout(r, 300));

            // ==================== STEP 3.5: CONTEXT QUERIES ====================
            // Generate and execute context-enrichment queries locally
            // These provide concrete entity names (group members, SPNs, DC hostname)
            // to the LLM for better attack chain generation
            set({
                localProgress: {
                    step: 'executing_queries',
                    message: 'Enriching context with additional queries...',
                    percentage: 85
                }
            });

            let contextQueryResults: any[] = [];
            let dcHostname: string | null = null;

            try {
                const contextRes = await fetch(`${API_URL}/api/attack-paths/generate-context-queries`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        analysis_id: get().analysisId,
                        query_results: results,
                        findings_summary: findings,
                        environment_info: get().environmentInfo
                    })
                });

                if (contextRes.ok) {
                    const { context_queries } = await contextRes.json();
                    console.log(`[ReportJobStore] Generated ${context_queries.length} context queries`);

                    for (let i = 0; i < context_queries.length; i++) {
                        const cq = context_queries[i];
                        try {
                            const neo4jResult = await window.neo4j.runQuery(cq.cypher, {});
                            let records: any[];
                            if (Array.isArray(neo4jResult)) {
                                records = neo4jResult;
                            } else if (neo4jResult && typeof neo4jResult === 'object') {
                                records = neo4jResult.records || [];
                            } else {
                                records = [];
                            }

                            // Extract DC hostname from dc_detection query
                            if (cq.query_type === 'dc_detection' && records.length > 0) {
                                dcHostname = records[0]?.name || null;
                            }

                            contextQueryResults.push({
                                query_id: cq.id,
                                finding_index: cq.finding_index,
                                query_type: cq.query_type,
                                entity_name: cq.entity_name,
                                results: records,
                                result_count: records.length
                            });
                        } catch (err) {
                            // Skip failed context queries — they're enrichment, not critical
                            console.warn(`[ReportJobStore] Context query "${cq.query_type}" failed:`, err);
                        }
                    }

                    console.log(`[ReportJobStore] Executed ${contextQueryResults.length} context queries, DC: ${dcHostname}`);
                } else {
                    console.warn('[ReportJobStore] Context query generation failed, continuing without enrichment');
                }
            } catch (err) {
                console.warn('[ReportJobStore] Context query step failed, continuing without enrichment:', err);
            }

            set({
                localProgress: {
                    step: 'executing_queries',
                    message: 'Context enrichment complete',
                    percentage: 95
                }
            });

            await new Promise(r => setTimeout(r, 200));

            // ==================== STEP 3.6: CHAIN DISCOVERY ====================
            // Dynamic weighted shortest-path discovery inspired by autobloody.
            // 1. Extract compromisable sources + high-value targets from query results
            // 2. Set edge costs (bloodycost property)
            // 3. Run weighted path queries for each (source, target) pair
            // 4. Cleanup costs
            // 5. Pass chain results to analyze-results

            let chainResults: any[] = [];
            let chainSourceInfo: any[] = [];

            try {
                // Extract compromisable sources from discovery query results
                const sources: Array<{name: string, type: string, compromise_method: string, properties: any}> = [];
                const targets: Array<{name: string, type: string}> = [];

                for (const qr of results) {
                    const queryName = qr.query_name || '';

                    // Source extraction from property-based, ACL-based, and service queries
                    if (queryName.includes('AS-REP') || queryName.includes('Kerberoast') ||
                        queryName.includes('Delegation') || queryName.includes('GMSA') ||
                        queryName.includes('LAPS') || queryName.includes('Dangerous Group') ||
                        queryName.includes('Outbound Object Control') || queryName.includes('Password Not Required') ||
                        queryName.includes('MSSQL') || queryName.includes('SQL') ||
                        queryName.includes('ADCS') || queryName.includes('ManageCA') ||
                        queryName.includes('CERT_PUBLISHERS')) {
                        for (const r of qr.results || []) {
                            // Extract source name from path results (BloodHound CE format)
                            const pathData = r?.p || r?.path;
                            let sourceName: string | null = null;
                            let sourceProps: any = {};

                            if (pathData && typeof pathData === 'object') {
                                if (pathData.start) {
                                    // BloodHound CE format
                                    const props = pathData.start.properties || pathData.start;
                                    sourceName = props.name || null;
                                    sourceProps = props;
                                } else if (pathData.nodes && pathData.nodes.length > 0) {
                                    // Standard format
                                    sourceName = pathData.nodes[0].name || pathData.nodes[0].properties?.name || null;
                                    sourceProps = pathData.nodes[0].properties || pathData.nodes[0];
                                }
                            }

                            if (sourceName && !sources.find(s => s.name === sourceName)) {
                                let method = 'unknown';
                                if (queryName.includes('AS-REP')) method = 'asrep_roastable';
                                else if (queryName.includes('Kerberoast')) method = 'kerberoastable';
                                else if (queryName.includes('Unconstrained')) method = 'unconstrained_delegation';
                                else if (queryName.includes('Constrained')) method = 'constrained_delegation';
                                else if (queryName.includes('GMSA')) method = 'gmsa_readable';
                                else if (queryName.includes('LAPS')) method = 'laps_readable';
                                else if (queryName.includes('Dangerous')) method = 'dangerous_group';
                                else if (queryName.includes('Outbound Object Control')) method = 'outbound_control';
                                else if (queryName.includes('Password Not Required')) method = 'password_not_required';
                                else if (queryName.includes('MSSQL') || queryName.includes('SQL')) method = 'mssql_admin';
                                else if (queryName.includes('ADCS') || queryName.includes('ManageCA') || queryName.includes('CERT_PUBLISHERS')) method = 'adcs_adjacent';
                                else if (queryName.includes('Unconstrained')) method = 'unconstrained_delegation';

                                sources.push({
                                    name: sourceName,
                                    type: 'User',
                                    compromise_method: method,
                                    properties: sourceProps,
                                });
                            }
                        }
                    }

                    // Target extraction from target discovery queries
                    if (queryName.includes('High-Value') || queryName.includes('Domain Object') ||
                        queryName.includes('Domain Controller') || queryName.includes('DA-Session') ||
                        queryName.includes('Certificate Authorit')) {
                        for (const r of qr.results || []) {
                            // Target queries return projected columns: name, labels, objectid
                            const name = r?.name || r?.['g.name'] || r?.['d.name'] || r?.['c.name']
                                || r?.p?.end?.properties?.name || r?.p?.start?.properties?.name;
                            const labels = r?.labels || [];
                            if (name && !targets.find(t => t.name === name)) {
                                targets.push({
                                    name,
                                    type: labels.find((l: string) => l !== 'Base') || 'Unknown'
                                });
                            }
                        }
                    }
                }

                // Second pass: extract ALL User/Computer entities from ALL query results
                // as potential "stepping stone" sources for chain discovery
                const NOISY_ENTITIES = new Set([
                    'DOMAIN USERS', 'DOMAIN COMPUTERS', 'DOMAIN ADMINS',
                    'ENTERPRISE ADMINS', 'ADMINISTRATORS', 'AUTHENTICATED USERS',
                    'EVERYONE', 'DOMAIN CONTROLLERS', 'SCHEMA ADMINS',
                    'ENTERPRISE KEY ADMINS', 'KEY ADMINS',
                ]);
                const sourceNames = new Set(sources.map(s => s.name));
                const targetNames = new Set(targets.map(t => t.name));

                for (const qr of results) {
                    // Skip target discovery queries — those are already handled
                    const qName = qr.query_name || '';
                    if (qName.includes('High-Value') || qName.includes('Domain Object') ||
                        qName.includes('Domain Controller')) continue;

                    for (const r of qr.results || []) {
                        const pathData = r?.p || r?.path;
                        if (!pathData || typeof pathData !== 'object') continue;

                        // Collect all nodes from the path
                        const pathNodes: Array<{name: string, labels: string[], props: any}> = [];

                        if (pathData.start && pathData.segments) {
                            // BloodHound CE format
                            const startProps = pathData.start.properties || pathData.start;
                            const startLabels = pathData.start.labels || [];
                            if (startProps.name) pathNodes.push({ name: startProps.name, labels: startLabels, props: startProps });

                            for (const seg of pathData.segments || []) {
                                const endProps = seg.end?.properties || seg.end || {};
                                const endLabels = seg.end?.labels || [];
                                if (endProps.name) pathNodes.push({ name: endProps.name, labels: endLabels, props: endProps });
                            }
                        } else if (pathData.nodes) {
                            // Standard format
                            for (const node of pathData.nodes) {
                                const props = node.properties || node;
                                const labels = node.labels || [];
                                if (props.name) pathNodes.push({ name: props.name, labels: labels, props: props });
                            }
                        }

                        // Add User/Computer entities not already in sources or targets
                        for (const pn of pathNodes) {
                            const nodeType = pn.labels.find((l: string) => l !== 'Base') || '';
                            const shortName = pn.name.split('@')[0];

                            // Only Users and Computers, skip noisy/group/domain entities
                            if (nodeType !== 'User' && nodeType !== 'Computer') continue;
                            if (NOISY_ENTITIES.has(shortName)) continue;
                            if (sourceNames.has(pn.name) || targetNames.has(pn.name)) continue;

                            sourceNames.add(pn.name);
                            sources.push({
                                name: pn.name,
                                type: nodeType,
                                compromise_method: 'stepping_stone',
                                properties: pn.props,
                            });
                        }
                    }
                }

                console.log(`[ReportJobStore] Chain discovery: ${sources.length} sources, ${targets.length} targets`);
                if (sources.length > 0) console.log(`[ReportJobStore] Sources: ${sources.map(s => s.name.split('@')[0]).join(', ')}`);
                if (targets.length > 0) console.log(`[ReportJobStore] Targets: ${targets.map(t => t.name.split('@')[0]).join(', ')}`);

                if (targets.length > 0) {
                    // Generate and execute chain queries (no cost setup needed —
                    // allShortestPaths is pure Cypher, scoring happens in Python)
                    set({
                        localProgress: {
                            step: 'executing_queries',
                            message: `Running chain queries (${sources.length} sources × ${targets.length} targets)...`,
                            percentage: 75
                        }
                    });

                    const chainQueryRes = await fetch(`${API_URL}/api/attack-paths/generate-chain-queries`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ sources, targets })
                    });

                    if (chainQueryRes.ok) {
                        const chainQueryData = await chainQueryRes.json();
                        console.log(`[ReportJobStore] Executing ${chainQueryData.total_pairs} chain queries`);

                        const CHAIN_QUERY_TIMEOUT = 15000; // 15s per query
                        for (let i = 0; i < chainQueryData.chain_queries.length; i++) {
                            const cq = chainQueryData.chain_queries[i];
                            set({
                                localProgress: {
                                    step: 'executing_queries',
                                    message: `Chain query ${i + 1}/${chainQueryData.total_pairs}: ${cq.source.split('@')[0]} → ${cq.target.split('@')[0]}`,
                                    percentage: 75 + Math.round((i / chainQueryData.total_pairs) * 14)
                                }
                            });

                            try {
                                const queryPromise = window.neo4j.runQuery(cq.cypher, cq.params);
                                const timeoutPromise = new Promise((_, reject) =>
                                    setTimeout(() => reject(new Error('Chain query timeout')), CHAIN_QUERY_TIMEOUT)
                                );
                                const neo4jResult = await Promise.race([queryPromise, timeoutPromise]) as any;

                                let records: any[];
                                if (Array.isArray(neo4jResult)) {
                                    records = neo4jResult;
                                } else if (neo4jResult && typeof neo4jResult === 'object') {
                                    records = neo4jResult.records || [];
                                } else {
                                    records = [];
                                }
                                for (const record of records) {
                                    chainResults.push(record);
                                }
                            } catch (err) {
                                console.warn(`[ReportJobStore] Chain query ${i + 1} skipped:`, (err as Error).message);
                            }
                        }

                        console.log(`[ReportJobStore] Chain discovery: ${chainResults.length} path results`);

                        // Execute reverse chain queries (target → any source)
                        if (chainQueryData.reverse_chain_queries?.length > 0) {
                            console.log(`[ReportJobStore] Executing ${chainQueryData.reverse_chain_queries.length} reverse chain queries`);
                            const REVERSE_QUERY_TIMEOUT = 5000; // 5s per reverse query (wider search)

                            for (let i = 0; i < chainQueryData.reverse_chain_queries.length; i++) {
                                const rq = chainQueryData.reverse_chain_queries[i];
                                set({
                                    localProgress: {
                                        step: 'executing_queries',
                                        message: `Reverse chain ${i + 1}/${chainQueryData.reverse_chain_queries.length}: → ${rq.target.split('@')[0]}`,
                                        percentage: 90 + Math.round((i / chainQueryData.reverse_chain_queries.length) * 5)
                                    }
                                });

                                try {
                                    const queryPromise = window.neo4j.runQuery(rq.cypher, rq.params);
                                    const timeoutPromise = new Promise((_, reject) =>
                                        setTimeout(() => reject(new Error('Reverse chain query timeout')), REVERSE_QUERY_TIMEOUT)
                                    );
                                    const neo4jResult = await Promise.race([queryPromise, timeoutPromise]) as any;

                                    let records: any[];
                                    if (Array.isArray(neo4jResult)) {
                                        records = neo4jResult;
                                    } else if (neo4jResult && typeof neo4jResult === 'object') {
                                        records = neo4jResult.records || [];
                                    } else {
                                        records = [];
                                    }
                                    for (const record of records) {
                                        chainResults.push(record);
                                    }
                                    if (records.length > 0) {
                                        console.log(`[ReportJobStore] Reverse chain → ${rq.target.split('@')[0]}: ${records.length} paths`);
                                    }
                                } catch (err) {
                                    console.warn(`[ReportJobStore] Reverse chain ${i + 1} skipped:`, (err as Error).message);
                                }
                            }

                            console.log(`[ReportJobStore] Total chain results (forward + reverse): ${chainResults.length}`);
                        }
                    }

                    chainSourceInfo = sources;
                }
            } catch (err) {
                console.warn('[ReportJobStore] Chain discovery failed, continuing with static results only:', err);
            }

            // ==================== STEP 4: ANALYZE RESULTS ====================
            set({
                currentStep: 'analyzing',
                currentStepStartedAt: now(),
                progress: {
                    step: 'analyzing',
                    percentage: 10,
                    message: 'Sending query results to RAG for analysis...',
                    timestamp: new Date().toISOString()
                }
            });

            const analyzeResponse = await fetch(`${API_URL}/api/attack-paths/analyze-results`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    analysis_id: get().analysisId,
                    findings_summary: findings,
                    environment_info: get().environmentInfo,
                    query_results: results,
                    options: {},
                    tier0_config: input.tier0Config || null,  // Pass T0 config for classification
                    context_query_results: contextQueryResults.length > 0 ? contextQueryResults : undefined,
                    dc_hostname: dcHostname,
                    // Chain discovery results
                    chain_results: chainResults.length > 0 ? chainResults : undefined,
                    chain_source_info: chainSourceInfo.length > 0 ? chainSourceInfo : undefined
                })
            });

            if (!analyzeResponse.ok) {
                const errorText = await analyzeResponse.text();
                throw new Error(`Failed to analyze results: ${analyzeResponse.status} - ${errorText}`);
            }

            const analyzeResult = await analyzeResponse.json();
            console.log('[ReportJobStore] RAG analysis complete');

            const report = analyzeResult.report;
            set({
                reportData: report,
                progress: {
                    step: 'completed',
                    percentage: 100,
                    message: 'Analysis complete',
                    timestamp: new Date().toISOString()
                }
            });

            // ==================== STEP 5: CREATE PROJECT ====================
            set({
                currentStep: 'creating_project',
                currentStepStartedAt: now(),
                progress: {
                    step: 'creating_project',
                    percentage: 95,
                    message: input.existingProjectId ? 'Linking to existing project...' : 'Creating project...',
                    timestamp: new Date().toISOString()
                }
            });

            const projectStore = useProjectStore.getState();
            let project: any;

            if (input.existingProjectId) {
                const existingProject = await window.database.getProject(input.existingProjectId);
                if (existingProject.success && existingProject.data) {
                    project = existingProject.data;
                    console.log(`[ReportJobStore] Using existing project: ${project.name}`);
                } else {
                    project = await createNewProject(input, get());
                }
            } else {
                project = await createNewProject(input, get());
            }

            // Create chat
            const chatResult = await window.database.createChat(project.id, project.name);
            if (!chatResult.success || !chatResult.data) {
                throw new Error('Failed to create chat');
            }

            const chat = chatResult.data;
            console.log(`[ReportJobStore] Chat created: ${chat.id}`);

            // Add initial message
            const summaryMessage = generateReportSummary(
                report,
                input.analysis,
                input.localAnalysis,
                get().environmentInfo
            );
            await window.database.addMessage(chat.id, 'assistant', summaryMessage, 'report', get().analysisId);

            // Save report
            const reportResult = await window.database.saveReport(
                project.id,
                `${project.name} - Security Report`,
                report,
                chat.id
            );

            if (reportResult.success && reportResult.data) {
                await window.database.updateChatReportId(chat.id, reportResult.data.id);
                console.log(`[ReportJobStore] Report saved: ${reportResult.data.id}`);
            }

            // Update project store
            await projectStore.loadProjects();
            projectStore.setCurrentProject(project);
            projectStore.setActiveProjectId(project.id);

            // Mark job as completed
            set({ currentStep: 'completed' });

            // Navigate to chat
            const { navigateToChat, analysisId, projectId } = get();
            if (navigateToChat) {
                console.log(`[ReportJobStore] Navigating to chat: /chat/${project.id}`);
                navigateToChat(project.id, {
                    reportData: report,
                    analysisId: analysisId,
                    openReport: true,
                    neo4jProjectId: projectId,
                    chatId: chat.id
                });
            }

            // Reset after navigation
            set({ isRunning: false });
            useUploadStore.getState().resetUpload();

        } catch (err: any) {
            console.error('[ReportJobStore] Pipeline failed:', err);
            set({
                currentStep: 'error',
                error: err.message || 'Analysis failed',
                isRunning: false
            });
        }
        };

        // Execute pipeline in next tick to ensure state is committed first
        // This allows React to see isRunning=true before any async work starts
        setTimeout(runPipeline, 0);
    },

    cancelJob: () => {
        console.log('[ReportJobStore] Cancelling job');
        set({
            isRunning: false,
            currentStep: 'idle',
            error: 'Job cancelled by user',
            jobStartedAt: null,
            currentStepStartedAt: null,
            elapsedSeconds: 0,
            stepElapsedSeconds: 0
        });
    },

    reset: () => {
        set({
            isRunning: false,
            fileName: null,
            currentStep: 'idle',
            progress: null,
            localProgress: null,
            error: null,
            analysisId: '',
            projectId: '',
            generatedQueries: [],
            queryResults: [],
            environmentInfo: null,
            reportData: null,
            jobInput: null,
            jobStartedAt: null,
            currentStepStartedAt: null,
            elapsedSeconds: 0,
            stepElapsedSeconds: 0
        });
    }
}));

// ==================== HELPER: Create New Project ====================

async function createNewProject(input: JobInput, state: ReportJobStore): Promise<any> {
    const baseName = input.fileName || input.localAnalysis?.filename || `Analysis - ${new Date().toLocaleDateString()}`;
    const projectName = await getUniqueProjectName(baseName);
    console.log(`[ReportJobStore] Creating new project: ${projectName}`);

    const domainFromAnalysis = input.analysis?.domain ? [input.analysis.domain] : [];
    const domains = domainFromAnalysis.length > 0 ? domainFromAnalysis : (state.environmentInfo?.domains || []);
    const domainName = domains.length > 0 ? domains.join(',') : undefined;

    const projectResult = await window.database.createProject(
        projectName,
        `Security analysis generated on ${new Date().toLocaleString()}`,
        state.projectId,
        domainName
    );

    if (!projectResult.success || !projectResult.data) {
        throw new Error('Failed to create project');
    }

    console.log(`[ReportJobStore] Project created: ${projectResult.data.id}`);
    return projectResult.data;
}

async function getUniqueProjectName(baseName: string): Promise<string> {
    try {
        const result = await window.database.getAllProjects();
        const projects = result.data || [];
        const existingNames = projects.map((p: any) => p.name);

        if (!existingNames.includes(baseName)) return baseName;

        let counter = 2;
        while (existingNames.includes(`${baseName} (${counter})`)) {
            counter++;
        }
        return `${baseName} (${counter})`;
    } catch (err) {
        return `${baseName} - ${Date.now()}`;
    }
}

// Convenience selectors
export const useIsReportJobRunning = () => useReportJobStore(s => s.isRunning);
export const useReportJobStep = () => useReportJobStore(s => s.currentStep);
export const useReportJobProgress = () => useReportJobStore(s => s.localProgress);

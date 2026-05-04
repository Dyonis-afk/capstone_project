/**
 * Chat Service
 * Local-first service for executing queries and getting suggestions.
 *
 * Flow (Local-First Architecture):
 * 1. Send query to backend /prepare-query (classify, generate Cypher)
 * 2. Execute Cypher locally via window.neo4j.runQuery()
 * 3. Send results to backend /format-results (RAG explanation)
 *
 * This ensures Neo4j queries run against the correct BloodHound CE instance
 * (Docker or Custom mode) as configured in the Electron app.
 */

import {
    QueryResponse,
    QueryType,
    ViewMode,
    AdditionalFinding,
    SuggestedQuery,
    SuggestionsResponse,
    ChatGraphData
} from '../types/chat';
import { Finding } from '../components/attack-components/types';
import { API_URL } from '../config/api';

interface ChatServiceConfig {
    baseUrl: string;
    queryTimeout: number;
    reportQueryTimeout: number;
}

const config: ChatServiceConfig = {
    baseUrl: API_URL,
    queryTimeout: 120000,  // 2 minutes for normal queries
    reportQueryTimeout: 180000,  // 3 minutes for report format (finding generation is slower)
};

// Types for local-first endpoints
interface PrepareQueryResponse {
    success: boolean;
    query_type: QueryType;
    cypher_query?: string;
    cypher_queries?: Array<{ name: string; cypher: string }>;
    is_safe: boolean;
    suggested_query?: string;
    explanation?: string;
    error?: string;
}

interface FormatResultsResponse {
    success: boolean;
    explanation?: string;
    understanding?: Array<{ question: string; answer: string }>;
    attack_steps?: Array<{
        step_number: number;
        title: string;
        tool: string;
        command: string;
        explanation: string;
    }>;
    remediation?: string;
    finding?: Record<string, unknown>;
    graph_data?: {
        nodes: Array<Record<string, unknown>>;
        edges: Array<Record<string, unknown>>;
        paths: Array<Record<string, unknown>>;
    };
    has_graph: boolean;
    error?: string;
}

/**
 * Fetch with timeout utility
 */
async function fetchWithTimeout(
    url: string,
    options: RequestInit = {},
    timeout: number
): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
        controller.abort(new Error(`Request timed out after ${timeout / 1000} seconds`));
    }, timeout);

    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        clearTimeout(timeoutId);
        return response;
    } catch (error: any) {
        clearTimeout(timeoutId);
        // Provide a more user-friendly error message for abort errors
        if (error?.name === 'AbortError' || error?.message?.includes('aborted')) {
            throw new Error('Request was cancelled or timed out. Please try again.');
        }
        throw error;
    }
}

/**
 * Detect if a query is Cypher or natural language
 */
function detectQueryType(query: string): QueryType {
    const trimmed = query.trim().toUpperCase();

    // Check for Cypher patterns
    const cypherPatterns = [
        /^MATCH\s/i,
        /^OPTIONAL\s+MATCH/i,
        /^WITH\s/i,
        /^RETURN\s/i,
        /^CALL\s/i,
        /^UNWIND\s/i
    ];

    for (const pattern of cypherPatterns) {
        if (pattern.test(trimmed)) {
            return 'cypher';
        }
    }

    // Empty query is for suggestions
    if (!query.trim()) {
        return 'suggestion';
    }

    return 'natural_language';
}

/**
 * Chat Service API
 */
export const chatService = {
    /**
     * Execute a query using local-first architecture
     *
     * Flow:
     * 1. Call /prepare-query to get Cypher (backend classifies, generates if needed)
     * 2. Execute Cypher locally via window.neo4j.runQuery()
     * 3. Call /format-results to get RAG explanation
     *
     * This ensures queries run against the correct Neo4j instance (Docker or Custom mode)
     */
    // Track current request ID for cancellation
    _currentRequestId: null as string | null,

    /**
     * Cancel the current in-flight request on the backend.
     * Prevents remaining LLM generators from starting.
     */
    async cancelCurrentRequest(): Promise<void> {
        if (chatService._currentRequestId) {
            const requestId = chatService._currentRequestId;
            chatService._currentRequestId = null;
            try {
                await fetch(`${config.baseUrl}/api/chat/cancel-request/${requestId}`, { method: 'POST' });
                console.log(`[ChatService] Cancelled request ${requestId.slice(0, 8)}...`);
            } catch {
                // Best effort — backend may have already finished
            }
        }
    },

    async executeQuery(
        query: string,
        outputFormat: ViewMode = 'normal',
        projectId?: string,
        domain?: string
    ): Promise<QueryResponse> {
        try {
            // Generate unique request ID for cancellation tracking
            const requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
            chatService._currentRequestId = requestId;
            console.log(`[ChatService] Starting query execution (${requestId.slice(0, 12)}...)`);

            // Try to get domain from Neo4j if not provided
            let effectiveDomain = domain;
            if (!effectiveDomain && window.neo4j?.extractFindings) {
                try {
                    const findings = await window.neo4j.extractFindings();
                    // domains array is at the top level of ExtractedFindings
                    effectiveDomain = findings?.domains?.[0];
                    if (effectiveDomain) {
                        console.log('[ChatService] Auto-detected domain:', effectiveDomain);
                    }
                } catch (e) {
                    console.warn('[ChatService] Could not auto-detect domain:', e);
                }
            }

            // Step 1: Prepare query (classify, generate Cypher if needed)
            const prepareResponse = await fetchWithTimeout(
                `${config.baseUrl}/api/chat/prepare-query`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        query,
                        project_id: projectId,
                        domain: effectiveDomain
                    })
                },
                60000  // 60s for preparation (RAG query generation can be slow)
            );

            if (!prepareResponse.ok) {
                const errorData = await prepareResponse.json().catch(() => ({}));
                throw new Error(errorData.detail || `Query preparation failed: ${prepareResponse.status}`);
            }

            const prepared: PrepareQueryResponse = await prepareResponse.json();
            console.log('[ChatService] Prepare response:', prepared);

            // Handle errors from preparation
            if (!prepared.success) {
                return {
                    success: false,
                    query_type: prepared.query_type || 'invalid',
                    result_count: 0,
                    has_graph: false,
                    error: prepared.error
                };
            }

            // Handle suggestion responses - validate the suggested query first
            if (prepared.query_type === 'suggestion' && prepared.suggested_query) {
                // Validate the suggested query before showing it
                if (window.neo4j?.runQuery) {
                    try {
                        // Convert to COUNT query for validation
                        let countQuery = prepared.suggested_query;
                        const returnMatch = countQuery.match(/RETURN\s+(.+?)(\s+LIMIT|\s*$)/i);
                        if (returnMatch) {
                            countQuery = countQuery.replace(/RETURN\s+.+?(\s+LIMIT|\s*$)/i, 'RETURN count(*) AS cnt$1');
                        }

                        const validationResult = await window.neo4j.runQuery(countQuery, {});
                        const resultCount = validationResult.success && validationResult.records?.[0]?.cnt
                            ? Number(validationResult.records[0].cnt)
                            : 0;

                        if (resultCount === 0) {
                            console.log('[ChatService] Suggested query would return no results, skipping suggestion');
                            // Return explanation without the invalid query
                            return {
                                success: true,
                                query_type: 'suggestion',
                                result_count: 0,
                                has_graph: false,
                                explanation: prepared.explanation + '\n\n*Note: The suggested query would return no results for your current data. Try exploring with the Suggest button for validated queries.*'
                            };
                        }

                        console.log(`[ChatService] Validated suggested query: ${resultCount} results`);
                    } catch (validationError) {
                        console.warn('[ChatService] Could not validate suggested query:', validationError);
                        // Continue with the suggestion anyway if validation fails
                    }
                }

                return {
                    success: true,
                    query_type: 'suggestion',
                    result_count: 0,
                    has_graph: false,
                    explanation: prepared.explanation,
                    suggested_query: prepared.suggested_query
                };
            }

            // ================================================================
            // MULTI-QUERY PATH: Execute each named query separately
            // ================================================================
            if (prepared.cypher_queries && prepared.cypher_queries.length > 0) {
                console.log(`[ChatService] Multi-query: ${prepared.cypher_queries.length} named queries`);

                if (!window.neo4j?.runQuery) {
                    return { success: false, query_type: 'invalid', result_count: 0, has_graph: false, error: 'Neo4j service not available.' };
                }

                // Get DC hostname once for all queries
                let dcHostname = '';
                try {
                    const dcResult = await window.neo4j.runQuery(
                        "MATCH (c:Computer) WHERE c.isdc = true OR c.unconstraineddelegation = true RETURN c.name AS name LIMIT 1"
                    );
                    const dcRecords = Array.isArray(dcResult) ? dcResult : dcResult?.records || [];
                    if (dcRecords.length > 0) dcHostname = dcRecords[0]?.name || '';
                } catch { /* optional */ }

                // Execute all queries against Neo4j (parallel)
                const queryResults: Array<{ name: string; cypher: string; results: any[]; error?: string }> = [];
                await Promise.all(prepared.cypher_queries.map(async (nq: { name: string; cypher: string }) => {
                    try {
                        const neo4jResult = await window.neo4j.runQuery(nq.cypher, {});
                        const records = neo4jResult?.success ? (neo4jResult.records || []) : [];
                        queryResults.push({ name: nq.name, cypher: nq.cypher, results: records });
                    } catch (err: unknown) {
                        const msg = err instanceof Error ? err.message : 'Unknown error';
                        queryResults.push({ name: nq.name, cypher: nq.cypher, results: [], error: msg });
                    }
                }));

                // Filter to queries that returned results
                const withResults = queryResults.filter(qr => qr.results.length > 0);
                console.log(`[ChatService] Multi-query: ${withResults.length}/${queryResults.length} returned results`);

                if (withResults.length === 0) {
                    return {
                        success: true,
                        query_type: prepared.query_type,
                        result_count: 0,
                        has_graph: false,
                        explanation: `Ran ${queryResults.length} queries but none returned results. The environment may not have these attack paths.`
                    };
                }

                // Format each result set (concurrency limit: 3)
                const CONCURRENCY = 3;
                const multiFindings: import('../types/chat').MultiQueryFinding[] = [];

                for (let i = 0; i < withResults.length; i += CONCURRENCY) {
                    const batch = withResults.slice(i, i + CONCURRENCY);
                    const batchResults = await Promise.all(batch.map(async (qr) => {
                        try {
                            const formatTimeout = outputFormat === 'report' ? config.reportQueryTimeout : config.queryTimeout;
                            const formatResp = await fetchWithTimeout(
                                `${config.baseUrl}/api/chat/format-results`,
                                {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({
                                        query: qr.name,
                                        cypher_query: qr.cypher,
                                        results: qr.results,
                                        output_format: outputFormat,
                                        project_id: projectId,
                                        dc_hostname: dcHostname,
                                        request_id: requestId
                                    })
                                },
                                formatTimeout
                            );

                            if (formatResp.ok) {
                                const data = await formatResp.json();
                                return {
                                    query_name: qr.name,
                                    cypher_query: qr.cypher,
                                    result_count: qr.results.length,
                                    results: qr.results,
                                    finding: data.finding || undefined,
                                    explanation: data.explanation || undefined,
                                    understanding: data.understanding || undefined,
                                    attack_steps: data.attack_steps || undefined,
                                    graph_data: data.graph_data || undefined,
                                    has_graph: data.has_graph || false,
                                } as import('../types/chat').MultiQueryFinding;
                            }
                            return {
                                query_name: qr.name, cypher_query: qr.cypher, result_count: qr.results.length,
                                has_graph: false, error: 'Format request failed'
                            } as import('../types/chat').MultiQueryFinding;
                        } catch (err: unknown) {
                            const msg = err instanceof Error ? err.message : 'Unknown error';
                            return {
                                query_name: qr.name, cypher_query: qr.cypher, result_count: qr.results.length,
                                has_graph: false, error: msg
                            } as import('../types/chat').MultiQueryFinding;
                        }
                    }));
                    multiFindings.push(...batchResults);
                }

                const totalResults = withResults.reduce((sum, qr) => sum + qr.results.length, 0);
                return {
                    success: true,
                    query_type: prepared.query_type,
                    cypher_queries: prepared.cypher_queries,
                    result_count: totalResults,
                    has_graph: multiFindings.some(f => f.has_graph),
                    multi_findings: multiFindings,
                    explanation: `Found ${totalResults} results across ${withResults.length} queries.`,
                    view_mode: outputFormat
                };
            }

            // ================================================================
            // SINGLE-QUERY PATH (existing flow)
            // ================================================================

            // Ensure we have a Cypher query to execute
            if (!prepared.cypher_query) {
                return {
                    success: false,
                    query_type: 'invalid',
                    result_count: 0,
                    has_graph: false,
                    error: 'No Cypher query generated'
                };
            }

            // Step 2: Execute query LOCALLY via Electron's Neo4j service
            console.log('[ChatService] Executing query locally:', prepared.cypher_query);
            let localResults: Array<Record<string, unknown>> = [];

            if (window.neo4j?.runQuery) {
                try {
                    const neo4jResult = await window.neo4j.runQuery(
                        prepared.cypher_query,
                        {}
                    );

                    if (neo4jResult.success && neo4jResult.records) {
                        localResults = neo4jResult.records;
                        console.log(`[ChatService] Local query returned ${localResults.length} results`);
                    } else if (neo4jResult.error) {
                        console.error('[ChatService] Local query error:', neo4jResult.error);
                        return {
                            success: false,
                            query_type: prepared.query_type,
                            cypher_query: prepared.cypher_query,
                            result_count: 0,
                            has_graph: false,
                            error: `Query execution failed: ${neo4jResult.error}`
                        };
                    }
                } catch (neo4jError: unknown) {
                    console.error('[ChatService] Neo4j execution error:', neo4jError);
                    const errorMessage = neo4jError instanceof Error ? neo4jError.message : 'Unknown error';
                    return {
                        success: false,
                        query_type: prepared.query_type,
                        cypher_query: prepared.cypher_query,
                        result_count: 0,
                        has_graph: false,
                        error: `Local query execution failed: ${errorMessage}`
                    };
                }
            } else {
                console.error('[ChatService] window.neo4j.runQuery not available');
                return {
                    success: false,
                    query_type: 'invalid',
                    result_count: 0,
                    has_graph: false,
                    error: 'Neo4j service not available. Please check your connection.'
                };
            }

            // Step 3: Get DC hostname for accurate commands
            let dcHostname = '';
            try {
                if (window.neo4j?.runQuery) {
                    const dcResult = await window.neo4j.runQuery(
                        "MATCH (c:Computer) WHERE c.isdc = true OR c.unconstraineddelegation = true RETURN c.name AS name LIMIT 1"
                    );
                    const dcRecords = Array.isArray(dcResult) ? dcResult : dcResult?.records || [];
                    if (dcRecords.length > 0) {
                        dcHostname = dcRecords[0]?.name || '';
                    }
                }
            } catch {
                // DC hostname is optional — commands will use fallback
            }

            // Step 4: Format results with RAG explanation
            console.log('[ChatService] Formatting results with RAG...');
            const timeout = outputFormat === 'report'
                ? config.reportQueryTimeout
                : config.queryTimeout;

            const formatResponse = await fetchWithTimeout(
                `${config.baseUrl}/api/chat/format-results`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        query,
                        cypher_query: prepared.cypher_query,
                        results: localResults,
                        output_format: outputFormat,
                        project_id: projectId,
                        dc_hostname: dcHostname,
                        request_id: requestId
                    })
                },
                timeout
            );

            if (!formatResponse.ok) {
                // Even if formatting fails, return the raw results
                console.warn('[ChatService] Format request failed, returning raw results');
                return {
                    success: true,
                    query_type: prepared.query_type,
                    cypher_query: prepared.cypher_query,
                    results: localResults,
                    result_count: localResults.length,
                    has_graph: false,
                    explanation: `**${localResults.length} results found** (RAG analysis unavailable)`
                };
            }

            const formatted: FormatResultsResponse = await formatResponse.json();
            console.log('[ChatService] Format response received');

            // Combine results
            return {
                success: true,
                query_type: prepared.query_type,
                cypher_query: prepared.cypher_query,
                results: localResults,
                result_count: localResults.length,
                explanation: formatted.explanation,
                understanding: formatted.understanding,
                attack_steps: formatted.attack_steps,
                remediation: formatted.remediation,
                finding: formatted.finding as Finding | undefined,
                graph_data: formatted.graph_data as ChatGraphData | undefined,
                has_graph: formatted.has_graph
            };

        } catch (error) {
            console.error('[ChatService] Query execution error:', error);
            chatService._currentRequestId = null;

            return {
                success: false,
                query_type: 'invalid',
                result_count: 0,
                has_graph: false,
                error: error instanceof Error
                    ? error.message
                    : 'An unexpected error occurred while processing your query.'
            };
        }
    },

    /**
     * Get query suggestions based on the environment (local-first)
     *
     * Flow:
     * 1. Gather environment context from local Neo4j
     * 2. Send context to backend via POST
     * 3. Backend generates suggestions based on provided context
     */
    async getSuggestions(
        projectId?: string,
        includeAiSuggestions: boolean = true
    ): Promise<SuggestionsResponse> {
        try {
            // Step 1: Gather environment context from local Neo4j
            let environmentContext = null;

            if (window.neo4j?.extractFindings) {
                try {
                    console.log('[ChatService] Gathering environment context from local Neo4j...');
                    const findings = await window.neo4j.extractFindings();

                    if (findings && findings.summary) {
                        environmentContext = {
                            kerberoastable_users: findings.high_risk
                                ?.filter((r: any) => r.edge_type === 'HasSPN' || r.source_type === 'User')
                                ?.slice(0, 5)
                                ?.map((r: any) => r.source) || [],
                            asrep_roastable_users: findings.high_risk
                                ?.filter((r: any) => r.edge_type === 'DontReqPreAuth')
                                ?.slice(0, 5)
                                ?.map((r: any) => r.source) || [],
                            unconstrained_delegation: findings.high_risk
                                ?.filter((r: any) => r.edge_type === 'AllowedToDelegate' || r.target_type === 'Computer')
                                ?.slice(0, 5)
                                ?.map((r: any) => r.target) || [],
                            domain_admins: findings.domain_admin_groups || [],
                            total_users: findings.summary.total_users || 0,
                            total_computers: findings.summary.total_computers || 0,
                            total_groups: findings.summary.total_groups || 0,
                            domains: findings.domains || [],
                            high_value_targets: findings.high_value_targets?.map((t: any) => t.name) || []
                        };
                        console.log('[ChatService] Environment context gathered:',
                            `${environmentContext.total_users} users, ${environmentContext.total_computers} computers`);
                    }
                } catch (neo4jError) {
                    console.warn('[ChatService] Could not gather local Neo4j context:', neo4jError);
                    // Continue without context - will get predefined suggestions only
                }
            }

            // Step 2: Send to backend via POST with context
            const response = await fetchWithTimeout(
                `${config.baseUrl}/api/chat/suggestions`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        project_id: projectId,
                        include_ai: includeAiSuggestions,
                        environment_context: environmentContext
                    })
                },
                30000  // 30 seconds for suggestions
            );

            if (!response.ok) {
                throw new Error(`Failed to get suggestions: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            console.error('Get suggestions error:', error);
            return {
                suggestions: [],
                ai_suggestions: []
            };
        }
    },

    /**
     * Get quick suggestions only (fast, predefined queries)
     */
    async getQuickSuggestions(projectId?: string): Promise<SuggestedQuery[]> {
        const response = await this.getSuggestions(projectId, false);
        return response.suggestions;
    },

    /**
     * Add a finding to the report's additional_findings array
     */
    async addFindingToReport(
        reportId: string,
        finding: Finding,
        sourceQuery: string,
        cypherQuery?: string,
        resultCount: number = 0,
        userNotes?: string,
        graphData?: ChatGraphData
    ): Promise<AdditionalFinding> {
        const additionalFinding: AdditionalFinding = {
            id: crypto.randomUUID(),
            added_at: new Date().toISOString(),
            source_query: sourceQuery,
            cypher_query: cypherQuery,
            result_count: resultCount,
            user_notes: userNotes,
            finding,
            graph_data: graphData
        };

        // Use Electron's database API to update the report
        if (window.database && typeof window.database.addFindingToReport === 'function') {
            await window.database.addFindingToReport(reportId, additionalFinding);
        } else {
            console.warn('Database API not available. Finding not persisted.');
        }

        return additionalFinding;
    },

    /**
     * Remove a finding from the report
     */
    async removeFindingFromReport(reportId: string, findingId: string): Promise<void> {
        if (window.database && typeof window.database.removeFindingFromReport === 'function') {
            await window.database.removeFindingFromReport(reportId, findingId);
        } else {
            console.warn('Database API not available. Cannot remove finding.');
        }
    },

    /**
     * Health check for chat service
     */
    async healthCheck(): Promise<{
        status: string;
        rag_service: string;
        neo4j_service: string;
    }> {
        try {
            const response = await fetchWithTimeout(
                `${config.baseUrl}/api/chat/health`,
                { method: 'GET' },
                5000
            );

            if (response.ok) {
                return await response.json();
            }

            return {
                status: 'error',
                rag_service: 'unknown',
                neo4j_service: 'unknown'
            };
        } catch (error) {
            return {
                status: 'error',
                rag_service: 'unavailable',
                neo4j_service: 'unavailable'
            };
        }
    },

    /**
     * Utility: Detect query type
     */
    detectQueryType
};

export default chatService;

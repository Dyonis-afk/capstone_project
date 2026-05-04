import type { Finding, AnalysisSummary, BloodHoundAnalysis, DetailedRemediation } from '@/types';
import { API_URL } from '../config/api';

interface ApiConfig {
    baseUrl: string;
    timeout: number;
    ragTimeout: number;
    batchTimeout: number;
    progressTimeout: number;
}

const config: ApiConfig = {
    baseUrl: API_URL,
    timeout: 30000,        // 30 seconds
    ragTimeout: 120000,    // 2 minutes for RAG queries
    batchTimeout: 300000,  // 5 minutes for batch operations
    progressTimeout: 30000 // 30 seconds for progress checks (backend may be slow during analysis)
};

class ApiService {
    private async fetchWithTimeout(
        url: string,
        options: RequestInit = {},
        timeout = config.timeout
    ): Promise<Response> {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(timeoutId);
            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    /**
     * Test backend connection
     */
    async testConnection(): Promise<boolean> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/health`,
                { method: 'GET' },
                5000 // 5 second timeout for health check
            );

            console.log('Connection test result:', response.status === 200);
            return response.status === 200;
        } catch (error) {
            console.error('Connection test failed:', error);
            return false;
        }
    }

    /**
     * Test Neo4j connection via backend
     */
    async testNeo4jConnection(): Promise<boolean> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/neo4j/test`,
                { method: 'GET' },
                5000
            );

            console.log('Neo4j test result:', response.status === 200);
            return response.status === 200;
        } catch (error) {
            console.error('Neo4j connection test failed:', error);
            return false;
        }
    }

    /**
     * Query RAG system
     */
    async queryRAG(question: string, projectId?: string): Promise<{ answer: string; sources: string[] }> {
        try {
            const url = projectId
                ? `${config.baseUrl}/api/query?project_id=${projectId}`
                : `${config.baseUrl}/api/query`;
            const response = await this.fetchWithTimeout(
                url,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ question })
                },
                config.ragTimeout
            );

            if (response.ok) {
                const data = await response.json();
                return {
                    answer: data.answer || data.result || '',
                    sources: data.sources || []
                };
            } else {
                throw new Error(`Query failed: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Failed to query RAG: ${error}`);
        }
    }

    /**
     * Upload BloodHound JSON file
     */
    /**
     * Check data status in Neo4j
     */
    async checkDataStatus(projectId?: string): Promise<{
        has_existing_data: boolean;
        total_nodes: number;
        total_relationships: number;
        users: number;
        groups: number;
        computers: number;
        recommendation: 'ready_for_import' | 'suggest_replace' | 'user_choice_required';
        message: string;
        estimated_clear_time: string;
        error?: string;
    }> {
        try {
            // Use project-specific endpoint if projectId provided
            const url = projectId
                ? `${config.baseUrl}/api/bloodhound/project/${projectId}/status`
                : `${config.baseUrl}/api/attack-paths/data/status`;

            console.log(`🔵 [FRONTEND] [API] Calling GET ${url}`);
            const response = await this.fetchWithTimeout(
                url,
                { method: 'GET' },
                10000
            );

            if (response.ok) {
                return await response.json();
            } else {
                throw new Error(`Failed to check data status: ${response.status}`);
            }
        } catch (error) {
            console.error('Data status check failed:', error);
            // Return safe default
            return {
                has_existing_data: false,
                total_nodes: 0,
                total_relationships: 0,
                users: 0,
                groups: 0,
                computers: 0,
                recommendation: 'ready_for_import',
                message: 'Unable to check existing data status',
                estimated_clear_time: '30 seconds',
                error: error instanceof Error ? error.message : 'Unknown error'
            };
        }
    }

    /**
     * Clear existing data from Neo4j
     */
    async clearExistingData(projectId?: string): Promise<{
        success: boolean;
        message: string;
        cleared_relationships: number;
        cleared_nodes: number;
    }> {
        try {
            // Use project-specific endpoint if projectId provided
            if (projectId) {
                const response = await this.fetchWithTimeout(
                    `${config.baseUrl}/api/bloodhound/project/${projectId}/clear?confirm=true`,
                    { method: 'DELETE' },
                    60000
                );

                if (response.ok) {
                    const data = await response.json();
                    return {
                        success: true,
                        message: data.message || 'Project data cleared',
                        cleared_relationships: data.relationships_deleted || 0,
                        cleared_nodes: data.nodes_deleted || 0
                    };
                } else {
                    const errorText = await response.text();
                    throw new Error(`Failed to clear project data: ${response.status} - ${errorText}`);
                }
            } else {
                // Legacy: clear all data
                const response = await this.fetchWithTimeout(
                    `${config.baseUrl}/api/attack-paths/data/clear`,
                    { method: 'POST' },
                    60000 // 1 minute timeout for clearing
                );

                if (response.ok) {
                    return await response.json();
                } else {
                    const errorText = await response.text();
                    throw new Error(`Failed to clear data: ${response.status} - ${errorText}`);
                }
            }
        } catch (error) {
            throw new Error(`Failed to clear data: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    async uploadBloodHoundFile(
        file: File,
        importMode: 'replace' | 'append' = 'replace',
        clearFirst: boolean = false,
        projectId?: string
    ): Promise<BloodHoundAnalysis> {
        try {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('import_mode', importMode);
            formData.append('clear_first', clearFirst.toString());

            // Use project-specific upload if projectId provided
            const url = projectId
                ? `${config.baseUrl}/api/bloodhound/upload?project_id=${projectId}`
                : `${config.baseUrl}/api/attack-paths/bloodhound/upload-with-mode`;

            const response = await this.fetchWithTimeout(
                url,
                {
                    method: 'POST',
                    body: formData
                },
                config.timeout
            );

            if (response.ok) {
                const data = await response.json();
                // If the new endpoint returns different structure, parse it
                if (data.statistics) {
                    // Convert to BloodHoundAnalysis format
                    return this.parseBloodHoundUploadResponse({
                        summary: {
                            totalFindings: data.statistics.total_relationships || 0,
                            highRisk: 0,
                            mediumRisk: 0,
                            lowRisk: 0
                        }
                    });
                }
                return this.parseBloodHoundUploadResponse(data);
            } else {
                const errorText = await response.text();
                throw new Error(`Upload failed: ${response.status} - ${errorText}`);
            }
        } catch (error) {
            throw new Error(`Failed to upload file: ${error}`);
        }
    }

    /**
     * Get all findings
     */
    async getFindings(riskLevel?: string): Promise<BloodHoundAnalysis> {
        try {
            let url = `${config.baseUrl}/api/bloodhound/findings`;
            if (riskLevel) {
                url += `?risk_level=${encodeURIComponent(riskLevel)}`;
            }

            const response = await this.fetchWithTimeout(url, { method: 'GET' });

            if (response.ok) {
                const data = await response.json();
                return this.parseBloodHoundFindingsResponse(data);
            } else if (response.status === 404) {
                throw new Error('No analysis data available. Please upload a BloodHound file first.');
            } else {
                throw new Error(`Failed to get findings: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Failed to get findings: ${error}`);
        }
    }

    /**
     * Get summary statistics
     */
    async getSummary(): Promise<AnalysisSummary> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/bloodhound/summary`,
                { method: 'GET' }
            );

            if (response.ok) {
                const data = await response.json();
                return this.parseAnalysisSummary(data.summary || data);
            } else {
                throw new Error(`Failed to get summary: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Failed to get summary: ${error}`);
        }
    }

    /**
     * Clear stored findings
     */
    async clearFindings(): Promise<void> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/bloodhound/clear`,
                { method: 'DELETE' }
            );

            if (!response.ok) {
                throw new Error(`Failed to clear findings: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Failed to clear findings: ${error}`);
        }
    }

    /**
     * Get data status for a specific project
     */
    async getProjectDataStatus(projectId: string): Promise<{
        has_existing_data: boolean;
        total_nodes: number;
        total_relationships: number;
        users: number;
        groups: number;
        computers: number;
        recommendation: string;
        message: string;
        estimated_clear_time: string;
    }> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/bloodhound/project/${projectId}/status`,
                { method: 'GET' },
                10000
            );

            if (response.ok) {
                return await response.json();
            } else {
                throw new Error(`Failed to get project status: ${response.status}`);
            }
        } catch (error) {
            console.error('Project status check failed:', error);
            return {
                has_existing_data: false,
                total_nodes: 0,
                total_relationships: 0,
                users: 0,
                groups: 0,
                computers: 0,
                recommendation: 'ready_for_import',
                message: 'Unable to check project data status',
                estimated_clear_time: 'unknown'
            };
        }
    }

    /**
     * Clear data for a specific project
     */
    async clearProjectData(projectId: string): Promise<{
        success: boolean;
        nodes_deleted: number;
        relationships_deleted: number;
        message?: string;
    }> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/bloodhound/project/${projectId}/clear?confirm=true`,
                { method: 'DELETE' },
                60000
            );

            if (response.ok) {
                const data = await response.json();
                return {
                    success: true,
                    nodes_deleted: data.nodes_deleted || 0,
                    relationships_deleted: data.relationships_deleted || 0,
                    message: data.message
                };
            } else {
                throw new Error(`Failed to clear project data: ${response.status}`);
            }
        } catch (error) {
            return {
                success: false,
                nodes_deleted: 0,
                relationships_deleted: 0,
                message: error instanceof Error ? error.message : 'Unknown error'
            };
        }
    }

    /**
     * Test RAG service
     */
    async testRAGService(): Promise<{ status: string; message: string }> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/query/health`,
                { method: 'GET' }
            );

            if (response.ok) {
                return await response.json();
            } else {
                throw new Error(`RAG test failed: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Failed to test RAG service: ${error}`);
        }
    }

    /**
     * Generate remediation for a single finding
     */
    async generateRemediation(finding: Finding): Promise<DetailedRemediation> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/remediation/generate`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        edge_type: finding.edgeType,
                        source: finding.source,
                        target: finding.target,
                        source_type: finding.sourceType || 'User',
                        target_type: finding.targetType || 'Computer'
                    })
                },
                config.ragTimeout
            );

            if (response.ok) {
                const data = await response.json();
                return this.parseDetailedRemediation(data);
            } else {
                throw new Error(`Remediation failed: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Failed to generate remediation: ${error}`);
        }
    }

    /**
     * Generate batch remediation for multiple findings
     */
    async generateBatchRemediation(
        findings: Finding[],
        priority: 'high_first' | 'low_first' | 'as_provided' = 'high_first'
    ): Promise<{ remediations: DetailedRemediation[]; successful: number; failed: number }> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/remediation/batch`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        findings: findings.map(f => ({
                            edge_type: f.edgeType,
                            source: f.source,
                            target: f.target,
                            source_type: f.sourceType || 'User',
                            target_type: f.targetType || 'Computer'
                        })),
                        priority
                    })
                },
                config.batchTimeout
            );

            if (response.ok) {
                const data = await response.json();
                return {
                    remediations: data.remediations.map((r: any) => this.parseDetailedRemediation(r)),
                    successful: data.successful || 0,
                    failed: data.failed || 0
                };
            } else {
                throw new Error(`Batch remediation failed: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Failed to generate batch remediation: ${error}`);
        }
    }

    /**
     * Get quick remediation for an edge type
     */
    async getQuickRemediation(edgeType: string): Promise<{
        edge_type: string;
        risk_level: string;
        quick_info: string;
        sources: string[];
    }> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/remediation/quick/${encodeURIComponent(edgeType)}`,
                { method: 'GET' },
                config.ragTimeout
            );

            if (response.ok) {
                return await response.json();
            } else {
                throw new Error(`Quick remediation failed: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Failed to get quick remediation: ${error}`);
        }
    }

    /**
     * Natural language Neo4j query
     */
    async naturalLanguageQuery(question: string): Promise<{
        success: boolean;
        generated_cypher: string;
        results: any[];
        analysis: string;
        result_count: number;
    }> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/neo4j/natural-query`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ question })
                },
                config.ragTimeout
            );

            if (response.ok) {
                return await response.json();
            } else {
                throw new Error(`Natural query failed: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Failed to execute natural query: ${error}`);
        }
    }

    /**
     * Execute raw Cypher query
     */
    async executeCypherQuery(cypher: string, projectId?: string): Promise<{
        success: boolean;
        records: any[];
        summary: any;
    }> {
        try {
            const url = projectId
                ? `${config.baseUrl}/api/neo4j/cypher?project_id=${projectId}`
                : `${config.baseUrl}/api/neo4j/execute`;

            const response = await this.fetchWithTimeout(
                url,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cypher })
                },
                config.ragTimeout
            );

            if (response.ok) {
                return await response.json();
            } else {
                throw new Error(`Cypher execution failed: ${response.status}`);
            }
        } catch (error) {
            throw new Error(`Failed to execute Cypher query: ${error}`);
        }
    }

    // Helper methods for parsing responses
    private parseAnalysisSummary(data: any): AnalysisSummary {
        return {
            totalNodes: data.total_nodes || 0,
            totalEdges: data.total_edges || 0,
            highRiskCount: data.high_risk_count || 0,
            mediumRiskCount: data.medium_risk_count || 0,
            lowRiskCount: data.low_risk_count || 0,
            totalFindings: (data.high_risk_count || 0) + (data.medium_risk_count || 0) + (data.low_risk_count || 0),
            overallRisk: this.calculateOverallRisk(data.high_risk_count || 0, data.medium_risk_count || 0)
        };
    }

    private calculateOverallRisk(highRisk: number, mediumRisk: number): string {
        if (highRisk > 10) return 'Critical';
        if (highRisk > 5) return 'High';
        if (mediumRisk > 20) return 'Medium';
        return 'Low';
    }

    private parseBloodHoundUploadResponse(data: any): BloodHoundAnalysis {
        // ✅ FIXED: Parse all findings (high, medium, low) from upload response
        const highRisk = (data.high_risk_findings || []).map((f: any) => this.parseFinding(f));
        const mediumRisk = (data.medium_risk_findings || []).map((f: any) => this.parseFinding(f));
        const lowRisk = (data.low_risk_findings || []).map((f: any) => this.parseFinding(f));

        return {
            message: data.message || '',
            filename: data.filename,
            summary: this.parseAnalysisSummary(data.summary || {}),
            highRiskFindings: highRisk,
            mediumRiskFindings: mediumRisk,
            lowRiskFindings: lowRisk,
            allFindings: [...highRisk, ...mediumRisk, ...lowRisk],
            raw_json: data.raw_json  // ✅ Include raw JSON for debugging
        };
    }

    private parseBloodHoundFindingsResponse(data: any): BloodHoundAnalysis {
        const highRisk = (data.high_risk || []).map((f: any) => this.parseFinding(f));
        const mediumRisk = (data.medium_risk || []).map((f: any) => this.parseFinding(f));
        const lowRisk = (data.low_risk || []).map((f: any) => this.parseFinding(f));

        return {
            message: 'Findings retrieved',
            summary: this.parseAnalysisSummary(data.summary || {}),
            highRiskFindings: highRisk,
            mediumRiskFindings: mediumRisk,
            lowRiskFindings: lowRisk,
            allFindings: [...highRisk, ...mediumRisk, ...lowRisk]
        };
    }

    private parseFinding(data: any): Finding {
        return {
            edgeType: data.edge_type || '',
            source: data.source || '',
            target: data.target || '',
            sourceType: data.source_type || 'User',
            targetType: data.target_type || 'Computer',
            riskLevel: data.risk_level || 'Low',
            explanation: data.explanation
        };
    }

    private parseDetailedRemediation(data: any): DetailedRemediation {
        const finding = data.finding || {};
        return {
            edgeType: finding.edge_type || data.edge_type || '',
            source: finding.source || data.source || '',
            target: finding.target || data.target || '',
            riskLevel: data.risk_level || 'Unknown',
            explanation: data.explanation || '',
            remediationSteps: Array.from(data.remediation_steps || []),
            powershellScript: data.powershell_script || '',
            rollbackScript: data.rollback_script,
            mitreMapping: Array.from(data.mitre_mapping || []),
            detectionMethods: Array.from(data.detection_methods || []),
            warnings: Array.from(data.warnings || [])
        };
    }

    /**
     * Get attack path analysis progress
     */
    async getAttackPathProgress(analysisId: string): Promise<{
        analysis_id: string;
        status: string;
        step: string;
        progress: number;
        message: string;
        started_at?: string;
        completed_at?: string;
        estimated_time_remaining?: string;
    }> {
        try {
            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/attack-paths/analyze/${analysisId}/progress`,
                { method: 'GET' },
                config.progressTimeout || 10000  // Use shorter timeout for progress checks
            );

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Progress check failed: ${response.status} - ${errorText}`);
            }

            return await response.json();
        } catch (error: any) {
            // Handle AbortError more gracefully
            if (error?.name === 'AbortError' || error?.message?.includes('aborted')) {
                throw new Error(`Progress request timed out after ${config.progressTimeout || 10000}ms`);
            }
            throw new Error(`Failed to get progress: ${error?.message || error}`);
        }
    }

    /**
     * Start attack path analysis
     */
    async startAttackPathAnalysis(bloodhoundData: any, options?: any, projectId?: string): Promise<{
        analysis_id: string;
        status: string;
        message: string;
    }> {
        try {
            console.log('🔵 [FRONTEND] [API] Calling POST /api/attack-paths/analyze');
            console.log('🔵 [FRONTEND] [API] Request payload:', {
                has_bloodhound_data: bloodhoundData !== null,
                options: options,
                project_id: projectId
            });

            const response = await this.fetchWithTimeout(
                `${config.baseUrl}/api/attack-paths/analyze`,
                {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        bloodhound_data: bloodhoundData,
                        options: options || {},
                        project_id: projectId
                    })
                },
                config.timeout
            );

            if (!response.ok) {
                const errorText = await response.text();
                console.error(`🔴 [FRONTEND] [API] Analysis start failed: ${response.status} - ${errorText}`);
                throw new Error(`Analysis start failed: ${response.status} - ${errorText}`);
            }

            const data = await response.json();
            console.log('🔵 [FRONTEND] [API] Analysis started successfully:', {
                analysis_id: data.analysis_id,
                status: data.status,
                message: data.message
            });
            return data;
        } catch (error) {
            console.error('🔴 [FRONTEND] [API] ERROR: Failed to start analysis:', error);
            throw new Error(`Failed to start analysis: ${error}`);
        }
    }
}

/**
 * Progress Service for polling attack path analysis progress
 */
export class ProgressService {
    private pollingInterval: NodeJS.Timeout | null = null;
    private isPolling: boolean = false;
    private apiService: ApiService;

    constructor(apiService: ApiService) {
        this.apiService = apiService;
    }

    /**
     * Start polling for progress updates
     */
    startPolling(
        analysisId: string,
        onProgress: (progress: {
            analysis_id: string;
            status: string;
            step: string;
            progress: number;
            message: string;
            started_at?: string;
            completed_at?: string;
        }) => void,
        onComplete: (progress: any) => void,
        onError: (error: string) => void,
        intervalMs: number = 1000
    ): void {
        if (this.isPolling) {
            console.warn('⚠️ Progress polling already active');
            return;
        }

        this.isPolling = true;
        let maxAttempts = 900; // 15 minutes max (900 * 1 second) - RAG analysis with remediation can take a while
        let attempts = 0;

        const poll = async () => {
            if (!this.isPolling) {
                return;
            }

            try {
                attempts++;

                if (attempts > maxAttempts) {
                    this.stopPolling();
                    onError(`Analysis timed out after ${maxAttempts} seconds`);
                    return;
                }

                const progress = await this.apiService.getAttackPathProgress(analysisId);

                // Call progress callback
                onProgress(progress);

                // Check if completed or failed
                if (progress.status === 'completed' || progress.status === 'failed') {
                    this.stopPolling();
                    onComplete(progress);
                    return;
                }

                // Continue polling
                if (this.isPolling) {
                    this.pollingInterval = setTimeout(poll, intervalMs);
                }
            } catch (error: any) {
                // Handle AbortError/timeout more gracefully - retry with backoff
                const isTimeout = error?.message?.includes('timed out') ||
                    error?.name === 'AbortError' ||
                    error?.message?.includes('aborted');

                if (isTimeout && this.isPolling && attempts < maxAttempts) {
                    // For timeouts, retry immediately (might be temporary network issue)
                    // Only log warning every 10 attempts to reduce noise
                    if (attempts % 10 === 0) {
                        console.warn(`⚠️ Progress request timed out, retrying... (attempt ${attempts}/${maxAttempts})`);
                    }
                    this.pollingInterval = setTimeout(poll, intervalMs);
                } else if (this.isPolling && attempts < maxAttempts) {
                    // For other errors, log and continue polling (might be temporary network issue)
                    console.error('❌ Progress polling error:', error);
                    this.pollingInterval = setTimeout(poll, intervalMs);
                } else {
                    // Stop polling if max attempts reached or polling was stopped
                    console.error('❌ Progress polling failed:', error);
                    this.stopPolling();
                    onError(error?.message || 'Progress polling failed');
                }
            }
        };

        // Start polling immediately
        poll();
    }

    /**
     * Stop polling for progress updates
     */
    stopPolling(): void {
        this.isPolling = false;
        if (this.pollingInterval) {
            clearTimeout(this.pollingInterval);
            this.pollingInterval = null;
        }
    }

    /**
     * Check if currently polling
     */
    isActive(): boolean {
        return this.isPolling;
    }
}

// Export singleton instance (check if already exists to avoid redeclaration)
let apiServiceInstance: ApiService;
let progressServiceInstance: ProgressService;

if (typeof window !== 'undefined') {
    // Browser environment - create singleton
    apiServiceInstance = new ApiService();
    progressServiceInstance = new ProgressService(apiServiceInstance);
} else {
    // Node/SSR environment
    apiServiceInstance = new ApiService();
    progressServiceInstance = new ProgressService(apiServiceInstance);
}

export const apiService = apiServiceInstance;
export const progressService = progressServiceInstance;
export default apiService;
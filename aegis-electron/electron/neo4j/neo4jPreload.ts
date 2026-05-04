/** Preload bridge exposing Neo4j query and findings-extraction APIs to the renderer. */

import { contextBridge, ipcRenderer } from 'electron';

// ==================== TYPE DEFINITIONS ====================

export interface Neo4jConfig {
    uri: string;
    username: string;
    password: string;
}

export interface Neo4jConnectionResult {
    connected: boolean;
    database?: string;
    nodeCount?: number;
    relationshipCount?: number;
    error?: string;
}

export interface QueryResult {
    success: boolean;
    records: any[];
    count: number;
    error?: string;
}

export interface DatabaseStats {
    nodes: { [label: string]: number };
    totalNodes: number;
    totalRelationships: number;
    labels: string[];
    relationshipTypes: string[];
}

// Findings extracted from BloodHound CE's Neo4j
export interface FindingsSummary {
    total_nodes: number;
    total_edges: number;
    high_risk_count: number;
    medium_risk_count: number;
    low_risk_count: number;
    // Entity type counts for domain overview
    total_users?: number;
    total_groups?: number;
    total_computers?: number;
    domain_controllers?: number;
    total_ous?: number;
    total_gpos?: number;
}

export interface ExtractedFindings {
    high_risk: any[];
    medium_risk: any[];
    low_risk: any[];
    summary: FindingsSummary;
    edge_type_counts: Record<string, number>;
    domains: string[];
    domain_admin_groups: string[];
    high_value_targets: Array<{ name: string; type: string; count: number }>;
}

export interface EnvironmentInfo {
    domains: string[];
    domainAdminGroups: string[];
    highValueGroups: string[];
    serviceAccounts: string[];
    computers: string[];
    edgeTypes: string[];
}

// Neo4j API interface (simplified - query only)
export interface Neo4jAPI {
    // Connection
    connect: () => Promise<Neo4jConnectionResult>;
    testConnection: () => Promise<Neo4jConnectionResult>;
    close: () => Promise<void>;
    setConfig: (config: Partial<Neo4jConfig>) => Promise<void>;
    getConfig: () => Promise<Neo4jConfig>;

    // Queries
    runQuery: (cypher: string, params?: Record<string, any>) => Promise<QueryResult>;
    getCommonQueries: () => Promise<Array<{ name: string; description: string; cypher: string }>>;

    // Statistics
    getStatistics: () => Promise<DatabaseStats>;

    // Findings Extraction (replaces manual parsing)
    extractFindings: () => Promise<ExtractedFindings>;
    getEnvironmentInfo: () => Promise<EnvironmentInfo>;

    // Data Management
    clearAllData: () => Promise<{ success: boolean; error?: string }>;
}

// ==================== EXPOSE NEO4J API ====================

const neo4jAPI: Neo4jAPI = {
    // Connection
    connect: () => ipcRenderer.invoke('neo4j:connect'),
    testConnection: () => ipcRenderer.invoke('neo4j:testConnection'),
    close: () => ipcRenderer.invoke('neo4j:close'),
    setConfig: (config) => ipcRenderer.invoke('neo4j:setConfig', config),
    getConfig: () => ipcRenderer.invoke('neo4j:getConfig'),

    // Queries
    runQuery: (cypher, params) => ipcRenderer.invoke('neo4j:runQuery', cypher, params),
    getCommonQueries: () => ipcRenderer.invoke('neo4j:getCommonQueries'),

    // Statistics
    getStatistics: () => ipcRenderer.invoke('neo4j:getStatistics'),

    // Findings Extraction (replaces manual parsing)
    extractFindings: () => ipcRenderer.invoke('neo4j:extractFindings'),
    getEnvironmentInfo: () => ipcRenderer.invoke('neo4j:getEnvironmentInfo'),

    // Data Management
    clearAllData: () => ipcRenderer.invoke('neo4j:clearAllData'),
};

// Expose to renderer
contextBridge.exposeInMainWorld('neo4j', neo4jAPI);

// ==================== TYPE DECLARATIONS ====================

declare global {
    interface Window {
        neo4j: Neo4jAPI;
    }
}

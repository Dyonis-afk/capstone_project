/** IPC handlers for read-only Neo4j queries, findings extraction, and environment info. */

import { ipcMain } from 'electron';
import {
    neo4jService,
    Neo4jConfig,
    Neo4jConnectionResult,
    QueryResult,
    DatabaseStats,
    ExtractedFindings
} from './neo4jService.js';

export function setupNeo4jHandlers(): void {
    console.log('[Main] Setting up Neo4j IPC handlers (query-only mode)...');

    // ==================== CONNECTION HANDLERS ====================

    ipcMain.handle('neo4j:connect', async (): Promise<Neo4jConnectionResult> => {
        try {
            return await neo4jService.connect();
        } catch (error: any) {
            console.error('[Main] Neo4j connect error:', error);
            return { connected: false, error: error.message };
        }
    });

    ipcMain.handle('neo4j:testConnection', async (): Promise<Neo4jConnectionResult> => {
        try {
            return await neo4jService.testConnection();
        } catch (error: any) {
            console.error('[Main] Neo4j test connection error:', error);
            return { connected: false, error: error.message };
        }
    });

    ipcMain.handle('neo4j:close', async (): Promise<void> => {
        try {
            await neo4jService.close();
        } catch (error: any) {
            console.error('[Main] Neo4j close error:', error);
        }
    });

    ipcMain.handle('neo4j:setConfig', async (_, config: Partial<Neo4jConfig>): Promise<void> => {
        try {
            neo4jService.setConfig(config);
        } catch (error: any) {
            console.error('[Main] Neo4j setConfig error:', error);
        }
    });

    ipcMain.handle('neo4j:getConfig', async (): Promise<Neo4jConfig> => {
        return neo4jService.getConfig();
    });

    // ==================== QUERY HANDLERS ====================

    ipcMain.handle('neo4j:runQuery', async (_, cypher: string, params?: Record<string, any>): Promise<QueryResult> => {
        try {
            return await neo4jService.runQuery(cypher, params || {});
        } catch (error: any) {
            console.error('[Main] Neo4j query error:', error);
            return { success: false, records: [], count: 0, error: error.message };
        }
    });

    ipcMain.handle('neo4j:getCommonQueries', async (): Promise<Array<{ name: string; description: string; cypher: string }>> => {
        return neo4jService.getCommonQueries();
    });

    // ==================== STATISTICS HANDLERS ====================

    ipcMain.handle('neo4j:getStatistics', async (): Promise<DatabaseStats> => {
        try {
            return await neo4jService.getStatistics();
        } catch (error: any) {
            console.error('[Main] Neo4j getStatistics error:', error);
            return { nodes: {}, totalNodes: 0, totalRelationships: 0, labels: [], relationshipTypes: [] };
        }
    });

    // ==================== FINDINGS EXTRACTION HANDLERS ====================
    // These replace manual parsing - we query what BloodHound CE already ingested

    ipcMain.handle('neo4j:extractFindings', async (): Promise<ExtractedFindings> => {
        try {
            return await neo4jService.extractFindings();
        } catch (error: any) {
            console.error('[Main] Neo4j extractFindings error:', error);
            return {
                high_risk: [],
                medium_risk: [],
                low_risk: [],
                summary: {
                    total_nodes: 0,
                    total_edges: 0,
                    high_risk_count: 0,
                    medium_risk_count: 0,
                    low_risk_count: 0,
                    total_users: 0,
                    total_groups: 0,
                    total_computers: 0,
                    domain_controllers: 0,
                    total_ous: 0,
                    total_gpos: 0
                },
                edge_type_counts: {},
                domains: [],
                domain_admin_groups: [],
                high_value_targets: []
            };
        }
    });

    ipcMain.handle('neo4j:getEnvironmentInfo', async (): Promise<{
        domains: string[];
        domainAdminGroups: string[];
        highValueGroups: string[];
        serviceAccounts: string[];
        computers: string[];
        edgeTypes: string[];
    }> => {
        try {
            return await neo4jService.getEnvironmentInfo();
        } catch (error: any) {
            console.error('[Main] Neo4j getEnvironmentInfo error:', error);
            return {
                domains: [],
                domainAdminGroups: [],
                highValueGroups: [],
                serviceAccounts: [],
                computers: [],
                edgeTypes: []
            };
        }
    });

    // ==================== DATA MANAGEMENT HANDLERS ====================

    ipcMain.handle('neo4j:clearAllData', async (): Promise<{ success: boolean; error?: string }> => {
        try {
            return await neo4jService.clearAllData();
        } catch (error: any) {
            console.error('[Main] Neo4j clearAllData error:', error);
            return { success: false, error: error.message };
        }
    });

    console.log('[Main] Neo4j IPC handlers registered (query-only mode)');
}

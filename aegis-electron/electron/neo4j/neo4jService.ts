/** Read-only Neo4j client: connects to BHCE's Neo4j, runs Cypher, extracts findings, reports stats. */

import neo4j, { Driver } from 'neo4j-driver';

// Connection configuration - matches BloodHound CE Docker setup
const DEFAULT_CONFIG = {
    uri: 'bolt://localhost:7687',
    username: 'neo4j',
    password: 'bloodhoundcommunityedition'
};

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

// Findings summary for RAG analysis (extracted from BloodHound CE's Neo4j)
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

class Neo4jService {
    private driver: Driver | null = null;
    private config: Neo4jConfig = DEFAULT_CONFIG;

    // High-risk edge types in BloodHound
    private highRiskEdges = new Set([
        'AdminTo', 'MemberOf', 'HasSession', 'DCSync', 'AllowedToDelegate',
        'GetChanges', 'GetChangesAll', 'WriteDacl', 'WriteOwner', 'GenericAll',
        'GenericWrite', 'ForceChangePassword', 'Owns', 'AllExtendedRights',
        'AddKeyCredentialLink', 'WriteAccountRestrictions',
        'ManageCA', 'ManageCertificates', 'ADCSESC1', 'ADCSESC4', 'ADCSESC6'
    ]);

    // Medium-risk edge types
    private mediumRiskEdges = new Set([
        'CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'AllowedToAct',
        'AddMember', 'ReadLAPSPassword', 'ReadGMSAPassword', 'Contains',
        'GPLink', 'TrustedBy', 'AddSelf', 'WriteSPN', 'Enroll', 'HasSPN'
    ]);

    constructor() {
        console.log('[Neo4jService] Initialized (query-only mode)');
    }

    /**
     * Set custom connection configuration
     */
    setConfig(config: Partial<Neo4jConfig>): void {
        this.config = { ...this.config, ...config };
        if (this.driver) {
            this.close();
        }
        console.log(`[Neo4jService] Config updated: ${this.config.uri}`);
    }

    /**
     * Get current configuration
     */
    getConfig(): Neo4jConfig {
        return { ...this.config };
    }

    /**
     * Connect to Neo4j
     */
    async connect(): Promise<Neo4jConnectionResult> {
        try {
            console.log(`[Neo4jService] Connecting to ${this.config.uri}...`);

            this.driver = neo4j.driver(
                this.config.uri,
                neo4j.auth.basic(this.config.username, this.config.password),
                {
                    maxConnectionLifetime: 3600000,
                    maxConnectionPoolSize: 50,
                    connectionAcquisitionTimeout: 30000
                }
            );

            const session = this.driver.session();
            try {
                await session.run('RETURN 1 as n');

                const statsResult = await session.run(`
                    MATCH (n) WITH count(n) as nodes
                    MATCH ()-[r]->() WITH nodes, count(r) as rels
                    RETURN nodes, rels
                `);

                const stats = statsResult.records[0];
                const nodeCount = stats?.get('nodes')?.toNumber() || 0;
                const relCount = stats?.get('rels')?.toNumber() || 0;

                console.log(`[Neo4jService] Connected! Nodes: ${nodeCount}, Rels: ${relCount}`);

                return {
                    connected: true,
                    database: 'neo4j',
                    nodeCount,
                    relationshipCount: relCount
                };
            } finally {
                await session.close();
            }
        } catch (error: any) {
            console.error('[Neo4jService] Connection failed:', error.message);
            this.driver = null;
            return { connected: false, error: error.message };
        }
    }

    /**
     * Test connection without storing driver
     */
    async testConnection(): Promise<Neo4jConnectionResult> {
        let testDriver: Driver | null = null;
        try {
            testDriver = neo4j.driver(
                this.config.uri,
                neo4j.auth.basic(this.config.username, this.config.password)
            );

            const session = testDriver.session();
            try {
                await session.run('RETURN 1');

                const statsResult = await session.run(`
                    MATCH (n) WITH count(n) as nodes
                    MATCH ()-[r]->() WITH nodes, count(r) as rels
                    RETURN nodes, rels
                `);

                const stats = statsResult.records[0];

                return {
                    connected: true,
                    database: 'neo4j',
                    nodeCount: stats?.get('nodes')?.toNumber() || 0,
                    relationshipCount: stats?.get('rels')?.toNumber() || 0
                };
            } finally {
                await session.close();
            }
        } catch (error: any) {
            return { connected: false, error: error.message };
        } finally {
            if (testDriver) await testDriver.close();
        }
    }

    /**
     * Ensure driver is connected
     */
    private async ensureConnected(): Promise<void> {
        if (!this.driver) {
            const result = await this.connect();
            if (!result.connected) {
                throw new Error(result.error || 'Failed to connect to Neo4j');
            }
        }
    }

    /**
     * Run a Cypher query
     */
    async runQuery(cypher: string, params: Record<string, any> = {}): Promise<QueryResult> {
        const queryPreview = cypher.length > 200 ? cypher.substring(0, 200) + '...' : cypher;
        console.log(`[Neo4jService] Executing query:\n${queryPreview}`);

        try {
            await this.ensureConnected();

            const session = this.driver!.session();
            try {
                const result = await session.run(cypher, params);
                const records = result.records.map(record => {
                    const obj: any = {};
                    record.keys.forEach(key => {
                        obj[key] = this.convertNeo4jValue(record.get(key));
                    });
                    return obj;
                });

                console.log(`[Neo4jService] Query returned ${records.length} records`);
                return { success: true, records, count: records.length };
            } finally {
                await session.close();
            }
        } catch (error: any) {
            console.error('[Neo4jService] Query FAILED:', error.message);
            console.error('[Neo4jService] Failed query was:\n', cypher);
            return { success: false, records: [], count: 0, error: error.message };
        }
    }

    /**
     * Convert Neo4j values to plain JavaScript objects
     */
    private convertNeo4jValue(value: any): any {
        if (value === null || value === undefined) return value;

        if (neo4j.isInt(value)) return value.toNumber();

        if (value.constructor?.name === 'Node') {
            return {
                id: value.identity.toNumber(),
                labels: value.labels,
                properties: this.convertNeo4jValue(value.properties)
            };
        }

        if (value.constructor?.name === 'Relationship') {
            return {
                id: value.identity.toNumber(),
                type: value.type,
                startNodeId: value.start.toNumber(),
                endNodeId: value.end.toNumber(),
                properties: this.convertNeo4jValue(value.properties)
            };
        }

        if (value.constructor?.name === 'Path') {
            return {
                start: this.convertNeo4jValue(value.start),
                end: this.convertNeo4jValue(value.end),
                segments: value.segments.map((seg: any) => ({
                    start: this.convertNeo4jValue(seg.start),
                    relationship: this.convertNeo4jValue(seg.relationship),
                    end: this.convertNeo4jValue(seg.end)
                }))
            };
        }

        if (Array.isArray(value)) return value.map(v => this.convertNeo4jValue(v));

        if (typeof value === 'object') {
            const converted: any = {};
            for (const key of Object.keys(value)) {
                converted[key] = this.convertNeo4jValue(value[key]);
            }
            return converted;
        }

        return value;
    }

    /**
     * Get database statistics
     */
    async getStatistics(): Promise<DatabaseStats> {
        try {
            await this.ensureConnected();

            const session = this.driver!.session();
            try {
                const nodeResult = await session.run('MATCH (n) RETURN count(n) as count');
                const totalNodes = nodeResult.records[0]?.get('count')?.toNumber() || 0;

                const relResult = await session.run('MATCH ()-[r]->() RETURN count(r) as count');
                const totalRelationships = relResult.records[0]?.get('count')?.toNumber() || 0;

                const labelsResult = await session.run('CALL db.labels() YIELD label RETURN label');
                const labels = labelsResult.records.map(r => r.get('label'));

                const nodes: { [label: string]: number } = {};
                for (const label of labels) {
                    const countResult = await session.run(`MATCH (n:\`${label}\`) RETURN count(n) as count`);
                    nodes[label] = countResult.records[0]?.get('count')?.toNumber() || 0;
                }

                const relTypesResult = await session.run('CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType');
                const relationshipTypes = relTypesResult.records.map(r => r.get('relationshipType'));

                return { nodes, totalNodes, totalRelationships, labels, relationshipTypes };
            } finally {
                await session.close();
            }
        } catch (error: any) {
            console.error('[Neo4jService] Error getting statistics:', error.message);
            return { nodes: {}, totalNodes: 0, totalRelationships: 0, labels: [], relationshipTypes: [] };
        }
    }

    /**
     * Extract findings from BloodHound CE's Neo4j database
     * This replaces the manual parsing - we query what BloodHound CE already ingested
     */
    async extractFindings(): Promise<ExtractedFindings> {
        console.log('[Neo4jService] Extracting findings from BloodHound CE data...');

        try {
            await this.ensureConnected();

            const session = this.driver!.session();
            try {
                // Get total counts
                const statsResult = await session.run(`
                    MATCH (n) WITH count(n) as nodes
                    MATCH ()-[r]->() WITH nodes, count(r) as rels
                    RETURN nodes, rels
                `);
                const totalNodes = statsResult.records[0]?.get('nodes')?.toNumber() || 0;
                const totalEdges = statsResult.records[0]?.get('rels')?.toNumber() || 0;

                // Get individual entity type counts for domain overview
                const userCountResult = await session.run(`MATCH (n:User) RETURN count(n) as count`);
                const totalUsers = userCountResult.records[0]?.get('count')?.toNumber() || 0;

                const groupCountResult = await session.run(`MATCH (n:Group) RETURN count(n) as count`);
                const totalGroups = groupCountResult.records[0]?.get('count')?.toNumber() || 0;

                const computerCountResult = await session.run(`MATCH (n:Computer) RETURN count(n) as count`);
                const totalComputers = computerCountResult.records[0]?.get('count')?.toNumber() || 0;

                // Get Domain Controller count: isdc/isdomaincontroller property, or name contains 'dc' (e.g. DC01)
                const dcCountResult = await session.run(`
                    MATCH (c:Computer)
                    WHERE (c.isdc = true OR c.isdomaincontroller = true)
                       OR (c.name IS NOT NULL AND toLower(toString(c.name)) CONTAINS 'dc')
                    RETURN count(DISTINCT c) as count
                `);
                const domainControllers = dcCountResult.records[0]?.get('count')?.toNumber() ?? 0;

                const ouCountResult = await session.run(`MATCH (n:OU) RETURN count(n) as count`);
                const totalOus = ouCountResult.records[0]?.get('count')?.toNumber() || 0;

                const gpoCountResult = await session.run(`MATCH (n:GPO) RETURN count(n) as count`);
                const totalGpos = gpoCountResult.records[0]?.get('count')?.toNumber() || 0;

                console.log(`[Neo4jService] Entity counts: ${totalUsers} users, ${totalGroups} groups, ${totalComputers} computers, ${domainControllers} DCs`);

                // Get relationship type counts
                const relTypesResult = await session.run(`
                    MATCH ()-[r]->()
                    RETURN type(r) as relType, count(r) as count
                    ORDER BY count DESC
                `);

                const edge_type_counts: Record<string, number> = {};
                let highRiskCount = 0;
                let mediumRiskCount = 0;
                let lowRiskCount = 0;

                for (const record of relTypesResult.records) {
                    const relType = record.get('relType');
                    const count = record.get('count')?.toNumber() || 0;
                    edge_type_counts[relType] = count;

                    if (this.highRiskEdges.has(relType)) {
                        highRiskCount += count;
                    } else if (this.mediumRiskEdges.has(relType)) {
                        mediumRiskCount += count;
                    } else {
                        lowRiskCount += count;
                    }
                }

                // Get domains - merge from Domain nodes AND User/Group names
                // This ensures child domains are detected even without explicit Domain nodes
                const allDomains = new Set<string>();

                // Approach 1: Query Domain nodes directly
                try {
                    const domainsResult = await session.run(`
                        MATCH (d:Domain) RETURN d.name as name LIMIT 10
                    `);
                    domainsResult.records.forEach(r => {
                        const name = r.get('name');
                        if (name) allDomains.add(name.toUpperCase());
                    });
                } catch (e) {
                    console.log('[Neo4jService] extractFindings: Domain query failed');
                }

                // Approach 2: ALWAYS extract from User names to catch child domains
                try {
                    const userDomainResult = await session.run(`
                        MATCH (u:User)
                        WHERE u.name CONTAINS '@'
                        WITH split(u.name, '@')[1] as domain
                        WHERE domain IS NOT NULL
                        RETURN DISTINCT domain as name
                        LIMIT 20
                    `);
                    userDomainResult.records.forEach(r => {
                        const name = r.get('name');
                        if (name) allDomains.add(name.toUpperCase());
                    });
                } catch (e) {
                    console.log('[Neo4jService] extractFindings: User domain extraction failed');
                }

                // Approach 3: ALWAYS extract from Group names to catch child domains
                try {
                    const groupDomainResult = await session.run(`
                        MATCH (g:Group)
                        WHERE g.name CONTAINS '@'
                        WITH split(g.name, '@')[1] as domain
                        WHERE domain IS NOT NULL
                        RETURN DISTINCT domain as name
                        LIMIT 20
                    `);
                    groupDomainResult.records.forEach(r => {
                        const name = r.get('name');
                        if (name) allDomains.add(name.toUpperCase());
                    });
                } catch (e) {
                    console.log('[Neo4jService] extractFindings: Group domain extraction failed');
                }

                const domains = Array.from(allDomains);
                console.log(`[Neo4jService] extractFindings: Domains found: ${domains.length > 0 ? domains.join(', ') : 'none'}`);

                // Get Domain Admin groups
                const daResult = await session.run(`
                    MATCH (g:Group)
                    WHERE g.name =~ '(?i).*DOMAIN ADMINS.*' OR g.objectid ENDS WITH '-512'
                    RETURN g.name as name LIMIT 10
                `);
                const domain_admin_groups = daResult.records.map(r => r.get('name')).filter(Boolean);

                // Get high-value targets
                const hvResult = await session.run(`
                    MATCH (n)
                    WHERE n.highvalue = true OR n.admincount = true
                    RETURN n.name as name, head(labels(n)) as type
                    LIMIT 20
                `);
                const high_value_targets = hvResult.records.map(r => ({
                    name: r.get('name') || 'Unknown',
                    type: r.get('type') || 'Unknown',
                    count: 1
                }));

                // Get sample high-risk edges
                const highRiskResult = await session.run(`
                    MATCH (source)-[r]->(target)
                    WHERE type(r) IN ['AdminTo', 'GenericAll', 'WriteDacl', 'WriteOwner', 'DCSync', 'GetChanges', 'GetChangesAll', 'ForceChangePassword', 'Owns']
                    RETURN source.name as source, type(r) as edge_type, target.name as target,
                           head(labels(source)) as source_type, head(labels(target)) as target_type
                    LIMIT 50
                `);
                const high_risk = highRiskResult.records.map(r => ({
                    source: r.get('source') || 'Unknown',
                    source_type: r.get('source_type') || 'Unknown',
                    edge_type: r.get('edge_type') || 'Unknown',
                    target: r.get('target') || 'Unknown',
                    target_type: r.get('target_type') || 'Unknown',
                    risk_level: 'High'
                }));

                // Get sample medium-risk edges
                const mediumRiskResult = await session.run(`
                    MATCH (source)-[r]->(target)
                    WHERE type(r) IN ['CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'AllowedToAct', 'AddMember', 'ReadLAPSPassword', 'Enroll']
                    RETURN source.name as source, type(r) as edge_type, target.name as target,
                           head(labels(source)) as source_type, head(labels(target)) as target_type
                    LIMIT 30
                `);
                const medium_risk = mediumRiskResult.records.map(r => ({
                    source: r.get('source') || 'Unknown',
                    source_type: r.get('source_type') || 'Unknown',
                    edge_type: r.get('edge_type') || 'Unknown',
                    target: r.get('target') || 'Unknown',
                    target_type: r.get('target_type') || 'Unknown',
                    risk_level: 'Medium'
                }));

                // Get sample low-risk (MemberOf) edges
                const lowRiskResult = await session.run(`
                    MATCH (source)-[r:MemberOf]->(target)
                    RETURN source.name as source, 'MemberOf' as edge_type, target.name as target,
                           head(labels(source)) as source_type, head(labels(target)) as target_type
                    LIMIT 20
                `);
                const low_risk = lowRiskResult.records.map(r => ({
                    source: r.get('source') || 'Unknown',
                    source_type: r.get('source_type') || 'Unknown',
                    edge_type: r.get('edge_type') || 'Unknown',
                    target: r.get('target') || 'Unknown',
                    target_type: r.get('target_type') || 'Unknown',
                    risk_level: 'Low'
                }));

                console.log(`[Neo4jService] Extracted findings: ${high_risk.length} high, ${medium_risk.length} medium, ${low_risk.length} low risk samples`);

                return {
                    high_risk,
                    medium_risk,
                    low_risk,
                    summary: {
                        total_nodes: totalNodes,
                        total_edges: totalEdges,
                        high_risk_count: highRiskCount,
                        medium_risk_count: mediumRiskCount,
                        low_risk_count: lowRiskCount,
                        // Entity type counts for domain overview
                        total_users: totalUsers,
                        total_groups: totalGroups,
                        total_computers: totalComputers,
                        domain_controllers: domainControllers,
                        total_ous: totalOus,
                        total_gpos: totalGpos
                    },
                    edge_type_counts,
                    domains,
                    domain_admin_groups,
                    high_value_targets
                };
            } finally {
                await session.close();
            }
        } catch (error: any) {
            console.error('[Neo4jService] Error extracting findings:', error.message);
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
    }

    /**
     * Get environment info for query generation
     */
    async getEnvironmentInfo(): Promise<{
        domains: string[];
        domainInfo: { name: string; functionalLevel?: string; forest?: string } | null;
        domainAdminGroups: string[];
        highValueGroups: string[];
        serviceAccounts: string[];
        computers: string[];
        edgeTypes: string[];
    }> {
        console.log('[Neo4jService] Getting environment info from BloodHound CE...');

        try {
            await this.ensureConnected();

            const session = this.driver!.session();
            try {
                // Get domains with full properties directly from Domain nodes
                let domains: string[] = [];
                let domainInfo: { name: string; functionalLevel?: string; forest?: string } | null = null;

                // Query Domain nodes with all relevant properties
                // Try multiple property names since BloodHound versions vary
                try {
                    const domainsResult = await session.run(`
                        MATCH (d:Domain)
                        RETURN d.name as name,
                               d.functionallevel as functionalLevel,
                               d.domainfunctionallevel as domainFunctionalLevel,
                               d.functional_level as functional_level,
                               d.domain as forest,
                               d.distinguishedname as dn,
                               keys(d) as allKeys
                        LIMIT 10
                    `);

                    if (domainsResult.records.length > 0) {
                        const firstDomain = domainsResult.records[0];
                        const domainName = firstDomain.get('name');
                        const forest = firstDomain.get('forest');

                        // Try multiple property names for functional level
                        const functionalLevel =
                            firstDomain.get('functionalLevel') ||
                            firstDomain.get('domainFunctionalLevel') ||
                            firstDomain.get('functional_level');

                        // Log available keys to help debug
                        const allKeys = firstDomain.get('allKeys');
                        console.log(`[Neo4jService] Domain node keys: ${JSON.stringify(allKeys)}`);

                        domains = domainsResult.records.map(r => r.get('name')).filter(Boolean);

                        domainInfo = {
                            name: domainName || domains[0],
                            functionalLevel: functionalLevel || undefined,
                            forest: forest || domainName || domains[0]  // Forest is often same as domain in single-domain
                        };

                        console.log(`[Neo4jService] Domain node found: ${domainName}, Level: ${functionalLevel}, Forest: ${forest}`);
                    }
                } catch (e) {
                    console.log('[Neo4jService] getEnvironmentInfo: Domain query failed, trying fallback');
                }

                // ALWAYS extract domains from User/Group names and merge with Domain nodes
                // This catches child domains that may not have explicit Domain nodes
                const allDomains = new Set<string>(domains.map(d => d.toUpperCase()));

                // Extract from User names
                try {
                    const userDomainResult = await session.run(`
                        MATCH (u:User)
                        WHERE u.name CONTAINS '@'
                        WITH split(u.name, '@')[1] as domain
                        WHERE domain IS NOT NULL
                        RETURN DISTINCT domain as name
                        LIMIT 20
                    `);
                    userDomainResult.records.forEach(r => {
                        const name = r.get('name');
                        if (name) allDomains.add(name.toUpperCase());
                    });
                } catch (e) {
                    console.log('[Neo4jService] getEnvironmentInfo: User domain extraction failed');
                }

                // Extract from Group names
                try {
                    const groupDomainResult = await session.run(`
                        MATCH (g:Group)
                        WHERE g.name CONTAINS '@'
                        WITH split(g.name, '@')[1] as domain
                        WHERE domain IS NOT NULL
                        RETURN DISTINCT domain as name
                        LIMIT 20
                    `);
                    groupDomainResult.records.forEach(r => {
                        const name = r.get('name');
                        if (name) allDomains.add(name.toUpperCase());
                    });
                } catch (e) {
                    console.log('[Neo4jService] getEnvironmentInfo: Group domain extraction failed');
                }

                // Update domains with merged set
                domains = Array.from(allDomains);

                // Set domainInfo if not already set
                if (!domainInfo && domains.length > 0) {
                    domainInfo = { name: domains[0], forest: domains[0] };
                }

                console.log(`[Neo4jService] getEnvironmentInfo: Domains found: ${domains.length > 0 ? domains.join(', ') : 'none'}`);

                // Get Domain Admin groups
                const daResult = await session.run(`
                    MATCH (g:Group)
                    WHERE g.name =~ '(?i).*DOMAIN ADMINS.*' OR g.objectid ENDS WITH '-512'
                    RETURN g.name as name LIMIT 10
                `);
                const domainAdminGroups = daResult.records.map(r => r.get('name')).filter(Boolean);

                // Get high-value groups
                const hvResult = await session.run(`
                    MATCH (g:Group)
                    WHERE g.highvalue = true OR g.admincount = true
                       OR g.name =~ '(?i).*(ADMIN|ENTERPRISE|SCHEMA|KEY|CERT).*'
                    RETURN g.name as name LIMIT 20
                `);
                const highValueGroups = hvResult.records.map(r => r.get('name')).filter(Boolean);

                // Get service accounts (users with SPN)
                const svcResult = await session.run(`
                    MATCH (u:User)
                    WHERE u.hasspn = true
                    RETURN u.name as name LIMIT 30
                `);
                const serviceAccounts = svcResult.records.map(r => r.get('name')).filter(Boolean);

                // Get computers
                const compResult = await session.run(`
                    MATCH (c:Computer) RETURN c.name as name LIMIT 50
                `);
                const computers = compResult.records.map(r => r.get('name')).filter(Boolean);

                // Get relationship types (edge types)
                const edgeResult = await session.run(`
                    CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType
                `);
                const edgeTypes = edgeResult.records.map(r => r.get('relationshipType')).filter(Boolean);

                console.log(`[Neo4jService] Environment: ${domains.length} domains, ${domainAdminGroups.length} DA groups, ${edgeTypes.length} edge types`);

                return {
                    domains,
                    domainInfo,  // Contains name, functionalLevel, forest from Domain node
                    domainAdminGroups,
                    highValueGroups,
                    serviceAccounts,
                    computers,
                    edgeTypes
                };
            } finally {
                await session.close();
            }
        } catch (error: any) {
            console.error('[Neo4jService] Error getting environment info:', error.message);
            return {
                domains: [],
                domainInfo: null,
                domainAdminGroups: [],
                highValueGroups: [],
                serviceAccounts: [],
                computers: [],
                edgeTypes: []
            };
        }
    }

    /**
     * Clear all data (used when switching projects)
     */
    async clearAllData(): Promise<{ success: boolean; error?: string }> {
        try {
            await this.ensureConnected();

            const session = this.driver!.session();
            try {
                await session.run('MATCH ()-[r]->() DELETE r');
                await session.run('MATCH (n) DELETE n');
                console.log('[Neo4jService] All data cleared');
                return { success: true };
            } finally {
                await session.close();
            }
        } catch (error: any) {
            console.error('[Neo4jService] Error clearing all data:', error.message);
            return { success: false, error: error.message };
        }
    }

    /**
     * Get common BloodHound queries
     */
    getCommonQueries(): Array<{ name: string; description: string; cypher: string }> {
        return [
            {
                name: 'Paths to Domain Admins',
                description: 'Find shortest paths to Domain Admins group',
                cypher: `MATCH p=shortestPath((n)-[*1..]->(g:Group)) WHERE g.name =~ '(?i).*DOMAIN ADMINS.*' AND n <> g RETURN p LIMIT 50`
            },
            {
                name: 'Kerberoastable Users',
                description: 'Find users with SPNs set',
                cypher: `MATCH (u:User) WHERE u.hasspn = true RETURN u.name, u.serviceprincipalnames LIMIT 100`
            },
            {
                name: 'Users with DCSync Rights',
                description: 'Find users with DCSync privileges',
                cypher: `MATCH p=(n)-[:GetChanges|GetChangesAll*1..]->(d:Domain) RETURN p LIMIT 50`
            },
            {
                name: 'Unconstrained Delegation',
                description: 'Find computers with unconstrained delegation',
                cypher: `MATCH (c:Computer {unconstraineddelegation: true}) RETURN c.name LIMIT 100`
            },
            {
                name: 'AS-REP Roastable Users',
                description: 'Find users without pre-authentication',
                cypher: `MATCH (u:User {dontreqpreauth: true}) RETURN u.name LIMIT 100`
            },
            {
                name: 'Local Admin Rights',
                description: 'Find who has local admin rights',
                cypher: `MATCH p=(n)-[:AdminTo]->(c:Computer) RETURN p LIMIT 100`
            },
            {
                name: 'High Value Targets',
                description: 'Find high value targets',
                cypher: `MATCH (n {highvalue: true}) RETURN n.name, labels(n) LIMIT 100`
            },
            {
                name: 'GenericAll Permissions',
                description: 'Find GenericAll ACL edges',
                cypher: `MATCH p=(n)-[:GenericAll]->(m) WHERE n <> m RETURN p LIMIT 100`
            }
        ];
    }

    /**
     * Close the connection
     */
    async close(): Promise<void> {
        if (this.driver) {
            await this.driver.close();
            this.driver = null;
            console.log('[Neo4jService] Connection closed');
        }
    }
}

export const neo4jService = new Neo4jService();
export default neo4jService;

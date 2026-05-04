/**
 * TestScreen - Graph Visualization Testing
 * Location: src/screens/TestScreen.tsx
 *
 * TEMPORARY: For debugging graph visualization issues.
 * - Paste Cypher queries
 * - Execute against Neo4j
 * - Visualize with AttackPathGraph
 * - View debug logs
 *
 * DELETE THIS FILE AFTER TESTING IS COMPLETE
 */

import React, { useState, useRef, useCallback } from 'react';
import AttackPathGraph from '../components/AttackPathGraph';

// Types for graph data
interface GraphNode {
    id: string;
    label: string;
    name: string;
    type: 'User' | 'Group' | 'Computer' | 'Domain' | 'Unknown';
    color: string;
    riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
    inAttackPath: boolean;
    pathIndex: number;
    properties: Record<string, any>;
}

interface GraphEdge {
    id: string;
    source: string;
    target: string;
    label: string;
    type: string;
    color: string;
    riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
    inAttackPath: boolean;
    pathIndex: number;
    attack_type: string;
    description: string;
    properties: Record<string, any>;
}

interface GraphPath {
    id: string;
    name: string;
    description: string;
    attack_type: string;
    priority: string;
    risk_level: 'Critical' | 'High' | 'Medium' | 'Low';
    result_count: number;
    scenario_number: number;
    color: string;
}

interface GraphData {
    graph: {
        nodes: GraphNode[];
        edges: GraphEdge[];
        paths: GraphPath[];
    };
    layout: {
        suggested_layout: string;
        paths_layout: Record<string, any>;
        total_complexity: number;
        max_nodes_per_path: number;
    };
    metadata: {
        analysis_id: string;
        total_paths: number;
        total_nodes: number;
        total_edges: number;
        generated_at: string;
    };
}

interface LogEntry {
    timestamp: string;
    level: 'info' | 'warn' | 'error' | 'debug';
    message: string;
}

// Sample queries for quick testing
const SAMPLE_QUERIES = [
    {
        name: 'Domain Admins Path',
        query: `MATCH p=shortestPath((u:User)-[*1..5]->(g:Group))
WHERE g.name CONTAINS 'DOMAIN ADMINS'
RETURN p LIMIT 5`
    },
    {
        name: 'All Users to Groups',
        query: `MATCH (u:User)-[r:MemberOf]->(g:Group)
RETURN u, r, g LIMIT 20`
    },
    {
        name: 'Computers with Sessions',
        query: `MATCH (c:Computer)-[r:HasSession]->(u:User)
RETURN c, r, u LIMIT 15`
    },
    {
        name: 'High Value Targets',
        query: `MATCH (n)
WHERE n.highvalue = true
OPTIONAL MATCH (n)-[r]-(m)
RETURN n, r, m LIMIT 20`
    },
    {
        name: 'DCSync Rights',
        query: `MATCH p=(n)-[r:GetChanges|GetChangesAll*1..2]->(d:Domain)
RETURN p LIMIT 10`
    }
];

// Get node type from Neo4j labels
const getNodeType = (labels: string[]): GraphNode['type'] => {
    if (labels.includes('User')) return 'User';
    if (labels.includes('Group')) return 'Group';
    if (labels.includes('Computer')) return 'Computer';
    if (labels.includes('Domain')) return 'Domain';
    return 'Unknown';
};

// Get risk level based on node/edge properties
const getRiskLevel = (type: string, properties: Record<string, any>): GraphNode['riskLevel'] => {
    const dangerousEdges = ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'DCSync', 'GetChanges', 'GetChangesAll'];
    if (dangerousEdges.some(e => type.toUpperCase().includes(e.toUpperCase()))) return 'Critical';
    if (properties?.highvalue) return 'Critical';
    if (type === 'AdminTo' || type === 'CanRDP' || type === 'CanPSRemote') return 'High';
    if (type === 'MemberOf' || type === 'HasSession') return 'Medium';
    return 'Low';
};

// Get color based on node type
const getNodeColor = (type: GraphNode['type']): string => {
    switch (type) {
        case 'User': return '#3b82f6';
        case 'Group': return '#22c55e';
        case 'Computer': return '#ef4444';
        case 'Domain': return '#a855f7';
        default: return '#6b7280';
    }
};

// Get edge color based on risk
const getEdgeColor = (riskLevel: GraphEdge['riskLevel']): string => {
    switch (riskLevel) {
        case 'Critical': return '#ef4444';
        case 'High': return '#f97316';
        case 'Medium': return '#eab308';
        case 'Low': return '#6b7280';
    }
};

const TestScreen: React.FC = () => {
    const [query, setQuery] = useState(SAMPLE_QUERIES[0].query);
    const [isLoading, setIsLoading] = useState(false);
    const [graphData, setGraphData] = useState<GraphData | null>(null);
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [rawResults, setRawResults] = useState<any[] | null>(null);
    const [showRawResults, setShowRawResults] = useState(false);
    const logRef = useRef<HTMLDivElement>(null);

    // Add log entry
    const addLog = useCallback((level: LogEntry['level'], message: string) => {
        const entry: LogEntry = {
            timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }),
            level,
            message
        };
        setLogs(prev => [...prev, entry]);
        console.log(`[TestScreen] [${level.toUpperCase()}] ${message}`);

        // Auto-scroll to bottom
        setTimeout(() => {
            if (logRef.current) {
                logRef.current.scrollTop = logRef.current.scrollHeight;
            }
        }, 10);
    }, []);

    // Clear logs
    const clearLogs = useCallback(() => {
        setLogs([]);
    }, []);

    // Transform Neo4j records to graph format
    // Note: neo4jService.runQuery() already converts Neo4j values:
    // - Node: { id, labels, properties }
    // - Relationship: { id, type, startNodeId, endNodeId, properties }
    // - Path: { start, end, segments: [{ start, relationship, end }] }
    const transformToGraphData = useCallback((records: any[]): GraphData => {
        const nodesMap = new Map<string, GraphNode>();
        const edgesMap = new Map<string, GraphEdge>();

        addLog('info', `Processing ${records.length} records...`);

        // Log first record structure for debugging
        if (records.length > 0) {
            const firstRecord = records[0];
            addLog('debug', `First record keys: ${JSON.stringify(Object.keys(firstRecord || {}))}`);

            // Log structure of first value
            const firstKey = Object.keys(firstRecord)[0];
            const firstValue = firstRecord[firstKey];
            if (firstValue) {
                addLog('debug', `First value "${firstKey}" keys: ${JSON.stringify(Object.keys(firstValue || {}))}`);
            }
        }

        // Helper to add a node
        const addNode = (node: any, source: string) => {
            if (!node || node.id === undefined) return;

            const nodeId = String(node.id);
            if (nodesMap.has(nodeId)) return;

            const labels = node.labels || [];
            const type = getNodeType(labels);
            const props = node.properties || {};

            nodesMap.set(nodeId, {
                id: nodeId,
                label: props.name || props.samaccountname || `Node ${nodeId}`,
                name: props.name || props.samaccountname || `Node ${nodeId}`,
                type,
                color: getNodeColor(type),
                riskLevel: props.highvalue ? 'Critical' : 'Medium',
                inAttackPath: true,
                pathIndex: 0,
                properties: props
            });
            addLog('debug', `Added node from ${source}: ${props.name || nodeId} (${type})`);
        };

        // Helper to add an edge
        const addEdge = (rel: any, startId?: string, endId?: string) => {
            if (!rel) return;

            // Use relationship's own IDs or fallback to provided IDs
            const sourceId = String(rel.startNodeId ?? startId ?? '');
            const targetId = String(rel.endNodeId ?? endId ?? '');
            const edgeId = rel.id !== undefined ? String(rel.id) : `edge-${sourceId}-${targetId}`;

            if (!sourceId || !targetId || edgesMap.has(edgeId)) return;

            const relType = rel.type || 'RELATED';
            const riskLevel = getRiskLevel(relType, rel.properties || {});

            edgesMap.set(edgeId, {
                id: edgeId,
                source: sourceId,
                target: targetId,
                label: relType,
                type: relType,
                color: getEdgeColor(riskLevel),
                riskLevel,
                inAttackPath: true,
                pathIndex: 0,
                attack_type: relType,
                description: `${relType} relationship`,
                properties: rel.properties || {}
            });
            addLog('debug', `Added edge: ${relType} (${riskLevel})`);
        };

        records.forEach((record, idx) => {
            // Records are plain objects with field names as keys
            const keys = Object.keys(record);

            keys.forEach((key) => {
                const value = record[key];
                if (!value) return;

                // Handle Path objects (has segments array)
                if (value.segments && Array.isArray(value.segments)) {
                    if (idx === 0) addLog('debug', `Path "${key}" has ${value.segments.length} segments`);

                    // Also add start and end nodes of the path itself
                    if (value.start) addNode(value.start, 'path.start');
                    if (value.end) addNode(value.end, 'path.end');

                    value.segments.forEach((segment: any, segIdx: number) => {
                        if (idx === 0 && segIdx === 0) {
                            addLog('debug', `Segment keys: ${JSON.stringify(Object.keys(segment || {}))}`);
                            if (segment.start) {
                                addLog('debug', `Segment.start keys: ${JSON.stringify(Object.keys(segment.start || {}))}`);
                            }
                            if (segment.relationship) {
                                addLog('debug', `Segment.relationship keys: ${JSON.stringify(Object.keys(segment.relationship || {}))}`);
                            }
                        }

                        // Add start and end nodes from segment
                        addNode(segment.start, 'segment.start');
                        addNode(segment.end, 'segment.end');

                        // Add relationship with fallback to segment node IDs
                        const startId = segment.start?.id;
                        const endId = segment.end?.id;
                        addEdge(segment.relationship, startId, endId);
                    });
                }
                // Handle Node objects directly (has labels array and id)
                else if (value.labels && Array.isArray(value.labels) && value.id !== undefined) {
                    addNode(value, 'direct-node');
                }
                // Handle Relationship objects directly (has type and startNodeId/endNodeId)
                else if (value.type && (value.startNodeId !== undefined || value.endNodeId !== undefined)) {
                    addEdge(value);
                }
            });
        });

        const nodes = Array.from(nodesMap.values());
        const edges = Array.from(edgesMap.values());

        addLog('info', `Extracted ${nodes.length} nodes and ${edges.length} edges`);

        // Log node positions (will be calculated by dagre)
        nodes.forEach(node => {
            addLog('debug', `Node "${node.label}" - Type: ${node.type}, Risk: ${node.riskLevel}`);
        });

        // Check for potential overlaps (nodes with same type in sequence)
        const typeGroups = new Map<string, number>();
        nodes.forEach(n => {
            typeGroups.set(n.type, (typeGroups.get(n.type) || 0) + 1);
        });
        typeGroups.forEach((count, type) => {
            if (count > 3) {
                addLog('warn', `${count} nodes of type "${type}" - may cause layout crowding`);
            }
        });

        return {
            graph: {
                nodes,
                edges,
                paths: [{
                    id: 'path-1',
                    name: 'Query Results',
                    description: 'Results from Cypher query',
                    attack_type: 'query',
                    priority: 'medium',
                    risk_level: 'Medium',
                    result_count: nodes.length,
                    scenario_number: 1,
                    color: '#58a6ff'
                }]
            },
            layout: {
                suggested_layout: 'LR',
                paths_layout: {},
                total_complexity: edges.length,
                max_nodes_per_path: nodes.length
            },
            metadata: {
                analysis_id: `test-${Date.now()}`,
                total_paths: 1,
                total_nodes: nodes.length,
                total_edges: edges.length,
                generated_at: new Date().toISOString()
            }
        };
    }, [addLog]);

    // Execute query
    const executeQuery = useCallback(async () => {
        if (!query.trim()) {
            setError('Please enter a Cypher query');
            return;
        }

        setIsLoading(true);
        setError(null);
        setGraphData(null);
        setRawResults(null);
        clearLogs();

        addLog('info', 'Starting query execution...');
        addLog('debug', `Query: ${query.substring(0, 100)}${query.length > 100 ? '...' : ''}`);

        const startTime = performance.now();

        try {
            // Check if Neo4j is available
            if (!window.neo4j) {
                throw new Error('Neo4j API not available. Make sure you are running in Electron.');
            }

            addLog('info', 'Connecting to Neo4j...');
            const result = await window.neo4j.runQuery(query);

            const queryTime = (performance.now() - startTime).toFixed(2);
            addLog('info', `Query executed in ${queryTime}ms`);

            if (!result.success) {
                throw new Error(result.error || 'Query failed');
            }

            addLog('info', `Received ${result.count} records`);
            setRawResults(result.records);

            if (result.records.length === 0) {
                addLog('warn', 'Query returned no results');
                setError('Query returned no results. Try a different query.');
                return;
            }

            // Transform to graph format
            addLog('info', 'Transforming results to graph format...');
            const transformStart = performance.now();
            const data = transformToGraphData(result.records);
            const transformTime = (performance.now() - transformStart).toFixed(2);
            addLog('info', `Transformation completed in ${transformTime}ms`);

            if (data.graph.nodes.length === 0) {
                addLog('warn', 'No nodes extracted from results');
                setError('Could not extract graph nodes from query results. Make sure your query returns nodes, relationships, or paths.');
                return;
            }

            setGraphData(data);
            addLog('info', `Graph ready: ${data.graph.nodes.length} nodes, ${data.graph.edges.length} edges`);

        } catch (err: any) {
            const errorMsg = err.message || 'Unknown error occurred';
            addLog('error', `Error: ${errorMsg}`);
            setError(errorMsg);
        } finally {
            setIsLoading(false);
        }
    }, [query, addLog, clearLogs, transformToGraphData]);

    // Get log color
    const getLogColor = (level: LogEntry['level']): string => {
        switch (level) {
            case 'error': return 'text-red-400';
            case 'warn': return 'text-yellow-400';
            case 'info': return 'text-blue-400';
            case 'debug': return 'text-purple-400';
        }
    };

    return (
        <div className="flex flex-col h-full bg-[#0d1117] text-white">
            {/* Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363d]">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-yellow-500/10 rounded-lg">
                        <svg className="w-5 h-5 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                    </div>
                    <div>
                        <h1 className="text-lg font-semibold">Graph Visualization Test</h1>
                        <p className="text-xs text-[#8b949e]">TEMPORARY - Delete after testing</p>
                    </div>
                </div>
            </div>

            {/* Main Content */}
            <div className="flex-1 overflow-hidden flex">
                {/* Left Panel - Query Input */}
                <div className="w-[400px] border-r border-[#30363d] flex flex-col">
                    {/* Query Input */}
                    <div className="p-4 border-b border-[#30363d]">
                        <div className="flex items-center justify-between mb-2">
                            <label className="text-sm font-medium text-[#c9d1d9]">Cypher Query</label>
                            <button
                                onClick={() => setQuery('')}
                                className="text-xs text-[#8b949e] hover:text-white"
                            >
                                Clear
                            </button>
                        </div>
                        <textarea
                            value={query}
                            onChange={(e) => setQuery(e.target.value)}
                            placeholder="MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 10"
                            className="w-full h-32 px-3 py-2 bg-[#161b22] border border-[#30363d] rounded-lg text-sm text-white font-mono resize-none focus:outline-none focus:border-[#58a6ff]"
                        />
                    </div>

                    {/* Sample Queries */}
                    <div className="p-4 border-b border-[#30363d]">
                        <label className="text-sm font-medium text-[#c9d1d9] mb-2 block">Sample Queries</label>
                        <div className="space-y-1">
                            {SAMPLE_QUERIES.map((sample, idx) => (
                                <button
                                    key={idx}
                                    onClick={() => setQuery(sample.query)}
                                    className="w-full text-left px-3 py-2 text-xs bg-[#161b22] hover:bg-[#21262d] rounded transition-colors text-[#8b949e] hover:text-white"
                                >
                                    {sample.name}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Execute Button */}
                    <div className="p-4">
                        <button
                            onClick={executeQuery}
                            disabled={isLoading || !query.trim()}
                            className={`w-full py-2.5 rounded-lg font-medium transition-colors flex items-center justify-center gap-2 ${
                                isLoading || !query.trim()
                                    ? 'bg-[#21262d] text-[#8b949e] cursor-not-allowed'
                                    : 'bg-[#238636] hover:bg-[#2ea043] text-white'
                            }`}
                        >
                            {isLoading ? (
                                <>
                                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                    Executing...
                                </>
                            ) : (
                                <>
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    Run Query & Visualize
                                </>
                            )}
                        </button>
                    </div>

                    {/* Debug Console */}
                    <div className="flex-1 flex flex-col min-h-0">
                        <div className="flex items-center justify-between px-4 py-2 border-t border-[#30363d]">
                            <span className="text-sm font-medium text-[#c9d1d9]">Debug Console</span>
                            <button
                                onClick={clearLogs}
                                className="text-xs text-[#8b949e] hover:text-white"
                            >
                                Clear
                            </button>
                        </div>
                        <div
                            ref={logRef}
                            className="flex-1 overflow-y-auto px-4 pb-4 font-mono text-xs"
                        >
                            {logs.length === 0 ? (
                                <div className="text-[#8b949e] py-4">
                                    Logs will appear here...
                                </div>
                            ) : (
                                logs.map((log, idx) => (
                                    <div key={idx} className="py-0.5 flex gap-2">
                                        <span className="text-[#6e7681] shrink-0">[{log.timestamp}]</span>
                                        <span className={`shrink-0 w-12 ${getLogColor(log.level)}`}>
                                            {log.level.toUpperCase()}
                                        </span>
                                        <span className="text-[#c9d1d9]">{log.message}</span>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                </div>

                {/* Right Panel - Graph Visualization */}
                <div className="flex-1 flex flex-col min-h-0">
                    {/* Stats Bar */}
                    {graphData && (
                        <div className="flex items-center gap-6 px-4 py-2 border-b border-[#30363d] bg-[#161b22]">
                            <div className="flex items-center gap-2">
                                <div className="w-2.5 h-2.5 rounded-full bg-[#58a6ff]" />
                                <span className="text-sm text-[#c9d1d9] font-medium">{graphData.graph.nodes.length}</span>
                                <span className="text-xs text-[#8b949e]">nodes</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <div className="w-4 h-0.5 bg-[#f85149]" />
                                <span className="text-sm text-[#c9d1d9] font-medium">{graphData.graph.edges.length}</span>
                                <span className="text-xs text-[#8b949e]">edges</span>
                            </div>
                            <button
                                onClick={() => setShowRawResults(!showRawResults)}
                                className="ml-auto text-xs text-[#8b949e] hover:text-[#58a6ff]"
                            >
                                {showRawResults ? 'Hide' : 'Show'} Raw Results
                            </button>
                        </div>
                    )}

                    {/* Graph Area */}
                    <div className="flex-1 min-h-0 relative">
                        {error ? (
                            <div className="flex items-center justify-center h-full">
                                <div className="text-center p-8">
                                    <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-red-500/10 flex items-center justify-center">
                                        <svg className="w-8 h-8 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                        </svg>
                                    </div>
                                    <p className="text-red-400 font-medium mb-2">Error</p>
                                    <p className="text-[#8b949e] text-sm max-w-md">{error}</p>
                                </div>
                            </div>
                        ) : graphData ? (
                            <div className="h-full">
                                <AttackPathGraph
                                    analysisId={graphData.metadata.analysis_id}
                                    graphData={graphData}
                                    isExpanded={false}
                                    hidePathSelector={true}
                                    singlePathMode={true}
                                    defaultSelectedPath="1"
                                    skipLazyLoad={true}
                                />
                            </div>
                        ) : (
                            <div className="flex items-center justify-center h-full">
                                <div className="text-center p-8">
                                    <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#21262d] flex items-center justify-center">
                                        <svg className="w-8 h-8 text-[#8b949e]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                                        </svg>
                                    </div>
                                    <p className="text-[#c9d1d9] font-medium mb-1">No Graph Data</p>
                                    <p className="text-[#8b949e] text-sm">Run a Cypher query to visualize the results</p>
                                </div>
                            </div>
                        )}

                        {/* Raw Results Overlay */}
                        {showRawResults && rawResults && (
                            <div className="absolute inset-0 bg-[#0d1117]/95 p-4 overflow-auto">
                                <div className="flex items-center justify-between mb-4">
                                    <h3 className="text-sm font-medium text-[#c9d1d9]">Raw Query Results</h3>
                                    <button
                                        onClick={() => setShowRawResults(false)}
                                        className="text-[#8b949e] hover:text-white"
                                    >
                                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                        </svg>
                                    </button>
                                </div>
                                <pre className="text-xs text-[#c9d1d9] font-mono whitespace-pre-wrap">
                                    {JSON.stringify(rawResults, null, 2)}
                                </pre>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default TestScreen;

/**
 * NormalResponseView Component
 * Renders normal chat responses with:
 * - Explanation (description of findings)
 * - Attack Commands (possible attack techniques)
 * - Remediation (fix strategies)
 * - Graph visualization (for path queries)
 * - Results table (for data queries)
 */

import React, { useMemo, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import toast from 'react-hot-toast';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { QueryResponse, ChatGraphData, AttackStep } from '../../types/chat';
import CypherQueryDisplay from '../attack-components/CypherQueryDisplay';
import AttackStepCard from '../attack-components/AttackStepCard';
import AttackPathGraph from '../AttackPathGraph';

interface NormalResponseViewProps {
    response: QueryResponse;
    onCopy?: (text: string) => void;
}

const NormalResponseView: React.FC<NormalResponseViewProps> = ({ response, onCopy }) => {
    const handleCopy = (text: string) => {
        if (onCopy) {
            onCopy(text);
        } else {
            navigator.clipboard.writeText(text);
        }
    };

    // Parse remediation into numbered steps
    const remediationSteps = useMemo(() => {
        if (!response.remediation) return [];

        // Split by newlines and filter out empty lines
        const lines = response.remediation
            .split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0)
            // Remove bullet points or existing numbers
            .map(line => line.replace(/^[-•*]\s*/, '').replace(/^\d+\.\s*/, ''));

        return lines;
    }, [response.remediation]);

    // Check if results contain BloodHound CE paths that should be rendered as graphs
    const bloodHoundCEGraphData = useMemo(() => {
        if (response.results && response.results.length > 0 && containsBloodHoundCEPaths(response.results)) {
            return convertBloodHoundCEPathsToGraphData(response.results);
        }
        return null;
    }, [response.results]);

    // Helper to check if sections exist
    const hasQuery = !!response.cypher_query;
    const hasBloodHoundCEGraph = !!bloodHoundCEGraphData;
    const hasResults = response.results && response.results.length > 0 && !response.has_graph && !hasBloodHoundCEGraph;
    const hasGraph = (response.has_graph && response.graph_data) || hasBloodHoundCEGraph;
    const effectiveGraphData = response.graph_data || bloodHoundCEGraphData;
    const hasExplanation = !!response.explanation;
    const hasUnderstanding = response.understanding && response.understanding.length > 0;
    const hasAttackSteps = response.attack_steps && response.attack_steps.length > 0;
    const hasRemediation = remediationSteps.length > 0;
    const hasSuggestedQuery = !!response.suggested_query;

    // Divider component
    const Divider = () => <div className="h-px bg-[#30363d] my-6" />;

    return (
        <div className="space-y-4">
            {/* Evidence — Cypher Query + Graph */}
            {hasQuery && (
                <ChatSectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>}>Evidence</ChatSectionTitle>
            )}
            {hasQuery && (
                <CypherQueryDisplay
                    query={response.cypher_query!}
                    queryName={response.query_type === 'cypher' ? 'Cypher Query' : 'Generated Query'}
                    description={`${response.result_count} result(s)`}
                    edgesUsed={effectiveGraphData?.edges?.map(e => e.type).filter((v, i, a) => a.indexOf(v) === i)}
                    onCopy={handleCopy}
                />
            )}

            {/* Divider after Query */}
            {hasQuery && (hasResults || hasGraph || hasExplanation || hasUnderstanding || hasAttackSteps || hasRemediation) && <Divider />}

            {/* Results Table (for data queries with tabular results) */}
            {hasResults && (
                <ResultsTable results={response.results!} onCopy={handleCopy} />
            )}

            {/* Divider after Results */}
            {hasResults && (hasExplanation || hasUnderstanding || hasAttackSteps || hasRemediation) && <Divider />}

            {/* Attack Path Graph (for path queries) */}
            {hasGraph && effectiveGraphData && (
                <ChatGraphVisualization graphData={effectiveGraphData} />
            )}

            {/* Divider after Graph */}
            {hasGraph && (hasExplanation || hasUnderstanding || hasAttackSteps || hasRemediation) && <Divider />}

            {/* Observation */}
            {hasExplanation && (
                <div>
                    <ChatSectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>}>Observation</ChatSectionTitle>
                    <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-4">
                        <MarkdownContent content={response.explanation!} onCopy={handleCopy} />
                    </div>
                </div>
            )}

            {/* Divider after Explanation */}
            {hasExplanation && (hasUnderstanding || hasAttackSteps || hasRemediation) && <Divider />}

            {/* Understanding Q&A Section */}
            {hasUnderstanding && (
                <UnderstandingSection explanations={response.understanding!} />
            )}

            {/* Divider after Understanding */}
            {hasUnderstanding && (hasAttackSteps || hasRemediation) && <Divider />}

            {/* Attack Commands Section */}
            {hasAttackSteps && (
                <AttackStepsSection steps={response.attack_steps!} onCopy={handleCopy} />
            )}

            {/* Divider after Attack Steps */}
            {hasAttackSteps && hasRemediation && <Divider />}

            {/* Remediation Section */}
            {hasRemediation && (
                <RemediationSection steps={remediationSteps} />
            )}

            {/* Divider before Suggested Query */}
            {hasRemediation && hasSuggestedQuery && <Divider />}

            {/* Suggested Query (for non-query inputs like "How to exploit WriteDacl?") */}
            {hasSuggestedQuery && (
                <CypherQueryDisplay
                    query={response.suggested_query!}
                    queryName="Suggested Query"
                    description="Try running this query to explore further"
                    onCopy={handleCopy}
                />
            )}

            {/* Copy Response JSON Button - for debugging/review */}
            <CopyResponseButton response={response} />
        </div>
    );
};

// Section title with SVG icon — matches the report FindingCard style
const ChatSectionTitle: React.FC<{ children: React.ReactNode; icon: React.ReactNode; color?: string }> = ({ children, icon, color = 'text-[#58a6ff]' }) => (
    <h2 className={`text-[15px] font-bold uppercase tracking-widest mt-2 mb-4 pb-2 border-b border-[#30363d] flex items-center gap-2.5 ${color}`}>
        {icon}
        {children}
    </h2>
);

// Attack Steps Section - uses shared AttackStepCard component
const AttackStepsSection: React.FC<{
    steps: AttackStep[];
    onCopy: (text: string) => void;
}> = ({ steps, onCopy }) => (
    <div className="space-y-4">
        <ChatSectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>}>Attack Steps</ChatSectionTitle>
        {steps.map((step, idx) => (
            <AttackStepCard key={idx} step={step} onCopy={onCopy} index={idx} />
        ))}
    </div>
);

// Remediation Section with numbered steps
const RemediationSection: React.FC<{ steps: string[] }> = ({ steps }) => {
    // Parse markdown-style bold (**text**) to JSX
    const parseMarkdown = (text: string) => {
        const parts = text.split(/(\*\*[^*]+\*\*)/g);
        return parts.map((part, idx) => {
            if (part.startsWith('**') && part.endsWith('**')) {
                return (
                    <strong key={idx} className="text-[#7ee787] font-semibold">
                        {part.slice(2, -2)}
                    </strong>
                );
            }
            return part;
        });
    };

    return (
        <div className="rounded-lg border border-[#23863640] bg-[#23863610] overflow-hidden">
            <div className="px-4 py-3 border-b border-[#23863630] flex items-center gap-2">
                <svg className="w-4 h-4 text-[#238636]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <span className="text-sm font-medium text-[#238636]">Remediation</span>
            </div>
            <div className="p-4 space-y-3">
                {steps.map((step, idx) => (
                    <div key={idx} className="flex gap-3">
                        <span className="flex-shrink-0 w-6 h-6 rounded-full bg-[#238636] text-white text-xs font-bold flex items-center justify-center">
                            {idx + 1}
                        </span>
                        <p className="text-[#c9d1d9] text-sm leading-relaxed pt-0.5">{parseMarkdown(step)}</p>
                    </div>
                ))}
            </div>
        </div>
    );
};

// Understanding Q&A Section (matches AttackExplainer style without card wrapper)
const UnderstandingSection: React.FC<{ explanations: Array<{ question: string; answer: string }> }> = ({ explanations }) => {
    if (!explanations || explanations.length === 0) return null;

    // Parse markdown-style bold (**text**) to JSX
    const parseAnswer = (text: string) => {
        const parts = text.split(/(\*\*[^*]+\*\*)/g);
        return parts.map((part, idx) => {
            if (part.startsWith('**') && part.endsWith('**')) {
                return (
                    <strong key={idx} className="text-[#fbbf24] font-semibold">
                        {part.slice(2, -2)}
                    </strong>
                );
            }
            return part;
        });
    };

    return (
        <div>
            <ChatSectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>}>Understanding the Attack</ChatSectionTitle>
            <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
                {explanations.map((item, index) => (
                    <React.Fragment key={index}>
                        <div className="p-4">
                            <div className="text-[#58a6ff] font-semibold mb-2 text-[15px]">
                                {item.question}
                            </div>
                            <div className="text-[#c9d1d9] leading-relaxed text-[15px]">
                                {parseAnswer(item.answer)}
                            </div>
                        </div>
                        {index < explanations.length - 1 && (
                            <div className="mx-4 h-px bg-[#30363d]" />
                        )}
                    </React.Fragment>
                ))}
            </div>
        </div>
    );
};

// Helper to check if a value is a Neo4j path object (classic format with nodes array)
const isPathObject = (value: unknown): value is { nodes: unknown[]; relationships?: unknown[] } => {
    return (
        typeof value === 'object' &&
        value !== null &&
        'nodes' in value &&
        Array.isArray((value as any).nodes)
    );
};

// Helper to check if a value is a BloodHound CE path object (segment-based format)
const isBloodHoundCEPath = (value: unknown): value is { start: unknown; end: unknown; segments?: unknown[] } => {
    return (
        typeof value === 'object' &&
        value !== null &&
        'start' in value &&
        'end' in value &&
        typeof (value as any).start === 'object' &&
        typeof (value as any).end === 'object'
    );
};

// Convert BloodHound CE path format to ChatGraphData format
const convertBloodHoundCEPathsToGraphData = (results: Array<Record<string, unknown>>): ChatGraphData | null => {
    const nodeMap = new Map<string, any>();
    const edges: any[] = [];

    results.forEach((row, rowIndex) => {
        Object.values(row).forEach((value) => {
            if (isBloodHoundCEPath(value)) {
                const path = value as any;

                // Add start node
                if (path.start) {
                    const startId = path.start.id?.toString() || path.start.objectid || `node-${rowIndex}-start`;
                    const labels = path.start.labels || path.start._labels || [];
                    const nodeType = labels.find((l: string) => l !== 'Base') || 'Unknown';
                    const props = path.start.properties || path.start;

                    if (!nodeMap.has(startId)) {
                        nodeMap.set(startId, {
                            id: startId,
                            label: props.name || props.samaccountname || props.objectid || startId,
                            type: nodeType,
                            properties: props,
                            path_ids: [`${rowIndex + 1}`]
                        });
                    }
                }

                // Add end node
                if (path.end) {
                    const endId = path.end.id?.toString() || path.end.objectid || `node-${rowIndex}-end`;
                    const labels = path.end.labels || path.end._labels || [];
                    const nodeType = labels.find((l: string) => l !== 'Base') || 'Unknown';
                    const props = path.end.properties || path.end;

                    if (!nodeMap.has(endId)) {
                        nodeMap.set(endId, {
                            id: endId,
                            label: props.name || props.samaccountname || props.objectid || endId,
                            type: nodeType,
                            properties: props,
                            path_ids: [`${rowIndex + 1}`]
                        });
                    }
                }

                // Process segments to get intermediate nodes and edges
                if (path.segments && Array.isArray(path.segments)) {
                    path.segments.forEach((segment: any, segIndex: number) => {
                        // Segment start node
                        if (segment.start) {
                            const nodeId = segment.start.id?.toString() || segment.start.objectid || `seg-${rowIndex}-${segIndex}-start`;
                            const labels = segment.start.labels || segment.start._labels || [];
                            const nodeType = labels.find((l: string) => l !== 'Base') || 'Unknown';
                            const props = segment.start.properties || segment.start;

                            if (!nodeMap.has(nodeId)) {
                                nodeMap.set(nodeId, {
                                    id: nodeId,
                                    label: props.name || props.samaccountname || props.objectid || nodeId,
                                    type: nodeType,
                                    properties: props,
                                    path_ids: [`${rowIndex + 1}`]
                                });
                            }
                        }

                        // Segment end node
                        if (segment.end) {
                            const nodeId = segment.end.id?.toString() || segment.end.objectid || `seg-${rowIndex}-${segIndex}-end`;
                            const labels = segment.end.labels || segment.end._labels || [];
                            const nodeType = labels.find((l: string) => l !== 'Base') || 'Unknown';
                            const props = segment.end.properties || segment.end;

                            if (!nodeMap.has(nodeId)) {
                                nodeMap.set(nodeId, {
                                    id: nodeId,
                                    label: props.name || props.samaccountname || props.objectid || nodeId,
                                    type: nodeType,
                                    properties: props,
                                    path_ids: [`${rowIndex + 1}`]
                                });
                            }
                        }

                        // Edge from segment relationship
                        if (segment.relationship && segment.start && segment.end) {
                            const sourceId = segment.start.id?.toString() || segment.start.objectid || `seg-${rowIndex}-${segIndex}-start`;
                            const targetId = segment.end.id?.toString() || segment.end.objectid || `seg-${rowIndex}-${segIndex}-end`;
                            const relType = segment.relationship.type || segment.relationship.kind || 'RELATED_TO';

                            edges.push({
                                id: `edge-${rowIndex}-${segIndex}`,
                                source: sourceId,
                                target: targetId,
                                type: relType,
                                path_ids: [`${rowIndex + 1}`]
                            });
                        }
                    });
                } else {
                    // No segments - create edge directly from start to end
                    const startId = path.start.id?.toString() || path.start.objectid || `node-${rowIndex}-start`;
                    const endId = path.end.id?.toString() || path.end.objectid || `node-${rowIndex}-end`;

                    edges.push({
                        id: `edge-${rowIndex}-direct`,
                        source: startId,
                        target: endId,
                        type: 'PATH',
                        path_ids: [`${rowIndex + 1}`]
                    });
                }
            }
        });
    });

    if (nodeMap.size === 0) {
        return null;
    }

    return {
        nodes: Array.from(nodeMap.values()),
        edges: edges,
        paths: [{
            id: 'path-1',
            name: 'Query Results',
            description: 'Path query results',
            attack_type: 'path_query',
            priority: 'medium',
            risk_level: 'Medium' as const,
            result_count: results.length,
            scenario_number: 1,
            color: '#58a6ff'
        }]
    };
};

// Check if results contain BloodHound CE paths
const containsBloodHoundCEPaths = (results: Array<Record<string, unknown>>): boolean => {
    if (!results || results.length === 0) return false;

    return results.some(row =>
        Object.values(row).some(value => isBloodHoundCEPath(value))
    );
};

// Helper to extract node display name
const getNodeDisplayName = (node: any): string => {
    // Try common BloodHound properties - check both direct and nested in properties
    const props = node?.properties || node;
    return props?.name || props?.samaccountname || props?.distinguishedname ||
        node?.name || node?.objectid || props?.objectid || 'Unknown';
};

// Helper to get node type from labels
const getNodeTypeFromLabels = (node: any): string => {
    // Check for _labels (how backend serializes Neo4j labels) or labels
    const labels = node?._labels || node?.labels;
    if (labels && Array.isArray(labels) && labels.length > 0) {
        // Filter out 'Base' and return the first meaningful label
        const meaningfulLabels = labels.filter((l: string) => l !== 'Base');
        if (meaningfulLabels.length > 0) {
            return meaningfulLabels[0];
        }
    }

    // Check for explicit type/kind properties
    if (node?.kind) return node.kind;
    if (node?.type) return node.type;
    if (node?.properties?.type) return node.properties.type;

    // Try to infer type from BloodHound-style properties
    const props = node?.properties || node;

    // Check for user-specific properties
    if (props?.samaccountname || props?.userprincipalname || props?.displayname) {
        return 'User';
    }

    // Check for computer-specific properties (computers often end with $)
    const name = getNodeDisplayName(node);
    if (name.endsWith('$') || props?.operatingsystem) {
        return 'Computer';
    }

    // Check for domain properties
    if (props?.domain && props?.functionallevel) {
        return 'Domain';
    }

    // Check for GPO properties
    if (props?.gpcpath) {
        return 'GPO';
    }

    // Check for OU properties
    if (props?.blocksinheritance !== undefined) {
        return 'OU';
    }

    // Common BloodHound group names
    const upperName = name.toUpperCase();
    if (upperName.includes('DOMAIN ADMINS') ||
        upperName.includes('ENTERPRISE ADMINS') ||
        upperName.includes('ADMINISTRATORS') ||
        upperName.includes('ACCOUNT OPERATORS') ||
        upperName.includes('BACKUP OPERATORS') ||
        upperName.includes('SERVER OPERATORS') ||
        upperName.includes('PRINT OPERATORS') ||
        upperName.includes('DOMAIN USERS') ||
        upperName.includes('DOMAIN COMPUTERS') ||
        upperName.includes('DOMAIN CONTROLLERS')) {
        return 'Group';
    }

    // If has objectid but no other distinguishing features, likely a User
    if (props?.objectid && name.includes('@')) {
        return 'User';
    }

    return 'Unknown';
};

// Helper to format a path into a readable string
const formatPathToString = (pathObj: { nodes: any[]; relationships?: any[] }): string => {
    const nodes = pathObj.nodes || [];
    const rels = pathObj.relationships || [];

    if (nodes.length === 0) return '(empty path)';

    const parts: string[] = [];
    for (let i = 0; i < nodes.length; i++) {
        const node = nodes[i];
        const nodeType = getNodeTypeFromLabels(node);
        const nodeName = getNodeDisplayName(node);
        parts.push(`[${nodeType}] ${nodeName}`);

        if (i < rels.length) {
            const rel = rels[i];
            const relType = rel?.type || rel?.label || '→';
            parts.push(` --(${relType})--> `);
        }
    }

    return parts.join('');
};

// Helper to check if a value is a Neo4j node object (has _labels or many BloodHound properties)
const isNodeObject = (value: unknown): boolean => {
    if (typeof value !== 'object' || value === null) return false;
    const obj = value as Record<string, unknown>;

    // Check for _labels (standard Neo4j) or labels (BloodHound CE format)
    if (obj._labels || obj.labels) return true;

    // Check for _id (standard Neo4j) or id (BloodHound CE format)
    if (obj._id !== undefined || (typeof obj.id === 'number' && obj.id > 0)) return true;

    // BloodHound CE nests properties - check for that pattern
    if (obj.properties && typeof obj.properties === 'object') return true;

    // Check for common BloodHound properties directly on the object
    return !!(obj.name && (obj.objectid || obj.distinguishedname || obj.domain));
};

// Priority columns to show for node results (in order)
const NODE_DISPLAY_COLUMNS = [
    'name', 'samaccountname', 'displayname',  // Identity
    '_labels',  // Type
    'enabled', 'admincount', 'unconstraineddelegation', 'trustedtoauth',  // Security flags
    'lastlogon', 'lastlogontimestamp', 'pwdlastset', 'whencreated',  // Timestamps
    'operatingsystem', 'description', 'domain'  // Additional info
];

// Helper to extract tabular data from path or node results
const extractPathData = (results: Array<Record<string, unknown>>): {
    isPathResult: boolean;
    extractedData: Array<Record<string, unknown>>;
    columns: string[];
} => {
    if (!results || results.length === 0) {
        return { isPathResult: false, extractedData: [], columns: [] };
    }

    const firstRow = results[0];

    // Check if results contain path objects
    const pathKeys = Object.keys(firstRow).filter(key => isPathObject(firstRow[key]));

    // Check if results contain node objects (returned directly, not as paths)
    const nodeKeys = Object.keys(firstRow).filter(key => isNodeObject(firstRow[key]));

    if (pathKeys.length === 0 && nodeKeys.length === 0) {
        // Not a path or node result - check if it's a flat result with BloodHound properties
        const allKeys = Object.keys(firstRow);
        const allKeysLower = allKeys.map(k => k.toLowerCase());

        // Expanded list of BloodHound node properties
        const bloodhoundProps = [
            'objectid', 'distinguishedname', 'samaccountname', '_labels', 'labels',
            'unconstraineddelegation', 'trustedtoauth', 'isaclprotected', 'admincount',
            'haslaps', 'isdc', 'sidhistory', 'serviceprincipalnames', 'operatingsystem',
            'pwdlastset', 'lastlogon', 'lastlogontimestamp', 'whencreated', 'enabled',
            'passwordexpired', 'lockedout', 'domain', 'highvalue', 'owned'
        ];

        const matchedProps = bloodhoundProps.filter(prop => allKeysLower.includes(prop));
        const hasBloodHoundProps = matchedProps.length >= 3; // At least 3 BloodHound properties

        if (hasBloodHoundProps) {
            // It's a flat node result - extract only relevant columns
            const extractedData = results.map(row => {
                const extracted: Record<string, unknown> = {};
                // Add name first - check multiple possible name fields
                extracted['Name'] = row.name || row.samaccountname || row.displayname ||
                    (row as any).Name || (row as any).Samaccountname || 'Unknown';

                // Add type from _labels or labels
                const labelsField = row._labels || row.labels || (row as any)._labels || (row as any).labels;
                if (labelsField && Array.isArray(labelsField)) {
                    const labels = (labelsField as string[]).filter(l => l !== 'Base');
                    extracted['Type'] = labels[0] || 'Unknown';
                } else {
                    extracted['Type'] = getNodeTypeFromLabels(row);
                }

                // Add other important columns that exist (case-insensitive matching)
                for (const col of NODE_DISPLAY_COLUMNS) {
                    if (col !== 'name' && col !== '_labels') {
                        // Find the actual key (might have different casing)
                        const actualKey = allKeys.find(k => k.toLowerCase() === col.toLowerCase());
                        if (actualKey && row[actualKey] !== undefined) {
                            const displayName = col.charAt(0).toUpperCase() + col.slice(1).replace(/([A-Z])/g, ' $1');
                            extracted[displayName] = row[actualKey];
                        }
                    }
                }
                return extracted;
            });

            const columns = extractedData.length > 0
                ? Array.from(new Set(extractedData.flatMap(row => Object.keys(row))))
                : [];

            return { isPathResult: true, extractedData, columns };
        }

        // Regular result, return as-is
        const columns = Array.from(new Set(results.flatMap(row => Object.keys(row))));
        return { isPathResult: false, extractedData: results, columns };
    }

    // Handle node objects (like RETURN c for a Computer node)
    if (nodeKeys.length > 0 && pathKeys.length === 0) {
        const extractedData: Array<Record<string, unknown>> = [];

        results.forEach((row) => {
            nodeKeys.forEach(nodeKey => {
                const node = row[nodeKey] as Record<string, unknown>;
                const extracted: Record<string, unknown> = {};

                // Add name first
                extracted['Name'] = getNodeDisplayName(node);
                extracted['Type'] = getNodeTypeFromLabels(node);

                // Add important properties
                const props = node.properties || node;
                for (const col of NODE_DISPLAY_COLUMNS) {
                    if (col !== 'name' && col !== '_labels') {
                        const value = (props as Record<string, unknown>)[col];
                        if (value !== undefined && value !== null) {
                            const displayName = col.charAt(0).toUpperCase() + col.slice(1).replace(/([A-Z])/g, ' $1');
                            extracted[displayName] = value;
                        }
                    }
                }

                extractedData.push(extracted);
            });

            // Include non-node columns
            Object.entries(row).forEach(([key, value]) => {
                if (!nodeKeys.includes(key) && extractedData.length > 0) {
                    extractedData[extractedData.length - 1][key] = value;
                }
            });
        });

        const columns = extractedData.length > 0
            ? Array.from(new Set(extractedData.flatMap(row => Object.keys(row))))
            : [];

        return { isPathResult: true, extractedData, columns };
    }

    // Extract meaningful data from paths
    const extractedData: Array<Record<string, unknown>> = [];

    results.forEach((row) => {
        pathKeys.forEach(pathKey => {
            const pathObj = row[pathKey] as { nodes: any[]; relationships?: any[] };
            const nodes = pathObj.nodes || [];

            if (nodes.length >= 2) {
                // Extract start and end nodes, and path summary
                const startNode = nodes[0];
                const endNode = nodes[nodes.length - 1];

                extractedData.push({
                    'Start Node': getNodeDisplayName(startNode),
                    'Start Type': getNodeTypeFromLabels(startNode),
                    'End Node': getNodeDisplayName(endNode),
                    'End Type': getNodeTypeFromLabels(endNode),
                    'Path Length': nodes.length - 1,
                    'Full Path': formatPathToString(pathObj)
                });
            } else if (nodes.length === 1) {
                // Single node
                const node = nodes[0];
                extractedData.push({
                    'Node': getNodeDisplayName(node),
                    'Type': getNodeTypeFromLabels(node),
                    'Properties': JSON.stringify(node.properties || {}).slice(0, 100)
                });
            }
        });

        // Also include any non-path columns from the row
        Object.entries(row).forEach(([key, value]) => {
            if (!pathKeys.includes(key) && extractedData.length > 0) {
                extractedData[extractedData.length - 1][key] = value;
            }
        });
    });

    // Get columns from extracted data
    const columns = extractedData.length > 0
        ? Array.from(new Set(extractedData.flatMap(row => Object.keys(row))))
        : [];

    return { isPathResult: true, extractedData, columns };
};

// Results table component with pagination
const ResultsTable: React.FC<{ results: Array<Record<string, unknown>>; onCopy: (text: string) => void }> = ({ results, onCopy }) => {
    const [currentPage, setCurrentPage] = React.useState(0);
    const pageSize = 25;

    // Extract and process path data if needed
    const { isPathResult, extractedData, columns } = useMemo(() => {
        return extractPathData(results);
    }, [results]);

    const dataToDisplay = isPathResult ? extractedData : results;
    const totalPages = Math.ceil(dataToDisplay.length / pageSize);

    const paginatedResults = useMemo(() => {
        const start = currentPage * pageSize;
        return dataToDisplay.slice(start, start + pageSize);
    }, [dataToDisplay, currentPage]);

    if (!results || results.length === 0) {
        return (
            <div className="text-sm text-[#8b949e] italic">No results found</div>
        );
    }

    const formatCellValue = (value: unknown): string => {
        if (value === null || value === undefined) return '-';
        if (typeof value === 'boolean') return value ? 'true' : 'false';
        if (isPathObject(value)) return formatPathToString(value);
        if (typeof value === 'object') {
            const str = JSON.stringify(value);
            return str.length > 200 ? str.slice(0, 200) + '...' : str;
        }
        return String(value);
    };

    const handleCopyTable = () => {
        const header = columns.join('\t');
        const rows = dataToDisplay.map(row =>
            columns.map(col => formatCellValue(row[col])).join('\t')
        ).join('\n');
        onCopy(`${header}\n${rows}`);
        toast.success('Copied to clipboard');
    };

    return (
        <div className="rounded-lg border border-[#30363d] overflow-hidden">
            {/* Table Header with Copy Button */}
            <div className="px-4 py-2 bg-[#161b22] border-b border-[#30363d] flex items-center justify-between">
                <span className="text-xs text-[#8b949e]">
                    {dataToDisplay.length} result{dataToDisplay.length !== 1 ? 's' : ''}
                    {isPathResult && ' (extracted from paths)'}
                </span>
                <button
                    onClick={handleCopyTable}
                    className="text-xs text-[#8b949e] hover:text-[#c9d1d9] flex items-center gap-1"
                    title="Copy all results as TSV"
                >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                    Copy All
                </button>
            </div>

            {/* Table */}
            <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
                <table className="w-full text-sm">
                    <thead className="bg-[#161b22] sticky top-0">
                        <tr>
                            {columns.map((col, idx) => (
                                <th
                                    key={idx}
                                    className="px-4 py-2 text-left text-xs font-medium text-[#8b949e] uppercase tracking-wider border-b border-[#30363d]"
                                >
                                    {col}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-[#30363d]">
                        {paginatedResults.map((row, rowIdx) => (
                            <tr key={rowIdx} className="hover:bg-[#161b22]/50">
                                {columns.map((col, colIdx) => (
                                    <td
                                        key={colIdx}
                                        className="px-4 py-2 text-[#c9d1d9] font-mono text-xs whitespace-nowrap"
                                        title={formatCellValue(row[col])}
                                    >
                                        {formatCellValue(row[col]).slice(0, 60)}
                                        {formatCellValue(row[col]).length > 60 && '...'}
                                    </td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
                <div className="px-4 py-2 bg-[#161b22] border-t border-[#30363d] flex items-center justify-between">
                    <span className="text-xs text-[#8b949e]">
                        Showing {currentPage * pageSize + 1}-{Math.min((currentPage + 1) * pageSize, dataToDisplay.length)} of {dataToDisplay.length}
                    </span>
                    <div className="flex items-center gap-1">
                        <button
                            onClick={() => setCurrentPage(0)}
                            disabled={currentPage === 0}
                            className="px-2 py-1 text-xs rounded hover:bg-[#21262d] disabled:opacity-40 disabled:cursor-not-allowed text-[#8b949e] hover:text-[#c9d1d9]"
                            title="First page"
                        >
                            {'<<'}
                        </button>
                        <button
                            onClick={() => setCurrentPage(p => Math.max(0, p - 1))}
                            disabled={currentPage === 0}
                            className="px-2 py-1 text-xs rounded hover:bg-[#21262d] disabled:opacity-40 disabled:cursor-not-allowed text-[#8b949e] hover:text-[#c9d1d9]"
                            title="Previous page"
                        >
                            {'<'}
                        </button>
                        <span className="px-3 py-1 text-xs text-[#c9d1d9]">
                            {currentPage + 1} / {totalPages}
                        </span>
                        <button
                            onClick={() => setCurrentPage(p => Math.min(totalPages - 1, p + 1))}
                            disabled={currentPage >= totalPages - 1}
                            className="px-2 py-1 text-xs rounded hover:bg-[#21262d] disabled:opacity-40 disabled:cursor-not-allowed text-[#8b949e] hover:text-[#c9d1d9]"
                            title="Next page"
                        >
                            {'>'}
                        </button>
                        <button
                            onClick={() => setCurrentPage(totalPages - 1)}
                            disabled={currentPage >= totalPages - 1}
                            className="px-2 py-1 text-xs rounded hover:bg-[#21262d] disabled:opacity-40 disabled:cursor-not-allowed text-[#8b949e] hover:text-[#c9d1d9]"
                            title="Last page"
                        >
                            {'>>'}
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

// Chat Graph Visualization - uses AttackPathGraph component with fullscreen modal
const ChatGraphVisualization: React.FC<{ graphData: ChatGraphData }> = ({ graphData }) => {
    const [isFullScreen, setIsFullScreen] = useState(false);

    // Convert ChatGraphData to the GraphData format expected by AttackPathGraph
    const attackPathGraphData = useMemo(() => {
        // Ensure paths array exists (create default if not)
        const paths = graphData.paths && graphData.paths.length > 0
            ? graphData.paths
            : [{
                id: 'path-1',
                name: 'Query Results',
                description: 'Results from chat query',
                attack_type: 'query',
                priority: 'medium',
                risk_level: 'Medium' as const,
                result_count: graphData.nodes?.length || 0,
                scenario_number: 1,
                color: '#58a6ff'
            }];

        return {
            graph: {
                nodes: graphData.nodes || [],
                edges: graphData.edges || [],
                paths: paths
            },
            layout: {
                suggested_layout: 'LR',
                paths_layout: {},
                total_complexity: graphData.edges?.length || 0,
                max_nodes_per_path: graphData.nodes?.length || 0
            },
            metadata: {
                analysis_id: `chat-${Date.now()}`,
                total_paths: paths.length,
                total_nodes: graphData.nodes?.length || 0,
                total_edges: graphData.edges?.length || 0,
                generated_at: new Date().toISOString()
            }
        };
    }, [graphData]);

    const nodeCount = graphData.nodes?.length || 0;
    const edgeCount = graphData.edges?.length || 0;

    // If no nodes/edges, show empty state
    if (nodeCount === 0 && edgeCount === 0) {
        return (
            <div className="rounded-lg border border-[#30363d] bg-[#0d1117] p-4 text-center text-[#8b949e]">
                No graph data available
            </div>
        );
    }

    return (
        <>
            {/* Graph visualization - node/edge counts are now in the graph footer */}
            <div className="h-[350px]">
                <AttackPathGraph
                    analysisId={`chat-${Date.now()}`}
                    graphData={attackPathGraphData}
                    isExpanded={false}
                    hidePathSelector={attackPathGraphData.graph.paths.length <= 1}
                    singlePathMode={attackPathGraphData.graph.paths.length === 1}
                    defaultSelectedPath="1"
                    onOpenFullScreen={() => setIsFullScreen(true)}
                />
            </div>

            {/* Fullscreen Modal */}
            {isFullScreen && (
                <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-8">
                    <div className="w-full max-w-6xl h-[85vh] flex flex-col">
                        <AttackPathGraph
                            analysisId={`chat-fullscreen-${Date.now()}`}
                            graphData={attackPathGraphData}
                            isExpanded={true}
                            onClose={() => setIsFullScreen(false)}
                            hidePathSelector={attackPathGraphData.graph.paths.length <= 1}
                            singlePathMode={attackPathGraphData.graph.paths.length === 1}
                            defaultSelectedPath="1"
                            title="Query Results"
                            className="h-full"
                        />
                    </div>
                </div>
            )}
        </>
    );
};

// Markdown content renderer
const MarkdownContent: React.FC<{ content: string; onCopy: (text: string) => void }> = ({ content, onCopy }) => (
    <div className="prose prose-invert max-w-none">
        <ReactMarkdown
            components={{
                h1: ({ children, ...props }: any) => (
                    <h1 className="text-xl font-semibold text-[#c9d1d9] mt-6 mb-4" {...props}>{children}</h1>
                ),
                h2: ({ children, ...props }: any) => (
                    <h2 className="text-lg font-semibold text-[#c9d1d9] mt-6 mb-3" {...props}>{children}</h2>
                ),
                h3: ({ children, ...props }: any) => (
                    <h3 className="text-base font-semibold text-[#c9d1d9] mt-4 mb-2" {...props}>{children}</h3>
                ),
                p: ({ children, ...props }: any) => (
                    <p className="text-[#c9d1d9] mb-4 leading-relaxed text-[15px]" {...props}>{children}</p>
                ),
                ul: ({ ...props }: any) => (
                    <ul className="mb-4 space-y-1 text-[15px] list-disc list-inside" {...props} />
                ),
                ol: ({ ...props }: any) => (
                    <ol className="mb-4 space-y-1 list-decimal list-inside text-[15px]" {...props} />
                ),
                li: ({ children, ...props }: any) => (
                    <li className="text-[#c9d1d9] leading-relaxed" {...props}>
                        {children}
                    </li>
                ),
                code: ({ inline, className, children, ...props }: any) => {
                    if (inline) {
                        return (
                            <code className="bg-[#21262d] px-1.5 py-0.5 rounded text-[#388bfd] text-sm font-mono" {...props}>
                                {children}
                            </code>
                        );
                    }
                    const match = /language-(\w+)/.exec(className || '');
                    const language = match ? match[1] : 'text';
                    return (
                        <div className="my-4 rounded-lg overflow-hidden border border-[#30363d]">
                            <div className="bg-[#161b22] px-4 py-2 border-b border-[#30363d] flex items-center justify-between">
                                <span className="text-xs font-mono text-[#8b949e]">{language}</span>
                                <button
                                    onClick={() => onCopy(String(children))}
                                    className="text-[#8b949e] hover:text-[#c9d1d9] transition-colors"
                                    title="Copy code"
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                    </svg>
                                </button>
                            </div>
                            <SyntaxHighlighter
                                language={language}
                                style={vscDarkPlus}
                                customStyle={{
                                    margin: 0,
                                    padding: '1rem',
                                    backgroundColor: '#010409',
                                    fontSize: '0.875rem',
                                }}
                                wrapLongLines={true}
                            >
                                {String(children).replace(/\n$/, '')}
                            </SyntaxHighlighter>
                        </div>
                    );
                },
                strong: ({ children, ...props }: any) => (
                    <strong className="text-[#c9d1d9] font-semibold" {...props}>{children}</strong>
                ),
                a: ({ children, href, ...props }: any) => (
                    <a href={href} className="text-[#388bfd] hover:text-[#58a6ff] hover:underline" target="_blank" rel="noopener noreferrer" {...props}>
                        {children}
                    </a>
                ),
                blockquote: ({ children, ...props }: any) => (
                    <blockquote className="border-l-2 border-[#30363d] pl-4 my-4 italic text-[#8b949e]" {...props}>
                        {children}
                    </blockquote>
                ),
                hr: () => (
                    <hr className="my-6 border-t border-[#30363d]" />
                ),
            }}
        >
            {content}
        </ReactMarkdown>
    </div>
);

// Copy Response Button - copies entire response as JSON for review/debugging
const CopyResponseButton: React.FC<{ response: QueryResponse }> = ({ response }) => {
    const [copied, setCopied] = React.useState(false);

    const handleCopyResponse = () => {
        // Create a clean JSON representation for review
        const reviewData = {
            query_type: response.query_type,
            cypher_query: response.cypher_query,
            result_count: response.result_count,
            explanation: response.explanation,
            understanding: response.understanding,
            attack_steps: response.attack_steps?.map(step => ({
                step_number: step.step_number,
                title: step.title,
                category: step.category,
                objective: step.objective,
                prerequisites: step.prerequisites,
                opsec_options: step.opsec_options?.map(opt => ({
                    opsec_level: opt.opsec_level,
                    tool_name: opt.tool_name,
                    command: opt.command,
                    explanation: opt.explanation
                }))
            })),
            remediation: response.remediation,
            // Exclude large data like results and graph_data to keep it readable
        };

        const jsonStr = JSON.stringify(reviewData, null, 2);
        navigator.clipboard.writeText(jsonStr);
        setCopied(true);
        toast.success('Response copied as JSON');
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div className="mt-6 pt-4 border-t border-[#30363d]">
            <button
                onClick={handleCopyResponse}
                className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-[#8b949e] hover:text-[#c9d1d9] bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] rounded-md transition-colors"
            >
                {copied ? (
                    <>
                        <svg className="w-4 h-4 text-[#238636]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                        Copied!
                    </>
                ) : (
                    <>
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                        Copy Response JSON
                    </>
                )}
            </button>
        </div>
    );
};

export default NormalResponseView;

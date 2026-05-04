/**
 * AttackPathGraph - React Flow-based Attack Path Visualization
 * Location: src/components/AttackPathGraph.tsx
 *
 * Replaced Cytoscape with React Flow for cleaner SVG-based visualization.
 * Uses dagre for automatic hierarchical layout.
 *
 * PERFORMANCE OPTIMIZATIONS:
 * - Intersection Observer for lazy rendering (only render when visible)
 * - Lightweight placeholder when not in viewport
 * - Memoized layout calculations
 * - Reduced animations when multiple graphs present
 */

import React, { useEffect, useRef, useState, useImperativeHandle, forwardRef, useCallback, useMemo } from 'react';
import { API_URL } from '../config/api';
import ReactFlow, {
    Node,
    Edge,
    Controls,
    Background,
    BackgroundVariant,
    useNodesState,
    useEdgesState,
    useReactFlow,
    ReactFlowProvider,
    MarkerType,
    Panel,
} from 'reactflow';
import dagre from 'dagre';
import 'reactflow/dist/style.css';

import { nodeTypes, AttackNodeData } from './graph-components/NodeTypes';
import { edgeTypes, AttackEdgeData } from './graph-components/EdgeTypes';

// Layout cache to avoid recalculating for same data
const layoutCache = new Map<string, { nodes: Node[]; edges: Edge[] }>();

// Custom hook for Intersection Observer (lazy loading)
const useIntersectionObserver = () => {
    const [hasBeenVisible, setHasBeenVisible] = useState(false);
    const elementRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const element = elementRef.current;
        if (!element || hasBeenVisible) return; // Don't observe if already visible

        const observer = new IntersectionObserver(
            ([entry]) => {
                if (entry.isIntersecting) {
                    setHasBeenVisible(true);
                    observer.disconnect(); // Stop observing once visible
                }
            },
            {
                threshold: 0, // Trigger as soon as any part is visible
                rootMargin: '50px', // Start loading 50px before entering viewport
            }
        );

        observer.observe(element);

        return () => {
            observer.disconnect();
        };
    }, [hasBeenVisible]);

    return { elementRef, hasBeenVisible };
};

// Type definitions
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

interface AttackPathGraphProps {
    analysisId: string;
    isExpanded?: boolean;
    onClose?: () => void;
    onNodeClick?: (node: GraphNode) => void;
    onEdgeClick?: (edge: GraphEdge) => void;
    className?: string;
    defaultSelectedPath?: string;
    hidePathSelector?: boolean;
    singlePathMode?: boolean;
    graphData?: GraphData | null;
    onOpenFullScreen?: () => void;
    title?: string;
    /** Skip lazy loading (always render immediately) */
    skipLazyLoad?: boolean;
}

export interface AttackPathGraphRef {
    resetView: () => void;
}

const NODE_WIDTH = 160;
const NODE_HEIGHT = 60;

// Layout options
type LayoutDirection = 'LR' | 'TB' | 'RL' | 'BT';

// Generate cache key for layout
const getLayoutCacheKey = (nodes: Node[], edges: Edge[], direction: LayoutDirection): string => {
    const nodeIds = nodes.map(n => n.id).sort().join(',');
    const edgeIds = edges.map(e => `${e.source}-${e.target}`).sort().join(',');
    return `${nodeIds}|${edgeIds}|${direction}`;
};

const getLayoutedElements = (
    nodes: Node[],
    edges: Edge[],
    direction: LayoutDirection = 'LR'
): { nodes: Node[]; edges: Edge[] } => {
    // Check cache first
    const cacheKey = getLayoutCacheKey(nodes, edges, direction);
    const cached = layoutCache.get(cacheKey);
    if (cached) {
        return cached;
    }

    // Create new dagre graph for each layout (avoid global state issues)
    const dagreGraph = new dagre.graphlib.Graph();
    dagreGraph.setDefaultEdgeLabel(() => ({}));

    const isHorizontal = direction === 'LR' || direction === 'RL';

    dagreGraph.setGraph({
        rankdir: direction,
        nodesep: 80,
        ranksep: 120,
        marginx: 50,
        marginy: 50,
    });

    nodes.forEach((node) => {
        dagreGraph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
    });

    edges.forEach((edge) => {
        dagreGraph.setEdge(edge.source, edge.target);
    });

    dagre.layout(dagreGraph);

    const layoutedNodes = nodes.map((node) => {
        const nodeWithPosition = dagreGraph.node(node.id);
        return {
            ...node,
            position: {
                x: nodeWithPosition.x - NODE_WIDTH / 2,
                y: nodeWithPosition.y - NODE_HEIGHT / 2,
            },
            sourcePosition: isHorizontal ? 'right' : 'bottom',
            targetPosition: isHorizontal ? 'left' : 'top',
        } as Node;
    });

    const result = { nodes: layoutedNodes, edges };

    // Cache the result (limit cache size to prevent memory issues)
    if (layoutCache.size > 50) {
        const firstKey = layoutCache.keys().next().value;
        if (firstKey) layoutCache.delete(firstKey);
    }
    layoutCache.set(cacheKey, result);

    return result;
};

// Lightweight placeholder component (shown when graph is not visible)
const GraphPlaceholder: React.FC<{
    nodeCount: number;
    edgeCount: number;
    isExpanded?: boolean;
}> = ({ nodeCount, edgeCount, isExpanded = false }) => (
    <div className="flex flex-col" style={{ minHeight: isExpanded ? '400px' : '300px' }}>
        {/* Header placeholder */}
        <div className={`bg-[#161b22] border border-[#30363d] ${isExpanded ? 'rounded-t-xl' : 'rounded-t-lg'} px-4 py-2`}>
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <div className="w-24 h-7 bg-[#21262d] rounded animate-pulse" />
                    <div className="w-28 h-7 bg-[#21262d] rounded animate-pulse" />
                </div>
                <div className="flex items-center gap-1">
                    <div className="w-8 h-8 bg-[#21262d] rounded animate-pulse" />
                </div>
            </div>
        </div>

        {/* Graph placeholder area */}
        <div className="flex-1 border-x border-[#30363d] bg-[#0d1117] flex items-center justify-center" style={{ minHeight: isExpanded ? '300px' : '200px' }}>
            <div className="text-center">
                {/* Graph icon */}
                <div className="w-16 h-16 mx-auto mb-4 rounded-xl bg-[#161b22] border border-[#30363d] flex items-center justify-center">
                    <svg className="w-8 h-8 text-[#58a6ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                    </svg>
                </div>

                {/* Stats */}
                <div className="flex items-center justify-center gap-4 mb-3">
                    <div className="flex items-center gap-1.5">
                        <div className="w-2 h-2 rounded-full bg-[#58a6ff]" />
                        <span className="text-sm text-[#c9d1d9] font-medium">{nodeCount}</span>
                        <span className="text-xs text-[#8b949e]">nodes</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                        <div className="w-3 h-0.5 bg-[#f85149]" />
                        <span className="text-sm text-[#c9d1d9] font-medium">{edgeCount}</span>
                        <span className="text-xs text-[#8b949e]">edges</span>
                    </div>
                </div>

                {/* Loading text */}
                <p className="text-xs text-[#8b949e]">Scroll to load interactive graph</p>
            </div>
        </div>

        {/* Footer placeholder */}
        <div className="flex items-center gap-6 px-4 py-2 bg-[#161b22] border border-[#30363d] border-t-0 rounded-b-lg">
            <div className="flex items-center gap-2">
                <div className="w-2.5 h-2.5 rounded-full bg-[#58a6ff]" />
                <span className="text-sm text-[#c9d1d9] font-medium">{nodeCount}</span>
                <span className="text-xs text-[#8b949e]">nodes</span>
            </div>
            <div className="flex items-center gap-2">
                <div className="w-4 h-0.5 bg-[#f85149]" />
                <span className="text-sm text-[#c9d1d9] font-medium">{edgeCount}</span>
                <span className="text-xs text-[#8b949e]">edges</span>
            </div>
        </div>
    </div>
);

// Convert backend graph data to React Flow format
const convertToReactFlowFormat = (
    graphData: GraphData,
    selectedPath: string
): { nodes: Node<AttackNodeData>[]; edges: Edge<AttackEdgeData>[] } => {
    const { nodes: graphNodes, edges: graphEdges } = graphData.graph;

    // Filter by selected path if not 'all'
    // Note: With per-finding graphs, each graph only contains edges for that finding
    let filteredNodes = graphNodes || [];
    let filteredEdges = graphEdges || [];

    if (selectedPath !== 'all' && graphEdges?.length > 0) {
        const pathIndex = parseInt(selectedPath) - 1;
        filteredEdges = graphEdges.filter((e) => e.pathIndex === pathIndex);

        // If no edges match the pathIndex filter, use all edges (per-finding graph case)
        if (filteredEdges.length === 0) {
            filteredEdges = graphEdges;
        }

        // Get unique node IDs from filtered edges
        const nodeIds = new Set<string>();
        filteredEdges.forEach((e) => {
            nodeIds.add(e.source);
            nodeIds.add(e.target);
        });

        filteredNodes = graphNodes.filter((n) => nodeIds.has(n.id));
    }

    // Convert nodes
    const nodes: Node<AttackNodeData>[] = filteredNodes.map((node) => ({
        id: node.id,
        type: 'attackNode',
        position: { x: 0, y: 0 }, // Will be set by dagre
        data: {
            label: node.label || node.name,
            type: node.type,
            riskLevel: node.riskLevel,
        },
    }));

    // Track edges between same node pairs for offset calculation
    const edgePairCounts = new Map<string, number>();
    const edgePairIndices = new Map<string, number>();

    // First pass: count edges between each node pair
    filteredEdges.forEach((edge) => {
        const pairKey = `${edge.source}->${edge.target}`;
        edgePairCounts.set(pairKey, (edgePairCounts.get(pairKey) || 0) + 1);
    });

    // Convert edges
    const edges: Edge<AttackEdgeData>[] = filteredEdges.map((edge) => {
        const pairKey = `${edge.source}->${edge.target}`;
        const totalEdgesBetween = edgePairCounts.get(pairKey) || 1;
        const currentIndex = edgePairIndices.get(pairKey) || 0;
        edgePairIndices.set(pairKey, currentIndex + 1);

        return {
            id: edge.id,
            source: edge.source,
            target: edge.target,
            type: 'attackEdge',
            animated: false, // Disabled for performance
            data: {
                label: edge.label || edge.type,
                type: edge.type,
                riskLevel: edge.riskLevel,
                attackType: edge.attack_type,
                description: edge.description,
                // Add edge index info for offset calculation
                edgeIndex: currentIndex,
                totalEdgesBetween,
            },
            markerEnd: {
                type: MarkerType.ArrowClosed,
                width: 20,
                height: 20,
                color: getMarkerColor(edge.type, edge.riskLevel),
            },
        };
    });

    return { nodes, edges };
};

// Get marker color based on edge type/risk
const getMarkerColor = (type: string, riskLevel?: string): string => {
    if (riskLevel === 'Critical') return '#ef4444';
    if (riskLevel === 'High') return '#f97316';

    const dangerous = ['GENERICALL', 'WRITEDACL', 'WRITEOWNER', 'OWNS', 'DCSYNC'];
    if (dangerous.includes(type.toUpperCase())) return '#ef4444';

    return '#6b7280';
};

// Inner component with React Flow hooks
const AttackPathGraphInner = forwardRef<AttackPathGraphRef, AttackPathGraphProps & { graphData: GraphData }>(
    (
        {
            graphData,
            isExpanded = false,
            onClose,
            onNodeClick,
            onEdgeClick,
            className = '',
            defaultSelectedPath,
            hidePathSelector = false,
            singlePathMode = false,
            onOpenFullScreen,
            title,
        },
        ref
    ) => {
        const [selectedPath, setSelectedPath] = useState<string>(defaultSelectedPath || 'all');
        const [layoutDirection, setLayoutDirection] = useState<LayoutDirection>('LR');
        const [focusedNodeId, setFocusedNodeId] = useState<string | null>(null);
        const { fitView } = useReactFlow();

        // Convert and layout graph data (memoized)
        const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
            const { nodes, edges } = convertToReactFlowFormat(graphData, selectedPath);
            return getLayoutedElements(nodes, edges, layoutDirection);
        }, [graphData, selectedPath, layoutDirection]);

        const [nodes, setNodesState, onNodesChange] = useNodesState(initialNodes);
        const [edges, setEdgesState, onEdgesChange] = useEdgesState(initialEdges);

        // Apply highlight/dim based on focused node
        useEffect(() => {
            if (!focusedNodeId) {
                // Clear all highlighting - reset to normal state
                setNodesState((nds) =>
                    nds.map((node) => ({
                        ...node,
                        data: { ...node.data, isHighlighted: false, isDimmed: false },
                    }))
                );
                setEdgesState((eds) =>
                    eds.map((edge) => ({
                        ...edge,
                        data: { ...edge.data, isHighlighted: false, isDimmed: false },
                    }))
                );
                return;
            }

            // Compute connected nodes and edges, then update both states
            setEdgesState((currentEdges) => {
                // Find connected nodes (nodes that have edges to/from the focused node)
                const connectedNodeIds = new Set<string>([focusedNodeId]);
                const connectedEdgeIds = new Set<string>();

                currentEdges.forEach((edge) => {
                    if (edge.source === focusedNodeId || edge.target === focusedNodeId) {
                        connectedNodeIds.add(edge.source);
                        connectedNodeIds.add(edge.target);
                        connectedEdgeIds.add(edge.id);
                    }
                });

                // Update nodes with the connected info
                setNodesState((nds) =>
                    nds.map((node) => ({
                        ...node,
                        data: {
                            ...node.data,
                            isHighlighted: node.id === focusedNodeId,
                            isDimmed: !connectedNodeIds.has(node.id),
                        },
                    }))
                );

                // Return updated edges
                return currentEdges.map((edge) => ({
                    ...edge,
                    data: {
                        ...edge.data,
                        isHighlighted: connectedEdgeIds.has(edge.id),
                        isDimmed: !connectedEdgeIds.has(edge.id),
                    },
                }));
            });
        }, [focusedNodeId, setNodesState, setEdgesState]);

        // Fit view on initial mount (important for lazy-loaded graphs)
        useEffect(() => {
            const timer = setTimeout(() => {
                fitView({ padding: 0.2, duration: 300 });
            }, 50);
            return () => clearTimeout(timer);
            // eslint-disable-next-line react-hooks/exhaustive-deps
        }, []); // Only run once on mount

        // Update nodes/edges when selection changes
        useEffect(() => {
            const { nodes: newNodes, edges: newEdges } = convertToReactFlowFormat(graphData, selectedPath);
            const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
                newNodes,
                newEdges,
                layoutDirection
            );
            setNodesState(layoutedNodes);
            setEdgesState(layoutedEdges);

            // Clear focus when path or layout changes
            setFocusedNodeId(null);

            // Fit view after layout
            setTimeout(() => fitView({ padding: 0.2, duration: 500 }), 100);
        }, [selectedPath, layoutDirection, graphData, setNodesState, setEdgesState, fitView]);

        // Update selectedPath when defaultSelectedPath changes
        useEffect(() => {
            if (defaultSelectedPath) {
                setSelectedPath(defaultSelectedPath);
            }
        }, [defaultSelectedPath]);

        // Reset view function
        const resetView = useCallback(() => {
            fitView({ padding: 0.2, duration: 500 });
        }, [fitView]);

        // Expose resetView via ref
        useImperativeHandle(ref, () => ({ resetView }), [resetView]);

        // Handle node click - toggle focus on the clicked node
        const handleNodeClick = useCallback(
            (_: React.MouseEvent, node: Node) => {
                // Toggle focus: if clicking the same node, clear focus; otherwise focus on this node
                setFocusedNodeId((prevId) => (prevId === node.id ? null : node.id));

                // Also call the external onNodeClick handler if provided
                if (onNodeClick) {
                    const originalNode = graphData.graph.nodes.find((n) => n.id === node.id);
                    if (originalNode) onNodeClick(originalNode);
                }
            },
            [graphData, onNodeClick]
        );

        // Handle pane click - clear focus when clicking on empty space
        const handlePaneClick = useCallback(() => {
            setFocusedNodeId(null);
        }, []);

        // Handle edge click
        const handleEdgeClick = useCallback(
            (_: React.MouseEvent, edge: Edge) => {
                if (onEdgeClick) {
                    const originalEdge = graphData.graph.edges.find((e) => e.id === edge.id);
                    if (originalEdge) onEdgeClick(originalEdge);
                }
            },
            [graphData, onEdgeClick]
        );

        return (
            <div className={`flex flex-col h-full ${className}`}>
                {/* Graph Header Bar */}
                <div
                    className={`bg-[#161b22] border border-[#30363d] ${isExpanded ? 'rounded-t-xl' : 'rounded-t-lg'}`}
                >
                    {isExpanded ? (
                        <>
                            {/* Row 1: Title + Action buttons */}
                            <div className="flex items-center justify-between px-3 py-2 border-b border-[#30363d]">
                                <h2 className="text-base font-semibold text-white">
                                    {title || 'Attack Path Graph'}
                                </h2>
                                <div className="flex items-center gap-1">
                                    <button
                                        onClick={resetView}
                                        className="p-1.5 rounded-lg text-gray-400 hover:text-[#58a6ff] hover:bg-[#21262d] transition-colors"
                                        title="Reset view"
                                    >
                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                                strokeWidth={2}
                                                d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                                            />
                                        </svg>
                                    </button>
                                    {onClose && (
                                        <button
                                            onClick={onClose}
                                            className="p-1.5 rounded-lg text-gray-400 hover:text-red-400 hover:bg-[#21262d] transition-colors"
                                            title="Close"
                                        >
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path
                                                    strokeLinecap="round"
                                                    strokeLinejoin="round"
                                                    strokeWidth={2}
                                                    d="M6 18L18 6M6 6l12 12"
                                                />
                                            </svg>
                                        </button>
                                    )}
                                </div>
                            </div>
                            {/* Row 2: Layout controls */}
                            <div className="flex items-center gap-2 px-3 pt-1.5 pb-2.5">
                                {!hidePathSelector && (
                                    <select
                                        value={selectedPath}
                                        onChange={(e) => setSelectedPath(e.target.value)}
                                        className="pl-3 pr-8 py-1.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white focus:outline-none focus:border-[#58a6ff] transition-colors"
                                    >
                                        {!singlePathMode && <option value="all">All Paths</option>}
                                        {graphData.graph.paths.map((path) => (
                                            <option key={path.id} value={path.scenario_number.toString()}>
                                                {singlePathMode
                                                    ? `Path ${path.scenario_number}`
                                                    : `Path ${path.scenario_number}: ${path.name}`}
                                            </option>
                                        ))}
                                    </select>
                                )}
                                <select
                                    value={layoutDirection}
                                    onChange={(e) => setLayoutDirection(e.target.value as LayoutDirection)}
                                    className="pl-3 pr-8 py-1.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white focus:outline-none focus:border-[#58a6ff] transition-colors"
                                >
                                    <option value="LR">Left to Right</option>
                                    <option value="TB">Top to Bottom</option>
                                    <option value="RL">Right to Left</option>
                                    <option value="BT">Bottom to Top</option>
                                </select>
                            </div>
                        </>
                    ) : (
                        /* Normal: Single-row header */
                        <div className="flex items-center justify-between px-4 py-2">
                            <div className="flex items-center gap-2">
                                {!hidePathSelector && (
                                    <select
                                        value={selectedPath}
                                        onChange={(e) => setSelectedPath(e.target.value)}
                                        className="pl-3 pr-8 py-1.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white focus:outline-none focus:border-[#58a6ff] transition-colors"
                                    >
                                        {!singlePathMode && <option value="all">All Paths</option>}
                                        {graphData.graph.paths.map((path) => (
                                            <option key={path.id} value={path.scenario_number.toString()}>
                                                {singlePathMode
                                                    ? `Path ${path.scenario_number}`
                                                    : `Path ${path.scenario_number}: ${path.name}`}
                                            </option>
                                        ))}
                                    </select>
                                )}
                                <select
                                    value={layoutDirection}
                                    onChange={(e) => setLayoutDirection(e.target.value as LayoutDirection)}
                                    className="pl-3 pr-8 py-1.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-sm text-white focus:outline-none focus:border-[#58a6ff] transition-colors"
                                >
                                    <option value="LR">Left to Right</option>
                                    <option value="TB">Top to Bottom</option>
                                </select>
                            </div>
                            <div className="flex items-center gap-1">
                                {onOpenFullScreen && (
                                    <button
                                        onClick={onOpenFullScreen}
                                        className="p-2 rounded-lg text-gray-400 hover:text-[#58a6ff] hover:bg-[#21262d] transition-colors"
                                        title="Open full view"
                                    >
                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path
                                                strokeLinecap="round"
                                                strokeLinejoin="round"
                                                strokeWidth={2}
                                                d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"
                                            />
                                        </svg>
                                    </button>
                                )}
                                <button
                                    onClick={resetView}
                                    className="p-2 rounded-lg text-gray-400 hover:text-[#58a6ff] hover:bg-[#21262d] transition-colors"
                                    title="Reset view"
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
                                        />
                                    </svg>
                                </button>
                            </div>
                        </div>
                    )}
                </div>

                {/* React Flow Container */}
                <div className="relative flex-1 min-h-0 border-x border-[#30363d] overflow-hidden">
                    <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        onNodesChange={onNodesChange}
                        onEdgesChange={onEdgesChange}
                        onNodeClick={handleNodeClick}
                        onEdgeClick={handleEdgeClick}
                        onPaneClick={handlePaneClick}
                        nodeTypes={nodeTypes}
                        edgeTypes={edgeTypes}
                        fitView
                        fitViewOptions={{ padding: 0.2 }}
                        minZoom={0.1}
                        maxZoom={2}
                        defaultEdgeOptions={{
                            type: 'attackEdge',
                        }}
                        proOptions={{ hideAttribution: true }}
                        style={{ backgroundColor: '#0d1117' }}
                    >
                        <Background
                            variant={BackgroundVariant.Dots}
                            gap={20}
                            size={1}
                            color="#21262d"
                        />
                        <Controls
                            showInteractive={false}
                            className="!bg-[#161b22] !border-[#30363d] !rounded-lg !shadow-lg"
                        />

                        {/* Legend Panel */}
                        <Panel position="bottom-left" className="!m-3">
                            <div className="bg-[#161b22]/95 border border-[#30363d] rounded-lg p-3 shadow-xl backdrop-blur-sm">
                                <div className="text-xs text-gray-400 space-y-2.5">
                                    <div className="font-semibold text-gray-300 mb-2">Legend</div>
                                    {/* User */}
                                    <div className="flex items-center gap-2">
                                        <div className="w-6 h-6 rounded bg-gradient-to-br from-[#1e3a5f] to-[#1e293b] border border-[#3b82f6] flex items-center justify-center">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#60a5fa" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                                                <circle cx="12" cy="7" r="4" />
                                            </svg>
                                        </div>
                                        <span>Users</span>
                                    </div>
                                    {/* Group */}
                                    <div className="flex items-center gap-2">
                                        <div className="w-6 h-6 rounded bg-gradient-to-br from-[#14532d] to-[#1e293b] border border-[#22c55e] flex items-center justify-center">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#4ade80" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                                                <circle cx="9" cy="7" r="4" />
                                                <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                                                <path d="M16 3.13a4 4 0 0 1 0 7.75" />
                                            </svg>
                                        </div>
                                        <span>Groups</span>
                                    </div>
                                    {/* Computer */}
                                    <div className="flex items-center gap-2">
                                        <div className="w-6 h-6 rounded bg-gradient-to-br from-[#7f1d1d] to-[#1e293b] border border-[#ef4444] flex items-center justify-center">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f87171" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                                                <line x1="8" y1="21" x2="16" y2="21" />
                                                <line x1="12" y1="17" x2="12" y2="21" />
                                            </svg>
                                        </div>
                                        <span>Computers</span>
                                    </div>
                                    {/* Domain */}
                                    <div className="flex items-center gap-2">
                                        <div className="w-6 h-6 rounded bg-gradient-to-br from-[#581c87] to-[#1e293b] border border-[#a855f7] flex items-center justify-center">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#c084fc" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                <circle cx="12" cy="12" r="10" />
                                                <line x1="2" y1="12" x2="22" y2="12" />
                                                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                                            </svg>
                                        </div>
                                        <span>Domains</span>
                                    </div>
                                    {/* GPO */}
                                    <div className="flex items-center gap-2">
                                        <div className="w-6 h-6 rounded bg-gradient-to-br from-[#713f12] to-[#1e293b] border border-[#f59e0b] flex items-center justify-center">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                                                <polyline points="14 2 14 8 20 8" />
                                                <line x1="16" y1="13" x2="8" y2="13" />
                                                <line x1="16" y1="17" x2="8" y2="17" />
                                            </svg>
                                        </div>
                                        <span>GPOs</span>
                                    </div>
                                    {/* OU */}
                                    <div className="flex items-center gap-2">
                                        <div className="w-6 h-6 rounded bg-gradient-to-br from-[#164e63] to-[#1e293b] border border-[#06b6d4] flex items-center justify-center">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                                            </svg>
                                        </div>
                                        <span>OUs</span>
                                    </div>
                                    {/* Container */}
                                    <div className="flex items-center gap-2">
                                        <div className="w-6 h-6 rounded bg-gradient-to-br from-[#1e3a3a] to-[#1e293b] border border-[#14b8a6] flex items-center justify-center">
                                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2dd4bf" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
                                            </svg>
                                        </div>
                                        <span>Containers</span>
                                    </div>
                                </div>
                            </div>
                        </Panel>
                    </ReactFlow>
                </div>

                {/* Footer with node/edge counts */}
                <div className="flex items-center gap-6 px-4 py-2 bg-[#161b22] border border-[#30363d] border-t-0 rounded-b-lg">
                    <div className="flex items-center gap-2">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#58a6ff]" />
                        <span className="text-sm text-[#c9d1d9] font-medium">{nodes.length}</span>
                        <span className="text-xs text-[#8b949e]">nodes</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-4 h-0.5 bg-[#f85149]" />
                        <span className="text-sm text-[#c9d1d9] font-medium">{edges.length}</span>
                        <span className="text-xs text-[#8b949e]">edges</span>
                    </div>
                </div>
            </div>
        );
    }
);

AttackPathGraphInner.displayName = 'AttackPathGraphInner';

// Main wrapper component with loading states and lazy loading
const AttackPathGraph = forwardRef<AttackPathGraphRef, AttackPathGraphProps>(
    (props, ref) => {
        const {
            analysisId,
            graphData: embeddedGraphData,
            isExpanded = false,
            className = '',
            singlePathMode = false,
            defaultSelectedPath,
            skipLazyLoad = false,
        } = props;

        const [graphData, setGraphData] = useState<GraphData | null>(embeddedGraphData || null);
        const [loading, setLoading] = useState(!embeddedGraphData);
        const [error, setError] = useState<string | null>(null);
        const innerRef = useRef<AttackPathGraphRef>(null);

        // Intersection Observer for lazy loading
        const { elementRef, hasBeenVisible } = useIntersectionObserver();

        // Forward ref to inner component
        useImperativeHandle(ref, () => ({
            resetView: () => innerRef.current?.resetView(),
        }));

        // Use embedded data if provided, otherwise fetch
        useEffect(() => {
            if (embeddedGraphData) {
                const nodes = embeddedGraphData.graph?.nodes?.length || 0;
                const edges = embeddedGraphData.graph?.edges?.length || 0;
                console.log(`📊 [Graph] Using embedded data: ${nodes} nodes, ${edges} edges`);
                setGraphData(embeddedGraphData);
                setLoading(false);
            } else if (analysisId && analysisId !== 'unknown') {
                fetchGraphData();
            }
        }, [analysisId, singlePathMode, defaultSelectedPath, embeddedGraphData]);

        // Determine if we should render the full graph
        const shouldRenderGraph = skipLazyLoad || isExpanded || hasBeenVisible;

        const fetchGraphData = async () => {
            try {
                setLoading(true);
                setError(null);

                if (!analysisId || analysisId === 'unknown') {
                    throw new Error('Invalid analysis ID. Cannot fetch graph data.');
                }

                let url = `${API_URL}/api/attack-paths/analyze/${analysisId}/attack-paths/graph`;
                if (singlePathMode && defaultSelectedPath) {
                    const pathNum = parseInt(defaultSelectedPath);
                    if (!isNaN(pathNum)) {
                        url += `?path_number=${pathNum}`;
                    }
                }

                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 30000);

                const response = await fetch(url, { signal: controller.signal });
                clearTimeout(timeoutId);

                if (!response.ok) {
                    if (response.status === 404) {
                        throw new Error(`Analysis ${analysisId} not found.`);
                    }
                    throw new Error(`Failed to fetch graph data: ${response.status}`);
                }

                const data: GraphData = await response.json();

                if (!data.graph || !data.graph.nodes || !data.graph.edges) {
                    throw new Error('Invalid graph data structure');
                }

                setGraphData(data);
            } catch (err: any) {
                console.error('❌ Error fetching graph data:', err);
                setError(err.message || 'Failed to load graph data');
            } finally {
                setLoading(false);
            }
        };

        // Loading state
        if (loading) {
            return (
                <div className={`flex items-center justify-center ${isExpanded ? 'h-96' : 'h-64'} ${className}`}>
                    <div className="text-center">
                        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#58a6ff] mx-auto mb-4"></div>
                        <p className="text-gray-300">Loading attack path graph...</p>
                    </div>
                </div>
            );
        }

        // Error state
        if (error) {
            return (
                <div className={`flex items-center justify-center ${isExpanded ? 'h-96' : 'h-64'} ${className}`}>
                    <div className="text-center">
                        <svg
                            className="w-12 h-12 text-red-400 mx-auto mb-4"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"
                            />
                        </svg>
                        <p className="text-red-300 mb-2">Failed to load graph</p>
                        <p className="text-gray-400 text-sm">{error}</p>
                        <button
                            onClick={fetchGraphData}
                            className="mt-4 px-4 py-2 bg-[#58a6ff] hover:bg-[#4A90E2] rounded text-sm transition-colors text-white"
                        >
                            Retry
                        </button>
                    </div>
                </div>
            );
        }

        // Empty state
        if (!graphData || !graphData.graph || graphData.graph.nodes.length === 0) {
            return (
                <div ref={elementRef} className={`flex items-center justify-center ${isExpanded ? 'h-96' : 'h-64'} ${className}`}>
                    <div className="text-center">
                        <svg
                            className="w-12 h-12 text-gray-400 mx-auto mb-4"
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                        >
                            <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2}
                                d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"
                            />
                        </svg>
                        <p className="text-gray-300">No attack paths to display</p>
                        <p className="text-gray-400 text-sm">The analysis didn't find any critical attack scenarios.</p>
                    </div>
                </div>
            );
        }

        // Use a single wrapper with ref for intersection observer
        // Show placeholder OR graph based on visibility
        return (
            <div
                ref={elementRef}
                className={`${className}`}
                style={{ minHeight: isExpanded ? '400px' : '300px', height: '100%' }}
            >
                {shouldRenderGraph ? (
                    <ReactFlowProvider>
                        <AttackPathGraphInner
                            ref={innerRef}
                            {...props}
                            graphData={graphData}
                        />
                    </ReactFlowProvider>
                ) : (
                    <GraphPlaceholder
                        nodeCount={graphData.graph.nodes.length}
                        edgeCount={graphData.graph.edges.length}
                        isExpanded={isExpanded}
                    />
                )}
            </div>
        );
    }
);

AttackPathGraph.displayName = 'AttackPathGraph';

export default AttackPathGraph;

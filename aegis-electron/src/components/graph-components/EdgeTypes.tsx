/**
 * Custom Edge Types for React Flow Attack Path Visualization
 * Location: src/components/graph-components/EdgeTypes.tsx
 */

import { memo } from 'react';
import { EdgeProps, getBezierPath, EdgeLabelRenderer } from 'reactflow';

// Edge data interface
export interface AttackEdgeData {
    label: string;
    type: string;
    riskLevel?: 'Critical' | 'High' | 'Medium' | 'Low';
    attackType?: string;
    description?: string;
    isHighlighted?: boolean;
    isDimmed?: boolean;
    // For handling multiple edges between same nodes
    edgeIndex?: number;
    totalEdgesBetween?: number;
}

// Edge colors based on relationship type
const getEdgeColor = (type: string, riskLevel?: string): string => {
    // Risk-based colors take priority
    if (riskLevel === 'Critical') return '#ef4444';
    if (riskLevel === 'High') return '#f97316';

    // Type-based colors
    const typeColors: Record<string, string> = {
        // Dangerous permissions
        'GENERICALL': '#ef4444',
        'WRITEDACL': '#ef4444',
        'WRITEOWNER': '#ef4444',
        'OWNS': '#ef4444',
        'DCSYNC': '#ef4444',
        'GETCHANGES': '#ef4444',
        'GETCHANGESALL': '#ef4444',

        // Moderate risk
        'GENERICWRITE': '#f97316',
        'ADDMEMBER': '#f97316',
        'FORCECHANGEPASSWORD': '#f97316',
        'ALLEXTENDEDRIGHTS': '#f97316',

        // Group membership
        'MEMBEROF': '#3b82f6',

        // Admin relationships
        'ADMINTO': '#a855f7',
        'CANRDP': '#a855f7',
        'CANPSREMOTE': '#a855f7',
        'EXECUTEDCOM': '#a855f7',

        // Session/logon
        'HASSESSION': '#22c55e',

        // Default
        'default': '#6b7280',
    };

    return typeColors[type.toUpperCase()] || typeColors['default'];
};

// Get label background color based on edge type
const getLabelBgColor = (type: string): string => {
    const dangerous = ['GENERICALL', 'WRITEDACL', 'WRITEOWNER', 'OWNS', 'DCSYNC', 'GETCHANGES', 'GETCHANGESALL'];
    const moderate = ['GENERICWRITE', 'ADDMEMBER', 'FORCECHANGEPASSWORD', 'ALLEXTENDEDRIGHTS'];

    if (dangerous.includes(type.toUpperCase())) return 'bg-red-900/90';
    if (moderate.includes(type.toUpperCase())) return 'bg-orange-900/90';
    if (type.toUpperCase() === 'MEMBEROF') return 'bg-blue-900/90';
    return 'bg-gray-800/90';
};

// Calculate offset for multiple edges between same nodes
const calculateEdgeOffset = (
    edgeIndex: number,
    totalEdges: number,
    sourceX: number,
    sourceY: number,
    targetX: number,
    targetY: number
): { offsetX: number; offsetY: number; curvature: number } => {
    if (totalEdges <= 1) {
        return { offsetX: 0, offsetY: 0, curvature: 0.25 };
    }

    // Calculate perpendicular offset direction
    const dx = targetX - sourceX;
    const dy = targetY - sourceY;
    const len = Math.sqrt(dx * dx + dy * dy) || 1;

    // Perpendicular unit vector
    const perpX = -dy / len;
    const perpY = dx / len;

    // Spread edges evenly around the center
    // For 2 edges: offsets of -25, +25
    // For 3 edges: offsets of -35, 0, +35
    // For 4 edges: offsets of -45, -15, +15, +45
    const spacing = 35; // Base spacing between edges
    const centerIndex = (totalEdges - 1) / 2;
    const offsetMultiplier = (edgeIndex - centerIndex) * spacing;

    // Also vary the curvature for visual distinction
    const baseCurvature = 0.25;
    const curvatureVariation = (edgeIndex - centerIndex) * 0.15;

    return {
        offsetX: perpX * offsetMultiplier,
        offsetY: perpY * offsetMultiplier,
        curvature: baseCurvature + curvatureVariation,
    };
};

// Custom Attack Edge component
const AttackEdge = memo(({
    id,
    sourceX,
    sourceY,
    targetX,
    targetY,
    sourcePosition,
    targetPosition,
    data,
    selected,
    markerEnd,
}: EdgeProps<AttackEdgeData>) => {
    // Calculate offset for multiple edges between same nodes
    const edgeIndex = data?.edgeIndex ?? 0;
    const totalEdges = data?.totalEdgesBetween ?? 1;
    const { offsetX, offsetY, curvature } = calculateEdgeOffset(
        edgeIndex,
        totalEdges,
        sourceX,
        sourceY,
        targetX,
        targetY
    );

    // Apply offset to source and target positions
    const adjustedSourceX = sourceX + offsetX * 0.3;
    const adjustedSourceY = sourceY + offsetY * 0.3;
    const adjustedTargetX = targetX + offsetX * 0.3;
    const adjustedTargetY = targetY + offsetY * 0.3;

    const [edgePath, labelX, labelY] = getBezierPath({
        sourceX: adjustedSourceX,
        sourceY: adjustedSourceY,
        sourcePosition,
        targetX: adjustedTargetX,
        targetY: adjustedTargetY,
        targetPosition,
        curvature: curvature,
    });

    // Adjust label position based on offset
    const adjustedLabelX = labelX + offsetX * 0.5;
    const adjustedLabelY = labelY + offsetY * 0.5;

    const edgeColor = getEdgeColor(data?.type || '', data?.riskLevel);
    const isHighlighted = selected || data?.isHighlighted;
    const isDimmed = data?.isDimmed;
    const labelBgColor = getLabelBgColor(data?.type || '');

    return (
        <>
            {/* Edge path - shadow for glow effect when highlighted */}
            {isHighlighted && (
                <path
                    d={edgePath}
                    fill="none"
                    stroke={edgeColor}
                    strokeWidth={6}
                    strokeOpacity={0.3}
                    className="react-flow__edge-path"
                />
            )}

            {/* Main edge path */}
            <path
                id={id}
                d={edgePath}
                fill="none"
                stroke={edgeColor}
                strokeWidth={isHighlighted ? 3 : 2}
                strokeOpacity={isDimmed ? 0.2 : 1}
                className="react-flow__edge-path transition-all duration-200"
                markerEnd={markerEnd}
            />


            {/* Edge label */}
            <EdgeLabelRenderer>
                <div
                    style={{
                        position: 'absolute',
                        transform: `translate(-50%, -50%) translate(${adjustedLabelX}px, ${adjustedLabelY}px)`,
                        pointerEvents: 'all',
                    }}
                    className={`
                        px-2 py-0.5 rounded text-xs font-medium
                        ${labelBgColor}
                        text-white
                        border border-white/20
                        shadow-lg
                        transition-opacity duration-200
                        ${isDimmed ? 'opacity-20' : 'opacity-100'}
                        ${isHighlighted ? 'ring-2 ring-yellow-400 border-yellow-400' : ''}
                        cursor-pointer
                        whitespace-nowrap
                    `}
                    title={data?.description || data?.label}
                >
                    {data?.label || data?.type || 'RELATED'}
                </div>
            </EdgeLabelRenderer>
        </>
    );
});

AttackEdge.displayName = 'AttackEdge';

// Export edge types for React Flow
export const edgeTypes = {
    attackEdge: AttackEdge,
};

export default AttackEdge;

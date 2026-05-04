/**
 * Custom Node Types for React Flow Attack Path Visualization
 * Location: src/components/graph-components/NodeTypes.tsx
 */

import { memo, useState } from 'react';
import { Handle, Position, NodeProps } from 'reactflow';

// Node data interface
export interface AttackNodeData {
    label: string;
    type: 'User' | 'Group' | 'Computer' | 'Domain' | 'GPO' | 'OU' | 'Unknown';
    riskLevel?: 'Critical' | 'High' | 'Medium' | 'Low';
    isHighlighted?: boolean;
    isDimmed?: boolean;
}

// Color schemes for each node type
const nodeStyles = {
    User: {
        bg: 'bg-[#1e3a5f]',
        border: 'border-[#3b82f6]',
        iconColor: '#60a5fa',
        gradient: 'from-[#1e3a5f] to-[#1e293b]',
    },
    Group: {
        bg: 'bg-[#14532d]',
        border: 'border-[#22c55e]',
        iconColor: '#4ade80',
        gradient: 'from-[#14532d] to-[#1e293b]',
    },
    Computer: {
        bg: 'bg-[#7f1d1d]',
        border: 'border-[#ef4444]',
        iconColor: '#f87171',
        gradient: 'from-[#7f1d1d] to-[#1e293b]',
    },
    Domain: {
        bg: 'bg-[#581c87]',
        border: 'border-[#a855f7]',
        iconColor: '#c084fc',
        gradient: 'from-[#581c87] to-[#1e293b]',
    },
    GPO: {
        bg: 'bg-[#713f12]',
        border: 'border-[#f59e0b]',
        iconColor: '#fbbf24',
        gradient: 'from-[#713f12] to-[#1e293b]',
    },
    OU: {
        bg: 'bg-[#164e63]',
        border: 'border-[#06b6d4]',
        iconColor: '#22d3ee',
        gradient: 'from-[#164e63] to-[#1e293b]',
    },
    Container: {
        bg: 'bg-[#1e3a3a]',
        border: 'border-[#14b8a6]',
        iconColor: '#2dd4bf',
        gradient: 'from-[#1e3a3a] to-[#1e293b]',
    },
    Unknown: {
        bg: 'bg-[#374151]',
        border: 'border-[#6b7280]',
        iconColor: '#9ca3af',
        gradient: 'from-[#374151] to-[#1e293b]',
    },
};

// SVG Icons for each node type
const UserIcon = ({ color }: { color: string }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
        <circle cx="12" cy="7" r="4" />
    </svg>
);

const GroupIcon = ({ color }: { color: string }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
        <circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
        <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
);

const ComputerIcon = ({ color }: { color: string }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
        <line x1="8" y1="21" x2="16" y2="21" />
        <line x1="12" y1="17" x2="12" y2="21" />
    </svg>
);

const DomainIcon = ({ color }: { color: string }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <line x1="2" y1="12" x2="22" y2="12" />
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
);

const GPOIcon = ({ color }: { color: string }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
    </svg>
);

const OUIcon = ({ color }: { color: string }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
    </svg>
);

const ContainerIcon = ({ color }: { color: string }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
    </svg>
);

const UnknownIcon = ({ color }: { color: string }) => (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10" />
        <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
        <line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
);

// Icon selector
const getIcon = (type: string, color: string) => {
    switch (type) {
        case 'User':
            return <UserIcon color={color} />;
        case 'Group':
            return <GroupIcon color={color} />;
        case 'Computer':
            return <ComputerIcon color={color} />;
        case 'Domain':
            return <DomainIcon color={color} />;
        case 'GPO':
            return <GPOIcon color={color} />;
        case 'OU':
            return <OUIcon color={color} />;
        case 'Container':
            return <ContainerIcon color={color} />;
        default:
            return <UnknownIcon color={color} />;
    }
};

// Truncate label for display
const truncateLabel = (label: string, maxLength: number = 20): string => {
    if (label.length <= maxLength) return label;

    // Try to truncate at @ symbol for AD names
    const atIndex = label.indexOf('@');
    if (atIndex > 0 && atIndex <= maxLength) {
        return label.substring(0, atIndex);
    }

    return label.substring(0, maxLength - 3) + '...';
};

// Base node component
const BaseNode = memo(({ data, selected }: NodeProps<AttackNodeData>) => {
    const styles = nodeStyles[data.type] || nodeStyles.Unknown;
    const isHighlighted = selected || data.isHighlighted;
    const isDimmed = data.isDimmed;
    const [showTooltip, setShowTooltip] = useState(false);

    return (
        <div
            className={`
                relative px-3 py-2 rounded-lg
                bg-gradient-to-br ${styles.gradient}
                border-2 ${styles.border}
                shadow-lg
                transition-opacity duration-200
                ${isHighlighted ? 'ring-2 ring-yellow-400 ring-offset-2 ring-offset-[#0d1117] z-50' : ''}
                ${isDimmed ? 'opacity-30' : 'opacity-100'}
                cursor-pointer
                min-w-[120px] max-w-[180px]
            `}
            onMouseEnter={() => setShowTooltip(true)}
            onMouseLeave={() => setShowTooltip(false)}
        >
            {/* Full name tooltip */}
            {showTooltip && (
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 z-[100] pointer-events-none">
                    <div className="bg-[#1c2128] border border-[#30363d] rounded-lg px-3 py-2 shadow-xl whitespace-nowrap">
                        <span className="text-[10px] text-gray-400 uppercase tracking-wide mr-2">{data.type}</span>
                        <span className="text-sm font-medium text-white">{data.label}</span>
                    </div>
                    <div className="absolute top-full left-1/2 -translate-x-1/2 w-2 h-2 bg-[#1c2128] border-r border-b border-[#30363d] transform rotate-45 -mt-1" />
                </div>
            )}
            {/* Connection handles */}
            <Handle
                type="target"
                position={Position.Left}
                className="!w-2 !h-2 !bg-[#30363d] !border-2 !border-[#58a6ff]"
            />
            <Handle
                type="source"
                position={Position.Right}
                className="!w-2 !h-2 !bg-[#30363d] !border-2 !border-[#58a6ff]"
            />

            {/* Node content */}
            <div className="flex items-center gap-2">
                <div className={`p-1.5 rounded-md bg-black/20`}>
                    {getIcon(data.type, styles.iconColor)}
                </div>
                <div className="flex-1 min-w-0">
                    <div className="text-xs text-gray-400 uppercase tracking-wide">
                        {data.type}
                    </div>
                    <div className="text-sm font-medium text-white truncate">
                        {truncateLabel(data.label)}
                    </div>
                </div>
            </div>

            {/* Risk indicator */}
            {data.riskLevel && (
                <div className={`
                    absolute -top-1 -right-1 w-3 h-3 rounded-full
                    ${data.riskLevel === 'Critical' ? 'bg-red-500' : ''}
                    ${data.riskLevel === 'High' ? 'bg-orange-500' : ''}
                    ${data.riskLevel === 'Medium' ? 'bg-yellow-500' : ''}
                    ${data.riskLevel === 'Low' ? 'bg-green-500' : ''}
                `} />
            )}
        </div>
    );
});

BaseNode.displayName = 'BaseNode';

// Export node types for React Flow
export const nodeTypes = {
    attackNode: BaseNode,
};

export default BaseNode;

/**
 * AdditionalFindingsSection Component
 * Displays user-discovered findings from chat queries in the security report.
 * These findings were added via the "Add to Report" feature in the chat interface.
 */

import React, { useState, useMemo } from 'react';
import { AdditionalFinding, ChatGraphData } from '../../types/chat';
import { FindingSeverity } from './types';
import FindingCard from './FindingCard';
import AttackPathGraph from '../AttackPathGraph';

interface AdditionalFindingsSectionProps {
    findings: AdditionalFinding[];
    onRemove?: (findingId: string) => void;
    onCopy?: (text: string) => void;
}

// Helper component to render graph for a finding
const FindingGraphVisualization: React.FC<{
    graphData: ChatGraphData;
    findingTitle: string;
    findingId: string;
}> = ({ graphData, findingTitle, findingId }) => {
    const [isFullScreen, setIsFullScreen] = useState(false);

    // Convert ChatGraphData to AttackPathGraph format
    const attackPathGraphData = useMemo(() => {
        if (!graphData) return null;

        const paths = graphData.paths && graphData.paths.length > 0
            ? graphData.paths
            : [{
                id: 'path-1',
                name: findingTitle || 'Query Results',
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
                analysis_id: `additional-finding-${findingId}`,
                total_paths: paths.length,
                total_nodes: graphData.nodes?.length || 0,
                total_edges: graphData.edges?.length || 0,
                generated_at: new Date().toISOString()
            }
        };
    }, [graphData, findingTitle, findingId]);

    const nodeCount = graphData?.nodes?.length || 0;
    const edgeCount = graphData?.edges?.length || 0;

    if (!attackPathGraphData || (nodeCount === 0 && edgeCount === 0)) {
        return null;
    }

    return (
        <>
            <div className="h-[350px] mb-6">
                <AttackPathGraph
                    analysisId={`additional-graph-${findingId}`}
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
                            analysisId={`additional-fullscreen-${findingId}`}
                            graphData={attackPathGraphData}
                            isExpanded={true}
                            onClose={() => setIsFullScreen(false)}
                            hidePathSelector={attackPathGraphData.graph.paths.length <= 1}
                            singlePathMode={attackPathGraphData.graph.paths.length === 1}
                            defaultSelectedPath="1"
                            title={findingTitle || 'Attack Path Graph'}
                            className="h-full"
                            skipLazyLoad={true}
                        />
                    </div>
                </div>
            )}
        </>
    );
};

const AdditionalFindingsSection: React.FC<AdditionalFindingsSectionProps> = ({
    findings,
    onRemove,
    onCopy
}) => {
    const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

    if (!findings || findings.length === 0) return null;

    const toggleExpanded = (id: string) => {
        setExpandedIds(prev => {
            const next = new Set(prev);
            if (next.has(id)) {
                next.delete(id);
            } else {
                next.add(id);
            }
            return next;
        });
    };

    const getSeverityColor = (severity: FindingSeverity): string => {
        switch (severity) {
            case 'Critical': return 'bg-red-600';
            case 'High': return 'bg-orange-600';
            case 'Medium': return 'bg-yellow-600';
            case 'Low': return 'bg-green-600';
            default: return 'bg-gray-600';
        }
    };

    const getSeverityBorder = (severity: FindingSeverity): string => {
        switch (severity) {
            case 'Critical': return 'border-l-red-600';
            case 'High': return 'border-l-orange-600';
            case 'Medium': return 'border-l-yellow-600';
            case 'Low': return 'border-l-green-600';
            default: return 'border-l-gray-600';
        }
    };

    const formatDate = (dateString: string): string => {
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    };

    return (
        <section className="mb-16">
            {/* Section Header */}
            <div className="flex items-center gap-3 mb-8">
                <div className="p-2 bg-[#388bfd]/10 rounded-lg">
                    <svg className="w-6 h-6 text-[#388bfd]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z" />
                    </svg>
                </div>
                <div>
                    <h2 className="text-2xl font-bold text-white">Additional Findings</h2>
                    <p className="text-[#8b949e] text-sm mt-1">
                        {findings.length} finding{findings.length !== 1 ? 's' : ''} discovered through chat queries
                    </p>
                </div>
            </div>

            {/* Findings List */}
            <div className="space-y-4">
                {findings.map((item, index) => (
                    <div
                        key={item.id}
                        className={`bg-[#161b22] border border-[#30363d] border-l-4 ${getSeverityBorder(item.finding.severity)} rounded-lg overflow-hidden`}
                    >
                        {/* Collapsed Header */}
                        <div
                            className="px-6 py-4 flex items-center justify-between cursor-pointer hover:bg-[#21262d]/50 transition-colors"
                            onClick={() => toggleExpanded(item.id)}
                        >
                            <div className="flex items-center gap-4 min-w-0">
                                {/* Finding Number */}
                                <div className="flex-shrink-0 w-8 h-8 rounded-full bg-[#21262d] flex items-center justify-center text-sm font-medium text-[#8b949e]">
                                    A{index + 1}
                                </div>

                                {/* Severity Badge */}
                                <div className={`flex-shrink-0 ${getSeverityColor(item.finding.severity)} px-2 py-1 rounded text-xs font-bold text-white`}>
                                    {item.finding.severity}
                                </div>

                                {/* Title & Meta */}
                                <div className="min-w-0">
                                    <h3 className="font-semibold text-[#c9d1d9] truncate">{item.finding.title}</h3>
                                    <div className="flex items-center gap-2 text-xs text-[#8b949e] mt-0.5">
                                        <span>{item.finding.category}</span>
                                        <span className="text-[#30363d]">|</span>
                                        <span>Added: {formatDate(item.added_at)}</span>
                                        {item.result_count > 0 && (
                                            <>
                                                <span className="text-[#30363d]">|</span>
                                                <span>{item.result_count} result{item.result_count !== 1 ? 's' : ''}</span>
                                            </>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Actions */}
                            <div className="flex items-center gap-2 flex-shrink-0">
                                {onRemove && (
                                    <button
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            onRemove(item.id);
                                        }}
                                        className="p-2 text-[#8b949e] hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-colors"
                                        title="Remove finding"
                                    >
                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                        </svg>
                                    </button>
                                )}
                                <div className={`p-2 text-[#8b949e] transition-transform ${expandedIds.has(item.id) ? 'rotate-180' : ''}`}>
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                    </svg>
                                </div>
                            </div>
                        </div>

                        {/* Expanded Content */}
                        {expandedIds.has(item.id) && (
                            <div className="border-t border-[#30363d]">
                                {/* Source Query */}
                                <div className="px-6 py-3 bg-[#0d1117] border-b border-[#30363d]">
                                    <span className="text-xs text-[#8b949e]">Source Query: </span>
                                    <code className="text-xs text-[#388bfd] font-mono">
                                        {item.source_query.length > 200
                                            ? item.source_query.slice(0, 200) + '...'
                                            : item.source_query}
                                    </code>
                                </div>

                                {/* User Notes */}
                                {item.user_notes && (
                                    <div className="px-6 py-3 bg-[#0d1117] border-b border-[#30363d]">
                                        <div className="flex items-start gap-2">
                                            <svg className="w-4 h-4 text-[#8b949e] mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z" />
                                            </svg>
                                            <div>
                                                <span className="text-xs text-[#8b949e]">Analyst Notes: </span>
                                                <span className="text-sm text-[#c9d1d9]">{item.user_notes}</span>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Full Finding Card with Graph */}
                                <div className="p-6">
                                    <FindingCard
                                        finding={item.finding}
                                        onCopy={onCopy}
                                        graphComponent={item.graph_data ? (
                                            <FindingGraphVisualization
                                                graphData={item.graph_data}
                                                findingTitle={item.finding.title}
                                                findingId={item.id}
                                            />
                                        ) : undefined}
                                    />
                                </div>
                            </div>
                        )}
                    </div>
                ))}
            </div>
        </section>
    );
};

export default AdditionalFindingsSection;

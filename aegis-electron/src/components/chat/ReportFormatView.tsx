/**
 * ReportFormatView Component
 * Renders chat response as a full Finding structure for Report Format view.
 * Includes "Add to Report" button for adding discovered findings to the report.
 */

import React, { useState, useMemo } from 'react';
import { Finding } from '../attack-components/types';
import { ChatGraphData } from '../../types/chat';
import FindingCard from '../attack-components/FindingCard';
import AttackPathGraph from '../AttackPathGraph';

interface ReportFormatViewProps {
    finding: Finding;
    cypherQuery?: string;
    graphData?: ChatGraphData;
    onAddToReport?: (finding: Finding) => void;
    onCopy?: (text: string) => void;
    isLoading?: boolean;
}

const ReportFormatView: React.FC<ReportFormatViewProps> = ({
    finding,
    cypherQuery: _cypherQuery,
    graphData,
    onAddToReport,
    onCopy,
    isLoading
}) => {
    const [isFullScreen, setIsFullScreen] = useState(false);

    // Convert ChatGraphData to AttackPathGraph format
    const attackPathGraphData = useMemo(() => {
        if (!graphData) return null;

        const paths = graphData.paths && graphData.paths.length > 0
            ? graphData.paths
            : [{
                id: 'path-1',
                name: finding?.title || 'Query Results',
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
                analysis_id: `report-${Date.now()}`,
                total_paths: paths.length,
                total_nodes: graphData.nodes?.length || 0,
                total_edges: graphData.edges?.length || 0,
                generated_at: new Date().toISOString()
            }
        };
    }, [graphData, finding?.title]);

    // Create graph component to pass to FindingCard
    const graphComponent = useMemo(() => {
        if (!attackPathGraphData || !graphData) return undefined;

        const nodeCount = graphData.nodes?.length || 0;
        const edgeCount = graphData.edges?.length || 0;

        if (nodeCount === 0 && edgeCount === 0) return undefined;

        return (
            <>
                <div className="h-[350px] mb-6">
                    <AttackPathGraph
                        analysisId={`report-graph-${Date.now()}`}
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
                                analysisId={`report-fullscreen-${Date.now()}`}
                                graphData={attackPathGraphData}
                                isExpanded={true}
                                onClose={() => setIsFullScreen(false)}
                                hidePathSelector={attackPathGraphData.graph.paths.length <= 1}
                                singlePathMode={attackPathGraphData.graph.paths.length === 1}
                                defaultSelectedPath="1"
                                title={finding?.title || 'Attack Path Graph'}
                                className="h-full"
                                skipLazyLoad={true}
                            />
                        </div>
                    </div>
                )}
            </>
        );
    }, [attackPathGraphData, graphData, isFullScreen, finding?.title]);

    if (isLoading) {
        return <LoadingSkeleton />;
    }

    // Safety check: if finding is null or undefined, show error state
    if (!finding) {
        return (
            <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                <div className="flex items-center gap-2 text-yellow-400 text-sm">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    No finding data available to display in report format.
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            {/* Add to Report Header */}
            <div className="flex items-center justify-between p-4 bg-[#161b22] rounded-lg border border-[#30363d]">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-[#388bfd]/10 rounded-lg">
                        <svg className="w-5 h-5 text-[#388bfd]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                    </div>
                    <div>
                        <h3 className="text-sm font-medium text-[#c9d1d9]">Report Format View</h3>
                        <p className="text-xs text-[#8b949e]">This finding can be added to your security report</p>
                    </div>
                </div>

                {onAddToReport && (
                    <button
                        onClick={() => onAddToReport(finding)}
                        className="flex items-center gap-2 px-4 py-2 bg-[#238636] hover:bg-[#2ea043] text-white text-sm font-medium rounded-lg transition-colors"
                    >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                        </svg>
                        Add to Report
                    </button>
                )}
            </div>

            {/* Finding Preview Card */}
            <div className="border border-[#30363d] rounded-lg overflow-hidden bg-[#0d1117]">
                <div className="p-6">
                    <FindingCard
                        finding={finding}
                        onCopy={onCopy}
                        graphComponent={graphComponent}
                    />
                </div>
            </div>
        </div>
    );
};

// Loading skeleton while finding is being generated
const LoadingSkeleton: React.FC = () => (
    <div className="space-y-4 animate-pulse">
        {/* Header skeleton */}
        <div className="flex items-center justify-between p-4 bg-[#161b22] rounded-lg border border-[#30363d]">
            <div className="flex items-center gap-3">
                <div className="w-9 h-9 bg-[#21262d] rounded-lg" />
                <div className="space-y-2">
                    <div className="w-32 h-4 bg-[#21262d] rounded" />
                    <div className="w-48 h-3 bg-[#21262d] rounded" />
                </div>
            </div>
            <div className="w-32 h-9 bg-[#21262d] rounded-lg" />
        </div>

        {/* Finding skeleton */}
        <div className="border border-[#30363d] rounded-lg overflow-hidden bg-[#0d1117] p-6">
            {/* Severity badge skeleton */}
            <div className="flex items-stretch mb-8 rounded-lg overflow-hidden border border-[#30363d]">
                <div className="w-24 h-16 bg-[#21262d]" />
                <div className="flex-1 px-6 py-4 bg-[#161b22]">
                    <div className="w-3/4 h-6 bg-[#21262d] rounded mb-2" />
                    <div className="w-1/2 h-4 bg-[#21262d] rounded" />
                </div>
            </div>

            {/* Observation skeleton */}
            <div className="mb-6">
                <div className="w-24 h-5 bg-[#21262d] rounded mb-3" />
                <div className="space-y-2">
                    <div className="w-full h-4 bg-[#21262d] rounded" />
                    <div className="w-5/6 h-4 bg-[#21262d] rounded" />
                    <div className="w-4/6 h-4 bg-[#21262d] rounded" />
                </div>
            </div>

            {/* Understanding skeleton */}
            <div className="mb-6">
                <div className="w-40 h-5 bg-[#21262d] rounded mb-3" />
                <div className="space-y-3">
                    <div className="p-4 bg-[#161b22] rounded-lg border border-[#30363d]">
                        <div className="w-48 h-4 bg-[#21262d] rounded mb-2" />
                        <div className="w-full h-3 bg-[#21262d] rounded" />
                    </div>
                </div>
            </div>

            {/* Entities skeleton */}
            <div className="mb-6">
                <div className="w-32 h-5 bg-[#21262d] rounded mb-3" />
                <div className="border border-[#30363d] rounded-lg overflow-hidden">
                    <div className="grid grid-cols-4 gap-4 p-3 bg-[#161b22]">
                        <div className="h-4 bg-[#21262d] rounded" />
                        <div className="h-4 bg-[#21262d] rounded" />
                        <div className="h-4 bg-[#21262d] rounded" />
                        <div className="h-4 bg-[#21262d] rounded" />
                    </div>
                    <div className="grid grid-cols-4 gap-4 p-3">
                        <div className="h-4 bg-[#21262d] rounded" />
                        <div className="h-4 bg-[#21262d] rounded" />
                        <div className="h-4 bg-[#21262d] rounded" />
                        <div className="h-4 bg-[#21262d] rounded" />
                    </div>
                </div>
            </div>

            {/* Attack steps skeleton */}
            <div className="mb-6">
                <div className="w-32 h-5 bg-[#21262d] rounded mb-3" />
                <div className="space-y-4">
                    {[1, 2].map(i => (
                        <div key={i} className="border border-[#30363d] rounded-lg overflow-hidden">
                            <div className="px-4 py-3 bg-[#161b22] border-b border-[#30363d]">
                                <div className="w-48 h-4 bg-[#21262d] rounded" />
                            </div>
                            <div className="p-4 bg-[#010409]">
                                <div className="w-full h-8 bg-[#21262d] rounded" />
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>

        {/* Generating text */}
        <div className="flex items-center justify-center gap-2 text-sm text-[#8b949e]">
            <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            Generating finding structure...
        </div>
    </div>
);

export default ReportFormatView;

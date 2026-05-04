/**
 * ChatResponseRenderer Component
 * Simplified renderer for chat responses.
 * Switches between NormalResponseView and ReportFormatView based on viewMode.
 * Includes error boundary to prevent crashes from malformed response data.
 */

import React, { Component, ErrorInfo, ReactNode, useState } from 'react';
import { QueryResponse, ViewMode } from '../../types/chat';
import { Finding } from '../attack-components/types';
import NormalResponseView from './NormalResponseView';
import ReportFormatView from './ReportFormatView';

// Error Boundary Component to catch rendering errors
interface ErrorBoundaryProps {
    children: ReactNode;
    fallback?: ReactNode;
}

interface ErrorBoundaryState {
    hasError: boolean;
    error: Error | null;
}

class ChatErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
    constructor(props: ErrorBoundaryProps) {
        super(props);
        this.state = { hasError: false, error: null };
    }

    static getDerivedStateFromError(error: Error): ErrorBoundaryState {
        return { hasError: true, error };
    }

    componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
        console.error('[ChatErrorBoundary] Caught error:', error);
        console.error('[ChatErrorBoundary] Error info:', errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return this.props.fallback || (
                <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                    <div className="flex items-start gap-3">
                        <svg className="w-5 h-5 text-red-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <div>
                            <p className="text-sm font-medium text-red-400">Failed to render response</p>
                            <p className="text-xs text-red-400/70 mt-1">
                                An error occurred while displaying this finding. The response data may be incomplete or malformed.
                            </p>
                            {this.state.error && (
                                <p className="text-xs text-red-400/50 mt-2 font-mono">
                                    {this.state.error.message}
                                </p>
                            )}
                        </div>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}

interface ChatResponseRendererProps {
    response: QueryResponse;
    viewMode: ViewMode;
    onAddToReport?: (finding: Finding) => void;
    onCopy?: (text: string) => void;
}

const ChatResponseRenderer: React.FC<ChatResponseRendererProps> = ({
    response,
    viewMode,
    onAddToReport,
    onCopy
}) => {
    const handleCopy = (text: string) => {
        navigator.clipboard.writeText(text);
        if (onCopy) {
            onCopy(text);
        }
    };

    const handleAddToReport = (finding: Finding) => {
        if (onAddToReport) {
            onAddToReport(finding);
        }
    };

    // Error state
    if (!response.success && response.error) {
        return (
            <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg">
                <div className="flex items-start gap-2 text-red-400 text-sm">
                    <svg className="w-4 h-4 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="break-all" style={{ overflowWrap: 'anywhere' }}>{response.error}</span>
                </div>
            </div>
        );
    }

    // Multi-query response: render each finding as collapsible card
    if (response.multi_findings && response.multi_findings.length > 0) {
        return (
            <ChatErrorBoundary>
                <MultiQueryFindings
                    findings={response.multi_findings}
                    totalResults={response.result_count}
                    viewMode={viewMode}
                    onAddToReport={handleAddToReport}
                    onCopy={handleCopy}
                />
            </ChatErrorBoundary>
        );
    }

    // Single-query response (existing flow)
    return (
        <ChatErrorBoundary>
            {viewMode === 'report' && response.finding ? (
                <ReportFormatView
                    finding={response.finding}
                    cypherQuery={response.cypher_query}
                    graphData={response.has_graph ? response.graph_data : undefined}
                    onAddToReport={handleAddToReport}
                    onCopy={handleCopy}
                    isLoading={false}
                />
            ) : (
                <NormalResponseView
                    response={response}
                    onCopy={handleCopy}
                />
            )}
        </ChatErrorBoundary>
    );
};

// Multi-query findings with collapsible cards
const MultiQueryFindings: React.FC<{
    findings: import('../../types/chat').MultiQueryFinding[];
    totalResults: number;
    viewMode: ViewMode;
    onAddToReport: (finding: Finding) => void;
    onCopy: (text: string) => void;
}> = ({ findings, totalResults, viewMode, onAddToReport, onCopy }) => {
    const [expandedIds, setExpandedIds] = useState<Set<number>>(new Set([0])); // First expanded by default

    const toggle = (idx: number) => {
        setExpandedIds(prev => {
            const next = new Set(prev);
            if (next.has(idx)) next.delete(idx);
            else next.add(idx);
            return next;
        });
    };

    const expandAll = () => setExpandedIds(new Set(findings.map((_, i) => i)));
    const collapseAll = () => setExpandedIds(new Set());

    return (
        <div className="space-y-3">
            {/* Summary header */}
            <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2 text-sm text-[#8b949e]">
                    <svg className="w-4 h-4 text-[#58a6ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                    <span><strong className="text-white">{findings.length}</strong> findings discovered</span>
                    <span className="text-[#6e7681]">({totalResults} total results)</span>
                </div>
                <div className="flex items-center gap-2">
                    <button onClick={expandAll} className="text-[11px] text-[#58a6ff] hover:text-[#79c0ff] transition-colors">
                        Expand All
                    </button>
                    <span className="text-[#30363d]">|</span>
                    <button onClick={collapseAll} className="text-[11px] text-[#58a6ff] hover:text-[#79c0ff] transition-colors">
                        Collapse All
                    </button>
                </div>
            </div>

            {/* Render each finding as collapsible */}
            {findings.map((mf, idx) => {
                if (mf.error) {
                    return (
                        <div key={idx} className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400">
                            <strong>{mf.query_name}</strong>: {mf.error}
                        </div>
                    );
                }
                if (mf.result_count === 0) return null;

                const isExpanded = expandedIds.has(idx);
                const severity = mf.finding?.severity || 'Medium';
                const severityColors: Record<string, string> = {
                    Critical: 'bg-red-600',
                    High: 'bg-orange-500',
                    Medium: 'bg-yellow-600',
                    Low: 'bg-green-500',
                };

                return (
                    <div key={idx} className="border border-[#30363d] rounded-xl overflow-hidden">
                        {/* Collapsible header */}
                        <button
                            onClick={() => toggle(idx)}
                            className="w-full flex items-center gap-3 px-4 py-3 bg-[#161b22] hover:bg-[#1c2128] transition-colors cursor-pointer"
                        >
                            <span className="w-6 h-6 bg-[#58a6ff] text-white text-xs font-bold rounded flex items-center justify-center flex-shrink-0">
                                {idx + 1}
                            </span>
                            {viewMode === 'report' && mf.finding && (
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold text-white ${severityColors[severity] || severityColors.Medium}`}>
                                    {severity}
                                </span>
                            )}
                            <span className="text-sm font-semibold text-white flex-1 text-left truncate">
                                {mf.query_name}
                            </span>
                            <span className="text-xs text-[#8b949e] flex-shrink-0">{mf.result_count} results</span>
                            <svg
                                className={`w-4 h-4 text-[#8b949e] transition-transform duration-200 flex-shrink-0 ${isExpanded ? 'rotate-180' : ''}`}
                                fill="none" stroke="currentColor" viewBox="0 0 24 24"
                            >
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                            </svg>
                        </button>

                        {/* Expandable content */}
                        {isExpanded && (
                            <div className="border-t border-[#30363d]">
                                {viewMode === 'report' && mf.finding ? (
                                    <ReportFormatView
                                        finding={mf.finding}
                                        cypherQuery={mf.cypher_query}
                                        graphData={mf.has_graph ? mf.graph_data : undefined}
                                        onAddToReport={onAddToReport}
                                        onCopy={onCopy}
                                        isLoading={false}
                                    />
                                ) : (
                                    <div className="p-4">
                                        <NormalResponseView
                                            response={{
                                                success: true,
                                                query_type: 'natural_language',
                                                cypher_query: mf.cypher_query,
                                                results: mf.results,
                                                result_count: mf.result_count,
                                                explanation: mf.explanation,
                                                understanding: mf.understanding,
                                                attack_steps: mf.attack_steps,
                                                graph_data: mf.graph_data,
                                                has_graph: mf.has_graph,
                                            }}
                                            onCopy={onCopy}
                                        />
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
};

export default ChatResponseRenderer;

/**
 * Attack Chain Position Widget
 * Location: src/components/attack-components/AttackChainPositionWidget.tsx
 *
 * Displays the position of a finding within an attack chain.
 * Shows visual chain with clickable steps and navigation links.
 */

import React from 'react';

export interface ChainStep {
    finding_id: number;
    edge_type: string;
    title?: string;
}

export interface ChainInfo {
    is_in_chain: boolean;
    chain_id: string;
    position: number;
    total_steps: number;
    chain_steps: ChainStep[];
    previous?: ChainStep;
    next?: ChainStep;
    chain_goal: string;
}

interface AttackChainPositionWidgetProps {
    chainInfo: ChainInfo;
    onNavigate: (findingId: number) => void;
}

const AttackChainPositionWidget: React.FC<AttackChainPositionWidgetProps> = ({
    chainInfo,
    onNavigate
}) => {
    if (!chainInfo?.is_in_chain) return null;

    const { chain_steps, position, total_steps, previous } = chainInfo;

    return (
        <div className="mb-4 p-4 bg-[#161b22] border border-[#30363d] rounded-lg">
            {/* Header */}
            <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                    <svg className="w-4 h-4 text-[#58a6ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                    </svg>
                    <span className="font-semibold text-white">Attack Chain Position</span>
                </div>
                <span className="text-sm text-[#8b949e]">Step {position} of {total_steps}</span>
            </div>

            {/* Chain visualization - horizontal scrollable */}
            <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-[#30363d] scrollbar-track-transparent">
                {chain_steps.map((step, idx) => {
                    const isCurrentStep = idx + 1 === position;

                    return (
                        <React.Fragment key={step.finding_id}>
                            <button
                                onClick={() => onNavigate(step.finding_id)}
                                className={`px-3 py-2 rounded-lg text-sm whitespace-nowrap transition-all flex-shrink-0 ${isCurrentStep
                                    ? 'bg-[#21262d] border-2 border-[#58a6ff] text-white font-semibold shadow-[0_0_10px_rgba(88,166,255,0.3)]'
                                    : 'bg-[#21262d] border border-[#30363d] text-[#8b949e] hover:border-[#8b949e] hover:text-white'
                                    }`}
                                title={step.title || `Finding #${step.finding_id}`}
                            >
                                #{step.finding_id} {step.edge_type}
                            </button>
                            {idx < chain_steps.length - 1 && (
                                <svg className="w-4 h-4 text-[#30363d] flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                </svg>
                            )}
                        </React.Fragment>
                    );
                })}
            </div>

            {/* Previous link */}
            {previous && (
                <button
                    onClick={() => onNavigate(previous.finding_id)}
                    className="mt-3 text-sm text-[#58a6ff] hover:underline flex items-center gap-1"
                >
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                    </svg>
                    Previous: #{previous.finding_id} {previous.edge_type}
                </button>
            )}
        </div>
    );
};

export default AttackChainPositionWidget;

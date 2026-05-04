/**
 * Global Attack Chain Component
 * Location: src/components/attack-components/GlobalAttackChain.tsx
 *
 * Displays the full attack chain above the findings list.
 * Highlights the currently active finding when user is viewing one in the chain.
 */

import React from 'react';
import { ChainStep } from './AttackChainPositionWidget';

interface GlobalAttackChainProps {
    chainSteps: ChainStep[];
    chainGoal: string;
    activeFindingId?: number | null;
    onNavigate: (findingId: number) => void;
}

const GlobalAttackChain: React.FC<GlobalAttackChainProps> = ({
    chainSteps,
    chainGoal,
    activeFindingId,
    onNavigate
}) => {
    if (!chainSteps?.length) return null;

    return (
        <div className="mb-8 p-4 bg-[#0d1117] border border-[#30363d] rounded-xl">
            {/* Header */}
            <div className="flex items-center gap-2 mb-3">
                <svg className="w-5 h-5 text-[#58a6ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>
                <span className="text-sm font-semibold text-[#c9d1d9]">Detected Attack Chain</span>
                <span className="text-xs text-[#8b949e]">({chainSteps.length} steps)</span>
            </div>

            {/* Chain visualization */}
            <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-[#30363d] scrollbar-track-transparent">
                <svg className="w-5 h-5 text-[#58a6ff] flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                </svg>

                {chainSteps.map((step) => {
                    const isActive = step.finding_id === activeFindingId;

                    return (
                        <React.Fragment key={step.finding_id}>
                            <button
                                onClick={() => onNavigate(step.finding_id)}
                                className={`px-3 py-1.5 rounded text-sm whitespace-nowrap transition-all flex-shrink-0 ${isActive
                                    ? 'bg-[#21262d] border-2 border-[#58a6ff] text-white font-semibold shadow-[0_0_10px_rgba(88,166,255,0.3)]'
                                    : 'text-[#8b949e] hover:text-white hover:bg-[#21262d]'
                                    }`}
                                title={step.title || `Finding #${step.finding_id}`}
                            >
                                #{step.finding_id} {step.edge_type}
                            </button>
                            <span className="text-[#30363d] flex-shrink-0">→</span>
                        </React.Fragment>
                    );
                })}

                {/* Chain goal */}
                <span className="px-3 py-1.5 bg-red-600/20 border border-red-600/50 rounded text-red-400 text-sm font-semibold whitespace-nowrap flex-shrink-0">
                    {chainGoal}
                </span>
            </div>
        </div>
    );
};

export default GlobalAttackChain;

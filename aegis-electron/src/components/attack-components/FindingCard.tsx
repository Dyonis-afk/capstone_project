/**
 * FindingCard Component
 * Location: src/components/attack-components/FindingCard.tsx
 *
 * Renders a single finding in pentest report style matching the mockup.
 * Includes: Header, Observation, Understanding, Entities, Attack Steps,
 * Evidence, Risk, Remediation, References, Detection, Related Findings
 */

import React, { useState, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import toast from 'react-hot-toast';
import {
    Finding,
    FindingSeverity,
    AffectedEntity,
    Reference,
} from './types';
import AttackExplainer from './AttackExplainer';
import AttackStepCard from './AttackStepCard';
import DetectionMonitoring from './DetectionMonitoring';
import CypherQueryDisplay from './CypherQueryDisplay';
import SyntaxHighlightedScript from './SyntaxHighlightedScript';

/**
 * Clean up malformed markdown from RAG output
 * Fixes spacing issues around bold markers
 */
const cleanMarkdown = (text: string): string => {
    if (!text) return text;

    let cleaned = text;

    // === STEP 1: Remove orphaned ** markers that are embedded in words ===
    // Fix cases like "likeGenericAll**" or "word**text" where ** is incomplete
    // Remove ** that appears at end of word without matching pair
    cleaned = cleaned.replace(/([a-zA-Z0-9])\*\*([a-zA-Z0-9])/g, '$1 $2');
    // Remove ** at end of word
    cleaned = cleaned.replace(/([a-zA-Z0-9])\*\*(\s|$|\.|,|;|:|\?|!)/g, '$1$2');
    // Remove ** at start of word (after space or start of line)
    cleaned = cleaned.replace(/(\s|^)\*\*([a-zA-Z0-9])/g, '$1$2');

    // === STEP 2: Fix spaces inside bold markers ===
    cleaned = cleaned.replace(/\*\*\s+([^*]+?)\s+\*\*/g, '**$1**');
    cleaned = cleaned.replace(/\*\*\s+([^*]+?)\*\*/g, '**$1**');
    cleaned = cleaned.replace(/\*\*([^*]+?)\s+\*\*/g, '**$1**');

    // === STEP 3: Add spaces around bold blocks when adjacent to word characters ===
    // This handles cases like "**OPERATORS**or" -> "**OPERATORS** or"
    // and "GenericAll**permission**" -> "GenericAll **permission**"

    // Add space AFTER closing ** if followed by word character
    cleaned = cleaned.replace(/(\*\*[^*]+\*\*)([a-zA-Z0-9])/g, '$1 $2');

    // Add space BEFORE opening ** if preceded by word character
    cleaned = cleaned.replace(/([a-zA-Z0-9])(\*\*[^*]+\*\*)/g, '$1 $2');

    // === STEP 4: Fix orphaned bold markers (standalone ** without pair) ===
    cleaned = cleaned.replace(/\s+\*\*(?!\S)/g, '');
    cleaned = cleaned.replace(/\*\*\s+(?=[^*]*$)/g, '');

    // === STEP 5: Remove empty bold markers ===
    cleaned = cleaned.replace(/\*\*\s*\*\*/g, '');

    // === STEP 6: Fix odd number of ** markers per line (remove incomplete pairs) ===
    const lines = cleaned.split('\n');
    const fixedLines = lines.map(line => {
        const count = (line.match(/\*\*/g) || []).length;
        // If odd number, remove all ** markers (incomplete pairs)
        if (count % 2 !== 0) {
            return line.replace(/\*\*/g, '');
        }
        return line;
    });
    cleaned = fixedLines.join('\n');

    // === STEP 7: Clean up multiple spaces ===
    cleaned = cleaned.replace(/\s{2,}/g, ' ');

    return cleaned.trim();
};

interface FindingCardProps {
    finding: Finding;
    onCopy?: (text: string) => void;
    // Graph visualization props
    graphComponent?: React.ReactNode;
    // Hide the header (used when parent component renders its own collapsible header)
    hideHeader?: boolean;
}

// Severity color mapping
const severityColors: Record<FindingSeverity, { bg: string; text: string; border: string }> = {
    Critical: { bg: 'bg-red-600', text: 'text-white', border: 'border-red-600' },
    High: { bg: 'bg-orange-600', text: 'text-white', border: 'border-orange-600' },
    Medium: { bg: 'bg-yellow-600', text: 'text-white', border: 'border-yellow-600' },
    Low: { bg: 'bg-green-600', text: 'text-white', border: 'border-green-600' },
};

const severityTagColors: Record<FindingSeverity, string> = {
    Critical: 'bg-red-600/20 text-red-400 border-red-600/30',
    High: 'bg-orange-600/20 text-orange-400 border-orange-600/30',
    Medium: 'bg-yellow-600/20 text-yellow-400 border-yellow-600/30',
    Low: 'bg-green-600/20 text-green-400 border-green-600/30',
};

const FindingCard: React.FC<FindingCardProps> = ({ finding, onCopy, graphComponent, hideHeader = false }) => {
    const handleCopy = (text: string, _index?: number) => {
        navigator.clipboard.writeText(text);
        onCopy?.(text);
    };

    // Defensive: ensure severity is valid, default to 'Medium' if not
    const severity = finding?.severity && severityColors[finding.severity] ? finding.severity : 'Medium';
    const severityStyle = severityColors[severity];

    // Defensive: provide default empty arrays/values for all required fields
    const safeUnderstanding = finding?.understanding || [];
    const safeEntities = finding?.affected_entities || [];
    const safeAttackSteps = finding?.attack_steps || [];
    const safeRemediationSteps = finding?.remediation_steps || [];
    const safeReferences = finding?.references || [];
    const safeDetection = finding?.detection || {
        event_ids: [],
        indicators_of_compromise: [],
        queries: []
    };

    return (
        <div className={hideHeader ? "p-6" : "mb-12"}>
            {/* Finding Header - hidden when using collapsible parent */}
            {!hideHeader && (
                <div className="flex items-stretch mb-8 rounded-lg overflow-hidden border border-[#30363d]">
                    <div className={`${severityStyle.bg} ${severityStyle.text} px-6 py-4 font-bold text-lg flex items-center justify-center min-w-[100px]`}>
                        {severity}
                    </div>
                    <div className="flex-1 px-6 py-4 bg-[#161b22]">
                        <h1 className="text-xl font-semibold text-white mb-1">
                            {finding?.title || 'Untitled Finding'}
                        </h1>
                        <div className="text-sm text-[#8b949e]">
                            Attack Complexity: <span className="text-[#fbbf24] font-semibold">{finding?.attack_complexity || 'Unknown'}</span>
                            <span className="mx-2">&bull;</span>
                            Category: {finding?.category || 'Uncategorized'}
                        </div>
                    </div>
                </div>
            )}

            {/* Observation */}
            <SectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>}>Observation</SectionTitle>
            <div className="mb-6 bg-[#161b22] border border-[#21262d] rounded-lg p-4">
                <div className="text-[#c9d1d9] leading-relaxed prose prose-invert prose-sm max-w-none">
                    <ReactMarkdown
                        components={{
                            strong: ({ children }) => <strong className="text-white font-semibold">{children}</strong>,
                            p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
                        }}
                    >
                        {cleanMarkdown(finding?.observation || 'No observation provided.')}
                    </ReactMarkdown>
                </div>
            </div>

            {/* Understanding the Attack */}
            {safeUnderstanding.length > 0 && (
                <>
                    <SectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>}>Understanding the Attack</SectionTitle>
                    <AttackExplainer explanations={safeUnderstanding} />
                </>
            )}

            {/* Affected Entities */}
            <SectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>}>Affected Entities</SectionTitle>
            <EntitiesTable entities={safeEntities} onCopy={onCopy} />

            {/* Attack Commands */}
            {safeAttackSteps.length > 0 && (
                <>
                    <SectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>}>Attack Steps</SectionTitle>
                    {finding?.attack_intro && (
                        <div className="text-[#c9d1d9] mb-4 leading-relaxed prose prose-invert prose-sm max-w-none">
                            <ReactMarkdown
                                components={{
                                    strong: ({ children }) => <strong className="text-[#fbbf24] font-semibold">{children}</strong>,
                                    p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
                                    code: ({ children }) => <code className="bg-[#21262d] px-1.5 py-0.5 rounded text-[#58a6ff] text-sm font-mono">{children}</code>,
                                }}
                            >
                                {cleanMarkdown(finding.attack_intro)}
                            </ReactMarkdown>
                        </div>
                    )}
                    <div className="space-y-4">
                        {safeAttackSteps.map((step, index) => (
                            <AttackStepCard
                                key={index}
                                step={step}
                                onCopy={onCopy}
                                index={index}
                            />
                        ))}
                    </div>
                </>
            )}

            {/* Evidence */}
            {finding?.cypher_query && (
                <>
                    <SectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>}>Evidence</SectionTitle>
                    {/* Cypher Query - using CypherQueryDisplay component */}
                    <div className="mb-4">
                        <CypherQueryDisplay
                            query={finding.cypher_query}
                            queryName={finding?.title || 'Query'}
                            description={`${finding?.category || 'Finding'} - ${severity} severity`}
                            edgesUsed={finding?.edges_used}
                            onCopy={onCopy}
                        />
                    </div>
                </>
            )}

            {/* Graph Visualization (rendered right after Cypher query) */}
            {graphComponent && graphComponent}

            {/* Risk */}
            {(finding?.risk_title || finding?.risk_description) && (
                <>
                    <SectionTitle color="text-[#f85149]" icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>}>Risk</SectionTitle>
                    <div className="bg-[#f8514920] border border-[#f851494d] rounded-lg p-4 mb-6">
                        <div className="flex items-center gap-2 text-[#f85149] font-semibold mb-2">
                            <WarningIcon />
                            {finding?.risk_title || 'Security Risk'}
                        </div>
                        <div className="text-[#c9d1d9] prose prose-invert prose-sm max-w-none">
                            <ReactMarkdown
                                components={{
                                    strong: ({ children }) => <strong className="text-white font-semibold">{children}</strong>,
                                    p: ({ children }) => <p className="mb-2 last:mb-0">{children}</p>,
                                }}
                            >
                                {cleanMarkdown(finding?.risk_description || 'No risk description provided.')}
                            </ReactMarkdown>
                        </div>
                    </div>
                </>
            )}

            {/* Remediation */}
            {(safeRemediationSteps.length > 0 || finding?.remediation_script) && (
                <>
                    <SectionTitle color="text-[#3fb950]" icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>}>Remediation</SectionTitle>
                    <div className="bg-[#7ee78720] border border-[#7ee7874d] rounded-lg p-4 mb-6">
                        <div className="flex items-center gap-2 text-[#7ee787] font-semibold mb-2">
                            <CheckIcon />
                            Recommended Actions
                        </div>
                        {safeRemediationSteps.length > 0 && (
                            <ol className="list-decimal list-inside text-[#c9d1d9] space-y-2 mb-4">
                                {safeRemediationSteps.map((step, index) => (
                                    <li key={index}>
                                        <ReactMarkdown
                                            components={{
                                                p: ({ children }) => <span>{children}</span>,
                                            }}
                                        >
                                            {step}
                                        </ReactMarkdown>
                                    </li>
                                ))}
                            </ol>
                        )}
                        {finding?.remediation_script && (
                            <div className="mt-4 rounded-lg overflow-hidden border border-[#30363d]">
                                <SyntaxHighlightedScript
                                    code={finding.remediation_script}
                                    language="powershell"
                                    onCopy={onCopy}
                                />
                            </div>
                        )}
                    </div>
                </>
            )}

            {/* References */}
            {safeReferences.length > 0 && (
                <>
                    <SectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>}>References</SectionTitle>
                    <ReferencesList references={safeReferences} />
                </>
            )}

            {/* Detection & Monitoring */}
            {(safeDetection.event_ids?.length > 0 || safeDetection.indicators_of_compromise?.length > 0 || safeDetection.queries?.length > 0) && (
                <>
                    <SectionTitle icon={<svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>}>Detection & Monitoring</SectionTitle>
                    <DetectionMonitoring detection={safeDetection} onCopy={handleCopy} />
                </>
            )}
        </div>
    );
};

// Section title component
const SectionTitle: React.FC<{ children: React.ReactNode; icon?: React.ReactNode; color?: string }> = ({ children, icon, color = 'text-[#58a6ff]' }) => (
    <h2 className={`text-[15px] font-bold uppercase tracking-widest mt-8 mb-4 pb-2 border-b border-[#30363d] flex items-center gap-2.5 ${color}`}>
        {icon}
        {children}
    </h2>
);

// Entities table component with pagination
const EntitiesTable: React.FC<{ entities: AffectedEntity[]; onCopy?: (text: string) => void }> = ({ entities, onCopy }) => {
    const [currentPage, setCurrentPage] = useState(0);
    const pageSize = 25;

    const totalPages = Math.ceil(entities.length / pageSize);

    const paginatedEntities = useMemo(() => {
        const start = currentPage * pageSize;
        return entities.slice(start, start + pageSize);
    }, [entities, currentPage]);

    // Determine dynamic column header for third column
    const thirdColumnHeader = entities[0]?.target_group ? 'Target Group' : entities[0]?.spn ? 'SPN' : 'Path';
    // Determine if fourth column shows risk or path
    const showRisk = entities.some(e => e.risk);

    const handleCopyAll = () => {
        const header = `Principal\tType\t${thirdColumnHeader}\t${showRisk ? 'Risk' : 'Path'}`;
        const rows = entities.map(entity =>
            `${entity.principal}\t${entity.type}\t${entity.target_group || entity.spn || entity.path || '-'}\t${entity.risk || entity.path || '-'}`
        ).join('\n');
        const text = `${header}\n${rows}`;
        navigator.clipboard.writeText(text);
        onCopy?.(text);
        toast.success('Copied to clipboard');
    };

    if (entities.length === 0) {
        return (
            <div className="text-sm text-[#8b949e] italic mb-6">No affected entities found</div>
        );
    }

    return (
        <div className="rounded-lg border border-[#30363d] overflow-hidden mb-6">
            {/* Table Header with Copy Button */}
            <div className="px-4 py-2 bg-[#161b22] border-b border-[#30363d] flex items-center justify-between">
                <span className="text-xs text-[#8b949e]">
                    {entities.length} affected entit{entities.length !== 1 ? 'ies' : 'y'}
                </span>
                <button
                    onClick={handleCopyAll}
                    className="text-xs text-[#8b949e] hover:text-[#c9d1d9] flex items-center gap-1"
                    title="Copy all entities as TSV"
                >
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                    Copy All
                </button>
            </div>

            {/* Table */}
            <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
                <table className="w-full text-sm border-collapse">
                    <thead className="bg-[#161b22] sticky top-0">
                        <tr>
                            <th className="text-left px-4 py-3 bg-[#161b22] border-b border-[#30363d] text-[#8b949e] font-semibold uppercase text-xs tracking-wider">
                                Principal
                            </th>
                            <th className="text-left px-4 py-3 bg-[#161b22] border-b border-[#30363d] text-[#8b949e] font-semibold uppercase text-xs tracking-wider">
                                Type
                            </th>
                            <th className="text-left px-4 py-3 bg-[#161b22] border-b border-[#30363d] text-[#8b949e] font-semibold uppercase text-xs tracking-wider">
                                {thirdColumnHeader}
                            </th>
                            <th className="text-left px-4 py-3 bg-[#161b22] border-b border-[#30363d] text-[#8b949e] font-semibold uppercase text-xs tracking-wider">
                                {showRisk ? 'Risk' : 'Path'}
                            </th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-[#30363d]">
                        {paginatedEntities.map((entity, index) => (
                            <tr key={index} className="hover:bg-[#161b22]/50">
                                <td className="px-4 py-3 font-mono text-sm text-[#c9d1d9]">
                                    {entity.principal}
                                </td>
                                <td className="px-4 py-3 text-[#8b949e]">
                                    {entity.type}
                                </td>
                                <td className="px-4 py-3 text-sm text-[#c9d1d9]">
                                    {entity.target_group || entity.spn || entity.path || '-'}
                                </td>
                                <td className="px-4 py-3">
                                    {entity.risk ? (
                                        <span className={`inline-block px-2 py-1 rounded text-xs font-semibold border ${severityTagColors[entity.risk]}`}>
                                            {entity.risk}
                                        </span>
                                    ) : (
                                        <span className="text-[#c9d1d9]">{entity.path || '-'}</span>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
                <div className="px-4 py-2 bg-[#161b22] border-t border-[#30363d] flex items-center justify-between">
                    <span className="text-xs text-[#8b949e]">
                        Showing {currentPage * pageSize + 1}-{Math.min((currentPage + 1) * pageSize, entities.length)} of {entities.length}
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

// References list component
const ReferencesList: React.FC<{ references: Reference[] }> = ({ references }) => (
    <ul className="list-none mb-6">
        {references.map((ref, index) => (
            <li key={index} className="py-2 border-b border-[#30363d] last:border-b-0">
                <span className="text-xs bg-[#21262d] px-1.5 py-0.5 rounded text-[#8b949e] mr-2 uppercase tracking-wide">
                    {ref.tag}
                </span>
                <a
                    href={ref.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[#58a6ff] hover:underline"
                >
                    {ref.title}
                </a>
            </li>
        ))}
    </ul>
);

// Icons
const WarningIcon = () => (
    <svg width="16" height="16" fill="currentColor" viewBox="0 0 20 20">
        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
    </svg>
);

const CheckIcon = () => (
    <svg width="16" height="16" fill="currentColor" viewBox="0 0 20 20">
        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
    </svg>
);

export default FindingCard;

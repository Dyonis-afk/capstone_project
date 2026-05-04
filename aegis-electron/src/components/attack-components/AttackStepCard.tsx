/**
 * AttackStepCard Component
 * Location: src/components/attack-components/AttackStepCard.tsx
 *
 * Reusable attack step card that supports both OPSEC-aware format and legacy format.
 * Used in both report findings and chat responses.
 */

import React from 'react';
import ReactMarkdown from 'react-markdown';
import { AttackStep } from './types';
import SyntaxHighlightedScript from './SyntaxHighlightedScript';
import ToolLinksFooter, { detectToolsFromCommand } from './ToolLinksFooter';

/**
 * Clean up malformed markdown from RAG output
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

// OPSEC badge component
const OpsecBadge: React.FC<{ level: 'safe' | 'risky' }> = ({ level }) => {
    if (level === 'safe') {
        return (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold bg-[#22c55e]/15 text-[#22c55e]">
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                OPSEC-SAFE
            </span>
        );
    }
    return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-semibold bg-[#ef4444]/15 text-[#ef4444]">
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            May trigger AV/EDR
        </span>
    );
};

export interface AttackStepCardProps {
    step: AttackStep;
    onCopy?: (text: string) => void;
    index?: number;
}

/**
 * Attack step card component - supports both legacy and OPSEC-aware formats
 */
const AttackStepCard: React.FC<AttackStepCardProps> = ({ step, onCopy, index: _index = 0 }) => {
    const handleCopy = (text: string) => {
        navigator.clipboard.writeText(text);
        onCopy?.(text);
    };

    // Check if this step uses the new OPSEC-aware format
    const hasOpsecOptions = step.opsec_options && step.opsec_options.length > 0;

    if (hasOpsecOptions) {
        // New OPSEC-aware format with multiple options
        return (
            <div className="bg-[#0d1117] border border-[#30363d] rounded-xl overflow-hidden">
                {/* Step Header */}
                <div className="flex items-center gap-4 px-5 py-4 bg-[#161b22] border-b border-[#30363d]">
                    <span className="w-7 h-7 flex items-center justify-center bg-[#58a6ff] text-white text-sm font-bold rounded-md flex-shrink-0">
                        {step.step_number}
                    </span>
                    <span className="flex-1 font-semibold text-white">{step.title}</span>
                    {step.category && (
                        <span className="px-2.5 py-1 bg-[#21262d] border border-[#30363d] rounded text-xs text-[#8b949e]">
                            {step.category}
                        </span>
                    )}
                </div>

                {/* OBJECTIVE Section */}
                {(step.objective || step.description) && (
                    <div className="px-5 py-4 border-b border-[#30363d]">
                        <div className="flex items-center gap-2 mb-2">
                            <svg className="w-4 h-4 text-[#58a6ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <span className="text-xs font-semibold uppercase tracking-wider text-[#58a6ff]">Objective</span>
                        </div>
                        <div className="text-[15px] text-[#c9d1d9] leading-relaxed">
                            <ReactMarkdown
                                components={{
                                    p: ({ children }) => <span className="leading-relaxed">{children}</span>,
                                    strong: ({ children }) => <strong className="text-[#fbbf24] font-semibold">{children}</strong>,
                                    code: ({ children }) => (
                                        <code className="bg-[#21262d] border border-[#30363d] px-1.5 py-0.5 rounded text-[#58a6ff] text-sm font-mono">
                                            {children}
                                        </code>
                                    ),
                                }}
                            >
                                {cleanMarkdown(step.objective || step.description || '')}
                            </ReactMarkdown>
                        </div>
                    </div>
                )}

                {/* PREREQUISITES Section */}
                {step.prerequisites && step.prerequisites.length > 0 && (
                    <div className="px-5 py-4 border-b border-[#30363d]">
                        <div>
                            <div className="flex items-center gap-2 mb-2">
                                <svg className="w-4 h-4 text-[#fbbf24]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                                </svg>
                                <span className="text-xs font-semibold uppercase tracking-wider text-[#fbbf24]">Prerequisites</span>
                            </div>
                            <ul className="space-y-2">
                                {step.prerequisites.map((prereq, idx) => (
                                    <li key={idx} className="flex items-start gap-2 text-[14px] text-[#c9d1d9]">
                                        <span className="text-[#7ee787] mt-0.5">•</span>
                                        <span>
                                            <ReactMarkdown
                                                components={{
                                                    p: ({ children }) => <span>{children}</span>,
                                                    strong: ({ children }) => <strong className="text-[#fbbf24] font-semibold">{children}</strong>,
                                                }}
                                            >
                                                {cleanMarkdown(prereq)}
                                            </ReactMarkdown>
                                        </span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>
                )}

                {/* OPSEC Options */}
                <div className="p-5">
                    {step.opsec_options!.map((option, optIdx) => (
                        <div key={optIdx}>
                            {/* Divider between options */}
                            {optIdx > 0 && <div className="h-px bg-[#30363d] my-5" />}

                            <div className={option.opsec_level === 'risky' ? 'opsec-option-risky' : ''}>
                                {/* OPSEC Header */}
                                <div className="flex items-center gap-3 mb-3">
                                    <OpsecBadge level={option.opsec_level} />
                                    <span className="text-[15px] font-semibold text-white">{option.tool_name}</span>
                                </div>

                                {/* AMSI Bypass Note */}
                                {option.amsi_bypass?.required && (
                                    <div className="mb-3 p-3 rounded-lg bg-[#fbbf24]/10 border border-[#fbbf24]/30">
                                        <div className="flex items-center gap-2">
                                            <svg className="w-4 h-4 text-[#fbbf24]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                            </svg>
                                            <span className="text-sm text-[#fbbf24]">
                                                <strong>AMSI Bypass Required:</strong>{' '}
                                                <button
                                                    onClick={(e) => {
                                                        e.preventDefault();
                                                        const appendix = document.getElementById('amsi-appendix');
                                                        if (appendix) {
                                                            appendix.scrollIntoView({ behavior: 'smooth', block: 'start' });
                                                        }
                                                    }}
                                                    className="underline hover:text-[#fcd34d] cursor-pointer bg-transparent border-none p-0 font-inherit text-inherit"
                                                >
                                                    {option.amsi_bypass.note || 'See Appendix for bypass code'}
                                                </button>
                                            </span>
                                        </div>
                                    </div>
                                )}

                                {/* Command Block - Using SyntaxHighlightedScript */}
                                <div className="rounded-lg overflow-hidden border border-[#30363d]">
                                    <SyntaxHighlightedScript
                                        code={option.command}
                                        language="powershell"
                                        onCopy={handleCopy}
                                    />
                                </div>

                                {/* Explanation */}
                                <div className={`mt-3 p-3.5 rounded-lg text-[13px] leading-relaxed ${option.opsec_level === 'risky'
                                    ? 'bg-[#ef4444]/5 border-l-[3px] border-[#ef4444] text-[#c9d1d9]'
                                    : 'bg-[#161b22] text-[#c9d1d9]'
                                    }`}>
                                    <ReactMarkdown
                                        components={{
                                            p: ({ children }) => <span className="leading-relaxed">{children}</span>,
                                            strong: ({ children }) => <strong className="text-[#fbbf24] font-semibold">{children}</strong>,
                                            code: ({ children }) => (
                                                <code className="bg-[#21262d] border border-[#30363d] px-1.5 py-0.5 rounded text-[#58a6ff] text-sm font-mono">
                                                    {children}
                                                </code>
                                            ),
                                        }}
                                    >
                                        {cleanMarkdown(option.explanation)}
                                    </ReactMarkdown>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>

                {/* Tool Download Links Footer */}
                <ToolLinksFooter
                    tools={detectToolsFromCommand(
                        step.opsec_options!.map(o => `${o.command} ${o.tool_name}`).join(' '),
                        step.title
                    )}
                />
            </div>
        );
    }

    // Legacy single-command format (backward compatibility)
    // Detect tools from command and tool name
    const detectedTools = detectToolsFromCommand(step.command || '', step.tool);

    return (
        <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden">
            {/* Header with step number, title, and tool */}
            <div className="flex items-center gap-3 px-4 py-3 bg-[#21262d] border-b border-[#30363d]">
                <span className="bg-[#58a6ff] text-white text-xs font-bold px-2 py-1 rounded min-w-[24px] text-center">
                    {step.step_number}
                </span>
                <span className="font-semibold text-white">{step.title}</span>
                {step.tool && (
                    <span className="ml-auto text-xs text-[#8b949e] bg-[#010409] px-2 py-1 rounded font-mono">
                        {step.tool}
                    </span>
                )}
            </div>

            {/* Code block with syntax highlighting */}
            {step.command && (
                <SyntaxHighlightedScript
                    code={step.command}
                    language="powershell"
                    onCopy={handleCopy}
                />
            )}

            {/* Explanation with markdown support */}
            {step.explanation && (
                <div className="p-4 text-[#c9d1d9] border-t border-[#30363d] prose prose-invert prose-sm max-w-none">
                    <ReactMarkdown
                        components={{
                            p: ({ children }) => <span className="leading-relaxed">{children}</span>,
                            strong: ({ children }) => <strong className="text-[#fbbf24] font-semibold">{children}</strong>,
                            code: ({ children }) => (
                                <code className="bg-[#21262d] border border-[#30363d] px-1.5 py-0.5 rounded text-[#58a6ff] text-sm font-mono">
                                    {children}
                                </code>
                            ),
                        }}
                    >
                        {cleanMarkdown(step.explanation)}
                    </ReactMarkdown>
                </div>
            )}

            {/* Tool Download Links Footer */}
            <ToolLinksFooter tools={detectedTools} />
        </div>
    );
};

export default AttackStepCard;

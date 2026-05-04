/**
 * SecurityReportSummary Component
 * Location: src/components/chat/SecurityReportSummary.tsx
 *
 * Renders a beautifully styled report summary in the chat after
 * report generation completes. Matches GitHub-dark styling.
 */

import React from 'react';

// ============ TYPES ============
export interface ReportSummaryData {
    domain: string;
    date: string;
    executiveSummary?: string;
    totalFindings: number;
    highRiskCount: number;
    mediumRiskCount: number;
    lowRiskCount: number;
    keyConcerns?: Array<{
        count: number;
        text: string;
        highlight: string;
    }>;
    attackPaths: Array<{
        title: string;
        risk: 'Critical' | 'High' | 'Medium' | 'Low';
        count: number;
    }>;
}

// ============ TEXT PROCESSING ============
/**
 * Clean up text from RAG model - fix duplicate words and common grammar issues
 */
const cleanupText = (text: string): string => {
    if (!text) return text;

    // Fix duplicate consecutive words (like "criticalcritical" -> "critical")
    let cleaned = text.replace(/\b(\w+)\1\b/gi, '$1');

    // Fix "a" vs "an" before vowels
    cleaned = cleaned.replace(/\ba\s+([aeiouAEIOU])/g, 'an $1');

    return cleaned;
};

/**
 * Apply color-coding to risk level mentions in text (consistent with UnifiedAttackPathReport)
 * Also handles markdown bold syntax (**text**)
 */
const colorCodeRiskLevels = (text: string): React.ReactNode[] => {
    if (!text) return [];

    // Clean up text first (fix duplicate words, etc.)
    let cleanedText = cleanupText(text);

    // First, process markdown bold syntax (**text**) separately
    // Split on **text** patterns and process each segment
    const segments = cleanedText.split(/(\*\*[^*]+\*\*)/g);

    const result: React.ReactNode[] = [];

    segments.forEach((segment, segmentIndex) => {
        // Check if this is a markdown bold segment
        if (segment.startsWith('**') && segment.endsWith('**')) {
            const boldText = segment.slice(2, -2);
            // Check if bold text contains risk keywords for color-coding
            if (/\bhigh[- ]risk\b/i.test(boldText)) {
                result.push(
                    <strong key={`bold-${segmentIndex}`} className="text-red-400 font-semibold">
                        {boldText}
                    </strong>
                );
            } else if (/\bmedium[- ]risk\b/i.test(boldText)) {
                result.push(
                    <strong key={`bold-${segmentIndex}`} className="text-yellow-400 font-semibold">
                        {boldText}
                    </strong>
                );
            } else if (/\blow[- ]risk\b/i.test(boldText)) {
                result.push(
                    <strong key={`bold-${segmentIndex}`} className="text-green-400 font-semibold">
                        {boldText}
                    </strong>
                );
            } else if (/\bcritical\b/i.test(boldText)) {
                result.push(
                    <strong key={`bold-${segmentIndex}`} className="text-red-500 font-bold">
                        {boldText}
                    </strong>
                );
            } else {
                // Just bold, no color coding
                result.push(
                    <strong key={`bold-${segmentIndex}`} className="text-[#c9d1d9] font-semibold">
                        {boldText}
                    </strong>
                );
            }
        } else if (segment) {
            // Regular text - apply risk-level color-coding
            const colorCodedSegment = applyRiskColorCoding(segment, segmentIndex);
            result.push(...colorCodedSegment);
        }
    });

    return result.length > 0 ? result : [cleanedText];
};

/**
 * Apply risk-level color-coding to a text segment (no markdown)
 */
const applyRiskColorCoding = (text: string, keyPrefix: number): React.ReactNode[] => {
    if (!text) return [];

    // Pattern to match risk level mentions
    const patterns = [
        // Match "X categorized as [risk] risk" or "X as [risk] risk"
        { regex: /(\d+)\s+(?:categorized\s+)?as\s+(critical)\s+risk/gi, color: 'text-red-500', weight: 'font-bold' },
        { regex: /(\d+)\s+(?:categorized\s+)?as\s+(high)\s+risk/gi, color: 'text-red-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(?:categorized\s+)?as\s+(medium)\s+risk/gi, color: 'text-yellow-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(?:categorized\s+)?as\s+(low)\s+risk/gi, color: 'text-green-400', weight: 'font-semibold' },
        // Match "X [risk]-risk" or "X [risk] risk" patterns
        { regex: /(\d+)\s+(critical)[- ]risk/gi, color: 'text-red-500', weight: 'font-bold' },
        { regex: /(\d+)\s+(high)[- ]risk/gi, color: 'text-red-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(medium)[- ]risk/gi, color: 'text-yellow-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(low)[- ]risk/gi, color: 'text-green-400', weight: 'font-semibold' },
        // Match "X [risk] findings"
        { regex: /(\d+)\s+(critical)\s+findings?/gi, color: 'text-red-500', weight: 'font-bold' },
        { regex: /(\d+)\s+(high)\s+findings?/gi, color: 'text-red-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(medium)\s+findings?/gi, color: 'text-yellow-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(low)\s+findings?/gi, color: 'text-green-400', weight: 'font-semibold' },
        // Match standalone risk words with context
        { regex: /\b(critical)\s+(risk|severity|finding|vulnerability)/gi, color: 'text-red-500', weight: 'font-bold' },
        { regex: /\b(high)\s+(risk|severity|finding|vulnerability)/gi, color: 'text-red-400', weight: 'font-semibold' },
        { regex: /\b(medium)\s+(risk|severity|finding|vulnerability)/gi, color: 'text-yellow-400', weight: 'font-semibold' },
        { regex: /\b(low)\s+(risk|severity|finding|vulnerability)/gi, color: 'text-green-400', weight: 'font-semibold' },
    ];

    interface MatchInfo {
        start: number;
        end: number;
        text: string;
        color?: string;
        weight: string;
    }

    const matches: MatchInfo[] = [];

    // Find risk-level matches
    for (const { regex, color, weight } of patterns) {
        let match;
        const regexCopy = new RegExp(regex.source, regex.flags);
        while ((match = regexCopy.exec(text)) !== null) {
            matches.push({
                start: match.index,
                end: match.index + match[0].length,
                text: match[0],
                color,
                weight,
            });
        }
    }

    // Find "total of X findings" patterns for bold styling
    const totalPatterns = [
        /total\s+of\s+(\d+)\s+(?:security\s+)?findings?/gi,
        /identified\s+(\d+)\s+(?:attack\s+)?findings?/gi,
        /(\d+)\s+total\s+findings?/gi,
    ];

    for (const pattern of totalPatterns) {
        let match;
        const regexCopy = new RegExp(pattern.source, pattern.flags);
        while ((match = regexCopy.exec(text)) !== null) {
            const isOverlapping = matches.some(
                m => (match!.index >= m.start && match!.index < m.end) ||
                    (match!.index + match![0].length > m.start && match!.index + match![0].length <= m.end)
            );
            if (!isOverlapping) {
                matches.push({
                    start: match.index,
                    end: match.index + match[0].length,
                    text: match[0],
                    weight: 'font-bold',
                });
            }
        }
    }

    // Sort matches by position
    matches.sort((a, b) => a.start - b.start);

    // Remove overlapping matches
    const filteredMatches: MatchInfo[] = [];
    for (const match of matches) {
        const isOverlapping = filteredMatches.some(
            m => (match.start >= m.start && match.start < m.end) ||
                (match.end > m.start && match.end <= m.end)
        );
        if (!isOverlapping) {
            filteredMatches.push(match);
        }
    }

    // Build result array
    const result: React.ReactNode[] = [];
    let lastEnd = 0;

    for (let i = 0; i < filteredMatches.length; i++) {
        const match = filteredMatches[i];

        if (match.start > lastEnd) {
            result.push(text.slice(lastEnd, match.start));
        }

        if (match.color) {
            result.push(
                <span key={`${keyPrefix}-match-${i}`} className={`${match.color} ${match.weight}`}>
                    {match.text}
                </span>
            );
        } else {
            result.push(
                <strong key={`${keyPrefix}-match-${i}`} className={`text-[#c9d1d9] ${match.weight}`}>
                    {match.text}
                </strong>
            );
        }

        lastEnd = match.end;
    }

    if (lastEnd < text.length) {
        result.push(text.slice(lastEnd));
    }

    return result.length > 0 ? result : [text];
};

interface SecurityReportSummaryProps {
    data: ReportSummaryData;
    onViewReport?: () => void;  // Kept for future use if needed
}

// ============ RISK BADGE ============
/**
 * Displays severity level badge for attack paths.
 * Severity is based on: attack complexity, business impact, and exploitability.
 * - Critical: Direct path to domain admin, requires minimal steps
 * - High: Path to high-value targets with few prerequisites
 * - Medium: Exploitable with moderate complexity
 * - Low: Informational or requires extensive prerequisites
 */
const RiskBadge: React.FC<{ level: string }> = ({ level }) => {
    const config: Record<string, { bg: string; tooltip: string }> = {
        critical: {
            bg: 'bg-red-600',
            tooltip: 'Direct path to domain compromise with minimal steps'
        },
        high: {
            bg: 'bg-orange-500',
            tooltip: 'Path to high-value targets with few prerequisites'
        },
        medium: {
            bg: 'bg-yellow-600',
            tooltip: 'Exploitable with moderate complexity'
        },
        low: {
            bg: 'bg-green-500',
            tooltip: 'Informational or requires extensive prerequisites'
        },
    };

    const style = config[level.toLowerCase()] || config.medium;

    return (
        <span
            className={`inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-bold uppercase tracking-wide ${style.bg} text-white cursor-help`}
            title={style.tooltip}
        >
            {level}
        </span>
    );
};

// ============ FINDING ROW ============
const FindingCard: React.FC<{
    number: number;
    title: string;
    risk: string;
    count: number;
}> = ({ number, title, risk, count }) => {
    return (
        <div className="flex items-center justify-between gap-3 py-3 border-b border-[#21262d] last:border-b-0">
            <div className="flex items-center gap-3 flex-1 min-w-0">
                <span className="w-5 h-5 rounded flex items-center justify-center text-xs font-medium text-[#6e7681]">
                    {number}
                </span>
                <RiskBadge level={risk} />
                <p className="text-sm text-[#c9d1d9] truncate">
                    {title}
                </p>
            </div>
            <div className="flex items-center gap-1.5 flex-shrink-0">
                <span className="text-sm font-semibold text-[#c9d1d9]">{count}</span>
                <span className="text-xs text-[#6e7681]">findings</span>
            </div>
        </div>
    );
};

// ============ SUGGESTION CHIP ============
// const SuggestionChip: React.FC<{ text: string }> = ({ text }) => (
//     <button className="px-3 py-1.5 bg-[#21262d] hover:bg-[#30363d] border border-[#30363d] hover:border-[#8b949e]/50 rounded-lg text-xs text-[#8b949e] hover:text-[#c9d1d9] transition-all duration-150">
//         {text}
//     </button>
// );

// ============ MAIN COMPONENT ============
const SecurityReportSummary: React.FC<SecurityReportSummaryProps> = ({
    data,
    onViewReport: _onViewReport  // Kept for potential future use
}) => {
    // Parse executive summary into paragraphs and key concerns
    const parsedSummary = React.useMemo(() => {
        if (!data.executiveSummary) return { paragraphs: [], concerns: [] };

        const lines = data.executiveSummary.split('\n').filter(l => l.trim());
        const paragraphs: string[] = [];
        const concerns: string[] = [];

        let inList = false;
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('-') || trimmed.startsWith('•') || trimmed.match(/^\d+\./)) {
                inList = true;
                concerns.push(trimmed.replace(/^[-•\d.]\s*/, ''));
            } else if (trimmed.length > 0) {
                if (!inList) {
                    paragraphs.push(trimmed);
                }
            }
        }

        return { paragraphs, concerns };
    }, [data.executiveSummary]);

    // Count paths by severity level
    const criticalPathCount = data.attackPaths.filter(p => p.risk.toLowerCase() === 'critical').length;
    const highPathCount = data.attackPaths.filter(p => p.risk.toLowerCase() === 'high').length;
    const mediumPathCount = data.attackPaths.filter(p => p.risk.toLowerCase() === 'medium').length;
    const lowPathCount = data.attackPaths.filter(p => p.risk.toLowerCase() === 'low').length;

    // Build severity summary text
    const getSeveritySummary = () => {
        const parts: string[] = [];
        if (criticalPathCount > 0) parts.push(`${criticalPathCount} critical`);
        if (highPathCount > 0) parts.push(`${highPathCount} high`);
        if (mediumPathCount > 0) parts.push(`${mediumPathCount} medium`);
        if (lowPathCount > 0) parts.push(`${lowPathCount} low`);
        if (parts.length === 0) return `${data.attackPaths.length} path${data.attackPaths.length !== 1 ? 's' : ''}`;
        return parts.join(', ') + ' severity';
    };

    return (
        <div className="max-w-[720px] font-sans">
            {/* Header */}
            <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#2ea043]/20 to-[#2ea043]/10 border border-[#2ea043]/30 flex items-center justify-center">
                    <svg className="w-5 h-5 text-[#2ea043]" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                </div>
                <div>
                    <h1 className="text-lg font-semibold text-[#c9d1d9] m-0">
                        Security Analysis Complete
                    </h1>
                    <p className="text-[13px] text-[#6e7681] m-0">
                        {data.domain} • {data.date}
                    </p>
                </div>
            </div>

            {/* Executive Summary */}
            <div className="mb-6">
                <h2 className="text-[15px] font-semibold text-[#c9d1d9] mb-3">
                    Executive Summary
                </h2>
                <div className="flex flex-col gap-3">
                    {/* Main paragraphs with risk-level color-coding */}
                    {parsedSummary.paragraphs.slice(0, 2).map((p, i) => (
                        <p key={i} className="text-sm text-[#8b949e] leading-relaxed m-0">
                            {colorCodeRiskLevels(p)}
                        </p>
                    ))}
                </div>

                {/* Key Concerns */}
                {(data.keyConcerns && data.keyConcerns.length > 0) ? (
                    <div className="mt-4">
                        <p className="text-[13px] font-semibold text-[#8b949e] mb-2.5">
                            Key Concerns:
                        </p>
                        <ul className="m-0 pl-[18px] flex flex-col gap-1.5">
                            {data.keyConcerns.map((item, i) => (
                                <li key={i} className="text-[13px] text-[#8b949e] leading-snug">
                                    <span className="text-[#c9d1d9] font-semibold">{item.count}</span> {item.text} — <span className="text-[#6e7681]">{item.highlight}</span>
                                </li>
                            ))}
                        </ul>
                    </div>
                ) : parsedSummary.concerns.length > 0 && (
                    <div className="mt-4">
                        <p className="text-[13px] font-semibold text-[#8b949e] mb-2.5">
                            Key Concerns:
                        </p>
                        <ul className="m-0 pl-[18px] flex flex-col gap-1.5">
                            {parsedSummary.concerns.slice(0, 4).map((concern, i) => (
                                <li key={i} className="text-[13px] text-[#8b949e] leading-snug">
                                    {colorCodeRiskLevels(concern)}
                                </li>
                            ))}
                        </ul>
                    </div>
                )}

                {/* Recommendation Alert */}
                <div className="mt-4 p-3 bg-[#f85149]/8 rounded-lg border border-[#f85149]/20 flex items-start gap-2.5">
                    <svg className="w-4 h-4 text-[#f85149] flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <p className="text-[13px] text-[#f85149] leading-snug m-0">
                        <strong>Immediate action required:</strong> Prioritize remediation on tier-zero assets to disrupt identified attack paths and prevent rapid domain compromise.
                    </p>
                </div>
            </div>

            {/* Attack Paths */}
            {data.attackPaths.length > 0 && (
                <div className="mb-5">
                    <div className="flex items-center justify-between mb-3">
                        <h2 className="text-sm font-semibold text-[#8b949e] uppercase tracking-wide m-0">
                            Attack Paths Identified
                        </h2>
                        <span className="text-xs text-[#6e7681]" title="Severity based on attack complexity and business impact">
                            {getSeveritySummary()}
                        </span>
                    </div>

                    <div className="flex flex-col">
                        {data.attackPaths.slice(0, 5).map((path, index) => (
                            <FindingCard
                                key={index}
                                number={index + 1}
                                title={path.title}
                                risk={path.risk}
                                count={path.count}
                            />
                        ))}
                        {data.attackPaths.length > 5 && (
                            <p className="text-xs text-[#6e7681] text-center pt-2">
                                ...and {data.attackPaths.length - 5} more paths
                            </p>
                        )}
                    </div>
                </div>
            )}

            {/* Try Asking Suggestions */}
            {/* <div className="mb-3">
                <p className="text-[13px] text-[#6e7681] mb-2.5">
                    Try asking:
                </p>
                <div className="flex flex-wrap gap-2">
                    <SuggestionChip text="How do I remediate Kerberoasting?" />
                    <SuggestionChip text="Show paths to Domain Admins" />
                    <SuggestionChip text="What are the most critical attack paths?" />
                </div>
            </div> */}
        </div>
    );
};

export default SecurityReportSummary;

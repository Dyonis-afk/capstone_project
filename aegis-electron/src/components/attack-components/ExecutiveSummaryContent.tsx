/**
 * ExecutiveSummaryContent Component
 * Location: src/components/attack-components/ExecutiveSummaryContent.tsx
 *
 * Renders the executive summary with color-coded risk levels:
 * - Total findings count: bold
 * - High risk: red
 * - Medium risk: yellow
 * - Low risk: green
 * - Critical risk: red (darker)
 */

import React from 'react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface ExecutiveSummaryContentProps {
    content: string;
}

/**
 * Parse and apply color-coding to risk level mentions in text
 */
const colorCodeRiskLevels = (text: string): React.ReactNode[] => {
    if (!text) return [];

    // Pattern to match risk level mentions in various formats:
    // "50 categorized as high risk", "2 as medium risk", "20 as low risk"
    // "X high-risk", "X critical findings", "2 critical and 0 high severity"
    // "X critical", "X high severity findings"
    const patterns = [
        // Match "X categorized as [risk] risk" or "X as [risk] risk"
        { regex: /(\d+)\s+(?:categorized\s+)?as\s+(critical)\s+risk/gi, color: 'text-red-500', weight: 'font-bold' },
        { regex: /(\d+)\s+(?:categorized\s+)?as\s+(high)\s+risk/gi, color: 'text-red-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(?:categorized\s+)?as\s+(medium)\s+risk/gi, color: 'text-yellow-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(?:categorized\s+)?as\s+(low)\s+risk/gi, color: 'text-green-400', weight: 'font-semibold' },
        // Match "X [risk]-risk" patterns
        { regex: /(\d+)\s+(critical)[- ]risk/gi, color: 'text-red-500', weight: 'font-bold' },
        { regex: /(\d+)\s+(high)[- ]risk/gi, color: 'text-red-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(medium)[- ]risk/gi, color: 'text-yellow-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(low)[- ]risk/gi, color: 'text-green-400', weight: 'font-semibold' },
        // Match "X [risk] findings" or "X [risk] severity findings"
        { regex: /(\d+)\s+(critical)\s+(?:severity\s+)?findings?/gi, color: 'text-red-500', weight: 'font-bold' },
        { regex: /(\d+)\s+(high)\s+(?:severity\s+)?findings?/gi, color: 'text-red-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(medium)\s+(?:severity\s+)?findings?/gi, color: 'text-yellow-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(low)\s+(?:severity\s+)?findings?/gi, color: 'text-green-400', weight: 'font-semibold' },
        // Match "X critical and Y high" patterns (common in executive summaries)
        { regex: /(\d+)\s+(critical)\s+and/gi, color: 'text-red-500', weight: 'font-bold' },
        { regex: /(\d+)\s+(high)\s+(?:severity|and)/gi, color: 'text-red-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(medium)\s+(?:severity|and)/gi, color: 'text-yellow-400', weight: 'font-semibold' },
        { regex: /(\d+)\s+(low)\s+(?:severity|and)/gi, color: 'text-green-400', weight: 'font-semibold' },
        // Match standalone "X [risk]" at word boundary (e.g., "with 2 critical")
        { regex: /\b(\d+)\s+(critical)\b(?!\s+(?:and|attack))/gi, color: 'text-red-500', weight: 'font-bold' },
        { regex: /\b(\d+)\s+(high)\b(?!\s+(?:and|attack|value))/gi, color: 'text-red-400', weight: 'font-semibold' },
    ];

    // First, collect all matches with their positions
    interface MatchInfo {
        start: number;
        end: number;
        text: string;
        color?: string;
        weight: string;
        isTotalFindings: boolean;
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
                isTotalFindings: false,
            });
        }
    }

    // Find "total of X findings" patterns for bold styling
    const totalPatterns = [
        /total\s+of\s+(\d+)\s+findings?/gi,
        /identified\s+(\d+)\s+(?:attack\s+)?findings?/gi,
        /(\d+)\s+total\s+findings?/gi,
    ];

    for (const pattern of totalPatterns) {
        let match;
        const regexCopy = new RegExp(pattern.source, pattern.flags);
        while ((match = regexCopy.exec(text)) !== null) {
            // Check if this position is already matched by a risk pattern
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
                    isTotalFindings: true,
                });
            }
        }
    }

    // Sort matches by position
    matches.sort((a, b) => a.start - b.start);

    // Remove overlapping matches (keep the first one)
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

        // Add text before this match
        if (match.start > lastEnd) {
            result.push(text.slice(lastEnd, match.start));
        }

        // Add the styled match
        if (match.color) {
            result.push(
                <span key={`match-${i}`} className={`${match.color} ${match.weight}`}>
                    {match.text}
                </span>
            );
        } else {
            result.push(
                <strong key={`match-${i}`} className={`text-white ${match.weight}`}>
                    {match.text}
                </strong>
            );
        }

        lastEnd = match.end;
    }

    // Add remaining text
    if (lastEnd < text.length) {
        result.push(text.slice(lastEnd));
    }

    return result.length > 0 ? result : [text];
};

/**
 * Custom paragraph renderer that applies color-coding to risk levels
 */
const ColorCodedParagraph: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    // Process each text child for color-coding
    const processChildren = (nodes: React.ReactNode): React.ReactNode => {
        return React.Children.map(nodes, (child) => {
            if (typeof child === 'string') {
                return colorCodeRiskLevels(child);
            }
            if (React.isValidElement<{ children?: React.ReactNode }>(child) && child.props.children) {
                return React.cloneElement(child, {
                    children: processChildren(child.props.children),
                });
            }
            return child;
        });
    };

    return (
        <p className="text-[#c9d1d9] mb-4 leading-relaxed">
            {processChildren(children)}
        </p>
    );
};

const ExecutiveSummaryContent: React.FC<ExecutiveSummaryContentProps> = ({ content }) => {
    if (!content) return null;

    return (
        <div className="prose prose-invert max-w-none">
            <ReactMarkdown
                components={{
                    h1: ({ node, ...props }) => <h1 className="text-2xl font-semibold text-white mt-0 mb-4" {...props} />,
                    h2: ({ node, ...props }) => <h2 className="text-xl font-semibold text-white mt-8 mb-4" {...props} />,
                    h3: ({ node, ...props }) => <h3 className="text-lg font-semibold text-white mt-6 mb-3" {...props} />,
                    p: ({ children }) => (
                        <ColorCodedParagraph>{children}</ColorCodedParagraph>
                    ),
                    ul: ({ node, ...props }) => <ul className="my-4 ml-4 space-y-2" {...props} />,
                    li: ({ node, children, ...props }) => (
                        <li className="text-[#c9d1d9] leading-relaxed flex items-start gap-2" {...props}>
                            <span className="text-[#c9d1d9] mt-0.5">•</span>
                            <span className="flex-1">{children}</span>
                        </li>
                    ),
                    strong: ({ node, ...props }) => <strong className="text-white font-bold" {...props} />,
                    code: ({ node, inline, className, children, ...props }: any) => {
                        if (inline) {
                            return (
                                <code className="bg-[#21262d] border border-[#30363d] px-1.5 py-0.5 rounded text-[#58a6ff] text-sm font-mono" {...props}>
                                    {children}
                                </code>
                            );
                        }
                        const match = /language-(\w+)/.exec(className || '');
                        const language = match ? match[1] : 'text';
                        return (
                            <div className="my-4 rounded-lg overflow-hidden border border-aegis-border max-w-full">
                                <div className="bg-aegis-gray/50 px-4 py-2 border-b border-aegis-border">
                                    <span className="text-xs font-mono text-aegis-text-muted uppercase">{language}</span>
                                </div>
                                <div className="overflow-x-auto">
                                    <SyntaxHighlighter
                                        language={language}
                                        style={vscDarkPlus}
                                        customStyle={{
                                            margin: 0,
                                            padding: '1.25rem',
                                            backgroundColor: '#1a1d23',
                                            fontSize: '0.8125rem',
                                            lineHeight: '1.5',
                                            overflowX: 'auto',
                                            wordBreak: 'break-word',
                                            whiteSpace: 'pre-wrap',
                                        }}
                                        wrapLongLines={true}
                                        showLineNumbers={false}
                                    >
                                        {String(children).replace(/\n$/, '')}
                                    </SyntaxHighlighter>
                                </div>
                            </div>
                        );
                    },
                }}
            >
                {content}
            </ReactMarkdown>
        </div>
    );
};

export default ExecutiveSummaryContent;

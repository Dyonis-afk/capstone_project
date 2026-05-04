/**
 * Cypher Query Display Component
 * Location: src/components/attack-components/CypherQueryDisplay.tsx
 *
 * Displays Cypher queries with syntax highlighting and copy functionality
 * Redesigned for cleaner UI with single copy button and toast notifications
 */

import React, { useState } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import toast from 'react-hot-toast';

interface CypherQueryDisplayProps {
    query: string;
    queryName: string;
    description?: string;
    edgesUsed?: string[];
    onCopy?: (text: string) => void;
}

const CypherQueryDisplay: React.FC<CypherQueryDisplayProps> = ({
    query,
    queryName,
    description,
    edgesUsed,
    onCopy
}) => {
    const [isExpanded, setIsExpanded] = useState(true);

    if (!query) return null;

    // Clean up the query for better display
    const formattedQuery = query
        .replace(/\s+/g, ' ')
        .trim()
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0)
        .join('\n');

    const handleCopy = async (e: React.MouseEvent) => {
        e.stopPropagation();
        try {
            await navigator.clipboard.writeText(query);
            toast.success('Query copied to clipboard');
            onCopy?.(query);
        } catch (err) {
            toast.error('Failed to copy query');
        }
    };

    return (
        <div className="border border-aegis-border rounded-lg overflow-hidden bg-aegis-gray">
            {/* Header - Always visible */}
            <div
                className="flex items-center justify-between px-4 py-3 cursor-pointer hover:bg-aegis-gray-hover transition-colors"
                onClick={() => setIsExpanded(!isExpanded)}
            >
                <div className="flex items-center gap-3 min-w-0 flex-1">
                    {/* Query Icon */}
                    <div className="shrink-0 w-8 h-8 rounded-lg bg-aegis-accent/10 flex items-center justify-center">
                        <svg className="w-4 h-4 text-aegis-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                        </svg>
                    </div>

                    {/* Query Name & Description */}
                    <div className="min-w-0 flex-1">
                        <h4 className="font-medium text-aegis-text text-sm truncate">{queryName}</h4>
                        {description && (
                            <p className="text-aegis-text-muted text-xs mt-0.5 truncate">{description}</p>
                        )}
                    </div>
                </div>

                {/* Right side actions */}
                <div className="flex items-center gap-1 shrink-0 ml-3">
                    {/* Copy Button */}
                    <button
                        onClick={handleCopy}
                        className="p-2 rounded-lg text-aegis-text-muted hover:text-aegis-accent hover:bg-aegis-gray-light transition-colors"
                        title="Copy query to clipboard"
                    >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                    </button>

                    {/* Expand/Collapse Icon */}
                    <div className="p-2">
                        <svg
                            className={`w-4 h-4 text-aegis-text-muted transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                        >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                        </svg>
                    </div>
                </div>
            </div>

            {/* Expandable Content */}
            {isExpanded && (
                <div className="border-t border-aegis-border">
                    {/* Code Block */}
                    <div className="relative overflow-hidden">
                        <SyntaxHighlighter
                            language="cypher"
                            style={vscDarkPlus}
                            wrapLongLines={true}
                            customStyle={{
                                margin: 0,
                                padding: '1rem',
                                backgroundColor: '#0d1117',
                                fontSize: '0.875rem',
                                lineHeight: '1.6',
                                borderRadius: 0,
                            }}
                            codeTagProps={{
                                style: {
                                    whiteSpace: 'pre-wrap',
                                    wordBreak: 'break-word',
                                    overflowWrap: 'break-word',
                                }
                            }}
                        >
                            {formattedQuery}
                        </SyntaxHighlighter>
                    </div>

                    {/* Footer - BloodHound Link & Relationships */}
                    <div className="px-4 py-2.5 bg-aegis-darker border-t border-aegis-border flex items-center justify-between flex-wrap gap-2">
                        {/* BloodHound Link */}
                        <a
                            href="http://localhost:8080"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-2 text-xs text-aegis-text-muted hover:text-aegis-accent transition-colors group"
                        >
                            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                            </svg>
                            <span>Run in BloodHound CE</span>
                            <code className="text-aegis-accent group-hover:underline">localhost:8080</code>
                        </a>

                        {/* Relationship Types */}
                        {edgesUsed && edgesUsed.length > 0 && (
                            <div className="flex items-center gap-2 text-xs">
                                <span className="text-aegis-text-subtle">Relationships:</span>
                                <div className="flex flex-wrap gap-1">
                                    {edgesUsed.slice(0, 4).map((edge, idx) => (
                                        <span
                                            key={idx}
                                            className="px-1.5 py-0.5 bg-aegis-gray-light text-aegis-text-muted rounded font-mono text-[10px]"
                                        >
                                            {edge}
                                        </span>
                                    ))}
                                    {edgesUsed.length > 4 && (
                                        <span className="text-aegis-text-subtle">+{edgesUsed.length - 4}</span>
                                    )}
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
};

export default CypherQueryDisplay;

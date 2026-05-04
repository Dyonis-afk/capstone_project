/**
 * Markdown Content Component
 * Location: src/components/attack-components/MarkdownContent.tsx
 *
 * Renders markdown content with custom styling for security reports
 */

import React from 'react';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface MarkdownContentProps {
    content: string;
}

/**
 * Clean up malformed markdown from RAG output
 * Fixes common issues like incomplete bold markers, orphaned asterisks,
 * and spaces inside bold markers (e.g., "** text **" -> "**text**")
 */
const cleanMarkdown = (text: string): string => {
    if (!text) return text;

    let cleaned = text;

    // === FIX BOLD MARKERS WITH INTERNAL SPACES FIRST ===
    cleaned = cleaned.replace(/\*\*\s+([^*]+?)\s+\*\*/g, '**$1**');
    cleaned = cleaned.replace(/\*\*\s+([^*]+?)\*\*/g, '**$1**');
    cleaned = cleaned.replace(/\*\*([^*]+?)\s+\*\*/g, '**$1**');

    // === CRITICAL FIX: Add spacing around bold blocks ===
    // Process left-to-right to avoid matching across multiple bold blocks
    const boldRegex = /\*\*([^*]+|\*[^*])+\*\*/g;
    let result = '';
    let lastIndex = 0;
    let match;

    while ((match = boldRegex.exec(cleaned)) !== null) {
        const beforeMatch = cleaned.slice(lastIndex, match.index);
        result += beforeMatch;

        // Add space before if preceded by word char
        if (result.length > 0 && /[a-zA-Z0-9]$/.test(result)) {
            result += ' ';
        }

        result += match[0];

        // Add space after if followed by word char
        const afterIndex = match.index + match[0].length;
        if (afterIndex < cleaned.length && /^[a-zA-Z0-9]/.test(cleaned[afterIndex])) {
            result += ' ';
        }

        lastIndex = afterIndex;
    }

    result += cleaned.slice(lastIndex);
    cleaned = result || cleaned;

    // === FIX INCOMPLETE/ORPHANED BOLD MARKERS ===
    cleaned = cleaned.replace(/^([^*\n]+):\*\*\s*$/gm, '**$1:**');
    cleaned = cleaned.replace(/^(Step \d+[:\s]+[^*\n]+)\*\*\s*$/gm, '**$1**');
    cleaned = cleaned.replace(/\s+\*\*(?!\S)/g, '');
    cleaned = cleaned.replace(/\*\*\s+(?=[^*]*$)/g, '');
    cleaned = cleaned.replace(/^\*\*\s*$/gm, '');

    // Replace bullet characters with dashes
    cleaned = cleaned.replace(/^[•·]\s*/gm, '- ');

    // Fix single ** at end of line without matching start
    const lines = cleaned.split('\n');
    const fixedLines = lines.map(line => {
        const count = (line.match(/\*\*/g) || []).length;
        if (count === 1) {
            if (line.trimEnd().endsWith('**')) {
                return line.replace(/\*\*\s*$/, '');
            }
            if (line.trimStart().startsWith('**')) {
                return line.replace(/^\s*\*\*/, '');
            }
        }
        if (count % 2 !== 0 && count > 0) {
            const orphanedPattern = /(\s)\*\*(\s)(?![^*]*\*\*)/g;
            return line.replace(orphanedPattern, '$1$2');
        }
        return line;
    });
    cleaned = fixedLines.join('\n');

    // Remove empty ** **
    cleaned = cleaned.replace(/\*\*\s*\*\*/g, '');

    // Clean multiple blank lines
    cleaned = cleaned.replace(/\n{3,}/g, '\n\n');

    // === FINAL PASS: Ensure word boundaries around bold (simplified) ===
    // Add space after bold if followed by word char (handles "**ADMINS**group")
    cleaned = cleaned.replace(/\*\*([^*]+)\*\*(?=[a-zA-Z0-9])/g, '**$1** ');
    // Add space before bold if preceded by word char (handles "group**ADMINS**")
    cleaned = cleaned.replace(/([a-zA-Z0-9])\*\*([^*]+)\*\*/g, '$1 **$2**');

    // Clean up double/triple spaces (run after spacing fixes)
    cleaned = cleaned.replace(/\s{2,}/g, ' ');

    return cleaned.trim();
};

const MarkdownContent: React.FC<MarkdownContentProps> = ({ content }) => {
    // Clean the markdown before rendering
    const cleanedContent = cleanMarkdown(content);

    return (
    <div className="prose prose-invert max-w-none">
        <ReactMarkdown
            components={{
                h1: ({ node, ...props }) => <h1 className="text-2xl font-semibold text-white mt-0 mb-4" {...props} />,
                h2: ({ node, ...props }) => <h2 className="text-xl font-semibold text-white mt-8 mb-4" {...props} />,
                h3: ({ node, ...props }) => <h3 className="text-lg font-semibold text-white mt-6 mb-3" {...props} />,
                p: ({ node, ...props }) => <p className="text-aegis-text mb-4 leading-relaxed" {...props} />,
                ul: ({ node, ...props }) => <ul className="mb-4 space-y-2" {...props} />,
                li: ({ node, children, ...props }) => (
                    <li className="text-aegis-text leading-relaxed flex items-start gap-3" {...props}>
                        <span className="text-aegis-accent font-bold mt-1">•</span>
                        <span className="flex-1">{children}</span>
                    </li>
                ),
                code: ({ node, inline, className, children, ...props }: any) => {
                    const codeContent = String(children).replace(/\n$/, '');

                    // Check if this is actually inline-style content (short, single line, no newlines)
                    // LLMs sometimes use fenced blocks for what should be inline code
                    const isShortCode = !codeContent.includes('\n') && codeContent.length < 80;
                    const shouldRenderInline = inline || (isShortCode && !className);

                    if (shouldRenderInline) {
                        // Don't style domain names, usernames, and relationship types as code
                        // Check if it looks like a domain name, username, or relationship type
                        if (codeContent.includes('@') ||
                            codeContent.includes('.LOCAL') ||
                            codeContent.includes('.local') ||
                            codeContent.includes('.htb') ||
                            codeContent.match(/^\w+\/\w+/) ||
                            (codeContent.match(/^[A-Z_]+$/) && codeContent.length > 2 && codeContent.length < 30)) {
                            // Render as bold text instead of code for better readability
                            return <strong className="text-aegis-accent font-semibold">{children}</strong>;
                        }

                        return (
                            <code className="bg-[#21262d] border border-[#30363d] px-1.5 py-0.5 rounded text-[#58a6ff] text-sm font-mono break-all" {...props}>
                                {children}
                            </code>
                        );
                    }

                    const match = /language-(\w+)/.exec(className || '');
                    const language = match ? match[1] : 'text';

                    // For "text" language, use simpler styling without the language header
                    if (language === 'text' || !match) {
                        return (
                            <div className="my-4 rounded-lg overflow-hidden border border-[#30363d] max-w-full bg-[#0d1117]">
                                <div className="overflow-x-auto p-4">
                                    <code className="text-[#c9d1d9] text-sm font-mono whitespace-pre-wrap break-all">
                                        {codeContent}
                                    </code>
                                </div>
                            </div>
                        );
                    }

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
                                    {codeContent}
                                </SyntaxHighlighter>
                            </div>
                        </div>
                    );
                },
                // Handle pre blocks - wrap in div to prevent <pre> inside <p> HTML nesting error
                pre: ({ node, children, ...props }) => (
                    <div className="overflow-x-auto max-w-full">
                        <pre {...props}>{children}</pre>
                    </div>
                ),
                strong: ({ node, ...props }) => <strong className="text-white font-bold" {...props} />,
            }}
        >
            {cleanedContent}
        </ReactMarkdown>
    </div>
    );
};

export default MarkdownContent;

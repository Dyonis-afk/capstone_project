/**
 * SyntaxHighlightedScript Component
 * Location: src/components/attack-components/SyntaxHighlightedScript.tsx
 *
 * Renders code/scripts with proper syntax highlighting using Prism.
 * Supports PowerShell, Bash, Python, and other languages.
 * Handles command prompts (PS >, $, mimikatz #) with special styling.
 */

import React, { useState, useMemo } from 'react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface SyntaxHighlightedScriptProps {
    /** The code/script to display */
    code: string;
    /** Programming language for syntax highlighting (default: powershell) */
    language?: string;
    /** Optional title/label to show above the code */
    title?: string;
    /** Callback when copy button is clicked */
    onCopy?: (code: string) => void;
    /** Show line numbers (default: false) */
    showLineNumbers?: boolean;
    /** Maximum height before scrolling (default: none) */
    maxHeight?: string;
    /** Show command prompts with special styling (default: true) */
    showPrompts?: boolean;
}

/**
 * Detect language from code content if not specified
 */
const detectLanguage = (code: string): string => {
    const trimmed = code.trim().toLowerCase();

    // PowerShell indicators
    if (trimmed.includes('invoke-') ||
        trimmed.includes('get-') ||
        trimmed.includes('set-') ||
        trimmed.includes('$env:') ||
        trimmed.includes('$_') ||
        trimmed.includes('| where-object') ||
        trimmed.includes('| select-object') ||
        trimmed.includes('import-module') ||
        trimmed.includes('new-object system.')) {
        return 'powershell';
    }

    // Bash/Shell indicators
    if (trimmed.startsWith('#!/bin/') ||
        trimmed.includes('sudo ') ||
        trimmed.includes(' | grep ') ||
        trimmed.includes('impacket-') ||
        trimmed.includes('crackmapexec') ||
        trimmed.includes('certipy') ||
        trimmed.includes('bloodhound-python')) {
        return 'bash';
    }

    // Python indicators
    if (trimmed.includes('import ') && trimmed.includes('from ') ||
        trimmed.includes('def ') ||
        trimmed.includes('print(')) {
        return 'python';
    }

    // Default to powershell for AD/security context
    return 'powershell';
};

/**
 * Command prompt patterns to detect and style
 */
const PROMPT_PATTERNS = [
    { pattern: /^(PS\s*>\s*)/i, type: 'powershell' },
    { pattern: /^(PS\s+[A-Z]:\\[^>]*>\s*)/i, type: 'powershell' }, // PS C:\Users\admin>
    { pattern: /^(\$\s+)/i, type: 'bash' },
    { pattern: /^(mimikatz\s*#\s*)/i, type: 'mimikatz' },
    { pattern: /^(C:\\[^>]*>\s*)/i, type: 'cmd' }, // C:\Windows\system32>
];

interface ParsedLine {
    prompt?: string;
    promptType?: string;
    content: string;
    isComment: boolean;
    isEmpty: boolean;
}

/**
 * Parse a line to extract prompt, content, and metadata
 */
const parseLine = (line: string): ParsedLine => {
    const trimmed = line.trim();

    // Check if empty
    if (!trimmed) {
        return { content: '', isComment: false, isEmpty: true };
    }

    // Check if comment
    if (trimmed.startsWith('#')) {
        return { content: line, isComment: true, isEmpty: false };
    }

    // Check for prompts
    for (const { pattern, type } of PROMPT_PATTERNS) {
        const match = line.match(pattern);
        if (match) {
            return {
                prompt: match[1],
                promptType: type,
                content: line.slice(match[1].length),
                isComment: false,
                isEmpty: false
            };
        }
    }

    return { content: line, isComment: false, isEmpty: false };
};

/**
 * Clean up code - remove leading/trailing whitespace and normalize indentation
 */
const cleanCode = (code: string): string => {
    if (!code) return '';

    // Remove code fence markers if present
    let cleaned = code
        .replace(/^```\w*\n?/gm, '')
        .replace(/\n?```$/gm, '')
        .trim();

    // Find minimum indentation (excluding empty lines)
    const lines = cleaned.split('\n');
    const nonEmptyLines = lines.filter(line => line.trim().length > 0);

    if (nonEmptyLines.length === 0) return cleaned;

    const minIndent = Math.min(
        ...nonEmptyLines.map(line => {
            const match = line.match(/^(\s*)/);
            return match ? match[1].length : 0;
        })
    );

    // Remove common indentation
    if (minIndent > 0) {
        cleaned = lines
            .map(line => line.slice(minIndent))
            .join('\n');
    }

    return cleaned.trim();
};

/**
 * Extract code without prompts for copying
 */
const getCodeForCopy = (code: string): string => {
    const lines = code.split('\n');
    return lines.map(line => {
        for (const { pattern } of PROMPT_PATTERNS) {
            const match = line.match(pattern);
            if (match) {
                return line.slice(match[1].length);
            }
        }
        return line;
    }).join('\n');
};

const SyntaxHighlightedScript: React.FC<SyntaxHighlightedScriptProps> = ({
    code,
    language,
    onCopy,
    showLineNumbers = false,
    maxHeight,
    showPrompts = true
}) => {
    const [copied, setCopied] = useState(false);

    const cleanedCode = cleanCode(code);
    const detectedLanguage = language || detectLanguage(cleanedCode);

    // Parse lines to extract prompts
    const parsedLines = useMemo(() => {
        if (!showPrompts) return null;
        return cleanedCode.split('\n').map(parseLine);
    }, [cleanedCode, showPrompts]);

    // Check if code has prompts
    const hasPrompts = useMemo(() => {
        return parsedLines?.some(line => line.prompt) ?? false;
    }, [parsedLines]);

    const handleCopy = () => {
        // Copy without prompts for cleaner paste
        const codeToCopy = hasPrompts ? getCodeForCopy(cleanedCode) : cleanedCode;
        navigator.clipboard.writeText(codeToCopy);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
        onCopy?.(codeToCopy);
    };

    // Render with custom prompt styling
    const renderWithPrompts = () => {
        if (!parsedLines) return null;

        return (
            <div
                className="font-mono text-[0.8125rem] leading-[1.7] p-4 overflow-x-auto whitespace-pre-wrap break-words"
                style={{ backgroundColor: '#0d1117' }}
            >
                {parsedLines.map((line, index) => {
                    if (line.isEmpty) {
                        return <div key={index} className="h-[1.7em]">&nbsp;</div>;
                    }

                    if (line.isComment) {
                        return (
                            <div key={index} className="text-[#7ee787]">
                                {line.content}
                            </div>
                        );
                    }

                    if (line.prompt) {
                        return (
                            <div key={index} className="flex">
                                <span
                                    className="text-aegis-text-muted opacity-70 select-none flex-shrink-0"
                                    style={{ userSelect: 'none' }}
                                >
                                    {line.prompt}
                                </span>
                                <SyntaxHighlighter
                                    language={line.promptType === 'bash' ? 'bash' : 'powershell'}
                                    style={vscDarkPlus}
                                    customStyle={{
                                        margin: 0,
                                        padding: 0,
                                        backgroundColor: 'transparent',
                                        fontSize: 'inherit',
                                        lineHeight: 'inherit',
                                        display: 'inline',
                                    }}
                                    codeTagProps={{
                                        style: {
                                            fontFamily: 'inherit',
                                        }
                                    }}
                                    PreTag="span"
                                    wrapLongLines={true}
                                >
                                    {line.content}
                                </SyntaxHighlighter>
                            </div>
                        );
                    }

                    // Regular code line without prompt
                    return (
                        <div key={index}>
                            <SyntaxHighlighter
                                language={detectedLanguage}
                                style={vscDarkPlus}
                                customStyle={{
                                    margin: 0,
                                    padding: 0,
                                    backgroundColor: 'transparent',
                                    fontSize: 'inherit',
                                    lineHeight: 'inherit',
                                }}
                                codeTagProps={{
                                    style: {
                                        fontFamily: 'inherit',
                                    }
                                }}
                                PreTag="span"
                                wrapLongLines={true}
                            >
                                {line.content}
                            </SyntaxHighlighter>
                        </div>
                    );
                })}
            </div>
        );
    };

    return (
        <div className="overflow-hidden relative group">
            {/* Copy button - appears on hover */}
            <button
                onClick={handleCopy}
                className="absolute top-2 right-2 z-10 flex items-center gap-1.5 px-2 py-1 text-xs text-aegis-text-muted hover:text-aegis-text bg-aegis-gray-light hover:bg-aegis-border rounded opacity-0 group-hover:opacity-100 transition-opacity"
                title="Copy code (without prompts)"
            >
                {copied ? (
                    <>
                        <svg className="w-3.5 h-3.5 text-aegis-success-light" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                        <span>Copied!</span>
                    </>
                ) : (
                    <>
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                        <span>Copy</span>
                    </>
                )}
            </button>

            {/* Code content with syntax highlighting */}
            <div
                className="overflow-auto"
                style={maxHeight ? { maxHeight } : undefined}
            >
                {hasPrompts && showPrompts ? (
                    renderWithPrompts()
                ) : (
                    <SyntaxHighlighter
                        language={detectedLanguage}
                        style={vscDarkPlus}
                        showLineNumbers={showLineNumbers}
                        customStyle={{
                            margin: 0,
                            padding: '1rem',
                            backgroundColor: '#0d1117',
                            fontSize: '0.8125rem',
                            lineHeight: '1.6',
                        }}
                        codeTagProps={{
                            style: {
                                fontFamily: "'SF Mono', 'Fira Code', 'Consolas', monospace",
                            }
                        }}
                        wrapLongLines={true}
                    >
                        {cleanedCode}
                    </SyntaxHighlighter>
                )}
            </div>
        </div>
    );
};

export default SyntaxHighlightedScript;

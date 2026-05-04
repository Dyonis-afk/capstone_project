/**
 * AttackExplainer Component
 * Location: src/components/attack-components/AttackExplainer.tsx
 *
 * Renders Q&A style explanation for understanding attacks.
 * Format: "What is X?", "Why is it dangerous?", "How does it apply here?"
 */

import React from 'react';
import ReactMarkdown from 'react-markdown';
import { AttackExplanation } from './types';

interface AttackExplainerProps {
    explanations: AttackExplanation[];
}

/**
 * Clean up malformed markdown from RAG output
 * Fixes bold markers with spaces like "** text **" -> "**text**"
 * Also ensures proper spacing around bold text
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

const AttackExplainer: React.FC<AttackExplainerProps> = ({ explanations }) => {
    if (!explanations || explanations.length === 0) {
        return null;
    }

    return (
        <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden mb-6">
            {explanations.map((explanation, index) => (
                <React.Fragment key={index}>
                <div className="p-4">
                    <div className="text-[#58a6ff] font-semibold mb-2 text-[15px]">
                        <ReactMarkdown
                            components={{
                                strong: ({ children }) => (
                                    <strong className="text-[#fbbf24] font-semibold">{children}</strong>
                                ),
                                p: ({ children }) => <span>{children}</span>,
                            }}
                        >
                            {cleanMarkdown(explanation.question)}
                        </ReactMarkdown>
                    </div>
                    <div className="text-[#c9d1d9] leading-relaxed text-[15px] prose prose-invert prose-sm max-w-none">
                        <ReactMarkdown
                            components={{
                                strong: ({ children }) => (
                                    <strong className="text-[#fbbf24] font-semibold">{children}</strong>
                                ),
                                p: ({ children }) => <span>{children}</span>,
                            }}
                        >
                            {cleanMarkdown(explanation.answer)}
                        </ReactMarkdown>
                    </div>
                </div>
                {index < explanations.length - 1 && (
                    <div className="mx-4 h-px bg-[#30363d]" />
                )}
                </React.Fragment>
            ))}
        </div>
    );
};

export default AttackExplainer;

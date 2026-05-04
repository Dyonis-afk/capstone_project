/**
 * DetectionMonitoring Component
 * Location: src/components/attack-components/DetectionMonitoring.tsx
 *
 * Renders detection and monitoring section with:
 * - Event IDs to monitor
 * - Indicators of Compromise
 * - Proactive Measures
 * - Detection Queries (Splunk, KQL)
 */

import React, { useState } from 'react';
import { FindingDetection } from './types';

interface DetectionMonitoringProps {
    detection: FindingDetection;
    onCopy?: (text: string) => void;
}

const DetectionMonitoring: React.FC<DetectionMonitoringProps> = ({ detection, onCopy }) => {
    const [copiedQuery, setCopiedQuery] = useState<number | null>(null);

    const handleCopyQuery = (query: string, index: number) => {
        navigator.clipboard.writeText(query);
        setCopiedQuery(index);
        setTimeout(() => setCopiedQuery(null), 2000);
        onCopy?.(query);
    };

    // Safety check: if detection is null/undefined, return null
    if (!detection) {
        return null;
    }

    // Check if we have any content to display
    const hasContent = (detection.event_ids && detection.event_ids.length > 0) ||
                       (detection.indicators_of_compromise && detection.indicators_of_compromise.length > 0) ||
                       (detection.proactive_measures && detection.proactive_measures.length > 0) ||
                       (detection.queries && detection.queries.length > 0);

    if (!hasContent) {
        return null;
    }

    return (
        <div className="bg-[#161b22] border border-[#30363d] rounded-lg overflow-hidden mb-6">
            {/* Header */}
            <div className="flex items-center gap-3 px-4 py-3 bg-[#21262d] border-b border-[#30363d]">
                <EyeIcon className="w-5 h-5 text-[#58a6ff]" />
                <span className="font-semibold text-white">Event IDs to Monitor</span>
            </div>

            {/* Content */}
            <div className="p-4">
                {/* Event IDs */}
                {detection.event_ids && detection.event_ids.length > 0 && (
                    <ul className="list-disc list-inside text-[#8b949e] text-sm space-y-1 mb-4">
                        {detection.event_ids.map((event, index) => (
                            <li key={index}>
                                <code className="bg-[#010409] px-1.5 py-0.5 rounded text-[#58a6ff] font-mono text-xs">
                                    {event.id}
                                </code>
                                <span className="ml-1">— {event.description}</span>
                            </li>
                        ))}
                    </ul>
                )}

                {/* Indicators of Compromise */}
                {detection.indicators_of_compromise && detection.indicators_of_compromise.length > 0 && (
                    <>
                        <div className="font-semibold text-[#c9d1d9] text-sm mb-2 mt-4">
                            Indicators of Compromise
                        </div>
                        <ul className="list-disc list-inside text-[#8b949e] text-sm space-y-1">
                            {detection.indicators_of_compromise.map((ioc, index) => (
                                <li key={index}>
                                    <FormattedIOC text={ioc} />
                                </li>
                            ))}
                        </ul>
                    </>
                )}

                {/* Proactive Measures */}
                {detection.proactive_measures && detection.proactive_measures.length > 0 && (
                    <>
                        <div className="font-semibold text-[#c9d1d9] text-sm mb-2 mt-4">
                            Proactive Measures
                        </div>
                        <ul className="list-disc list-inside text-[#8b949e] text-sm space-y-1">
                            {detection.proactive_measures.map((measure, index) => (
                                <li key={index}>
                                    <FormattedIOC text={measure} />
                                </li>
                            ))}
                        </ul>
                    </>
                )}

                {/* Detection Queries */}
                {detection.queries && detection.queries.length > 0 && (
                    <>
                        <div className="font-semibold text-[#c9d1d9] text-sm mb-2 mt-4">
                            Detection Query
                        </div>
                        {detection.queries.map((query, index) => (
                            <div key={index} className="mb-3">
                                <div className="text-xs text-[#6e7681] mb-1">
                                    {query.platform}
                                </div>
                                <div className="relative group">
                                    <button
                                        onClick={() => handleCopyQuery(query.query, index)}
                                        className="absolute top-2 right-2 p-1.5 rounded bg-[#21262d] text-[#8b949e] hover:text-white opacity-0 group-hover:opacity-100 transition-opacity z-10"
                                        title="Copy query"
                                    >
                                        {copiedQuery === index ? <CheckIcon /> : <CopyIcon />}
                                    </button>
                                    <div className="bg-[#010409] border border-[#30363d] rounded-md p-3 font-mono text-xs text-[#58a6ff] overflow-x-auto">
                                        <pre className="whitespace-pre-wrap">{query.query}</pre>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </>
                )}
            </div>
        </div>
    );
};

/**
 * Formats IOC text, highlighting code blocks wrapped in backticks
 */
const FormattedIOC: React.FC<{ text: string }> = ({ text }) => {
    const parts = text.split(/(`[^`]+`)/g);

    return (
        <>
            {parts.map((part, index) => {
                if (part.startsWith('`') && part.endsWith('`')) {
                    const code = part.slice(1, -1);
                    return (
                        <code key={index} className="bg-[#010409] px-1.5 py-0.5 rounded text-[#58a6ff] font-mono text-xs">
                            {code}
                        </code>
                    );
                }
                return <span key={index}>{part}</span>;
            })}
        </>
    );
};

// Icons
const EyeIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg className={className} fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
    </svg>
);

const CopyIcon = () => (
    <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
    </svg>
);

const CheckIcon = () => (
    <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
);

export default DetectionMonitoring;

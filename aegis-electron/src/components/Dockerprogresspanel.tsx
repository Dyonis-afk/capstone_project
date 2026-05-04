/**
 * Docker Progress Panel for AEGIS
 * Location: src/components/DockerProgressPanel.tsx
 *
 * Collapsible panel showing Docker operation progress with terminal-style UI
 * matching the TerminalLogViewer aesthetic
 */

import React, { useEffect, useRef, useState } from 'react';
import { ChevronDown, X } from 'lucide-react';

// ==================== TYPES ====================

export interface DockerStep {
    id: string;
    label: string;
    status: 'pending' | 'running' | 'completed' | 'error';
}

export interface DockerProgressPanelProps {
    isVisible: boolean;
    onDismiss: () => void;
    title: string;
    steps: DockerStep[];
    logs: string[];
    progress: number; // 0-100
    status: 'running' | 'success' | 'error';
    errorMessage?: string;
}

// ==================== MAIN COMPONENT ====================

const DockerProgressPanel: React.FC<DockerProgressPanelProps> = ({
    isVisible,
    onDismiss,
    title,
    steps,
    logs,
    progress,
    status,
    errorMessage
}) => {
    const [isExpanded, setIsExpanded] = useState(false);
    const logEndRef = useRef<HTMLDivElement>(null);

    // Auto-expand on error
    useEffect(() => {
        if (status === 'error') {
            setIsExpanded(true);
        }
    }, [status]);

    // Auto-scroll logs
    useEffect(() => {
        if (isExpanded) {
            logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
        }
    }, [logs, isExpanded]);

    // Auto-dismiss on success after delay
    useEffect(() => {
        if (status === 'success') {
            const timer = setTimeout(() => {
                onDismiss();
            }, 2000);
            return () => clearTimeout(timer);
        }
    }, [status, onDismiss]);

    if (!isVisible) return null;

    // Get current step info
    const currentStep = steps.find(s => s.status === 'running');
    const completedSteps = steps.filter(s => s.status === 'completed').length;

    // Progress bar color
    const getProgressColor = () => {
        switch (status) {
            case 'success': return 'bg-green-500';
            case 'error': return 'bg-red-500';
            default: return 'bg-blue-500';
        }
    };

    // Status indicator color
    const getStatusDotColor = () => {
        switch (status) {
            case 'success': return 'bg-green-500';
            case 'error': return 'bg-red-500';
            default: return 'bg-yellow-500 animate-pulse';
        }
    };

    // Format log entry
    const formatLog = (log: string, index: number) => {
        let color = 'text-gray-300';
        let prefix = '›';

        if (log.includes('✓') || log.includes('success') || log.includes('ready') || log.includes('complete')) {
            color = 'text-green-400';
            prefix = '✓';
        } else if (log.includes('ERROR') || log.includes('fail') || log.includes('error')) {
            color = 'text-red-400';
            prefix = '✗';
        } else if (log.includes('...') || log.includes('ing')) {
            color = 'text-blue-400';
            prefix = '◐';
        }

        return (
            <div key={index} className={`flex items-start gap-2 ${color} text-xs hover:bg-white/5 px-2 py-0.5 rounded`}>
                <span className="shrink-0 w-4 text-gray-500">{prefix}</span>
                <span className="break-all">{log}</span>
            </div>
        );
    };

    return (
        <div className="rounded-lg border border-white/10 overflow-hidden bg-black/90 transition-all duration-300">
            {/* Terminal Header */}
            <div
                className="flex items-center gap-3 px-4 py-3 cursor-pointer select-none bg-gray-900 border-b border-white/10"
                onClick={() => setIsExpanded(!isExpanded)}
            >
                {/* Terminal Dots */}
                <div className="flex gap-1.5 shrink-0">
                    <div className="w-3 h-3 rounded-full bg-red-500"></div>
                    <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                    <div className="w-3 h-3 rounded-full bg-green-500"></div>
                </div>

                {/* Title and Current Step */}
                <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                        <span className="font-medium text-sm text-white/90 truncate font-mono">
                            {title}
                        </span>
                        {status === 'running' && (
                            <span className="text-xs text-white/50 font-mono">
                                ({completedSteps}/{steps.length})
                            </span>
                        )}
                    </div>
                    <p className="text-xs text-white/50 truncate font-mono">
                        {status === 'success'
                            ? 'Completed successfully'
                            : status === 'error'
                                ? errorMessage || 'An error occurred'
                                : currentStep?.label || 'Processing...'}
                    </p>
                </div>

                {/* Status Indicator */}
                <div className="flex items-center gap-2 shrink-0">
                    <div className={`w-2 h-2 rounded-full ${getStatusDotColor()}`}></div>
                    {status === 'running' && (
                        <span className="text-xs font-mono text-white/60">
                            {Math.round(progress)}%
                        </span>
                    )}
                </div>

                {/* Dismiss Button (only when done) */}
                {(status === 'success' || status === 'error') && (
                    <button
                        onClick={(e) => {
                            e.stopPropagation();
                            onDismiss();
                        }}
                        className="p-1 hover:bg-white/10 rounded transition-colors shrink-0"
                    >
                        <X className="w-4 h-4 text-white/50" />
                    </button>
                )}

                {/* Expand Arrow */}
                <ChevronDown
                    className={`w-4 h-4 text-white/50 transition-transform shrink-0 ${isExpanded ? 'rotate-180' : ''}`}
                />
            </div>

            {/* Progress Bar */}
            <div className="h-1 bg-gray-800">
                <div
                    className={`h-full transition-all duration-500 ease-out ${getProgressColor()}`}
                    style={{ width: `${progress}%` }}
                />
            </div>

            {/* Expanded Content */}
            {isExpanded && (
                <div className="border-t border-white/10">
                    {/* Step Indicators */}
                    <div className="px-4 py-2 flex items-center gap-1 border-b border-white/5 bg-gray-900/50">
                        {steps.map((step, index) => (
                            <React.Fragment key={step.id}>
                                <div
                                    className={`w-2 h-2 rounded-full transition-all ${step.status === 'completed'
                                        ? 'bg-green-500'
                                        : step.status === 'running'
                                            ? 'bg-blue-500 animate-pulse'
                                            : step.status === 'error'
                                                ? 'bg-red-500'
                                                : 'bg-gray-600'
                                        }`}
                                    title={step.label}
                                />
                                {index < steps.length - 1 && (
                                    <div
                                        className={`w-3 h-0.5 ${step.status === 'completed' ? 'bg-green-500/50' : 'bg-gray-700'}`}
                                    />
                                )}
                            </React.Fragment>
                        ))}
                        <span className="ml-2 text-[10px] text-gray-500 font-mono">
                            {currentStep?.label || (status === 'success' ? 'Done' : 'Error')}
                        </span>
                    </div>

                    {/* Terminal Logs */}
                    <div
                        className="p-3 max-h-32 overflow-y-auto bg-black/50 font-mono space-y-0.5"
                        style={{
                            fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace'
                        }}
                    >
                        {logs.length === 0 ? (
                            <div className="text-gray-500 text-xs flex items-center gap-2">
                                <span className="animate-pulse">▋</span>
                                <span>Waiting...</span>
                            </div>
                        ) : (
                            logs.map((log, index) => formatLog(log, index))
                        )}
                        <div ref={logEndRef} />
                    </div>

                    {/* Error Details */}
                    {status === 'error' && errorMessage && (
                        <div className="px-3 py-2 bg-gray-900 border-t border-white/10">
                            <p className="text-red-400 text-xs font-mono">{errorMessage}</p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default DockerProgressPanel;

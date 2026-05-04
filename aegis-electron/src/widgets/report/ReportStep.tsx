/**
 * ReportStep - Individual step component for report generation
 * Location: src/widgets/report/ReportStep.tsx
 *
 * Refactored: BloodHound CE handles data import.
 * - Local steps (red): checking_connection, executing_queries - BloodHound CE
 * - Backend steps (blue): generating_queries, analyzing, formatting - Cloud RAG
 */

import TerminalLogViewer from './TerminalLogViewer';
import BloodHoundIcon from '../../components/BloodHoundIcon';
import { API_URL } from '../../config/api';

export interface ReportStepData {
    id: string;
    title: string;
    description: string;
    status: 'pending' | 'active' | 'completed' | 'error';
    startTime?: Date;
    endTime?: Date;
    duration?: number;
    error?: string;
}

interface ReportStepProps {
    step: ReportStepData;
    index: number;
    isExpanded: boolean;
    onToggle: () => void;
    showTerminal?: boolean;
}

const ReportStep = ({ step, index, isExpanded, onToggle, showTerminal = true }: ReportStepProps) => {
    // Local steps run on user's machine (red color - BloodHound CE)
    const isLocalStep = ['checking_connection', 'executing_queries'].includes(step.id);

    const getStepIcon = () => {
        switch (step.status) {
            case 'completed':
                return (
                    <div className="w-9 h-9 rounded-full bg-green-600 border-2 border-green-500 flex items-center justify-center text-white shadow-lg shadow-green-500/20 animate-check">
                        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                        </svg>
                    </div>
                );
            case 'active':
                return (
                    <div className={`w-9 h-9 rounded-full ${isLocalStep ? 'bg-red-600 border-red-400' : 'bg-blue-600 border-blue-400'} border-2 flex items-center justify-center text-white shadow-lg ${isLocalStep ? 'shadow-red-500/30' : 'shadow-blue-500/30'} relative`}>
                        <div className={`absolute inset-0 rounded-full border-2 ${isLocalStep ? 'border-red-400' : 'border-blue-400'} animate-ping opacity-75`}></div>
                        {isLocalStep ? (
                            // BloodHound icon for local steps
                            <BloodHoundIcon size={18} className="text-white" />
                        ) : (
                            // Cloud icon for backend steps
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
                            </svg>
                        )}
                    </div>
                );
            case 'error':
                return (
                    <div className="w-9 h-9 rounded-full bg-red-600 border-2 border-red-500 flex items-center justify-center text-white shadow-lg shadow-red-500/20">
                        <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </div>
                );
            default:
                return (
                    <div className="w-9 h-9 rounded-full bg-gray-700 border-2 border-gray-600 flex items-center justify-center text-gray-400 text-sm font-semibold">
                        {index + 1}
                    </div>
                );
        }
    };

    const formatDuration = (seconds?: number) => {
        if (!seconds) return 'Pending';
        if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
        return `${seconds.toFixed(1)}s`;
    };

    const getStatusText = () => {
        if (step.status === 'completed' && step.duration) {
            return formatDuration(step.duration);
        }
        if (step.status === 'active') {
            if (step.id === 'checking_connection') return 'Connecting...';
            if (step.id === 'executing_queries') return 'Querying...';
            return 'Running...';
        }
        if (step.status === 'error') {
            return 'Failed';
        }
        return 'Pending';
    };

    return (
        <div className="relative mb-6">
            {/* Connector Line */}
            <div
                className={`absolute left-[17px] top-9 bottom-0 w-0.5 transition-all duration-500 ${step.status === 'completed'
                    ? 'bg-green-500'
                    : step.status === 'active'
                        ? isLocalStep
                            ? 'bg-gradient-to-b from-red-500 to-gray-700'
                            : 'bg-gradient-to-b from-blue-500 to-gray-700'
                        : 'bg-gray-700'
                    }`}
            />

            {/* Step Content */}
            <div className="flex items-start gap-3">
                {/* Icon */}
                <div className="relative z-10">
                    {getStepIcon()}
                </div>

                {/* Content Card */}
                <div className="flex-1">
                    <div
                        className={`rounded-lg border transition-all duration-200 cursor-pointer ${step.status === 'active'
                            ? isLocalStep
                                ? 'bg-gray-900/50 border-red-500 shadow-lg shadow-red-500/10'
                                : 'bg-gray-900/50 border-blue-500 shadow-lg shadow-blue-500/10'
                            : step.status === 'completed'
                                ? 'bg-gray-900/30 border-gray-700 hover:border-gray-600'
                                : step.status === 'error'
                                    ? 'bg-gray-900/50 border-red-500 shadow-lg shadow-red-500/10'
                                    : 'bg-gray-900/20 border-gray-800 hover:border-gray-700'
                            }`}
                        onClick={onToggle}
                    >
                        <div className="p-4">
                            <div className="flex items-start justify-between">
                                <div className="flex-1">
                                    <h3 className={`font-semibold mb-1 transition-colors ${step.status === 'active'
                                        ? isLocalStep ? 'text-red-400' : 'text-blue-400'
                                        : step.status === 'completed'
                                            ? 'text-green-400'
                                            : step.status === 'error'
                                                ? 'text-red-400'
                                                : 'text-gray-400'
                                        }`}>
                                        {step.title}
                                    </h3>
                                    <p className="text-sm text-gray-500">
                                        {step.status === 'error' && step.error ? step.error : step.description}
                                    </p>
                                </div>
                                <div className="flex items-center gap-3 ml-4">
                                    <span className={`text-xs font-mono px-2 py-1 rounded ${step.status === 'completed'
                                        ? 'bg-green-500/10 text-green-400'
                                        : step.status === 'active'
                                            ? isLocalStep
                                                ? 'bg-red-500/10 text-red-400'
                                                : 'bg-blue-500/10 text-blue-400'
                                            : step.status === 'error'
                                                ? 'bg-red-500/10 text-red-400'
                                                : 'bg-gray-700/50 text-gray-500'
                                        }`}>
                                        {getStatusText()}
                                    </span>
                                    {showTerminal && (step.status === 'completed' || step.status === 'active' || step.status === 'error') && (
                                        <svg
                                            className={`w-4 h-4 text-gray-500 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''
                                                }`}
                                            fill="none"
                                            viewBox="0 0 24 24"
                                            stroke="currentColor"
                                        >
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                        </svg>
                                    )}
                                </div>
                            </div>
                        </div>

                        {/* Local Step Progress - Show inline progress for local steps */}
                        {isLocalStep && step.status === 'active' && isExpanded && (
                            <div className="border-t border-gray-700 p-4 bg-gray-900/30">
                                <div className="flex items-center gap-3">
                                    <div className="flex-1">
                                        <div className="h-1.5 bg-gray-700 rounded-full overflow-hidden">
                                            <div
                                                className="h-full bg-gradient-to-r from-red-500 to-red-400 transition-all duration-300 animate-pulse"
                                                style={{ width: '60%' }}
                                            />
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-2 text-red-400 text-xs">
                                        <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                        </svg>
                                        <BloodHoundIcon size={14} className="text-red-400" />
                                        <span>BloodHound CE</span>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Terminal Viewer - Only show for ACTIVE backend steps */}
                        {showTerminal && !isLocalStep && step.status === 'active' && (
                            <div
                                className={`overflow-hidden transition-all duration-300 ease-in-out ${isExpanded ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'
                                    }`}
                            >
                                <div className="border-t border-gray-700">
                                    <div className="h-80">
                                        <div className="h-full">
                                            <TerminalLogViewer
                                                isActive={true}
                                                baseUrl={API_URL}
                                            />
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}

                        {/* Show completion status for completed steps */}
                        {showTerminal && step.status === 'completed' && isExpanded && (
                            <div className="border-t border-gray-700 p-4 bg-gray-900/30">
                                <div className="flex items-center gap-2 text-green-400 text-sm">
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                    </svg>
                                    {isLocalStep ? (
                                        <span className="flex items-center gap-1.5">
                                            <BloodHoundIcon size={14} className="text-red-400" />
                                            BloodHound CE completed in {step.duration ? `${step.duration.toFixed(1)}s` : 'N/A'}
                                        </span>
                                    ) : (
                                        <span>☁️ Cloud RAG completed in {step.duration ? `${step.duration.toFixed(1)}s` : 'N/A'}</span>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Show error details for failed steps */}
                        {showTerminal && step.status === 'error' && isExpanded && (
                            <div className="border-t border-gray-700 p-4 bg-red-900/20">
                                <div className="flex items-center gap-2 text-red-400 text-sm">
                                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                    <span>{step.error || 'Step failed'}</span>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ReportStep;
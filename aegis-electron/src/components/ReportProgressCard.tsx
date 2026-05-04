/**
 * ReportProgressCard - Floating progress indicator for background report generation
 * Location: src/components/ReportProgressCard.tsx
 *
 * Shows in bottom-right corner when a report is being generated in the background.
 * Clicking the card navigates to ReportGenerationScreen for detailed logs.
 */

import { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { FileText, Loader2, CheckCircle, AlertCircle, ChevronRight, X, AlertTriangle } from 'lucide-react';
import { useReportJobStore } from '../stores/reportJobStore';

const STEP_LABELS: Record<string, string> = {
    idle: 'Starting...',
    checking_connection: 'Connecting...',
    generating_queries: 'Generating queries...',
    executing_queries: 'Executing queries...',
    analyzing: 'Analyzing results...',
    creating_project: 'Creating project...',
    completed: 'Complete!',
    error: 'Failed'
};

// Step progress percentages (same as ReportGenerationScreen)
const STEP_PROGRESS: Record<string, number> = {
    idle: 0,
    checking_connection: 20,
    generating_queries: 40,
    executing_queries: 60,
    analyzing: 80,
    creating_project: 95,
    completed: 100,
    error: 0
};

// Calculate overall progress (same logic as ReportGenerationScreen)
function calculateOverallProgress(
    currentStep: string,
    localProgressPercent: number | undefined
): number {
    const baseProgress = STEP_PROGRESS[currentStep] || 0;

    // Add sub-progress from local progress within the step range
    if (localProgressPercent !== undefined && currentStep !== 'completed' && currentStep !== 'error') {
        const stepRange = 20; // Each step is ~20%
        const subProgress = (localProgressPercent / 100) * stepRange;
        return Math.min(99, baseProgress - stepRange + subProgress);
    }

    return baseProgress;
}

const ReportProgressCard = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const [showConfirmCancel, setShowConfirmCancel] = useState(false);

    const {
        isRunning,
        fileName,
        currentStep,
        localProgress,
        error,
        jobInput,
        cancelJob,
        reset
    } = useReportJobStore();

    // Don't render on /report page (full-screen, shows detailed progress)
    if (location.pathname === '/report') {
        return null;
    }

    // Don't render if no job is running and no error
    if (!isRunning && currentStep !== 'error') {
        return null;
    }

    const handleClick = () => {
        if (showConfirmCancel) return; // Don't navigate if confirmation is showing
        // Navigate to report generation screen with the current job data
        navigate('/report', {
            state: {
                localAnalysis: jobInput?.localAnalysis,
                analysis: jobInput?.analysis,
                fileName: jobInput?.fileName,
                existingProjectId: jobInput?.existingProjectId,
                // Flag to indicate viewing existing job (not starting new pipeline)
                viewingJob: true
            }
        });
    };

    const handleCancelClick = (e: React.MouseEvent) => {
        e.stopPropagation(); // Don't trigger card click
        setShowConfirmCancel(true);
    };

    const handleConfirmCancel = (e: React.MouseEvent) => {
        e.stopPropagation();
        cancelJob();
        setShowConfirmCancel(false);
    };

    const handleCancelConfirm = (e: React.MouseEvent) => {
        e.stopPropagation();
        setShowConfirmCancel(false);
    };

    const handleDismissError = (e: React.MouseEvent) => {
        e.stopPropagation(); // Don't trigger card click
        reset();
    };

    const isError = currentStep === 'error';
    const stepLabel = STEP_LABELS[currentStep] || currentStep;
    // Use the same progress calculation as ReportGenerationScreen
    const progressPercent = calculateOverallProgress(currentStep, localProgress?.percentage);

    return (
        <div
            onClick={handleClick}
            className="fixed bottom-4 right-4 z-50 w-72 cursor-pointer group"
        >
            <div className={`
                bg-aegis-gray border rounded-lg shadow-xl p-4
                transition-all duration-200 hover:scale-[1.02]
                ${isError
                    ? 'border-red-500/50 hover:border-red-500'
                    : 'border-aegis-border hover:border-aegis-accent'
                }
            `}>
                {/* Header */}
                <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                        {isError ? (
                            <AlertCircle className="w-5 h-5 text-red-400" />
                        ) : currentStep === 'completed' ? (
                            <CheckCircle className="w-5 h-5 text-emerald-400" />
                        ) : (
                            <div className="relative">
                                <FileText className="w-5 h-5 text-aegis-accent" />
                                <Loader2 className="w-3 h-3 text-aegis-accent absolute -bottom-1 -right-1 animate-spin" />
                            </div>
                        )}
                        <span className="font-medium text-white text-sm">
                            {isError ? 'Report Failed' : 'Generating Report'}
                        </span>
                    </div>
                    <div className="flex items-center gap-1">
                        {/* Cancel/Dismiss button */}
                        {isError ? (
                            <button
                                onClick={handleDismissError}
                                className="p-1 text-gray-400 hover:text-white hover:bg-white/10 rounded transition-colors"
                                title="Dismiss"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        ) : isRunning && !showConfirmCancel ? (
                            <button
                                onClick={handleCancelClick}
                                className="p-1 text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded transition-colors"
                                title="Cancel"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        ) : null}
                        <ChevronRight className="w-4 h-4 text-gray-400 group-hover:text-white transition-colors" />
                    </div>
                </div>

                {/* Confirmation Dialog */}
                {showConfirmCancel ? (
                    <div className="py-2">
                        <div className="flex items-center gap-2 mb-3">
                            <AlertTriangle className="w-5 h-5 text-amber-400" />
                            <p className="text-sm text-white font-medium">Cancel Report Generation?</p>
                        </div>
                        <p className="text-xs text-gray-400 mb-4">
                            This will stop the current report generation. You'll need to start over.
                        </p>
                        <div className="flex gap-2">
                            <button
                                onClick={handleCancelConfirm}
                                className="flex-1 px-3 py-1.5 text-xs text-gray-300 hover:text-white bg-gray-700 hover:bg-gray-600 rounded transition-colors"
                            >
                                Keep Running
                            </button>
                            <button
                                onClick={handleConfirmCancel}
                                className="flex-1 px-3 py-1.5 text-xs text-white bg-red-600 hover:bg-red-500 rounded transition-colors"
                            >
                                Yes, Cancel
                            </button>
                        </div>
                    </div>
                ) : (
                    <>
                        {/* File name */}
                        {fileName && (
                            <p className="text-xs text-gray-400 truncate mb-2" title={fileName}>
                                {fileName}
                            </p>
                        )}

                        {/* Progress or error */}
                        {isError ? (
                            <p className="text-sm text-red-400 truncate" title={error || 'Unknown error'}>
                                {error || 'An error occurred'}
                            </p>
                        ) : (
                            <>
                                {/* Step label */}
                                <p className="text-sm text-gray-300 mb-2">
                                    {localProgress?.message || stepLabel}
                                </p>

                                {/* Progress bar */}
                                <div className="w-full bg-gray-700 rounded-full h-1.5">
                                    <div
                                        className={`h-1.5 rounded-full transition-all duration-300 ${
                                            currentStep === 'completed' ? 'bg-emerald-500' : 'bg-aegis-accent'
                                        }`}
                                        style={{ width: `${progressPercent}%` }}
                                    />
                                </div>

                                {/* Percentage */}
                                <p className="text-xs text-gray-500 mt-1 text-right">
                                    {progressPercent.toFixed(0)}%
                                </p>
                            </>
                        )}

                        {/* Tap hint */}
                        <p className="text-xs text-gray-500 mt-2 opacity-0 group-hover:opacity-100 transition-opacity">
                            Click to view details
                        </p>
                    </>
                )}
            </div>
        </div>
    );
};

export default ReportProgressCard;

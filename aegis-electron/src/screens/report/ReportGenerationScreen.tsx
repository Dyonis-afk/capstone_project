/**
 * ReportGenerationScreen - Refactored for BloodHound CE
 * Location: src/screens/report/ReportGenerationScreen.tsx
 *
 * Shows progress for 5-step hybrid flow:
 * 1. Connect to BloodHound CE (local)
 * 2. Generate Queries (Backend RAG)
 * 3. Execute Queries (BloodHound CE)
 * 4. RAG Analysis (Backend)
 * 5. Finalize Report
 */

import { useState, useEffect } from 'react';
import ReportProgressStepper from '../../widgets/report/ReportProgressStepper';
import { ReportStepData } from '../../widgets/report/ReportStep';
import type { BloodHoundAnalysis } from '../../types';
import ErrorCard from '../../components/ErrorCard';
import BloodHoundIcon from '../../components/BloodHoundIcon';
import AsciiProgressBar from '../../components/AsciiProgressBar';
import { useReportJobStore } from '../../stores/reportJobStore';

// Types (data property removed - BloodHound CE handles import)
interface LocalAnalysis {
    findings: any;
    filename: string;
}

interface LocalProgress {
    step: string;
    message: string;
    percentage: number;
}

interface GeneratedQuery {
    id: string;
    name: string;
    cypher: string;
}

interface QueryResult {
    query_id: string;
    query_name: string;
    results: any[];
    result_count: number;
}

interface ReportGenerationScreenProps {
    bloodhoundData?: BloodHoundAnalysis;
    localAnalysis?: LocalAnalysis;
    reportId?: string;
    analysisId?: string;
    progress?: {
        step: string;
        percentage: number;
        message: string;
        timestamp: string;
    } | null;
    localProgress?: LocalProgress | null;
    currentStep?: 'checking_connection' | 'generating_queries' | 'executing_queries' | 'analyzing' | 'creating_project' | 'completed' | 'error';
    generatedQueries?: GeneratedQuery[];
    queryResults?: QueryResult[];
    onReportComplete?: (report: any) => void;
    onCancel?: () => void;
    useExistingData?: boolean;
}

const ReportGenerationScreen = ({
    bloodhoundData: _bloodhoundData,
    localAnalysis: _localAnalysis,
    reportId: _parentReportId,
    analysisId: parentAnalysisId,
    progress: parentProgress,
    localProgress,
    currentStep: parentCurrentStep,
    generatedQueries,
    queryResults,
    onReportComplete: _onReportComplete,
    onCancel,
    useExistingData: _useExistingData = false
}: ReportGenerationScreenProps) => {
    // Build steps for hybrid flow
    const buildSteps = (): ReportStepData[] => {
        return [
            {
                id: 'checking_connection',
                title: 'Connect to BloodHound CE',
                description: 'Connecting to BloodHound CE graph database',
                status: 'active',
                startTime: new Date()
            },
            {
                id: 'generating_queries',
                title: 'Generate Attack Queries',
                description: 'Backend RAG generating context-aware Cypher queries',
                status: 'pending'
            },
            {
                id: 'executing_queries',
                title: 'Execute Queries',
                description: 'Running queries on BloodHound CE database',
                status: 'pending'
            },
            {
                id: 'analyzing',
                title: 'RAG Security Analysis',
                description: 'AI analyzing attack paths and generating remediation',
                status: 'pending'
            },
            {
                id: 'formatting',
                title: 'Finalize Report',
                description: 'Assembling comprehensive security report',
                status: 'pending'
            }
        ];
    };

    const [steps, setSteps] = useState<ReportStepData[]>(buildSteps);
    const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set(['checking_connection']));
    const [error, _setError] = useState<string | null>(null);

    // Use store timers (persists when navigating away)
    const { elapsedSeconds, stepElapsedSeconds, tickTimers, isRunning } = useReportJobStore();

    // Tick timers every second while running
    useEffect(() => {
        if (!isRunning) return;

        const interval = setInterval(() => {
            tickTimers();
        }, 1000);

        return () => clearInterval(interval);
    }, [isRunning, tickTimers]);

    // Map parent step to UI step
    const stepMapping: Record<string, string> = {
        'checking_connection': 'checking_connection',
        'generating_queries': 'generating_queries',
        'executing_queries': 'executing_queries',
        'analyzing': 'analyzing',
        'creating_project': 'formatting',
        'completed': 'completed',
        'error': 'error'
    };

    // Update steps based on parent current step
    useEffect(() => {
        if (!parentCurrentStep) return;

        const uiStepId = stepMapping[parentCurrentStep] || parentCurrentStep;
        const now = new Date();

        setSteps(prev => prev.map(step => {
            if (step.id === uiStepId) {
                // Current step - make active
                return {
                    ...step,
                    status: 'active' as const,
                    startTime: step.startTime || now,
                    description: getStepDescription(step.id, localProgress, parentProgress)
                };
            } else if (shouldStepBeCompleted(step.id, uiStepId)) {
                // Previous step - mark completed
                if (step.status === 'completed') return step;

                return {
                    ...step,
                    status: 'completed' as const,
                    endTime: now,
                    duration: step.startTime ? (now.getTime() - step.startTime.getTime()) / 1000 : 0.1,
                    description: getCompletedDescription(step.id)
                };
            }
            return step;
        }));

        // Auto-expand current step
        setExpandedSteps(new Set([uiStepId]));

    }, [parentCurrentStep, localProgress, parentProgress]);

    // Update step description based on progress
    useEffect(() => {
        if (localProgress) {
            setSteps(prev => prev.map(step => {
                if (step.status === 'active') {
                    return {
                        ...step,
                        description: localProgress.message
                    };
                }
                return step;
            }));
        }
    }, [localProgress]);

    const shouldStepBeCompleted = (stepId: string, currentStepId: string): boolean => {
        const stepOrder = ['checking_connection', 'generating_queries', 'executing_queries', 'analyzing', 'formatting'];
        const stepIndex = stepOrder.indexOf(stepId);
        const currentIndex = stepOrder.indexOf(currentStepId);
        return stepIndex >= 0 && currentIndex >= 0 && stepIndex < currentIndex;
    };

    const getStepDescription = (
        stepId: string,
        localProg: LocalProgress | null | undefined,
        parentProg: any
    ): string => {
        if (localProg?.message) return localProg.message;
        if (parentProg?.message) return parentProg.message;

        switch (stepId) {
            case 'checking_connection':
                return 'Connecting to BloodHound CE graph database';
            case 'generating_queries':
                return 'Backend RAG generating context-aware Cypher queries';
            case 'executing_queries':
                return 'Running queries on BloodHound CE database';
            case 'analyzing':
                return 'AI analyzing attack paths and generating remediation';
            case 'formatting':
                return 'Assembling comprehensive security report';
            default:
                return 'Processing...';
        }
    };

    const getCompletedDescription = (stepId: string): string => {
        switch (stepId) {
            case 'checking_connection':
                return 'Connected to BloodHound CE';
            case 'generating_queries':
                if (generatedQueries?.length) {
                    return `Generated ${generatedQueries.length} attack path queries`;
                }
                return 'Queries generated';
            case 'executing_queries':
                if (queryResults?.length) {
                    const totalFindings = queryResults.reduce((sum, qr) => sum + qr.result_count, 0);
                    return `Executed ${queryResults.length} queries, found ${totalFindings} findings`;
                }
                return 'Queries executed';
            case 'analyzing':
                return 'Attack path intelligence generated';
            case 'formatting':
                return 'Report complete';
            default:
                return 'Complete';
        }
    };

    const toggleStep = (stepId: string) => {
        setExpandedSteps(prev => {
            const newSet = new Set(prev);
            if (newSet.has(stepId)) {
                newSet.delete(stepId);
            } else {
                newSet.add(stepId);
            }
            return newSet;
        });
    };

    const handleCancel = () => {
        if (onCancel) onCancel();
    };

    const getOverallProgress = () => {
        // Calculate based on step
        const stepProgress: Record<string, number> = {
            'checking_connection': 20,
            'generating_queries': 40,
            'executing_queries': 60,
            'analyzing': 80,
            'formatting': 95,
            'completed': 100
        };

        const currentUIStep = stepMapping[parentCurrentStep || 'checking_connection'] || 'checking_connection';
        const baseProgress = stepProgress[currentUIStep] || 0;

        // Add sub-progress from local progress
        if (localProgress && parentCurrentStep) {
            const stepRange = 20; // Each step is ~20%
            const subProgress = (localProgress.percentage / 100) * stepRange;
            return Math.min(99, baseProgress - stepRange + subProgress);
        }

        if (parentProgress?.percentage) {
            return parentProgress.percentage;
        }

        return baseProgress;
    };

    const isGenerating = steps.some(s => s.status === 'active');

    // Error state
    if (error && !isGenerating) {
        return (
            <ErrorCard
                title="Report Generation Failed"
                message={error}
                onRetry={() => window.location.reload()}
                onGoBack={handleCancel}
                retryLabel="Retry Generation"
                goBackLabel="Go Back"
            />
        );
    }

    return (
        <div className="min-h-screen bg-aegis-dark text-aegis-text">
            {/* Back Button */}
            <div className="absolute top-4 left-4 z-10">
                <button
                    onClick={handleCancel}
                    className="flex items-center gap-2 px-4 py-2 hover:bg-aegis-gray-light rounded-lg transition-colors text-aegis-text hover:text-white"
                >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
                    </svg>
                    <span className="text-sm font-medium">Back</span>
                </button>
            </div>

            <div className="max-w-4xl mx-auto px-6 py-8 pt-20">
                {/* Header */}
                <div className="text-center mb-12">
                    <p className="text-[#58a6ff] font-mono text-2xl sm:text-3xl uppercase tracking-widest mb-2">
                        // {isGenerating ? 'Generating Security Report' : 'Report Complete'}
                    </p>

                    <p className="text-aegis-text-muted mb-2">
                        {isGenerating
                            ? 'Hybrid analysis: Local queries + Cloud RAG intelligence'
                            : 'Your comprehensive security assessment is ready'}
                    </p>

                    {/* Hybrid Flow Badge */}
                    <div className="flex items-center justify-center gap-2 mt-3">
                        <span className="px-3 py-1 bg-red-500/10 border border-red-500/30 rounded-full text-red-400 text-xs font-medium flex items-center gap-1.5">
                            <BloodHoundIcon size={14} className="text-red-400" />
                            BloodHound CE Queries
                        </span>
                        <span className="text-aegis-text-subtle">+</span>
                        <span className="px-3 py-1 bg-blue-500/10 border border-blue-500/30 rounded-full text-blue-400 text-xs font-medium">
                            ☁️ Cloud RAG Analysis
                        </span>
                    </div>

                    {/* Stats */}
                    {((generatedQueries?.length ?? 0) > 0 || (queryResults?.reduce((s, q) => s + q.result_count, 0) ?? 0) > 0) && (
                        <div className="flex items-center justify-center gap-4 mt-4 text-xs">
                            {(generatedQueries?.length ?? 0) > 0 && generatedQueries && (
                                <span className="px-2 py-1 bg-blue-500/10 rounded text-blue-400">
                                    🔍 {generatedQueries.length} queries
                                </span>
                            )}
                            {(queryResults?.reduce((s, q) => s + q.result_count, 0) ?? 0) > 0 && queryResults && (
                                <span className="px-2 py-1 bg-red-500/10 rounded text-red-400">
                                    🎯 {queryResults.reduce((s, q) => s + q.result_count, 0)} findings
                                </span>
                            )}
                        </div>
                    )}

                    {/* Analysis ID */}
                    {parentAnalysisId && (
                        <p className="text-xs text-aegis-text-subtle font-mono mt-2">
                            Analysis: <span className="text-blue-400">{parentAnalysisId.slice(0, 8)}...</span>
                        </p>
                    )}

                    {/* ASCII Progress Bar with integrated timers */}
                    {isGenerating && (
                        <div className="mt-6 max-w-2xl mx-auto">
                            <AsciiProgressBar
                                progress={getOverallProgress()}
                                step={
                                    parentCurrentStep === 'checking_connection' ? 'connect' :
                                    parentCurrentStep === 'generating_queries' ? 'generate' :
                                    parentCurrentStep === 'executing_queries' ? 'execute' :
                                    parentCurrentStep === 'analyzing' ? 'analyze' :
                                    parentCurrentStep === 'creating_project' ? 'finalize' :
                                    parentCurrentStep === 'completed' ? 'done' : 'init'
                                }
                                action={
                                    parentCurrentStep === 'checking_connection' ? 'BloodHound CE' :
                                    parentCurrentStep === 'generating_queries' ? 'Cypher queries' :
                                    parentCurrentStep === 'executing_queries' ? 'Neo4j' :
                                    parentCurrentStep === 'analyzing' ? 'RAG analysis' :
                                    parentCurrentStep === 'creating_project' ? 'report' :
                                    parentCurrentStep === 'completed' ? 'complete ✓' : 'initializing'
                                }
                                totalElapsedSeconds={elapsedSeconds}
                                stepElapsedSeconds={stepElapsedSeconds}
                                isComplete={parentCurrentStep === 'completed'}
                            />
                        </div>
                    )}
                </div>

                {/* Steps */}
                <ReportProgressStepper
                    steps={steps}
                    expandedSteps={expandedSteps}
                    onToggleStep={toggleStep}
                />

                {/* Legend */}
                <div className="mt-8 flex items-center justify-center gap-6 text-xs text-aegis-text-muted">
                    <div className="flex items-center gap-2">
                        <BloodHoundIcon size={14} className="text-red-500" />
                        <span>BloodHound CE (Local)</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-blue-500"></div>
                        <span>Backend (Cloud RAG)</span>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default ReportGenerationScreen;
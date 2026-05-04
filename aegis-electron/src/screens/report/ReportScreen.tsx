/**
 * ReportScreen - Report Generation Progress Viewer
 * Location: src/screens/report/ReportScreen.tsx
 *
 * This screen displays the progress of background report generation.
 * The actual pipeline runs in reportJobStore - this screen just shows the state.
 *
 * Flow:
 * 1. HomeContent starts the job via reportJobStore.startJob()
 * 2. HomeContent navigates here with viewingJob: true
 * 3. This screen reads state from the store and displays progress
 * 4. When job completes, store navigates to ChatScreen automatically
 */

import { useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import type { BloodHoundAnalysis } from '../../types';
import ReportGenerationScreen from './ReportGenerationScreen';
import ErrorCard from '../../components/ErrorCard';
import { useReportJobStore } from '../../stores/reportJobStore';

// ==================== TYPES ====================

interface ParsedFindings {
    high_risk: any[];
    medium_risk: any[];
    low_risk: any[];
    summary: {
        total_nodes: number;
        total_edges: number;
        high_risk_count: number;
        medium_risk_count: number;
        low_risk_count: number;
        files_processed?: number;
    };
}

interface LocalAnalysis {
    findings: ParsedFindings;
    filename: string;
}

// ==================== COMPONENT ====================

const ReportScreen = () => {
    const location = useLocation();
    const navigate = useNavigate();

    // Get data from navigation state (passed by HomeContent)
    const analysis = location.state?.analysis as BloodHoundAnalysis | undefined;
    const localAnalysis = location.state?.localAnalysis as LocalAnalysis | undefined;
    const useExistingData = location.state?.useExistingData as boolean | undefined;

    // Read state from the report job store
    const {
        isRunning,
        currentStep,
        progress,
        localProgress,
        error,
        analysisId,
        generatedQueries,
        queryResults,
        reset
    } = useReportJobStore();

    // If no job is running and we're on this page, redirect back
    useEffect(() => {
        if (!isRunning && currentStep === 'idle') {
            console.log('[ReportScreen] No job running, redirecting to home');
            navigate('/', { replace: true });
        }
    }, [isRunning, currentStep, navigate]);

    // Handle errors - show error card
    if (currentStep === 'error' && error) {
        return (
            <ErrorCard
                title="Attack Path Analysis Failed"
                message={error}
                onRetry={() => {
                    reset();
                    navigate('/');
                }}
                onGoBack={() => {
                    reset();
                    navigate('/');
                }}
                retryLabel="Try Again"
                goBackLabel="Go Back"
            />
        );
    }

    // Show loading if we're waiting for job state
    if (!isRunning && currentStep === 'idle') {
        return (
            <div className="min-h-screen bg-aegis-dark flex items-center justify-center">
                <div className="text-center">
                    <p className="text-gray-400">Loading...</p>
                </div>
            </div>
        );
    }

    // Map 'idle' step to 'checking_connection' for the UI (idle shouldn't normally be seen here)
    const displayStep = currentStep === 'idle' ? 'checking_connection' : currentStep;

    // Render the progress screen with state from the store
    return (
        <ReportGenerationScreen
            bloodhoundData={analysis || undefined}
            localAnalysis={localAnalysis}
            reportId={analysisId}
            analysisId={analysisId}
            progress={progress}
            localProgress={localProgress}
            currentStep={displayStep as 'checking_connection' | 'generating_queries' | 'executing_queries' | 'analyzing' | 'creating_project' | 'completed' | 'error'}
            generatedQueries={generatedQueries}
            queryResults={queryResults}
            onCancel={() => {
                // Just navigate back - let the job continue in the background
                // The floating ReportProgressCard will show progress on other pages
                navigate('/');
            }}
            useExistingData={useExistingData}
        />
    );
};

export default ReportScreen;

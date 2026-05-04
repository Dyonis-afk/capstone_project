/**
 * AsciiProgressBar - Minimal ASCII progress bar matching the mockup
 * Location: src/components/AsciiProgressBar.tsx
 *
 * Features:
 * - CSS spinner (not braille)
 * - Step → action format
 * - Elapsed time display (single "Xm Ys" or inline Total/Step timers)
 * - Block character progress bar with inline timers for report generation
 */

interface AsciiProgressBarProps {
    /** Current progress percentage (0-100) */
    progress: number;
    /** Current step name (e.g., "upload", "extract") */
    step: string;
    /** Current action/target (e.g., "BloodHound CE", "Neo4j findings") */
    action: string;
    /** Elapsed time in seconds (single timer, e.g. HomeContent Neo4j load) */
    elapsedSeconds?: number;
    /** Total elapsed seconds (when set with stepElapsedSeconds, shows Total/Step row) */
    totalElapsedSeconds?: number;
    /** Current step elapsed seconds (when set with totalElapsedSeconds, shows Total/Step row) */
    stepElapsedSeconds?: number;
    /** Whether the operation is complete */
    isComplete?: boolean;
}

const AsciiProgressBar = ({
    progress,
    step,
    action,
    elapsedSeconds = 0,
    totalElapsedSeconds,
    stepElapsedSeconds,
    isComplete = false
}: AsciiProgressBarProps) => {
    const showTotalAndStep = totalElapsedSeconds !== undefined && stepElapsedSeconds !== undefined;

    const formatTimeShort = (seconds: number): string => {
        const mins = Math.floor(seconds / 60);
        const secs = seconds % 60;
        return `${mins}m ${secs}s`;
    };

    const clampedProgress = Math.min(100, Math.max(0, progress));

    return (
        <div className="px-5 py-5">
            {/* Status Row */}
            <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2.5">
                    {/* Spinner or Checkmark */}
                    {isComplete ? (
                        <svg className="w-4 h-4 text-aegis-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                        </svg>
                    ) : (
                        <div className="w-4 h-4 border-2 border-aegis-accent border-t-transparent rounded-full animate-spin" />
                    )}
                    {/* Step → Action */}
                    <span className="text-sm text-aegis-text">
                        <span className="text-aegis-accent font-medium">{step}</span>
                        <span className="text-aegis-text-subtle mx-1.5">→</span>
                        <span>{action}</span>
                    </span>
                </div>
                {/* Single elapsed (when not showing Total/Step) */}
                {!isComplete && !showTotalAndStep && (
                    <span className="text-xs text-aegis-text-subtle font-mono">{formatTimeShort(elapsedSeconds)}</span>
                )}
            </div>

            {/* ASCII Progress Bar with inline timers */}
            <div className="font-mono text-sm flex items-center gap-2">
                <span className="text-aegis-text-subtle">[</span>
                <div className="flex-1 h-4 bg-aegis-gray-light rounded-sm overflow-hidden">
                    <div
                        className={`h-full transition-all duration-300 ${isComplete ? 'bg-aegis-success' : 'bg-aegis-accent'}`}
                        style={{ width: `${clampedProgress}%` }}
                    />
                </div>
                <span className="text-aegis-text-subtle">]</span>
                <span className={`w-10 text-right ${isComplete ? 'text-aegis-success font-semibold' : 'text-aegis-text-muted'}`}>
                    {Math.round(clampedProgress)}%
                </span>
                {/* Inline Total + Step timers (same row as progress bar) */}
                {!isComplete && showTotalAndStep && (
                    <>
                        <span className="text-aegis-text-subtle mx-1">|</span>
                        <span className="text-aegis-text-subtle">Total:</span>
                        <span className="text-white">{formatTimeShort(totalElapsedSeconds)}</span>
                        <span className="text-aegis-text-subtle mx-1">|</span>
                        <span className="text-aegis-text-subtle">Step:</span>
                        <span className="text-green-400">{formatTimeShort(stepElapsedSeconds)}</span>
                    </>
                )}
            </div>
        </div>
    );
};

export default AsciiProgressBar;

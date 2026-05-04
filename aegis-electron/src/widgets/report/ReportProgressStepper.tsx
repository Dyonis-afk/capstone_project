/**
 * ReportProgressStepper - Container for report generation steps
 * Location: src/widgets/report/ReportProgressStepper.tsx
 */

import ReportStep, { ReportStepData } from './ReportStep';

interface ReportProgressStepperProps {
    steps: ReportStepData[];
    expandedSteps: Set<string>;
    onToggleStep: (stepId: string) => void;
}

const ReportProgressStepper = ({
    steps,
    expandedSteps,
    onToggleStep
}: ReportProgressStepperProps) => {
    return (
        <div className="relative py-4">
            {steps.map((step, index) => (
                <ReportStep
                    key={step.id}
                    step={step}
                    index={index}
                    isExpanded={expandedSteps.has(step.id)}
                    onToggle={() => onToggleStep(step.id)}
                    showTerminal={true}
                />
            ))}
        </div>
    );
};

export default ReportProgressStepper;
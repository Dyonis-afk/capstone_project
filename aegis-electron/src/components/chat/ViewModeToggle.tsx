/**
 * ViewModeToggle Component
 * Toggles between Normal view and Report Format view for chat responses.
 */

import React from 'react';
import { ViewModeToggleProps } from '../../types/chat';

const ViewModeToggle: React.FC<ViewModeToggleProps> = ({ mode, onChange, disabled }) => {
    return (
        <div className="flex items-center gap-1 bg-[#21262d] rounded-lg p-0.5 border border-[#30363d]">
            <button
                onClick={() => onChange('normal')}
                className={`px-3 py-1.5 rounded text-xs font-medium transition-all duration-200 ${
                    mode === 'normal'
                        ? 'bg-[#388bfd] text-white shadow-sm'
                        : 'text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#30363d]'
                }`}
                disabled={disabled}
                title="View as natural response"
            >
                Normal
            </button>
            <button
                onClick={() => onChange('report')}
                className={`px-3 py-1.5 rounded text-xs font-medium transition-all duration-200 ${
                    mode === 'report'
                        ? 'bg-[#388bfd] text-white shadow-sm'
                        : 'text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#30363d]'
                }`}
                disabled={disabled}
                title="View as report finding (for Add to Report)"
            >
                Report Format
            </button>
        </div>
    );
};

export default ViewModeToggle;

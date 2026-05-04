/**
 * AddToReportModal Component
 * Modal dialog for adding a chat-discovered finding to the security report.
 * Allows user to add optional notes before adding the finding.
 */

import React, { useState, useEffect } from 'react';
import { FindingSeverity } from '../attack-components/types';
import { AddToReportModalProps } from '../../types/chat';

const AddToReportModal: React.FC<AddToReportModalProps> = ({
    isOpen,
    onClose,
    onAdd,
    finding,
    sourceQuery,
    resultCount
}) => {
    const [notes, setNotes] = useState('');
    const [isAdding, setIsAdding] = useState(false);

    // Reset notes when modal opens
    useEffect(() => {
        if (isOpen) {
            setNotes('');
            setIsAdding(false);
        }
    }, [isOpen]);

    // Close on escape key
    useEffect(() => {
        const handleEscape = (e: KeyboardEvent) => {
            if (e.key === 'Escape' && isOpen) {
                onClose();
            }
        };
        document.addEventListener('keydown', handleEscape);
        return () => document.removeEventListener('keydown', handleEscape);
    }, [isOpen, onClose]);

    if (!isOpen) return null;

    const handleAdd = async () => {
        setIsAdding(true);
        try {
            await onAdd(notes.trim() || undefined);
        } finally {
            setIsAdding(false);
        }
    };

    const getSeverityColor = (severity: FindingSeverity): string => {
        switch (severity) {
            case 'Critical': return 'bg-red-600';
            case 'High': return 'bg-orange-600';
            case 'Medium': return 'bg-yellow-600';
            case 'Low': return 'bg-green-600';
            default: return 'bg-gray-600';
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
            {/* Backdrop */}
            <div
                className="absolute inset-0 bg-black/60 backdrop-blur-sm"
                onClick={onClose}
            />

            {/* Modal */}
            <div className="relative w-full max-w-lg mx-4 bg-[#161b22] border border-[#30363d] rounded-xl shadow-2xl">
                {/* Header */}
                <div className="flex items-center justify-between px-6 py-4 border-b border-[#30363d]">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-[#238636]/10 rounded-lg">
                            <svg className="w-5 h-5 text-[#238636]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                            </svg>
                        </div>
                        <h2 className="text-lg font-semibold text-[#c9d1d9]">Add Finding to Report</h2>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#21262d] rounded-lg transition-colors"
                    >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {/* Body */}
                <div className="px-6 py-4 space-y-4">
                    {/* Finding Preview */}
                    <div className="flex items-start gap-3 p-4 bg-[#0d1117] rounded-lg border border-[#30363d]">
                        <div className={`${getSeverityColor(finding.severity)} px-2 py-1 rounded text-xs font-bold text-white`}>
                            {finding.severity}
                        </div>
                        <div className="flex-1 min-w-0">
                            <h3 className="font-medium text-[#c9d1d9] truncate">{finding.title}</h3>
                            <p className="text-sm text-[#8b949e] mt-0.5">{finding.category}</p>
                        </div>
                    </div>

                    {/* Source Query */}
                    <div>
                        <label className="block text-xs font-medium text-[#8b949e] mb-1.5">Source Query</label>
                        <div className="p-3 bg-[#0d1117] rounded-lg border border-[#30363d]">
                            <code className="text-xs text-[#388bfd] font-mono break-all">
                                {sourceQuery.length > 150 ? sourceQuery.slice(0, 150) + '...' : sourceQuery}
                            </code>
                        </div>
                    </div>

                    {/* Result Count */}
                    {resultCount !== undefined && resultCount > 0 && (
                        <div className="flex items-center gap-2 text-sm text-[#8b949e]">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                            </svg>
                            <span>{resultCount} result{resultCount !== 1 ? 's' : ''} from query</span>
                        </div>
                    )}

                    {/* Notes */}
                    <div>
                        <label className="block text-xs font-medium text-[#8b949e] mb-1.5">
                            Notes <span className="text-[#484f58]">(optional)</span>
                        </label>
                        <textarea
                            value={notes}
                            onChange={(e) => setNotes(e.target.value)}
                            className="w-full px-3 py-2.5 bg-[#0d1117] border border-[#30363d] rounded-lg text-[#c9d1d9] text-sm placeholder-[#484f58] focus:outline-none focus:border-[#388bfd] focus:ring-1 focus:ring-[#388bfd] resize-none"
                            rows={3}
                            placeholder="Add context about why this finding is important..."
                            autoFocus
                        />
                    </div>
                </div>

                {/* Footer */}
                <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#30363d]">
                    <button
                        onClick={onClose}
                        className="px-4 py-2 text-sm font-medium text-[#c9d1d9] hover:text-white transition-colors"
                        disabled={isAdding}
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleAdd}
                        disabled={isAdding}
                        className="flex items-center gap-2 px-4 py-2 bg-[#238636] hover:bg-[#2ea043] disabled:bg-[#238636]/50 text-white text-sm font-medium rounded-lg transition-colors"
                    >
                        {isAdding ? (
                            <>
                                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                </svg>
                                Adding...
                            </>
                        ) : (
                            <>
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                                </svg>
                                Add to Report
                            </>
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default AddToReportModal;

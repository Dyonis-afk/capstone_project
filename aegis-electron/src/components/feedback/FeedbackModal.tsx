/**
 * Feedback Modal
 * Form for users to submit feedback
 */

import React, { useState, useEffect } from 'react';
import { X, Send, Bug, Sparkles, MessageSquare, Loader2 } from 'lucide-react';
import toast from 'react-hot-toast';

interface FeedbackModalProps {
    isOpen: boolean;
    onClose: () => void;
}

type FeedbackType = 'bug' | 'feature' | 'feedback';

interface SystemInfo {
    platform: string;
    osVersion: string;
    arch: string;
    aegisVersion: string;
    electronVersion: string;
    memory: string;
}

const FEEDBACK_TYPES: Array<{ value: FeedbackType; label: string; icon: React.ReactNode; color: string }> = [
    { value: 'bug', label: 'Bug Report', icon: <Bug className="w-4 h-4" />, color: 'border-red-500 bg-red-500/10 text-red-400' },
    { value: 'feature', label: 'Feature Request', icon: <Sparkles className="w-4 h-4" />, color: 'border-green-500 bg-green-500/10 text-green-400' },
    { value: 'feedback', label: 'Feedback', icon: <MessageSquare className="w-4 h-4" />, color: 'border-blue-500 bg-blue-500/10 text-blue-400' },
];

const FeedbackModal: React.FC<FeedbackModalProps> = ({ isOpen, onClose }) => {
    const [type, setType] = useState<FeedbackType>('bug');
    const [title, setTitle] = useState('');
    const [description, setDescription] = useState('');
    const [email, setEmail] = useState('');
    const [includeSystemInfo, setIncludeSystemInfo] = useState(true);
    const [includeLogs, setIncludeLogs] = useState(true);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);

    // Load system info when modal opens
    useEffect(() => {
        if (isOpen && window.feedback) {
            window.feedback.getSystemInfo().then((result) => {
                if (result.success && result.data) {
                    setSystemInfo(result.data);
                }
            });
        }
    }, [isOpen]);

    // Reset form when modal closes
    useEffect(() => {
        if (!isOpen) {
            setTitle('');
            setDescription('');
            setEmail('');
            setType('bug');
        }
    }, [isOpen]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!title.trim() || !description.trim()) {
            toast.error('Please fill in the title and description');
            return;
        }

        if (!window.feedback) {
            toast.error('Feedback system not available');
            return;
        }

        setIsSubmitting(true);

        try {
            const result = await window.feedback.submit({
                type,
                title: title.trim(),
                description: description.trim(),
                email: email.trim() || undefined,
                includeSystemInfo,
                includeLogs,
            });

            if (result.success) {
                toast.success('Feedback sent! Thank you for helping improve AEGIS.');
                onClose();
            } else {
                toast.error(result.error || 'Failed to send feedback');
            }
        } catch (err: any) {
            toast.error(err.message || 'Failed to send feedback');
        } finally {
            setIsSubmitting(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
            {/* Backdrop */}
            <div
                className="absolute inset-0 bg-black/60 backdrop-blur-sm"
                onClick={onClose}
            />

            {/* Modal */}
            <div className="relative bg-[#0d1117] border border-[#30363d] rounded-2xl
                            shadow-2xl w-full max-w-lg mx-4 max-h-[90vh] overflow-hidden">
                {/* Header */}
                <div className="px-6 py-4 border-b border-[#30363d] flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-white">Send Feedback</h2>
                    <button
                        onClick={onClose}
                        className="text-gray-400 hover:text-white transition-colors p-1 rounded hover:bg-[#21262d]"
                    >
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Form */}
                <form onSubmit={handleSubmit} className="p-6 space-y-5 overflow-y-auto max-h-[calc(90vh-140px)]">
                    {/* Feedback Type */}
                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                            Type
                        </label>
                        <div className="grid grid-cols-2 gap-2">
                            {FEEDBACK_TYPES.map((ft) => (
                                <button
                                    key={ft.value}
                                    type="button"
                                    onClick={() => setType(ft.value)}
                                    className={`px-3 py-2 rounded-lg border-2 transition-all text-sm font-medium flex items-center gap-2
                                        ${type === ft.value
                                            ? ft.color + ' border-current'
                                            : 'border-[#30363d] bg-[#161b22] hover:bg-[#21262d] text-gray-400'
                                        }`}
                                >
                                    {ft.icon}
                                    {ft.label}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Title */}
                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                            Title <span className="text-red-400">*</span>
                        </label>
                        <input
                            type="text"
                            value={title}
                            onChange={(e) => setTitle(e.target.value)}
                            placeholder="Brief summary of your feedback"
                            className="w-full px-4 py-2.5 bg-[#161b22] border border-[#30363d] rounded-lg
                                      text-white placeholder-gray-500 focus:outline-none
                                      focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                            required
                        />
                    </div>

                    {/* Description */}
                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                            Description <span className="text-red-400">*</span>
                        </label>
                        <textarea
                            value={description}
                            onChange={(e) => setDescription(e.target.value)}
                            placeholder={type === 'bug'
                                ? "What happened? What did you expect to happen? Steps to reproduce..."
                                : "Describe your feedback in detail..."
                            }
                            rows={4}
                            className="w-full px-4 py-2.5 bg-[#161b22] border border-[#30363d] rounded-lg
                                      text-white placeholder-gray-500 focus:outline-none
                                      focus:border-blue-500 focus:ring-1 focus:ring-blue-500 resize-none"
                            required
                        />
                    </div>

                    {/* Email (Optional) */}
                    <div>
                        <label className="block text-sm font-medium text-gray-300 mb-2">
                            Email <span className="text-gray-500">(optional)</span>
                        </label>
                        <input
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="your@email.com - for follow-up questions"
                            className="w-full px-4 py-2.5 bg-[#161b22] border border-[#30363d] rounded-lg
                                      text-white placeholder-gray-500 focus:outline-none
                                      focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                        />
                    </div>

                    {/* Options */}
                    <div className="space-y-3">
                        <label className="flex items-center gap-3 cursor-pointer group">
                            <input
                                type="checkbox"
                                checked={includeSystemInfo}
                                onChange={(e) => setIncludeSystemInfo(e.target.checked)}
                                className="w-4 h-4 rounded border-[#30363d] bg-[#161b22]
                                          text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                            />
                            <span className="text-sm text-gray-400 group-hover:text-white transition-colors">
                                Include system information
                            </span>
                        </label>

                        {/* System info preview */}
                        {includeSystemInfo && systemInfo && (
                            <div className="ml-7 p-3 bg-[#161b22] rounded-lg text-xs text-gray-500 space-y-1 border border-[#30363d]">
                                <div>Platform: {systemInfo.platform} {systemInfo.osVersion}</div>
                                <div>AEGIS: v{systemInfo.aegisVersion}</div>
                                <div>Memory: {systemInfo.memory}</div>
                            </div>
                        )}

                        <label className="flex items-center gap-3 cursor-pointer group">
                            <input
                                type="checkbox"
                                checked={includeLogs}
                                onChange={(e) => setIncludeLogs(e.target.checked)}
                                className="w-4 h-4 rounded border-[#30363d] bg-[#161b22]
                                          text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                            />
                            <span className="text-sm text-gray-400 group-hover:text-white transition-colors">
                                Include recent logs (helps diagnose issues)
                            </span>
                        </label>
                    </div>

                    {/* Discord Link */}
                    <div className="flex items-center gap-3 p-3 bg-[#5865F2]/10 border border-[#5865F2]/30 rounded-lg">
                        <svg className="w-5 h-5 text-[#5865F2] flex-shrink-0" viewBox="0 0 24 24" fill="currentColor">
                            <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
                        </svg>
                        <div className="flex-1 min-w-0">
                            <p className="text-sm text-gray-300">
                                Join our Discord for discussions and support
                            </p>
                        </div>
                        <a
                            href="https://discord.gg/ERyjU7UJxC"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="px-3 py-1.5 bg-[#5865F2] hover:bg-[#4752C4] text-white text-sm font-medium rounded-md transition-colors flex-shrink-0"
                        >
                            Join
                        </a>
                    </div>

                    {/* Submit Button */}
                    <div className="flex justify-end gap-3 pt-2">
                        <button
                            type="button"
                            onClick={onClose}
                            className="px-4 py-2 text-sm font-medium text-gray-400
                                      hover:text-white transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={isSubmitting || !title.trim() || !description.trim()}
                            className="px-5 py-2 bg-blue-600 hover:bg-blue-500
                                      disabled:opacity-50 disabled:cursor-not-allowed
                                      text-white text-sm font-medium rounded-lg transition-colors
                                      flex items-center gap-2"
                        >
                            {isSubmitting ? (
                                <>
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                    Sending...
                                </>
                            ) : (
                                <>
                                    <Send className="w-4 h-4" />
                                    Send Feedback
                                </>
                            )}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default FeedbackModal;

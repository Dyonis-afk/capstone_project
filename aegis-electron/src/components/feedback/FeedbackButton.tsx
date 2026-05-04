/**
 * Floating Feedback Button
 * Shows in bottom-right corner of the app
 */

import React, { useState } from 'react';
import { MessageSquare } from 'lucide-react';
import FeedbackModal from './FeedbackModal';

const FeedbackButton: React.FC = () => {
    const [isModalOpen, setIsModalOpen] = useState(false);

    return (
        <>
            {/* Floating Button */}
            <button
                onClick={() => setIsModalOpen(true)}
                className="fixed bottom-6 right-6 w-12 h-12 bg-blue-600 hover:bg-blue-500
                           rounded-full shadow-lg flex items-center justify-center transition-all
                           hover:scale-110 z-40 group"
                title="Send Feedback"
            >
                <MessageSquare className="w-5 h-5 text-white" />

                {/* Tooltip */}
                <span className="absolute right-full mr-3 px-2 py-1 bg-[#21262d] text-gray-300 text-xs
                                rounded whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity
                                border border-[#30363d]">
                    Send Feedback
                </span>
            </button>

            {/* Modal */}
            <FeedbackModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
            />
        </>
    );
};

export default FeedbackButton;

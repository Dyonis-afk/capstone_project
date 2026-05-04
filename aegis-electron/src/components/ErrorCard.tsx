import React from 'react';

interface ErrorCardProps {
    title?: string;
    message: string;
    onRetry?: () => void;
    onGoBack?: () => void;
    retryLabel?: string;
    goBackLabel?: string;
    showAegisBranding?: boolean;
}

const ErrorCard: React.FC<ErrorCardProps> = ({
    title = 'Report Generation Failed',
    message: _message,
    onRetry,
    onGoBack,
    retryLabel = 'Try Again',
    goBackLabel = 'Go Back',
    showAegisBranding = true
}) => {
    return (
        <div className="min-h-screen bg-aegis-dark flex items-center justify-center p-6" style={{
            background: 'linear-gradient(135deg, #0d1117 0%, #010409 50%, #0d1117 100%)'
        }}>
            <div className="max-w-[400px] w-full bg-aegis-gray border border-aegis-border rounded-2xl p-8" style={{
                boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.8)'
            }}>
                {/* Error Icon */}
                <div className="w-20 h-20 mx-auto mb-6 rounded-full flex items-center justify-center" style={{
                    background: 'linear-gradient(135deg, #da3633 0%, #b62324 100%)',
                    boxShadow: '0 0 0 8px rgba(248, 81, 73, 0.15)'
                }}>
                    <svg className="w-10 h-10 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                </div>

                {/* AEGIS Brand */}
                {showAegisBranding && (
                    <div className="text-center mb-4 text-2xl font-bold bg-gradient-to-r from-aegis-info via-aegis-info-muted to-aegis-info-dark bg-clip-text text-transparent">
                        AEGIS
                    </div>
                )}

                {/* Error Title */}
                <h1 className="text-2xl font-bold text-aegis-text text-center mb-8 break-words overflow-wrap-anywhere">{title}</h1>

                {/* Action Buttons */}
                <div className="flex flex-col gap-3">
                    {onRetry && (
                        <button
                            onClick={onRetry}
                            className="w-full px-6 py-3.5 bg-aegis-info hover:bg-aegis-info-dark rounded-xl font-semibold text-sm text-white flex items-center justify-center gap-2 transition-all"
                            style={{
                                boxShadow: '0 0 0 4px rgba(88, 166, 255, 0.15)'
                            }}
                        >
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                            </svg>
                            <span>{retryLabel}</span>
                        </button>
                    )}
                    
                    {onGoBack && (
                        <button
                            onClick={onGoBack}
                            className="w-full px-6 py-3.5 bg-aegis-gray hover:bg-aegis-gray-hover border border-aegis-border hover:border-aegis-border-muted rounded-xl font-semibold text-sm text-aegis-text-muted hover:text-aegis-text flex items-center justify-center gap-2 transition-all"
                        >
                            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
                            </svg>
                            <span>{goBackLabel}</span>
                        </button>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ErrorCard;

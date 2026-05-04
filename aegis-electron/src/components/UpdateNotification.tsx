import React, { useState, useEffect } from 'react';
import { Download, X, RefreshCw, CheckCircle } from 'lucide-react';

interface UpdateInfo {
    version: string;
    releaseNotes?: string | null;
}

type UpdateState = 'idle' | 'checking' | 'available' | 'downloading' | 'ready' | 'error';

const UpdateNotification: React.FC = () => {
    const [state, setState] = useState<UpdateState>('idle');
    const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
    const [progress, setProgress] = useState(0);
    const [error, setError] = useState<string | null>(null);
    const [dismissed, setDismissed] = useState(false);

    useEffect(() => {
        if (!window.updater) return;

        const unsubChecking = window.updater.onChecking(() => {
            setState('checking');
        });

        const unsubAvailable = window.updater.onUpdateAvailable((info) => {
            setState('downloading');
            setUpdateInfo(info);
            setDismissed(false);
        });

        const unsubProgress = window.updater.onDownloadProgress((prog) => {
            setProgress(prog.percent);
        });

        const unsubDownloaded = window.updater.onUpdateDownloaded((info) => {
            setState('ready');
            setUpdateInfo(info);
        });

        const unsubError = window.updater.onError((err) => {
            setState('error');
            setError(err.message);
        });

        return () => {
            unsubChecking();
            unsubAvailable();
            unsubProgress();
            unsubDownloaded();
            unsubError();
        };
    }, []);

    const handleInstall = async () => {
        await window.updater.installUpdate();
    };

    const handleDismiss = () => {
        setDismissed(true);
    };

    // Don't show if dismissed or no update
    if (dismissed || state === 'idle' || state === 'checking') {
        return null;
    }

    return (
        <div className="fixed bottom-4 right-4 z-50 max-w-sm">
            <div className="bg-[#1a1f2e] border border-[#30363d] rounded-lg shadow-xl p-4">
                {/* Header */}
                <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-2">
                        {state === 'ready' ? (
                            <CheckCircle className="w-5 h-5 text-emerald-400" />
                        ) : (
                            <Download className="w-5 h-5 text-blue-400" />
                        )}
                        <span className="font-semibold text-white">
                            {state === 'ready' ? 'Update Ready' : 'Downloading Update'}
                        </span>
                    </div>
                    <button
                        onClick={handleDismiss}
                        className="p-1 text-gray-400 hover:text-white rounded"
                    >
                        <X className="w-4 h-4" />
                    </button>
                </div>

                {/* Content */}
                <div className="text-sm text-gray-300 mb-3">
                    {state === 'ready' ? (
                        <p>Version {updateInfo?.version} is ready to install. Restart to update.</p>
                    ) : state === 'downloading' ? (
                        <>
                            <p className="mb-2">Downloading version {updateInfo?.version}...</p>
                            <div className="w-full bg-gray-700 rounded-full h-2">
                                <div
                                    className="bg-blue-500 h-2 rounded-full transition-all"
                                    style={{ width: `${progress}%` }}
                                />
                            </div>
                            <p className="text-xs text-gray-400 mt-1">{progress.toFixed(0)}%</p>
                        </>
                    ) : state === 'error' ? (
                        <p className="text-red-400">Update failed: {error}</p>
                    ) : null}
                </div>

                {/* Actions */}
                {state === 'ready' && (
                    <div className="flex gap-2">
                        <button
                            onClick={handleDismiss}
                            className="flex-1 px-3 py-2 text-sm text-gray-300 hover:text-white rounded border border-gray-600 hover:border-gray-500"
                        >
                            Later
                        </button>
                        <button
                            onClick={handleInstall}
                            className="flex-1 px-3 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded flex items-center justify-center gap-2"
                        >
                            <RefreshCw className="w-4 h-4" />
                            Restart
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default UpdateNotification;

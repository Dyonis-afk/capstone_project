/**
 * ChatTerminalLogViewer - Real-time log streaming for chat queries
 * Location: src/components/chat/ChatTerminalLogViewer.tsx
 *
 * Displays backend logs while waiting for chat responses.
 * Header changes based on view mode (normal vs report).
 */

import { useState, useEffect, useRef } from 'react';
import { ViewMode } from '../../types/chat';
import { API_URL } from '../../config/api';

interface ChatTerminalLogViewerProps {
    isActive: boolean;
    viewMode: ViewMode;
    baseUrl?: string;
    onCancel?: () => void;
}

interface LogEntry {
    id?: number;
    timestamp: string;
    level: string;
    message: string;
    logger?: string;
}

const ChatTerminalLogViewer = ({
    isActive,
    viewMode,
    baseUrl = API_URL,
    onCancel
}: ChatTerminalLogViewerProps) => {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting');
    const [lastError, setLastError] = useState<string | null>(null);
    const [elapsedSeconds, setElapsedSeconds] = useState(0);
    const scrollRef = useRef<HTMLDivElement>(null);
    const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);
    const timerIntervalRef = useRef<NodeJS.Timeout | null>(null);
    const lastLogIdRef = useRef<number>(0);
    const retryCountRef = useRef<number>(0);
    const sessionStartTimeRef = useRef<Date | null>(null);
    const prevIsActiveRef = useRef<boolean>(false);

    // Get header text based on view mode
    const getHeaderText = (): string => {
        if (viewMode === 'report') {
            return 'Generating Security Finding';
        }
        return 'Processing Query';
    };

    useEffect(() => {
        // Detect transition from inactive to active (new query starting)
        if (isActive && !prevIsActiveRef.current) {
            // New session starting - clear logs and set session start time
            setLogs([]);
            lastLogIdRef.current = 0;
            retryCountRef.current = 0;
            setConnectionStatus('connecting');
            setLastError(null);
            // Record when this session started (with small buffer for timing)
            sessionStartTimeRef.current = new Date(Date.now() - 1000);
        }
        prevIsActiveRef.current = isActive;

        if (!isActive) {
            // Clean up when not active
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
                pollIntervalRef.current = null;
            }
            return;
        }

        // Helper to check if a log is from the current session
        const isLogFromCurrentSession = (log: LogEntry): boolean => {
            if (!sessionStartTimeRef.current) return true;
            try {
                const logTime = new Date(log.timestamp);
                return logTime >= sessionStartTimeRef.current;
            } catch {
                return true; // If we can't parse, include it
            }
        };

        // Poll for logs
        const fetchLogs = async () => {
            try {
                const sinceParam = lastLogIdRef.current > 0 ? lastLogIdRef.current : 0;
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout

                // Use the chat logs endpoint (falls back to attack-paths logs)
                const response = await fetch(`${baseUrl}/api/chat/logs?since=${sinceParam}`, {
                    method: 'GET',
                    headers: {
                        'Accept': 'application/json'
                    },
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (response.ok) {
                    const data = await response.json();
                    setConnectionStatus('connected');
                    setLastError(null);
                    retryCountRef.current = 0;

                    // Update last_id
                    if (data.last_id !== undefined && data.last_id > 0) {
                        lastLogIdRef.current = data.last_id;
                    }

                    if (data.logs && data.logs.length > 0) {
                        setLogs(prev => {
                            // Filter out duplicates by ID and logs from previous sessions
                            const existingIds = new Set(prev.map(log => log.id));
                            const newLogs = data.logs.filter((log: LogEntry & { id?: number }) =>
                                log.id && !existingIds.has(log.id) && isLogFromCurrentSession(log)
                            );

                            if (newLogs.length > 0) {
                                const combined = [...prev, ...newLogs];
                                // Keep only last 100 logs for chat (smaller than report)
                                return combined.slice(-100);
                            }
                            return prev;
                        });
                    }
                } else {
                    // Try fallback to attack-paths logs endpoint
                    const fallbackResponse = await fetch(`${baseUrl}/api/attack-paths/logs?since=${sinceParam}`, {
                        method: 'GET',
                        headers: { 'Accept': 'application/json' }
                    });

                    if (fallbackResponse.ok) {
                        const data = await fallbackResponse.json();
                        setConnectionStatus('connected');
                        setLastError(null);
                        retryCountRef.current = 0;

                        if (data.last_id !== undefined && data.last_id > 0) {
                            lastLogIdRef.current = data.last_id;
                        }

                        if (data.logs && data.logs.length > 0) {
                            setLogs(prev => {
                                const existingIds = new Set(prev.map(log => log.id));
                                const newLogs = data.logs.filter((log: LogEntry & { id?: number }) =>
                                    log.id && !existingIds.has(log.id) && isLogFromCurrentSession(log)
                                );
                                if (newLogs.length > 0) {
                                    return [...prev, ...newLogs].slice(-100);
                                }
                                return prev;
                            });
                        }
                    } else {
                        retryCountRef.current++;
                        if (retryCountRef.current >= 3) {
                            setConnectionStatus('disconnected');
                        }
                    }
                }
            } catch (error: any) {
                const errorMessage = error?.name === 'AbortError' ? 'Timeout' : (error?.message || 'Network error');
                console.error('[ChatTerminalLogViewer] Error fetching logs:', errorMessage);
                setLastError(errorMessage);
                retryCountRef.current++;
                if (retryCountRef.current >= 3) {
                    setConnectionStatus('disconnected');
                }
            }
        };

        // Initial fetch
        fetchLogs();

        // Set up polling - 500ms for chat (balance between responsiveness and load)
        pollIntervalRef.current = setInterval(fetchLogs, 500);

        return () => {
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
            }
        };
    }, [isActive, baseUrl]);

    // Elapsed timer
    useEffect(() => {
        if (isActive) {
            setElapsedSeconds(0);
            timerIntervalRef.current = setInterval(() => {
                setElapsedSeconds(prev => prev + 1);
            }, 1000);
        } else {
            if (timerIntervalRef.current) {
                clearInterval(timerIntervalRef.current);
                timerIntervalRef.current = null;
            }
        }
        return () => {
            if (timerIntervalRef.current) clearInterval(timerIntervalRef.current);
        };
    }, [isActive]);

    const formatElapsed = (seconds: number): string => {
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return m > 0 ? `${m}m ${s.toString().padStart(2, '0')}s` : `${s}s`;
    };

    // Auto-scroll to bottom
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [logs]);

    const getLogColor = (level: string): string => {
        switch (level.toUpperCase()) {
            case 'ERROR':
            case 'CRITICAL':
                return 'text-red-400';
            case 'WARNING':
            case 'WARN':
                return 'text-yellow-400';
            case 'INFO':
                return 'text-blue-400';
            case 'DEBUG':
                return 'text-purple-400';
            case 'SUCCESS':
                return 'text-green-400';
            default:
                return 'text-gray-300';
        }
    };

    const formatTimestamp = (timestamp: string): string => {
        try {
            const date = new Date(timestamp);
            return date.toLocaleTimeString('en-US', {
                hour12: false,
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
            });
        } catch {
            return timestamp;
        }
    };

    if (!isActive) return null;

    return (
        <div className="w-full rounded-lg overflow-hidden border border-[#30363d] bg-black/90">
            {/* Terminal Header */}
            <div className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-white/10">
                <div className="flex items-center gap-2">
                    <div className="flex gap-1.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-red-500"></div>
                        <div className="w-2.5 h-2.5 rounded-full bg-yellow-500"></div>
                        <div className="w-2.5 h-2.5 rounded-full bg-green-500"></div>
                    </div>
                    <span className="text-xs text-white/80 ml-2 font-medium">
                        {getHeaderText()}
                    </span>
                </div>
                <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${
                        connectionStatus === 'connected' ? 'bg-green-500' :
                        connectionStatus === 'connecting' ? 'bg-yellow-500' : 'bg-red-500'
                    } animate-pulse`}></div>
                    <span className="text-xs text-white/60 font-mono">
                        {connectionStatus === 'connected' ? 'Connected' :
                            connectionStatus === 'connecting' ? 'Connecting...' :
                                `Disconnected${lastError ? ` (${lastError})` : ''}`}
                    </span>
                </div>
            </div>

            {/* Terminal Content */}
            <div
                ref={scrollRef}
                className="overflow-y-auto p-3 font-mono text-xs max-h-[200px]"
                style={{
                    fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace'
                }}
            >
                {logs.length === 0 ? (
                    <div className="text-gray-500">
                        <div className="flex items-center gap-2">
                            <span className="animate-pulse">▋</span>
                            <span>
                                {connectionStatus === 'connecting' ? 'Connecting to backend...' :
                                    connectionStatus === 'disconnected' ? 'Unable to connect to backend' :
                                        'Waiting for backend logs...'}
                            </span>
                        </div>
                    </div>
                ) : (
                    logs.map((log, index) => (
                        <div
                            key={log.id || index}
                            className="mb-0.5 flex items-start gap-2 hover:bg-white/5 px-1 py-0.5 rounded transition-colors"
                        >
                            <span className="text-gray-500 shrink-0 text-[10px] font-mono">
                                {formatTimestamp(log.timestamp)}
                            </span>
                            <span className={`shrink-0 w-14 text-[10px] font-semibold ${getLogColor(log.level)}`}>
                                {log.level.padEnd(7)}
                            </span>
                            <span className="text-gray-300 flex-1 text-[11px] break-words">
                                {log.message}
                            </span>
                        </div>
                    ))
                )}

                {/* Cursor indicator when active */}
                {isActive && (
                    <div className="flex items-center gap-2 text-gray-500 mt-1">
                        <span className="animate-pulse">▋</span>
                        <span className="text-[11px]">
                            {viewMode === 'report' ? 'Generating finding...' : 'Processing...'}
                        </span>
                    </div>
                )}
            </div>

            {/* Footer: Timer + Cancel */}
            {isActive && (
                <div className="flex items-center justify-between px-4 py-2 bg-gray-900 border-t border-white/10">
                    <div className="flex items-center gap-2 text-[11px] text-gray-400 font-mono">
                        <svg className="w-3.5 h-3.5 animate-spin text-[#58a6ff]" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        <span>Elapsed: {formatElapsed(elapsedSeconds)}</span>
                    </div>
                    {onCancel && (
                        <button
                            onClick={onCancel}
                            className="flex items-center gap-1.5 px-3 py-1 text-[11px] font-medium text-red-400 hover:text-red-300 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 rounded transition-colors"
                        >
                            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                            </svg>
                            Cancel
                        </button>
                    )}
                </div>
            )}
        </div>
    );
};

export default ChatTerminalLogViewer;

/**
 * TerminalLogViewer - Real-time log streaming from backend
 * Location: src/widgets/report/TerminalLogViewer.tsx
 *
 * Polls the backend /api/attack-paths/logs endpoint to display real-time logs
 * during report generation.
 */

import { useState, useEffect, useRef } from 'react';
import { API_URL } from '../../config/api';

interface TerminalLogViewerProps {
    isActive: boolean;
    baseUrl?: string;
}

interface LogEntry {
    id?: number;
    timestamp: string;
    level: string;
    message: string;
    logger?: string;
}

const TerminalLogViewer = ({ isActive, baseUrl = API_URL }: TerminalLogViewerProps) => {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting');
    const [lastError, setLastError] = useState<string | null>(null);
    const scrollRef = useRef<HTMLDivElement>(null);
    const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);
    const lastLogIdRef = useRef<number>(0);
    const retryCountRef = useRef<number>(0);
    const fetchingRef = useRef<boolean>(false);

    // Detect if backend is remote (not localhost)
    const isRemote = !baseUrl.includes('localhost') && !baseUrl.includes('127.0.0.1');
    const POLL_INTERVAL = isRemote ? 1500 : 300;
    const FETCH_TIMEOUT = isRemote ? 20000 : 15000;
    const MAX_RETRIES = isRemote ? 15 : 5;

    useEffect(() => {
        if (!isActive) {
            setLogs([]);
            lastLogIdRef.current = 0;
            retryCountRef.current = 0;
            fetchingRef.current = false;
            setConnectionStatus('connecting');
            setLastError(null);
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
                pollIntervalRef.current = null;
            }
            return;
        }

        // Poll for logs
        const fetchLogs = async () => {
            // Skip if a fetch is already in progress (prevents overlapping requests)
            if (fetchingRef.current) return;
            fetchingRef.current = true;

            try {
                const sinceParam = lastLogIdRef.current > 0 ? lastLogIdRef.current : 0;
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

                const response = await fetch(`${baseUrl}/api/attack-paths/logs?since=${sinceParam}`, {
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

                    // Always update last_id, even if no new logs
                    if (data.last_id !== undefined && data.last_id > 0) {
                        lastLogIdRef.current = data.last_id;
                    }

                    if (data.logs && data.logs.length > 0) {
                        setLogs(prev => {
                            // Filter out duplicates by ID
                            const existingIds = new Set(prev.map(log => log.id));
                            const newLogs = data.logs.filter((log: LogEntry & { id?: number }) =>
                                log.id && !existingIds.has(log.id)
                            );

                            if (newLogs.length > 0) {
                                const combined = [...prev, ...newLogs];
                                // Keep only last 200 logs to prevent memory issues
                                return combined.slice(-200);
                            }
                            return prev;
                        });
                    }
                } else {
                    const errorText = await response.text().catch(() => 'Unknown error');
                    console.error('[TerminalLogViewer] Failed to fetch logs:', response.status, errorText);
                    setLastError(`HTTP ${response.status}`);
                    retryCountRef.current++;
                    if (retryCountRef.current >= MAX_RETRIES) {
                        setConnectionStatus('disconnected');
                    }
                }
            } catch (error: any) {
                const errorMessage = error?.name === 'AbortError' ? 'Timeout' : (error?.message || 'Network error');
                console.error('[TerminalLogViewer] Error fetching logs:', errorMessage);
                setLastError(errorMessage);
                retryCountRef.current++;
                if (retryCountRef.current >= MAX_RETRIES) {
                    setConnectionStatus('disconnected');
                }
            } finally {
                fetchingRef.current = false;
            }
        };

        // Initial fetch immediately
        fetchLogs();

        // Adaptive polling: slower for remote servers, faster for local
        pollIntervalRef.current = setInterval(fetchLogs, POLL_INTERVAL);

        return () => {
            if (pollIntervalRef.current) {
                clearInterval(pollIntervalRef.current);
            }
        };
    }, [isActive, baseUrl]);

    // Auto-scroll to bottom when new logs arrive
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

    return (
        <div className="w-full h-full flex flex-col bg-black/90 overflow-hidden">
            {/* Terminal Header */}
            <div className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-white/10">
                <div className="flex items-center gap-2">
                    <div className="flex gap-1.5">
                        <div className="w-3 h-3 rounded-full bg-red-500"></div>
                        <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                        <div className="w-3 h-3 rounded-full bg-green-500"></div>
                    </div>
                    <span className="text-xs text-white/60 ml-2 font-mono">backend.log</span>
                </div>
                <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${connectionStatus === 'connected' ? 'bg-green-500' :
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
                className="flex-1 overflow-y-auto p-4 font-mono text-sm"
                style={{
                    fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace'
                }}
            >
                {logs.length === 0 ? (
                    <div className="text-gray-500">
                        <div className="mb-2 flex items-center gap-2">
                            <span className="animate-pulse">▋</span>
                            <span>
                                {connectionStatus === 'connecting' ? 'Connecting to backend...' :
                                    connectionStatus === 'disconnected' ? 'Unable to connect to backend' :
                                        'Waiting for backend logs...'}
                            </span>
                        </div>
                        <div className="text-gray-600 text-xs">
                            {connectionStatus === 'disconnected' && lastError ? (
                                <span className="text-red-400">Error: {lastError} - Check if backend is running at {baseUrl}</span>
                            ) : (
                                <span>Endpoint: {baseUrl}/api/attack-paths/logs</span>
                            )}
                        </div>
                    </div>
                ) : (
                    logs.map((log, index) => (
                        <div key={log.id || index} className="mb-1 flex items-start gap-2 hover:bg-white/5 px-2 py-0.5 rounded transition-colors">
                            <span className="text-gray-500 shrink-0 text-xs font-mono">
                                {formatTimestamp(log.timestamp)}
                            </span>
                            <span className={`shrink-0 w-16 text-xs font-semibold ${getLogColor(log.level)}`}>
                                {log.level.padEnd(7)}
                            </span>
                            <span className="text-gray-300 flex-1 text-xs break-words">{log.message}</span>
                        </div>
                    ))
                )}

                {/* Cursor indicator when active */}
                {isActive && (
                    <div className="flex items-center gap-2 text-gray-500 mt-2">
                        <span className="animate-pulse">▋</span>
                        <span>Generating report...</span>
                    </div>
                )}
            </div>
        </div>
    );
};

export default TerminalLogViewer;
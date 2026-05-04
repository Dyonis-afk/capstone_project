/**
 * Feedback IPC Handlers
 * Handles feedback submission from renderer process
 */

import { ipcMain } from 'electron';
import { sendToDiscord, isWebhookConfigured, FeedbackPayload } from './discordService.js';
import { getSanitizedSystemInfo } from './systemInfo.js';

// In-memory log buffer for including in feedback
let recentLogs: string[] = [];
const MAX_LOGS = 100;

// Rate limiting
const rateLimitMap = new Map<string, number>();
const RATE_LIMIT_MS = 30000; // 30 seconds between submissions

/**
 * Add a log entry to the buffer (call this from other parts of main process)
 */
export function addToLogBuffer(message: string): void {
    recentLogs.push(`[${new Date().toISOString()}] ${message}`);
    if (recentLogs.length > MAX_LOGS) {
        recentLogs = recentLogs.slice(-MAX_LOGS);
    }
}

/**
 * Get recent logs for feedback
 */
function getRecentLogs(count: number = 20): string[] {
    return recentLogs.slice(-count);
}

/**
 * Setup feedback IPC handlers
 */
export function setupFeedbackHandlers(): void {
    console.log('[Main] Setting up feedback IPC handlers...');

    // Submit feedback
    ipcMain.handle('feedback:submit', async (_, data: {
        type: 'bug' | 'feature' | 'feedback';
        title: string;
        description: string;
        email?: string;
        includeSystemInfo: boolean;
        includeLogs: boolean;
    }) => {
        try {
            // Rate limiting check
            const now = Date.now();
            const lastSubmit = rateLimitMap.get('feedback') || 0;

            if (now - lastSubmit < RATE_LIMIT_MS) {
                const waitSeconds = Math.ceil((RATE_LIMIT_MS - (now - lastSubmit)) / 1000);
                return { success: false, error: `Please wait ${waitSeconds} seconds before submitting again` };
            }

            rateLimitMap.set('feedback', now);

            const feedback: FeedbackPayload = {
                type: data.type,
                title: data.title,
                description: data.description,
                email: data.email,
                systemInfo: data.includeSystemInfo ? getSanitizedSystemInfo() : undefined,
                logs: data.includeLogs ? getRecentLogs(20) : undefined,
                timestamp: new Date().toISOString(),
            };

            const result = await sendToDiscord(feedback);

            return result;
        } catch (error: any) {
            console.error('[Feedback] Error submitting feedback:', error);
            return { success: false, error: error.message };
        }
    });

    // Get system info (for preview in modal)
    ipcMain.handle('feedback:getSystemInfo', async () => {
        try {
            return { success: true, data: getSanitizedSystemInfo() };
        } catch (error: any) {
            return { success: false, error: error.message };
        }
    });

    // Check if feedback is configured
    ipcMain.handle('feedback:isConfigured', async () => {
        return { success: true, data: isWebhookConfigured() };
    });

    console.log('[Main] Feedback IPC handlers registered');
}

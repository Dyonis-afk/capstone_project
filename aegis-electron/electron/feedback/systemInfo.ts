/**
 * System Information Collector
 * Gathers system details for feedback context
 */

import os from 'os';
import { app } from 'electron';

export interface SystemInfo {
    platform: string;
    osVersion: string;
    arch: string;
    aegisVersion: string;
    electronVersion: string;
    memory: string;
    nodeVersion: string;
    cpuCores: number;
}

/**
 * Get human-readable platform name
 */
function getPlatformName(): string {
    switch (process.platform) {
        case 'darwin': return 'macOS';
        case 'win32': return 'Windows';
        case 'linux': return 'Linux';
        default: return process.platform;
    }
}

/**
 * Get human-readable memory size
 */
function formatMemory(bytes: number): string {
    const gb = bytes / (1024 * 1024 * 1024);
    return `${gb.toFixed(1)} GB`;
}

/**
 * Collect system information
 */
export function getSystemInfo(): SystemInfo {
    return {
        platform: getPlatformName(),
        osVersion: os.release(),
        arch: process.arch,
        aegisVersion: app.getVersion(),
        electronVersion: process.versions.electron,
        memory: formatMemory(os.totalmem()),
        nodeVersion: process.versions.node,
        cpuCores: os.cpus().length,
    };
}

/**
 * Get sanitized system info (safe to send externally)
 */
export function getSanitizedSystemInfo(): SystemInfo {
    return getSystemInfo();
}

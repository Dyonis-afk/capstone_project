/**
 * Docker Preload Additions for AEGIS
 * Location: Add to src/electron/preload.ts
 * 
 * Add these type definitions and API exposure to your existing preload.ts
 */

import { contextBridge, ipcRenderer } from 'electron';

// ==================== TYPE DEFINITIONS ====================

export interface DockerStatus {
    dockerInstalled: boolean;
    dockerRunning: boolean;
    containerExists: boolean;
    containerRunning: boolean;
    neo4jReady: boolean;
    error?: string;
}

export interface DockerResult {
    success: boolean;
    message: string;
    error?: string;
}

export interface Neo4jConnectionInfo {
    uri: string;
    httpUrl: string;
    username: string;
    password: string;
}

// Docker API interface
export interface DockerAPI {
    // Status checks
    getStatus: () => Promise<DockerStatus>;
    isInstalled: () => Promise<boolean>;
    isRunning: () => Promise<boolean>;
    isNeo4jRunning: () => Promise<boolean>;
    isNeo4jReady: () => Promise<boolean>;

    // Actions
    start: () => Promise<DockerResult>;
    stop: () => Promise<DockerResult>;
    setup: () => Promise<DockerResult>;
    pullImage: () => Promise<DockerResult>;
    remove: () => Promise<DockerResult>;
    reset: () => Promise<DockerResult>;

    // Utility
    getLogs: (lines?: number) => Promise<string>;
    getConnectionInfo: () => Promise<Neo4jConnectionInfo>;

    // Progress listener
    onProgress: (callback: (message: string) => void) => () => void;
}

// ==================== EXPOSE DOCKER API ====================

const dockerAPI: DockerAPI = {
    // Status checks
    getStatus: () => ipcRenderer.invoke('docker:getStatus'),
    isInstalled: () => ipcRenderer.invoke('docker:isInstalled'),
    isRunning: () => ipcRenderer.invoke('docker:isRunning'),
    isNeo4jRunning: () => ipcRenderer.invoke('docker:isNeo4jRunning'),
    isNeo4jReady: () => ipcRenderer.invoke('docker:isNeo4jReady'),

    // Actions
    start: () => ipcRenderer.invoke('docker:start'),
    stop: () => ipcRenderer.invoke('docker:stop'),
    setup: () => ipcRenderer.invoke('docker:setup'),
    pullImage: () => ipcRenderer.invoke('docker:pullImage'),
    remove: () => ipcRenderer.invoke('docker:remove'),
    reset: () => ipcRenderer.invoke('docker:reset'),

    // Utility
    getLogs: (lines = 50) => ipcRenderer.invoke('docker:getLogs', lines),
    getConnectionInfo: () => ipcRenderer.invoke('docker:getConnectionInfo'),

    // Progress listener - returns unsubscribe function
    onProgress: (callback: (message: string) => void) => {
        const handler = (_event: any, message: string) => callback(message);
        ipcRenderer.on('docker:progress', handler);
        // Return unsubscribe function
        return () => ipcRenderer.removeListener('docker:progress', handler);
    }
};

// Expose to renderer
contextBridge.exposeInMainWorld('docker', dockerAPI);

// ==================== TYPE DECLARATIONS ====================

declare global {
    interface Window {
        docker: DockerAPI;
    }
}
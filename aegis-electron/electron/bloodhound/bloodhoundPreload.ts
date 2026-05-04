/** Preload bridge for BloodHound file selection and domain extraction. */

import { contextBridge, ipcRenderer } from 'electron';

// ==================== TYPE DEFINITIONS ====================

export interface FileSelectionResult {
    success: boolean;
    filePath?: string;
    fileName?: string;
    error?: string;
}

export interface DomainExtractionResult {
    success: boolean;
    domains?: string[];
    error?: string;
}

// BloodHound API interface
export interface BloodHoundAPI {
    // File selection only - BloodHound CE handles parsing
    selectFile: () => Promise<FileSelectionResult>;

    // Legacy alias for backwards compatibility
    openAndParse: () => Promise<FileSelectionResult>;

    // Domain extraction for validating re-uploads
    extractDomainsFromBuffer: (buffer: ArrayBuffer, fileName: string) => Promise<DomainExtractionResult>;
    extractDomainsFromFile: (filePath: string) => Promise<DomainExtractionResult>;
}

// ==================== EXPOSE BLOODHOUND API ====================

const bloodhoundAPI: BloodHoundAPI = {
    selectFile: () => ipcRenderer.invoke('bloodhound:selectFile'),
    openAndParse: () => ipcRenderer.invoke('bloodhound:selectFile'), // Redirects to selectFile
    extractDomainsFromBuffer: (buffer: ArrayBuffer, fileName: string) =>
        ipcRenderer.invoke('bloodhound:extractDomainsFromBuffer', buffer, fileName),
    extractDomainsFromFile: (filePath: string) =>
        ipcRenderer.invoke('bloodhound:extractDomainsFromFile', filePath),
};

// Expose to renderer
contextBridge.exposeInMainWorld('bloodhound', bloodhoundAPI);

// ==================== TYPE DECLARATIONS ====================

declare global {
    interface Window {
        bloodhound: BloodHoundAPI;
    }
}

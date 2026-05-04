/** IPC handlers for BloodHound file selection dialog and domain extraction. */

import { ipcMain, dialog, OpenDialogReturnValue } from 'electron';
import * as path from 'path';
import AdmZip from 'adm-zip';
import * as fs from 'fs';

/**
 * Extract domain names from BloodHound data
 * Looks for domain names in:
 * 1. domains.json file in ZIP
 * 2. Principal names (USER@DOMAIN.LOCAL format)
 * 3. Domain labels in node data
 */
function extractDomainsFromBloodHoundData(data: any): string[] {
    const domains = new Set<string>();

    // Helper to extract domain from principal name (e.g., USER@DOMAIN.LOCAL)
    const extractDomainFromPrincipal = (name: string): string | null => {
        if (!name || typeof name !== 'string') return null;
        const atIndex = name.indexOf('@');
        if (atIndex > 0) {
            return name.substring(atIndex + 1).toUpperCase();
        }
        return null;
    };

    // If it's a single BloodHound JSON file (array format)
    if (Array.isArray(data)) {
        for (const item of data.slice(0, 100)) { // Sample first 100 items
            if (item.Properties?.name) {
                const domain = extractDomainFromPrincipal(item.Properties.name);
                if (domain) domains.add(domain);
            }
            if (item.Properties?.domain) {
                domains.add(String(item.Properties.domain).toUpperCase());
            }
        }
        return Array.from(domains);
    }

    // If it's a single BloodHound JSON file (object with data array - newer format)
    if (data.data && Array.isArray(data.data)) {
        for (const item of data.data.slice(0, 100)) {
            if (item.Properties?.name) {
                const domain = extractDomainFromPrincipal(item.Properties.name);
                if (domain) domains.add(domain);
            }
            if (item.Properties?.domain) {
                domains.add(String(item.Properties.domain).toUpperCase());
            }
        }
        return Array.from(domains);
    }

    // If it's a domain object directly
    if (data.Properties?.name && data.ObjectType === 'Domain') {
        domains.add(String(data.Properties.name).toUpperCase());
    }

    return Array.from(domains);
}

/**
 * Extract domains from a ZIP buffer containing BloodHound JSON files
 */
function extractDomainsFromZipBuffer(buffer: Buffer): string[] {
    const domains = new Set<string>();

    try {
        const zip = new AdmZip(buffer);
        const entries = zip.getEntries();

        for (const entry of entries) {
            if (entry.isDirectory) continue;

            const name = entry.entryName.toLowerCase();
            // Prioritize domains.json, but also check other files
            if (name.endsWith('.json')) {
                try {
                    const content = entry.getData().toString('utf8');
                    const data = JSON.parse(content);

                    // If this is domains.json, extract directly
                    if (name.includes('domain') || name.endsWith('domains.json')) {
                        const extracted = extractDomainsFromBloodHoundData(data);
                        extracted.forEach(d => domains.add(d));

                        // If we found domains in domains.json, we can stop
                        if (domains.size > 0) {
                            console.log(`[BloodHound] Found domains in ${entry.entryName}:`, Array.from(domains));
                            break;
                        }
                    }

                    // Otherwise sample from users/groups/computers
                    if (name.includes('user') || name.includes('group') || name.includes('computer')) {
                        const extracted = extractDomainsFromBloodHoundData(data);
                        extracted.forEach(d => domains.add(d));

                        // Stop after finding domains
                        if (domains.size > 0) {
                            console.log(`[BloodHound] Found domains in ${entry.entryName}:`, Array.from(domains));
                            break;
                        }
                    }
                } catch (parseError) {
                    // Skip files that can't be parsed
                    console.log(`[BloodHound] Could not parse ${entry.entryName}`);
                }
            }
        }
    } catch (error) {
        console.error('[BloodHound] Error extracting domains from ZIP:', error);
    }

    return Array.from(domains);
}

/**
 * Extract domains from a JSON file content
 */
function extractDomainsFromJsonContent(content: string): string[] {
    try {
        const data = JSON.parse(content);
        return extractDomainsFromBloodHoundData(data);
    } catch (error) {
        console.error('[BloodHound] Error parsing JSON:', error);
        return [];
    }
}

export function setupBloodHoundHandlers(): void {
    console.log('[Main] Setting up BloodHound IPC handlers (simplified)...');

    /**
     * Open file dialog and return selected file path
     * BloodHound CE will handle all parsing when uploaded via API
     */
    ipcMain.handle('bloodhound:selectFile', async (): Promise<{
        success: boolean;
        filePath?: string;
        fileName?: string;
        error?: string;
    }> => {
        try {
            const dialogOptions = {
                title: 'Select BloodHound File',
                filters: [
                    { name: 'BloodHound Files', extensions: ['zip', 'json'] },
                    { name: 'ZIP Archives', extensions: ['zip'] },
                    { name: 'JSON Files', extensions: ['json'] },
                    { name: 'All Files', extensions: ['*'] }
                ],
                properties: ['openFile'] as Array<'openFile'>
            };

            const dialogResult = await dialog.showOpenDialog(dialogOptions) as unknown as OpenDialogReturnValue;

            if (dialogResult.canceled || !dialogResult.filePaths || dialogResult.filePaths.length === 0) {
                return { success: false, error: 'No file selected' };
            }

            const filePath = dialogResult.filePaths[0];
            const fileName = path.basename(filePath);

            console.log(`[BloodHound] User selected file: ${fileName}`);

            return {
                success: true,
                filePath,
                fileName
            };
        } catch (error: any) {
            console.error('[BloodHound] File selection error:', error);
            return { success: false, error: error.message };
        }
    });

    // Legacy handler for backwards compatibility - redirects to new flow
    ipcMain.handle('bloodhound:openAndParse', async (): Promise<{
        success: boolean;
        filePath?: string;
        fileName?: string;
        error?: string;
    }> => {
        console.log('[BloodHound] Legacy openAndParse called - redirecting to selectFile');
        // Just select the file - actual parsing is done by BloodHound CE
        return ipcMain.emit('bloodhound:selectFile') as any;
    });

    /**
     * Extract domain names from a BloodHound file buffer
     * Used to verify uploaded data matches the project's domain
     */
    ipcMain.handle('bloodhound:extractDomainsFromBuffer', async (_, buffer: ArrayBuffer, fileName: string): Promise<{
        success: boolean;
        domains?: string[];
        error?: string;
    }> => {
        try {
            console.log(`[BloodHound] Extracting domains from file: ${fileName}`);

            const nodeBuffer = Buffer.from(buffer);
            let domains: string[] = [];

            if (fileName.toLowerCase().endsWith('.zip')) {
                domains = extractDomainsFromZipBuffer(nodeBuffer);
            } else if (fileName.toLowerCase().endsWith('.json')) {
                const content = nodeBuffer.toString('utf8');
                domains = extractDomainsFromJsonContent(content);
            } else {
                return { success: false, error: 'Unsupported file type. Only .zip and .json files are supported.' };
            }

            console.log(`[BloodHound] Extracted domains:`, domains);

            return {
                success: true,
                domains
            };
        } catch (error: any) {
            console.error('[BloodHound] Error extracting domains:', error);
            return { success: false, error: error.message };
        }
    });

    /**
     * Extract domain names from a file path
     * Useful when file is already on disk
     */
    ipcMain.handle('bloodhound:extractDomainsFromFile', async (_, filePath: string): Promise<{
        success: boolean;
        domains?: string[];
        error?: string;
    }> => {
        try {
            console.log(`[BloodHound] Extracting domains from file path: ${filePath}`);

            if (!fs.existsSync(filePath)) {
                return { success: false, error: 'File not found' };
            }

            const buffer = fs.readFileSync(filePath);
            const fileName = path.basename(filePath);
            let domains: string[] = [];

            if (fileName.toLowerCase().endsWith('.zip')) {
                domains = extractDomainsFromZipBuffer(buffer);
            } else if (fileName.toLowerCase().endsWith('.json')) {
                const content = buffer.toString('utf8');
                domains = extractDomainsFromJsonContent(content);
            } else {
                return { success: false, error: 'Unsupported file type. Only .zip and .json files are supported.' };
            }

            console.log(`[BloodHound] Extracted domains:`, domains);

            return {
                success: true,
                domains
            };
        } catch (error: any) {
            console.error('[BloodHound] Error extracting domains from file:', error);
            return { success: false, error: error.message };
        }
    });

    console.log('[Main] BloodHound IPC handlers registered (with domain extraction)');
}

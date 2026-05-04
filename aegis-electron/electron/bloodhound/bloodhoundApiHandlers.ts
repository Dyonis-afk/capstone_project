/**
 * BloodHound CE API IPC Handlers
 * Location: electron/bloodhound/bloodhoundApiHandlers.ts
 *
 * Exposes BloodHound CE API functions to renderer process
 */

import { ipcMain } from 'electron';
import { bloodhoundApi, BloodHoundCredentials } from './bloodhoundApi.js';
import { neo4jService } from '../neo4j/neo4jService.js';
import * as fs from 'fs';
import * as path from 'path';
import { app } from 'electron';

// Store for project files
const projectFilesDir = path.join(app.getPath('userData'), 'bloodhound-projects');

// Ensure project files directory exists
if (!fs.existsSync(projectFilesDir)) {
    fs.mkdirSync(projectFilesDir, { recursive: true });
}

export function setupBloodHoundApiHandlers(): void {
    console.log('[Main] Setting up BloodHound API IPC handlers...');

    /**
     * Get config file path for a specific mode
     * Docker and Custom modes have separate credential storage
     */
    const getConfigPath = (mode: 'docker' | 'custom'): string => {
        return path.join(app.getPath('userData'), `bloodhound-config-${mode}.json`);
    };

    /**
     * Set BloodHound CE API credentials (mode-specific)
     */
    ipcMain.handle('bloodhound-api:setCredentials', async (_, credentials: BloodHoundCredentials, mode: 'docker' | 'custom' = 'docker') => {
        try {
            bloodhoundApi.setCredentials(credentials);
            const configPath = getConfigPath(mode);
            fs.writeFileSync(configPath, JSON.stringify(credentials));
            console.log(`[BloodHoundAPI] Credentials saved for mode: ${mode}`);
            return { success: true };
        } catch (error: any) {
            return { success: false, error: error.message };
        }
    });

    /**
     * Get BloodHound CE API credentials (mode-specific)
     */
    ipcMain.handle('bloodhound-api:getCredentials', async (_, mode: 'docker' | 'custom' = 'docker') => {
        try {
            const configPath = getConfigPath(mode);
            if (fs.existsSync(configPath)) {
                const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
                bloodhoundApi.setCredentials(config);
                return config;
            }
            return null;
        } catch (error) {
            return null;
        }
    });

    /**
     * Check if API credentials are configured (mode-specific)
     */
    ipcMain.handle('bloodhound-api:hasCredentials', async (_, mode: 'docker' | 'custom' = 'docker') => {
        try {
            const configPath = getConfigPath(mode);
            if (fs.existsSync(configPath)) {
                const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
                if (config.tokenId && config.tokenKey) {
                    bloodhoundApi.setCredentials(config);
                    return true;
                }
            }
            return false;
        } catch (error) {
            console.error('[BloodHoundAPI] Failed to load credentials from file:', error);
            return false;
        }
    });

    /**
     * Test BloodHound CE API connection
     */
    ipcMain.handle('bloodhound-api:testConnection', async () => {
        return await bloodhoundApi.testConnection();
    });

    /**
     * Upload file to BloodHound CE and save for project
     */
    ipcMain.handle('bloodhound-api:uploadFile', async (event, filePath: string, projectId: string) => {
        try {
            // Save a copy of the file for this project
            const fileName = path.basename(filePath);
            const projectFilePath = path.join(projectFilesDir, `${projectId}_${fileName}`);
            fs.copyFileSync(filePath, projectFilePath);

            // Upload to BloodHound CE
            const result = await bloodhoundApi.uploadFile(filePath, (step, progress) => {
                event.sender.send('bloodhound-api:uploadProgress', { step, progress });
            });

            if (result.success) {
                // Store project file reference
                const projectsIndex = path.join(projectFilesDir, 'projects-index.json');
                let index: Record<string, string> = {};
                if (fs.existsSync(projectsIndex)) {
                    index = JSON.parse(fs.readFileSync(projectsIndex, 'utf-8'));
                }
                index[projectId] = projectFilePath;
                fs.writeFileSync(projectsIndex, JSON.stringify(index));
            }

            return result;
        } catch (error: any) {
            return { success: false, message: 'Upload failed', error: error.message };
        }
    });

    /**
     * Upload buffer to BloodHound CE and save for project
     */
    ipcMain.handle('bloodhound-api:uploadBuffer', async (event, buffer: ArrayBuffer, fileName: string, projectId: string) => {
        try {
            const nodeBuffer = Buffer.from(buffer);

            // Save a copy of the file for this project
            const projectFilePath = path.join(projectFilesDir, `${projectId}_${fileName}`);
            fs.writeFileSync(projectFilePath, nodeBuffer);

            // Upload to BloodHound CE
            const result = await bloodhoundApi.uploadBuffer(nodeBuffer, fileName, (step, progress) => {
                event.sender.send('bloodhound-api:uploadProgress', { step, progress });
            });

            if (result.success) {
                // Store project file reference
                const projectsIndex = path.join(projectFilesDir, 'projects-index.json');
                let index: Record<string, string> = {};
                if (fs.existsSync(projectsIndex)) {
                    index = JSON.parse(fs.readFileSync(projectsIndex, 'utf-8'));
                }
                index[projectId] = projectFilePath;
                fs.writeFileSync(projectsIndex, JSON.stringify(index));
            }

            return result;
        } catch (error: any) {
            return { success: false, message: 'Upload failed', error: error.message };
        }
    });

    /**
     * Switch to a different project (clear Neo4j and re-import)
     */
    ipcMain.handle('bloodhound-api:switchProject', async (event, projectId: string) => {
        try {
            // Get project file path
            const projectsIndex = path.join(projectFilesDir, 'projects-index.json');
            if (!fs.existsSync(projectsIndex)) {
                return { success: false, error: 'No projects found' };
            }

            const index = JSON.parse(fs.readFileSync(projectsIndex, 'utf-8'));
            const projectFilePath = index[projectId];

            if (!projectFilePath || !fs.existsSync(projectFilePath)) {
                return { success: false, error: 'Project file not found' };
            }

            event.sender.send('bloodhound-api:uploadProgress', { step: 'Clearing database...', progress: 10 });

            // Clear Neo4j data
            const clearResult = await neo4jService.clearAllData();
            if (!clearResult.success) {
                console.warn('[BloodHoundAPI] Neo4j clear warning:', clearResult.error);
            }

            event.sender.send('bloodhound-api:uploadProgress', { step: 'Re-importing project...', progress: 30 });

            // Re-upload to BloodHound CE
            const uploadResult = await bloodhoundApi.uploadFile(projectFilePath, (step, progress) => {
                // Scale progress from 30-100
                const scaledProgress = 30 + (progress * 0.7);
                event.sender.send('bloodhound-api:uploadProgress', { step, progress: scaledProgress });
            });

            return uploadResult;
        } catch (error: any) {
            return { success: false, message: 'Failed to switch project', error: error.message };
        }
    });

    /**
     * Get list of stored projects
     */
    ipcMain.handle('bloodhound-api:getStoredProjects', async () => {
        try {
            const projectsIndex = path.join(projectFilesDir, 'projects-index.json');
            if (!fs.existsSync(projectsIndex)) {
                return {};
            }
            return JSON.parse(fs.readFileSync(projectsIndex, 'utf-8'));
        } catch (error) {
            return {};
        }
    });

    /**
     * Delete project data
     */
    ipcMain.handle('bloodhound-api:deleteProject', async (_, projectId: string) => {
        try {
            const projectsIndex = path.join(projectFilesDir, 'projects-index.json');
            if (!fs.existsSync(projectsIndex)) {
                return { success: true };
            }

            const index = JSON.parse(fs.readFileSync(projectsIndex, 'utf-8'));
            const projectFilePath = index[projectId];

            // Delete file if exists
            if (projectFilePath && fs.existsSync(projectFilePath)) {
                fs.unlinkSync(projectFilePath);
            }

            // Remove from index
            delete index[projectId];
            fs.writeFileSync(projectsIndex, JSON.stringify(index));

            return { success: true };
        } catch (error: any) {
            return { success: false, error: error.message };
        }
    });

    /**
     * Clear all BloodHound CE / Neo4j data
     */
    ipcMain.handle('bloodhound-api:clearAllData', async () => {
        try {
            // Try BloodHound CE API first
            const bhResult = await bloodhoundApi.clearAllData();

            // Also clear via Neo4j directly as fallback
            const neo4jResult = await neo4jService.clearAllData();

            return {
                success: bhResult.success || neo4jResult.success,
                error: bhResult.error || neo4jResult.error
            };
        } catch (error: any) {
            return { success: false, error: error.message };
        }
    });

    console.log('[Main] BloodHound API IPC handlers registered');
}

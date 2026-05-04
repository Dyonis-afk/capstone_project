/**
 * Docker IPC Handlers for AEGIS
 * Location: src/electron/dockerHandlers.ts
 * 
 * Add these handlers to your main.ts setupDatabaseHandlers() function
 * or create a new setupDockerHandlers() function
 */

import { ipcMain } from 'electron';
import { dockerService, DockerStatus, DockerResult, ExistingBloodHoundInfo } from './dockerService.js';

// Progress callback store for sending updates to renderer
let progressCallback: ((message: string) => void) | null = null;

export function setupDockerHandlers(): void {
    console.log('[Main] Setting up Docker IPC handlers...');

    // ----- STATUS HANDLERS -----

    /**
     * Get complete Docker/Neo4j status
     */
    ipcMain.handle('docker:getStatus', async (): Promise<DockerStatus> => {
        try {
            return await dockerService.getStatus();
        } catch (error: any) {
            console.error('[Main] Error getting Docker status:', error);
            return {
                dockerInstalled: false,
                dockerRunning: false,
                containerExists: false,
                containerRunning: false,
                neo4jReady: false,
                error: error.message
            };
        }
    });

    /**
     * Check if Docker is installed
     */
    ipcMain.handle('docker:isInstalled', async (): Promise<boolean> => {
        try {
            return await dockerService.isDockerInstalled();
        } catch (error) {
            console.error('[Main] Error checking Docker installation:', error);
            return false;
        }
    });

    /**
     * Check if Docker daemon is running
     */
    ipcMain.handle('docker:isRunning', async (): Promise<boolean> => {
        try {
            return await dockerService.isDockerRunning();
        } catch (error) {
            console.error('[Main] Error checking Docker daemon:', error);
            return false;
        }
    });

    /**
     * Check if Neo4j container is running
     */
    ipcMain.handle('docker:isNeo4jRunning', async (): Promise<boolean> => {
        try {
            return await dockerService.isContainerRunning();
        } catch (error) {
            console.error('[Main] Error checking Neo4j container:', error);
            return false;
        }
    });

    /**
     * Check if Neo4j is ready to accept connections
     */
    ipcMain.handle('docker:isNeo4jReady', async (): Promise<boolean> => {
        try {
            return await dockerService.isNeo4jReady();
        } catch (error) {
            console.error('[Main] Error checking Neo4j readiness:', error);
            return false;
        }
    });

    // ----- ACTION HANDLERS -----

    /**
     * Start Neo4j container
     */
    ipcMain.handle('docker:start', async (event): Promise<DockerResult> => {
        try {
            const onProgress = (message: string) => {
                console.log('[Docker]', message);
                // Send progress to renderer
                event.sender.send('docker:progress', message);
            };

            return await dockerService.startContainer(onProgress);
        } catch (error: any) {
            console.error('[Main] Error starting Docker:', error);
            return { success: false, message: 'Failed to start Neo4j', error: error.message };
        }
    });

    /**
     * Stop Neo4j container
     */
    ipcMain.handle('docker:stop', async (): Promise<DockerResult> => {
        try {
            return await dockerService.stopContainer();
        } catch (error: any) {
            console.error('[Main] Error stopping Docker:', error);
            return { success: false, message: 'Failed to stop Neo4j', error: error.message };
        }
    });

    /**
     * First-time setup (pull image + create container)
     */
    ipcMain.handle('docker:setup', async (event): Promise<DockerResult> => {
        try {
            const onProgress = (message: string) => {
                console.log('[Docker Setup]', message);
                // Send progress to renderer
                event.sender.send('docker:progress', message);
            };

            return await dockerService.setup(onProgress);
        } catch (error: any) {
            console.error('[Main] Error during Docker setup:', error);
            return { success: false, message: 'Setup failed', error: error.message };
        }
    });

    /**
     * Pull Neo4j image
     */
    ipcMain.handle('docker:pullImage', async (event): Promise<DockerResult> => {
        try {
            const onProgress = (message: string) => {
                console.log('[Docker Pull]', message);
                event.sender.send('docker:progress', message);
            };

            return await dockerService.pullImage(onProgress);
        } catch (error: any) {
            console.error('[Main] Error pulling image:', error);
            return { success: false, message: 'Failed to pull image', error: error.message };
        }
    });

    /**
     * Remove Neo4j container (keeps data)
     */
    ipcMain.handle('docker:remove', async (): Promise<DockerResult> => {
        try {
            return await dockerService.removeContainer();
        } catch (error: any) {
            console.error('[Main] Error removing container:', error);
            return { success: false, message: 'Failed to remove container', error: error.message };
        }
    });

    /**
     * Full reset (remove container + data)
     */
    ipcMain.handle('docker:reset', async (): Promise<DockerResult> => {
        try {
            return await dockerService.fullReset();
        } catch (error: any) {
            console.error('[Main] Error during reset:', error);
            return { success: false, message: 'Reset failed', error: error.message };
        }
    });

    // ----- UTILITY HANDLERS -----

    /**
     * Get container logs
     */
    ipcMain.handle('docker:getLogs', async (_, lines: number = 50): Promise<string> => {
        try {
            return await dockerService.getLogs(lines);
        } catch (error: any) {
            console.error('[Main] Error getting logs:', error);
            return '';
        }
    });

    /**
     * Get Neo4j connection info
     */
    ipcMain.handle('docker:getConnectionInfo', async () => {
        return dockerService.getConnectionInfo();
    });

    // ----- BLOODHOUND CONFLICT DETECTION HANDLERS -----

    /**
     * Detect existing non-AEGIS BloodHound CE installation
     */
    ipcMain.handle('docker:detectExistingBloodHound', async (): Promise<ExistingBloodHoundInfo> => {
        try {
            return await dockerService.detectExistingBloodHound();
        } catch (error: any) {
            console.error('[Main] Error detecting existing BloodHound:', error);
            return {
                detected: false,
                containers: [],
                conflictingPorts: [],
                recommendation: ''
            };
        }
    });

    /**
     * Stop existing non-AEGIS BloodHound containers
     */
    ipcMain.handle('docker:stopExistingBloodHound', async (): Promise<DockerResult> => {
        try {
            return await dockerService.stopExistingBloodHound();
        } catch (error: any) {
            console.error('[Main] Error stopping existing BloodHound:', error);
            return { success: false, message: 'Failed to stop existing BloodHound', error: error.message };
        }
    });

    /**
     * Get debug information for troubleshooting Docker issues
     * Useful for diagnosing production build problems
     */
    ipcMain.handle('docker:getDebugInfo', async () => {
        try {
            return dockerService.getDebugInfo();
        } catch (error: any) {
            console.error('[Main] Error getting debug info:', error);
            return {
                composePath: 'Error retrieving',
                composeExists: false,
                isDev: false,
                isPackaged: true,
                appPath: 'Error',
                resourcesPath: 'Error',
                dirname: 'Error',
                nodeEnv: undefined,
                error: error.message
            };
        }
    });

    console.log('[Main] Docker IPC handlers registered');
}
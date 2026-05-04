import { app, BrowserWindow, ipcMain, shell, dialog } from 'electron';
import * as fs from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import electronUpdater from 'electron-updater';
const { autoUpdater } = electronUpdater;
import { databaseService } from './database.js';
import { setupDockerHandlers } from './docker/dockerHandlers.js';
import { setupNeo4jHandlers } from './neo4j/neo4jHandlers.js';
import { setupBloodHoundHandlers } from './bloodhound/bloodhoundHandlers.js';
import { setupBloodHoundApiHandlers } from './bloodhound/bloodhoundApiHandlers.js';
import { setupFeedbackHandlers } from './feedback/feedbackHandlers.js';
import { loadEnvForMode } from './utils/loadEnv.js';
import { initializeAnalytics, trackAppOpened, shutdownAnalytics } from './analytics/analyticsService.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const isDev = process.env.NODE_ENV === 'development';

// Load environment variables from .env file based on NODE_ENV
loadEnvForMode(join(__dirname, '..'));

// Prevent multiple windows
let mainWindow: BrowserWindow | null = null;

function createWindow(): void {
    // If window already exists, focus it instead of creating a new one
    if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.focus();
        return;
    }
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 1000,
        minHeight: 700,
        show: false,
        backgroundColor: '#111827', // Match bg-gray-900
        titleBarStyle: process.platform === 'darwin' ? 'hidden' : 'default',
        frame: true,
        icon: join(__dirname, '../build/icons/icon.png'), // App icon
        webPreferences: {
            preload: join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: false
        }
    });

    if (isDev) {
        const loadDevURL = () => {
            if (mainWindow) {
                mainWindow.loadURL('http://localhost:5173').catch((err) => {
                    console.error('Failed to load dev server:', err.message);
                });
            }
        };

        // Handle failed loads and retry
        mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription) => {
            if (errorCode === -106 || errorCode === -105) { // ERR_CONNECTION_REFUSED or ERR_NAME_NOT_RESOLVED
                console.log('Dev server not ready, retrying in 2 seconds...');
                setTimeout(loadDevURL, 2000);
            }
        });

        loadDevURL();
    } else {
        mainWindow.loadFile(join(__dirname, '../dist/index.html'));
    }

    // Forward console logs from renderer to terminal via IPC
    ipcMain.on('console-log', (event, level: 'log' | 'warn' | 'error' | 'info' | 'debug', args: any[]) => {
        const prefix = '[Renderer]';
        const timestamp = new Date().toISOString();

        // Format the message - limit size to prevent buffer overflow
        const message = args.map(arg => {
            if (typeof arg === 'object' && arg !== null) {
                try {
                    const str = JSON.stringify(arg);
                    return str.length > 500 ? str.substring(0, 500) + '...[truncated]' : str;
                } catch (e) {
                    return String(arg);
                }
            }
            return String(arg);
        }).join(' ');

        switch (level) {
            case 'log':
            case 'info':
                console.log(`${prefix} [${timestamp}] ${message}`);
                break;
            case 'warn':
                console.warn(`${prefix} [${timestamp}] ⚠️  ${message}`);
                break;
            case 'error':
                console.error(`${prefix} [${timestamp}] ❌ ${message}`);
                break;
            case 'debug':
                if (isDev) {
                    console.debug(`${prefix} [${timestamp}] ${message}`);
                }
                break;
            default:
                console.log(`${prefix} [${timestamp}] ${message}`);
        }
    });

    // Open external links in system browser (not inside the app)
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        // Open http/https links in system browser
        if (url.startsWith('http://') || url.startsWith('https://')) {
            shell.openExternal(url);
            return { action: 'deny' };
        }
        return { action: 'allow' };
    });

    // Also handle navigation attempts to external URLs
    mainWindow.webContents.on('will-navigate', (event, url) => {
        // Allow localhost dev server navigation
        if (isDev && url.startsWith('http://localhost:5173')) {
            return;
        }
        // Block and open external URLs in system browser
        if (url.startsWith('http://') || url.startsWith('https://')) {
            if (!url.includes('localhost:5173')) {
                event.preventDefault();
                shell.openExternal(url);
            }
        }
    });

    mainWindow.once('ready-to-show', () => {
        if (mainWindow) {
            mainWindow.show();
        }
    });

    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

// ==================== DATABASE IPC HANDLERS ====================

function setupDatabaseHandlers(): void {
    console.log('[Main] Setting up database IPC handlers...');

    // ----- PROJECT HANDLERS -----

    ipcMain.handle('db:createProject', async (_, name: string, description?: string, neo4jDatabase?: string, domainName?: string, tier0Config?: string) => {
        try {
            return { success: true, data: databaseService.createProject(name, description, neo4jDatabase, domainName, tier0Config) };
        } catch (error: any) {
            console.error('[Main] Error creating project:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:getAllProjects', async () => {
        try {
            return { success: true, data: databaseService.getAllProjects() };
        } catch (error: any) {
            console.error('[Main] Error getting projects:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:getProject', async (_, id: string) => {
        try {
            return { success: true, data: databaseService.getProject(id) };
        } catch (error: any) {
            console.error('[Main] Error getting project:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:updateProject', async (_, id: string, updates: any) => {
        try {
            return { success: true, data: databaseService.updateProject(id, updates) };
        } catch (error: any) {
            console.error('[Main] Error updating project:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:deleteProject', async (_, id: string) => {
        try {
            return { success: true, data: databaseService.deleteProject(id) };
        } catch (error: any) {
            console.error('[Main] Error deleting project:', error);
            return { success: false, error: error.message };
        }
    });

    // ----- CHAT HANDLERS -----

    ipcMain.handle('db:createChat', async (_, projectId: string, title: string) => {
        try {
            return { success: true, data: databaseService.createChat(projectId, title) };
        } catch (error: any) {
            console.error('[Main] Error creating chat:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:getChatsForProject', async (_, projectId: string) => {
        try {
            return { success: true, data: databaseService.getChatsForProject(projectId) };
        } catch (error: any) {
            console.error('[Main] Error getting chats:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:getChat', async (_, id: string) => {
        try {
            return { success: true, data: databaseService.getChat(id) };
        } catch (error: any) {
            console.error('[Main] Error getting chat:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:updateChat', async (_, id: string, title: string) => {
        try {
            return { success: true, data: databaseService.updateChat(id, title) };
        } catch (error: any) {
            console.error('[Main] Error updating chat:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:updateChatReportId', async (_, chatId: string, reportId: string) => {
        try {
            return { success: true, data: databaseService.updateChatReportId(chatId, reportId) };
        } catch (error: any) {
            console.error('[Main] Error updating chat report ID:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:deleteChat', async (_, id: string) => {
        try {
            return { success: true, data: databaseService.deleteChat(id) };
        } catch (error: any) {
            console.error('[Main] Error deleting chat:', error);
            return { success: false, error: error.message };
        }
    });

    // ----- MESSAGE HANDLERS -----

    ipcMain.handle('db:addMessage', async (_, chatId: string, role: 'user' | 'assistant', content: string, artifactType?: string, artifactId?: string, responseData?: object) => {
        try {
            return { success: true, data: databaseService.addMessage(chatId, role, content, artifactType, artifactId, responseData) };
        } catch (error: any) {
            console.error('[Main] Error adding message:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:getMessagesForChat', async (_, chatId: string) => {
        try {
            return { success: true, data: databaseService.getMessagesForChat(chatId) };
        } catch (error: any) {
            console.error('[Main] Error getting messages:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:getMessagesForChatPaginated', async (_, chatId: string, limit: number, offset: number = 0) => {
        try {
            return { success: true, data: databaseService.getMessagesForChatPaginated(chatId, limit, offset) };
        } catch (error: any) {
            console.error('[Main] Error getting paginated messages:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:deleteMessage', async (_, id: string) => {
        try {
            return { success: true, data: databaseService.deleteMessage(id) };
        } catch (error: any) {
            console.error('[Main] Error deleting message:', error);
            return { success: false, error: error.message };
        }
    });

    // ----- REPORT HANDLERS -----

    ipcMain.handle('db:saveReport', async (_, projectId: string, title: string, reportData: object, chatId?: string) => {
        try {
            return { success: true, data: databaseService.saveReport(projectId, title, reportData, chatId) };
        } catch (error: any) {
            console.error('[Main] Error saving report:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:getReportsForProject', async (_, projectId: string) => {
        try {
            return { success: true, data: databaseService.getReportsForProject(projectId) };
        } catch (error: any) {
            console.error('[Main] Error getting reports:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:getReport', async (_, id: string) => {
        try {
            return { success: true, data: databaseService.getReport(id) };
        } catch (error: any) {
            console.error('[Main] Error getting report:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:deleteReport', async (_, id: string) => {
        try {
            return { success: true, data: databaseService.deleteReport(id) };
        } catch (error: any) {
            console.error('[Main] Error deleting report:', error);
            return { success: false, error: error.message };
        }
    });

    // ----- ADDITIONAL FINDINGS HANDLERS -----

    ipcMain.handle('db:addFindingToReport', async (_, reportId: string, finding: any) => {
        try {
            return { success: true, data: databaseService.addFindingToReport(reportId, finding) };
        } catch (error: any) {
            console.error('[Main] Error adding finding to report:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:removeFindingFromReport', async (_, reportId: string, findingId: string) => {
        try {
            return { success: true, data: databaseService.removeFindingFromReport(reportId, findingId) };
        } catch (error: any) {
            console.error('[Main] Error removing finding from report:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:updateReportData', async (_, reportId: string, reportData: object) => {
        try {
            return { success: true, data: databaseService.updateReportData(reportId, reportData) };
        } catch (error: any) {
            console.error('[Main] Error updating report data:', error);
            return { success: false, error: error.message };
        }
    });

    // ----- SEARCH & UTILITY HANDLERS -----

    ipcMain.handle('db:searchMessages', async (_, projectId: string, query: string) => {
        try {
            return { success: true, data: databaseService.searchMessages(projectId, query) };
        } catch (error: any) {
            console.error('[Main] Error searching messages:', error);
            return { success: false, error: error.message };
        }
    });

    ipcMain.handle('db:getProjectStats', async (_, projectId: string) => {
        try {
            return { success: true, data: databaseService.getProjectStats(projectId) };
        } catch (error: any) {
            console.error('[Main] Error getting project stats:', error);
            return { success: false, error: error.message };
        }
    });

    console.log('[Main] Database IPC handlers registered');
}

// ==================== AUTO-UPDATER SETUP ====================

function setupAutoUpdater(): void {
    // Configure logging
    autoUpdater.logger = {
        info: (msg: string) => console.log('[AutoUpdater]', msg),
        warn: (msg: string) => console.warn('[AutoUpdater]', msg),
        error: (msg: string) => console.error('[AutoUpdater]', msg),
        debug: (msg: string) => isDev && console.debug('[AutoUpdater]', msg),
    };

    // Don't auto-download, we'll control when to download
    autoUpdater.autoDownload = false;
    autoUpdater.autoInstallOnAppQuit = true;

    // Event handlers
    autoUpdater.on('checking-for-update', () => {
        console.log('[AutoUpdater] Checking for updates...');
        mainWindow?.webContents.send('updater:checking');
    });

    autoUpdater.on('update-available', (info) => {
        console.log('[AutoUpdater] Update available:', info.version);
        mainWindow?.webContents.send('updater:update-available', {
            version: info.version,
            releaseDate: info.releaseDate,
            releaseNotes: info.releaseNotes,
        });
        // Auto-download the update (with error handling)
        autoUpdater.downloadUpdate().catch((err) => {
            console.error('[AutoUpdater] Download failed:', err.message);
            // Don't send error for transient network issues
            if (!err.message.includes('ERR_NETWORK_CHANGED')) {
                mainWindow?.webContents.send('updater:error', {
                    message: 'Download failed: ' + err.message,
                });
            }
        });
    });

    autoUpdater.on('update-not-available', (info) => {
        console.log('[AutoUpdater] No updates available. Current:', info.version);
        mainWindow?.webContents.send('updater:update-not-available', {
            version: info.version,
        });
    });

    autoUpdater.on('download-progress', (progress) => {
        console.log(`[AutoUpdater] Download progress: ${progress.percent.toFixed(1)}%`);
        mainWindow?.webContents.send('updater:download-progress', {
            percent: progress.percent,
            bytesPerSecond: progress.bytesPerSecond,
            transferred: progress.transferred,
            total: progress.total,
        });
    });

    autoUpdater.on('update-downloaded', (info) => {
        console.log('[AutoUpdater] Update downloaded:', info.version);
        mainWindow?.webContents.send('updater:update-downloaded', {
            version: info.version,
            releaseNotes: info.releaseNotes,
        });
    });

    autoUpdater.on('error', (error) => {
        console.error('[AutoUpdater] Error:', error.message);
        // Don't show transient network errors to the user
        const isTransientError = error.message.includes('ERR_NETWORK_CHANGED') ||
            error.message.includes('ERR_INTERNET_DISCONNECTED') ||
            error.message.includes('ERR_CONNECTION_RESET');
        if (!isTransientError) {
            mainWindow?.webContents.send('updater:error', {
                message: error.message,
            });
        }
    });
}

// ==================== AUTO-UPDATER IPC HANDLERS ====================

function setupUpdaterHandlers(): void {
    // Check for updates (manual trigger)
    ipcMain.handle('updater:check', async () => {
        try {
            const result = await autoUpdater.checkForUpdates();
            return { success: true, data: result };
        } catch (error: any) {
            console.error('[AutoUpdater] Check failed:', error.message);
            // Provide user-friendly error messages
            let userMessage = error.message;
            if (error.message.includes('ERR_NETWORK_CHANGED')) {
                userMessage = 'Network connection changed. Please try again.';
            } else if (error.message.includes('ERR_INTERNET_DISCONNECTED')) {
                userMessage = 'No internet connection. Please check your network.';
            } else if (error.message.includes('ERR_CONNECTION_RESET')) {
                userMessage = 'Connection was reset. Please try again.';
            }
            return { success: false, error: userMessage };
        }
    });

    // Install update and restart
    ipcMain.handle('updater:install', async () => {
        try {
            autoUpdater.quitAndInstall(false, true);
            return { success: true };
        } catch (error: any) {
            console.error('[AutoUpdater] Install failed:', error);
            return { success: false, error: error.message };
        }
    });

    // Get current version
    ipcMain.handle('updater:getVersion', () => {
        return app.getVersion();
    });

    console.log('[Main] Updater IPC handlers registered');
}

// ==================== FILE SAVE HANDLERS ====================

function setupFileSaveHandlers() {
    // Save file with dialog
    ipcMain.handle('file:saveWithDialog', async (_, options: {
        defaultFilename: string;
        content: string;
        encoding?: 'utf8' | 'base64';
        filters?: { name: string; extensions: string[] }[];
    }) => {
        try {
            const { defaultFilename, content, filters, encoding = 'utf8' } = options;

            const result = await dialog.showSaveDialog({
                defaultPath: defaultFilename,
                filters: filters || [
                    { name: 'JSON Files', extensions: ['json'] },
                    { name: 'All Files', extensions: ['*'] }
                ]
            });

            if (result.canceled || !result.filePath) {
                return { success: false, canceled: true };
            }

            // Handle different encodings (utf8 for text, base64 for binary like PDF)
            if (encoding === 'base64') {
                const buffer = Buffer.from(content, 'base64');
                fs.writeFileSync(result.filePath, buffer);
            } else {
                fs.writeFileSync(result.filePath, content, 'utf-8');
            }
            console.log('[FileSave] Saved file to:', result.filePath);

            return { success: true, filePath: result.filePath };
        } catch (error: any) {
            console.error('[FileSave] Failed to save file:', error);
            return { success: false, error: error.message };
        }
    });

    console.log('[Main] File save IPC handlers registered');
}

// ==================== APP LIFECYCLE ====================

app.whenReady().then(() => {
    console.log('[Main] App ready, initializing...');

    // Initialize database
    try {
        databaseService.initialize();
    } catch (error) {
        console.error('[Main] Failed to initialize database:', error);
    }

    // Setup IPC handlers
    setupDatabaseHandlers();
    setupDockerHandlers();
    setupNeo4jHandlers();
    setupBloodHoundHandlers();
    setupBloodHoundApiHandlers();
    setupFeedbackHandlers();

    // Setup auto-updater
    setupAutoUpdater();
    setupUpdaterHandlers();

    // Setup file save handlers
    setupFileSaveHandlers();

    // Create window
    createWindow();

    // Initialize analytics (PostHog)
    initializeAnalytics();
    trackAppOpened();

    // Check for updates after a short delay (don't block startup)
    if (!isDev) {
        setTimeout(() => {
            autoUpdater.checkForUpdates().catch((err) => {
                console.error('[AutoUpdater] Initial check failed:', err.message);
            });
        }, 3000);
    }
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});

app.on('before-quit', async () => {
    console.log('[Main] App quitting...');

    // Shutdown analytics (flush pending events)
    await shutdownAnalytics();

    // Close database
    databaseService.close();
    console.log('[Main] Cleanup complete');
});
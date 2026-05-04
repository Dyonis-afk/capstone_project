import { contextBridge, ipcRenderer } from 'electron';

// ==================== TYPE DEFINITIONS ====================

interface Project {
    id: string;
    name: string;
    description?: string;
    neo4j_database?: string;
    domain_name?: string;
    tier0_config?: string;
    created_at: string;
    updated_at: string;
}

interface Chat {
    id: string;
    project_id: string;
    title: string;
    report_id?: string;
    created_at: string;
    updated_at: string;
}

interface Message {
    id: string;
    chat_id: string;
    role: 'user' | 'assistant';
    content: string;
    artifact_type?: string;
    artifact_id?: string;
    response_data?: string;  // JSON string of ChatQueryResponse for intelligent chat
    created_at: string;
}

interface Report {
    id: string;
    project_id: string;
    chat_id?: string;
    title: string;
    report_data: string;
    created_at: string;
}

interface DBResult<T> {
    success: boolean;
    data?: T;
    error?: string;
}

interface ProjectStats {
    chatCount: number;
    messageCount: number;
    reportCount: number;
}

// Database API interface
interface DatabaseAPI {
    // Projects
    createProject: (name: string, description?: string, neo4jDatabase?: string, domainName?: string, tier0Config?: string) => Promise<DBResult<Project>>;
    getAllProjects: () => Promise<DBResult<Project[]>>;
    getProject: (id: string) => Promise<DBResult<Project | null>>;
    updateProject: (id: string, updates: Partial<Pick<Project, 'name' | 'description' | 'neo4j_database' | 'domain_name' | 'tier0_config'>>) => Promise<DBResult<Project | null>>;
    deleteProject: (id: string) => Promise<DBResult<boolean>>;

    // Chats
    createChat: (projectId: string, title: string) => Promise<DBResult<Chat>>;
    getChatsForProject: (projectId: string) => Promise<DBResult<Chat[]>>;
    getChat: (id: string) => Promise<DBResult<Chat | null>>;
    updateChat: (id: string, title: string) => Promise<DBResult<Chat | null>>;
    updateChatReportId: (chatId: string, reportId: string) => Promise<DBResult<Chat | null>>;
    deleteChat: (id: string) => Promise<DBResult<boolean>>;

    // Messages
    addMessage: (chatId: string, role: 'user' | 'assistant', content: string, artifactType?: string, artifactId?: string, responseData?: object) => Promise<DBResult<Message>>;
    getMessagesForChat: (chatId: string) => Promise<DBResult<Message[]>>;
    getMessagesForChatPaginated: (chatId: string, limit: number, offset?: number) => Promise<DBResult<{ messages: Message[], hasMore: boolean, totalCount: number }>>;
    deleteMessage: (id: string) => Promise<DBResult<boolean>>;

    // Reports
    saveReport: (projectId: string, title: string, reportData: object, chatId?: string) => Promise<DBResult<Report>>;
    getReportsForProject: (projectId: string) => Promise<DBResult<Report[]>>;
    getReport: (id: string) => Promise<DBResult<Report | null>>;
    deleteReport: (id: string) => Promise<DBResult<boolean>>;

    // Additional Findings (for chat-discovered findings)
    addFindingToReport: (reportId: string, finding: any) => Promise<DBResult<Report>>;
    removeFindingFromReport: (reportId: string, findingId: string) => Promise<DBResult<Report>>;
    updateReportData: (reportId: string, reportData: object) => Promise<DBResult<Report>>;

    // Search & Utility
    searchMessages: (projectId: string, query: string) => Promise<DBResult<Array<Message & { chat_title: string }>>>;
    getProjectStats: (projectId: string) => Promise<DBResult<ProjectStats>>;
}

// Electron API interface
interface ElectronAPI {
    getVersion: () => string;
    platform: string;
    logToMain: (level: 'log' | 'warn' | 'error' | 'info' | 'debug', ...args: any[]) => void;
}

// Docker API types
interface DockerStatus {
    dockerInstalled: boolean;
    dockerRunning: boolean;
    containerExists: boolean;
    containerRunning: boolean;
    neo4jReady: boolean;
    error?: string;
}

interface DockerResult {
    success: boolean;
    message: string;
    error?: string;
}

interface ExistingBloodHoundInfo {
    detected: boolean;
    containers: Array<{
        name: string;
        status: string;
        ports: string;
    }>;
    conflictingPorts: number[];
    recommendation: string;
}

interface Neo4jConnectionInfo {
    uri: string;
    httpUrl: string;
    username: string;
    password: string;
}

interface DockerAPI {
    getStatus: () => Promise<DockerStatus>;
    isInstalled: () => Promise<boolean>;
    isRunning: () => Promise<boolean>;
    isNeo4jRunning: () => Promise<boolean>;
    isNeo4jReady: () => Promise<boolean>;
    start: () => Promise<DockerResult>;
    stop: () => Promise<DockerResult>;
    setup: () => Promise<DockerResult>;
    pullImage: () => Promise<DockerResult>;
    remove: () => Promise<DockerResult>;
    reset: () => Promise<DockerResult>;
    getLogs: (lines?: number) => Promise<string>;
    getConnectionInfo: () => Promise<Neo4jConnectionInfo>;
    onProgress: (callback: (message: string) => void) => () => void;
    detectExistingBloodHound: () => Promise<ExistingBloodHoundInfo>;
    stopExistingBloodHound: () => Promise<DockerResult>;
}

// Neo4j API types
interface Neo4jConfig {
    uri: string;
    username: string;
    password: string;
}

interface Neo4jConnectionResult {
    connected: boolean;
    database?: string;
    nodeCount?: number;
    relationshipCount?: number;
    error?: string;
}

interface QueryResult {
    success: boolean;
    records: any[];
    count: number;
    error?: string;
}

interface DatabaseStats {
    nodes: { [label: string]: number };
    totalNodes: number;
    totalRelationships: number;
    labels: string[];
    relationshipTypes: string[];
}

// Extracted findings type
interface ExtractedFindings {
    high_risk: any[];
    medium_risk: any[];
    low_risk: any[];
    summary: {
        total_nodes: number;
        total_edges: number;
        high_risk_count: number;
        medium_risk_count: number;
        low_risk_count: number;
    };
    edge_type_counts: Record<string, number>;
    domains: string[];
    domain_admin_groups: string[];
    high_value_targets: Array<{ name: string; type: string; count: number }>;
}

interface EnvironmentInfo {
    domains: string[];
    domainAdminGroups: string[];
    highValueGroups: string[];
    serviceAccounts: string[];
    computers: string[];
    edgeTypes: string[];
}

interface Neo4jAPI {
    connect: () => Promise<Neo4jConnectionResult>;
    testConnection: () => Promise<Neo4jConnectionResult>;
    close: () => Promise<void>;
    setConfig: (config: Partial<Neo4jConfig>) => Promise<void>;
    getConfig: () => Promise<Neo4jConfig>;
    runQuery: (cypher: string, params?: Record<string, any>) => Promise<QueryResult>;
    getCommonQueries: () => Promise<Array<{ name: string; description: string; cypher: string }>>;
    getStatistics: () => Promise<DatabaseStats>;
    extractFindings: () => Promise<ExtractedFindings>;
    getEnvironmentInfo: () => Promise<EnvironmentInfo>;
    clearAllData: () => Promise<{ success: boolean; error?: string }>;
}

// BloodHound API types (simplified - BloodHound CE handles parsing)
interface FileSelectionResult {
    success: boolean;
    filePath?: string;
    fileName?: string;
    error?: string;
}

interface BloodHoundAPI {
    selectFile: () => Promise<FileSelectionResult>;
    openAndParse: () => Promise<FileSelectionResult>; // Legacy alias
}

// BloodHound CE API types
interface BloodHoundCECredentials {
    url: string;
    tokenId: string;
    tokenKey: string;
}

interface BloodHoundCEUploadResult {
    success: boolean;
    jobId?: string;
    message: string;
    error?: string;
}

// Neo4j connection mode type
type Neo4jMode = 'docker' | 'custom';

interface BloodHoundCEAPI {
    // Mode-specific credential management
    setCredentials: (credentials: BloodHoundCECredentials, mode?: Neo4jMode) => Promise<{ success: boolean; error?: string }>;
    getCredentials: (mode?: Neo4jMode) => Promise<BloodHoundCECredentials | null>;
    hasCredentials: (mode?: Neo4jMode) => Promise<boolean>;
    testConnection: () => Promise<{ success: boolean; error?: string }>;
    uploadFile: (filePath: string, projectId: string) => Promise<BloodHoundCEUploadResult>;
    uploadBuffer: (buffer: ArrayBuffer, fileName: string, projectId: string) => Promise<BloodHoundCEUploadResult>;
    switchProject: (projectId: string) => Promise<BloodHoundCEUploadResult>;
    getStoredProjects: () => Promise<Record<string, string>>;
    deleteProject: (projectId: string) => Promise<{ success: boolean; error?: string }>;
    clearAllData: () => Promise<{ success: boolean; error?: string }>;
    onUploadProgress: (callback: (progress: { step: string; progress: number }) => void) => () => void;
}

// Updater API types
interface UpdateInfo {
    version: string;
    releaseDate?: string;
    releaseNotes?: string | null;
}

interface DownloadProgress {
    percent: number;
    bytesPerSecond: number;
    transferred: number;
    total: number;
}

interface UpdaterAPI {
    checkForUpdates: () => Promise<{ success: boolean; error?: string }>;
    installUpdate: () => Promise<{ success: boolean; error?: string }>;
    getVersion: () => Promise<string>;
    onChecking: (callback: () => void) => () => void;
    onUpdateAvailable: (callback: (info: UpdateInfo) => void) => () => void;
    onUpdateNotAvailable: (callback: (info: { version: string }) => void) => () => void;
    onDownloadProgress: (callback: (progress: DownloadProgress) => void) => () => void;
    onUpdateDownloaded: (callback: (info: UpdateInfo) => void) => () => void;
    onError: (callback: (error: { message: string }) => void) => () => void;
}

// ==================== EXPOSE APIs ====================

// Expose Electron API
const electronAPI: ElectronAPI = {
    getVersion: () => process.versions.electron,
    platform: process.platform,
    logToMain: (level, ...args) => {
        ipcRenderer.send('console-log', level, args);
    }
};

// File save API interface
interface FileSaveOptions {
    defaultFilename: string;
    content: string;
    encoding?: 'utf8' | 'base64';
    filters?: { name: string; extensions: string[] }[];
}

interface FileSaveResult {
    success: boolean;
    filePath?: string;
    canceled?: boolean;
    error?: string;
}

interface FileAPI {
    saveWithDialog: (options: FileSaveOptions) => Promise<FileSaveResult>;
}

// Expose File API
const fileAPI: FileAPI = {
    saveWithDialog: (options) => ipcRenderer.invoke('file:saveWithDialog', options)
};

// Expose Database API
const databaseAPI: DatabaseAPI = {
    // Projects
    createProject: (name, description, neo4jDatabase, domainName, tier0Config) =>
        ipcRenderer.invoke('db:createProject', name, description, neo4jDatabase, domainName, tier0Config),
    getAllProjects: () =>
        ipcRenderer.invoke('db:getAllProjects'),
    getProject: (id) =>
        ipcRenderer.invoke('db:getProject', id),
    updateProject: (id, updates) =>
        ipcRenderer.invoke('db:updateProject', id, updates),
    deleteProject: (id) =>
        ipcRenderer.invoke('db:deleteProject', id),

    // Chats
    createChat: (projectId, title) =>
        ipcRenderer.invoke('db:createChat', projectId, title),
    getChatsForProject: (projectId) =>
        ipcRenderer.invoke('db:getChatsForProject', projectId),
    getChat: (id) =>
        ipcRenderer.invoke('db:getChat', id),
    updateChat: (id, title) =>
        ipcRenderer.invoke('db:updateChat', id, title),
    updateChatReportId: (chatId, reportId) =>
        ipcRenderer.invoke('db:updateChatReportId', chatId, reportId),
    deleteChat: (id) =>
        ipcRenderer.invoke('db:deleteChat', id),

    // Messages
    addMessage: (chatId, role, content, artifactType, artifactId, responseData) =>
        ipcRenderer.invoke('db:addMessage', chatId, role, content, artifactType, artifactId, responseData),
    getMessagesForChat: (chatId) =>
        ipcRenderer.invoke('db:getMessagesForChat', chatId),
    getMessagesForChatPaginated: (chatId, limit, offset) =>
        ipcRenderer.invoke('db:getMessagesForChatPaginated', chatId, limit, offset),
    deleteMessage: (id) =>
        ipcRenderer.invoke('db:deleteMessage', id),

    // Reports
    saveReport: (projectId, title, reportData, chatId) =>
        ipcRenderer.invoke('db:saveReport', projectId, title, reportData, chatId),
    getReportsForProject: (projectId) =>
        ipcRenderer.invoke('db:getReportsForProject', projectId),
    getReport: (id) =>
        ipcRenderer.invoke('db:getReport', id),
    deleteReport: (id) =>
        ipcRenderer.invoke('db:deleteReport', id),

    // Additional Findings (for chat-discovered findings)
    addFindingToReport: (reportId, finding) =>
        ipcRenderer.invoke('db:addFindingToReport', reportId, finding),
    removeFindingFromReport: (reportId, findingId) =>
        ipcRenderer.invoke('db:removeFindingFromReport', reportId, findingId),
    updateReportData: (reportId, reportData) =>
        ipcRenderer.invoke('db:updateReportData', reportId, reportData),

    // Search & Utility
    searchMessages: (projectId, query) =>
        ipcRenderer.invoke('db:searchMessages', projectId, query),
    getProjectStats: (projectId) =>
        ipcRenderer.invoke('db:getProjectStats', projectId),
};

// Expose Docker API
const dockerAPI: DockerAPI = {
    getStatus: () => ipcRenderer.invoke('docker:getStatus'),
    isInstalled: () => ipcRenderer.invoke('docker:isInstalled'),
    isRunning: () => ipcRenderer.invoke('docker:isRunning'),
    isNeo4jRunning: () => ipcRenderer.invoke('docker:isNeo4jRunning'),
    isNeo4jReady: () => ipcRenderer.invoke('docker:isNeo4jReady'),
    start: () => ipcRenderer.invoke('docker:start'),
    stop: () => ipcRenderer.invoke('docker:stop'),
    setup: () => ipcRenderer.invoke('docker:setup'),
    pullImage: () => ipcRenderer.invoke('docker:pullImage'),
    remove: () => ipcRenderer.invoke('docker:remove'),
    reset: () => ipcRenderer.invoke('docker:reset'),
    getLogs: (lines = 50) => ipcRenderer.invoke('docker:getLogs', lines),
    getConnectionInfo: () => ipcRenderer.invoke('docker:getConnectionInfo'),
    onProgress: (callback) => {
        const handler = (_event: any, message: string) => callback(message);
        ipcRenderer.on('docker:progress', handler);
        return () => ipcRenderer.removeListener('docker:progress', handler);
    },
    detectExistingBloodHound: () => ipcRenderer.invoke('docker:detectExistingBloodHound'),
    stopExistingBloodHound: () => ipcRenderer.invoke('docker:stopExistingBloodHound'),
    getDebugInfo: () => ipcRenderer.invoke('docker:getDebugInfo')
};

// Expose Neo4j API (simplified - query only, BloodHound CE handles import)
const neo4jAPI: Neo4jAPI = {
    connect: () => ipcRenderer.invoke('neo4j:connect'),
    testConnection: () => ipcRenderer.invoke('neo4j:testConnection'),
    close: () => ipcRenderer.invoke('neo4j:close'),
    setConfig: (config) => ipcRenderer.invoke('neo4j:setConfig', config),
    getConfig: () => ipcRenderer.invoke('neo4j:getConfig'),
    runQuery: (cypher, params) => ipcRenderer.invoke('neo4j:runQuery', cypher, params),
    getCommonQueries: () => ipcRenderer.invoke('neo4j:getCommonQueries'),
    getStatistics: () => ipcRenderer.invoke('neo4j:getStatistics'),
    extractFindings: () => ipcRenderer.invoke('neo4j:extractFindings'),
    getEnvironmentInfo: () => ipcRenderer.invoke('neo4j:getEnvironmentInfo'),
    clearAllData: () => ipcRenderer.invoke('neo4j:clearAllData'),
};

// Expose BloodHound API (simplified - file selection only, BloodHound CE handles parsing)
const bloodhoundAPI: BloodHoundAPI = {
    selectFile: () => ipcRenderer.invoke('bloodhound:selectFile'),
    openAndParse: () => ipcRenderer.invoke('bloodhound:selectFile'), // Legacy alias redirects to selectFile
};

// Expose BloodHound CE API (for uploading to BloodHound CE)
// Credentials are stored separately for Docker vs Custom modes
const bloodhoundCEAPI: BloodHoundCEAPI = {
    setCredentials: (credentials, mode) => ipcRenderer.invoke('bloodhound-api:setCredentials', credentials, mode),
    getCredentials: (mode) => ipcRenderer.invoke('bloodhound-api:getCredentials', mode),
    hasCredentials: (mode) => ipcRenderer.invoke('bloodhound-api:hasCredentials', mode),
    testConnection: () => ipcRenderer.invoke('bloodhound-api:testConnection'),
    uploadFile: (filePath, projectId) => ipcRenderer.invoke('bloodhound-api:uploadFile', filePath, projectId),
    uploadBuffer: async (buffer, fileName, projectId) => {
        return ipcRenderer.invoke('bloodhound-api:uploadBuffer', buffer, fileName, projectId);
    },
    switchProject: (projectId) => ipcRenderer.invoke('bloodhound-api:switchProject', projectId),
    getStoredProjects: () => ipcRenderer.invoke('bloodhound-api:getStoredProjects'),
    deleteProject: (projectId) => ipcRenderer.invoke('bloodhound-api:deleteProject', projectId),
    clearAllData: () => ipcRenderer.invoke('bloodhound-api:clearAllData'),
    onUploadProgress: (callback) => {
        const handler = (_event: any, progress: { step: string; progress: number }) => callback(progress);
        ipcRenderer.on('bloodhound-api:uploadProgress', handler);
        return () => ipcRenderer.removeListener('bloodhound-api:uploadProgress', handler);
    }
};

// Expose Updater API
const updaterAPI: UpdaterAPI = {
    checkForUpdates: () => ipcRenderer.invoke('updater:check'),
    installUpdate: () => ipcRenderer.invoke('updater:install'),
    getVersion: () => ipcRenderer.invoke('updater:getVersion'),
    onChecking: (callback) => {
        const handler = () => callback();
        ipcRenderer.on('updater:checking', handler);
        return () => ipcRenderer.removeListener('updater:checking', handler);
    },
    onUpdateAvailable: (callback) => {
        const handler = (_event: any, info: UpdateInfo) => callback(info);
        ipcRenderer.on('updater:update-available', handler);
        return () => ipcRenderer.removeListener('updater:update-available', handler);
    },
    onUpdateNotAvailable: (callback) => {
        const handler = (_event: any, info: { version: string }) => callback(info);
        ipcRenderer.on('updater:update-not-available', handler);
        return () => ipcRenderer.removeListener('updater:update-not-available', handler);
    },
    onDownloadProgress: (callback) => {
        const handler = (_event: any, progress: DownloadProgress) => callback(progress);
        ipcRenderer.on('updater:download-progress', handler);
        return () => ipcRenderer.removeListener('updater:download-progress', handler);
    },
    onUpdateDownloaded: (callback) => {
        const handler = (_event: any, info: UpdateInfo) => callback(info);
        ipcRenderer.on('updater:update-downloaded', handler);
        return () => ipcRenderer.removeListener('updater:update-downloaded', handler);
    },
    onError: (callback) => {
        const handler = (_event: any, error: { message: string }) => callback(error);
        ipcRenderer.on('updater:error', handler);
        return () => ipcRenderer.removeListener('updater:error', handler);
    },
};

// ==================== FEEDBACK API ====================

interface FeedbackSubmission {
    type: 'bug' | 'feature' | 'feedback';
    title: string;
    description: string;
    email?: string;
    includeSystemInfo: boolean;
    includeLogs: boolean;
}

interface FeedbackResult {
    success: boolean;
    error?: string;
}

interface FeedbackSystemInfo {
    platform: string;
    osVersion: string;
    arch: string;
    aegisVersion: string;
    electronVersion: string;
    memory: string;
    nodeVersion: string;
    cpuCores: number;
}

interface FeedbackAPI {
    submit: (data: FeedbackSubmission) => Promise<FeedbackResult>;
    getSystemInfo: () => Promise<{ success: boolean; data?: FeedbackSystemInfo; error?: string }>;
    isConfigured: () => Promise<{ success: boolean; data: boolean }>;
}

const feedbackAPI: FeedbackAPI = {
    submit: (data) => ipcRenderer.invoke('feedback:submit', data),
    getSystemInfo: () => ipcRenderer.invoke('feedback:getSystemInfo'),
    isConfigured: () => ipcRenderer.invoke('feedback:isConfigured'),
};

contextBridge.exposeInMainWorld('electronAPI', electronAPI);
contextBridge.exposeInMainWorld('database', databaseAPI);
contextBridge.exposeInMainWorld('docker', dockerAPI);
contextBridge.exposeInMainWorld('neo4j', neo4jAPI);
contextBridge.exposeInMainWorld('bloodhound', bloodhoundAPI);
contextBridge.exposeInMainWorld('bloodhoundCE', bloodhoundCEAPI);
contextBridge.exposeInMainWorld('updater', updaterAPI);
contextBridge.exposeInMainWorld('feedback', feedbackAPI);
contextBridge.exposeInMainWorld('fileAPI', fileAPI);

// ==================== CONSOLE FORWARDING ====================

// Override console methods to forward to main process (with throttling to prevent ENOBUFS)
(function () {
    const originalLog = console.log;
    const originalWarn = console.warn;
    const originalError = console.error;
    const originalInfo = console.info;
    const originalDebug = console.debug;

    // Throttle console messages to prevent buffer overflow
    let messageQueue: Array<{ level: string; args: any[] }> = [];
    let isProcessing = false;

    function processQueue() {
        if (isProcessing || messageQueue.length === 0) return;

        isProcessing = true;
        const batch = messageQueue.splice(0, 10); // Process 10 at a time

        batch.forEach(({ level, args }) => {
            try {
                ipcRenderer.send('console-log', level, args);
            } catch (e) {
                // Ignore IPC errors
            }
        });

        isProcessing = false;

        // Process more if queue has items
        if (messageQueue.length > 0) {
            setTimeout(processQueue, 50);
        }
    }

    function sendToMain(level: 'log' | 'warn' | 'error' | 'info' | 'debug', ...args: any[]) {
        // Limit queue size to prevent memory issues
        if (messageQueue.length < 100) {
            // Serialize args safely
            const safeArgs = args.map(arg => {
                if (typeof arg === 'object' && arg !== null) {
                    try {
                        const str = JSON.stringify(arg);
                        return str.length > 500 ? str.substring(0, 500) + '...' : str;
                    } catch {
                        return String(arg);
                    }
                }
                return String(arg);
            });

            messageQueue.push({ level, args: safeArgs });
            processQueue();
        }
    }

    console.log = function (...args: any[]) {
        originalLog.apply(console, args);
        sendToMain('log', ...args);
    };

    console.warn = function (...args: any[]) {
        originalWarn.apply(console, args);
        sendToMain('warn', ...args);
    };

    console.error = function (...args: any[]) {
        originalError.apply(console, args);
        sendToMain('error', ...args);
    };

    console.info = function (...args: any[]) {
        originalInfo.apply(console, args);
        sendToMain('info', ...args);
    };

    console.debug = function (...args: any[]) {
        originalDebug.apply(console, args);
        sendToMain('debug', ...args);
    };
})();

// ==================== TYPE DECLARATIONS ====================

declare global {
    interface Window {
        electronAPI: ElectronAPI;
        database: DatabaseAPI;
        docker: DockerAPI;
        neo4j: Neo4jAPI;
        bloodhound: BloodHoundAPI;
        bloodhoundCE: BloodHoundCEAPI;
        updater: UpdaterAPI;
    }
}
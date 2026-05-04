/** Global type declarations for the AEGIS Electron app. */

// ==================== DATABASE TYPES ====================

interface Project {
    id: string;
    name: string;
    description?: string;
    neo4j_database?: string;
    domain_name?: string;  // Domain name(s) from BloodHound data - used to identify matching data on re-upload
    tier0_config?: string; // JSON string of Tier0Config - defines which assets are considered T0
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

interface ProjectStats {
    chatCount: number;
    messageCount: number;
    reportCount: number;
}

interface DBResult<T> {
    success: boolean;
    data?: T;
    error?: string;
}

// ==================== DOCKER TYPES ====================

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
    message?: string;
    error?: string;
}

interface Neo4jConnectionInfo {
    uri: string;
    username: string;
    password: string;
    httpUrl: string;
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

interface DockerDebugInfo {
    composePath: string;
    composeExists: boolean;
    isDev: boolean;
    isPackaged: boolean;
    appPath: string;
    resourcesPath: string;
    dirname: string;
    nodeEnv: string | undefined;
    error?: string;
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
    getConnectionInfo: () => Neo4jConnectionInfo;
    onProgress: (callback: (message: string) => void) => () => void;
    detectExistingBloodHound: () => Promise<ExistingBloodHoundInfo>;
    stopExistingBloodHound: () => Promise<DockerResult>;
    getDebugInfo: () => Promise<DockerDebugInfo>;
}

// ==================== NEO4J TYPES (Query-Only) ====================

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

// Findings extracted from BloodHound CE's Neo4j (replaces manual parsing)
interface FindingsSummary {
    total_nodes: number;
    total_edges: number;
    high_risk_count: number;
    medium_risk_count: number;
    low_risk_count: number;
    // Entity type counts for domain overview
    total_users?: number;
    total_groups?: number;
    total_computers?: number;
    domain_controllers?: number;
    total_ous?: number;
    total_gpos?: number;
}

interface ExtractedFindings {
    high_risk: any[];
    medium_risk: any[];
    low_risk: any[];
    summary: FindingsSummary;
    edge_type_counts: Record<string, number>;
    domains: string[];
    domain_admin_groups: string[];
    high_value_targets: Array<{ name: string; type: string; count: number }>;
}

interface EnvironmentInfo {
    domains: string[];
    domainInfo: {
        name: string;
        functionalLevel?: string;
        forest?: string;
    } | null;
    domainAdminGroups: string[];
    highValueGroups: string[];
    serviceAccounts: string[];
    computers: string[];
    edgeTypes: string[];
}

// Neo4j API (simplified - query only, no imports)
interface Neo4jAPI {
    // Connection
    connect: () => Promise<Neo4jConnectionResult>;
    testConnection: () => Promise<Neo4jConnectionResult>;
    close: () => Promise<void>;
    setConfig: (config: Partial<Neo4jConfig>) => Promise<void>;
    getConfig: () => Promise<Neo4jConfig>;

    // Queries
    runQuery: (cypher: string, params?: Record<string, any>) => Promise<QueryResult>;
    getCommonQueries: () => Promise<Array<{ name: string; description: string; cypher: string }>>;

    // Statistics
    getStatistics: () => Promise<DatabaseStats>;

    // Findings Extraction (replaces manual parsing)
    extractFindings: () => Promise<ExtractedFindings>;
    getEnvironmentInfo: () => Promise<EnvironmentInfo>;

    // Data Management
    clearAllData: () => Promise<{ success: boolean; error?: string }>;
}

// ==================== BLOODHOUND TYPES ====================

// File selection result (no parsing - BloodHound CE handles that)
interface FileSelectionResult {
    success: boolean;
    filePath?: string;
    fileName?: string;
    error?: string;
}

// Domain extraction result
interface DomainExtractionResult {
    success: boolean;
    domains?: string[];
    error?: string;
}

// BloodHound API (file selection and domain extraction)
interface BloodHoundAPI {
    // File selection only - BloodHound CE handles parsing
    selectFile: () => Promise<FileSelectionResult>;

    // Legacy alias for backwards compatibility
    openAndParse: () => Promise<FileSelectionResult>;

    // Domain extraction for validating re-uploads match the project's domain
    extractDomainsFromBuffer: (buffer: ArrayBuffer, fileName: string) => Promise<DomainExtractionResult>;
    extractDomainsFromFile: (filePath: string) => Promise<DomainExtractionResult>;
}

// ==================== BLOODHOUND CE API ====================

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
    // Docker and Custom modes have separate credential storage
    setCredentials: (credentials: BloodHoundCECredentials, mode?: Neo4jMode) => Promise<{ success: boolean; error?: string }>;
    getCredentials: (mode?: Neo4jMode) => Promise<BloodHoundCECredentials | null>;
    hasCredentials: (mode?: Neo4jMode) => Promise<boolean>;
    testConnection: () => Promise<{ success: boolean; error?: string }>;

    // Upload (BloodHound CE handles parsing and ingestion)
    uploadFile: (filePath: string, projectId: string) => Promise<BloodHoundCEUploadResult>;
    uploadBuffer: (buffer: ArrayBuffer, fileName: string, projectId: string) => Promise<BloodHoundCEUploadResult>;

    // Project Management
    switchProject: (projectId: string) => Promise<BloodHoundCEUploadResult>;
    getStoredProjects: () => Promise<Record<string, string>>;
    deleteProject: (projectId: string) => Promise<{ success: boolean; error?: string }>;

    // Data Management
    clearAllData: () => Promise<{ success: boolean; error?: string }>;

    // Progress
    onUploadProgress: (callback: (progress: { step: string; progress: number }) => void) => () => void;
}

// ==================== DATABASE API ====================

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

interface ElectronAPI {
    getVersion: () => string;
    platform: string;
    logToMain: (level: 'log' | 'warn' | 'error' | 'info' | 'debug', ...args: any[]) => void;
}

// ==================== UPDATER API ====================

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

// ==================== FILE API ====================

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

// ==================== FEEDBACK API ====================

interface FeedbackSubmission {
    type: 'bug' | 'feature' | 'feedback';
    title: string;
    description: string;
    email?: string;
    includeSystemInfo: boolean;
    includeLogs: boolean;
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
    submit: (data: FeedbackSubmission) => Promise<{ success: boolean; error?: string }>;
    getSystemInfo: () => Promise<{ success: boolean; data?: FeedbackSystemInfo; error?: string }>;
    isConfigured: () => Promise<{ success: boolean; data: boolean }>;
}

// ==================== EXTEND WINDOW ====================

declare global {
    interface Window {
        // Existing
        database: DatabaseAPI;
        electronAPI: ElectronAPI;

        // Docker
        docker: DockerAPI;

        // Neo4j (query-only)
        neo4j: Neo4jAPI;

        // BloodHound (file selection only)
        bloodhound: BloodHoundAPI;

        // BloodHound CE API (handles upload and ingestion)
        bloodhoundCE: BloodHoundCEAPI;

        // Auto-updater
        updater: UpdaterAPI;

        // Feedback
        feedback: FeedbackAPI;

        // File operations
        fileAPI: FileAPI;
    }
}

export { };

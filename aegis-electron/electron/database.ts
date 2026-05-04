/**
 * SQLite Database Service for AEGIS
 * Location: electron/database.ts
 * 
 * Handles all database operations in the main process.
 * Renderer communicates via IPC through preload.ts
 */

import Database from 'better-sqlite3';
import { app } from 'electron';
import { join } from 'path';
import { existsSync, mkdirSync } from 'fs';

// Types
export interface Project {
    id: string;
    name: string;
    description?: string;
    neo4j_database?: string;
    domain_name?: string;  // Domain name(s) from BloodHound data - used to identify matching data on re-upload
    tier0_config?: string; // JSON string of Tier0Config - defines which assets are considered T0
    created_at: string;
    updated_at: string;
}

export interface Chat {
    id: string;
    project_id: string;
    report_id?: string;
    title: string;
    created_at: string;
    updated_at: string;
}

export interface Message {
    id: string;
    chat_id: string;
    role: 'user' | 'assistant';
    content: string;
    artifact_type?: string;
    artifact_id?: string;
    response_data?: string;  // JSON string of ChatQueryResponse for intelligent chat
    created_at: string;
}

export interface Report {
    id: string;
    project_id: string;
    chat_id?: string;
    title: string;
    report_data: string; // JSON string
    created_at: string;
}

class DatabaseService {
    private db: Database | null = null;
    private dbPath: string;

    constructor() {
        // Store database in user's app data directory
        const userDataPath = app.getPath('userData');
        const dbDir = join(userDataPath, 'data');

        // Ensure directory exists
        if (!existsSync(dbDir)) {
            mkdirSync(dbDir, { recursive: true });
        }

        this.dbPath = join(dbDir, 'aegis.db');
        console.log(`[Database] Database path: ${this.dbPath}`);
    }

    /**
     * Initialize the database connection and create tables
     */
    initialize(): void {
        try {
            console.log('[Database] Initializing database...');

            this.db = new (Database as any)(this.dbPath) as Database;
            this.db.pragma('journal_mode = WAL'); // Better performance
            this.db.pragma('foreign_keys = ON');  // Enable foreign key constraints

            this.createTables();

            console.log('[Database] Database initialized successfully');
        } catch (error) {
            console.error('[Database] Failed to initialize database:', error);
            throw error;
        }
    }

    /**
     * Create database tables if they don't exist
     */
    private createTables(): void {
        if (!this.db) throw new Error('Database not initialized');

        // Projects table
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                neo4j_database TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Chats table
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS chats (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                title TEXT NOT NULL,
                report_id TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY (report_id) REFERENCES reports(id) ON DELETE SET NULL
            )
        `);

        // Messages table
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                chat_id TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
                content TEXT NOT NULL,
                artifact_type TEXT,
                artifact_id TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE
            )
        `);

        // Reports table
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                chat_id TEXT,
                title TEXT NOT NULL,
                report_data TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE SET NULL
            )
        `);

        // Create indexes for better query performance
        this.db.exec(`
            CREATE INDEX IF NOT EXISTS idx_chats_project_id ON chats(project_id);
            CREATE INDEX IF NOT EXISTS idx_messages_chat_id ON messages(chat_id);
            CREATE INDEX IF NOT EXISTS idx_reports_project_id ON reports(project_id);
            CREATE INDEX IF NOT EXISTS idx_reports_chat_id ON reports(chat_id);
        `);

        // Run migrations
        this.runMigrations();

        console.log('[Database] Tables created/verified');
    }

    /**
     * Run database migrations for schema updates
     */
    private runMigrations(): void {
        if (!this.db) throw new Error('Database not initialized');

        // Migration: Add domain_name column to projects table
        try {
            const projectsInfo = this.db.prepare("PRAGMA table_info(projects)").all() as Array<{ name: string }>;
            const hasDomainName = projectsInfo.some(col => col.name === 'domain_name');

            if (!hasDomainName) {
                console.log('[Database] Running migration: Adding domain_name column to projects');
                this.db.exec(`ALTER TABLE projects ADD COLUMN domain_name TEXT`);
                console.log('[Database] Migration complete: domain_name column added');
            }
        } catch (error) {
            console.error('[Database] Migration error (domain_name):', error);
        }

        // Migration: Add response_data column to messages table
        try {
            const messagesInfo = this.db.prepare("PRAGMA table_info(messages)").all() as Array<{ name: string }>;
            const hasResponseData = messagesInfo.some(col => col.name === 'response_data');

            if (!hasResponseData) {
                console.log('[Database] Running migration: Adding response_data column to messages');
                this.db.exec(`ALTER TABLE messages ADD COLUMN response_data TEXT`);
                console.log('[Database] Migration complete: response_data column added');
            }
        } catch (error) {
            console.error('[Database] Migration error (response_data):', error);
        }

        // Migration: Add tier0_config column to projects table
        try {
            const projectsInfo2 = this.db.prepare("PRAGMA table_info(projects)").all() as Array<{ name: string }>;
            const hasTier0Config = projectsInfo2.some(col => col.name === 'tier0_config');

            if (!hasTier0Config) {
                console.log('[Database] Running migration: Adding tier0_config column to projects');
                this.db.exec(`ALTER TABLE projects ADD COLUMN tier0_config TEXT`);
                console.log('[Database] Migration complete: tier0_config column added');
            }
        } catch (error) {
            console.error('[Database] Migration error (tier0_config):', error);
        }
    }

    /**
     * Generate a unique ID
     */
    private generateId(prefix: string): string {
        return `${prefix}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    // ==================== PROJECT OPERATIONS ====================

    createProject(name: string, description?: string, neo4jDatabase?: string, domainName?: string, tier0Config?: string): Project {
        if (!this.db) throw new Error('Database not initialized');

        const id = this.generateId('proj');
        const now = new Date().toISOString();

        const stmt = this.db.prepare(`
            INSERT INTO projects (id, name, description, neo4j_database, domain_name, tier0_config, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `);

        stmt.run(id, name, description || null, neo4jDatabase || null, domainName || null, tier0Config || null, now, now);

        return {
            id,
            name,
            description,
            neo4j_database: neo4jDatabase,
            domain_name: domainName,
            tier0_config: tier0Config,
            created_at: now,
            updated_at: now
        };
    }

    getAllProjects(): Project[] {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`
            SELECT * FROM projects ORDER BY updated_at DESC
        `);

        return stmt.all() as Project[];
    }

    getProject(id: string): Project | null {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`SELECT * FROM projects WHERE id = ?`);
        return stmt.get(id) as Project | null;
    }

    updateProject(id: string, updates: Partial<Pick<Project, 'name' | 'description' | 'neo4j_database' | 'domain_name' | 'tier0_config'>>): Project | null {
        if (!this.db) throw new Error('Database not initialized');

        const now = new Date().toISOString();
        const fields: string[] = ['updated_at = ?'];
        const values: any[] = [now];

        if (updates.name !== undefined) {
            fields.push('name = ?');
            values.push(updates.name);
        }
        if (updates.description !== undefined) {
            fields.push('description = ?');
            values.push(updates.description);
        }
        if (updates.neo4j_database !== undefined) {
            fields.push('neo4j_database = ?');
            values.push(updates.neo4j_database);
        }
        if (updates.domain_name !== undefined) {
            fields.push('domain_name = ?');
            values.push(updates.domain_name);
        }
        if (updates.tier0_config !== undefined) {
            fields.push('tier0_config = ?');
            values.push(updates.tier0_config);
        }

        values.push(id);

        const stmt = this.db.prepare(`
            UPDATE projects SET ${fields.join(', ')} WHERE id = ?
        `);

        stmt.run(...values);
        return this.getProject(id);
    }

    deleteProject(id: string): boolean {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`DELETE FROM projects WHERE id = ?`);
        const result = stmt.run(id);
        return result.changes > 0;
    }

    // ==================== CHAT OPERATIONS ====================

    createChat(projectId: string, title: string): Chat {
        if (!this.db) throw new Error('Database not initialized');

        const id = this.generateId('chat');
        const now = new Date().toISOString();

        const stmt = this.db.prepare(`
            INSERT INTO chats (id, project_id, title, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        `);

        stmt.run(id, projectId, title, now, now);

        return {
            id,
            project_id: projectId,
            title,
            created_at: now,
            updated_at: now
        };
    }

    getChatsForProject(projectId: string): Chat[] {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`
            SELECT * FROM chats WHERE project_id = ? ORDER BY updated_at DESC
        `);

        return stmt.all(projectId) as Chat[];
    }

    getChat(id: string): Chat | null {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`SELECT * FROM chats WHERE id = ?`);
        return stmt.get(id) as Chat | null;
    }

    updateChat(id: string, title: string): Chat | null {
        if (!this.db) throw new Error('Database not initialized');

        const now = new Date().toISOString();

        const stmt = this.db.prepare(`
            UPDATE chats SET title = ?, updated_at = ? WHERE id = ?
        `);

        stmt.run(title, now, id);
        return this.getChat(id);
    }

    updateChatTimestamp(id: string): void {
        if (!this.db) throw new Error('Database not initialized');

        const now = new Date().toISOString();

        const stmt = this.db.prepare(`
            UPDATE chats SET updated_at = ? WHERE id = ?
        `);

        stmt.run(now, id);
    }

    updateChatReportId(id: string, reportId: string): Chat | null {
        if (!this.db) throw new Error('Database not initialized');

        const now = new Date().toISOString();

        const stmt = this.db.prepare(`
            UPDATE chats SET report_id = ?, updated_at = ? WHERE id = ?
        `);

        stmt.run(reportId, now, id);
        return this.getChat(id);
    }

    deleteChat(id: string): boolean {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`DELETE FROM chats WHERE id = ?`);
        const result = stmt.run(id);
        return result.changes > 0;
    }

    // ==================== MESSAGE OPERATIONS ====================

    addMessage(
        chatId: string,
        role: 'user' | 'assistant',
        content: string,
        artifactType?: string,
        artifactId?: string,
        responseData?: object  // ChatQueryResponse object - will be JSON stringified
    ): Message {
        if (!this.db) throw new Error('Database not initialized');

        const id = this.generateId('msg');
        const now = new Date().toISOString();
        const responseDataJson = responseData ? JSON.stringify(responseData) : null;

        const stmt = this.db.prepare(`
            INSERT INTO messages (id, chat_id, role, content, artifact_type, artifact_id, response_data, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `);

        stmt.run(id, chatId, role, content, artifactType || null, artifactId || null, responseDataJson, now);

        // Update chat timestamp
        this.updateChatTimestamp(chatId);

        return {
            id,
            chat_id: chatId,
            role,
            content,
            artifact_type: artifactType,
            artifact_id: artifactId,
            response_data: responseDataJson || undefined,
            created_at: now
        };
    }

    getMessagesForChat(chatId: string): Message[] {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`
            SELECT * FROM messages WHERE chat_id = ? ORDER BY created_at ASC
        `);

        return stmt.all(chatId) as Message[];
    }

    /**
     * Get messages for a chat with pagination support.
     * Messages are returned in ASC order (oldest first) for display,
     * but pagination loads from the most recent messages first.
     *
     * @param chatId - The chat ID
     * @param limit - Number of messages to fetch
     * @param offset - Number of messages to skip from the end (most recent)
     * @returns Messages in chronological order (oldest first)
     */
    getMessagesForChatPaginated(chatId: string, limit: number, offset: number = 0): { messages: Message[], hasMore: boolean, totalCount: number } {
        if (!this.db) throw new Error('Database not initialized');

        // Get total count first
        const countStmt = this.db.prepare(`SELECT COUNT(*) as count FROM messages WHERE chat_id = ?`);
        const countResult = countStmt.get(chatId) as { count: number };
        const totalCount = countResult.count;

        // Calculate how many messages to skip from the start to get the most recent ones
        // We want messages from (totalCount - offset - limit) to (totalCount - offset)
        const startFrom = Math.max(0, totalCount - offset - limit);
        const actualLimit = Math.min(limit, totalCount - offset);

        if (actualLimit <= 0) {
            return { messages: [], hasMore: false, totalCount };
        }

        // Fetch messages in chronological order, but starting from the calculated offset
        const stmt = this.db.prepare(`
            SELECT * FROM messages
            WHERE chat_id = ?
            ORDER BY created_at ASC
            LIMIT ? OFFSET ?
        `);

        const messages = stmt.all(chatId, actualLimit, startFrom) as Message[];
        const hasMore = startFrom > 0;

        return { messages, hasMore, totalCount };
    }

    deleteMessage(id: string): boolean {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`DELETE FROM messages WHERE id = ?`);
        const result = stmt.run(id);
        return result.changes > 0;
    }

    // ==================== REPORT OPERATIONS ====================

    saveReport(
        projectId: string,
        title: string,
        reportData: object,
        chatId?: string
    ): Report {
        if (!this.db) throw new Error('Database not initialized');

        const id = this.generateId('rpt');
        const now = new Date().toISOString();
        const reportJson = JSON.stringify(reportData);

        const stmt = this.db.prepare(`
            INSERT INTO reports (id, project_id, chat_id, title, report_data, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        `);

        stmt.run(id, projectId, chatId || null, title, reportJson, now);

        return {
            id,
            project_id: projectId,
            chat_id: chatId,
            title,
            report_data: reportJson,
            created_at: now
        };
    }

    getReportsForProject(projectId: string): Report[] {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`
            SELECT * FROM reports WHERE project_id = ? ORDER BY created_at DESC
        `);

        return stmt.all(projectId) as Report[];
    }

    getReport(id: string): Report | null {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`SELECT * FROM reports WHERE id = ?`);
        return stmt.get(id) as Report | null;
    }

    deleteReport(id: string): boolean {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`DELETE FROM reports WHERE id = ?`);
        const result = stmt.run(id);
        return result.changes > 0;
    }

    /**
     * Add a finding to a report's additional_findings array
     */
    addFindingToReport(reportId: string, finding: any): Report {
        if (!this.db) throw new Error('Database not initialized');

        const report = this.getReport(reportId);
        if (!report) throw new Error(`Report not found: ${reportId}`);

        // Parse existing report data
        let reportData: any;
        try {
            reportData = JSON.parse(report.report_data);
        } catch {
            throw new Error('Failed to parse report data');
        }

        // Initialize additional_findings array if not exists
        if (!reportData.additional_findings) {
            reportData.additional_findings = [];
        }

        // Add new finding
        reportData.additional_findings.push(finding);

        // Update in database
        const stmt = this.db.prepare(`
            UPDATE reports SET report_data = ? WHERE id = ?
        `);
        stmt.run(JSON.stringify(reportData), reportId);

        console.log(`[Database] Added finding to report ${reportId}. Total additional findings: ${reportData.additional_findings.length}`);

        return {
            ...report,
            report_data: JSON.stringify(reportData)
        };
    }

    /**
     * Remove a finding from a report's additional_findings array
     */
    removeFindingFromReport(reportId: string, findingId: string): Report {
        if (!this.db) throw new Error('Database not initialized');

        const report = this.getReport(reportId);
        if (!report) throw new Error(`Report not found: ${reportId}`);

        // Parse existing report data
        let reportData: any;
        try {
            reportData = JSON.parse(report.report_data);
        } catch {
            throw new Error('Failed to parse report data');
        }

        // Filter out the finding
        if (reportData.additional_findings) {
            reportData.additional_findings = reportData.additional_findings.filter(
                (f: any) => f.id !== findingId
            );
        }

        // Update in database
        const stmt = this.db.prepare(`
            UPDATE reports SET report_data = ? WHERE id = ?
        `);
        stmt.run(JSON.stringify(reportData), reportId);

        console.log(`[Database] Removed finding ${findingId} from report ${reportId}`);

        return {
            ...report,
            report_data: JSON.stringify(reportData)
        };
    }

    /**
     * Update the entire report data (for general updates)
     */
    updateReportData(reportId: string, reportData: object): Report {
        if (!this.db) throw new Error('Database not initialized');

        const report = this.getReport(reportId);
        if (!report) throw new Error(`Report not found: ${reportId}`);

        const reportJson = JSON.stringify(reportData);

        const stmt = this.db.prepare(`
            UPDATE reports SET report_data = ? WHERE id = ?
        `);
        stmt.run(reportJson, reportId);

        return {
            ...report,
            report_data: reportJson
        };
    }

    // ==================== SEARCH OPERATIONS ====================

    searchMessages(projectId: string, query: string): Array<Message & { chat_title: string }> {
        if (!this.db) throw new Error('Database not initialized');

        const stmt = this.db.prepare(`
            SELECT m.*, c.title as chat_title
            FROM messages m
            JOIN chats c ON m.chat_id = c.id
            WHERE c.project_id = ? AND m.content LIKE ?
            ORDER BY m.created_at DESC
            LIMIT 50
        `);

        return stmt.all(projectId, `%${query}%`) as Array<Message & { chat_title: string }>;
    }

    // ==================== UTILITY OPERATIONS ====================

    /**
     * Get statistics for a project
     */
    getProjectStats(projectId: string): { chatCount: number; messageCount: number; reportCount: number } {
        if (!this.db) throw new Error('Database not initialized');

        const chatCount = this.db.prepare(`
            SELECT COUNT(*) as count FROM chats WHERE project_id = ?
        `).get(projectId) as { count: number };

        const messageCount = this.db.prepare(`
            SELECT COUNT(*) as count FROM messages m
            JOIN chats c ON m.chat_id = c.id
            WHERE c.project_id = ?
        `).get(projectId) as { count: number };

        const reportCount = this.db.prepare(`
            SELECT COUNT(*) as count FROM reports WHERE project_id = ?
        `).get(projectId) as { count: number };

        return {
            chatCount: chatCount.count,
            messageCount: messageCount.count,
            reportCount: reportCount.count
        };
    }

    /**
     * Close the database connection
     */
    close(): void {
        if (this.db) {
            this.db.close();
            this.db = null;
            console.log('[Database] Database connection closed');
        }
    }
}

// Export singleton instance
export const databaseService = new DatabaseService();
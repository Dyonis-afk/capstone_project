/**
 * Database Service for AEGIS Frontend
 * Location: src/services/databaseService.ts
 * 
 * Provides a clean API for React components to interact with the SQLite database
 * through Electron's IPC bridge.
 */

// ==================== TYPE DEFINITIONS ====================

export interface Project {
    id: string;
    name: string;
    description?: string;
    neo4j_database?: string;
    created_at: string;
    updated_at: string;
}

export interface Chat {
    id: string;
    project_id: string;
    title: string;
    report_id?: string;
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

export interface ProjectStats {
    chatCount: number;
    messageCount: number;
    reportCount: number;
}

export interface SearchResult extends Message {
    chat_title: string;
}

// ==================== DATABASE SERVICE ====================

class DatabaseService {
    /**
     * Check if running in Electron environment
     */
    private isElectron(): boolean {
        return typeof window !== 'undefined' && window.database !== undefined;
    }

    /**
     * Throw error if not in Electron
     */
    private ensureElectron(): void {
        if (!this.isElectron()) {
            throw new Error('Database operations are only available in Electron environment');
        }
    }

    // ==================== PROJECT METHODS ====================

    /**
     * Create a new project
     */
    async createProject(name: string, description?: string, neo4jDatabase?: string): Promise<Project> {
        this.ensureElectron();
        const result = await window.database.createProject(name, description, neo4jDatabase);
        if (!result.success) {
            throw new Error(result.error || 'Failed to create project');
        }
        return result.data!;
    }

    /**
     * Get all projects
     */
    async getAllProjects(): Promise<Project[]> {
        this.ensureElectron();
        const result = await window.database.getAllProjects();
        if (!result.success) {
            throw new Error(result.error || 'Failed to get projects');
        }
        return result.data || [];
    }

    /**
     * Get a single project by ID
     */
    async getProject(id: string): Promise<Project | null> {
        this.ensureElectron();
        const result = await window.database.getProject(id);
        if (!result.success) {
            throw new Error(result.error || 'Failed to get project');
        }
        return result.data || null;
    }

    /**
     * Update a project
     */
    async updateProject(
        id: string,
        updates: Partial<Pick<Project, 'name' | 'description' | 'neo4j_database'>>
    ): Promise<Project | null> {
        this.ensureElectron();
        const result = await window.database.updateProject(id, updates);
        if (!result.success) {
            throw new Error(result.error || 'Failed to update project');
        }
        return result.data || null;
    }

    /**
     * Delete a project (cascades to chats and messages)
     */
    async deleteProject(id: string): Promise<boolean> {
        this.ensureElectron();
        const result = await window.database.deleteProject(id);
        if (!result.success) {
            throw new Error(result.error || 'Failed to delete project');
        }
        return result.data || false;
    }

    // ==================== CHAT METHODS ====================

    /**
     * Create a new chat in a project
     */
    async createChat(projectId: string, title: string): Promise<Chat> {
        this.ensureElectron();
        const result = await window.database.createChat(projectId, title);
        if (!result.success) {
            throw new Error(result.error || 'Failed to create chat');
        }
        return result.data!;
    }

    /**
     * Get all chats for a project
     */
    async getChatsForProject(projectId: string): Promise<Chat[]> {
        this.ensureElectron();
        const result = await window.database.getChatsForProject(projectId);
        if (!result.success) {
            throw new Error(result.error || 'Failed to get chats');
        }
        return result.data || [];
    }

    /**
     * Get a single chat by ID
     */
    async getChat(id: string): Promise<Chat | null> {
        this.ensureElectron();
        const result = await window.database.getChat(id);
        if (!result.success) {
            throw new Error(result.error || 'Failed to get chat');
        }
        return result.data || null;
    }

    /**
     * Update chat title
     */
    async updateChat(id: string, title: string): Promise<Chat | null> {
        this.ensureElectron();
        const result = await window.database.updateChat(id, title);
        if (!result.success) {
            throw new Error(result.error || 'Failed to update chat');
        }
        return result.data || null;
    }

    /**
     * Delete a chat (cascades to messages)
     */
    async deleteChat(id: string): Promise<boolean> {
        this.ensureElectron();
        const result = await window.database.deleteChat(id);
        if (!result.success) {
            throw new Error(result.error || 'Failed to delete chat');
        }
        return result.data || false;
    }

    /**
     * Update a chat's associated report ID
     */
    async updateChatReportId(chatId: string, reportId: string): Promise<Chat | null> {
        this.ensureElectron();
        const result = await window.database.updateChatReportId(chatId, reportId);
        if (!result.success) {
            throw new Error(result.error || 'Failed to update chat report ID');
        }
        return result.data || null;
    }

    // ==================== MESSAGE METHODS ====================

    /**
     * Add a message to a chat
     */
    async addMessage(
        chatId: string,
        role: 'user' | 'assistant',
        content: string,
        artifactType?: string,
        artifactId?: string
    ): Promise<Message> {
        this.ensureElectron();
        const result = await window.database.addMessage(chatId, role, content, artifactType, artifactId);
        if (!result.success) {
            throw new Error(result.error || 'Failed to add message');
        }
        return result.data!;
    }

    /**
     * Get all messages for a chat
     */
    async getMessagesForChat(chatId: string): Promise<Message[]> {
        this.ensureElectron();
        const result = await window.database.getMessagesForChat(chatId);
        if (!result.success) {
            throw new Error(result.error || 'Failed to get messages');
        }
        return result.data || [];
    }

    /**
     * Delete a message
     */
    async deleteMessage(id: string): Promise<boolean> {
        this.ensureElectron();
        const result = await window.database.deleteMessage(id);
        if (!result.success) {
            throw new Error(result.error || 'Failed to delete message');
        }
        return result.data || false;
    }

    // ==================== REPORT METHODS ====================

    /**
     * Save a report
     */
    async saveReport(
        projectId: string,
        title: string,
        reportData: object,
        chatId?: string
    ): Promise<Report> {
        this.ensureElectron();
        const result = await window.database.saveReport(projectId, title, reportData, chatId);
        if (!result.success) {
            throw new Error(result.error || 'Failed to save report');
        }
        return result.data!;
    }

    /**
     * Get all reports for a project
     */
    async getReportsForProject(projectId: string): Promise<Report[]> {
        this.ensureElectron();
        const result = await window.database.getReportsForProject(projectId);
        if (!result.success) {
            throw new Error(result.error || 'Failed to get reports');
        }
        return result.data || [];
    }

    /**
     * Get a single report by ID
     */
    async getReport(id: string): Promise<Report | null> {
        this.ensureElectron();
        const result = await window.database.getReport(id);
        if (!result.success) {
            throw new Error(result.error || 'Failed to get report');
        }
        return result.data || null;
    }

    /**
     * Get a report with parsed data
     */
    async getReportWithData(id: string): Promise<{ report: Report; data: any } | null> {
        const report = await this.getReport(id);
        if (!report) return null;

        try {
            const data = JSON.parse(report.report_data);
            return { report, data };
        } catch (e) {
            console.error('Failed to parse report data:', e);
            return { report, data: null };
        }
    }

    /**
     * Delete a report
     */
    async deleteReport(id: string): Promise<boolean> {
        this.ensureElectron();
        const result = await window.database.deleteReport(id);
        if (!result.success) {
            throw new Error(result.error || 'Failed to delete report');
        }
        return result.data || false;
    }

    // ==================== SEARCH & UTILITY METHODS ====================

    /**
     * Search messages across a project
     */
    async searchMessages(projectId: string, query: string): Promise<SearchResult[]> {
        this.ensureElectron();
        const result = await window.database.searchMessages(projectId, query);
        if (!result.success) {
            throw new Error(result.error || 'Failed to search messages');
        }
        return result.data || [];
    }

    /**
     * Get project statistics
     */
    async getProjectStats(projectId: string): Promise<ProjectStats> {
        this.ensureElectron();
        const result = await window.database.getProjectStats(projectId);
        if (!result.success) {
            throw new Error(result.error || 'Failed to get project stats');
        }
        return result.data || { chatCount: 0, messageCount: 0, reportCount: 0 };
    }

    // ==================== CONVENIENCE METHODS ====================

    /**
     * Create a new chat with an initial user message
     */
    async createChatWithMessage(
        projectId: string,
        title: string,
        userMessage: string
    ): Promise<{ chat: Chat; message: Message }> {
        const chat = await this.createChat(projectId, title);
        const message = await this.addMessage(chat.id, 'user', userMessage);
        return { chat, message };
    }

    /**
     * Get a chat with all its messages
     */
    async getChatWithMessages(chatId: string): Promise<{ chat: Chat; messages: Message[] } | null> {
        const chat = await this.getChat(chatId);
        if (!chat) return null;

        const messages = await this.getMessagesForChat(chatId);
        return { chat, messages };
    }

    /**
     * Generate a chat title from the first message
     */
    generateChatTitle(firstMessage: string, maxLength: number = 50): string {
        // Remove markdown and special characters
        let title = firstMessage
            .replace(/```[\s\S]*?```/g, '') // Remove code blocks
            .replace(/[#*`_\[\]]/g, '')     // Remove markdown characters
            .replace(/\n/g, ' ')            // Replace newlines with spaces
            .trim();

        // Truncate if needed
        if (title.length > maxLength) {
            title = title.substring(0, maxLength - 3) + '...';
        }

        return title || 'New Chat';
    }
}

// Export singleton instance
export const databaseService = new DatabaseService();
export default databaseService;
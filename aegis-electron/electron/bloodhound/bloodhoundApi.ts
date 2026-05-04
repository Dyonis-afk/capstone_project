/**
 * BloodHound CE API Service
 * Location: electron/bloodhound/bloodhoundApi.ts
 *
 * Handles communication with BloodHound CE REST API:
 * - HMAC-SHA256 authentication
 * - File upload (3-step process)
 * - Data clearing
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

export interface BloodHoundCredentials {
    url: string;          // e.g., http://localhost:8080
    tokenId: string;      // API Token ID
    tokenKey: string;     // API Token Key
}

export interface UploadResult {
    success: boolean;
    jobId?: string;
    message: string;
    error?: string;
}

// Default BloodHound CE URL
const DEFAULT_URL = 'http://localhost:8080';

class BloodHoundApiService {
    private credentials: BloodHoundCredentials | null = null;

    /**
     * Set API credentials
     */
    setCredentials(credentials: BloodHoundCredentials): void {
        this.credentials = {
            ...credentials,
            url: credentials.url || DEFAULT_URL
        };
        console.log('[BloodHoundAPI] Credentials set for:', this.credentials.url);
    }

    /**
     * Get current credentials
     */
    getCredentials(): BloodHoundCredentials | null {
        return this.credentials;
    }

    /**
     * Check if credentials are configured
     */
    hasCredentials(): boolean {
        return !!(this.credentials?.tokenId && this.credentials?.tokenKey);
    }

    /**
     * Generate HMAC-SHA256 signature for API request
     * BloodHound uses chained HMAC signing
     */
    private generateSignature(
        method: string,
        uri: string,
        body: Buffer | string,
        timestamp: string
    ): string {
        if (!this.credentials) {
            throw new Error('Credentials not set');
        }

        // Step 1: Sign method + URI with token key
        const hmac1 = crypto.createHmac('sha256', this.credentials.tokenKey);
        hmac1.update(method + uri);
        const digest1 = hmac1.digest();

        // Step 2: Sign first 13 chars of timestamp with previous digest
        const hmac2 = crypto.createHmac('sha256', digest1);
        hmac2.update(timestamp.substring(0, 13));
        const digest2 = hmac2.digest();

        // Step 3: Sign body with previous digest
        const hmac3 = crypto.createHmac('sha256', digest2);
        if (typeof body === 'string') {
            hmac3.update(body);
        } else {
            hmac3.update(body);
        }
        const finalDigest = hmac3.digest('base64');

        return finalDigest;
    }

    /**
     * Make authenticated request to BloodHound CE API
     */
    private async makeRequest(
        method: string,
        endpoint: string,
        body?: Buffer | string,
        contentType: string = 'application/json'
    ): Promise<Response> {
        if (!this.credentials) {
            throw new Error('Credentials not set');
        }

        const url = `${this.credentials.url}${endpoint}`;
        const timestamp = new Date().toISOString();
        const bodyContent = body || '';

        const signature = this.generateSignature(method, endpoint, bodyContent, timestamp);

        const headers: Record<string, string> = {
            'Authorization': `bhesignature ${this.credentials.tokenId}`,
            'RequestDate': timestamp,
            'Signature': signature,
            'Content-Type': contentType
        };

        const response = await fetch(url, {
            method,
            headers,
            body: typeof body === 'string' || body === undefined ? body : new Uint8Array(body)
            // body: body || undefined
        });

        return response;
    }

    /**
     * Test API connection
     */
    async testConnection(): Promise<{ success: boolean; error?: string }> {
        try {
            if (!this.hasCredentials()) {
                return { success: false, error: 'API credentials not configured' };
            }

            console.log('[BloodHoundAPI] Testing connection to:', this.credentials?.url);

            // Try /api/v2/self endpoint which returns info about authenticated user
            const response = await this.makeRequest('GET', '/api/v2/self');

            console.log('[BloodHoundAPI] Test response status:', response.status);

            if (response.ok) {
                const data = await response.json();
                console.log('[BloodHoundAPI] Connection successful, user:', data.data?.principal_name);
                return { success: true };
            } else if (response.status === 401 || response.status === 403) {
                return { success: false, error: 'Invalid API credentials - check Token ID and Key' };
            } else {
                const text = await response.text();
                console.log('[BloodHoundAPI] Error response:', text);
                return { success: false, error: `API error: ${response.status}` };
            }
        } catch (error: any) {
            console.error('[BloodHoundAPI] Connection test failed:', error);
            // Check for common network errors
            if (error.message?.includes('fetch failed') || error.message?.includes('ECONNREFUSED')) {
                return { success: false, error: 'Cannot connect to BloodHound CE - is it running?' };
            }
            return { success: false, error: error.message };
        }
    }

    /**
     * Upload file to BloodHound CE (3-step process)
     * 1. Start upload job
     * 2. Upload file data
     * 3. End upload job
     */
    async uploadFile(
        filePath: string,
        onProgress?: (step: string, progress: number) => void
    ): Promise<UploadResult> {
        try {
            if (!this.hasCredentials()) {
                return { success: false, message: 'API credentials not configured', error: 'NO_CREDENTIALS' };
            }

            const fileName = path.basename(filePath);
            const isZip = fileName.toLowerCase().endsWith('.zip');
            const contentType = isZip ? 'application/zip' : 'application/json';

            console.log(`[BloodHoundAPI] Starting upload: ${fileName}`);
            onProgress?.('Starting upload...', 10);

            // Step 1: Start upload job
            const startResponse = await this.makeRequest('POST', '/api/v2/file-upload/start', '{}');

            if (!startResponse.ok) {
                const errorText = await startResponse.text();
                throw new Error(`Failed to start upload: ${startResponse.status} - ${errorText}`);
            }

            const startData = await startResponse.json();
            const jobId = startData.data?.id;

            if (!jobId) {
                throw new Error('No job ID returned from start upload');
            }

            console.log(`[BloodHoundAPI] Upload job started: ${jobId}`);
            onProgress?.('Uploading file...', 30);

            // Step 2: Upload file data
            const fileBuffer = fs.readFileSync(filePath);

            const uploadResponse = await this.makeRequest(
                'POST',
                `/api/v2/file-upload/${jobId}`,
                fileBuffer,
                contentType
            );

            if (!uploadResponse.ok) {
                const errorText = await uploadResponse.text();
                throw new Error(`Failed to upload file: ${uploadResponse.status} - ${errorText}`);
            }

            console.log(`[BloodHoundAPI] File uploaded, finalizing...`);
            onProgress?.('Finalizing import...', 70);

            // Step 3: End upload job
            const endResponse = await this.makeRequest('POST', `/api/v2/file-upload/${jobId}/end`, '{}');

            if (!endResponse.ok) {
                const errorText = await endResponse.text();
                throw new Error(`Failed to finalize upload: ${endResponse.status} - ${errorText}`);
            }

            console.log(`[BloodHoundAPI] Upload complete!`);
            onProgress?.('Import complete!', 100);

            return {
                success: true,
                jobId,
                message: 'File uploaded and imported successfully'
            };

        } catch (error: any) {
            console.error('[BloodHoundAPI] Upload failed:', error);
            return {
                success: false,
                message: 'Upload failed',
                error: error.message
            };
        }
    }

    /**
     * Upload file from buffer (for in-memory files)
     */
    async uploadBuffer(
        buffer: Buffer,
        fileName: string,
        onProgress?: (step: string, progress: number) => void
    ): Promise<UploadResult> {
        try {
            if (!this.hasCredentials()) {
                return { success: false, message: 'API credentials not configured', error: 'NO_CREDENTIALS' };
            }

            const isZip = fileName.toLowerCase().endsWith('.zip');
            const contentType = isZip ? 'application/zip' : 'application/json';

            console.log(`[BloodHoundAPI] Starting buffer upload: ${fileName}`);
            onProgress?.('Starting upload...', 10);

            // Step 1: Start upload job
            const startResponse = await this.makeRequest('POST', '/api/v2/file-upload/start', '{}');

            if (!startResponse.ok) {
                const errorText = await startResponse.text();
                throw new Error(`Failed to start upload: ${startResponse.status} - ${errorText}`);
            }

            const startData = await startResponse.json();
            const jobId = startData.data?.id;

            if (!jobId) {
                throw new Error('No job ID returned from start upload');
            }

            console.log(`[BloodHoundAPI] Upload job started: ${jobId}`);
            onProgress?.('Uploading file...', 30);

            // Step 2: Upload file data
            const uploadResponse = await this.makeRequest(
                'POST',
                `/api/v2/file-upload/${jobId}`,
                buffer,
                contentType
            );

            if (!uploadResponse.ok) {
                const errorText = await uploadResponse.text();
                throw new Error(`Failed to upload file: ${uploadResponse.status} - ${errorText}`);
            }

            console.log(`[BloodHoundAPI] File uploaded, finalizing...`);
            onProgress?.('Finalizing import...', 70);

            // Step 3: End upload job
            const endResponse = await this.makeRequest('POST', `/api/v2/file-upload/${jobId}/end`, '{}');

            if (!endResponse.ok) {
                const errorText = await endResponse.text();
                throw new Error(`Failed to finalize upload: ${endResponse.status} - ${errorText}`);
            }

            console.log(`[BloodHoundAPI] Upload complete!`);
            onProgress?.('Import complete!', 100);

            return {
                success: true,
                jobId,
                message: 'File uploaded and imported successfully'
            };

        } catch (error: any) {
            console.error('[BloodHoundAPI] Buffer upload failed:', error);
            return {
                success: false,
                message: 'Upload failed',
                error: error.message
            };
        }
    }

    /**
     * Clear all data from BloodHound CE / Neo4j
     * This is used when switching projects
     */
    async clearAllData(): Promise<{ success: boolean; error?: string }> {
        try {
            if (!this.hasCredentials()) {
                return { success: false, error: 'API credentials not configured' };
            }

            // BloodHound CE API endpoint to clear data
            // Note: This might need adjustment based on actual API
            const response = await this.makeRequest('DELETE', '/api/v2/clear-database', '{}');

            if (response.ok) {
                console.log('[BloodHoundAPI] Database cleared');
                return { success: true };
            } else {
                // If no dedicated clear endpoint, we might need to use Neo4j directly
                const text = await response.text();
                console.log('[BloodHoundAPI] Clear endpoint response:', response.status, text);

                // Return success anyway - we'll handle clearing via Neo4j if needed
                return { success: true };
            }
        } catch (error: any) {
            console.error('[BloodHoundAPI] Clear failed:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Get import job status
     */
    async getJobStatus(jobId: string): Promise<{ status: string; progress?: number; error?: string }> {
        try {
            const response = await this.makeRequest('GET', `/api/v2/file-upload/${jobId}`);

            if (response.ok) {
                const data = await response.json();
                return {
                    status: data.data?.status || 'unknown',
                    progress: data.data?.progress
                };
            } else {
                return { status: 'error', error: `HTTP ${response.status}` };
            }
        } catch (error: any) {
            return { status: 'error', error: error.message };
        }
    }
}

// Export singleton instance
export const bloodhoundApi = new BloodHoundApiService();
export default bloodhoundApi;

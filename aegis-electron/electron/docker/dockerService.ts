/**
 * Docker Service for AEGIS
 * Location: src/electron/dockerService.ts
 *
 * Manages Docker operations for BloodHound CE stack:
 * - Neo4j (graph database)
 * - Postgres (BloodHound data)
 * - BloodHound API/UI
 *
 * Uses docker-compose for orchestration.
 */

import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import { join, dirname } from 'path';
import { existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { app } from 'electron';

const execAsync = promisify(exec);

// ES Module compatibility: __dirname equivalent
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Parse Docker errors and return user-friendly messages
 * Converts raw stack traces into actionable messages
 */
function parseDockerError(error: string): string {
    const errorLower = error.toLowerCase();

    // Permission denied - most common on Linux
    if (errorLower.includes('permission denied') || errorLower.includes('permissionerror')) {
        return 'Docker permission denied. Please run: sudo usermod -aG docker $USER && sudo reboot';
    }

    // Docker daemon not running
    if (errorLower.includes('cannot connect to the docker daemon') ||
        errorLower.includes('is the docker daemon running')) {
        return 'Docker is not running. Please start Docker Desktop or run: sudo systemctl start docker';
    }

    // Network conflicts
    if (errorLower.includes('network') && errorLower.includes('ambiguous')) {
        return 'Docker network conflict. Cleaning up and retrying...';
    }

    // Container already exists
    if (errorLower.includes('already in use') || errorLower.includes('already exists')) {
        return 'Container conflict detected. Cleaning up...';
    }

    // Image pull failures
    if (errorLower.includes('pull access denied') || errorLower.includes('manifest unknown')) {
        return 'Failed to download Docker images. Please check your internet connection.';
    }

    // Timeout
    if (errorLower.includes('timeout') || errorLower.includes('timed out')) {
        return 'Operation timed out. Docker may be slow or unresponsive.';
    }

    // Disk space
    if (errorLower.includes('no space left') || errorLower.includes('disk quota')) {
        return 'Not enough disk space. Please free up space and try again.';
    }

    // Port conflicts
    if (errorLower.includes('port') && (errorLower.includes('already allocated') || errorLower.includes('in use'))) {
        return 'Port conflict. Another application is using ports 7474, 7687, or 8080.';
    }

    // Container unhealthy - usually Neo4j taking too long to start
    if (errorLower.includes('unhealthy') || errorLower.includes('health check')) {
        return 'Neo4j is still starting up. Please wait a moment and try again, or click "Reset" to start fresh.';
    }

    // Dependency failed
    if (errorLower.includes('dependency failed')) {
        return 'A required service failed to start. Please try "Reset" and then "Setup" again.';
    }

    // Generic - extract first meaningful line, skip stack traces
    const lines = error.split('\n');
    for (const line of lines) {
        const trimmed = line.trim();
        // Skip empty lines, stack trace lines, and Python traceback headers
        if (trimmed &&
            !trimmed.startsWith('File "') &&
            !trimmed.startsWith('Traceback') &&
            !trimmed.startsWith('During handling') &&
            !trimmed.startsWith('^^^') &&
            !trimmed.includes('raise ') &&
            trimmed.length < 150) {
            // Return first meaningful line (likely the actual error)
            if (trimmed.includes('Error') || trimmed.includes('error') || trimmed.includes('failed')) {
                return trimmed.length > 100 ? trimmed.substring(0, 100) + '...' : trimmed;
            }
        }
    }

    // Fallback - just truncate
    return error.length > 100 ? error.substring(0, 100) + '...' : error;
}

// BloodHound CE Stack Configuration
const NEO4J_CONTAINER = 'aegis-neo4j';
const BLOODHOUND_CONTAINER = 'aegis-bloodhound';
const POSTGRES_CONTAINER = 'aegis-postgres';
const NEO4J_HTTP_PORT = 7474;
const NEO4J_BOLT_PORT = 7687;
const BLOODHOUND_PORT = 8080;
const NEO4J_PASSWORD = 'bloodhoundcommunityedition';

export interface DockerStatus {
    dockerInstalled: boolean;
    dockerRunning: boolean;
    containerExists: boolean;
    containerRunning: boolean;
    neo4jReady: boolean;
    error?: string;
}

export interface DockerResult {
    success: boolean;
    message: string;
    error?: string;
}

export interface ExistingBloodHoundInfo {
    detected: boolean;
    containers: Array<{
        name: string;
        status: string;
        ports: string;
    }>;
    conflictingPorts: number[];
    recommendation: string;
}

class DockerService {
    private composePath: string;

    constructor() {
        // In development, docker-compose.yaml location varies by project structure
        // In production, it's bundled with the app via extraResources
        const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged;

        console.log('[DockerService] Initializing...');
        console.log('[DockerService] isDev:', isDev);
        console.log('[DockerService] app.isPackaged:', app.isPackaged);
        console.log('[DockerService] NODE_ENV:', process.env.NODE_ENV);

        if (isDev) {
            // Development: check multiple possible locations
            const possiblePaths = [
                join(process.cwd(), 'docker-compose.yaml'),
                join(process.cwd(), 'electron', 'docker-compose.yaml'),
                join(process.cwd(), 'electron', 'docker', 'docker-compose.yaml'),
                join(__dirname, 'docker-compose.yaml'),
                join(__dirname, 'docker', 'docker-compose.yaml'),
                join(__dirname, '..', 'docker', 'docker-compose.yaml'),
            ];

            this.composePath = possiblePaths.find(p => existsSync(p)) || possiblePaths[2];

            console.log('[DockerService] Development mode - searched paths:', possiblePaths);
            console.log('[DockerService] Found at:', this.composePath, '- exists:', existsSync(this.composePath));
        } else {
            // Production: bundled in app resources via extraResources in package.json
            // On macOS: /path/to/AEGIS.app/Contents/Resources/docker-compose.yaml
            // On Windows: C:\...\resources\docker-compose.yaml
            // On Linux: /path/to/resources/docker-compose.yaml
            console.log('[DockerService] Production mode - resolving paths...');
            console.log('[DockerService] app.getAppPath():', app.getAppPath());
            console.log('[DockerService] process.resourcesPath:', process.resourcesPath);
            console.log('[DockerService] __dirname:', __dirname);

            const possiblePaths = [
                // extraResources copies to process.resourcesPath (most likely location)
                join(process.resourcesPath, 'docker-compose.yaml'),
                join(process.resourcesPath, 'docker', 'docker-compose.yaml'),
                // Fallback to app path
                join(app.getAppPath(), 'docker-compose.yaml'),
                join(app.getAppPath(), 'docker', 'docker-compose.yaml'),
                // Additional fallbacks for different packaging scenarios
                join(app.getAppPath(), '..', 'docker-compose.yaml'),
                join(__dirname, 'docker-compose.yaml'),
                join(__dirname, '..', 'docker-compose.yaml'),
                join(__dirname, '..', 'docker', 'docker-compose.yaml'),
            ];

            // Log each path and whether it exists
            console.log('[DockerService] Checking paths:');
            possiblePaths.forEach((p, i) => {
                console.log(`  [${i}] ${p} - exists: ${existsSync(p)}`);
            });

            this.composePath = possiblePaths.find(p => existsSync(p)) || possiblePaths[0];

            if (!existsSync(this.composePath)) {
                console.error('[DockerService] WARNING: docker-compose.yaml not found at any expected location!');
                console.error('[DockerService] This will cause Docker mode to fail.');
                console.error('[DockerService] Expected locations checked:', possiblePaths);
            }
        }

        console.log(`[DockerService] Using compose file: ${this.composePath}`);
        console.log(`[DockerService] File exists: ${existsSync(this.composePath)}`);
    }

    /**
     * Get debug information for troubleshooting Docker connection issues
     * This can be called from the UI to display diagnostic info
     */
    getDebugInfo(): {
        composePath: string;
        composeExists: boolean;
        isDev: boolean;
        isPackaged: boolean;
        appPath: string;
        resourcesPath: string;
        dirname: string;
        nodeEnv: string | undefined;
    } {
        return {
            composePath: this.composePath,
            composeExists: existsSync(this.composePath),
            isDev: process.env.NODE_ENV === 'development' || !app.isPackaged,
            isPackaged: app.isPackaged,
            appPath: app.getAppPath(),
            resourcesPath: process.resourcesPath,
            dirname: __dirname,
            nodeEnv: process.env.NODE_ENV,
        };
    }

    /**
     * Check if Docker CLI is installed
     */
    async isDockerInstalled(): Promise<boolean> {
        try {
            await execAsync('docker --version');
            return true;
        } catch (error) {
            console.log('[DockerService] Docker not installed:', error);
            return false;
        }
    }

    /**
     * Check if Docker daemon is running
     */
    async isDockerRunning(): Promise<boolean> {
        try {
            await execAsync('docker info', { timeout: 10000 });
            return true;
        } catch (error) {
            console.log('[DockerService] Docker daemon not running:', error);
            return false;
        }
    }

    /**
     * Check if the BloodHound CE stack containers exist (at least Neo4j)
     */
    async containerExists(): Promise<boolean> {
        try {
            const { stdout } = await execAsync(
                `docker ps -a --filter "name=${NEO4J_CONTAINER}" --format "{{.Names}}"`
            );
            return stdout.trim().includes(NEO4J_CONTAINER);
        } catch (error) {
            console.log('[DockerService] Error checking container:', error);
            return false;
        }
    }

    /**
     * Check if the BloodHound CE stack is running (Neo4j container)
     */
    async isContainerRunning(): Promise<boolean> {
        try {
            const { stdout } = await execAsync(
                `docker ps --filter "name=${NEO4J_CONTAINER}" --filter "status=running" --format "{{.Names}}"`
            );
            return stdout.trim().includes(NEO4J_CONTAINER);
        } catch (error) {
            console.log('[DockerService] Error checking if container running:', error);
            return false;
        }
    }

    /**
     * Check if Neo4j is ready to accept connections
     */
    async isNeo4jReady(): Promise<boolean> {
        try {
            // Method 1: Check Neo4j HTTP endpoint from host
            const http = await import('http');

            return new Promise((resolve) => {
                const req = http.request({
                    hostname: 'localhost',
                    port: NEO4J_HTTP_PORT,
                    path: '/',
                    method: 'GET',
                    timeout: 3000
                }, (res) => {
                    resolve(res.statusCode === 200);
                });

                req.on('error', () => resolve(false));
                req.on('timeout', () => {
                    req.destroy();
                    resolve(false);
                });

                req.end();
            });
        } catch (error) {
            console.log('[DockerService] Neo4j ready check failed:', error);
            return false;
        }
    }

    /**
     * Detect existing non-AEGIS BloodHound CE installation
     * Looks for containers with 'bloodhound' in the name that are NOT AEGIS containers
     */
    async detectExistingBloodHound(): Promise<ExistingBloodHoundInfo> {
        const result: ExistingBloodHoundInfo = {
            detected: false,
            containers: [],
            conflictingPorts: [],
            recommendation: ''
        };

        try {
            if (!await this.isDockerInstalled() || !await this.isDockerRunning()) {
                return result;
            }

            // Get all running containers with 'bloodhound' or common BloodHound-related names
            // Exclude AEGIS containers (prefixed with 'aegis-')
            const { stdout } = await execAsync(
                `docker ps --format "{{.Names}}|{{.Status}}|{{.Ports}}" | grep -iE "(bloodhound|neo4j|graph-db)" || true`,
                { timeout: 10000 }
            );

            if (!stdout.trim()) {
                return result;
            }

            const lines = stdout.trim().split('\n').filter(line => line.trim());

            for (const line of lines) {
                const [name, status, ports] = line.split('|');

                // Skip AEGIS containers
                if (name && name.toLowerCase().startsWith('aegis-')) {
                    continue;
                }

                // This is a non-AEGIS BloodHound-related container
                result.containers.push({
                    name: name || 'unknown',
                    status: status || 'unknown',
                    ports: ports || ''
                });

                // Check for port conflicts
                if (ports) {
                    if (ports.includes(':7474') || ports.includes('7474->7474')) {
                        result.conflictingPorts.push(7474);
                    }
                    if (ports.includes(':7687') || ports.includes('7687->7687')) {
                        result.conflictingPorts.push(7687);
                    }
                    if (ports.includes(':8080') || ports.includes('8080->8080')) {
                        result.conflictingPorts.push(8080);
                    }
                }
            }

            // Remove duplicates from conflicting ports
            result.conflictingPorts = [...new Set(result.conflictingPorts)];
            result.detected = result.containers.length > 0;

            if (result.detected) {
                result.recommendation = result.conflictingPorts.length > 0
                    ? 'You have an existing BloodHound CE installation using the same ports. We recommend using Custom Mode to connect to your existing Neo4j instance instead.'
                    : 'You have an existing BloodHound CE installation. Consider using Custom Mode to connect to it instead of starting a new Docker stack.';
            }

            console.log('[DockerService] Existing BloodHound detection:', result);
            return result;
        } catch (error) {
            console.log('[DockerService] Error detecting existing BloodHound:', error);
            return result;
        }
    }

    /**
     * Stop existing non-AEGIS BloodHound containers
     * Used when user chooses to proceed with AEGIS Docker mode
     */
    async stopExistingBloodHound(): Promise<DockerResult> {
        try {
            const existing = await this.detectExistingBloodHound();

            if (!existing.detected) {
                return { success: true, message: 'No existing BloodHound containers to stop' };
            }

            const containerNames = existing.containers.map(c => c.name).join(' ');
            console.log('[DockerService] Stopping existing BloodHound containers:', containerNames);

            await execAsync(`docker stop ${containerNames}`, { timeout: 60000 });

            return {
                success: true,
                message: `Stopped ${existing.containers.length} existing BloodHound container(s)`
            };
        } catch (error: any) {
            console.error('[DockerService] Error stopping existing BloodHound:', error);
            return {
                success: false,
                message: 'Failed to stop existing BloodHound containers',
                error: error.message || String(error)
            };
        }
    }

    /**
     * Get complete Docker status
     */
    async getStatus(): Promise<DockerStatus> {
        const status: DockerStatus = {
            dockerInstalled: false,
            dockerRunning: false,
            containerExists: false,
            containerRunning: false,
            neo4jReady: false
        };

        try {
            status.dockerInstalled = await this.isDockerInstalled();
            if (!status.dockerInstalled) {
                status.error = 'Docker is not installed';
                return status;
            }

            status.dockerRunning = await this.isDockerRunning();
            if (!status.dockerRunning) {
                status.error = 'Docker Desktop is not running';
                return status;
            }

            status.containerExists = await this.containerExists();
            if (!status.containerExists) {
                // Not an error, just needs setup
                return status;
            }

            status.containerRunning = await this.isContainerRunning();
            if (!status.containerRunning) {
                // Not an error, container just needs to be started
                return status;
            }

            status.neo4jReady = await this.isNeo4jReady();
            // Don't set error for "starting up" - it's a normal transitional state
            // The UI will show "Running" status which is accurate

            return status;
        } catch (error) {
            status.error = `Error checking status: ${error}`;
            return status;
        }
    }

    /**
     * Pull BloodHound CE images (first-time setup)
     */
    async pullImage(onProgress?: (message: string) => void): Promise<DockerResult> {
        try {
            onProgress?.('Checking Docker...');

            if (!await this.isDockerInstalled()) {
                return { success: false, message: 'Docker is not installed', error: 'DOCKER_NOT_INSTALLED' };
            }

            if (!await this.isDockerRunning()) {
                return { success: false, message: 'Docker Desktop is not running', error: 'DOCKER_NOT_RUNNING' };
            }

            // Check if compose file exists
            if (!existsSync(this.composePath)) {
                return { success: false, message: 'docker-compose.yaml not found', error: 'COMPOSE_NOT_FOUND' };
            }

            onProgress?.('Pulling BloodHound CE images... This may take a few minutes.');
            onProgress?.('  - specterops/bloodhound:latest');
            onProgress?.('  - neo4j:4.4-community');
            onProgress?.('  - postgres:16');

            // Use docker-compose pull to get all images
            await execAsync(`docker-compose -f "${this.composePath}" pull`, { timeout: 600000 }); // 10 min timeout

            onProgress?.('Images pulled successfully');
            return { success: true, message: 'BloodHound CE images pulled successfully' };
        } catch (error: any) {
            console.error('[DockerService] Error pulling images:', error);
            const friendlyError = parseDockerError(error.message || String(error));
            return { success: false, message: 'Failed to pull BloodHound CE images', error: friendlyError };
        }
    }

    /**
     * Clean up orphaned containers and networks before starting
     * This prevents "network is ambiguous" and "already in use" errors
     */
    private async cleanupOrphans(onProgress?: (message: string) => void): Promise<void> {
        try {
            onProgress?.('Cleaning up orphaned resources...');
            console.log('[DockerService] Running cleanup before start...');
            await execAsync(`docker-compose -f "${this.composePath}" down --remove-orphans`, {
                timeout: 60000
            }).catch(() => {
                // Ignore errors - cleanup is best-effort
                console.log('[DockerService] Cleanup completed (or nothing to clean)');
            });
        } catch (error) {
            // Ignore cleanup errors - we'll try to start anyway
            console.log('[DockerService] Cleanup step completed');
        }
    }

    /**
     * Start BloodHound CE stack using docker-compose
     */
    async startContainer(onProgress?: (message: string) => void): Promise<DockerResult> {
        try {
            onProgress?.('Checking Docker status...');

            if (!await this.isDockerInstalled()) {
                return { success: false, message: 'Docker is not installed', error: 'DOCKER_NOT_INSTALLED' };
            }

            if (!await this.isDockerRunning()) {
                return { success: false, message: 'Docker Desktop is not running. Please start Docker Desktop.', error: 'DOCKER_NOT_RUNNING' };
            }

            // Check if compose file exists
            if (!existsSync(this.composePath)) {
                const debugInfo = this.getDebugInfo();
                console.error(`[DockerService] docker-compose.yaml not found at: ${this.composePath}`);
                console.error(`[DockerService] Debug info:`, JSON.stringify(debugInfo, null, 2));
                return {
                    success: false,
                    message: `Docker configuration file not found. This is a packaging issue. Expected at: ${this.composePath}. App path: ${debugInfo.appPath}, Resources path: ${debugInfo.resourcesPath}`,
                    error: 'COMPOSE_NOT_FOUND'
                };
            }

            // Check if containers already running
            if (await this.isContainerRunning()) {
                onProgress?.('BloodHound CE stack already running');
                return { success: true, message: 'BloodHound CE is already running' };
            }

            // Clean up any orphaned resources first (prevents network conflicts)
            await this.cleanupOrphans(onProgress);

            // Start the BloodHound CE stack with docker-compose
            onProgress?.('Starting BloodHound CE stack...');
            onProgress?.('  - Neo4j (graph database)');
            onProgress?.('  - Postgres (BloodHound data)');
            onProgress?.('  - BloodHound API/UI');

            // Use docker-compose to start the stack with --remove-orphans flag
            await execAsync(`docker-compose -f "${this.composePath}" up -d --remove-orphans`, {
                timeout: 180000 // 3 min timeout for multi-container startup
            });

            // Wait for Neo4j to be ready
            onProgress?.('Waiting for Neo4j to be ready...');
            const ready = await this.waitForNeo4j(90); // Wait up to 90 seconds for full stack

            if (ready) {
                onProgress?.('BloodHound CE is ready!');
                return { success: true, message: 'BloodHound CE started successfully' };
            } else {
                return { success: true, message: 'BloodHound CE started but still initializing' };
            }
        } catch (error: any) {
            console.error('[DockerService] Error starting BloodHound CE:', error);
            const errorMsg = error.message || String(error);

            // Check if it's a container/network conflict (covers "already in use" and "is ambiguous")
            const isConflictError = errorMsg.includes('already in use') ||
                                    errorMsg.includes('is ambiguous') ||
                                    errorMsg.includes('network') && errorMsg.includes('found');

            if (isConflictError) {
                try {
                    console.log('[DockerService] Resource conflict detected, cleaning up...');
                    onProgress?.('Resource conflict detected, cleaning up...');

                    // Full cleanup with remove-orphans
                    await execAsync(`docker-compose -f "${this.composePath}" down --remove-orphans`, { timeout: 60000 }).catch(() => {});

                    // Retry starting
                    onProgress?.('Retrying...');
                    await execAsync(`docker-compose -f "${this.composePath}" up -d --remove-orphans`, { timeout: 180000 });

                    onProgress?.('Waiting for Neo4j to be ready...');
                    const ready = await this.waitForNeo4j(90);

                    if (ready) {
                        onProgress?.('BloodHound CE is ready!');
                        return { success: true, message: 'BloodHound CE started successfully' };
                    } else {
                        return { success: true, message: 'BloodHound CE started but still initializing' };
                    }
                } catch (retryError: any) {
                    const friendlyError = parseDockerError(retryError.message || String(retryError));
                    return { success: false, message: 'Failed to start BloodHound CE', error: friendlyError };
                }
            }

            const friendlyError = parseDockerError(errorMsg);
            return { success: false, message: 'Failed to start BloodHound CE', error: friendlyError };
        }
    }

    /**
     * Stop BloodHound CE stack
     */
    async stopContainer(): Promise<DockerResult> {
        try {
            if (!await this.isContainerRunning()) {
                return { success: true, message: 'BloodHound CE is not running' };
            }

            if (existsSync(this.composePath)) {
                await execAsync(`docker-compose -f "${this.composePath}" stop`, { timeout: 60000 });
            } else {
                // Fallback: stop individual containers
                await execAsync(`docker stop ${NEO4J_CONTAINER} ${BLOODHOUND_CONTAINER} ${POSTGRES_CONTAINER}`, { timeout: 60000 }).catch(() => {});
            }

            return { success: true, message: 'BloodHound CE stopped successfully' };
        } catch (error: any) {
            console.error('[DockerService] Error stopping BloodHound CE:', error);
            const friendlyError = parseDockerError(error.message || String(error));
            return { success: false, message: 'Failed to stop BloodHound CE', error: friendlyError };
        }
    }

    /**
     * Remove BloodHound CE containers (keeps data volumes)
     */
    async removeContainer(): Promise<DockerResult> {
        try {
            // Stop first if running
            await this.stopContainer();

            if (!await this.containerExists()) {
                return { success: true, message: 'Containers do not exist' };
            }

            if (existsSync(this.composePath)) {
                await execAsync(`docker-compose -f "${this.composePath}" down`, { timeout: 60000 });
            } else {
                await execAsync(`docker rm ${NEO4J_CONTAINER} ${BLOODHOUND_CONTAINER} ${POSTGRES_CONTAINER}`, { timeout: 30000 }).catch(() => {});
            }

            return { success: true, message: 'BloodHound CE containers removed successfully' };
        } catch (error: any) {
            console.error('[DockerService] Error removing containers:', error);
            const friendlyError = parseDockerError(error.message || String(error));
            return { success: false, message: 'Failed to remove BloodHound CE containers', error: friendlyError };
        }
    }

    /**
     * Full reset - remove containers AND data volumes
     */
    async fullReset(): Promise<DockerResult> {
        try {
            if (existsSync(this.composePath)) {
                await execAsync(`docker-compose -f "${this.composePath}" down -v`, { timeout: 60000 });
            } else {
                await this.removeContainer();
                // Remove all BloodHound CE volumes
                await execAsync('docker volume rm aegis_neo4j_data aegis_neo4j_logs aegis_postgres_data aegis_bloodhound_config', { timeout: 30000 }).catch(() => {});
            }

            return { success: true, message: 'BloodHound CE containers and data removed successfully' };
        } catch (error: any) {
            console.error('[DockerService] Error during full reset:', error);
            const friendlyError = parseDockerError(error.message || String(error));
            return { success: false, message: 'Failed to reset BloodHound CE', error: friendlyError };
        }
    }

    /**
     * First-time setup: Pull images and create BloodHound CE stack
     */
    async setup(onProgress?: (message: string) => void): Promise<DockerResult> {
        try {
            // Check Docker
            onProgress?.('Checking Docker installation...');
            if (!await this.isDockerInstalled()) {
                return {
                    success: false,
                    message: 'Docker is not installed. Please install Docker Desktop.',
                    error: 'DOCKER_NOT_INSTALLED'
                };
            }

            onProgress?.('Checking if Docker is running...');
            if (!await this.isDockerRunning()) {
                return {
                    success: false,
                    message: 'Docker Desktop is not running. Please start Docker Desktop.',
                    error: 'DOCKER_NOT_RUNNING'
                };
            }

            // Clean up any orphaned resources first (prevents network conflicts on re-setup)
            await this.cleanupOrphans(onProgress);

            // Check if already set up (after cleanup, re-check)
            if (await this.containerExists()) {
                onProgress?.('BloodHound CE already exists. Starting...');
                return await this.startContainer(onProgress);
            }

            // Pull images
            onProgress?.('Downloading BloodHound CE images... This may take a few minutes.');
            const pullResult = await this.pullImage(onProgress);
            if (!pullResult.success) {
                return pullResult;
            }

            // Start stack
            onProgress?.('Creating and starting BloodHound CE stack...');
            return await this.startContainer(onProgress);
        } catch (error: any) {
            console.error('[DockerService] Error during setup:', error);
            const friendlyError = parseDockerError(error.message || String(error));
            return { success: false, message: 'Setup failed', error: friendlyError };
        }
    }

    /**
     * Wait for Neo4j to be ready
     */
    private async waitForNeo4j(timeoutSeconds: number): Promise<boolean> {
        const startTime = Date.now();
        const timeoutMs = timeoutSeconds * 1000;

        while (Date.now() - startTime < timeoutMs) {
            if (await this.isNeo4jReady()) {
                return true;
            }
            await new Promise(resolve => setTimeout(resolve, 2000)); // Check every 2 seconds
        }

        return false;
    }

    /**
     * Get container logs (from Neo4j container)
     */
    async getLogs(lines: number = 50): Promise<string> {
        try {
            const { stdout } = await execAsync(`docker logs --tail ${lines} ${NEO4J_CONTAINER}`);
            return stdout;
        } catch (error) {
            console.error('[DockerService] Error getting logs:', error);
            return '';
        }
    }

    /**
     * Get BloodHound CE connection info
     */
    getConnectionInfo() {
        return {
            // Neo4j connection
            uri: `bolt://localhost:${NEO4J_BOLT_PORT}`,
            httpUrl: `http://localhost:${NEO4J_HTTP_PORT}`,
            username: 'neo4j',
            password: NEO4J_PASSWORD,
            // BloodHound UI
            bloodhoundUrl: `http://localhost:${BLOODHOUND_PORT}`
        };
    }
}

// Export singleton instance
export const dockerService = new DockerService();
export default dockerService;
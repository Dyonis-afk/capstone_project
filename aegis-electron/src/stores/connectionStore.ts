/**
 * Connection Store using Zustand
 * Location: src/stores/connectionStore.ts
 *
 * Centralized connection status management for all services:
 * - Docker Desktop (when in Docker mode)
 * - BloodHound CE (container + Neo4j) OR Custom Neo4j connection
 * - Backend API (RAG service)
 * - BloodHound CE API token
 *
 * Features:
 * - Single source of truth for all connection states
 * - Smart polling: faster when services are down, slower when up
 * - Silent background checks (no UI flicker)
 * - Manual refresh with visible "checking" state
 * - Action-triggered checks for uploads/queries
 * - Support for Docker mode (AEGIS-managed) and Custom mode (user's own BloodHound)
 */

import { create } from 'zustand';
import { apiService } from '../services/api';

// ==================== TYPES ====================

export type Neo4jMode = 'docker' | 'custom';

interface ConnectionState {
    // Neo4j connection mode (Docker = AEGIS-managed, Custom = user's own BloodHound)
    neo4jMode: Neo4jMode;

    // Docker Desktop status (only relevant in Docker mode)
    dockerRunning: boolean;

    // BloodHound CE status (container running + Neo4j ready) - Docker mode
    bloodhoundRunning: boolean;  // Container exists and running
    neo4jReady: boolean;         // Neo4j accepting connections (both modes)

    // Custom Neo4j connection status (only relevant in Custom mode)
    customNeo4jConnected: boolean;

    // Backend API status
    backendConnected: boolean;

    // BloodHound CE API token configured
    bhceTokenConfigured: boolean;

    // Loading states for individual checks (only set during manual checks)
    isCheckingDocker: boolean;
    isCheckingBloodhound: boolean;
    isCheckingBackend: boolean;
    isCheckingToken: boolean;

    // Global checking state (only true during MANUAL checks, not background polling)
    isChecking: boolean;

    // Last check timestamp
    lastChecked: Date | null;

    // Error message if any check failed critically
    lastError: string | null;
}

interface ConnectionActions {
    // Set Neo4j connection mode (syncs from Settings)
    setNeo4jMode: (mode: Neo4jMode) => void;

    // Load mode from localStorage on init
    loadNeo4jMode: () => void;

    // Check all connections (manual - shows "Checking..." in UI)
    checkAll: () => Promise<void>;

    // Check all connections silently (background - no UI flicker)
    checkAllSilent: () => Promise<void>;

    // Action-triggered check (before upload/query - returns status object)
    verifyServicesForAction: () => Promise<{
        ready: boolean;
        error?: string;
    }>;

    // Individual checks (silent by default)
    checkDocker: (silent?: boolean) => Promise<boolean>;
    checkBloodhound: (silent?: boolean) => Promise<boolean>;
    checkCustomNeo4j: (silent?: boolean) => Promise<boolean>;
    checkBackend: (silent?: boolean) => Promise<boolean>;
    checkToken: (silent?: boolean) => Promise<boolean>;

    // Smart polling control
    startSmartPolling: () => void;
    stopPolling: () => void;

    // Reset state
    reset: () => void;
}

interface ConnectionStore extends ConnectionState, ConnectionActions {
    // Computed properties (as getters)
    isFullyOperational: () => boolean;
    isBloodhoundReady: () => boolean;
}

// ==================== INITIAL STATE ====================

const initialState: ConnectionState = {
    neo4jMode: 'docker', // Default to Docker mode, will be overwritten on load
    dockerRunning: false,
    bloodhoundRunning: false,
    neo4jReady: false,
    customNeo4jConnected: false,
    backendConnected: false,
    bhceTokenConfigured: false,
    isCheckingDocker: false,
    isCheckingBloodhound: false,
    isCheckingBackend: false,
    isCheckingToken: false,
    isChecking: false,
    lastChecked: null,
    lastError: null,
};

// ==================== POLLING CONFIGURATION ====================

let pollingTimeout: NodeJS.Timeout | null = null;

// Smart polling intervals
const POLLING_INTERVAL_SERVICES_DOWN = 15000;  // 15 seconds when services are down
const POLLING_INTERVAL_SERVICES_UP = 60000;    // 60 seconds when everything is up

// ==================== STORE ====================

export const useConnectionStore = create<ConnectionStore>((set, get) => ({
    ...initialState,

    // ==================== MODE MANAGEMENT ====================

    /**
     * Set Neo4j connection mode and trigger appropriate checks
     */
    setNeo4jMode: (mode: Neo4jMode) => {
        set({ neo4jMode: mode });
        console.log('[ConnectionStore] Neo4j mode set to:', mode);
        // Trigger a silent check to update status based on new mode
        get().checkAllSilent();
    },

    /**
     * Load Neo4j mode from localStorage (called on app init)
     */
    loadNeo4jMode: () => {
        try {
            const savedMode = localStorage.getItem('aegis_neo4j_mode') as Neo4jMode | null;
            if (savedMode === 'docker' || savedMode === 'custom') {
                set({ neo4jMode: savedMode });
                console.log('[ConnectionStore] Loaded Neo4j mode from storage:', savedMode);
            }
        } catch (error) {
            console.error('[ConnectionStore] Error loading Neo4j mode:', error);
        }
    },

    // ==================== COMPUTED PROPERTIES ====================

    /**
     * All services are operational
     * Docker mode: Docker running + BloodHound CE ready + Backend connected + Token configured
     * Custom mode: Custom Neo4j connected + Backend connected + Token configured
     */
    isFullyOperational: () => {
        const state = get();

        if (state.neo4jMode === 'custom') {
            // Custom mode: Need custom Neo4j connection + backend + token
            return (
                state.customNeo4jConnected &&
                state.neo4jReady &&
                state.backendConnected &&
                state.bhceTokenConfigured
            );
        }

        // Docker mode: Need Docker + BloodHound container + Neo4j + backend + token
        return (
            state.dockerRunning &&
            state.bloodhoundRunning &&
            state.neo4jReady &&
            state.backendConnected &&
            state.bhceTokenConfigured
        );
    },

    /**
     * BloodHound CE is ready for queries
     * Docker mode: Container running + Neo4j accepting connections
     * Custom mode: Custom Neo4j connected
     */
    isBloodhoundReady: () => {
        const state = get();

        if (state.neo4jMode === 'custom') {
            return state.customNeo4jConnected && state.neo4jReady;
        }

        return state.bloodhoundRunning && state.neo4jReady;
    },

    // ==================== MANUAL CHECK (shows "Checking..." in UI) ====================

    /**
     * Check all connections in parallel - MANUAL (shows loading state)
     * Use this for manual refresh buttons
     * Checks appropriate services based on neo4jMode
     */
    checkAll: async () => {
        set({
            isChecking: true,
            isCheckingDocker: true,
            isCheckingBloodhound: true,
            isCheckingBackend: true,
            isCheckingToken: true,
            lastError: null
        });

        try {
            const state = get();

            if (state.neo4jMode === 'custom') {
                // Custom mode: Check custom Neo4j, backend, and token (skip Docker checks)
                await Promise.all([
                    get().checkCustomNeo4j(false),
                    get().checkBackend(false),
                    get().checkToken(false),
                ]);
            } else {
                // Docker mode: Check Docker, BloodHound container, backend, and token
                await Promise.all([
                    get().checkDocker(false),
                    get().checkBloodhound(false),
                    get().checkBackend(false),
                    get().checkToken(false),
                ]);
            }

            set({ lastChecked: new Date() });
        } catch (error) {
            console.error('[ConnectionStore] Error during checkAll:', error);
            set({ lastError: error instanceof Error ? error.message : 'Unknown error' });
        } finally {
            set({
                isChecking: false,
                isCheckingDocker: false,
                isCheckingBloodhound: false,
                isCheckingBackend: false,
                isCheckingToken: false
            });
        }
    },

    // ==================== SILENT CHECK (background polling) ====================

    /**
     * Check all connections silently - BACKGROUND (no UI flicker)
     * Use this for automatic background polling
     * Checks appropriate services based on neo4jMode
     */
    checkAllSilent: async () => {
        try {
            const state = get();

            if (state.neo4jMode === 'custom') {
                // Custom mode: Check custom Neo4j, backend, and token (skip Docker checks)
                await Promise.all([
                    get().checkCustomNeo4j(true),
                    get().checkBackend(true),
                    get().checkToken(true),
                ]);
            } else {
                // Docker mode: Check Docker, BloodHound container, backend, and token
                await Promise.all([
                    get().checkDocker(true),
                    get().checkBloodhound(true),
                    get().checkBackend(true),
                    get().checkToken(true),
                ]);
            }

            set({ lastChecked: new Date(), lastError: null });
        } catch (error) {
            console.error('[ConnectionStore] Error during silent check:', error);
            // Don't set lastError for silent checks to avoid UI disruption
        }
    },

    // ==================== ACTION-TRIGGERED CHECK ====================

    /**
     * Verify services before an action (upload, query, etc.)
     * Returns immediately usable status without UI flicker
     * Checks appropriate services based on neo4jMode
     */
    verifyServicesForAction: async () => {
        try {
            // Run silent checks
            await get().checkAllSilent();

            const state = get();

            if (state.neo4jMode === 'custom') {
                // Custom mode: Check custom Neo4j connection, backend, and token
                if (!state.customNeo4jConnected) {
                    return { ready: false, error: 'Custom Neo4j connection failed. Check Settings.' };
                }
                if (!state.neo4jReady) {
                    return { ready: false, error: 'Neo4j is not responding' };
                }
                if (!state.backendConnected) {
                    return { ready: false, error: 'Backend API is not connected' };
                }
                if (!state.bhceTokenConfigured) {
                    return { ready: false, error: 'BloodHound CE API token not configured' };
                }
            } else {
                // Docker mode: Check Docker, BloodHound, Neo4j, backend, and token
                if (!state.dockerRunning) {
                    return { ready: false, error: 'Docker is not running' };
                }
                if (!state.bloodhoundRunning) {
                    return { ready: false, error: 'BloodHound CE is not running' };
                }
                if (!state.neo4jReady) {
                    return { ready: false, error: 'Neo4j is not ready' };
                }
                if (!state.backendConnected) {
                    return { ready: false, error: 'Backend API is not connected' };
                }
                if (!state.bhceTokenConfigured) {
                    return { ready: false, error: 'BloodHound CE API token not configured' };
                }
            }

            return { ready: true };
        } catch (error) {
            return {
                ready: false,
                error: error instanceof Error ? error.message : 'Service check failed'
            };
        }
    },

    // ==================== INDIVIDUAL CHECKS ====================

    /**
     * Check Docker Desktop status
     * @param silent - If true, don't update isCheckingDocker state
     */
    checkDocker: async (silent = true) => {
        if (!silent) set({ isCheckingDocker: true });

        try {
            if (!window.docker) {
                set({ dockerRunning: false });
                if (!silent) set({ isCheckingDocker: false });
                return false;
            }

            const status = await window.docker.getStatus();
            set({ dockerRunning: status.dockerRunning });
            if (!silent) set({ isCheckingDocker: false });
            return status.dockerRunning;
        } catch (error) {
            console.error('[ConnectionStore] Docker check failed:', error);
            set({ dockerRunning: false });
            if (!silent) set({ isCheckingDocker: false });
            return false;
        }
    },

    /**
     * Check BloodHound CE status (container + Neo4j) - DOCKER MODE ONLY
     * @param silent - If true, don't update isCheckingBloodhound state
     */
    checkBloodhound: async (silent = true) => {
        if (!silent) set({ isCheckingBloodhound: true });

        try {
            if (!window.docker) {
                set({ bloodhoundRunning: false, neo4jReady: false });
                if (!silent) set({ isCheckingBloodhound: false });
                return false;
            }

            const status = await window.docker.getStatus();
            const isReady = status.containerRunning && status.neo4jReady;

            set({
                bloodhoundRunning: status.containerRunning,
                neo4jReady: status.neo4jReady
            });
            if (!silent) set({ isCheckingBloodhound: false });

            return isReady;
        } catch (error) {
            console.error('[ConnectionStore] BloodHound check failed:', error);
            set({ bloodhoundRunning: false, neo4jReady: false });
            if (!silent) set({ isCheckingBloodhound: false });
            return false;
        }
    },

    /**
     * Check custom Neo4j connection - CUSTOM MODE ONLY
     * Uses the saved custom connection settings from Settings page
     * @param silent - If true, don't update isCheckingBloodhound state
     */
    checkCustomNeo4j: async (silent = true) => {
        if (!silent) set({ isCheckingBloodhound: true });

        try {
            if (!window.neo4j) {
                set({ customNeo4jConnected: false, neo4jReady: false });
                if (!silent) set({ isCheckingBloodhound: false });
                return false;
            }

            // Test the connection using the saved custom settings
            const result = await window.neo4j.testConnection();
            const isConnected = result.connected; // Neo4jConnectionResult uses 'connected' not 'success'

            set({
                customNeo4jConnected: isConnected,
                neo4jReady: isConnected,
                // In custom mode, we consider "bloodhound running" as Neo4j connected
                bloodhoundRunning: isConnected
            });

            if (!silent) set({ isCheckingBloodhound: false });
            return isConnected;
        } catch (error) {
            console.error('[ConnectionStore] Custom Neo4j check failed:', error);
            set({ customNeo4jConnected: false, neo4jReady: false, bloodhoundRunning: false });
            if (!silent) set({ isCheckingBloodhound: false });
            return false;
        }
    },

    /**
     * Check Backend API connection
     * @param silent - If true, don't update isCheckingBackend state
     */
    checkBackend: async (silent = true) => {
        if (!silent) set({ isCheckingBackend: true });

        try {
            const isConnected = await apiService.testConnection();
            set({ backendConnected: isConnected });
            if (!silent) set({ isCheckingBackend: false });
            return isConnected;
        } catch (error) {
            console.error('[ConnectionStore] Backend check failed:', error);
            set({ backendConnected: false });
            if (!silent) set({ isCheckingBackend: false });
            return false;
        }
    },

    /**
     * Check BloodHound CE API token configuration (mode-aware)
     * Checks if credentials exist for the CURRENT mode (Docker vs Custom)
     * @param silent - If true, don't update isCheckingToken state
     */
    checkToken: async (silent = true) => {
        if (!silent) set({ isCheckingToken: true });

        try {
            if (!window.bloodhoundCE) {
                set({ bhceTokenConfigured: false });
                if (!silent) set({ isCheckingToken: false });
                return false;
            }

            // Check credentials for the current mode (Docker vs Custom have separate tokens)
            const currentMode = get().neo4jMode;
            const hasToken = await window.bloodhoundCE.hasCredentials(currentMode);
            set({ bhceTokenConfigured: hasToken });
            if (!silent) set({ isCheckingToken: false });
            return hasToken;
        } catch (error) {
            console.error('[ConnectionStore] Token check failed:', error);
            set({ bhceTokenConfigured: false });
            if (!silent) set({ isCheckingToken: false });
            return false;
        }
    },

    // ==================== SMART POLLING ====================

    /**
     * Start smart polling - adjusts interval based on service status
     * - Services DOWN: Poll every 15 seconds (detect recovery quickly)
     * - Services UP: Poll every 60 seconds (minimal resource usage)
     */
    startSmartPolling: () => {
        // Clear any existing timeout
        if (pollingTimeout) {
            clearTimeout(pollingTimeout);
            pollingTimeout = null;
        }

        const scheduleNextPoll = async () => {
            // Do a silent check
            await get().checkAllSilent();

            // Determine next interval based on current status
            const isOperational = get().isFullyOperational();
            const nextInterval = isOperational
                ? POLLING_INTERVAL_SERVICES_UP
                : POLLING_INTERVAL_SERVICES_DOWN;

            // Schedule next poll
            pollingTimeout = setTimeout(scheduleNextPoll, nextInterval);

            console.log(`[ConnectionStore] Next poll in ${nextInterval / 1000}s (services ${isOperational ? 'UP' : 'DOWN'})`);
        };

        // Start the polling cycle
        scheduleNextPoll();
        console.log('[ConnectionStore] Smart polling started');
    },

    /**
     * Stop polling for connection status
     */
    stopPolling: () => {
        if (pollingTimeout) {
            clearTimeout(pollingTimeout);
            pollingTimeout = null;
            console.log('[ConnectionStore] Polling stopped');
        }
    },

    // ==================== RESET ====================

    /**
     * Reset store to initial state and stop polling
     */
    reset: () => {
        get().stopPolling();
        set(initialState);
    },
}));

// ==================== CONVENIENCE HOOKS ====================

/**
 * Hook to get overall operational status
 */
export const useIsFullyOperational = () =>
    useConnectionStore((state) => state.isFullyOperational());

/**
 * Hook to get BloodHound ready status
 */
export const useIsBloodhoundReady = () =>
    useConnectionStore((state) => state.isBloodhoundReady());

/**
 * Hook to get checking status (only true during manual checks)
 */
export const useIsChecking = () =>
    useConnectionStore((state) => state.isChecking);

/**
 * Hook to get all connection statuses
 */
export const useConnectionStatus = () =>
    useConnectionStore((state) => ({
        neo4jMode: state.neo4jMode,
        dockerRunning: state.dockerRunning,
        bloodhoundRunning: state.bloodhoundRunning,
        neo4jReady: state.neo4jReady,
        customNeo4jConnected: state.customNeo4jConnected,
        backendConnected: state.backendConnected,
        bhceTokenConfigured: state.bhceTokenConfigured,
        isFullyOperational: state.isFullyOperational(),
        isBloodhoundReady: state.isBloodhoundReady(),
    }));

/**
 * Hook to check if infrastructure is down (mode-aware)
 * In Docker mode: Docker or Neo4j not running
 * In Custom mode: Custom Neo4j not connected
 */
export const useIsInfrastructureDown = () =>
    useConnectionStore((state) => {
        if (state.neo4jMode === 'custom') {
            return !state.customNeo4jConnected || !state.neo4jReady;
        }
        return !state.dockerRunning || !state.neo4jReady;
    });

/**
 * Hook to get Neo4j mode
 */
export const useNeo4jMode = () =>
    useConnectionStore((state) => state.neo4jMode);

// ==================== SELECTORS ====================

/**
 * Get connection store state (for use outside React)
 */
export const getConnectionState = () => useConnectionStore.getState();

/**
 * Check all connections (for use outside React) - MANUAL with loading state
 */
export const checkAllConnections = () => useConnectionStore.getState().checkAll();

/**
 * Check all connections silently (for use outside React) - no loading state
 */
export const checkAllConnectionsSilent = () => useConnectionStore.getState().checkAllSilent();

/**
 * Verify services before action (for use outside React)
 */
export const verifyServices = () => useConnectionStore.getState().verifyServicesForAction();

/**
 * Set Neo4j mode (for use outside React)
 */
export const setNeo4jMode = (mode: Neo4jMode) => useConnectionStore.getState().setNeo4jMode(mode);

/**
 * Load Neo4j mode from localStorage (for use on app init)
 */
export const loadNeo4jModeFromStorage = () => useConnectionStore.getState().loadNeo4jMode();

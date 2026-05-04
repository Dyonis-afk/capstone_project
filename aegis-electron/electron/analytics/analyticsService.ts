/**
 * Analytics Service - PostHog Integration
 *
 * Tracks anonymous usage metrics for AEGIS:
 * - App opens (daily active users)
 * - App version distribution
 * - Platform breakdown (Windows/macOS/Linux)
 *
 * Privacy: Only anonymous device ID is used, no personal data collected.
 */

import { PostHog } from 'posthog-node';
import Store from 'electron-store';
import { app } from 'electron';
import * as os from 'os';
import * as crypto from 'crypto';

const POSTHOG_HOST = 'https://app.posthog.com';

// Persistent store for device ID
const store = new Store({
    name: 'aegis-analytics',
    defaults: {
        deviceId: '',
        analyticsEnabled: true,
        lastSeen: ''
    }
});

// PostHog client instance
let posthog: PostHog | null = null;

/**
 * Get or create anonymous device ID
 * This ID is random and not tied to any user identity
 */
function getDeviceId(): string {
    let deviceId = store.get('deviceId') as string;

    if (!deviceId) {
        deviceId = crypto.randomUUID();
        store.set('deviceId', deviceId);
        console.log('[Analytics] Generated new device ID');
    }

    return deviceId;
}

/**
 * Initialize PostHog analytics
 * Call this once when the app starts (after env vars are loaded)
 */
export function initializeAnalytics(): void {
    // Read API key at runtime (after loadEnvForMode has been called)
    const apiKey = process.env.POST_HOG || '';
    const isConfigured = apiKey && apiKey.startsWith('phc_');

    if (!isConfigured) {
        console.log('[Analytics] PostHog not configured - analytics disabled');
        console.log('[Analytics] POST_HOG env var:', apiKey ? 'set but invalid' : 'not set');
        return;
    }

    try {
        posthog = new PostHog(apiKey, {
            host: POSTHOG_HOST,
            flushAt: 1, // Send events immediately (good for desktop apps)
            flushInterval: 0
        });

        console.log('[Analytics] PostHog initialized successfully');
    } catch (error) {
        console.error('[Analytics] Failed to initialize PostHog:', error);
        posthog = null;
    }
}

/**
 * Track app opened event
 * Call this when the app window is ready
 */
export function trackAppOpened(): void {
    if (!posthog) return;

    const deviceId = getDeviceId();
    const today = new Date().toISOString().split('T')[0];
    const lastSeen = store.get('lastSeen') as string;

    // Update last seen
    store.set('lastSeen', today);

    try {
        posthog.capture({
            distinctId: deviceId,
            event: 'app_opened',
            properties: {
                app_version: app.getVersion(),
                platform: process.platform,
                os_version: os.release(),
                arch: process.arch,
                is_first_open_today: lastSeen !== today,
                node_version: process.version
            }
        });

        console.log('[Analytics] Tracked app_opened event');
    } catch (error) {
        console.error('[Analytics] Failed to track app_opened:', error);
    }
}

/**
 * Track custom event
 * Use for specific feature usage tracking
 */
export function trackEvent(eventName: string, properties?: Record<string, any>): void {
    if (!posthog) return;

    try {
        posthog.capture({
            distinctId: getDeviceId(),
            event: eventName,
            properties: {
                app_version: app.getVersion(),
                platform: process.platform,
                ...properties
            }
        });

        console.log(`[Analytics] Tracked event: ${eventName}`);
    } catch (error) {
        console.error(`[Analytics] Failed to track ${eventName}:`, error);
    }
}

/**
 * Track report generation
 */
export function trackReportGenerated(findingsCount: number): void {
    trackEvent('report_generated', {
        findings_count: findingsCount
    });
}

/**
 * Track Neo4j connection mode
 */
export function trackNeo4jConnection(mode: 'docker' | 'custom'): void {
    trackEvent('neo4j_connected', {
        connection_mode: mode
    });
}

/**
 * Track chat query
 */
export function trackChatQuery(queryType: string): void {
    trackEvent('chat_query', {
        query_type: queryType
    });
}

/**
 * Shutdown analytics - call before app quits
 * Ensures all pending events are sent
 */
export async function shutdownAnalytics(): Promise<void> {
    if (!posthog) return;

    try {
        console.log('[Analytics] Shutting down, flushing events...');
        await posthog.shutdown();
        console.log('[Analytics] Shutdown complete');
    } catch (error) {
        console.error('[Analytics] Error during shutdown:', error);
    }
}

/**
 * Check if analytics is enabled
 */
export function isAnalyticsEnabled(): boolean {
    return posthog !== null && (store.get('analyticsEnabled') as boolean);
}

/**
 * Enable/disable analytics (user preference)
 */
export function setAnalyticsEnabled(enabled: boolean): void {
    store.set('analyticsEnabled', enabled);
    console.log(`[Analytics] Analytics ${enabled ? 'enabled' : 'disabled'} by user`);
}

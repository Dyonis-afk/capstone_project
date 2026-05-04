/**
 * Simple .env file loader for Electron main process
 * Works with ES modules bundler (no require() calls)
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * Load environment variables from a .env file
 */
export function loadEnvFile(envPath: string): void {
    if (!existsSync(envPath)) {
        return;
    }

    try {
        const content = readFileSync(envPath, 'utf-8');
        const lines = content.split('\n');

        for (const line of lines) {
            // Skip empty lines and comments
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) {
                continue;
            }

            // Parse KEY=VALUE
            const eqIndex = trimmed.indexOf('=');
            if (eqIndex === -1) {
                continue;
            }

            const key = trimmed.slice(0, eqIndex).trim();
            let value = trimmed.slice(eqIndex + 1).trim();

            // Remove surrounding quotes if present
            if ((value.startsWith('"') && value.endsWith('"')) ||
                (value.startsWith("'") && value.endsWith("'"))) {
                value = value.slice(1, -1);
            }

            // Only set if not already defined
            if (!(key in process.env)) {
                process.env[key] = value;
            }
        }
    } catch (error) {
        // Silent fail - env file is optional
    }
}

/**
 * Load the appropriate .env file based on NODE_ENV
 */
export function loadEnvForMode(basePath: string): void {
    const isDev = process.env.NODE_ENV === 'development';
    const envFile = isDev ? '.env.development' : '.env.production';
    const envPath = join(basePath, envFile);

    loadEnvFile(envPath);
}

/**
 * API Configuration
 *
 * Centralized configuration for backend API URL.
 * Uses Vite environment variables to switch between development and production.
 *
 * Development: Uses .env.development (localhost:8000)
 * Production:  Uses .env.production (hosted backend URL)
 */

// API Base URL - reads from environment variable with fallback
export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Export individual config values if needed
export const config = {
    apiUrl: API_URL,
    isDevelopment: import.meta.env.DEV,
    isProduction: import.meta.env.PROD,
};

export default API_URL;

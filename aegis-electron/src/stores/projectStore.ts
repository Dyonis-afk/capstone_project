/**
 * Project Store using Zustand
 * Location: src/stores/projectStore.ts
 *
 * Much simpler than React Context - no Provider needed!
 *
 * Tracks:
 * - Current project being viewed
 * - All projects list
 * - Global upload state (to disable uploads across all screens during upload)
 * - Active project ID (which project's data is currently loaded in BloodHound CE)
 *   - Persisted to localStorage so it survives app restarts/sleep
 */

import { create } from 'zustand';

// Storage key for persisting active project ID
const ACTIVE_PROJECT_STORAGE_KEY = 'aegis_active_project_id';

// Helper to get persisted active project ID
const getPersistedActiveProjectId = (): string | null => {
    try {
        return localStorage.getItem(ACTIVE_PROJECT_STORAGE_KEY);
    } catch {
        return null;
    }
};

// Helper to persist active project ID
const persistActiveProjectId = (projectId: string | null): void => {
    try {
        if (projectId) {
            localStorage.setItem(ACTIVE_PROJECT_STORAGE_KEY, projectId);
        } else {
            localStorage.removeItem(ACTIVE_PROJECT_STORAGE_KEY);
        }
    } catch (err) {
        console.warn('[ProjectStore] Failed to persist active project ID:', err);
    }
};

// Type from your preload.ts
interface Project {
    id: string;
    name: string;
    description?: string;
    neo4j_database?: string;
    domain_name?: string;
    created_at: string;
    updated_at: string;
}

interface ProjectStore {
    currentProject: Project | null;
    projects: Project[];
    isLoading: boolean;

    // Global upload state - when true, upload buttons are disabled everywhere
    isUploading: boolean;
    uploadingProjectId: string | null;  // Which project is currently uploading

    // Active project - which project's data is currently loaded in BloodHound CE
    // Only one project can be "active" at a time since BloodHound CE holds one dataset
    activeProjectId: string | null;

    setCurrentProject: (project: Project | null) => void;
    setCurrentProjectById: (id: string) => void;
    loadProjects: () => Promise<void>;

    // Upload state management
    setUploading: (isUploading: boolean, projectId?: string | null) => void;

    // Active project management
    setActiveProjectId: (projectId: string | null) => void;
    clearActiveProject: () => void;  // Clears both state and localStorage
}

export const useProjectStore = create<ProjectStore>((set, get) => ({
    currentProject: null,
    projects: [],
    isLoading: false,
    isUploading: false,
    uploadingProjectId: null,
    // Initialize from localStorage so it survives app restarts/sleep
    activeProjectId: getPersistedActiveProjectId(),

    setCurrentProject: (project) => set({ currentProject: project }),

    setCurrentProjectById: (id) => {
        const project = get().projects.find(p => p.id === id);
        if (project) set({ currentProject: project });
    },

    loadProjects: async () => {
        set({ isLoading: true });
        try {
            const result = await window.database.getAllProjects();
            if (result.success && result.data) {
                const current = get().currentProject;

                // Don't auto-detect activeProjectId - it should only be set when:
                // 1. A project's data is actually uploaded to BloodHound CE
                // 2. Explicitly set via setActiveProjectId()
                // This prevents overwriting intentional null (e.g., after mode switch)
                set({
                    projects: result.data,
                    currentProject: current || result.data[0] || null,
                    isLoading: false
                });
            } else {
                console.error('Failed to load projects:', result.error);
                set({ isLoading: false });
            }
        } catch (error) {
            console.error('Failed to load projects:', error);
            set({ isLoading: false });
        }
    },

    setUploading: (isUploading, projectId = null) => set({
        isUploading,
        uploadingProjectId: isUploading ? projectId : null
    }),

    setActiveProjectId: (projectId) => {
        // Persist to localStorage so it survives app restarts/sleep
        persistActiveProjectId(projectId);
        set({ activeProjectId: projectId });
    },

    clearActiveProject: () => {
        // Clear both state and localStorage
        persistActiveProjectId(null);
        set({ activeProjectId: null });
    }
}));

// Convenience hooks
export const useCurrentProject = () => useProjectStore(s => s.currentProject);
export const useProjectId = () => useProjectStore(s => s.currentProject?.id);
export const useProjects = () => useProjectStore(s => s.projects);

// For use outside React (e.g., in API service)
export const getProjectId = () => useProjectStore.getState().currentProject?.id;

// Re-export Project type for convenience
export type { Project };
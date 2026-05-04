/**
 * Upload Store using Zustand
 * Location: src/stores/uploadStore.ts
 *
 * Persists upload/ingestion state across navigation (e.g., HomeContent → Settings → HomeContent).
 * Without this, navigating away during ingestion would lose all upload state since React
 * component state (useState) is destroyed on unmount.
 */

import { create } from 'zustand';
import { Tier0Config, Tier0Asset } from '../components/Tier0ConfigModal';

interface FindingsSummary {
    total_nodes: number;
    total_edges: number;
    high_risk_count: number;
    medium_risk_count: number;
    low_risk_count: number;
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

export interface LocalAnalysis {
    findings: ExtractedFindings;
    filename: string;
}

type UploadStep = 'idle' | 'selecting' | 'uploading' | 'extracting' | 'done';

interface UploadStore {
    // Upload state
    isUploading: boolean;
    uploadStep: UploadStep;
    selectedFileName: string | null;
    errorMessage: string | null;
    uploadProgress: string;
    uploadStartTime: number | null;
    elapsedSeconds: number;

    // Result state
    bhceImportSuccess: boolean;
    localAnalysis: LocalAnalysis | null;

    // Tier 0 state
    t0AutoDetectedAssets: Tier0Asset[];
    t0Config: Tier0Config | null;
    t0Configured: boolean;
    isDetectingT0: boolean;

    // Actions
    setIsUploading: (v: boolean) => void;
    setUploadStep: (v: UploadStep) => void;
    setSelectedFileName: (v: string | null) => void;
    setErrorMessage: (v: string | null) => void;
    setUploadProgress: (v: string) => void;
    setUploadStartTime: (v: number | null) => void;
    setElapsedSeconds: (v: number) => void;
    setBhceImportSuccess: (v: boolean) => void;
    setLocalAnalysis: (v: LocalAnalysis | null) => void;
    setT0AutoDetectedAssets: (v: Tier0Asset[]) => void;
    setT0Config: (v: Tier0Config | null) => void;
    setT0Configured: (v: boolean) => void;
    setIsDetectingT0: (v: boolean) => void;

    // Bulk actions
    resetUpload: () => void;
    cancelIngestion: () => void;
}

const initialState = {
    isUploading: false,
    uploadStep: 'idle' as UploadStep,
    selectedFileName: null as string | null,
    errorMessage: null as string | null,
    uploadProgress: '',
    uploadStartTime: null as number | null,
    elapsedSeconds: 0,
    bhceImportSuccess: false,
    localAnalysis: null as LocalAnalysis | null,
    t0AutoDetectedAssets: [] as Tier0Asset[],
    t0Config: null as Tier0Config | null,
    t0Configured: false,
    isDetectingT0: false,
};

export const useUploadStore = create<UploadStore>((set) => ({
    ...initialState,

    setIsUploading: (v) => set({ isUploading: v }),
    setUploadStep: (v) => set({ uploadStep: v }),
    setSelectedFileName: (v) => set({ selectedFileName: v }),
    setErrorMessage: (v) => set({ errorMessage: v }),
    setUploadProgress: (v) => set({ uploadProgress: v }),
    setUploadStartTime: (v) => set({ uploadStartTime: v }),
    setElapsedSeconds: (v) => set({ elapsedSeconds: v }),
    setBhceImportSuccess: (v) => set({ bhceImportSuccess: v }),
    setLocalAnalysis: (v) => set({ localAnalysis: v }),
    setT0AutoDetectedAssets: (v) => set({ t0AutoDetectedAssets: v }),
    setT0Config: (v) => set({ t0Config: v }),
    setT0Configured: (v) => set({ t0Configured: v }),
    setIsDetectingT0: (v) => set({ isDetectingT0: v }),

    resetUpload: () => set({
        localAnalysis: null,
        selectedFileName: null,
        bhceImportSuccess: false,
        t0Config: null,
        t0AutoDetectedAssets: [],
        t0Configured: false,
        errorMessage: null,
        uploadStep: 'idle',
        uploadProgress: '',
        uploadStartTime: null,
        elapsedSeconds: 0,
    }),

    cancelIngestion: () => set({
        errorMessage: 'Ingestion cancelled by user.',
        uploadStep: 'idle',
        isUploading: false,
        uploadStartTime: null,
        elapsedSeconds: 0,
    }),
}));

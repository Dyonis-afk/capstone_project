// Global type definitions for AEGIS

export interface AegisConfig {
    version: string;
    isDevelopment: boolean;
}

export type TabType = 'home' | 'chat' | 'dashboard' | 'upload' | 'settings';

export interface NavigationTab {
    key: TabType;
    label: string;
    icon: string;
}

// Future types for AEGIS features
export interface ChatMessage {
    id: string;
    role: 'user' | 'assistant';
    content: string;
    timestamp: Date;
    metadata?: Record<string, unknown>;
}

// BloodHound and Report Types

export interface Finding {
    edgeType: string;
    source: string;
    target: string;
    sourceType: string;
    targetType: string;
    riskLevel: 'High' | 'Medium' | 'Low';
    explanation?: string;
}

export interface AnalysisSummary {
    totalNodes: number;
    totalEdges: number;
    highRiskCount: number;
    mediumRiskCount: number;
    lowRiskCount: number;
    totalFindings: number;
    overallRisk: string;
    domain?: string;  // ✅ Added for domain name extraction
}

export interface BloodHoundAnalysis {
    message: string;
    filename?: string;
    domain?: string;  // ✅ Added for direct domain access
    summary: AnalysisSummary;
    highRiskFindings: Finding[];
    mediumRiskFindings: Finding[];
    lowRiskFindings: Finding[];
    raw_json?: string;
    allFindings: Finding[];
    metadata?: {      // ✅ Added for metadata support
        domain?: string;
        collectionDate?: string;
        version?: string;
        type?: string;
    };
}

export interface DetailedRemediation {
    edgeType: string;
    source: string;
    target: string;
    riskLevel: string;
    explanation: string;
    remediationSteps: string[];
    powershellScript: string;
    rollbackScript?: string;
    mitreMapping: string[];
    detectionMethods: string[];
    warnings: string[];
}

export interface SecurityReport {
    reportId: string;
    generatedAt: Date;
    executiveSummary: string;
    environmentOverview?: string;  // ✅ Added for future environment overview section
    summary: AnalysisSummary;
    findings: Finding[];
    recommendations: string[];
    overallRiskAssessment: string;
    findingsByType: Record<string, number>;
    detailedRemediations: DetailedRemediation[];
}
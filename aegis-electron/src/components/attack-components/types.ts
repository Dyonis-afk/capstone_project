/**
 * Shared types for attack-components
 * Location: src/components/attack-components/types.ts
 */

export interface GraphNode {
    id: string;
    label: string;
    name: string;
    type: 'User' | 'Group' | 'Computer' | 'Domain' | 'Unknown';
    color: string;
    riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
    inAttackPath: boolean;
    pathIndex: number;
    properties: Record<string, any>;
}

export interface GraphEdge {
    id: string;
    source: string;
    target: string;
    label: string;
    type: string;
    color: string;
    riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
    inAttackPath: boolean;
    pathIndex: number;
    attack_type: string;
    description: string;
    properties: Record<string, any>;
}

export type StatCardColor = 'red' | 'yellow' | 'green' | 'blue' | 'purple';

// ============================================================
// Finding-Based Report Types (Pentest Style)
// ============================================================

export type FindingSeverity = 'Critical' | 'High' | 'Medium' | 'Low';
export type AttackComplexity = 'Low' | 'Medium' | 'High';

/**
 * Q&A style explanation for understanding the attack
 */
export interface AttackExplanation {
    question: string;  // "What is Kerberoasting?"
    answer: string;    // Detailed explanation
}

/**
 * Affected entity in the finding
 */
export interface AffectedEntity {
    principal: string;       // "SQLSERVICE@MARVEL.LOCAL"
    type: string;            // "Service Account", "User", "Computer"
    target_group?: string;   // "ENTERPRISE ADMINS@MARVEL.LOCAL"
    path?: string;           // "Direct" or description of path
    risk?: FindingSeverity;  // Individual risk level
    spn?: string;            // Service Principal Name if applicable
}

/**
 * OPSEC classification for attack commands
 */
export type OpsecLevel = 'safe' | 'risky';

/**
 * Individual OPSEC option within an attack step
 * Represents one way to accomplish the step with different OPSEC profiles
 */
export interface OpsecOption {
    opsec_level: OpsecLevel;  // 'safe' = Native PowerShell/offline, 'risky' = known tools (PowerView, Rubeus)
    tool_name: string;        // "Native PowerShell", "PowerView", "Rubeus", "Hashcat (Offline)"
    command: string;          // The actual command
    explanation: string;      // Why this approach is OPSEC-safe or risky, and what it does
    amsi_bypass?: {           // AMSI bypass reference (if PowerShell tool)
        required: boolean;
        note: string;
        family?: string;
    };
}

/**
 * Attack command/step in the PoC
 * Supports both legacy single-command format and new OPSEC-aware multi-option format
 */
export interface AttackStep {
    step_number: number;
    title: string;           // "Reconnaissance and Target Discovery"
    category?: string;       // "Discovery", "Credential Access", "Lateral Movement", etc.
    objective?: string;      // What this step accomplishes (displayed as OBJECTIVE section)
    prerequisites?: string[]; // What's needed before this step (displayed as PREREQUISITES box)
    description?: string;    // What this step accomplishes overall (fallback if no objective)

    // New OPSEC-aware format: multiple options per step
    opsec_options?: OpsecOption[];

    // Legacy single-command format (for backward compatibility)
    tool?: string;           // "Impacket", "PowerView", "Rubeus", "hashcat"
    command?: string;        // The actual command
    explanation?: string;    // What this step does
    highlight?: string;      // Entity or value to highlight in explanation
}

/**
 * Reference link (MITRE, Microsoft, etc.)
 */
export interface Reference {
    tag: string;             // "MITRE", "Microsoft", "Blog"
    title: string;           // "T1558.003 - Steal or Forge Kerberos Tickets"
    url: string;
}

/**
 * Detection query for SIEM platforms
 */
export interface DetectionQuery {
    platform: string;        // "Splunk", "KQL (Microsoft Sentinel)"
    query: string;
}

/**
 * Detection and monitoring section
 */
export interface FindingDetection {
    event_ids: Array<{
        id: string;
        description: string;
    }>;
    indicators_of_compromise: string[];
    proactive_measures?: string[];
    queries: DetectionQuery[];
}

/**
 * Chain step information for attack chain visualization
 */
export interface ChainStepInfo {
    finding_id: number;
    edge_type: string;
    title?: string;
}

/**
 * Chain info for findings that are part of an attack chain
 */
export interface ChainInfoData {
    is_in_chain: boolean;
    chain_id: string;
    position: number;
    total_steps: number;
    chain_steps: ChainStepInfo[];
    previous?: ChainStepInfo;
    next?: ChainStepInfo;
    chain_goal: string;
}

/**
 * Complete finding structure matching the mockup
 */
export interface Finding {
    // Header
    finding_number: number;
    severity: FindingSeverity;
    title: string;
    attack_complexity: AttackComplexity;
    category: string;        // "Privileged Access", "Credential Access", etc.

    // Chain info (if finding is part of an attack chain)
    chain_info?: ChainInfoData;

    // Observation
    observation: string;

    // Understanding the Attack (Q&A format)
    understanding: AttackExplanation[];

    // Affected Entities
    affected_entities: AffectedEntity[];

    // Attack Commands (PoC)
    attack_steps: AttackStep[];
    attack_intro?: string;   // Introduction text before steps

    // Evidence
    cypher_query: string;
    edges_used?: string[];   // Edge types used in the query (MemberOf, GenericAll, etc.)
    graph_data?: any;        // For embedded graph visualization

    // Risk
    risk_title: string;      // "Critical Business Impact"
    risk_description: string;

    // Remediation
    remediation_steps: string[];
    remediation_script?: string;  // PowerShell script

    // References
    references: Reference[];

    // Detection & Monitoring
    detection: FindingDetection;
}

/**
 * Findings overview table row
 */
export interface FindingSummaryRow {
    finding_number: number;
    title: string;
    severity: FindingSeverity;
    complexity: AttackComplexity;
    category: string;
}

/**
 * Complete report structure with findings
 */
export interface FindingsReport {
    // Report header
    report_title: string;
    report_subtitle: string;
    report_id: string;
    analysis_date: string;
    domain: string;

    // Stats
    total_attack_paths: number;

    // Executive summary
    executive_summary: string;
    key_concerns: string[];

    // Findings summary table
    findings_summary: FindingSummaryRow[];

    // Detailed findings
    findings: Finding[];
}

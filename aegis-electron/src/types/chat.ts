/**
 * Chat Types for Simplified Query System
 *
 * Flow: User Input → Cypher (direct or generated) → Execute → Results
 *       Results rendered in Normal (chat) or Report (finding) format
 */

import { Finding } from '../components/attack-components/types';

// =============================================================================
// CORE TYPES
// =============================================================================

/**
 * View mode toggle - Normal chat vs Report format
 */
export type ViewMode = 'normal' | 'report';

/**
 * Query classification (simplified)
 */
export type QueryType = 'cypher' | 'natural_language' | 'suggestion' | 'invalid';

/**
 * Response type for rendering
 */
export type ResponseType = 'markdown' | 'graph' | 'error';

// =============================================================================
// GRAPH DATA
// =============================================================================

/**
 * Graph data for AttackPathGraph visualization
 */
export interface ChatGraphData {
    nodes: Array<{
        id: string;
        label: string;
        name: string;
        type: 'User' | 'Group' | 'Computer' | 'Domain' | 'Unknown';
        color: string;
        riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
        inAttackPath: boolean;
        pathIndex: number;
        properties: Record<string, unknown>;
    }>;
    edges: Array<{
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
        properties: Record<string, unknown>;
    }>;
    paths: Array<{
        id: string;
        name: string;
        description: string;
        attack_type: string;
        priority: string;
        risk_level: 'Critical' | 'High' | 'Medium' | 'Low';
        result_count: number;
        scenario_number: number;
        color: string;
    }>;
}

// =============================================================================
// QUERY & RESPONSE
// =============================================================================

/**
 * Request to execute a query
 */
export interface QueryRequest {
    query: string;
    query_type: QueryType;
    output_format: ViewMode;
    project_id?: string;
}

/**
 * OPSEC option within an attack step
 */
export interface OpsecOption {
    opsec_level: 'safe' | 'risky';
    tool_name: string;
    command: string;
    explanation: string;
}

/**
 * Attack step for structured attack commands (matches FindingCard's AttackStepCard)
 * Supports both legacy single-command format and new OPSEC-aware multi-option format
 */
export interface AttackStep {
    step_number: number;
    title: string;
    category?: string;
    objective?: string;
    prerequisites?: string[];
    description?: string;

    // New OPSEC-aware format
    opsec_options?: OpsecOption[];

    // Legacy single-command format
    tool?: string;
    command?: string;
    explanation?: string;
    highlight?: string;
}

/**
 * A named Cypher query (for multi-query responses)
 */
export interface NamedQuery {
    name: string;
    cypher: string;
}

/**
 * A single finding result from a multi-query execution
 */
export interface MultiQueryFinding {
    query_name: string;
    cypher_query: string;
    result_count: number;
    results?: Array<Record<string, unknown>>;  // Raw Neo4j results for table display
    finding?: Finding;
    explanation?: string;
    understanding?: Array<{ question: string; answer: string }>;
    attack_steps?: AttackStep[];
    graph_data?: ChatGraphData;
    has_graph: boolean;
    error?: string;
}

/**
 * Response from query execution
 */
export interface QueryResponse {
    success: boolean;
    query_type: QueryType;

    // The executed Cypher (either provided or generated)
    cypher_query?: string;

    // Multi-query: named queries from broad security questions
    cypher_queries?: NamedQuery[];

    // Raw results from Neo4j
    results?: Array<Record<string, unknown>>;
    result_count: number;

    // Normal mode content (markdown)
    explanation?: string;      // Basic description of findings
    understanding?: Array<{ question: string; answer: string }>;  // Q&A explanations
    attack_steps?: AttackStep[];  // Structured attack steps (matches FindingCard style)
    remediation?: string;      // Remediation strategy

    // Report mode content
    finding?: Finding;

    // Multi-query findings (when cypher_queries was used)
    multi_findings?: MultiQueryFinding[];

    // Graph data (when query returns paths/relationships)
    graph_data?: ChatGraphData;
    has_graph: boolean;

    // Suggested query (for non-query inputs like "How to exploit WriteDacl?")
    suggested_query?: string;

    // Error handling
    error?: string;

    // View mode used when this response was generated (for persistence)
    view_mode?: ViewMode;
}

// =============================================================================
// SUGGESTIONS
// =============================================================================

/**
 * Suggested query item
 */
export interface SuggestedQuery {
    name: string;
    description: string;
    cypher: string;
    category: string;
}

/**
 * Response from suggestions endpoint
 */
export interface SuggestionsResponse {
    suggestions: SuggestedQuery[];      // Predefined quick suggestions
    ai_suggestions: SuggestedQuery[];   // Model-generated suggestions
    environment_summary?: string;
}

// =============================================================================
// REPORT INTEGRATION
// =============================================================================

/**
 * Additional finding stored in the report (from chat queries)
 */
export interface AdditionalFinding {
    id: string;
    added_at: string;
    source_query: string;
    cypher_query?: string;
    result_count: number;
    user_notes?: string;
    finding: Finding;
    graph_data?: ChatGraphData;  // Graph data for visualization in report
}

// =============================================================================
// CHAT MESSAGE
// =============================================================================

/**
 * Chat message with response metadata
 */
export interface ChatMessage {
    id: string;
    chat_id: string;
    role: 'user' | 'assistant';
    content: string;
    created_at: string;

    // Response metadata (for assistant messages)
    response_data?: QueryResponse;
    view_mode?: ViewMode;
}

// =============================================================================
// COMPONENT PROPS
// =============================================================================

/**
 * Props for chat response rendering
 */
export interface ChatResponseRenderProps {
    response: QueryResponse;
    viewMode: ViewMode;
    onAddToReport?: (finding: Finding) => void;
    onCopy?: (text: string) => void;
    onViewModeChange?: (mode: ViewMode) => void;
}

/**
 * Props for the Add to Report modal
 */
export interface AddToReportModalProps {
    isOpen: boolean;
    onClose: () => void;
    onAdd: (notes?: string) => void;
    finding: Finding;
    sourceQuery: string;
    cypherQuery?: string;
    resultCount?: number;
}

/**
 * Props for View Mode toggle
 */
export interface ViewModeToggleProps {
    mode: ViewMode;
    onChange: (mode: ViewMode) => void;
    disabled?: boolean;
}

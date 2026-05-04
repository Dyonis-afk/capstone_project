/**
 * Attack Components Barrel Export
 * Location: src/components/attack-components/index.ts
 *
 * Exports all attack path report components
 */

// Types
export * from './types';
export type { ChainStepInfo, ChainInfoData } from './types';

// Core Components
export { default as CypherQueryDisplay } from './CypherQueryDisplay';
export { default as MarkdownContent } from './MarkdownContent';
export { default as ExecutiveSummaryContent } from './ExecutiveSummaryContent';
export { default as SyntaxHighlightedScript } from './SyntaxHighlightedScript';

// UI Components
export { default as SectionHeader } from './SectionHeader';
export { default as StatCard } from './StatCard';

// Finding-Based Report Components (Pentest Style - Matching Mockup)
export { default as FindingCard } from './FindingCard';
export { default as AttackExplainer } from './AttackExplainer';
export { default as AttackStepCard } from './AttackStepCard';
export { default as DetectionMonitoring } from './DetectionMonitoring';
export { default as AdditionalFindingsSection } from './AdditionalFindingsSection';

// Tool Links (for attack commands)
export { default as ToolLinksFooter, detectToolsFromCommand, detectToolsFromStep, TOOL_LINKS } from './ToolLinksFooter';

// Attack Chain Components
export { default as AttackChainPositionWidget } from './AttackChainPositionWidget';
export { default as GlobalAttackChain } from './GlobalAttackChain';
export type { ChainStep, ChainInfo } from './AttackChainPositionWidget';

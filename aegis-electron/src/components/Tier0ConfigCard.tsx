/**
 * Tier0ConfigCard - Card shown in HomeContent after upload for T0 configuration
 * Location: src/components/Tier0ConfigCard.tsx
 *
 * Features:
 * - Shows T0 configuration status
 * - Button to open configuration modal
 * - Shows count of auto-detected/configured assets
 * - "Skip" link to bypass configuration
 */

import React from 'react';
import { Tier0Config } from './Tier0ConfigModal';

interface Tier0ConfigCardProps {
    isConfigured: boolean;
    config: Tier0Config | null;
    autoDetectedCount: number;
    configuredCount: number;
    domains: string[];
    onConfigure: () => void;
    onSkip: () => void;
    isLoading?: boolean;
}

const Tier0ConfigCard: React.FC<Tier0ConfigCardProps> = ({
    isConfigured,
    config,
    autoDetectedCount,
    configuredCount: _configuredCount,
    domains,
    onConfigure,
    onSkip,
    isLoading = false
}) => {
    // Count assets per category if configured
    const getAssetCounts = () => {
        if (!config) return { users: 0, groups: 0, computers: 0 };

        let users = 0;
        let groups = 0;
        let computers = 0;

        Object.values(config.domains).forEach(domainConfig => {
            domainConfig.assets.forEach(asset => {
                if (asset.type === 'User') users++;
                else if (asset.type === 'Group') groups++;
                else if (asset.type === 'Computer') computers++;
            });
        });

        return { users, groups, computers };
    };

    const assetCounts = getAssetCounts();

    return (
        <div className="aegis-card overflow-hidden p-0">
            {/* Header with gradient */}
            <div className="px-5 py-4 bg-gradient-to-r from-aegis-t0/20 via-aegis-t0/10 to-transparent border-b border-aegis-t0/20">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-aegis-t0/20 rounded-lg">
                        <svg className="w-5 h-5 text-aegis-t0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                    </div>
                    <div>
                        <h3 className="text-base font-semibold text-aegis-text">Tier 0 Asset Configuration</h3>
                        <p className="text-sm text-aegis-text-muted">Define privileged assets to reduce false positives</p>
                    </div>
                </div>
            </div>

            {/* Content */}
            <div className="p-5">
                {isLoading ? (
                    <div className="flex items-center gap-3 text-aegis-text-muted">
                        <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                        </svg>
                        <span>Detecting privileged assets...</span>
                    </div>
                ) : isConfigured ? (
                    // Configured State
                    <>
                        <div className="flex items-center gap-2 mb-4">
                            <svg className="w-5 h-5 text-aegis-success-light" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                            </svg>
                            <span className="text-aegis-success-light font-medium">T0 Configuration Complete</span>
                        </div>

                        {/* Asset Stats */}
                        <div className="grid grid-cols-3 gap-3 mb-4">
                            <div className="bg-aegis-dark rounded-lg p-3 text-center">
                                <div className="text-xl font-bold text-aegis-success-light">{assetCounts.groups}</div>
                                <div className="text-xs text-aegis-text-subtle">Groups</div>
                            </div>
                            <div className="bg-aegis-dark rounded-lg p-3 text-center">
                                <div className="text-xl font-bold text-aegis-info">{assetCounts.users}</div>
                                <div className="text-xs text-aegis-text-subtle">Users</div>
                            </div>
                            <div className="bg-aegis-dark rounded-lg p-3 text-center">
                                <div className="text-xl font-bold text-aegis-warning">{assetCounts.computers}</div>
                                <div className="text-xs text-aegis-text-subtle">Computers</div>
                            </div>
                        </div>

                        {/* Domains */}
                        {domains.length > 0 && (
                            <div className="flex flex-wrap gap-2 mb-4">
                                {domains.map(domain => (
                                    <span key={domain} className="aegis-badge-t0">
                                        {domain}
                                    </span>
                                ))}
                            </div>
                        )}

                        {/* Edit Button */}
                        <button
                            onClick={onConfigure}
                            className="aegis-button-secondary w-full flex items-center justify-center gap-2"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                            </svg>
                            Edit Configuration
                        </button>
                    </>
                ) : (
                    // Unconfigured State
                    <>
                        {/* Auto-detected Stats */}
                        <div className="flex items-center justify-between mb-4">
                            <div className="flex items-center gap-2">
                                <span className="text-sm text-aegis-text-muted">Auto-detected:</span>
                                <span className="aegis-badge-t0">
                                    {autoDetectedCount} assets
                                </span>
                            </div>
                            {domains.length > 1 && (
                                <span className="text-xs text-aegis-text-subtle">
                                    {domains.length} domains
                                </span>
                            )}
                        </div>

                        {/* Description */}
                        <p className="text-sm text-aegis-text-muted mb-4">
                            We detected <strong className="text-aegis-t0-light">{autoDetectedCount}</strong> privileged assets
                            (Domain Admins, Enterprise Admins, Domain Controllers, etc.).
                            Configure which assets are Tier 0 to classify expected privileges separately.
                        </p>

                        {/* Configure Button */}
                        <button
                            onClick={onConfigure}
                            className="w-full py-3 px-4 bg-aegis-t0-dark hover:bg-aegis-t0-muted text-white rounded-lg text-sm font-semibold transition-colors flex items-center justify-center gap-2 mb-3"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            </svg>
                            Configure T0 Assets
                        </button>

                        {/* Skip Link */}
                        <button
                            onClick={onSkip}
                            className="w-full text-center text-sm text-aegis-text-subtle hover:text-aegis-text-muted transition-colors"
                        >
                            Skip (use auto-detected assets)
                        </button>
                    </>
                )}
            </div>

            {/* Info Footer */}
            <div className="px-5 py-3 bg-aegis-dark border-t border-aegis-border-light">
                <p className="text-xs text-aegis-text-subtle">
                    <strong className="text-aegis-text-muted">Why configure T0?</strong> Paths between Tier 0 assets
                    (e.g., DA → DC) are expected. Configuring T0 assets shows them separately as
                    "T0 Lateral Movement" rather than as actionable findings.
                </p>
            </div>
        </div>
    );
};

export default Tier0ConfigCard;

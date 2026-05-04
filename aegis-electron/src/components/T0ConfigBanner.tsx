/**
 * T0ConfigBanner - Banner shown at top of report when T0 is configured
 * Location: src/components/T0ConfigBanner.tsx
 *
 * Features:
 * - Blue accent icon (matching the mock)
 * - Shows T0 asset count summary
 * - "View Configuration" expandable section
 */

import React, { useState } from 'react';
import { Tier0Config } from './Tier0ConfigModal';

interface T0ConfigBannerProps {
    config: Tier0Config;
    className?: string;
}

const T0ConfigBanner: React.FC<T0ConfigBannerProps> = ({ config, className = '' }) => {
    const [isExpanded, setIsExpanded] = useState(false);

    // Calculate totals
    const getTotals = () => {
        let totalAssets = 0;
        let groups = 0;
        let users = 0;
        let computers = 0;
        const domains: string[] = [];

        Object.entries(config.domains).forEach(([domain, domainConfig]) => {
            domains.push(domain);
            domainConfig.assets.forEach(asset => {
                totalAssets++;
                if (asset.type === 'Group') groups++;
                else if (asset.type === 'User') users++;
                else if (asset.type === 'Computer') computers++;
            });
        });

        return { totalAssets, groups, users, computers, domains };
    };

    const totals = getTotals();

    if (!config.enabled || totals.totalAssets === 0) {
        return null;
    }

    return (
        <div className={`rounded-lg overflow-hidden bg-[#161b22] border border-[#30363d] ${className}`}>
            {/* Banner Header */}
            <div className="px-5 py-4">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        {/* Blue accent icon */}
                        <svg className="w-5 h-5 text-[#58a6ff] flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        <div className="flex-1 text-sm text-[#c9d1d9]">
                            <strong className="text-white">Tier 0 Classification Active:</strong>{' '}
                            {totals.users > 0 && <>{totals.users} user{totals.users !== 1 ? 's' : ''}</>}
                            {totals.users > 0 && totals.groups > 0 && ', '}
                            {totals.groups > 0 && <>{totals.groups} group{totals.groups !== 1 ? 's' : ''}</>}
                            {(totals.users > 0 || totals.groups > 0) && totals.computers > 0 && ', and '}
                            {totals.computers > 0 && <>{totals.computers} computer{totals.computers !== 1 ? 's' : ''}</>}
                            {' '}marked as T0 assets. Paths between T0 assets are documented separately for post-compromise analysis.
                            {config.skipped && <span className="text-[#8b949e]"> (Auto-detected)</span>}
                        </div>
                    </div>

                    {/* View Configuration Link */}
                    <button
                        onClick={() => setIsExpanded(!isExpanded)}
                        className="text-sm text-[#58a6ff] hover:underline transition-colors flex items-center gap-1 ml-4 flex-shrink-0"
                    >
                        {isExpanded ? 'Hide' : 'View'} Configuration →
                    </button>
                </div>
            </div>

            {/* Expandable Details */}
            {isExpanded && (
                <div className="border-t border-[#30363d] px-5 py-4">
                    <div className="space-y-4">
                        {Object.entries(config.domains).map(([domain, domainConfig]) => (
                            <div key={domain}>
                                <h4 className="text-xs font-semibold text-[#8b949e] uppercase tracking-wider mb-2">
                                    {domain}
                                </h4>
                                <div className="flex flex-wrap gap-2">
                                    {domainConfig.assets.map((asset, idx) => (
                                        <div
                                            key={`${asset.name}-${idx}`}
                                            className="inline-flex items-center gap-1.5 px-2 py-1 bg-[#21262d] rounded text-xs"
                                        >
                                            <span className={`w-1.5 h-1.5 rounded-full ${
                                                asset.type === 'Group' ? 'bg-[#7ee787]' :
                                                asset.type === 'User' ? 'bg-[#38bdf8]' :
                                                asset.type === 'Computer' ? 'bg-[#fbbf24]' :
                                                'bg-[#58a6ff]'
                                            }`}></span>
                                            <span className="text-[#c9d1d9] font-mono">{asset.name.split('@')[0]}</span>
                                            <span className="text-[#6e7681]">({asset.type})</span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        ))}
                    </div>

                    {/* Info Note */}
                    <div className="mt-4 pt-4 border-t border-[#30363d]">
                        <p className="text-xs text-[#6e7681]">
                            Attack paths between these Tier 0 assets are shown in the
                            <strong className="text-[#c9d1d9]"> "Tier 0 Lateral Movement"</strong> section
                            as expected administrative privileges, separate from actionable findings.
                        </p>
                    </div>
                </div>
            )}
        </div>
    );
};

export default T0ConfigBanner;

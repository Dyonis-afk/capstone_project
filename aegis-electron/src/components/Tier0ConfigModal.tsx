/**
 * Tier0ConfigModal - Modal for configuring Tier 0 (T0) asset exclusions
 * Location: src/components/Tier0ConfigModal.tsx
 *
 * Features:
 * - Autocomplete search from BloodHound Neo4j data
 * - Domain tabs for multi-domain environments
 * - Auto-detected T0 assets (DA, EA, SA, DCs, KRBTGT)
 * - Manual add/remove assets with confirmation
 * - Toast notifications for user feedback
 */

import React, { useState, useEffect, useMemo, useCallback, useRef } from 'react';

// T0 Asset types
export interface Tier0Asset {
    name: string;
    type: 'User' | 'Group' | 'Computer' | 'OU';
    domain: string;
    autoDetected: boolean;
    reason?: string;
    source?: 'auto' | 'user';
}

export interface Tier0Config {
    domains: {
        [domain: string]: {
            assets: Tier0Asset[];
            excludedMembers: string[];
        };
    };
    enabled: boolean;
    skipped: boolean;
}

interface SearchResult {
    name: string;
    type: 'User' | 'Group' | 'Computer';
    desc?: string;
}

interface Tier0ConfigModalProps {
    isOpen: boolean;
    onClose: () => void;
    onSave: (config: Tier0Config) => void;
    domains: string[];
    autoDetectedAssets: Tier0Asset[];
    isLoading?: boolean;
}

const Tier0ConfigModal: React.FC<Tier0ConfigModalProps> = ({
    isOpen,
    onClose,
    onSave,
    domains,
    autoDetectedAssets,
    isLoading = false
}) => {
    // State
    const [activeDomain, setActiveDomain] = useState<string>(domains[0] || '');
    const [t0Assets, setT0Assets] = useState<Tier0Asset[]>([]);
    const [searchType, setSearchType] = useState<'Group' | 'User' | 'Computer'>('Group');
    const [searchQuery, setSearchQuery] = useState('');
    const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
    const [isSearching, setIsSearching] = useState(false);
    const [showDropdown, setShowDropdown] = useState(false);
    const [filterType, setFilterType] = useState<'All' | 'Group' | 'User' | 'Computer'>('All');

    // Confirmation modal state
    const [confirmModalOpen, setConfirmModalOpen] = useState(false);
    const [assetToRemove, setAssetToRemove] = useState<Tier0Asset | null>(null);

    // Toast state
    const [toast, setToast] = useState<{ message: string; visible: boolean }>({ message: '', visible: false });

    const searchInputRef = useRef<HTMLInputElement>(null);
    const dropdownRef = useRef<HTMLDivElement>(null);

    // Initialize state when modal opens OR when data changes while open
    useEffect(() => {
        console.log('[T0Modal] useEffect triggered:', {
            isOpen,
            domains,
            assetCount: autoDetectedAssets.length,
            firstAsset: autoDetectedAssets[0]?.name
        });

        if (isOpen) {
            // Reset all UI state
            setSearchQuery('');
            setSearchResults([]);
            setShowDropdown(false);
            setFilterType('All');
            setConfirmModalOpen(false);
            setAssetToRemove(null);

            // Initialize with current auto-detected assets
            const initialAssets = autoDetectedAssets.map(a => ({
                ...a,
                source: 'auto' as const
            }));
            setT0Assets(initialAssets);

            // Set active domain to first domain that has assets
            const domainsWithAssets = domains.filter(d => initialAssets.some(a => a.domain === d));
            setActiveDomain(domainsWithAssets[0] || domains[0] || '');

            console.log('[T0Modal] Initialized with', initialAssets.length, 'assets, domains with assets:', domainsWithAssets);
        }
    }, [isOpen, autoDetectedAssets, domains]); // Include all dependencies

    // Filter assets by active domain
    const domainAssets = useMemo(() => {
        return t0Assets.filter(a => a.domain === activeDomain);
    }, [t0Assets, activeDomain]);

    // Filter assets by type
    const filteredAssets = useMemo(() => {
        if (filterType === 'All') return domainAssets;
        return domainAssets.filter(a => a.type === filterType);
    }, [domainAssets, filterType]);

    // Counts per type for filter tabs
    const typeCounts = useMemo(() => {
        return {
            All: domainAssets.length,
            Group: domainAssets.filter(a => a.type === 'Group').length,
            User: domainAssets.filter(a => a.type === 'User').length,
            Computer: domainAssets.filter(a => a.type === 'Computer').length,
        };
    }, [domainAssets]);

    // Stats
    const selectedCount = filteredAssets.length;
    const totalCount = domainAssets.length;

    // Show toast notification
    const showToast = useCallback((message: string) => {
        setToast({ message, visible: true });
        setTimeout(() => {
            setToast(prev => ({ ...prev, visible: false }));
        }, 3000);
    }, []);

    // Search BloodHound data
    const searchBloodHoundData = useCallback(async (query: string, type: string) => {
        if (!query || query.length < 1 || !window.neo4j) {
            setSearchResults([]);
            return;
        }

        setIsSearching(true);
        try {
            let cypherQuery = '';
            const upperQuery = query.toUpperCase();

            switch (type) {
                case 'Group':
                    cypherQuery = `
                        MATCH (g:Group)
                        WHERE toUpper(g.name) CONTAINS $query
                        RETURN g.name AS name, labels(g) AS labels
                        LIMIT 10
                    `;
                    break;
                case 'User':
                    cypherQuery = `
                        MATCH (u:User)
                        WHERE toUpper(u.name) CONTAINS $query
                        RETURN u.name AS name, labels(u) AS labels
                        LIMIT 10
                    `;
                    break;
                case 'Computer':
                    cypherQuery = `
                        MATCH (c:Computer)
                        WHERE toUpper(c.name) CONTAINS $query
                        RETURN c.name AS name, labels(c) AS labels
                        LIMIT 10
                    `;
                    break;
            }

            const result = await window.neo4j.runQuery(cypherQuery, { query: upperQuery });

            if (result.success && result.records) {
                const results: SearchResult[] = result.records.map((record: any) => {
                    const name = record.name || record._fields?.[0];
                    return {
                        name: name,
                        type: type as 'User' | 'Group' | 'Computer',
                        desc: getAssetDescription(name, type)
                    };
                });
                setSearchResults(results);
            } else {
                setSearchResults([]);
            }
        } catch (error) {
            console.error('[T0Modal] Search error:', error);
            setSearchResults([]);
        } finally {
            setIsSearching(false);
        }
    }, []);

    // Debounced search
    useEffect(() => {
        if (!searchQuery) {
            setSearchResults([]);
            setShowDropdown(false);
            return;
        }

        const timer = setTimeout(() => {
            searchBloodHoundData(searchQuery, searchType);
            setShowDropdown(true);
        }, 300);

        return () => clearTimeout(timer);
    }, [searchQuery, searchType, searchBloodHoundData]);

    // Get description based on asset name
    const getAssetDescription = (name: string, type: string): string => {
        const upperName = name.toUpperCase();
        if (type === 'Group') {
            if (upperName.includes('DOMAIN ADMINS')) return 'Domain Admins group';
            if (upperName.includes('ENTERPRISE ADMINS')) return 'Enterprise Admins group';
            if (upperName.includes('SCHEMA ADMINS')) return 'Schema Admins group';
            if (upperName.includes('ADMINISTRATORS')) return 'Built-in Administrators';
            if (upperName.includes('ACCOUNT OPERATORS')) return 'Account Operators group';
            if (upperName.includes('BACKUP OPERATORS')) return 'Backup Operators group';
            if (upperName.includes('SERVER OPERATORS')) return 'Server Operators group';
            if (upperName.includes('PRINT OPERATORS')) return 'Print Operators group';
            return 'Group';
        }
        if (type === 'User') {
            if (upperName.includes('KRBTGT')) return 'KRBTGT account (Kerberos service)';
            if (upperName.includes('ADMINISTRATOR')) return 'Built-in Administrator';
            return 'User account';
        }
        if (type === 'Computer') {
            if (upperName.includes('DC')) return 'Domain Controller';
            return 'Computer';
        }
        return '';
    };

    // Filter search results to exclude already added assets
    const filteredResults = useMemo(() => {
        const existingNames = new Set(t0Assets.map(a => a.name.toUpperCase()));
        return searchResults.filter(r => !existingNames.has(r.name.toUpperCase()));
    }, [searchResults, t0Assets]);

    // Add asset from search
    const handleAddAsset = (result: SearchResult) => {
        const domain = result.name.split('@')[1] || activeDomain;

        const newAsset: Tier0Asset = {
            name: result.name,
            type: result.type,
            domain: domain,
            autoDetected: false,
            reason: 'Manually added',
            source: 'user'
        };

        setT0Assets(prev => [newAsset, ...prev]);
        setSearchQuery('');
        setShowDropdown(false);
        showToast(`Added ${result.name.split('@')[0]} to T0`);
    };

    // Handle clicking on an asset row
    const handleAssetClick = (asset: Tier0Asset) => {
        // Show confirmation before removing
        setAssetToRemove(asset);
        setConfirmModalOpen(true);
    };

    // Confirm removal
    const handleConfirmRemove = () => {
        if (assetToRemove) {
            setT0Assets(prev => prev.filter(a =>
                a.name !== assetToRemove.name || a.domain !== assetToRemove.domain
            ));
            showToast(`Removed ${assetToRemove.name.split('@')[0]} from T0`);
        }
        setAssetToRemove(null);
        setConfirmModalOpen(false);
    };

    // Cancel removal
    const handleCancelRemove = () => {
        setAssetToRemove(null);
        setConfirmModalOpen(false);
    };

    // Select/Deselect all
    const handleSelectAll = () => {
        // Re-add auto-detected assets that might have been removed
        const domainAutoAssets = autoDetectedAssets.filter(a => a.domain === activeDomain);
        const existingNames = new Set(t0Assets.map(a => a.name));
        const newAssets = domainAutoAssets
            .filter(a => !existingNames.has(a.name))
            .map(a => ({ ...a, source: 'auto' as const }));

        if (newAssets.length > 0) {
            setT0Assets(prev => [...prev, ...newAssets]);
        }
    };

    const handleDeselectAll = () => {
        if (confirm('Remove all assets from Tier 0 for this domain? This will cause all paths to appear as actionable findings.')) {
            setT0Assets(prev => prev.filter(a => a.domain !== activeDomain));
        }
    };

    // State for save in progress
    const [isSaving, setIsSaving] = useState(false);

    // Expand group membership - query Neo4j for members of T0 groups
    const expandGroupMembership = async (assets: Tier0Asset[]): Promise<Tier0Asset[]> => {
        if (!window.neo4j) return assets;

        const expandedAssets = [...assets];
        const existingNames = new Set(assets.map(a => a.name.toUpperCase()));

        // Get all groups from the asset list
        const groups = assets.filter(a => a.type === 'Group');

        console.log(`[T0Modal] Expanding membership for ${groups.length} groups...`);

        for (const group of groups) {
            try {
                // Query for direct members of this group
                const query = `
                    MATCH (m)-[:MemberOf*1..]->(g:Group {name: $groupName})
                    WHERE m:User OR m:Computer
                    RETURN DISTINCT m.name AS name, labels(m) AS labels
                `;

                const result = await window.neo4j.runQuery(query, { groupName: group.name });

                if (result.success && result.records) {
                    for (const record of result.records) {
                        const memberName = record.name || record._fields?.[0];
                        if (!memberName) continue;

                        const memberUpper = memberName.toUpperCase();
                        if (existingNames.has(memberUpper)) continue;

                        // Determine type from labels
                        const labels = record.labels || record._fields?.[1] || [];
                        const isUser = labels.includes('User');
                        const isComputer = labels.includes('Computer');
                        const memberType = isUser ? 'User' : isComputer ? 'Computer' : 'User';

                        // Extract domain from member name
                        const memberDomain = memberName.split('@')[1] || group.domain;

                        expandedAssets.push({
                            name: memberName,
                            type: memberType as 'User' | 'Group' | 'Computer',
                            domain: memberDomain,
                            autoDetected: false,
                            reason: `Member of ${group.name.split('@')[0]}`,
                            source: 'auto'
                        });

                        existingNames.add(memberUpper);
                    }
                }
            } catch (error) {
                console.error(`[T0Modal] Error expanding group ${group.name}:`, error);
            }
        }

        console.log(`[T0Modal] Expanded from ${assets.length} to ${expandedAssets.length} assets`);
        return expandedAssets;
    };

    // Save configuration with group membership expansion
    const handleSave = async () => {
        setIsSaving(true);
        showToast('Expanding group membership...');

        try {
            // Expand group membership before saving
            const expandedAssets = await expandGroupMembership(t0Assets);

            const config: Tier0Config = {
                domains: {},
                enabled: true,
                skipped: false
            };

            // Group assets by domain
            const domainSet = new Set([...domains, ...expandedAssets.map(a => a.domain)]);
            domainSet.forEach(domain => {
                config.domains[domain] = {
                    assets: expandedAssets.filter(a => a.domain === domain),
                    excludedMembers: []
                };
            });

            console.log(`[T0Modal] Saving config with ${expandedAssets.length} total assets (including group members)`);
            onSave(config);
            showToast(`Configuration saved (${expandedAssets.length} assets including group members)`);
        } catch (error) {
            console.error('[T0Modal] Error saving config:', error);
            showToast('Error saving configuration');
        } finally {
            setIsSaving(false);
        }
    };

    // Close dropdown on outside click
    useEffect(() => {
        const handleClickOutside = (e: MouseEvent) => {
            if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
                setShowDropdown(false);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    // Handle escape key
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape') {
                if (confirmModalOpen) {
                    handleCancelRemove();
                } else if (isOpen) {
                    onClose();
                }
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [isOpen, confirmModalOpen, onClose]);

    // Highlight matching text
    const highlightMatch = (text: string, query: string) => {
        if (!query) return text;
        const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
        const parts = text.split(regex);
        return parts.map((part, i) =>
            regex.test(part) ? (
                <mark key={i} className="bg-[#58a6ff]/30 text-[#58a6ff] rounded px-0.5">{part}</mark>
            ) : part
        );
    };

    // Get icon for asset type
    const getTypeIcon = (type: string) => {
        switch (type) {
            case 'Group':
                return (
                    <svg className="w-4 h-4 text-[#fbbf24]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                    </svg>
                );
            case 'User':
                return (
                    <svg className="w-4 h-4 text-[#7ee787]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                    </svg>
                );
            case 'Computer':
                return (
                    <svg className="w-4 h-4 text-[#58a6ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                    </svg>
                );
            default:
                return null;
        }
    };

    // Get type badge color
    const getTypeBadgeClass = (type: string) => {
        switch (type) {
            case 'Group':
                return 'bg-[#fbbf24]/15 text-[#fbbf24]';
            case 'User':
                return 'bg-[#7ee787]/15 text-[#7ee787]';
            case 'Computer':
                return 'bg-[#58a6ff]/15 text-[#58a6ff]';
            default:
                return 'bg-gray-500/15 text-gray-400';
        }
    };

    if (!isOpen) return null;

    return (
        <>
            {/* Modal Overlay */}
            <div
                className="fixed inset-0 z-50 flex items-center justify-center p-5"
                style={{ background: 'rgba(1, 4, 9, 0.85)' }}
                onClick={onClose}
            >
                {/* Modal */}
                <div
                    className="w-full max-w-[560px] max-h-[85vh] bg-[#0d1117] border border-[#30363d] rounded-2xl flex flex-col overflow-hidden"
                    onClick={e => e.stopPropagation()}
                >
                    {/* Header */}
                    <div className="flex items-center justify-between px-6 py-5 border-b border-[#30363d]">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 flex items-center justify-center bg-[#58a6ff]/10 border border-[#58a6ff]/20 rounded-lg">
                                <svg className="w-5 h-5 text-[#58a6ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                            </div>
                            <div>
                                <h2 className="text-lg font-semibold text-white">Configure Tier 0 Assets</h2>
                                <p className="text-[13px] text-[#8b949e] mt-0.5">Define privileged assets to reduce false positives</p>
                            </div>
                        </div>
                        <button
                            onClick={onClose}
                            className="w-8 h-8 flex items-center justify-center rounded-md text-[#8b949e] hover:text-[#c9d1d9] hover:bg-[#161b22] transition-colors"
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                            </svg>
                        </button>
                    </div>

                    {/* Info Banner */}
                    <div className="px-6 py-4 bg-[#58a6ff]/5 border-b border-[#30363d] text-[13px] text-[#8b949e] leading-relaxed">
                        <strong className="text-[#58a6ff]">Tier 0</strong> assets are legitimate high-privilege accounts (Domain Admins, Domain Controllers, etc.). Attack paths between T0 assets are classified as T0 lateral and are not counted as actionable findings in the report.
                    </div>

                    {/* Body */}
                    <div className="flex-1 overflow-y-auto px-6 py-4">
                        {isLoading ? (
                            <div className="flex items-center justify-center py-12">
                                <svg className="w-8 h-8 text-[#58a6ff] animate-spin" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                                </svg>
                                <span className="ml-3 text-[#8b949e]">Detecting privileged assets...</span>
                            </div>
                        ) : (
                            <>
                                {/* Search Section */}
                                <div className="mb-6 pb-6 border-b border-[#30363d]">
                                    <label className="block text-[13px] font-semibold text-white mb-3">
                                        Add T0 Asset
                                    </label>
                                    <div className="flex gap-2">
                                        <select
                                            value={searchType}
                                            onChange={(e) => {
                                                setSearchType(e.target.value as 'Group' | 'User' | 'Computer');
                                                setSearchQuery('');
                                                setSearchResults([]);
                                            }}
                                            className="w-[110px] px-3 py-2.5 bg-[#161b22] border border-[#30363d] rounded-lg text-[#c9d1d9] text-[13px] focus:outline-none focus:border-[#58a6ff] cursor-pointer appearance-none"
                                            style={{
                                                backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%238b949e'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'/%3E%3C/svg%3E")`,
                                                backgroundRepeat: 'no-repeat',
                                                backgroundPosition: 'right 0.5rem center',
                                                backgroundSize: '16px'
                                            }}
                                        >
                                            <option value="Group">Group</option>
                                            <option value="User">User</option>
                                            <option value="Computer">Computer</option>
                                        </select>

                                        <div className="flex-1 relative" ref={dropdownRef}>
                                            <input
                                                ref={searchInputRef}
                                                type="text"
                                                value={searchQuery}
                                                onChange={(e) => setSearchQuery(e.target.value)}
                                                onFocus={() => searchQuery && setShowDropdown(true)}
                                                placeholder={`Search ${searchType.toLowerCase()}s...`}
                                                className="w-full px-3 py-2.5 bg-[#161b22] border border-[#30363d] rounded-lg text-[#c9d1d9] text-[13px] placeholder-[#6e7681] focus:outline-none focus:border-[#58a6ff]"
                                                autoComplete="off"
                                            />

                                            {/* Autocomplete Dropdown */}
                                            {showDropdown && (
                                                <div className="absolute top-full left-0 right-0 bg-[#0d1117] border border-[#30363d] border-t-0 rounded-b-lg max-h-[200px] overflow-y-auto z-50">
                                                    {isSearching ? (
                                                        <div className="px-3 py-4 text-center text-[#8b949e] text-[13px]">
                                                            Searching...
                                                        </div>
                                                    ) : filteredResults.length > 0 ? (
                                                        filteredResults.map((result, idx) => (
                                                            <div
                                                                key={idx}
                                                                onClick={() => handleAddAsset(result)}
                                                                className="flex items-center gap-3 px-3 py-2.5 cursor-pointer hover:bg-[#161b22] transition-colors"
                                                            >
                                                                <div className={`w-6 h-6 flex items-center justify-center flex-shrink-0 ${result.type === 'Group' ? 'text-[#fbbf24]' :
                                                                        result.type === 'User' ? 'text-[#7ee787]' : 'text-[#58a6ff]'
                                                                    }`}>
                                                                    {getTypeIcon(result.type)}
                                                                </div>
                                                                <div className="flex-1 min-w-0">
                                                                    <div className="text-[13px] text-white truncate">
                                                                        {highlightMatch(result.name, searchQuery)}
                                                                    </div>
                                                                    {result.desc && (
                                                                        <div className="text-[11px] text-[#8b949e]">{result.desc}</div>
                                                                    )}
                                                                </div>
                                                            </div>
                                                        ))
                                                    ) : searchResults.length > 0 && filteredResults.length === 0 ? (
                                                        <div className="px-3 py-4 text-center text-[#8b949e] text-[13px]">
                                                            Already in T0 list
                                                        </div>
                                                    ) : searchQuery.length > 0 ? (
                                                        <div className="px-3 py-4 text-center text-[#8b949e] text-[13px]">
                                                            No matching assets in BloodHound data
                                                        </div>
                                                    ) : null}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>

                                {/* Domain Tabs - Only show domains with T0 assets */}
                                {(() => {
                                    const domainsWithAssets = domains.filter(d => t0Assets.some(a => a.domain === d));
                                    return domainsWithAssets.length > 1 && (
                                        <div className="mb-4">
                                            <label className="block text-[12px] font-medium text-[#8b949e] mb-2">Domain</label>
                                            <div className="flex flex-wrap gap-2">
                                                {domainsWithAssets.map((domain) => {
                                                    const domainAssetCount = t0Assets.filter(a => a.domain === domain).length;
                                                    return (
                                                        <button
                                                            key={domain}
                                                            onClick={() => setActiveDomain(domain)}
                                                            className={`px-3 py-1.5 rounded-lg text-[13px] font-medium transition-colors border ${activeDomain === domain
                                                                    ? 'bg-[#58a6ff]/10 border-[#58a6ff]/50 text-[#58a6ff]'
                                                                    : 'bg-[#161b22] border-[#30363d] text-[#8b949e] hover:border-[#8b949e]'
                                                                }`}
                                                        >
                                                            {domain}
                                                            <span className={`ml-1.5 text-[11px] ${activeDomain === domain ? 'text-[#58a6ff]/70' : 'text-[#6e7681]'
                                                                }`}>
                                                                ({domainAssetCount})
                                                            </span>
                                                        </button>
                                                    );
                                                })}
                                            </div>
                                        </div>
                                    );
                                })()}

                                {/* Filter Tabs */}
                                <div className="flex items-center gap-1 mb-4 p-1 bg-[#161b22] rounded-lg">
                                    {(['All', 'Group', 'User', 'Computer'] as const).map((type) => (
                                        <button
                                            key={type}
                                            onClick={() => setFilterType(type)}
                                            className={`flex-1 px-3 py-2 rounded-md text-[13px] font-medium transition-colors ${filterType === type
                                                    ? 'bg-[#21262d] text-white'
                                                    : 'text-[#8b949e] hover:text-[#c9d1d9]'
                                                }`}
                                        >
                                            {type}
                                            <span className={`ml-1.5 text-[11px] ${filterType === type ? 'text-[#8b949e]' : 'text-[#6e7681]'
                                                }`}>
                                                {typeCounts[type]}
                                            </span>
                                        </button>
                                    ))}
                                </div>

                                {/* Group Disclaimer */}
                                {filterType === 'Group' && typeCounts.Group > 0 && (
                                    <div className="flex items-start gap-2 mb-4 px-3 py-2.5 bg-[#fbbf24]/5 border border-[#fbbf24]/20 rounded-lg">
                                        <svg className="w-4 h-4 text-[#fbbf24] flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                        </svg>
                                        <p className="text-[12px] text-[#c9d1d9] leading-relaxed">
                                            All members within these groups will be classified as T0 assets.
                                        </p>
                                    </div>
                                )}

                                {/* List Header */}
                                <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#30363d]">
                                    <div className="text-[13px] text-[#8b949e]">
                                        <strong className="text-white">{selectedCount}</strong>{filterType !== 'All' ? ` ${filterType.toLowerCase()}s` : ''} of <span>{totalCount}</span> total in {activeDomain}
                                    </div>
                                    <div className="flex gap-2">
                                        <button
                                            onClick={handleSelectAll}
                                            className="px-2 py-1 text-[12px] font-medium text-[#58a6ff] hover:bg-[#58a6ff]/10 rounded transition-colors"
                                        >
                                            Select All
                                        </button>
                                        <button
                                            onClick={handleDeselectAll}
                                            className="px-2 py-1 text-[12px] font-medium text-[#8b949e] hover:bg-[#161b22] rounded transition-colors"
                                        >
                                            Deselect All
                                        </button>
                                    </div>
                                </div>

                                {/* Asset List */}
                                <div className="space-y-0">
                                    {filteredAssets.length === 0 ? (
                                        <div className="text-center py-8 text-[#6e7681] text-sm">
                                            {domainAssets.length === 0
                                                ? `No T0 assets in ${activeDomain}. Use the search above to add assets.`
                                                : `No ${filterType.toLowerCase()}s in T0 list.`
                                            }
                                        </div>
                                    ) : (
                                        filteredAssets.map((asset, idx) => (
                                            <div
                                                key={`${asset.domain}:${asset.type}:${asset.name}`}
                                                onClick={() => handleAssetClick(asset)}
                                                className={`flex items-center gap-3 py-3.5 border-b border-[#30363d] cursor-pointer hover:bg-[#161b22] hover:-mx-4 hover:px-4 transition-all ${asset.source === 'user' ? 'bg-[#58a6ff]/5' : ''
                                                    } ${idx === filteredAssets.length - 1 ? 'border-b-0' : ''}`}
                                            >
                                                {/* Checkbox (always checked since it's in the list) */}
                                                <div className="w-[18px] h-[18px] bg-[#58a6ff] border-2 border-[#58a6ff] rounded flex items-center justify-center flex-shrink-0">
                                                    <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                                                    </svg>
                                                </div>

                                                {/* Type Icon */}
                                                <div className="w-8 h-8 flex items-center justify-center flex-shrink-0">
                                                    {getTypeIcon(asset.type)}
                                                </div>

                                                {/* Asset Info */}
                                                <div className="flex-1 min-w-0">
                                                    <div className="text-[14px] font-medium text-white truncate flex items-center gap-2">
                                                        {asset.name}
                                                        {asset.source === 'user' && (
                                                            <span className="text-[10px] text-[#58a6ff]">Added</span>
                                                        )}
                                                    </div>
                                                    {asset.reason && (
                                                        <div className="text-[12px] text-[#8b949e] mt-0.5">{asset.reason}</div>
                                                    )}
                                                </div>

                                                {/* Type Badge */}
                                                <span className={`px-2 py-0.5 rounded text-[11px] font-semibold uppercase tracking-wide flex-shrink-0 ${getTypeBadgeClass(asset.type)}`}>
                                                    {asset.type}
                                                </span>
                                            </div>
                                        ))
                                    )}
                                </div>
                            </>
                        )}
                    </div>

                    {/* Footer */}
                    <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#30363d] bg-[#161b22]">
                        <button
                            onClick={onClose}
                            className="px-5 py-2.5 bg-[#21262d] border border-[#30363d] rounded-lg text-[#c9d1d9] text-[14px] font-medium hover:border-[#8b949e] transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={handleSave}
                            disabled={isLoading || isSaving}
                            className="px-5 py-2.5 bg-[#1f6feb] hover:bg-[#388bfd] rounded-lg text-white text-[14px] font-medium transition-colors flex items-center gap-2 disabled:opacity-50"
                        >
                            {isSaving ? (
                                <>
                                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                                    </svg>
                                    Expanding Groups...
                                </>
                            ) : (
                                <>
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                    </svg>
                                    Save Configuration
                                </>
                            )}
                        </button>
                    </div>
                </div>
            </div>

            {/* Confirmation Modal */}
            {confirmModalOpen && assetToRemove && (
                <div
                    className="fixed inset-0 z-[60] flex items-center justify-center p-5"
                    style={{ background: 'rgba(1, 4, 9, 0.9)' }}
                >
                    <div className="bg-[#0d1117] border border-[#30363d] rounded-xl p-6 w-full max-w-[400px] text-center">
                        <div className="w-12 h-12 mx-auto mb-4 flex items-center justify-center bg-[#fbbf24]/10 rounded-full">
                            <svg className="w-6 h-6 text-[#fbbf24]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                            </svg>
                        </div>
                        <h3 className="text-lg font-semibold text-white mb-3">Remove from Tier 0?</h3>
                        <p className="text-[14px] text-[#8b949e] leading-relaxed mb-6">
                            <strong className="text-white font-medium">{assetToRemove.name}</strong> will no longer be classified as a Tier 0 asset. Attack paths involving this account will appear as actionable findings.
                        </p>
                        <div className="flex gap-3">
                            <button
                                onClick={handleCancelRemove}
                                className="flex-1 px-4 py-2.5 bg-[#161b22] border border-[#30363d] rounded-lg text-[#c9d1d9] text-[14px] font-medium hover:bg-[#21262d] transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleConfirmRemove}
                                className="flex-1 px-4 py-2.5 bg-[#f85149] hover:bg-[#dc2626] rounded-lg text-white text-[14px] font-medium transition-colors"
                            >
                                Remove from T0
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Toast Notification */}
            <div
                className={`fixed bottom-6 left-1/2 -translate-x-1/2 z-[70] bg-[#161b22] border border-[#30363d] rounded-lg px-5 py-3 flex items-center gap-2 transition-all duration-300 ${toast.visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-[100px]'
                    }`}
            >
                <svg className="w-5 h-5 text-[#7ee787]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                <span className="text-[14px] text-[#c9d1d9]">{toast.message}</span>
            </div>
        </>
    );
};

export default Tier0ConfigModal;

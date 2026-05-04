/**
 * Section Header Component
 * Location: src/components/attack-components/SectionHeader.tsx
 */

import React from 'react';

interface SectionHeaderProps {
    title: string;
    subtitle: string;
    icon: React.ReactNode;
    titleColor?: string;
}

const SectionHeader: React.FC<SectionHeaderProps> = ({ title, subtitle, icon, titleColor }) => (
    <div className="mb-8 pb-4 border-b-2 border-aegis-border">
        <div className="flex items-center gap-3 mb-2">
            <div className="text-aegis-accent">{icon}</div>
            <h2 className={`text-2xl font-bold ${titleColor || 'text-white'}`}>{title}</h2>
        </div>
        <p className="text-aegis-text-muted">{subtitle}</p>
    </div>
);

export default SectionHeader;

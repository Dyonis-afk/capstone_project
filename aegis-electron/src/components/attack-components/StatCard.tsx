/**
 * Stat Card Component
 * Location: src/components/attack-components/StatCard.tsx
 */

import React from 'react';
import { StatCardColor } from './types';

interface StatCardProps {
    label: string;
    value: number | string;
    color: StatCardColor;
}

const StatCard: React.FC<StatCardProps> = ({ label, value, color }) => {
    const colorClass = {
        red: 'text-red-400',
        yellow: 'text-yellow-400',
        green: 'text-green-400',
        blue: 'text-aegis-accent',
        purple: 'text-purple-400'
    }[color];

    return (
        <div className="bg-aegis-gray border border-aegis-border rounded-lg p-4 text-center">
            <div className={`text-2xl font-bold ${colorClass}`}>{value}</div>
            <div className="text-sm text-aegis-text-muted">{label}</div>
        </div>
    );
};

export default StatCard;

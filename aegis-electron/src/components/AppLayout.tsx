/**
 * AppLayout - Shared layout with fixed sidebar
 * Location: src/components/AppLayout.tsx
 * 
 * This component wraps all routes and provides:
 * - A SINGLE sidebar instance that persists across route changes
 * - Seamless content switching (sidebar doesn't re-render)
 * - Sidebar shows icon rail when collapsed (hamburger is IN the sidebar)
 * 
 */

import React, { useState } from 'react';
import Sidebar from './Sidebar';

interface AppLayoutProps {
    children: React.ReactNode;
}

const AppLayout: React.FC<AppLayoutProps> = ({ children }) => {
    const [sidebarOpen, setSidebarOpen] = useState(true);

    return (
        <div className="h-screen bg-aegis-darker text-white flex flex-col overflow-hidden">
            {/* macOS drag region - allows window to be moved */}
            <div
                className="w-full h-8 shrink-0 bg-aegis-darker z-50"
                style={{ WebkitAppRegion: 'drag' } as React.CSSProperties}
            />

            <div className="flex-1 flex overflow-hidden">
                {/* Fixed Sidebar - persists across all routes */}
                {/* Shows full width when open, icon rail when collapsed */}
                <Sidebar
                    isOpen={sidebarOpen}
                    onToggle={() => setSidebarOpen(!sidebarOpen)}
                />

                {/* Main Content Area */}
                <div className="flex-1 flex flex-col overflow-hidden">
                    {/* Content - swaps seamlessly based on route */}
                    <main className="flex-1 overflow-y-auto overflow-x-hidden relative">
                        {children}
                    </main>
                </div>
            </div>
        </div>
    );
};

export default AppLayout;
/**
 * Sidebar - Collapsible sidebar with icon rail when collapsed
 * Location: src/components/Sidebar.tsx
 *
 * Features:
 * - Expanded: Full sidebar with project list and search
 * - Collapsed: Icon rail with key actions (expand, new, search)
 * - Search modal accessible via button or ⌘K
 * - Project context menu with rename/delete options
 */

import React, { useEffect, useState, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Tooltip } from 'react-tooltip';
import { useLottie } from 'lottie-react';
import folderAnimation from '../assets/folder-hover-pinch.json';
import { useProjectStore } from '../stores/projectStore';
import { useIsInfrastructureDown, useNeo4jMode } from '../stores/connectionStore';
import { useReportJobStore, useIsReportJobRunning, useReportJobProgress } from '../stores/reportJobStore';
import SearchProjectsModal from './SearchprojectModal';

// ============ RENAME MODAL ============
const RenameModal: React.FC<{
    isOpen: boolean;
    projectName: string;
    onClose: () => void;
    onRename: (newName: string) => void;
}> = ({ isOpen, projectName, onClose, onRename }) => {
    const [value, setValue] = useState(projectName);
    const inputRef = useRef<HTMLInputElement>(null);

    useEffect(() => {
        if (isOpen) {
            setValue(projectName);
            setTimeout(() => inputRef.current?.select(), 50);
        }
    }, [isOpen, projectName]);

    if (!isOpen) return null;

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (value.trim()) {
            onRename(value.trim());
            onClose();
        }
    };

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center"
            style={{ background: 'rgba(0, 0, 0, 0.6)', backdropFilter: 'blur(4px)' }}
            onClick={onClose}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                className="w-[400px] bg-aegis-dark border border-aegis-border rounded-xl shadow-2xl overflow-hidden"
            >
                {/* Header */}
                <div className="px-5 py-4 border-b border-aegis-border flex items-center justify-between">
                    <h2 className="text-base font-semibold text-aegis-text">Rename Project</h2>
                    <button
                        onClick={onClose}
                        className="w-7 h-7 rounded-md flex items-center justify-center text-aegis-text-muted hover:bg-aegis-gray-light transition-colors"
                    >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {/* Content */}
                <form onSubmit={handleSubmit}>
                    <div className="p-5">
                        <label className="block text-[13px] font-medium text-aegis-text-muted mb-2">
                            Project name
                        </label>
                        <input
                            ref={inputRef}
                            type="text"
                            value={value}
                            onChange={(e) => setValue(e.target.value)}
                            className="w-full px-3 py-2.5 bg-aegis-darker border border-aegis-border rounded-lg text-aegis-text text-sm outline-none focus:border-aegis-accent transition-colors"
                        />
                    </div>

                    {/* Footer */}
                    <div className="px-5 py-4 border-t border-aegis-border bg-aegis-darker flex justify-end gap-2.5">
                        <button
                            type="button"
                            onClick={onClose}
                            className="px-4 py-2.5 rounded-lg border border-aegis-border text-aegis-text text-[13px] font-medium hover:bg-aegis-gray-light transition-colors"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={!value.trim()}
                            className={`px-4 py-2.5 rounded-lg text-[13px] font-medium transition-colors ${value.trim()
                                ? 'bg-emerald-600 hover:bg-emerald-700 text-white cursor-pointer'
                                : 'bg-aegis-gray text-aegis-text-subtle cursor-not-allowed'
                                }`}
                        >
                            Save
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

// ============ DELETE MODAL ============
const DeleteModal: React.FC<{
    isOpen: boolean;
    projectName: string;
    onClose: () => void;
    onDelete: () => void;
}> = ({ isOpen, projectName, onClose, onDelete }) => {
    if (!isOpen) return null;

    return (
        <div
            className="fixed inset-0 z-50 flex items-center justify-center"
            style={{ background: 'rgba(0, 0, 0, 0.6)', backdropFilter: 'blur(4px)' }}
            onClick={onClose}
        >
            <div
                onClick={(e) => e.stopPropagation()}
                className="w-[400px] bg-aegis-dark border border-aegis-border rounded-xl shadow-2xl overflow-hidden"
            >
                {/* Header */}
                <div className="px-5 py-4 border-b border-aegis-border flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-red-500/15 flex items-center justify-center">
                            <svg className="w-4 h-4 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                            </svg>
                        </div>
                        <h2 className="text-base font-semibold text-aegis-text">Delete Project</h2>
                    </div>
                    <button
                        onClick={onClose}
                        className="w-7 h-7 rounded-md flex items-center justify-center text-aegis-text-muted hover:bg-aegis-gray-light transition-colors"
                    >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {/* Content */}
                <div className="p-5">
                    <p className="text-sm text-aegis-text-muted leading-relaxed">
                        Are you sure you want to delete <span className="text-aegis-text font-medium">"{projectName}"</span>?
                        This action cannot be undone and all associated data will be permanently removed.
                    </p>
                </div>

                {/* Footer */}
                <div className="px-5 py-4 border-t border-aegis-border bg-aegis-darker flex justify-end gap-2.5">
                    <button
                        onClick={onClose}
                        className="px-4 py-2.5 rounded-lg border border-aegis-border text-aegis-text text-[13px] font-medium hover:bg-aegis-gray-light transition-colors"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={() => {
                            onDelete();
                            onClose();
                        }}
                        className="px-4 py-2.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-[13px] font-medium transition-colors"
                    >
                        Delete
                    </button>
                </div>
            </div>
        </div>
    );
};

// ============ DROPDOWN MENU ============
const DropdownMenu: React.FC<{
    isOpen: boolean;
    onClose: () => void;
    onRename: () => void;
    onDelete: () => void;
}> = ({ isOpen, onClose, onRename, onDelete }) => {
    const menuRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleClickOutside = (e: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
                onClose();
            }
        };
        if (isOpen) {
            document.addEventListener('mousedown', handleClickOutside);
        }
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [isOpen, onClose]);

    if (!isOpen) return null;

    return (
        <div
            ref={menuRef}
            className="absolute top-full right-0 mt-1 w-40 bg-aegis-dark border border-aegis-border rounded-lg shadow-xl overflow-hidden z-50"
        >
            <button
                onClick={(e) => {
                    e.stopPropagation();
                    onRename();
                    onClose();
                }}
                className="w-full px-3.5 py-2.5 flex items-center gap-2.5 text-aegis-text text-[13px] hover:bg-aegis-gray-light transition-colors text-left"
            >
                <svg className="w-4 h-4 text-aegis-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
                Rename
            </button>

            <div className="h-px bg-aegis-border mx-2" />

            <button
                onClick={(e) => {
                    e.stopPropagation();
                    onDelete();
                    onClose();
                }}
                className="w-full px-3.5 py-2.5 flex items-center gap-2.5 text-red-500 text-[13px] hover:bg-red-500/10 transition-colors text-left"
            >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
                Delete
            </button>
        </div>
    );
};

// ============ PROJECT LIST ITEM ============
interface ProjectListItemProps {
    project: {
        id: string;
        name: string;
        neo4j_database?: string;
        created_at: string;
    };
    isSelected: boolean;
    isActiveProject: boolean;
    globalIsUploading: boolean;
    isThisProjectUploading: boolean;
    isInfrastructureDown: boolean;
    neo4jMode: 'docker' | 'custom';
    formatDate: (date: string) => string;
    onSelect: () => void;
    onRename: (newName: string) => void;
    onDelete: () => void;
}

const ProjectListItem: React.FC<ProjectListItemProps> = ({
    project,
    isSelected,
    isActiveProject,
    globalIsUploading,
    isThisProjectUploading,
    isInfrastructureDown,
    neo4jMode,
    formatDate,
    onSelect,
    onRename,
    onDelete,
}) => {
    const [isHovered, setIsHovered] = useState(false);
    const [showDropdown, setShowDropdown] = useState(false);
    const [showRenameModal, setShowRenameModal] = useState(false);
    const [showDeleteModal, setShowDeleteModal] = useState(false);

    // Status logic: Stopped/Active/Inactive with upload state
    const getStatusInfo = () => {
        // Show stopped if Docker or Neo4j is down
        if (isInfrastructureDown) {
            return { text: 'Stopped', color: 'text-red-500', dotColor: 'bg-red-500' };
        }
        // Show uploading state for this project
        if (isThisProjectUploading) {
            return { text: 'Uploading', color: 'text-aegis-accent', dotColor: 'bg-aegis-accent animate-pulse' };
        }
        // Active = this project's data is loaded in BloodHound CE (show mode context)
        if (isActiveProject && !globalIsUploading) {
            const modeLabel = neo4jMode === 'docker' ? 'Docker' : 'Custom';
            return { text: `Active (${modeLabel})`, color: 'text-emerald-500', dotColor: 'bg-emerald-500' };
        }
        // Inactive = data not loaded
        return { text: 'Inactive', color: 'text-amber-500', dotColor: 'bg-amber-500' };
    };

    const status = getStatusInfo();

    return (
        <>
            <div
                onMouseEnter={() => setIsHovered(true)}
                onMouseLeave={() => {
                    setIsHovered(false);
                    if (!showDropdown) setShowDropdown(false);
                }}
                onClick={onSelect}
                className={`relative group flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors duration-150 ${globalIsUploading
                    ? 'cursor-not-allowed opacity-60'
                    : 'cursor-pointer'
                    } ${isSelected
                        ? 'border border-aegis-accent/30 bg-aegis-accent/5'
                        : globalIsUploading
                            ? 'border border-transparent'
                            : 'hover:bg-aegis-gray-light border border-transparent'
                    }`}
            >
                {/* Folder Icon */}
                <div className={`shrink-0 ${isSelected ? 'text-aegis-accent' : isActiveProject ? 'text-aegis-accent' : 'text-aegis-text-muted'}`}>
                    <svg className="w-[18px] h-[18px]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                    </svg>
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                    <p className={`text-[13px] font-medium truncate ${isSelected ? 'text-aegis-accent' : 'text-aegis-text'}`}>
                        {project.name}
                    </p>
                    <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-[11px] text-aegis-text-subtle">
                            {formatDate(project.created_at)}
                        </span>
                        {/* Status indicator */}
                        <span className={`inline-flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide ${status.color}`}>
                            <span className={`w-1.5 h-1.5 rounded-full ${status.dotColor}`} />
                            {status.text}
                        </span>
                    </div>
                </div>

                {/* More Button (3 dots) */}
                <button
                    onClick={(e) => {
                        e.stopPropagation();
                        setShowDropdown(!showDropdown);
                    }}
                    className={`shrink-0 w-7 h-7 rounded-md flex items-center justify-center transition-all ${showDropdown ? 'bg-aegis-gray-light' : 'bg-transparent'
                        } ${globalIsUploading ? 'hidden' : (isHovered || showDropdown) ? 'opacity-100' : 'opacity-0'
                        } text-aegis-text-muted hover:text-aegis-text hover:bg-aegis-gray-light`}
                    disabled={globalIsUploading}
                >
                    <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                        <circle cx="12" cy="6" r="2" />
                        <circle cx="12" cy="12" r="2" />
                        <circle cx="12" cy="18" r="2" />
                    </svg>
                </button>

                {/* Dropdown Menu */}
                <DropdownMenu
                    isOpen={showDropdown}
                    onClose={() => setShowDropdown(false)}
                    onRename={() => setShowRenameModal(true)}
                    onDelete={() => setShowDeleteModal(true)}
                />
            </div>

            {/* Modals */}
            <RenameModal
                isOpen={showRenameModal}
                projectName={project.name}
                onClose={() => setShowRenameModal(false)}
                onRename={onRename}
            />
            <DeleteModal
                isOpen={showDeleteModal}
                projectName={project.name}
                onClose={() => setShowDeleteModal(false)}
                onDelete={onDelete}
            />
        </>
    );
};

interface SidebarProps {
    isOpen: boolean;
    onToggle: () => void;
}

// Animated Folder Icon Component
const AnimatedFolderIcon: React.FC<{
    size?: number;
    className?: string;
    isSelected?: boolean;
    isCollapsed?: boolean;
}> = ({ size = 20, className = '', isSelected = false, isCollapsed = false }) => {
    const { View, play, stop } = useLottie({
        animationData: folderAnimation,
        loop: false,
        autoplay: false,
    });

    // Apply color filter based on selection and sidebar state
    // When selected in expanded: blue (#58a6ff - aegis-accent)
    // When selected in collapsed: white
    // When not selected: grey (text-aegis-text-muted)
    const filterStyle = isSelected
        ? isCollapsed
            ? {
                // White for collapsed selected state
                filter: 'brightness(0) saturate(100%) invert(100%)',
            }
            : {
                // Blue (#58a6ff) for expanded selected state - matches aegis-accent
                filter: 'brightness(0) saturate(100%) invert(70%) sepia(100%) saturate(3000%) hue-rotate(195deg) brightness(1.15) contrast(1.1)',
            }
        : {
            // Grey for not selected
            filter: 'brightness(0) saturate(100%) invert(45%) sepia(0%) saturate(0%) hue-rotate(0deg) brightness(120%) contrast(100%)',
            opacity: 0.7
        };

    return (
        <div
            className={className}
            onMouseEnter={play}
            onMouseLeave={stop}
            style={{
                width: size,
                height: size,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                ...filterStyle
            }}
        >
            {View}
        </div>
    );
};

const Sidebar: React.FC<SidebarProps> = ({ isOpen, onToggle }) => {
    const navigate = useNavigate();
    const location = useLocation();

    // Search modal state
    const [isSearchOpen, setIsSearchOpen] = useState(false);

    // Zustand store for projects
    const {
        projects,
        currentProject,
        setCurrentProject,
        loadProjects,
        isLoading,
        isUploading: globalIsUploading,
        activeProjectId
    } = useProjectStore();

    // Infrastructure is down status (mode-aware: checks Docker in Docker mode, custom Neo4j in Custom mode)
    const isInfrastructureDown = useIsInfrastructureDown();

    // Current Neo4j mode (Docker or Custom)
    const neo4jMode = useNeo4jMode();

    // Report generation status
    const isReportGenerating = useIsReportJobRunning();
    const reportProgress = useReportJobProgress();
    const reportFileName = useReportJobStore(s => s.fileName);

    // Load projects on mount
    useEffect(() => {
        loadProjects();
    }, [loadProjects]);

    // Keyboard shortcut for search (Cmd+K / Ctrl+K)
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                e.preventDefault();
                setIsSearchOpen(true);
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, []);

    // Click project → select it and open its conversation
    const handleSelectProject = (project: typeof currentProject) => {
        if (!project) return;
        setCurrentProject(project);
        navigate(`/chat/${project.id}`);
    };

    const handleDeleteProject = async (projectId: string) => {
        try {
            const result = await window.database.deleteProject(projectId);
            if (result.success) {
                await loadProjects();
                // Clear currentProject if it was the deleted one
                if (currentProject?.id === projectId) {
                    setCurrentProject(null);
                    navigate('/');
                }
                // Clear activeProjectId if the deleted project was active
                if (activeProjectId === projectId) {
                    useProjectStore.getState().setActiveProjectId(null);
                }
            }
        } catch (err) {
            console.error('Failed to delete project:', err);
        }
    };

    const handleRenameProject = async (projectId: string, newName: string) => {
        try {
            const result = await window.database.updateProject(projectId, { name: newName });
            if (result.success) {
                await loadProjects();
            }
        } catch (err) {
            console.error('Failed to rename project:', err);
        }
    };

    const formatDate = (dateString: string) => {
        const date = new Date(dateString);
        const now = new Date();
        const diff = now.getTime() - date.getTime();
        const days = Math.floor(diff / (1000 * 60 * 60 * 24));

        if (days === 0) return 'Today';
        if (days === 1) return 'Yesterday';
        if (days < 7) return `${days}d ago`;
        return date.toLocaleDateString();
    };

    return (
        <>
            {/* Sidebar Container - switches between expanded and collapsed */}
            <aside className={`
                h-full bg-aegis-dark border-r border-aegis-border
                transition-all duration-300 ease-in-out
                flex flex-col overflow-hidden shrink-0
                ${isOpen ? 'w-72' : 'w-16'}
            `}>
                {isOpen ? (
                    /* ==================== EXPANDED STATE ==================== */
                    <>
                        {/* Header with Logo and Close Button - draggable region */}
                        <div
                            className="p-4 flex items-center justify-between shrink-0"
                            style={{ WebkitAppRegion: 'drag' } as React.CSSProperties}
                        >
                            <div className="flex items-center gap-2">
                                <svg className="w-6 h-6 text-aegis-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                </svg>
                                <span className="text-lg font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                                    AEGIS
                                </span>
                            </div>
                            <button
                                onClick={onToggle}
                                className="p-2 hover:bg-aegis-gray-light rounded-lg transition-colors"
                                title="Collapse sidebar"
                                style={{ WebkitAppRegion: 'no-drag' } as React.CSSProperties}
                            >
                                <svg className="w-5 h-5 text-aegis-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
                                </svg>
                            </button>
                        </div>

                        {/* Search Button */}
                        <div className="px-3 pb-2 shrink-0">
                            <button
                                onClick={() => setIsSearchOpen(true)}
                                className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg bg-aegis-gray hover:bg-aegis-gray-light transition-colors text-sm text-aegis-text-muted"
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                </svg>
                                <span>Search projects...</span>
                                <kbd className="ml-auto px-1.5 py-0.5 text-xs bg-aegis-darker rounded">⌘K</kbd>
                            </button>
                        </div>

                        {/* New Analysis Button */}
                        <div className="px-3 pb-2 shrink-0">
                            <button
                                onClick={() => navigate('/')}
                                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors text-sm ${location.pathname === '/'
                                    ? 'bg-aegis-accent/20 text-aegis-accent'
                                    : 'text-aegis-text-muted hover:bg-aegis-gray-light hover:text-aegis-text'
                                    }`}
                            >
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                                </svg>
                                <span>New Analysis</span>
                            </button>
                        </div>

                        {/* Settings Button */}
                        <div className="px-3 pb-2 shrink-0">
                            <button
                                onClick={() => navigate('/settings')}
                                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors text-sm ${location.pathname === '/settings'
                                    ? 'bg-aegis-accent/20 text-aegis-accent'
                                    : 'text-aegis-text-muted hover:bg-aegis-gray-light hover:text-aegis-text'
                                    }`}
                            >
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                </svg>
                                <span>Settings</span>
                            </button>
                        </div>

                        {/* 
                        TODO: Implement when needed or in the development git channel
                        TEMPORARY: Graph Test Button - Delete after testing */}
                        {/* <div className="px-3 pb-2 shrink-0">
                            <button
                                onClick={() => navigate('/test')}
                                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors text-sm ${location.pathname === '/test'
                                    ? 'bg-yellow-500/20 text-yellow-500'
                                    : 'text-yellow-500/70 hover:bg-yellow-500/10 hover:text-yellow-500'
                                    }`}
                            >
                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                                </svg>
                                <span>Graph Test</span>
                            </button>
                        </div> */}

                        {/* Report Generation Status */}
                        {isReportGenerating && (
                            <div className="px-3 pb-2 shrink-0">
                                <div className="bg-aegis-accent/10 border border-aegis-accent/30 rounded-lg p-3">
                                    <div className="flex items-center gap-2 mb-2">
                                        <div className="w-4 h-4 border-2 border-aegis-accent border-t-transparent rounded-full animate-spin" />
                                        <span className="text-sm font-medium text-aegis-accent">Generating Report</span>
                                    </div>
                                    {reportFileName && (
                                        <p className="text-xs text-aegis-text-muted truncate mb-1">
                                            {reportFileName}
                                        </p>
                                    )}
                                    {reportProgress && (
                                        <>
                                            <p className="text-xs text-aegis-text-subtle mb-2">
                                                {reportProgress.message}
                                            </p>
                                            <div className="w-full h-1 bg-aegis-darker rounded-full overflow-hidden">
                                                <div
                                                    className="h-full bg-aegis-accent transition-all duration-300"
                                                    style={{ width: `${reportProgress.percentage}%` }}
                                                />
                                            </div>
                                        </>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* Projects List */}
                        <div className="flex-1 overflow-y-auto">
                            <div className="p-2">
                                <div className="text-sm font-semibold text-aegis-text-muted uppercase tracking-wider px-3 py-2" title={`${projects.length} project${projects.length !== 1 ? 's' : ''}`}>
                                    Your Projects ({projects.length})
                                </div>

                                {isLoading ? (
                                    <div className="px-4 py-8 text-center">
                                        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-aegis-accent mx-auto"></div>
                                    </div>
                                ) : projects.length === 0 ? (
                                    <div className="px-4 py-8 text-center text-aegis-text-subtle text-sm">
                                        No projects yet.<br />
                                        <span className="text-aegis-text-muted">Upload BloodHound data to start!</span>
                                    </div>
                                ) : (
                                    <div className="space-y-1">
                                        {projects.map(project => (
                                            <ProjectListItem
                                                key={project.id}
                                                project={project}
                                                isSelected={location.pathname === `/chat/${project.id}`}
                                                isActiveProject={activeProjectId === project.id}
                                                globalIsUploading={globalIsUploading}
                                                isThisProjectUploading={globalIsUploading && useProjectStore.getState().uploadingProjectId === project.id}
                                                isInfrastructureDown={isInfrastructureDown}
                                                neo4jMode={neo4jMode}
                                                formatDate={formatDate}
                                                onSelect={() => !globalIsUploading && handleSelectProject(project)}
                                                onRename={(newName) => handleRenameProject(project.id, newName)}
                                                onDelete={() => handleDeleteProject(project.id)}
                                            />
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    </>
                ) : (
                    /* ==================== COLLAPSED STATE (Icon Rail) ==================== */
                    <div className="flex flex-col items-center py-3 gap-1">
                        {/* Logo (shield) that becomes hamburger on hover - draggable area above */}
                        <div
                            className="w-full h-2 shrink-0"
                            style={{ WebkitAppRegion: 'drag' } as React.CSSProperties}
                        />
                        <button
                            data-tooltip-id="expand-sidebar-tooltip"
                            data-tooltip-content="Expand sidebar"
                            onClick={onToggle}
                            className="group relative p-2 mb-1 hover:bg-aegis-gray-light rounded-lg transition-colors"
                        >
                            {/* Shield icon - visible by default */}
                            <svg className="w-6 h-6 text-aegis-accent group-hover:opacity-0 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                            {/* Hamburger icon - visible on hover */}
                            <svg className="w-6 h-6 text-aegis-text-muted absolute inset-0 m-auto opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                            </svg>
                        </button>
                        <Tooltip
                            id="expand-sidebar-tooltip"
                            place="right"
                            style={{
                                backgroundColor: '#1a1d23',
                                border: '1px solid #2d3748',
                                color: '#e2e8f0',
                                fontSize: '0.875rem',
                                padding: '0.5rem 0.75rem',
                                borderRadius: '0.5rem',
                                boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
                                zIndex: 50
                            }}
                        />

                        {/* New Analysis */}
                        <button
                            data-tooltip-id="new-analysis-tooltip"
                            data-tooltip-content="New Analysis"
                            onClick={() => navigate('/')}
                            className={`p-2 mb-1 rounded-lg transition-colors ${location.pathname === '/'
                                ? 'bg-aegis-info-dark text-white'
                                : 'hover:bg-aegis-gray-light text-aegis-text-muted hover:text-aegis-text'
                                }`}
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                            </svg>
                        </button>
                        <Tooltip
                            id="new-analysis-tooltip"
                            place="right"
                            style={{
                                backgroundColor: '#1a1d23',
                                border: '1px solid #2d3748',
                                color: '#e2e8f0',
                                fontSize: '0.875rem',
                                padding: '0.5rem 0.75rem',
                                borderRadius: '0.5rem',
                                boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
                                zIndex: 50
                            }}
                        />

                        {/* Search */}
                        <button
                            data-tooltip-id="search-tooltip"
                            data-tooltip-content="Search projects (⌘K)"
                            onClick={() => setIsSearchOpen(true)}
                            className="p-2 mb-1 hover:bg-aegis-gray-light rounded-lg transition-colors text-aegis-text-muted hover:text-aegis-text"
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                            </svg>
                        </button>
                        <Tooltip
                            id="search-tooltip"
                            place="right"
                            style={{
                                backgroundColor: '#1a1d23',
                                border: '1px solid #2d3748',
                                color: '#e2e8f0',
                                fontSize: '0.875rem',
                                padding: '0.5rem 0.75rem',
                                borderRadius: '0.5 brem',
                                boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
                                zIndex: 50
                            }}
                        />

                        {/* Settings */}
                        <button
                            data-tooltip-id="settings-tooltip"
                            data-tooltip-content="Settings"
                            onClick={() => navigate('/settings')}
                            className={`p-2 mb-1 rounded-lg transition-colors ${location.pathname === '/settings'
                                ? 'bg-aegis-info-dark text-white'
                                : 'hover:bg-aegis-gray-light text-aegis-text-muted hover:text-aegis-text'
                                }`}
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                            </svg>
                        </button>
                        <Tooltip
                            id="settings-tooltip"
                            place="right"
                            style={{
                                backgroundColor: '#1a1d23',
                                border: '1px solid #2d3748',
                                color: '#e2e8f0',
                                fontSize: '0.875rem',
                                padding: '0.5rem 0.75rem',
                                borderRadius: '0.5rem',
                                boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
                                zIndex: 50
                            }}
                        />

                        {/* 
                        
                        TODO: Implement when needed or in the development git channel
                        TEMPORARY: Graph Test - Delete after testing */}
                        {/* <button
                            data-tooltip-id="test-tooltip"
                            data-tooltip-content="Graph Test"
                            onClick={() => navigate('/test')}
                            className={`p-2 mb-1 rounded-lg transition-colors ${location.pathname === '/test'
                                ? 'bg-yellow-500 text-white'
                                : 'hover:bg-yellow-500/10 text-yellow-500/70 hover:text-yellow-500'
                                }`}
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                            </svg>
                        </button> */}
                        <Tooltip
                            id="test-tooltip"
                            place="right"
                            style={{
                                backgroundColor: '#1a1d23',
                                border: '1px solid #2d3748',
                                color: '#e2e8f0',
                                fontSize: '0.875rem',
                                padding: '0.5rem 0.75rem',
                                borderRadius: '0.5rem',
                                boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
                                zIndex: 50
                            }}
                        />

                        {/* Divider */}
                        <div className="w-8 h-px bg-aegis-border my-2" />

                        {/* Report Generation Indicator (collapsed) */}
                        {isReportGenerating && (
                            <>
                                <button
                                    data-tooltip-id="report-progress-tooltip"
                                    data-tooltip-content={reportProgress?.message || 'Generating report...'}
                                    className="p-2 mb-1 rounded-lg bg-aegis-accent/15"
                                    disabled
                                >
                                    <div className="w-5 h-5 border-2 border-aegis-accent border-t-transparent rounded-full animate-spin" />
                                </button>
                                <Tooltip
                                    id="report-progress-tooltip"
                                    place="right"
                                    style={{
                                        backgroundColor: '#1a1d23',
                                        border: '1px solid #58a6ff',
                                        color: '#58a6ff',
                                        fontSize: '0.875rem',
                                        padding: '0.5rem 0.75rem',
                                        borderRadius: '0.5rem',
                                        boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
                                        zIndex: 50,
                                        maxWidth: '200px'
                                    }}
                                />
                                <div className="w-8 h-px bg-aegis-border my-2" />
                            </>
                        )}

                        {/* Projects (as icons) */}
                        <div className="flex-1 overflow-y-auto w-full">
                            <div className="flex flex-col items-center gap-1">
                                {projects.map(project => {
                                    const isSelected = location.pathname === `/chat/${project.id}`;
                                    const isActiveProject = activeProjectId === project.id;
                                    const isThisProjectUploading = globalIsUploading && useProjectStore.getState().uploadingProjectId === project.id;

                                    // Status logic: Stopped/Active/Inactive with upload state
                                    const getStatusInfo = () => {
                                        // Show stopped if Docker or Neo4j is down
                                        if (isInfrastructureDown) {
                                            return { text: 'Stopped', dotColor: 'bg-red-500' };
                                        }
                                        // Show uploading state for this project
                                        if (isThisProjectUploading) {
                                            return { text: 'Uploading', dotColor: 'bg-aegis-accent animate-pulse' };
                                        }
                                        // Active = this project's data is loaded in BloodHound CE (show mode context)
                                        if (isActiveProject && !globalIsUploading) {
                                            const modeLabel = neo4jMode === 'docker' ? 'Docker' : 'Custom';
                                            return { text: `Active (${modeLabel})`, dotColor: 'bg-emerald-500' };
                                        }
                                        // Inactive = data not loaded
                                        return { text: 'Inactive', dotColor: 'bg-amber-500' };
                                    };

                                    const status = getStatusInfo();

                                    return (
                                        <React.Fragment key={project.id}>
                                            <button
                                                data-tooltip-id={`project-tooltip-${project.id}`}
                                                data-tooltip-content={`${project.name} • ${status.text}`}
                                                onClick={() => !globalIsUploading && handleSelectProject(project)}
                                                disabled={globalIsUploading}
                                                className={`relative p-2 mb-1 rounded-lg transition-colors duration-150 flex justify-center items-center ${globalIsUploading
                                                    ? 'cursor-not-allowed opacity-60'
                                                    : ''
                                                    } ${isSelected
                                                        ? 'bg-aegis-info-dark text-white'
                                                        : globalIsUploading
                                                            ? 'text-aegis-text-muted'
                                                            : 'hover:bg-aegis-gray-light text-aegis-text-muted hover:text-aegis-text'
                                                    }`}
                                            >
                                                <AnimatedFolderIcon size={20} isSelected={isSelected || isActiveProject} isCollapsed={true} />
                                                {/* Status indicator dot */}
                                                <span className={`
                                                    absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full
                                                    border-2 border-aegis-dark
                                                    ${status.dotColor}
                                                `} />
                                            </button>
                                            <Tooltip
                                                id={`project-tooltip-${project.id}`}
                                                place="right"
                                                style={{
                                                    backgroundColor: '#1a1d23',
                                                    border: '1px solid #2d3748',
                                                    color: '#e2e8f0',
                                                    fontSize: '0.875rem',
                                                    padding: '0.5rem 0.75rem',
                                                    borderRadius: '0.5rem',
                                                    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
                                                    zIndex: 50
                                                }}
                                            />
                                        </React.Fragment>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                )}
            </aside>

            {/* Search Modal */}
            <SearchProjectsModal
                isOpen={isSearchOpen}
                onClose={() => setIsSearchOpen(false)}
            />
        </>
    );
};

export default Sidebar;
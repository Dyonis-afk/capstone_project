/**
 * SearchProjectsModal - Modal for searching and selecting projects
 * Location: src/components/SearchProjectsModal.tsx
 * 
 * Features:
 * - Search input to filter projects
 * - Groups projects by time (Today, Previous 7 Days, Previous 30 Days, Older)
 * - Click project to navigate (seamless content swap)
 * - Keyboard navigation support (Escape to close)
 */

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useProjectStore } from '../stores/projectStore';

interface SearchProjectsModalProps {
    isOpen: boolean;
    onClose: () => void;
}

interface Project {
    id: string;
    name: string;
    description?: string;
    created_at: string;
    updated_at: string;
}

const SearchProjectsModal: React.FC<SearchProjectsModalProps> = ({ isOpen, onClose }) => {
    const navigate = useNavigate();
    const [searchQuery, setSearchQuery] = useState('');
    const inputRef = useRef<HTMLInputElement>(null);

    const { projects, setCurrentProject, loadProjects } = useProjectStore();

    // Focus input when modal opens
    useEffect(() => {
        if (isOpen) {
            loadProjects();
            setTimeout(() => inputRef.current?.focus(), 100);
        } else {
            setSearchQuery('');
        }
    }, [isOpen, loadProjects]);

    // Handle escape key
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape' && isOpen) {
                onClose();
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [isOpen, onClose]);

    // Filter projects based on search query
    const filteredProjects = useMemo(() => {
        if (!searchQuery.trim()) return projects;
        const query = searchQuery.toLowerCase();
        return projects.filter(p =>
            p.name.toLowerCase().includes(query) ||
            p.description?.toLowerCase().includes(query)
        );
    }, [projects, searchQuery]);

    // Group projects by time period
    const groupedProjects = useMemo(() => {
        const now = new Date();
        const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const weekAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000);
        const monthAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000);

        const groups: { [key: string]: Project[] } = {
            'Today': [],
            'Previous 7 Days': [],
            'Previous 30 Days': [],
            'Older': []
        };

        filteredProjects.forEach(project => {
            const projectDate = new Date(project.updated_at || project.created_at);

            if (projectDate >= today) {
                groups['Today'].push(project);
            } else if (projectDate >= weekAgo) {
                groups['Previous 7 Days'].push(project);
            } else if (projectDate >= monthAgo) {
                groups['Previous 30 Days'].push(project);
            } else {
                groups['Older'].push(project);
            }
        });

        // Filter out empty groups
        return Object.entries(groups).filter(([_, items]) => items.length > 0);
    }, [filteredProjects]);

    const handleSelectProject = (project: Project) => {
        setCurrentProject(project);
        navigate(`/chat/${project.id}`);
        onClose();
    };

    const handleNewAnalysis = () => {
        navigate('/');
        onClose();
    };

    if (!isOpen) return null;

    return (
        <div
            className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh]"
            onClick={onClose}
        >
            {/* Backdrop */}
            <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />

            {/* Modal */}
            <div
                className="relative w-full max-w-2xl bg-aegis-dark border border-aegis-border rounded-2xl shadow-2xl overflow-hidden"
                onClick={e => e.stopPropagation()}
            >
                {/* Search Header */}
                <div className="flex items-center px-4 py-3 border-b border-aegis-border">
                    <svg className="w-5 h-5 text-aegis-text-muted mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    <input
                        ref={inputRef}
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder="Search projects..."
                        className="flex-1 bg-transparent text-aegis-text placeholder-aegis-text-muted focus:outline-none text-lg"
                    />
                    <button
                        onClick={onClose}
                        className="p-1.5 hover:bg-aegis-gray rounded-lg transition-colors ml-2"
                    >
                        <svg className="w-5 h-5 text-aegis-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>

                {/* Content */}
                <div className="max-h-[60vh] overflow-y-auto">
                    {/* New Analysis Option */}
                    <div className="px-2 py-2">
                        <button
                            onClick={handleNewAnalysis}
                            className="w-full flex items-center gap-3 px-4 py-3 rounded-xl bg-aegis-gray hover:bg-aegis-gray-light transition-colors"
                        >
                            <div className="w-8 h-8 rounded-lg bg-aegis-accent/20 flex items-center justify-center">
                                <svg className="w-5 h-5 text-aegis-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                                </svg>
                            </div>
                            <span className="text-aegis-text font-medium">New Analysis</span>
                        </button>
                    </div>

                    {/* Project Groups */}
                    {groupedProjects.length > 0 ? (
                        groupedProjects.map(([groupName, groupProjects]) => (
                            <div key={groupName} className="px-2 pb-2">
                                <div className="px-4 py-2 text-xs font-semibold text-aegis-text-muted uppercase tracking-wider">
                                    {groupName}
                                </div>
                                <div className="space-y-1">
                                    {groupProjects.map(project => (
                                        <button
                                            key={project.id}
                                            onClick={() => handleSelectProject(project)}
                                            className="w-full flex items-center gap-3 px-4 py-3 rounded-xl hover:bg-aegis-gray transition-colors text-left"
                                        >
                                            <svg className="w-5 h-5 text-aegis-text-muted shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                                            </svg>
                                            <span className="text-aegis-text truncate">{project.name}</span>
                                        </button>
                                    ))}
                                </div>
                            </div>
                        ))
                    ) : searchQuery ? (
                        <div className="px-4 py-8 text-center text-aegis-text-muted">
                            No projects found for "{searchQuery}"
                        </div>
                    ) : (
                        <div className="px-4 py-8 text-center text-aegis-text-muted">
                            No projects yet. Upload BloodHound data to start!
                        </div>
                    )}
                </div>

                {/* Footer hint */}
                <div className="px-4 py-2 border-t border-aegis-border bg-aegis-darker/50">
                    <div className="flex items-center gap-4 text-xs text-aegis-text-subtle">
                        <span className="flex items-center gap-1">
                            <kbd className="px-1.5 py-0.5 bg-aegis-gray rounded text-aegis-text-muted">↵</kbd>
                            to select
                        </span>
                        <span className="flex items-center gap-1">
                            <kbd className="px-1.5 py-0.5 bg-aegis-gray rounded text-aegis-text-muted">esc</kbd>
                            to close
                        </span>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SearchProjectsModal;
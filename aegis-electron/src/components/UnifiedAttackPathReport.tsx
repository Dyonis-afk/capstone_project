/**
 * Unified Attack Path Report Component
 * Location: src/components/UnifiedAttackPathReport.tsx
 *
 * Main report component that displays RAG-generated attack path analysis
 * Updated to use pentest-style findings matching the mockup structure
 */

import React, { useState, useRef, useMemo, useEffect, useCallback } from 'react';
import toast from 'react-hot-toast';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import AttackPathGraph, { AttackPathGraphRef } from './AttackPathGraph';
import {
    GraphNode,
    GraphEdge,
    SectionHeader,
    MarkdownContent,
    ExecutiveSummaryContent,
    FindingCard,
    CypherQueryDisplay,
    Finding,
    FindingSeverity,
    AdditionalFindingsSection,
    SyntaxHighlightedScript,
} from './attack-components';
import { AdditionalFinding } from '../types/chat';
import T0ConfigBanner from './T0ConfigBanner';
import { Tier0Config } from './Tier0ConfigModal';

interface UnifiedAttackPathReportProps {
    report: any; // Whatever RAG returns
    analysisId?: string; // Analysis ID for graph generation
    onDownload?: () => void;
    onBack?: () => void;
    onExportMarkdown?: () => void;
    onExportJSON?: () => void; // Export report as JSON
    onRemoveFinding?: (findingId: string) => void; // Remove additional finding from report
    onFullScreen?: () => void; // Toggle fullscreen mode
    isFullScreen?: boolean; // Whether report is in fullscreen mode
    tier0Config?: Tier0Config | null; // T0 configuration for filtering findings
}

const UnifiedAttackPathReport: React.FC<UnifiedAttackPathReportProps> = ({
    report,
    analysisId: propAnalysisId,
    onDownload: _onDownload,
    onBack,
    onExportMarkdown: _onExportMarkdown,
    onExportJSON,
    onRemoveFinding,
    onFullScreen,
    isFullScreen,
    tier0Config
}) => {
    const [expandedGraphs] = useState<Set<number>>(new Set());
    const [_selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
    const [_selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
    const [fullScreenGraph, setFullScreenGraph] = useState<{ pathNumber: number; analysisId: string; attackName?: string } | null>(null);
    // Track which findings are expanded (collapsed by default)
    const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

    // Search functionality state
    const [isSearchOpen, setIsSearchOpen] = useState(false);
    const [searchQuery, setSearchQuery] = useState('');
    const [highlightedFindingId, setHighlightedFindingId] = useState<string | null>(null);
    const searchInputRef = useRef<HTMLInputElement>(null);
    const findingRefs = useRef<{ [key: string]: HTMLDivElement | null }>({});

    // Export dropdown state
    const [showExportMenu, setShowExportMenu] = useState(false);
    const exportMenuRef = useRef<HTMLDivElement>(null);

    // Toggle finding expansion
    const toggleFinding = (findingId: string) => {
        setExpandedFindings(prev => {
            const newSet = new Set(prev);
            if (newSet.has(findingId)) {
                newSet.delete(findingId);
            } else {
                newSet.add(findingId);
            }
            return newSet;
        });
    };

    // Severity color mapping for collapsible headers
    const severityColors: Record<string, { bg: string; text: string }> = {
        Critical: { bg: 'bg-red-600', text: 'text-white' },
        High: { bg: 'bg-orange-500', text: 'text-white' },
        Medium: { bg: 'bg-yellow-600', text: 'text-white' },
        Low: { bg: 'bg-green-500', text: 'text-white' },
    };

    // Complexity color mapping
    const complexityColors: Record<string, string> = {
        Low: 'text-green-400',
        Medium: 'text-yellow-400',
        High: 'text-orange-400',
        Critical: 'text-red-400',
    };

    // Only show findings that have at least one attack step (hide 0-step findings)
    const hasAttackSteps = (path: any) => {
        const steps = path?.pentest_finding?.attack_steps;
        return Array.isArray(steps) && steps.length > 0;
    };

    // Generate search suggestions based on finding titles and categories (only findings with attack steps)
    const searchSuggestions = useMemo(() => {
        if (!report) return [];

        const suggestions: { id: string; title: string; severity?: string; category?: string }[] = [];
        const pathsWithSteps = (report?.paths || report?.critical_attack_paths || []).filter(hasAttackSteps);

        pathsWithSteps.forEach((path: any, index: number) => {
            const finding = path.pentest_finding;
            if (finding) {
                suggestions.push({
                    id: `finding-${path.scenario_number || index}`,
                    title: finding.title || path.title || `Attack Path ${index + 1}`,
                    severity: finding.severity,
                    category: finding.category
                });
            }
        });

        return suggestions;
    }, [report]);

    // Filter suggestions based on search query
    const filteredSuggestions = useMemo(() => {
        if (!searchQuery.trim()) return [];
        const query = searchQuery.toLowerCase();
        return searchSuggestions.filter(s =>
            s.title.toLowerCase().includes(query) ||
            s.category?.toLowerCase().includes(query) ||
            s.severity?.toLowerCase().includes(query)
        );
    }, [searchQuery, searchSuggestions]);

    // Navigate to and highlight a finding
    const navigateToFinding = useCallback((findingId: string) => {
        // Expand the finding
        setExpandedFindings(prev => new Set(prev).add(findingId));

        // Set highlight
        setHighlightedFindingId(findingId);

        // Close search
        setIsSearchOpen(false);
        setSearchQuery('');

        // Scroll to the finding after a short delay to allow expansion
        setTimeout(() => {
            const element = findingRefs.current[findingId];
            if (element) {
                element.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }, 100);

        // Remove highlight after 3 seconds
        setTimeout(() => {
            setHighlightedFindingId(null);
        }, 3000);
    }, []);

    // Handle search input keydown
    const handleSearchKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Escape') {
            setIsSearchOpen(false);
            setSearchQuery('');
        } else if (e.key === 'Enter' && filteredSuggestions.length > 0) {
            const suggestion = filteredSuggestions[0];
            navigateToFinding(suggestion.id);
        }
    };

    // Focus search input when opened
    useEffect(() => {
        if (isSearchOpen && searchInputRef.current) {
            searchInputRef.current.focus();
        }
    }, [isSearchOpen]);

    // Keyboard shortcut to open search (Ctrl/Cmd + F)
    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
                e.preventDefault();
                setIsSearchOpen(true);
            }
        };

        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, []);

    // Close export menu when clicking outside
    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (exportMenuRef.current && !exportMenuRef.current.contains(event.target as Node)) {
                setShowExportMenu(false);
            }
        };

        if (showExportMenu) {
            document.addEventListener('mousedown', handleClickOutside);
        }
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, [showExportMenu]);

    // Default JSON export handler using Electron's native save dialog
    const handleExportJSON = async () => {
        if (onExportJSON) {
            onExportJSON();
            return;
        }

        // Default implementation: download report as JSON file
        if (!report) {
            toast.error('No report data to export');
            return;
        }

        try {
            // Export only findings that have attack steps (same filter as UI); 0-step findings must not appear anywhere in output
            const pathsToExport = (report.paths || report.critical_attack_paths || []).filter(hasAttackSteps);
            const allPathsFiltered = (report.all_paths || report.paths || []).filter(hasAttackSteps);
            const n = pathsToExport.length;
            const bySeverity = (severity: string) =>
                pathsToExport.filter((p: any) => (p?.pentest_finding?.severity || '').toLowerCase() === severity.toLowerCase()).length;
            const domainOverviewForExport = report.domain_overview
                ? (() => {
                    const { domain_controllers: _dc, ...rest } = report.domain_overview as Record<string, unknown>;
                    return rest;
                })()
                : report.domain_overview;
            const exportReport = {
                ...report,
                domain_overview: domainOverviewForExport,
                paths: pathsToExport,
                all_paths: allPathsFiltered,
                statistics: report.statistics
                    ? {
                        ...report.statistics,
                        total_attack_paths: n,
                        actionable_paths: n,
                        critical_paths: bySeverity('critical'),
                        high_risk_paths: bySeverity('high'),
                        findings_by_severity: {
                            critical: bySeverity('critical'),
                            high: bySeverity('high'),
                            medium: bySeverity('medium'),
                            low: bySeverity('low'),
                        },
                    }
                    : report.statistics,
                tier0_statistics: report.tier0_statistics
                    ? { ...report.tier0_statistics, actionable_count: n }
                    : report.tier0_statistics,
            };
            const jsonString = JSON.stringify(exportReport, null, 2);

            // Create filename with timestamp
            const timestamp = new Date().toISOString().split('T')[0];
            const reportId = report?.report_id || report?.report_metadata?.analysis_id || 'report';
            const filename = `aegis_report_${reportId}_${timestamp}.json`;

            // Use Electron's native save dialog
            const result = await window.fileAPI.saveWithDialog({
                defaultFilename: filename,
                content: jsonString,
                filters: [
                    { name: 'JSON Files', extensions: ['json'] },
                    { name: 'All Files', extensions: ['*'] }
                ]
            });

            if (result.success) {
                toast.success(`Report saved to ${result.filePath}`);
            } else if (result.canceled) {
                // User canceled - no message needed
            } else {
                toast.error(result.error || 'Failed to save report');
            }
        } catch (error) {
            console.error('Failed to export JSON:', error);
            toast.error('Failed to export report');
        }
    };

    // PDF export handler with severity color coding
    const handleExportPDF = async () => {
        if (!report) {
            toast.error('No report data to export');
            return;
        }

        try {
            // Filter paths with attack steps (same as UI)
            const pathsToExport = (report.paths || report.critical_attack_paths || []).filter(hasAttackSteps);

            // Create PDF document
            const doc = new jsPDF();
            const pageWidth = doc.internal.pageSize.getWidth();
            const pageHeight = doc.internal.pageSize.getHeight();
            const margin = 15;
            let yPos = margin;

            // Severity color mapping (RGB values for PDF)
            const severityColorsPDF: Record<string, { bg: [number, number, number]; text: [number, number, number] }> = {
                Critical: { bg: [220, 38, 38], text: [255, 255, 255] },   // red-600
                High: { bg: [249, 115, 22], text: [255, 255, 255] },      // orange-500
                Medium: { bg: [202, 138, 4], text: [255, 255, 255] },     // yellow-600
                Low: { bg: [34, 197, 94], text: [255, 255, 255] },        // green-500
            };

            // Helper: Check if we need a new page
            const checkNewPage = (requiredSpace: number) => {
                if (yPos + requiredSpace > pageHeight - margin) {
                    doc.addPage();
                    yPos = margin;
                    return true;
                }
                return false;
            };

            // === COVER PAGE ===
            doc.setFillColor(15, 23, 42); // Dark blue background
            doc.rect(0, 0, pageWidth, pageHeight, 'F');

            // AEGIS Logo/Title
            doc.setTextColor(59, 130, 246); // Blue text
            doc.setFontSize(36);
            doc.setFont('helvetica', 'bold');
            doc.text('AEGIS', pageWidth / 2, 60, { align: 'center' });

            // Subtitle
            doc.setTextColor(255, 255, 255);
            doc.setFontSize(18);
            doc.setFont('helvetica', 'normal');
            doc.text('Attack Path Intelligence Report', pageWidth / 2, 75, { align: 'center' });

            // Description
            doc.setTextColor(156, 163, 175); // Gray text
            doc.setFontSize(11);
            const description = 'RAG-powered analysis of critical attack paths discovered in Active Directory infrastructure';
            const descLines = doc.splitTextToSize(description, pageWidth - 60);
            doc.text(descLines, pageWidth / 2, 90, { align: 'center' });

            // Report metadata box
            const metaBoxY = 120;
            doc.setFillColor(30, 41, 59);
            doc.roundedRect(margin + 20, metaBoxY, pageWidth - margin * 2 - 40, 50, 3, 3, 'F');

            doc.setTextColor(156, 163, 175);
            doc.setFontSize(10);
            doc.text('Report ID:', margin + 30, metaBoxY + 15);
            doc.text('Generated:', margin + 30, metaBoxY + 28);
            doc.text('Findings:', margin + 30, metaBoxY + 41);

            doc.setTextColor(255, 255, 255);
            const reportId = report?.report_id || report?.report_metadata?.analysis_id || 'Unknown';
            const generatedAt = report?.generated_at || report?.report_metadata?.generated_at || new Date().toISOString();
            doc.text(String(reportId).split('-')[0], margin + 60, metaBoxY + 15);
            doc.text(new Date(generatedAt).toLocaleDateString(), margin + 60, metaBoxY + 28);
            doc.text(`${pathsToExport.length} actionable finding${pathsToExport.length !== 1 ? 's' : ''}`, margin + 60, metaBoxY + 41);

            // Data source note
            doc.setTextColor(107, 114, 128);
            doc.setFontSize(9);
            doc.text('Data collected using BloodHound Community Edition', pageWidth / 2, pageHeight - 30, { align: 'center' });

            // === FINDINGS SUMMARY PAGE ===
            doc.addPage();
            yPos = margin;
            doc.setTextColor(0, 0, 0);

            // Section header
            doc.setFontSize(16);
            doc.setFont('helvetica', 'bold');
            doc.text('Findings Summary', margin, yPos + 5);
            yPos += 15;

            // Summary table data
            const summaryTableData = pathsToExport.map((path: any, index: number) => {
                const finding = path.pentest_finding;
                return [
                    (index + 1).toString(),
                    finding?.title || path.title || `Attack Path ${index + 1}`,
                    finding?.severity || 'Medium',
                    finding?.attack_complexity || 'Medium',
                ];
            });

            // Summary table with color-coded severity
            autoTable(doc, {
                startY: yPos,
                head: [['#', 'Finding', 'Severity', 'Complexity']],
                body: summaryTableData,
                theme: 'striped',
                headStyles: {
                    fillColor: [30, 41, 59],
                    textColor: [255, 255, 255],
                    fontStyle: 'bold',
                },
                columnStyles: {
                    0: { cellWidth: 12 },
                    1: { cellWidth: 'auto' },
                    2: { cellWidth: 25, halign: 'center' },
                    3: { cellWidth: 25, halign: 'center' },
                },
                didDrawCell: (data) => {
                    // Color-code severity column (index 2)
                    if (data.section === 'body' && data.column.index === 2) {
                        const severity = data.cell.raw as string;
                        const colors = severityColorsPDF[severity] || severityColorsPDF.Medium;
                        const cellX = data.cell.x + 2;
                        const cellY = data.cell.y + (data.cell.height - 6) / 2;
                        const cellWidth = data.cell.width - 4;
                        const cellHeight = 6;

                        doc.setFillColor(colors.bg[0], colors.bg[1], colors.bg[2]);
                        doc.roundedRect(cellX, cellY, cellWidth, cellHeight, 1, 1, 'F');
                        doc.setTextColor(colors.text[0], colors.text[1], colors.text[2]);
                        doc.setFontSize(8);
                        doc.setFont('helvetica', 'bold');
                        doc.text(severity, cellX + cellWidth / 2, cellY + cellHeight / 2 + 1, { align: 'center' });
                        doc.setTextColor(0, 0, 0);
                    }
                },
                margin: { left: margin, right: margin },
            });

            // Reset font state after autoTable (autoTable may leave font in unexpected state)
            doc.setFont('helvetica', 'normal');
            doc.setFontSize(10);
            doc.setTextColor(0, 0, 0);

            // === EXECUTIVE SUMMARY (continues on same page if space, otherwise new page) ===
            if (report?.executive_summary) {
                // Get current Y position after the table
                const tableEndY = (doc as any).lastAutoTable?.finalY || yPos;
                yPos = tableEndY + 15;

                // Check if we need a new page for the executive summary header
                if (yPos > pageHeight - 60) {
                    doc.addPage();
                    yPos = margin;
                }

                // Reset font state explicitly after autoTable
                doc.setFont('helvetica', 'bold');
                doc.setFontSize(14);
                doc.setTextColor(0, 0, 0);
                doc.text('Executive Summary', margin, yPos);
                yPos += 12;

                // Clean and normalize the text - remove markdown and special characters
                const cleanText = String(report.executive_summary)
                    .replace(/#{1,6}\s*/g, '')
                    .replace(/\*\*/g, '')
                    .replace(/\*/g, '')
                    .replace(/`/g, '')
                    .replace(/[^\x00-\x7F]/g, '') // Remove non-ASCII characters that cause issues
                    .trim();

                // Split into paragraphs (by double newline or single newline)
                const paragraphs = cleanText.split(/\n\n|\n(?=[A-Z]|\d|-)/).filter(p => p.trim());

                const lineHeight = 5;
                const bulletIndent = 8;

                paragraphs.forEach((paragraph) => {
                    const trimmedPara = paragraph.trim();

                    // Check if this is a bullet point line
                    const isBullet = trimmedPara.startsWith('- ') || trimmedPara.startsWith('* ');

                    // Reset font for each paragraph
                    doc.setFont('helvetica', 'normal');
                    doc.setFontSize(10);
                    doc.setTextColor(0, 0, 0);

                    if (isBullet) {
                        // Handle bullet points - split by newlines within the bullet section
                        const bulletLines = trimmedPara.split('\n').filter(l => l.trim());

                        bulletLines.forEach((bulletLine) => {
                            const cleanBullet = bulletLine.replace(/^[-*]\s*/, '').trim();
                            const wrappedLines = doc.splitTextToSize(cleanBullet, pageWidth - margin * 2 - bulletIndent);

                            wrappedLines.forEach((line: string, lineIdx: number) => {
                                if (yPos + lineHeight > pageHeight - margin) {
                                    doc.addPage();
                                    yPos = margin;
                                    doc.setFont('helvetica', 'normal');
                                    doc.setFontSize(10);
                                    doc.setTextColor(0, 0, 0);
                                }

                                if (lineIdx === 0) {
                                    // Draw bullet point
                                    doc.setFontSize(8);
                                    doc.text('-', margin + 2, yPos);
                                    doc.setFontSize(10);
                                }
                                doc.text(line, margin + bulletIndent, yPos);
                                yPos += lineHeight;
                            });
                        });
                        yPos += 2; // Extra space after bullet section
                    } else {
                        // Regular paragraph
                        const wrappedLines = doc.splitTextToSize(trimmedPara, pageWidth - margin * 2);

                        wrappedLines.forEach((line: string) => {
                            if (yPos + lineHeight > pageHeight - margin) {
                                doc.addPage();
                                yPos = margin;
                                doc.setFont('helvetica', 'normal');
                                doc.setFontSize(10);
                                doc.setTextColor(0, 0, 0);
                            }
                            doc.text(line, margin, yPos);
                            yPos += lineHeight;
                        });
                        yPos += 3; // Extra space between paragraphs
                    }
                });
            }

            // === DETAILED FINDINGS ===
            pathsToExport.forEach((path: any, index: number) => {
                const finding = path.pentest_finding;
                if (!finding) return;

                doc.addPage();
                yPos = margin;

                const severity = finding.severity || 'Medium';
                const severityColors = severityColorsPDF[severity] || severityColorsPDF.Medium;

                // Finding number and title - calculate header height based on title length
                const findingTitle = `Finding ${index + 1}: ${finding.title || path.title || 'Untitled'}`;
                doc.setFontSize(12);
                doc.setFont('helvetica', 'bold');
                // Reserve space for severity badge on right (about 60px)
                const titleLines = doc.splitTextToSize(findingTitle, pageWidth - margin * 2 - 60);
                const headerHeight = Math.max(25, 15 + titleLines.length * 6);

                // Finding header with severity color bar
                doc.setFillColor(severityColors.bg[0], severityColors.bg[1], severityColors.bg[2]);
                doc.rect(0, 0, pageWidth, headerHeight, 'F');

                // Finding title (wrapped if long)
                doc.setTextColor(255, 255, 255);
                let titleY = 12;
                titleLines.forEach((line: string) => {
                    doc.text(line, margin, titleY);
                    titleY += 6;
                });

                // Severity badge on right (vertically centered)
                doc.setFontSize(10);
                doc.text(severity.toUpperCase(), pageWidth - margin, headerHeight / 2 + 3, { align: 'right' });

                yPos = headerHeight + 10;
                doc.setTextColor(0, 0, 0);

                // Metadata row
                doc.setFontSize(9);
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(100, 100, 100);
                const complexity = finding.attack_complexity || 'Medium';
                const category = finding.category || 'Unknown';
                doc.text(`Complexity: ${complexity}  |  Category: ${category}`, margin, yPos);

                yPos += 10;

                // Observation section
                if (finding.observation) {
                    doc.setFontSize(11);
                    doc.setFont('helvetica', 'bold');
                    doc.setTextColor(0, 0, 0);
                    doc.text('Observation', margin, yPos);
                    yPos += 6;

                    doc.setFontSize(10);
                    doc.setFont('helvetica', 'normal');
                    const obsText = String(finding.observation).replace(/\*\*/g, '').replace(/`/g, '');
                    const obsLines = doc.splitTextToSize(obsText, pageWidth - margin * 2);
                    checkNewPage(obsLines.length * 5);
                    doc.text(obsLines, margin, yPos);
                    yPos += obsLines.length * 5 + 8;
                }

                // Attack Steps section
                if (finding.attack_steps && finding.attack_steps.length > 0) {
                    checkNewPage(30);
                    doc.setFontSize(11);
                    doc.setFont('helvetica', 'bold');
                    doc.text('Attack Steps', margin, yPos);
                    yPos += 8;

                    finding.attack_steps.forEach((step: any, stepIndex: number) => {
                        checkNewPage(25);

                        // Step header - wrap long titles
                        doc.setFontSize(10);
                        doc.setFont('helvetica', 'bold');
                        doc.setTextColor(59, 130, 246);
                        const stepTitle = `Step ${step.step_number || stepIndex + 1}: ${step.title || 'Untitled Step'}`;
                        const stepTitleLines = doc.splitTextToSize(stepTitle, pageWidth - margin * 2);
                        stepTitleLines.forEach((line: string) => {
                            if (yPos + 4 > pageHeight - margin) {
                                doc.addPage();
                                yPos = margin;
                            }
                            doc.text(line, margin, yPos);
                            yPos += 4;
                        });
                        yPos += 2;

                        // Step description
                        if (step.description) {
                            doc.setFont('helvetica', 'normal');
                            doc.setTextColor(0, 0, 0);
                            doc.setFontSize(9);
                            const stepDesc = String(step.description).replace(/\*\*/g, '').replace(/`/g, '');
                            const stepLines = doc.splitTextToSize(stepDesc, pageWidth - margin * 2 - 10);
                            // Handle multi-line descriptions with page breaks
                            const descLineHeight = 4;
                            stepLines.forEach((line: string) => {
                                if (yPos + descLineHeight > pageHeight - margin) {
                                    doc.addPage();
                                    yPos = margin;
                                }
                                doc.text(line, margin + 5, yPos);
                                yPos += descLineHeight;
                            });
                            yPos += 3;
                        }

                        // OPSEC options (commands)
                        if (step.opsec_options && step.opsec_options.length > 0) {
                            step.opsec_options.forEach((opt: any) => {
                                const opsecLevel = opt.opsec_level || 'safe';
                                const opsecColor: [number, number, number] = opsecLevel === 'safe' ? [34, 197, 94] : [249, 115, 22];

                                // Get full command text and calculate required space
                                const cmdText = opt.command ? String(opt.command) : '';
                                const cmdLines = cmdText ? doc.splitTextToSize(cmdText, pageWidth - margin * 2 - 20) : [];
                                const cmdLineHeight = 3.5;
                                const cmdBlockHeight = cmdLines.length * cmdLineHeight + 6;

                                // Check if we need a new page for this entire command block
                                const totalBlockHeight = 8 + cmdBlockHeight; // header + command
                                if (yPos + totalBlockHeight > pageHeight - margin) {
                                    doc.addPage();
                                    yPos = margin;
                                }

                                // OPSEC badge
                                doc.setFillColor(opsecColor[0], opsecColor[1], opsecColor[2]);
                                doc.roundedRect(margin + 5, yPos - 3, 14, 5, 1, 1, 'F');
                                doc.setTextColor(255, 255, 255);
                                doc.setFontSize(6);
                                doc.setFont('helvetica', 'bold');
                                doc.text(opsecLevel.toUpperCase(), margin + 12, yPos, { align: 'center' });

                                // Tool name
                                doc.setTextColor(0, 0, 0);
                                doc.setFontSize(9);
                                doc.setFont('helvetica', 'bold');
                                doc.text(opt.tool_name || 'Unknown Tool', margin + 22, yPos);
                                yPos += 6;

                                // Command in code block (full command, no truncation)
                                if (cmdText) {
                                    // Draw background
                                    doc.setFillColor(245, 245, 245);
                                    doc.roundedRect(margin + 5, yPos - 2, pageWidth - margin * 2 - 10, cmdBlockHeight, 2, 2, 'F');

                                    // Draw border
                                    doc.setDrawColor(200, 200, 200);
                                    doc.roundedRect(margin + 5, yPos - 2, pageWidth - margin * 2 - 10, cmdBlockHeight, 2, 2, 'S');

                                    // Draw command text
                                    doc.setFont('courier', 'normal');
                                    doc.setFontSize(7);
                                    doc.setTextColor(30, 30, 30);

                                    let cmdYPos = yPos + 2;
                                    cmdLines.forEach((line: string) => {
                                        doc.text(line, margin + 8, cmdYPos);
                                        cmdYPos += cmdLineHeight;
                                    });

                                    yPos += cmdBlockHeight + 4;
                                }
                            });
                        }
                        yPos += 3;
                    });
                }

                // Understanding the Attack section (Q&A format)
                if (finding.understanding && finding.understanding.length > 0) {
                    checkNewPage(30);
                    doc.setFontSize(11);
                    doc.setFont('helvetica', 'bold');
                    doc.setTextColor(0, 0, 0);
                    doc.text('Understanding the Attack', margin, yPos);
                    yPos += 8;

                    finding.understanding.forEach((qa: any) => {
                        checkNewPage(20);
                        // Question - wrap long text to prevent cutoff
                        doc.setFontSize(9);
                        doc.setFont('helvetica', 'bold');
                        doc.setTextColor(59, 130, 246);
                        const questionText = String(qa.question || '').replace(/\*\*/g, '');
                        const questionLines = doc.splitTextToSize(questionText, pageWidth - margin * 2);
                        questionLines.forEach((line: string) => {
                            if (yPos + 4 > pageHeight - margin) {
                                doc.addPage();
                                yPos = margin;
                            }
                            doc.text(line, margin, yPos);
                            yPos += 4;
                        });
                        yPos += 2;

                        // Answer
                        doc.setFont('helvetica', 'normal');
                        doc.setTextColor(0, 0, 0);
                        const answerText = String(qa.answer || '').replace(/\*\*/g, '').replace(/`/g, '');
                        const answerLines = doc.splitTextToSize(answerText, pageWidth - margin * 2 - 5);
                        answerLines.forEach((line: string) => {
                            if (yPos + 4 > pageHeight - margin) {
                                doc.addPage();
                                yPos = margin;
                            }
                            doc.text(line, margin + 3, yPos);
                            yPos += 4;
                        });
                        yPos += 4;
                    });
                }

                // Risk and Business Impact section
                if (finding.risk_description || finding.risk_title) {
                    checkNewPage(30);
                    doc.setFontSize(11);
                    doc.setFont('helvetica', 'bold');
                    doc.setTextColor(220, 38, 38); // Red for risk
                    const riskTitle = finding.risk_title || 'Risk and Business Impact';
                    const riskTitleLines = doc.splitTextToSize(riskTitle, pageWidth - margin * 2);
                    riskTitleLines.forEach((line: string) => {
                        if (yPos + 5 > pageHeight - margin) {
                            doc.addPage();
                            yPos = margin;
                        }
                        doc.text(line, margin, yPos);
                        yPos += 5;
                    });
                    yPos += 3;

                    if (finding.risk_description) {
                        doc.setFont('helvetica', 'normal');
                        doc.setTextColor(0, 0, 0);
                        doc.setFontSize(9);
                        const riskText = String(finding.risk_description).replace(/\*\*/g, '').replace(/`/g, '');
                        const riskLines = doc.splitTextToSize(riskText, pageWidth - margin * 2);
                        riskLines.forEach((line: string) => {
                            if (yPos + 4 > pageHeight - margin) {
                                doc.addPage();
                                yPos = margin;
                            }
                            doc.text(line, margin, yPos);
                            yPos += 4;
                        });
                        yPos += 6;
                    }
                }

                // Remediation section
                if (finding.remediation_steps && finding.remediation_steps.length > 0) {
                    checkNewPage(30);
                    doc.setFontSize(11);
                    doc.setFont('helvetica', 'bold');
                    doc.setTextColor(34, 197, 94); // Green for remediation
                    doc.text('Recommended Actions', margin, yPos);
                    yPos += 8;

                    doc.setTextColor(0, 0, 0);
                    doc.setFont('helvetica', 'normal');
                    doc.setFontSize(9);

                    finding.remediation_steps.forEach((step: any, stepIndex: number) => {
                        checkNewPage(15);
                        const stepText = typeof step === 'string' ? step : (step.description || step.title || '');
                        const cleanStep = String(stepText).replace(/\*\*/g, '').replace(/`/g, '');
                        const stepLines = doc.splitTextToSize(`${stepIndex + 1}. ${cleanStep}`, pageWidth - margin * 2 - 5);
                        stepLines.forEach((line: string) => {
                            if (yPos + 4 > pageHeight - margin) {
                                doc.addPage();
                                yPos = margin;
                            }
                            doc.text(line, margin + 3, yPos);
                            yPos += 4;
                        });
                        yPos += 2;
                    });
                }

                // Remediation Script (PowerShell)
                if (finding.remediation_script) {
                    checkNewPage(40);
                    doc.setFontSize(10);
                    doc.setFont('helvetica', 'bold');
                    doc.setTextColor(34, 197, 94);
                    doc.text('Remediation Script', margin, yPos);
                    yPos += 6;

                    // Script in code block
                    const scriptText = String(finding.remediation_script);
                    const scriptLines = doc.splitTextToSize(scriptText, pageWidth - margin * 2 - 20);
                    const scriptLineHeight = 3.2;
                    const scriptBlockHeight = Math.min(scriptLines.length * scriptLineHeight + 8, pageHeight - margin * 2 - 20);

                    // Check if script block fits, otherwise start new page
                    if (yPos + scriptBlockHeight > pageHeight - margin) {
                        doc.addPage();
                        yPos = margin;
                    }

                    // Draw background
                    doc.setFillColor(30, 35, 40); // Dark background for code
                    doc.roundedRect(margin, yPos - 2, pageWidth - margin * 2, scriptBlockHeight, 2, 2, 'F');

                    // Draw script text
                    doc.setFont('courier', 'normal');
                    doc.setFontSize(6.5);
                    doc.setTextColor(200, 200, 200); // Light text

                    let scriptYPos = yPos + 4;
                    const maxScriptLines = Math.floor((scriptBlockHeight - 8) / scriptLineHeight);
                    scriptLines.slice(0, maxScriptLines).forEach((line: string) => {
                        doc.text(line, margin + 4, scriptYPos);
                        scriptYPos += scriptLineHeight;
                    });

                    if (scriptLines.length > maxScriptLines) {
                        doc.setTextColor(150, 150, 150);
                        doc.text(`... (${scriptLines.length - maxScriptLines} more lines)`, margin + 4, scriptYPos);
                    }

                    yPos += scriptBlockHeight + 6;
                    doc.setTextColor(0, 0, 0); // Reset text color
                }

                // Detection and Monitoring section
                if (finding.detection) {
                    const det = finding.detection;
                    const hasContent = (det.event_ids && det.event_ids.length > 0) ||
                        (det.indicators_of_compromise && det.indicators_of_compromise.length > 0) ||
                        (det.queries && det.queries.length > 0);

                    if (hasContent) {
                        checkNewPage(30);
                        doc.setFontSize(11);
                        doc.setFont('helvetica', 'bold');
                        doc.setTextColor(139, 92, 246); // Purple for detection
                        doc.text('Detection and Monitoring', margin, yPos);
                        yPos += 8;

                        // Event IDs
                        if (det.event_ids && det.event_ids.length > 0) {
                            doc.setFontSize(9);
                            doc.setFont('helvetica', 'bold');
                            doc.setTextColor(0, 0, 0);
                            doc.text('Windows Event IDs to Monitor:', margin, yPos);
                            yPos += 5;

                            doc.setFont('helvetica', 'normal');
                            det.event_ids.forEach((evt: any) => {
                                checkNewPage(10);
                                const evtText = `Event ${evt.id}: ${evt.description}`;
                                const evtLines = doc.splitTextToSize(evtText, pageWidth - margin * 2 - 10);
                                evtLines.forEach((line: string) => {
                                    doc.text(line, margin + 5, yPos);
                                    yPos += 4;
                                });
                            });
                            yPos += 4;
                        }

                        // Indicators of Compromise
                        if (det.indicators_of_compromise && det.indicators_of_compromise.length > 0) {
                            checkNewPage(15);
                            doc.setFontSize(9);
                            doc.setFont('helvetica', 'bold');
                            doc.setTextColor(0, 0, 0);
                            doc.text('Indicators of Compromise:', margin, yPos);
                            yPos += 5;

                            doc.setFont('helvetica', 'normal');
                            det.indicators_of_compromise.forEach((ioc: string) => {
                                checkNewPage(8);
                                const iocLines = doc.splitTextToSize(`- ${ioc}`, pageWidth - margin * 2 - 10);
                                iocLines.forEach((line: string) => {
                                    doc.text(line, margin + 5, yPos);
                                    yPos += 4;
                                });
                            });
                            yPos += 4;
                        }
                    }
                }

                // References section
                if (finding.references && finding.references.length > 0) {
                    checkNewPage(25);
                    doc.setFontSize(11);
                    doc.setFont('helvetica', 'bold');
                    doc.setTextColor(0, 0, 0);
                    doc.text('References', margin, yPos);
                    yPos += 8;

                    doc.setFontSize(8);
                    doc.setFont('helvetica', 'normal');

                    finding.references.forEach((ref: any) => {
                        checkNewPage(10);
                        // Tag badge
                        const tagColor: [number, number, number] = ref.tag === 'MITRE' ? [220, 38, 38] :
                            ref.tag === 'Microsoft' ? [59, 130, 246] : [107, 114, 128];
                        doc.setFillColor(tagColor[0], tagColor[1], tagColor[2]);
                        const tagWidth = doc.getTextWidth(ref.tag || 'Link') + 4;
                        doc.roundedRect(margin, yPos - 3, tagWidth, 5, 1, 1, 'F');
                        doc.setTextColor(255, 255, 255);
                        doc.setFontSize(6);
                        doc.setFont('helvetica', 'bold');
                        doc.text(ref.tag || 'Link', margin + 2, yPos);

                        // Title
                        doc.setTextColor(59, 130, 246);
                        doc.setFontSize(8);
                        doc.setFont('helvetica', 'normal');
                        const refTitle = String(ref.title || ref.url || '').substring(0, 80);
                        doc.text(refTitle, margin + tagWidth + 4, yPos);
                        yPos += 6;
                    });
                }
            });

            // === AMSI BYPASS APPENDIX ===
            if (report.amsi_appendix && report.amsi_appendix.techniques?.length > 0) {
                doc.addPage();
                yPos = margin;
                const contentWidth = pageWidth - margin * 2;

                // Section header
                doc.setFillColor(251, 191, 36); // Yellow/amber
                doc.roundedRect(margin, yPos, contentWidth, 12, 2, 2, 'F');
                doc.setFontSize(14);
                doc.setFont('helvetica', 'bold');
                doc.setTextColor(0, 0, 0);
                doc.text(report.amsi_appendix.title || 'AMSI Bypass Reference', margin + 5, yPos + 8);
                yPos += 18;

                // Description
                doc.setFontSize(10);
                doc.setFont('helvetica', 'normal');
                doc.setTextColor(60, 60, 60);
                const appendixDesc = report.amsi_appendix.description || '';
                const descLines = doc.splitTextToSize(appendixDesc, contentWidth);
                doc.text(descLines, margin, yPos);
                yPos += descLines.length * 5 + 10;

                // Each technique
                report.amsi_appendix.techniques.forEach((technique: any, techIdx: number) => {
                    // Check if we need a new page
                    if (yPos > pageHeight - 80) {
                        doc.addPage();
                        yPos = margin;
                    }

                    // Technique header
                    doc.setFillColor(33, 38, 45); // Dark bg
                    doc.roundedRect(margin, yPos, contentWidth, 10, 1, 1, 'F');
                    doc.setFontSize(11);
                    doc.setFont('helvetica', 'bold');
                    doc.setTextColor(255, 255, 255);
                    doc.text(`${techIdx + 1}. ${technique.name}`, margin + 3, yPos + 7);

                    // Family badge
                    const familyText = technique.family || 'unknown';
                    const familyWidth = doc.getTextWidth(familyText) + 6;
                    doc.setFillColor(88, 166, 255);
                    doc.roundedRect(pageWidth - margin - familyWidth - 3, yPos + 2, familyWidth, 6, 1, 1, 'F');
                    doc.setFontSize(7);
                    doc.setTextColor(255, 255, 255);
                    doc.text(familyText, pageWidth - margin - familyWidth, yPos + 6);
                    yPos += 14;

                    // Description
                    if (technique.description) {
                        doc.setFontSize(9);
                        doc.setFont('helvetica', 'italic');
                        doc.setTextColor(100, 100, 100);
                        const techDescLines = doc.splitTextToSize(technique.description, contentWidth - 10);
                        doc.text(techDescLines, margin + 5, yPos);
                        yPos += techDescLines.length * 4 + 4;
                    }

                    // Code block - full code, no truncation
                    doc.setFontSize(6);
                    doc.setFont('courier', 'normal');
                    const codeText = technique.code || '';
                    // Wrap code to fit within box with padding
                    const codeWrapWidth = contentWidth - 12;
                    const codeLines = doc.splitTextToSize(codeText, codeWrapWidth);
                    const lineHeight = 3.5;
                    const codePadding = 6;

                    // Render code lines with page breaks as needed
                    let codeStartY = yPos;
                    let isFirstBlock = true;

                    codeLines.forEach((_line: string, lineIdx: number) => {
                        const lineY = codeStartY + codePadding + (lineIdx * lineHeight);

                        // Check if we need a new page
                        if (lineY > pageHeight - 20) {
                            // Close current code block
                            if (isFirstBlock || lineIdx > 0) {
                                const blockHeight = lineY - codeStartY;
                                doc.setFillColor(13, 17, 23);
                                doc.roundedRect(margin, codeStartY, contentWidth, Math.min(blockHeight, pageHeight - codeStartY - 20), 2, 2, 'F');
                                // Re-render lines for this block
                                doc.setTextColor(86, 156, 214); // Blue syntax color
                                const startIdx = isFirstBlock ? 0 : lineIdx - Math.floor((lineY - codeStartY - codePadding) / lineHeight);
                                for (let i = startIdx; i < lineIdx; i++) {
                                    const y = codeStartY + codePadding + ((i - startIdx) * lineHeight);
                                    if (y < pageHeight - 20) {
                                        doc.text(codeLines[i], margin + 6, y);
                                    }
                                }
                            }

                            doc.addPage();
                            codeStartY = margin;
                            isFirstBlock = false;
                        }
                    });

                    // Render final code block
                    const finalBlockHeight = Math.min(codeLines.length * lineHeight + codePadding * 2, pageHeight - codeStartY - 20);
                    doc.setFillColor(13, 17, 23); // Dark code bg
                    doc.roundedRect(margin, codeStartY, contentWidth, finalBlockHeight, 2, 2, 'F');

                    // Add subtle border
                    doc.setDrawColor(48, 54, 61);
                    doc.setLineWidth(0.5);
                    doc.roundedRect(margin, codeStartY, contentWidth, finalBlockHeight, 2, 2, 'S');

                    // Render code text
                    doc.setTextColor(86, 156, 214); // Blue syntax color for better readability
                    let currentLineY = codeStartY + codePadding;
                    codeLines.forEach((line: string) => {
                        if (currentLineY < codeStartY + finalBlockHeight - 2) {
                            doc.text(line, margin + 6, currentLineY);
                            currentLineY += lineHeight;
                        }
                    });

                    yPos = codeStartY + finalBlockHeight + 10;
                });
            }

            // === FOOTER ON ALL PAGES ===
            const totalPages = doc.getNumberOfPages();
            for (let i = 1; i <= totalPages; i++) {
                doc.setPage(i);
                doc.setFontSize(8);
                doc.setTextColor(150, 150, 150);
                doc.text(`AEGIS Security Report - Page ${i} of ${totalPages}`, pageWidth / 2, pageHeight - 10, { align: 'center' });
            }

            // Generate PDF blob
            const pdfBlob = doc.output('blob');
            const pdfArrayBuffer = await pdfBlob.arrayBuffer();
            const pdfBase64 = btoa(
                new Uint8Array(pdfArrayBuffer).reduce((data, byte) => data + String.fromCharCode(byte), '')
            );

            // Create filename
            const timestamp = new Date().toISOString().split('T')[0];
            const pdfReportId = report?.report_id || report?.report_metadata?.analysis_id || 'report';
            const filename = `aegis_report_${pdfReportId}_${timestamp}.pdf`;

            // Use Electron's native save dialog
            const result = await window.fileAPI.saveWithDialog({
                defaultFilename: filename,
                content: pdfBase64,
                encoding: 'base64',
                filters: [
                    { name: 'PDF Files', extensions: ['pdf'] },
                    { name: 'All Files', extensions: ['*'] }
                ]
            });

            if (result.success) {
                toast.success(`PDF saved to ${result.filePath}`);
            } else if (result.canceled) {
                // User canceled - no message needed
            } else {
                toast.error(result.error || 'Failed to save PDF');
            }

            setShowExportMenu(false);
        } catch (error) {
            console.error('Failed to export PDF:', error);
            toast.error('Failed to export PDF report');
        }
    };

    // HTML export handler — self-contained HTML matching the dark theme
    const handleExportHTML = async () => {
        if (!report) {
            toast.error('No report data to export');
            return;
        }

        try {
            const pathsToExport = (report.paths || report.critical_attack_paths || []).filter(hasAttackSteps);
            const reportId = report?.report_id || report?.report_metadata?.analysis_id || 'report';
            const generatedAt = report?.generated_at || report?.report_metadata?.generated_at || new Date().toISOString();
            const domainName = report?.domain_overview?.domain_name || 'Unknown Domain';

            const sevCSS: Record<string, { bg: string }> = {
                Critical: { bg: '#dc2626' },
                High: { bg: '#ea580c' },
                Medium: { bg: '#ca8a04' },
                Low: { bg: '#16a34a' },
            };

            const esc = (str: string) =>
                String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

            // Convert markdown bold (**text**) to <strong> after escaping
            const md = (str: string) =>
                esc(str).replace(/\*\*([^*]+)\*\*/g, '<strong style="color:#e6edf3;">$1</strong>');

            // Syntax-highlight a command block: comments gray, prompts dim, commands green
            const highlightCmd = (cmd: string) => {
                return esc(cmd).split('\n').map(line => {
                    const trimmed = line.trimStart();
                    // Comments — gray italic
                    if (trimmed.startsWith('#')) {
                        return `<span style="color:#6e7681;font-style:italic;">${line}</span>`;
                    }
                    // Shell prompt lines ($ command)
                    if (trimmed.startsWith('$ ')) {
                        const idx = line.indexOf('$ ');
                        const prefix = line.slice(0, idx + 2);
                        const rest = line.slice(idx + 2);
                        return `<span style="color:#8b949e;">${prefix}</span><span style="color:#7ee787;">${rest}</span>`;
                    }
                    // PowerShell prompt lines (PS > command)
                    if (trimmed.startsWith('PS &gt;')) {
                        const idx = line.indexOf('PS &gt;');
                        const prefix = line.slice(0, idx + 7);
                        const rest = line.slice(idx + 7);
                        return `<span style="color:#8b949e;">${prefix}</span><span style="color:#7ee787;">${rest}</span>`;
                    }
                    // Empty lines
                    if (trimmed === '') {
                        return line;
                    }
                    // Default: command/code text in green
                    return `<span style="color:#7ee787;">${line}</span>`;
                }).join('\n');
            };

            // Build findings summary rows
            const summaryRows = pathsToExport.map((path: any, i: number) => {
                const f = path.pentest_finding;
                const sev = f?.severity || 'Medium';
                const bg = (sevCSS[sev] || sevCSS.Medium).bg;
                return `<tr class="summary-row" onclick="document.getElementById('finding-${i + 1}').scrollIntoView({behavior:'smooth'})">
                    <td class="tc finding-num">${i + 1}</td>
                    <td class="tl finding-name">${esc(f?.title || path.title || '')}</td>
                    <td class="tc"><span class="sev-badge" style="background:${bg};">${sev}</span></td>
                    <td class="tc">${esc(f?.attack_complexity || 'Medium')}</td>
                    <td class="tc">${esc(f?.category || '')}</td>
                </tr>`;
            }).join('\n');

            // Build finding sections
            const findingSections = pathsToExport.map((path: any, i: number) => {
                const f = path.pentest_finding;
                if (!f) return '';
                const sev = f.severity || 'Medium';
                const bg = (sevCSS[sev] || sevCSS.Medium).bg;

                // Observation
                const observation = md(f.observation || 'No observation provided.');

                // Understanding Q&A
                const qaItems = f.understanding || [];
                const qaHtml = qaItems.map((qa: any, qIdx: number) =>
                    `<div class="qa-item">
                        <div class="qa-q">${md(qa.question || '')}</div>
                        <div class="qa-a">${md(qa.answer || '')}</div>
                    </div>${qIdx < qaItems.length - 1 ? '<div class="qa-divider"></div>' : ''}`
                ).join('');

                // Affected entities table
                const entities = f.affected_entities || [];
                let entitiesHtml = '';
                if (entities.length > 0) {
                    const thirdColHeader = entities[0]?.target_group ? 'Target Group' : entities[0]?.spn ? 'SPN' : 'Path';
                    const hasRisk = entities.some((e: any) => typeof e === 'object' && e.risk);
                    const fourthColHeader = hasRisk ? 'Risk' : 'Path';

                    const MAX_ENTITIES = 20;
                    const displayEntities = entities.slice(0, MAX_ENTITIES);
                    const remainingCount = entities.length - displayEntities.length;

                    const rows = displayEntities.map((e: any) => {
                        const principal = esc(typeof e === 'string' ? e : e.principal || e.name || e.entity || '');
                        const type = esc(typeof e === 'object' ? (e.type || '') : '');
                        const target = esc(typeof e === 'object' ? (e.target_group || e.spn || e.path || '') : '');
                        const fourthCol = hasRisk
                            ? (typeof e === 'object' && e.risk ? e.risk : '-')
                            : (typeof e === 'object' ? (e.path || '-') : '-');
                        return `<tr>
                            <td class="tl" style="color:#c9d1d9;font-family:monospace;font-size:13px;">${principal}</td>
                            <td class="tc" style="color:#8b949e;">${type}</td>
                            <td class="tl" style="color:#c9d1d9;font-size:13px;">${target}</td>
                            <td class="tc" style="color:#8b949e;">${esc(fourthCol)}</td>
                        </tr>`;
                    }).join('');

                    const overflowNote = remainingCount > 0
                        ? `<div style="padding:10px 14px;color:#8b949e;font-size:13px;text-align:center;border-top:1px solid #30363d;">...and ${remainingCount} more entit${remainingCount !== 1 ? 'ies' : 'y'} (see JSON export for full list)</div>`
                        : '';

                    entitiesHtml = `
                    <div class="section">
                        <div class="section-title"><svg viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>Affected Entities</div>
                        <div class="entity-count">${entities.length} affected entit${entities.length !== 1 ? 'ies' : 'y'}${remainingCount > 0 ? ` (showing first ${MAX_ENTITIES})` : ''}</div>
                        <table class="entity-table">
                            <thead><tr>
                                <th class="tl">Principal</th><th class="tc">Type</th>
                                <th class="tl">${thirdColHeader}</th>
                                <th class="tc">${fourthColHeader}</th>
                            </tr></thead>
                            <tbody>${rows}</tbody>
                        </table>
                        ${overflowNote}
                    </div>`;
                }

                // Attack steps
                const stepsHtml = (f.attack_steps || []).map((step: any) => {
                    // Objective
                    const objective = step.objective || step.description || '';

                    // Prerequisites
                    const prereqs = step.prerequisites || [];
                    const prereqHtml = prereqs.length > 0
                        ? `<div class="prereq-box">
                            <div class="prereq-title"><svg style="width:18px;height:18px;display:inline;vertical-align:middle;margin-right:4px;" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>Prerequisites</div>
                            <ul class="prereq-list">${prereqs.map((p: string) => `<li>${md(p)}</li>`).join('')}</ul>
                          </div>`
                        : '';

                    // OPSEC options
                    const optionsHtml = (step.opsec_options || []).map((opt: any, optIdx: number) => {
                        const isSafe = (opt.opsec_level || '').toLowerCase() === 'safe';
                        const badgeClass = isSafe ? 'opsec-safe' : 'opsec-risky';
                        const badgeLabel = isSafe
                            ? '<svg style="width:14px;height:14px;display:inline;vertical-align:middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg> OPSEC-SAFE'
                            : '<svg style="width:14px;height:14px;display:inline;vertical-align:middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg> May trigger AV/EDR';
                        const divider = optIdx > 0 ? '<div class="opsec-divider"></div>' : '';

                        // AMSI bypass note
                        const amsiHtml = opt.amsi_bypass?.required
                            ? `<div class="amsi-note"><svg style="width:14px;height:14px;display:inline;vertical-align:middle;margin-right:4px;" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg><strong>AMSI Bypass Required:</strong> Run AMSI bypass before executing (see Appendix)</div>`
                            : '';

                        return `${divider}
                        <div class="opsec-option">
                            <div class="opsec-header">
                                <span class="${badgeClass}">${badgeLabel}</span>
                                <span class="tool-name">${esc(opt.tool_name || '')}</span>
                            </div>
                            ${amsiHtml}
                            <div class="cmd-block">${highlightCmd(opt.command || '')}</div>
                            ${opt.explanation ? `<div class="cmd-explain">${esc(opt.explanation)}</div>` : ''}
                        </div>`;
                    }).join('');

                    return `<div class="step-card">
                        <div class="step-header">
                            <span class="step-num">${step.step_number || ''}</span>
                            <span class="step-title">${esc(step.title || '')}</span>
                            ${step.category ? `<span class="step-cat">${esc(step.category)}</span>` : ''}
                        </div>
                        ${objective ? `<div class="step-objective"><span class="obj-label"><svg style="width:18px;height:18px;display:inline;vertical-align:middle;margin-right:4px;" viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>Objective</span><div>${md(objective)}</div></div>` : ''}
                        ${prereqHtml}
                        <div class="step-options">${optionsHtml}</div>
                    </div>`;
                }).join('');

                // Risk section
                const riskHtml = f.risk_description
                    ? `<div class="section">
                        <div class="section-title" style="color:#f85149;"><svg viewBox="0 0 24 24" fill="none" stroke="#f85149" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>${esc(f.risk_title || 'Risk Assessment')}</div>
                        <div class="risk-box">${md(f.risk_description)}</div>
                    </div>`
                    : '';

                // Remediation — remediation_steps is string[], not objects
                const remSteps = (f.remediation_steps || []).map((step: any) => {
                    const text = typeof step === 'string' ? step : (step.title || step.action || step.description || '');
                    return `<li style="color:#c9d1d9;margin-bottom:6px;">${md(text)}</li>`;
                }).join('');

                const remScript = f.remediation_script
                    ? `<div class="cmd-block" style="margin-top:12px;">${highlightCmd(f.remediation_script)}</div>`
                    : '';

                return `
                <details class="finding" id="finding-${i + 1}">
                    <summary class="finding-header">
                        <div class="finding-sev" style="background:${bg};">${sev}</div>
                        <div class="finding-info">
                            <div class="finding-title">${esc(f.title || path.title || '')}</div>
                            <div class="finding-meta">
                                Complexity: <span style="color:#facc15;font-weight:600;">${esc(f.attack_complexity || 'Medium')}</span>
                                ${f.category ? ` &bull; Category: ${esc(f.category)}` : ''}
                            </div>
                        </div>
                        <div class="finding-chevron"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#8b949e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg></div>
                    </summary>
                    <div class="finding-body">
                        <div class="section">
                            <div class="section-title"><svg viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>Observation</div>
                            <div class="obs-text">${observation}</div>
                        </div>
                        ${qaHtml ? `<div class="section">
                            <div class="section-title"><svg viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Understanding the Attack</div>
                            <div class="qa-container">${qaHtml}</div>
                        </div>` : ''}
                        ${entitiesHtml}
                        <div class="section">
                            <div class="section-title"><svg viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>Attack Steps</div>
                            ${stepsHtml}
                        </div>
                        ${riskHtml}
                        ${remSteps ? `<div class="section">
                            <div class="section-title" style="color:#3fb950;"><svg viewBox="0 0 24 24" fill="none" stroke="#3fb950" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Remediation</div>
                            <div class="rem-box">
                                <div style="display:flex;align-items:center;gap:8px;color:#7ee787;font-weight:600;margin-bottom:10px;"><svg style="width:16px;height:16px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>Recommended Actions</div>
                                <ol style="padding-left:20px;margin:0;">${remSteps}</ol>
                                ${remScript}
                            </div>
                        </div>` : ''}
                        ${(f.references && f.references.length > 0) ? `<div class="section">
                            <div class="section-title"><svg viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>References</div>
                            <div style="display:flex;flex-wrap:wrap;gap:8px;">
                                ${f.references.map((ref: any) => {
                                    const tag = esc(typeof ref === 'string' ? '' : ref.tag || '');
                                    const title = esc(typeof ref === 'string' ? ref : ref.title || '');
                                    const url = typeof ref === 'string' ? '' : ref.url || '';
                                    return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer" style="display:inline-flex;align-items:center;gap:8px;padding:10px 16px;background:#161b22;border:1px solid #30363d;border-radius:8px;color:#58a6ff;font-size:15px;text-decoration:none;">
                                        ${tag ? `<span style="background:#21262d;color:#8b949e;padding:3px 8px;border-radius:4px;font-size:13px;font-weight:600;">${tag}</span>` : ''}
                                        ${title}
                                    </a>`;
                                }).join('')}
                            </div>
                        </div>` : ''}
                    </div>
                </details>`;
            }).join('\n');

            // Executive summary with markdown conversion
            const execSummary = report?.executive_summary
                ? md(report.executive_summary).replace(/\n/g, '<br>')
                : '';

            const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS Report - ${esc(domainName)}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html{scroll-behavior:smooth}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}
.container{max-width:1100px;margin:0 auto;padding:40px 24px}
strong{color:#e6edf3}
h2{color:#e6edf3;font-size:24px;font-weight:700;margin:32px 0 16px;display:flex;align-items:center;gap:10px}
h2 svg{width:24px;height:24px;flex-shrink:0}
.divider{height:1px;background:#30363d;margin:40px 0}

/* Summary table */
.summary-table{width:100%;border-collapse:collapse;background:#161b22;border-radius:10px;overflow:hidden;margin-bottom:8px}
.summary-table thead tr{background:#21262d}
.summary-table th{padding:10px 12px;color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid #30363d}
.summary-table td{padding:10px 12px;border-bottom:1px solid #21262d;color:#8b949e}
.tl{text-align:left}.tc{text-align:center}
.summary-row{cursor:pointer;transition:background 0.15s}
.summary-row:hover{background:#21262d}
.summary-row:hover .finding-num,.summary-row:hover .finding-name{color:#58a6ff}
.sev-badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:700;color:#fff}

/* Finding card — collapsible */
.finding{margin-bottom:32px;border:1px solid #30363d;border-radius:12px;overflow:hidden}
.finding-header{display:flex;align-items:stretch;cursor:pointer;list-style:none}
.finding-header::-webkit-details-marker{display:none}
.finding-header:focus{outline:none}
.finding-header:hover .finding-info{background:#1c2128}
.finding-header:hover .finding-chevron{background:#1c2128}
.finding-sev{color:#fff;padding:18px;font-weight:700;font-size:14px;width:100px;flex-shrink:0;display:flex;align-items:center;justify-content:center;text-transform:uppercase;letter-spacing:0.05em}
.finding-info{flex:1;padding:14px 20px;background:#161b22;transition:background 0.15s;min-width:0}
.finding-title{font-size:22px;font-weight:600;color:#fff;margin-bottom:4px}
.finding-meta{font-size:13px;color:#8b949e}
.finding-chevron{display:flex;align-items:center;padding:0 16px;background:#161b22;transition:background 0.15s;flex-shrink:0}
.finding-chevron svg{transition:transform 0.3s ease}
.finding[open] .finding-chevron svg{transform:rotate(180deg)}
.finding-body{padding:24px;background:#0d1117;border-top:1px solid #30363d}

/* Sections */
.section{margin-bottom:28px}
.section-title{color:#58a6ff;font-size:17px;text-transform:uppercase;letter-spacing:0.1em;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:10px}
.section-title svg{width:22px;height:22px;flex-shrink:0}
.obs-text{color:#c9d1d9;line-height:1.8;background:#161b22;padding:16px;border-radius:8px;border:1px solid #21262d}

/* Q&A */
.qa-container{background:#161b22;padding:16px;border-radius:8px;border:1px solid #21262d}
.qa-item{margin-bottom:16px}.qa-item:last-child{margin-bottom:0}
.qa-divider{height:1px;background:#30363d;margin:20px 0}
.qa-q{color:#58a6ff;font-weight:600;font-size:18px;margin-bottom:8px}
.qa-a{color:#c9d1d9;line-height:1.7}

/* Entity table */
.entity-count{font-size:14px;color:#8b949e;margin-bottom:10px}
.entity-table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden}
.entity-table th{padding:10px 14px;background:#21262d;color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid #30363d}
.entity-table td{padding:10px 14px;border-bottom:1px solid #21262d;color:#c9d1d9;font-size:15px}

/* Attack step card */
.step-card{background:#0d1117;border:1px solid #30363d;border-radius:12px;overflow:hidden;margin-bottom:16px}
.step-header{display:flex;align-items:center;gap:12px;padding:14px 18px;background:#161b22;border-bottom:1px solid #30363d}
.step-num{background:#58a6ff;color:#0d1117;width:28px;height:28px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;flex-shrink:0}
.step-title{flex:1;font-weight:600;color:#fff;font-size:18px}
.step-cat{padding:2px 8px;background:#21262d;border:1px solid #30363d;border-radius:4px;font-size:11px;color:#8b949e}
.step-objective{padding:14px 18px;border-bottom:1px solid #30363d;color:#c9d1d9;font-size:15px;line-height:1.7}
.obj-label{display:inline-block;color:#58a6ff;font-size:15px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px}
.step-options{padding:16px 18px}

/* Prerequisites */
.prereq-box{padding:14px 18px 14px 22px;border-bottom:1px solid #30363d}
.prereq-title{color:#fbbf24;font-size:15px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:10px}
.prereq-list{list-style:none;padding:0;margin:0}
.prereq-list li{color:#c9d1d9;font-size:15px;padding:4px 0;padding-left:16px;position:relative;line-height:1.6}
.prereq-list li::before{content:"\\2022";color:#7ee787;position:absolute;left:0}

/* OPSEC options */
.opsec-divider{height:1px;background:#30363d;margin:16px 0}
.opsec-option{margin-bottom:4px}
.opsec-header{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.opsec-safe{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:5px;font-size:13px;font-weight:600;background:rgba(34,197,94,0.15);color:#22c55e}
.opsec-risky{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:5px;font-size:13px;font-weight:600;background:rgba(239,68,68,0.15);color:#ef4444}
.tool-name{font-size:17px;font-weight:600;color:#fff}
.cmd-block{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:14px;font-family:'Fira Code','Cascadia Code','JetBrains Mono','SF Mono',monospace;font-size:13px;color:#7ee787;white-space:pre-wrap;overflow-x:auto;line-height:1.5}
.cmd-explain{padding:12px 16px;margin-top:10px;background:#161b22;color:#8b949e;font-size:13px;line-height:1.6;border:1px solid #30363d;border-radius:8px}
.amsi-note{padding:12px 16px;background:transparent;border:1px solid rgba(251,191,36,0.4);border-radius:6px;color:#fbbf24;font-size:14px;margin-bottom:12px;line-height:1.5}

/* Risk box */
.risk-box{background:rgba(248,81,73,0.08);border:1px solid rgba(248,81,73,0.3);border-radius:8px;padding:16px;color:#c9d1d9;line-height:1.7}

/* Remediation */
.rem-box{background:rgba(126,231,135,0.08);border:1px solid rgba(126,231,135,0.3);border-radius:8px;padding:16px}

/* Metadata items */
.meta-item{flex:1;text-align:center;padding:24px 28px}
.meta-item strong{color:#fff;display:block;font-size:18px;margin-bottom:6px}
.meta-item span{color:#8b949e;font-size:13px}
.meta-divider{width:1px;height:72px;background:#30363d;flex-shrink:0}

/* Exec summary */
.exec-summary{color:#c9d1d9;line-height:1.8;margin-bottom:8px}

/* Footer */
.footer{text-align:center;padding:40px 0 20px;color:#484f58;font-size:12px;border-top:1px solid #21262d;margin-top:40px}

@media print{
    body{background:#fff;color:#1a1a1a}
    .finding-body,.obs-text,.qa-container,.step-card{background:#f9f9f9;border-color:#ddd}
    .cmd-block{background:#f0f0f0;color:#1a1a1a;border-color:#ddd}
    .step-header{background:#f5f5f5}
}
</style>
</head>
<body>
<div class="container">
    <div style="text-align:center;padding:80px 0 48px;">
        <pre style="color:#3b82f6;font-family:'Fira Code','Cascadia Code','JetBrains Mono',monospace;font-size:20px;line-height:1.1;display:inline-block;text-align:left;margin:0 auto;">
 █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝</pre>
        <div style="color:#e6edf3;font-size:28px;margin-top:24px;font-weight:500;">Attack Path Intelligence Report</div>
        <div style="color:#8b949e;font-size:17px;margin-top:10px;">RAG-powered analysis of critical attack paths in Active Directory</div>
    </div>

    <div style="display:flex;align-items:center;justify-content:center;gap:0;margin-bottom:8px;">
        <div class="meta-item"><strong>${esc(String(reportId).split('-')[0])}</strong><span>Report ID</span></div>
        <div class="meta-divider"></div>
        <div class="meta-item"><strong>${new Date(generatedAt).toLocaleDateString()} ${new Date(generatedAt).toLocaleTimeString()}</strong><span>Generated</span></div>
    </div>

    ${report?.domain_overview ? (() => {
                const dov = report.domain_overview;
                const statItems = [
                    { label: 'Total Users', value: dov.total_users || 0 },
                    { label: 'Total Groups', value: dov.total_groups || 0 },
                    { label: 'Total Computers', value: dov.total_computers || 0 },
                ];
                return `
    <div class="divider"></div>
    <h2><svg viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2"><path d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg>Domain Overview</h2>
    <div style="background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden;margin-bottom:8px;">
        <div style="padding:16px 24px;border-bottom:1px solid #30363d;display:flex;flex-wrap:wrap;gap:32px;">
            <div><span style="color:#8b949e;font-size:13px;">Domain:</span> <strong style="color:#fff;margin-left:6px;">${esc(dov.domain_name || domainName)}</strong></div>
            ${dov.forest_name ? `<div><span style="color:#8b949e;font-size:13px;">Forest:</span> <strong style="color:#fff;margin-left:6px;">${esc(dov.forest_name)}</strong></div>` : ''}
            ${dov.functional_level ? `<div><span style="color:#8b949e;font-size:13px;">Functional Level:</span> <span style="color:#58a6ff;font-weight:500;margin-left:6px;">${esc(dov.functional_level)}</span></div>` : ''}
        </div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:#30363d;">
            ${statItems.map(s => `<div style="background:#161b22;padding:16px 24px;text-align:center;">
                <div style="font-size:24px;font-weight:700;color:#fff;">${Number(s.value).toLocaleString()}</div>
                <div style="font-size:13px;color:#8b949e;">${s.label}</div>
            </div>`).join('')}
        </div>
    </div>`;
            })() : ''}

    <div class="divider"></div>
    <h2><svg viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"/></svg>Findings Summary</h2>
    <table class="summary-table">
        <thead><tr>
            <th class="tl">#</th><th class="tl">Finding</th><th class="tc">Severity</th><th class="tc">Complexity</th><th class="tc">Category</th>
        </tr></thead>
        <tbody>${summaryRows}</tbody>
    </table>

    ${execSummary ? `<div class="divider"></div><h2><svg viewBox="0 0 24 24" fill="none" stroke="#58a6ff" stroke-width="2"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>Executive Summary</h2><div class="exec-summary">${execSummary}</div>` : ''}

    <div class="divider"></div>
    <div style="border-left:4px solid #58a6ff;padding-left:16px;margin-bottom:24px;">
        <div style="display:flex;align-items:baseline;gap:12px;margin-bottom:4px;">
            <h2 style="margin:0;">Actionable Findings</h2>
            <span style="font-size:18px;color:#8b949e;">(${pathsToExport.length} finding${pathsToExport.length !== 1 ? 's' : ''})</span>
        </div>
        <p style="color:#8b949e;font-size:15px;margin:0;">Detailed analysis of vulnerabilities requiring remediation</p>
    </div>
    ${findingSections}

    ${report?.amsi_appendix?.techniques?.length > 0 ? `
    <div style="height:1px;background:#30363d;margin:48px 0;"></div>
    <div id="amsi-appendix">
        <h2 style="color:#fbbf24;display:flex;align-items:center;gap:10px;"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>${esc(report.amsi_appendix.title || 'AMSI Bypass Reference')}</h2>
        <p style="color:#8b949e;font-size:13px;margin-bottom:4px;">Pre-validated bypass techniques for PowerShell offensive tools</p>
        <div style="background:#0d1117;border:1px solid #30363d;border-radius:12px;padding:24px;margin-top:14px;">
            <p style="color:#c9d1d9;margin-bottom:20px;">${esc(report.amsi_appendix.description || '')}</p>
            ${report.amsi_appendix.techniques.map((tech: any) => `
                <div style="border:1px solid #30363d;border-radius:8px;overflow:hidden;margin-bottom:16px;">
                    <div style="background:#161b22;padding:12px 16px;border-bottom:1px solid #30363d;display:flex;align-items:center;justify-content:space-between;">
                        <span style="font-weight:600;color:#fff;">${esc(tech.name || '')}</span>
                        <span style="font-size:11px;padding:2px 8px;background:#21262d;color:#8b949e;border-radius:4px;">${esc(tech.family || '')}</span>
                    </div>
                    ${tech.description ? `<div style="padding:8px 16px;color:#8b949e;font-size:13px;border-bottom:1px solid #30363d;">${esc(tech.description)}</div>` : ''}
                    <div class="cmd-block" style="border:0;border-radius:0;">${highlightCmd(tech.code || '')}</div>
                </div>
            `).join('')}
        </div>
    </div>
    ` : ''}

    <div class="footer">Generated by AEGIS &mdash; Attack Path Intelligence Platform<br>Data collected using BloodHound Community Edition</div>
</div>
</body>
</html>`;

            const now = new Date();
            const timestamp = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}_${String(now.getHours()).padStart(2,'0')}${String(now.getMinutes()).padStart(2,'0')}${String(now.getSeconds()).padStart(2,'0')}`;
            const filename = `aegis_report_${domainName.replace(/[^a-zA-Z0-9]/g, '_')}_${timestamp}.html`;

            const result = await window.fileAPI.saveWithDialog({
                defaultFilename: filename,
                content: html,
                filters: [
                    { name: 'HTML Files', extensions: ['html'] },
                    { name: 'All Files', extensions: ['*'] }
                ]
            });

            if (result.success) {
                toast.success(`HTML report saved to ${result.filePath}`);
            } else if (result.canceled) {
                // User canceled
            } else {
                toast.error(result.error || 'Failed to save HTML report');
            }

            setShowExportMenu(false);
        } catch (error) {
            console.error('Failed to export HTML:', error);
            toast.error('Failed to export HTML report');
        }
    };

    // Refs for graph components to call resetView
    const graphRefs = useRef<{ [key: number]: AttackPathGraphRef | null }>({});

    // Debug: Log RAG report structure (minimal logging to prevent ENOBUFS)
    React.useEffect(() => {
        if (report) {
            // Only log summary info, not full JSON (prevents Electron ENOBUFS error)
            const paths = report?.paths || report?.critical_attack_paths || [];
            console.log('RAG Report loaded:', {
                hasReport: !!report,
                pathCount: paths.length,
                tier0Stats: report?.tier0_statistics,
                hasExecutiveSummary: !!report?.executive_summary,
                keys: Object.keys(report || {})
            });

            if (paths.length > 0) {
                const firstPath = paths[0];
                console.log('First Attack Path summary:', {
                    keys: Object.keys(firstPath),
                    classification: firstPath?.classification,
                    hasResults: !!firstPath?.results,
                    resultCount: firstPath?.results?.length || 0
                });
            }
        }
    }, [report]);

    // Extract analysis ID from prop, report metadata, or fallback
    const analysisId = propAnalysisId ||
        report?.report_metadata?.analysis_id ||
        report?.analysis_id ||
        report?.report_id ||
        report?.metadata?.analysis_id ||
        'unknown';

    // Extract and normalize report data
    const extractReportData = (rawReport: any) => {
        if (!rawReport) return null;

        return {
            analysisDate: rawReport?.report_metadata?.generated_at ||
                rawReport?.metadata?.timestamp ||
                rawReport?.generated_at ||
                new Date().toISOString(),
            reportId: rawReport?.report_metadata?.analysis_id ||
                rawReport?.analysis_id ||
                rawReport?.report_id ||
                'Generated Report',
            attackPaths: rawReport?.paths || rawReport?.critical_attack_paths || [],
            executiveSummary: rawReport?.executive_summary || '',
            // recommendations removed — did not add value to the report
            // Additional findings from chat queries
            additionalFindings: (rawReport?.additional_findings || []) as AdditionalFinding[],
            // Extract domain overview stats
            domainOverview: rawReport?.domain_overview || null,
            // Extract embedded graph data for visualization
            graph: rawReport?.graph || null,
            // Extract proper path data from paths (fallback to critical_attack_paths for backwards compat)
            paths: (rawReport?.paths || rawReport?.critical_attack_paths || []).map((path: any) => ({
                ...path,
                // Path overview data
                pathOverview: path?.path_overview || {
                    path_length: path?.attack_chain?.length || path?.steps?.length || path?.path_length || null,
                    attack_complexity: path?.risk_assessment?.complexity || path?.complexity || path?.path_overview?.complexity || 'Medium',
                    business_impact: path?.risk_assessment?.business_impact || path?.business_impact || path?.path_overview?.business_impact || 'High',
                    estimated_exploitation_time: path?.path_overview?.estimated_exploitation_time || path?.estimated_time || null,
                    priority: path?.query_info?.priority || path?.priority || path?.path_overview?.priority || 'High'
                },
                // Attack scenario/commands - check multiple possible keys
                attackScenario: (() => {
                    const candidates = [
                        path?.attack_scenario,
                        path?.attackScenario,
                        path?.exploitation_steps,
                        path?.exploitationSteps,
                        path?.attack_commands,
                        path?.attackCommands,
                        path?.commands,
                        path?.attack_steps,
                        path?.attackSteps
                    ];

                    for (const candidate of candidates) {
                        if (candidate != null) {
                            if (typeof candidate === 'string' && candidate.trim().length > 0) {
                                return candidate;
                            }
                            if (Array.isArray(candidate) && candidate.length > 0) {
                                return candidate;
                            }
                            if (typeof candidate === 'object' && !Array.isArray(candidate)) {
                                return candidate;
                            }
                        }
                    }
                    return null;
                })(),
                // Technical analysis
                technicalAnalysis: path?.technical_analysis || path?.technical_explanation || '',
                // Remediation - Support both legacy and enhanced formats
                remediationStrategy: path?.remediation_strategy || path?.mitigation_steps || path?.remediation || [],
                // Enhanced remediation data from RemediationService
                detailedRemediations: path?.detailed_remediations || null,
                // MITRE mapping
                mitreMapping: path?.mitre_mapping || path?.mitre_attack || path?.attack_techniques || [],
                // Title and type
                title: path?.query_info?.name || path?.name || path?.title || `Attack Path ${path?.scenario_number || ''}`,
                attackType: path?.query_info?.attack_type || path?.attack_type || path?.type || 'Unknown Type',
                // Query information
                query_info: {
                    ...path?.query_info,
                    cypher_query: path?.query_info?.cypher_query || path?.query_info?.cypher || path?.cypher_query || path?.cypher || path?.query || '',
                    cypher: path?.query_info?.cypher || path?.cypher || path?.query || '',
                    edges_used: path?.query_info?.edges_used || path?.edges_used || [],
                    query_description: path?.query_info?.query_description || path?.query_info?.description || path?.description || ''
                },
                // Context-aware analysis data (phased attack narrative, prioritized remediation)
                context_aware: path?.context_aware || null,
                // NEW: Pentest-style finding data
                pentest_finding: path?.pentest_finding || null
            })),
            // AMSI bypass appendix (techniques for PowerShell tools)
            amsi_appendix: rawReport?.amsi_appendix || null
        };
    };

    // Severity badge colors for summary table
    const severityTagColors: Record<FindingSeverity, string> = {
        Critical: 'bg-red-600 text-white border-red-600',
        High: 'bg-orange-500 text-white border-orange-500',
        Medium: 'bg-yellow-600 text-white border-yellow-600',
        Low: 'bg-green-500 text-white border-green-500',
    };

    const reportData = extractReportData(report);

    // Get actionable paths: only show findings that have at least one attack step
    const actionablePaths = (reportData?.attackPaths || []).filter(hasAttackSteps);

    const openFullScreenGraph = (pathNumber: number, attackName?: string) => {
        setFullScreenGraph({ pathNumber, analysisId, attackName });
    };

    const closeFullScreenGraph = () => {
        setFullScreenGraph(null);
    };

    const handleNodeClick = (node: GraphNode) => {
        console.log('Node selected:', node);
        setSelectedNode(node);
        setSelectedEdge(null);
    };

    const handleEdgeClick = (edge: GraphEdge) => {
        console.log('Edge selected:', edge);
        setSelectedEdge(edge);
        setSelectedNode(null);
    };

    const copyToClipboard = async (text: string) => {
        try {
            await navigator.clipboard.writeText(text);
            console.log('Copied to clipboard:', text.substring(0, 50) + '...');
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    if (!report) {
        return (
            <div className="min-h-screen bg-aegis-dark flex items-center justify-center">
                <div className="text-center">
                    <p className="text-aegis-text mb-4">No report data available</p>
                    {onBack && (
                        <button onClick={onBack} className="px-6 py-2 bg-aegis-accent hover:bg-aegis-accent-hover rounded-lg transition-colors">
                            Go Back
                        </button>
                    )}
                </div>
            </div>
        );
    }

    return (
        <>
            <div className="min-h-screen bg-aegis-dark">
                {/* Header Actions */}
                <div className="sticky top-0 bg-aegis-dark/95 backdrop-blur z-10">
                    <div className="px-4 py-2 flex items-center justify-between">
                        {/* Left side - Close button */}
                        <div>
                            {onBack && (
                                <button
                                    onClick={onBack}
                                    className="text-aegis-text-muted hover:text-aegis-text transition-colors text-sm flex items-center gap-2"
                                    title={isFullScreen ? "Exit fullscreen" : "Close report"}
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" className="size-6">
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18 18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            )}
                        </div>

                        {/* Right side - Search, Export JSON and Fullscreen buttons */}
                        <div className="flex items-center gap-2">
                            {/* Search button and input */}
                            <div className="relative">
                                {isSearchOpen ? (
                                    <div className="flex items-center gap-2">
                                        <div className="relative">
                                            <input
                                                ref={searchInputRef}
                                                type="text"
                                                value={searchQuery}
                                                onChange={(e) => setSearchQuery(e.target.value)}
                                                onKeyDown={handleSearchKeyDown}
                                                placeholder="Search findings..."
                                                className="w-64 px-3 py-1.5 pl-9 bg-[#21262d] border border-[#30363d] rounded-lg text-sm text-white placeholder-[#8b949e] focus:outline-none focus:border-[#58a6ff] focus:ring-1 focus:ring-[#58a6ff]"
                                            />
                                            <svg
                                                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#8b949e]"
                                                fill="none"
                                                stroke="currentColor"
                                                viewBox="0 0 24 24"
                                            >
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                            </svg>

                                            {/* Auto-suggestions dropdown */}
                                            {filteredSuggestions.length > 0 && (
                                                <div className="absolute top-full left-0 right-0 mt-1 bg-[#161b22] border border-[#30363d] rounded-lg shadow-xl max-h-64 overflow-y-auto z-50">
                                                    {filteredSuggestions.map((suggestion) => (
                                                        <button
                                                            key={suggestion.id}
                                                            onClick={() => navigateToFinding(suggestion.id)}
                                                            className="w-full px-3 py-2 text-left hover:bg-[#21262d] transition-colors flex items-center gap-3"
                                                        >
                                                            {/* Severity badge */}
                                                            <span className={`px-2 py-0.5 rounded text-xs font-semibold ${suggestion.severity === 'Critical'
                                                                ? 'bg-red-600 text-white'
                                                                : suggestion.severity === 'High'
                                                                    ? 'bg-orange-500 text-white'
                                                                    : suggestion.severity === 'Medium'
                                                                        ? 'bg-yellow-600 text-white'
                                                                        : 'bg-green-500 text-white'
                                                                }`}>
                                                                {suggestion.severity?.slice(0, 4).toUpperCase() || 'MED'}
                                                            </span>
                                                            {/* Title */}
                                                            <span className="text-sm text-[#c9d1d9] truncate flex-1">
                                                                {suggestion.title}
                                                            </span>
                                                        </button>
                                                    ))}
                                                </div>
                                            )}

                                            {/* No results message */}
                                            {searchQuery.trim() && filteredSuggestions.length === 0 && (
                                                <div className="absolute top-full left-0 right-0 mt-1 bg-[#161b22] border border-[#30363d] rounded-lg shadow-xl p-3 z-50">
                                                    <p className="text-sm text-[#8b949e]">No findings match "{searchQuery}"</p>
                                                </div>
                                            )}
                                        </div>

                                        {/* Close search button */}
                                        <button
                                            onClick={() => { setIsSearchOpen(false); setSearchQuery(''); }}
                                            className="p-1.5 text-[#8b949e] hover:text-white hover:bg-[#21262d] rounded-lg transition-colors"
                                            title="Close search"
                                        >
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                            </svg>
                                        </button>
                                    </div>
                                ) : (
                                    <button
                                        onClick={() => setIsSearchOpen(true)}
                                        className="text-aegis-text-muted hover:text-aegis-text transition-colors text-sm flex items-center gap-2 p-1.5 rounded-lg hover:bg-aegis-gray"
                                        title="Search findings (Ctrl+F)"
                                    >
                                        <svg className="size-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                                        </svg>
                                    </button>
                                )}
                            </div>

                            {/* Export dropdown menu */}
                            <div className="relative" ref={exportMenuRef}>
                                <button
                                    onClick={() => setShowExportMenu(!showExportMenu)}
                                    className="text-aegis-text-muted hover:text-aegis-text transition-colors text-sm flex items-center gap-2 p-1.5 rounded-lg hover:bg-aegis-gray"
                                    title="Export report"
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="size-5">
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75V16.5M16.5 12 12 16.5m0 0L7.5 12m4.5 4.5V3" />
                                    </svg>
                                    <span className="hidden sm:inline">Export</span>
                                    <svg className={`size-4 transition-transform ${showExportMenu ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                    </svg>
                                </button>

                                {/* Dropdown menu */}
                                {showExportMenu && (
                                    <div className="absolute right-0 top-full mt-1 w-48 bg-[#161b22] border border-[#30363d] rounded-lg shadow-xl z-50 overflow-hidden">
                                        <button
                                            onClick={() => {
                                                handleExportJSON();
                                                setShowExportMenu(false);
                                            }}
                                            className="w-full px-4 py-2.5 text-left text-sm text-[#c9d1d9] hover:bg-[#21262d] flex items-center gap-3 transition-colors"
                                        >
                                            <svg className="size-4 text-[#58a6ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h7" />
                                            </svg>
                                            Export as JSON
                                        </button>
                                        <button
                                            onClick={handleExportPDF}
                                            className="w-full px-4 py-2.5 text-left text-sm text-[#c9d1d9] hover:bg-[#21262d] flex items-center gap-3 transition-colors border-t border-[#30363d]"
                                        >
                                            <svg className="size-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                                            </svg>
                                            Export as PDF
                                        </button>
                                        <button
                                            onClick={handleExportHTML}
                                            className="w-full px-4 py-2.5 text-left text-sm text-[#c9d1d9] hover:bg-[#21262d] flex items-center gap-3 transition-colors border-t border-[#30363d]"
                                        >
                                            <svg className="size-4 text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                                            </svg>
                                            Export as HTML
                                        </button>
                                    </div>
                                )}
                            </div>
                            {/* Fullscreen button (only show when not already fullscreen) */}
                            {onFullScreen && !isFullScreen && (
                                <button
                                    onClick={onFullScreen}
                                    className="text-aegis-text-muted hover:text-aegis-text transition-colors text-sm flex items-center gap-2 p-1.5 rounded-lg hover:bg-aegis-gray"
                                    title="View fullscreen"
                                >
                                    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="size-5">
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 3.75v4.5m0-4.5h4.5m-4.5 0L9 9M3.75 20.25v-4.5m0 4.5h4.5m-4.5 0L9 15M20.25 3.75h-4.5m4.5 0v4.5m0-4.5L15 9m5.25 11.25h-4.5m4.5 0v-4.5m0 4.5L15 15" />
                                    </svg>
                                </button>
                            )}
                        </div>
                    </div>
                </div>

                {/* Report Content */}
                <div className="max-w-[900px] mx-auto px-6 py-6 pb-32">
                    {/* Cover Section */}
                    <div className="mb-10 pb-10 border-b border-aegis-border-light">
                        <div className="text-center mb-10">
                            <pre className="text-blue-500 font-mono text-[11px] sm:text-[14px] leading-[1.1] inline-block text-left mx-auto select-none">{` █████╗ ███████╗ ██████╗ ██╗███████╗
██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
███████║█████╗  ██║  ███╗██║███████╗
██╔══██║██╔══╝  ██║   ██║██║╚════██║
██║  ██║███████╗╚██████╔╝██║███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝`}</pre>
                            <h1 className="text-3xl font-bold text-white mt-5 mb-3 tracking-tight">
                                Attack Path Intelligence Report
                            </h1>
                            <p className="text-lg text-aegis-text-muted leading-relaxed">
                                RAG-powered analysis of critical attack paths discovered in Active Directory infrastructure
                            </p>
                        </div>

                        {/* Report Stats - flat with divider */}
                        <div className="flex items-center justify-center py-6">
                            <div className="flex-1 text-center">
                                <div className="text-xl font-bold text-white">
                                    {reportData?.reportId ? String(reportData.reportId).split('-')[0] : 'Unknown'}
                                </div>
                                <div className="text-sm text-[#8b949e] mt-1">Report ID</div>
                            </div>
                            <div className="w-px h-16 bg-[#30363d] mx-6" />
                            <div className="flex-1 text-center">
                                <div className="text-xl font-bold text-white">
                                    {reportData?.analysisDate
                                        ? `${new Date(reportData.analysisDate).toLocaleDateString()} ${new Date(reportData.analysisDate).toLocaleTimeString()}`
                                        : 'Unknown'}
                                </div>
                                <div className="text-sm text-[#8b949e] mt-1">Generated</div>
                            </div>
                        </div>

                        {/* T0 Configuration Banner */}
                        {tier0Config?.enabled && (
                            <T0ConfigBanner config={tier0Config} className="mt-6" />
                        )}
                    </div>

                    {/* Domain Overview */}
                    {reportData?.domainOverview && (
                        <section className="mb-16">
                            <SectionHeader
                                title="Domain Overview"
                                subtitle={`Active Directory environment statistics${reportData.domainOverview.domain_count > 1 ? ` (${reportData.domainOverview.domain_count} domains)` : ''}`}
                                icon={
                                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                                    </svg>
                                }
                            />
                            <div className="bg-aegis-gray border border-aegis-border rounded-lg overflow-hidden">
                                {/* Domain Info Header */}
                                <div className="px-6 py-4 border-b border-aegis-border">
                                    <div className="flex flex-wrap gap-x-8 gap-y-2">
                                        {/* Show all domains if multiple, otherwise show single domain */}
                                        {reportData.domainOverview.all_domains && reportData.domainOverview.all_domains.length > 1 ? (
                                            <div className="w-full">
                                                <span className="text-aegis-text-muted text-sm">Domains:</span>
                                                <div className="mt-2 flex flex-wrap gap-2">
                                                    {reportData.domainOverview.all_domains.map((domain: string, idx: number) => (
                                                        <span
                                                            key={idx}
                                                            className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-[#21262d] text-white border border-[#30363d]"
                                                        >
                                                            <svg className="w-3.5 h-3.5 mr-1.5 text-[#58a6ff]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                                                            </svg>
                                                            {domain}
                                                        </span>
                                                    ))}
                                                </div>
                                            </div>
                                        ) : (
                                            <div>
                                                <span className="text-aegis-text-muted text-sm">Domain:</span>
                                                <span className="ml-2 text-white font-semibold">{reportData.domainOverview.domain_name || 'Unknown'}</span>
                                            </div>
                                        )}
                                        <div>
                                            <span className="text-aegis-text-muted text-sm">Forest:</span>
                                            <span className="ml-2 text-white font-semibold">{reportData.domainOverview.forest_name || 'Unknown'}</span>
                                        </div>
                                        <div>
                                            <span className="text-aegis-text-muted text-sm">Functional Level:</span>
                                            <span className="ml-2 text-aegis-accent font-medium">{reportData.domainOverview.functional_level || 'Unknown'}</span>
                                        </div>
                                    </div>
                                </div>

                                {/* Stats Grid */}
                                <div className="grid grid-cols-2 md:grid-cols-3 gap-px bg-aegis-border">
                                    <div className="bg-aegis-gray px-6 py-4 text-center">
                                        <div className="text-2xl font-bold text-white">{reportData.domainOverview.total_users?.toLocaleString() || 0}</div>
                                        <div className="text-sm text-aegis-text-muted">Total Users</div>
                                    </div>
                                    <div className="bg-aegis-gray px-6 py-4 text-center">
                                        <div className="text-2xl font-bold text-white">{reportData.domainOverview.total_groups?.toLocaleString() || 0}</div>
                                        <div className="text-sm text-aegis-text-muted">Total Groups</div>
                                    </div>
                                    <div className="bg-aegis-gray px-6 py-4 text-center">
                                        <div className="text-2xl font-bold text-white">{reportData.domainOverview.total_computers?.toLocaleString() || 0}</div>
                                        <div className="text-sm text-aegis-text-muted">Total Computers</div>
                                    </div>
                                </div>

                                {/* Collection Info Footer */}
                                <div className="px-6 py-3 bg-aegis-darker border-t border-aegis-border flex flex-wrap gap-x-6 gap-y-1 text-sm">
                                    <div>
                                        <span className="text-aegis-text-subtle">Collection Method:</span>
                                        <span className="ml-2 text-aegis-text">{reportData.domainOverview.collection_method || 'BloodHound CE'}</span>
                                    </div>
                                    {reportData.domainOverview.total_ous > 0 && (
                                        <div>
                                            <span className="text-aegis-text-subtle">OUs:</span>
                                            <span className="ml-2 text-aegis-text">{reportData.domainOverview.total_ous}</span>
                                        </div>
                                    )}
                                    {reportData.domainOverview.total_gpos > 0 && (
                                        <div>
                                            <span className="text-aegis-text-subtle">GPOs:</span>
                                            <span className="ml-2 text-aegis-text">{reportData.domainOverview.total_gpos}</span>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </section>
                    )}

                    {/* Executive Summary */}
                    <section className="mb-16">
                        <SectionHeader
                            title="Executive Summary"
                            subtitle="High-level overview of security posture and critical findings"
                            icon={
                                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                                </svg>
                            }
                        />
                        <div className="prose prose-lg prose-invert max-w-none">
                            {reportData?.executiveSummary ? (
                                <ExecutiveSummaryContent content={reportData.executiveSummary} />
                            ) : (
                                <p className="text-aegis-text-muted">No executive summary available.</p>
                            )}
                        </div>
                    </section>

                    {/* Findings Summary Table - Actionable Only */}
                    {actionablePaths.length > 0 && (
                        <FindingsOverviewTable
                            paths={actionablePaths}
                            severityTagColors={severityTagColors}
                            onCopy={copyToClipboard}
                            onNavigateToFinding={navigateToFinding}
                            title="Actionable Findings Overview"
                            subtitle="Summary of vulnerabilities requiring remediation"
                        />
                    )}

                    {/* Divider */}
                    <div className="h-px bg-[#30363d] my-12" />

                    {/* Actionable Findings Header */}
                    <div className="mb-8">
                        <div className="border-l-4 border-[#58a6ff] pl-4 mb-4">
                            <div className="flex items-baseline gap-3 mb-1">
                                <h2 className="text-2xl font-bold text-white">
                                    Actionable Findings
                                </h2>
                                {actionablePaths.length > 0 && (
                                    <span className="text-lg text-[#8b949e]">
                                        ({actionablePaths.length} finding{actionablePaths.length !== 1 ? 's' : ''})
                                    </span>
                                )}
                            </div>
                            <p className="text-[#8b949e]">Detailed analysis of vulnerabilities requiring remediation</p>
                        </div>

                        {/* Expand/Collapse All Buttons - Outside the border */}
                        {actionablePaths.length > 0 && (
                            <div className="flex items-center gap-2">
                                <button
                                    onClick={() => {
                                        const allIds = actionablePaths.map((path: any, index: number) =>
                                            `finding-${path.scenario_number || index}`
                                        );
                                        setExpandedFindings(new Set(allIds));
                                    }}
                                    className="flex items-center gap-2 px-3 py-1.5 text-sm text-[#c9d1d9] bg-[#21262d] border border-[#30363d] rounded-lg hover:bg-[#30363d] hover:border-[#8b949e] transition-colors"
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
                                    </svg>
                                    Expand All
                                </button>
                                <button
                                    onClick={() => setExpandedFindings(new Set())}
                                    className="flex items-center gap-2 px-3 py-1.5 text-sm text-[#c9d1d9] bg-[#21262d] border border-[#30363d] rounded-lg hover:bg-[#30363d] hover:border-[#8b949e] transition-colors"
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 9V4.5M9 9H4.5M9 9L3.75 3.75M9 15v4.5M9 15H4.5M9 15l-5.25 5.25M15 9h4.5M15 9V4.5M15 9l5.25-5.25M15 15h4.5M15 15v4.5m0-4.5l5.25 5.25" />
                                    </svg>
                                    Collapse All
                                </button>
                            </div>
                        )}
                    </div>

                    {/* Detailed Actionable Findings - Collapsible Cards */}
                    {actionablePaths.length > 0 ? (
                        <div className="space-y-4">
                            {actionablePaths.map((path: any, index: number) => {
                                const finding = path.pentest_finding;
                                const findingId = `finding-${path.scenario_number || index}`;
                                const isExpanded = expandedFindings.has(findingId);

                                // If we have a pentest_finding, use collapsible card
                                if (finding) {
                                    const severity = finding.severity || 'Medium';
                                    const severityStyle = severityColors[severity] || severityColors.Medium;
                                    const complexity = finding.attack_complexity || 'Medium';
                                    const complexityColor = complexityColors[complexity] || 'text-yellow-400';

                                    // Build graph component to pass into FindingCard (rendered in Evidence section)
                                    // Use per-finding graph from path.graph
                                    const pathGraph = (path as any).graph;
                                    const graphElement = pathGraph ? (
                                        <div className="relative h-[400px]">
                                            {/* Floating action buttons */}
                                            <div className="absolute top-2 right-2 z-10 flex items-center gap-1">
                                                {/* Reset/Refresh button */}
                                                <button
                                                    onClick={() => graphRefs.current[index]?.resetView()}
                                                    className="p-2 rounded-lg bg-[#21262d] text-[#8b949e] hover:text-[#58a6ff] hover:bg-[#30363d] transition-colors"
                                                    title="Reset view"
                                                >
                                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                                    </svg>
                                                </button>
                                                {/* Fullscreen button */}
                                                <button
                                                    onClick={() => openFullScreenGraph(path.scenario_number || index + 1, finding.title)}
                                                    className="p-2 rounded-lg bg-[#21262d] text-[#8b949e] hover:text-[#58a6ff] hover:bg-[#30363d] transition-colors"
                                                    title="Open full screen"
                                                >
                                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
                                                    </svg>
                                                </button>
                                            </div>
                                            <AttackPathGraph
                                                ref={(el) => { graphRefs.current[index] = el; }}
                                                analysisId={analysisId}
                                                isExpanded={expandedGraphs.has(path.scenario_number || index)}
                                                onNodeClick={handleNodeClick}
                                                onEdgeClick={handleEdgeClick}
                                                graphData={(path as any).graph}
                                                defaultSelectedPath={(path.scenario_number || index + 1).toString()}
                                                singlePathMode={true}
                                                hidePathSelector={true}
                                            />
                                        </div>
                                    ) : undefined;

                                    return (
                                        <div
                                            key={findingId}
                                            ref={(el) => { findingRefs.current[findingId] = el; }}
                                            className={`rounded-xl overflow-hidden border transition-all duration-500 ${highlightedFindingId === findingId
                                                ? 'border-green-500 ring-2 ring-green-500/50 shadow-[0_0_20px_rgba(34,197,94,0.3)]'
                                                : 'border-[#30363d]'
                                                }`}
                                        >
                                            {/* Collapsible Header */}
                                            <button
                                                onClick={() => toggleFinding(findingId)}
                                                className="w-full flex items-stretch bg-[#161b22] hover:bg-[#1c2128] transition-colors cursor-pointer"
                                            >
                                                {/* Severity Badge */}
                                                <div className={`${severityStyle.bg} ${severityStyle.text} px-5 py-5 font-bold text-sm flex items-center justify-center min-w-[100px] uppercase tracking-wide`}>
                                                    {severity}
                                                </div>
                                                {/* Title and Info */}
                                                <div className="flex-1 px-5 py-4 text-left">
                                                    <div className="flex items-center gap-2 mb-1">
                                                        <h3 className="text-lg font-semibold text-white">
                                                            {finding.title || path.title || `Attack Path ${index + 1}`}
                                                        </h3>
                                                    </div>
                                                    <div className="text-sm text-[#8b949e]">
                                                        Attack Complexity: <span className={`font-semibold ${complexityColor}`}>{complexity}</span>
                                                        {finding.category && (
                                                            <span> &nbsp;•&nbsp; Category: {finding.category}</span>
                                                        )}
                                                    </div>
                                                </div>
                                                {/* Chevron */}
                                                <div className="flex items-center px-5">
                                                    <svg
                                                        className={`w-6 h-6 text-[#8b949e] transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
                                                        fill="none"
                                                        stroke="currentColor"
                                                        viewBox="0 0 24 24"
                                                    >
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                                    </svg>
                                                </div>
                                            </button>

                                            {/* Expandable Content */}
                                            {isExpanded && (
                                                <div className="border-t border-[#30363d]">
                                                    <FindingCard
                                                        finding={finding as Finding}
                                                        onCopy={copyToClipboard}
                                                        graphComponent={graphElement}
                                                        hideHeader={true}
                                                    />
                                                </div>
                                            )}
                                        </div>
                                    );
                                }

                                // Fallback: if no pentest_finding, show basic collapsible card
                                const fallbackId = `fallback-${index}`;
                                const isFallbackExpanded = expandedFindings.has(fallbackId);

                                return (
                                    <div
                                        key={fallbackId}
                                        ref={(el) => { findingRefs.current[fallbackId] = el; }}
                                        className={`rounded-xl overflow-hidden border transition-all duration-500 ${highlightedFindingId === fallbackId
                                            ? 'border-green-500 ring-2 ring-green-500/50 shadow-[0_0_20px_rgba(34,197,94,0.3)]'
                                            : 'border-[#30363d]'
                                            }`}
                                    >
                                        {/* Collapsible Header */}
                                        <button
                                            onClick={() => toggleFinding(fallbackId)}
                                            className="w-full flex items-stretch bg-[#161b22] hover:bg-[#1c2128] transition-colors cursor-pointer"
                                        >
                                            {/* Default Badge */}
                                            <div className="bg-yellow-600 text-white px-5 py-5 font-bold text-sm flex items-center justify-center min-w-[100px] uppercase tracking-wide">
                                                Medium
                                            </div>
                                            {/* Title */}
                                            <div className="flex-1 px-5 py-4 text-left">
                                                <h3 className="text-lg font-semibold text-white mb-1">
                                                    {path.title || `Attack Path ${index + 1}`}
                                                </h3>
                                                <div className="text-sm text-[#8b949e]">
                                                    {path.attackType || 'Unknown Type'}
                                                </div>
                                            </div>
                                            {/* Chevron */}
                                            <div className="flex items-center px-5">
                                                <svg
                                                    className={`w-6 h-6 text-[#8b949e] transition-transform duration-200 ${isFallbackExpanded ? 'rotate-180' : ''}`}
                                                    fill="none"
                                                    stroke="currentColor"
                                                    viewBox="0 0 24 24"
                                                >
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                                </svg>
                                            </div>
                                        </button>

                                        {/* Expandable Content */}
                                        {isFallbackExpanded && (
                                            <div className="border-t border-[#30363d] p-6">
                                                {path.path_overview && (
                                                    <div className="prose prose-invert max-w-none mb-4">
                                                        <MarkdownContent content={path.path_overview} />
                                                    </div>
                                                )}

                                                {path.query_info?.cypher_query && (
                                                    <CypherQueryDisplay
                                                        query={path.query_info.cypher_query}
                                                        queryName={path.query_info?.name || path.title || `Attack Path ${index + 1}`}
                                                        description={path.query_info?.query_description}
                                                        edgesUsed={path.query_info?.edges_used}
                                                        onCopy={copyToClipboard}
                                                    />
                                                )}
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    ) : (
                        <section className="mb-16">
                            <div className="text-center py-12 bg-aegis-info-dark/10 border border-aegis-info-dark/30 rounded-lg">
                                <p className="text-aegis-info">
                                    No attack paths found in the analysis.
                                </p>
                            </div>
                        </section>
                    )}

                    {/* Additional Findings from Chat Queries */}
                    {reportData?.additionalFindings && reportData.additionalFindings.length > 0 && (
                        <>
                            <div className="h-px bg-[#30363d] my-12" />
                            <AdditionalFindingsSection
                                findings={reportData.additionalFindings}
                                onCopy={copyToClipboard}
                                onRemove={onRemoveFinding}
                            />
                        </>
                    )}

                    {/* AMSI Bypass Appendix */}
                    {reportData?.amsi_appendix && reportData.amsi_appendix.techniques?.length > 0 && (
                        <>
                            <div className="h-px bg-[#30363d] my-12" />
                            <section id="amsi-appendix" className="mb-16 scroll-mt-24">
                                <SectionHeader
                                    title={reportData.amsi_appendix.title || 'AMSI Bypass Reference'}
                                    subtitle="Pre-validated bypass techniques for PowerShell offensive tools"
                                    titleColor="text-[#fbbf24]"
                                    icon={
                                        <svg className="w-6 h-6 text-[#fbbf24]" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                        </svg>
                                    }
                                />

                                <div className="bg-[#0d1117] border border-[#30363d] rounded-xl p-6 mt-4">
                                    <p className="text-[#c9d1d9] mb-6">
                                        {reportData.amsi_appendix.description}
                                    </p>

                                    <div className="space-y-6">
                                        {reportData.amsi_appendix.techniques.map((technique: any, idx: number) => (
                                            <div key={idx} className="border border-[#30363d] rounded-lg overflow-hidden">
                                                <div className="bg-[#161b22] px-4 py-3 border-b border-[#30363d]">
                                                    <div className="flex items-center justify-between">
                                                        <span className="font-semibold text-white">{technique.name}</span>
                                                        <span className="text-xs px-2 py-1 bg-[#21262d] text-[#8b949e] rounded">
                                                            {technique.family}
                                                        </span>
                                                    </div>
                                                    {technique.description && (
                                                        <p className="text-sm text-[#8b949e] mt-1">{technique.description}</p>
                                                    )}
                                                </div>
                                                <SyntaxHighlightedScript
                                                    code={technique.code}
                                                    language="powershell"
                                                    onCopy={(text: string) => {
                                                        navigator.clipboard.writeText(text);
                                                        toast.success('Bypass code copied!');
                                                    }}
                                                />
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            </section>
                        </>
                    )}
                </div>
            </div>

            {/* Full Screen Graph Modal - Centered and Clean */}
            {fullScreenGraph && (
                <div className="fixed inset-0 bg-black/90 z-[70] flex items-center justify-center p-4">
                    <div className="w-full h-[95vh] flex flex-col">
                        <AttackPathGraph
                            analysisId={fullScreenGraph.analysisId}
                            isExpanded={true}
                            onClose={closeFullScreenGraph}
                            onNodeClick={handleNodeClick}
                            onEdgeClick={handleEdgeClick}
                            className="h-full"
                            graphData={(() => {
                                // Find the path by scenario_number to get its per-finding graph
                                const path = reportData?.paths?.find(
                                    (p: any) => p.scenario_number === fullScreenGraph.pathNumber
                                );
                                return (path as any)?.graph || null;
                            })()}
                            title={`Attack Path ${fullScreenGraph.pathNumber}${fullScreenGraph.attackName ? ` - ${fullScreenGraph.attackName}` : ''}`}
                            defaultSelectedPath={fullScreenGraph.pathNumber.toString()}
                            hidePathSelector={true}
                            singlePathMode={true}
                        />
                    </div>
                </div>
            )}
        </>
    );
};

// Findings Overview Table component with pagination
const FindingsOverviewTable: React.FC<{
    paths: any[];
    severityTagColors: Record<FindingSeverity, string>;
    onCopy?: (text: string) => void;
    onNavigateToFinding?: (findingId: string) => void;
    title?: string;
    subtitle?: string;
}> = ({ paths, severityTagColors, onCopy, onNavigateToFinding, title = 'Findings Overview', subtitle = 'Summary of all discovered vulnerabilities' }) => {
    const [currentPage, setCurrentPage] = useState(0);
    const pageSize = 25;

    const totalPages = Math.ceil(paths.length / pageSize);

    const paginatedPaths = useMemo(() => {
        const start = currentPage * pageSize;
        return paths.slice(start, start + pageSize);
    }, [paths, currentPage]);

    const handleCopyAll = () => {
        const header = `#\tFinding\tSeverity\tComplexity\tCategory`;
        const rows = paths.map((path: any, index: number) => {
            const finding = path.pentest_finding;
            const severity = finding?.severity || 'Medium';
            return `${index + 1}\t${finding?.title || path.title || `Attack Path ${index + 1}`}\t${severity}\t${finding?.attack_complexity || 'Medium'}\t${finding?.category || path.attackType || 'Unknown'}`;
        }).join('\n');
        const text = `${header}\n${rows}`;
        navigator.clipboard.writeText(text);
        onCopy?.(text);
        toast.success('Copied to clipboard');
    };

    return (
        <section className="mb-12">
            <div className="border-l-4 border-[#58a6ff] pl-4 mb-6">
                <h2 className="text-2xl font-bold text-white mb-1">{title}</h2>
                <p className="text-[#8b949e]">{subtitle}</p>
            </div>

            <div className="rounded-lg border border-[#30363d] overflow-hidden">
                {/* Table Header with Copy Button */}
                <div className="px-4 py-2 bg-[#161b22] border-b border-[#30363d] flex items-center justify-between">
                    <span className="text-xs text-[#8b949e]">
                        {paths.length} finding{paths.length !== 1 ? 's' : ''}
                    </span>
                    <button
                        onClick={handleCopyAll}
                        className="text-xs text-[#8b949e] hover:text-[#c9d1d9] flex items-center gap-1"
                        title="Copy all findings as TSV"
                    >
                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                        Copy All
                    </button>
                </div>

                {/* Table */}
                <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
                    <table className="w-full text-sm border-collapse">
                        <thead className="bg-[#161b22] sticky top-0">
                            <tr>
                                <th className="text-left px-4 py-3 bg-[#161b22] border-b border-[#30363d] text-[#8b949e] font-semibold uppercase text-xs tracking-wider">#</th>
                                <th className="text-left px-4 py-3 bg-[#161b22] border-b border-[#30363d] text-[#8b949e] font-semibold uppercase text-xs tracking-wider">Finding</th>
                                <th className="text-left px-4 py-3 bg-[#161b22] border-b border-[#30363d] text-[#8b949e] font-semibold uppercase text-xs tracking-wider">Severity</th>
                                <th className="text-left px-4 py-3 bg-[#161b22] border-b border-[#30363d] text-[#8b949e] font-semibold uppercase text-xs tracking-wider">Complexity</th>
                                <th className="text-left px-4 py-3 bg-[#161b22] border-b border-[#30363d] text-[#8b949e] font-semibold uppercase text-xs tracking-wider">Category</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-[#30363d]">
                            {paginatedPaths.map((path: any, index: number) => {
                                const finding = path.pentest_finding;
                                const severity = finding?.severity || 'Medium';
                                const globalIndex = currentPage * pageSize + index;
                                const findingId = `finding-${path.scenario_number || globalIndex}`;
                                return (
                                    <tr
                                        key={globalIndex}
                                        className="hover:bg-[#161b22]/50 transition-colors cursor-pointer"
                                        onClick={() => onNavigateToFinding?.(findingId)}
                                        title="Click to navigate to finding"
                                    >
                                        <td className="px-4 py-3 text-[#c9d1d9]">{globalIndex + 1}</td>
                                        <td className="px-4 py-3 text-[#c9d1d9]">
                                            {finding?.title || path.title || `Attack Path ${globalIndex + 1}`}
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`inline-block px-2 py-1 rounded text-xs font-semibold border ${severityTagColors[severity as FindingSeverity] || severityTagColors.Medium}`}>
                                                {severity}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3 text-[#c9d1d9]">
                                            {finding?.attack_complexity || 'Medium'}
                                        </td>
                                        <td className="px-4 py-3 text-[#c9d1d9]">
                                            {finding?.category || path.attackType || 'Unknown'}
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>

                {/* Pagination Controls */}
                {totalPages > 1 && (
                    <div className="px-4 py-2 bg-[#161b22] border-t border-[#30363d] flex items-center justify-between">
                        <span className="text-xs text-[#8b949e]">
                            Showing {currentPage * pageSize + 1}-{Math.min((currentPage + 1) * pageSize, paths.length)} of {paths.length}
                        </span>
                        <div className="flex items-center gap-1">
                            <button
                                onClick={() => setCurrentPage(0)}
                                disabled={currentPage === 0}
                                className="px-2 py-1 text-xs rounded hover:bg-[#21262d] disabled:opacity-40 disabled:cursor-not-allowed text-[#8b949e] hover:text-[#c9d1d9]"
                                title="First page"
                            >
                                {'<<'}
                            </button>
                            <button
                                onClick={() => setCurrentPage(p => Math.max(0, p - 1))}
                                disabled={currentPage === 0}
                                className="px-2 py-1 text-xs rounded hover:bg-[#21262d] disabled:opacity-40 disabled:cursor-not-allowed text-[#8b949e] hover:text-[#c9d1d9]"
                                title="Previous page"
                            >
                                {'<'}
                            </button>
                            <span className="px-3 py-1 text-xs text-[#c9d1d9]">
                                {currentPage + 1} / {totalPages}
                            </span>
                            <button
                                onClick={() => setCurrentPage(p => Math.min(totalPages - 1, p + 1))}
                                disabled={currentPage >= totalPages - 1}
                                className="px-2 py-1 text-xs rounded hover:bg-[#21262d] disabled:opacity-40 disabled:cursor-not-allowed text-[#8b949e] hover:text-[#c9d1d9]"
                                title="Next page"
                            >
                                {'>'}
                            </button>
                            <button
                                onClick={() => setCurrentPage(totalPages - 1)}
                                disabled={currentPage >= totalPages - 1}
                                className="px-2 py-1 text-xs rounded hover:bg-[#21262d] disabled:opacity-40 disabled:cursor-not-allowed text-[#8b949e] hover:text-[#c9d1d9]"
                                title="Last page"
                            >
                                {'>>'}
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </section>
    );
};

export default UnifiedAttackPathReport;

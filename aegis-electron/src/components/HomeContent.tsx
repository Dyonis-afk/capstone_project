/** Home screen — uploads a BloodHound zip to BHCE and extracts findings from Neo4j. */

import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import BloodHoundIcon from './BloodHoundIcon';
import AsciiProgressBar from './AsciiProgressBar';
import figlet from 'figlet';
import ansiShadow from 'figlet/importable-fonts/ANSI Shadow.js';
import { useProjectStore } from '../stores/projectStore';
import { useConnectionStore, useNeo4jMode } from '../stores/connectionStore';
import { useReportJobStore } from '../stores/reportJobStore';
import { useUploadStore } from '../stores/uploadStore';
import Tier0ConfigModal, { Tier0Config, Tier0Asset } from './Tier0ConfigModal';

figlet.parseFont('ANSI Shadow', ansiShadow);

const HomeContent = () => {
    const navigate = useNavigate();

    // Global upload state from Zustand store
    const {
        isUploading: globalIsUploading,
        uploadingProjectId,
        setUploading: setGlobalUploading
    } = useProjectStore();

    // Connection status from central store (smart polling handled in App.tsx)
    // Note: isCheckingBackend/isCheckingBloodhound only true during MANUAL checks (no UI flicker)
    const {
        backendConnected: isBackendConnected,
        neo4jReady: isBloodhoundConnected,
        bhceTokenConfigured: hasBhceCredentials,
        isCheckingBackend,
        isCheckingBloodhound,
        checkAll: handleCheckConnections,
        verifyServicesForAction
    } = useConnectionStore();

    // Get Neo4j connection mode (Docker vs Custom)
    const neo4jMode = useNeo4jMode();

    // Report job store - for background report generation
    const { isRunning: isReportJobRunning, startJob: startReportJob } = useReportJobStore();

    // Upload state from Zustand store (persists across navigation)
    const {
        isUploading, setIsUploading,
        uploadStep, setUploadStep,
        selectedFileName, setSelectedFileName,
        errorMessage, setErrorMessage,
        uploadProgress: _uploadProgress, setUploadProgress,
        uploadStartTime, setUploadStartTime,
        elapsedSeconds, setElapsedSeconds,
        bhceImportSuccess, setBhceImportSuccess,
        localAnalysis, setLocalAnalysis,
        t0AutoDetectedAssets, setT0AutoDetectedAssets,
        t0Config, setT0Config,
        t0Configured, setT0Configured,
        isDetectingT0, setIsDetectingT0,
        resetUpload: storeResetUpload,
        cancelIngestion: storeCancelIngestion,
    } = useUploadStore();

    // ANSI Shadow ASCII art (AEGIS)
    const [asciiArt, setAsciiArt] = useState<string>('');
    // App version (from Electron, same as Settings)
    const [appVersion, setAppVersion] = useState<string>('');
    // Update check: null = unknown, true = on latest, false = update available; latestReleaseVersion set when update available
    const [isLatestRelease, setIsLatestRelease] = useState<boolean | null>(null);
    const [latestReleaseVersion, setLatestReleaseVersion] = useState<string | null>(null);

    // T0 modal is local-only (no need to persist across nav)
    const [t0ModalOpen, setT0ModalOpen] = useState(false);

    // Cancellation ref for ingestion polling
    const cancelIngestionRef = useRef(false);

    const fileInputRef = useRef<HTMLInputElement>(null);

    // Cancel ingestion handler
    const handleCancelIngestion = () => {
        cancelIngestionRef.current = true;
        storeCancelIngestion();
        setGlobalUploading(false);
    };

    // Timer effect for tracking elapsed time during upload
    useEffect(() => {
        if (!uploadStartTime || !isUploading) {
            return;
        }

        const interval = setInterval(() => {
            setElapsedSeconds(Math.floor((Date.now() - uploadStartTime) / 1000));
        }, 1000);

        return () => clearInterval(interval);
    }, [uploadStartTime, isUploading]);

    // ==================== INGESTION POLLING (shared between fresh upload & resume) ====================

    const pollIngestionAndExtract = async (fileName: string): Promise<boolean> => {
        if (!window.neo4j) {
            setErrorMessage('Neo4j connection not available for findings extraction');
            setUploadStep('idle');
            setGlobalUploading(false);
            return false;
        }

        cancelIngestionRef.current = false;
        let attempts = 0;
        let findings = null;
        let lastNodeCount = 0;
        let stablePolls = 0;
        const STABLE_THRESHOLD = 2;

        while (true) {
            if (cancelIngestionRef.current) {
                console.log('[HomeContent] Ingestion cancelled by user');
                return false;
            }

            attempts++;
            const elapsedTime = Math.floor(attempts * 2 / 60);
            const elapsedSecs = (attempts * 2) % 60;

            await new Promise(resolve => setTimeout(resolve, 2000));

            if (cancelIngestionRef.current) {
                console.log('[HomeContent] Ingestion cancelled by user');
                return false;
            }

            const testResult = await window.neo4j.runQuery('MATCH (n) RETURN count(n) as count LIMIT 1');
            const nodeCount = testResult.success && testResult.records?.[0]?.count
                ? (typeof testResult.records[0].count === 'object' && 'low' in testResult.records[0].count
                    ? testResult.records[0].count.low
                    : testResult.records[0].count)
                : 0;

            console.log(`[HomeContent] Ingestion check ${attempts}: ${nodeCount} nodes (prev: ${lastNodeCount}, stable: ${stablePolls}/${STABLE_THRESHOLD})`);

            if (nodeCount === 0) {
                setUploadProgress(`Waiting for data ingestion... ${elapsedTime}m ${elapsedSecs}s elapsed`);
                lastNodeCount = 0;
                stablePolls = 0;
                continue;
            }

            if (nodeCount === lastNodeCount) {
                stablePolls++;
            } else {
                stablePolls = 0;
            }
            lastNodeCount = nodeCount;

            setUploadProgress(`Ingesting... ${nodeCount.toLocaleString()} nodes (${elapsedTime}m ${elapsedSecs}s)`);

            if (stablePolls >= STABLE_THRESHOLD) {
                console.log(`[HomeContent] Ingestion stabilized at ${nodeCount} nodes after ${attempts} polls`);
                setUploadProgress('Extracting findings from Neo4j...');
                findings = await window.neo4j.extractFindings();
                break;
            }
        }

        if (!findings) {
            setErrorMessage('Failed to extract findings from Neo4j. Please try again.');
            setUploadStep('idle');
            setIsUploading(false);
            setGlobalUploading(false);
            return false;
        }

        console.log('[HomeContent] Extracted findings:', findings);

        setLocalAnalysis({ findings, filename: fileName });
        setUploadProgress('Analysis complete!');
        setUploadStep('done');

        if (findings.domains && findings.domains.length > 0) {
            detectT0Candidates(findings.domains);
        }

        return true;
    };

    // Resume ingestion polling if component remounts while ingestion was in progress
    useEffect(() => {
        if (isUploading && uploadStep === 'extracting' && selectedFileName) {
            console.log('[HomeContent] Resuming ingestion polling after navigation return');
            setGlobalUploading(true, 'home');

            pollIngestionAndExtract(selectedFileName).then((success) => {
                if (success) {
                    setIsUploading(false);
                    setGlobalUploading(false);
                    setUploadProgress('');
                    setUploadStartTime(null);
                }
            }).catch((error) => {
                console.error('Failed during resumed ingestion:', error);
                setErrorMessage(error instanceof Error ? error.message : 'Failed during ingestion');
                setUploadStep('idle');
                setIsUploading(false);
                setGlobalUploading(false);
            });
        }
        // Only run on mount (dependency on store values would cause re-runs)
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    // ==================== FILE HANDLING (REFACTORED) ====================
    // NOTE: Project creation has been moved to ReportScreen to prevent orphaned projects
    // when backend fails during report generation. Project is now created AFTER report completes.

    const handleBrowseClick = () => {
        if (!isUploading) {
            // Use native Electron dialog if available
            if (window.bloodhound) {
                handleElectronFileSelect();
            } else {
                fileInputRef.current?.click();
            }
        }
    };

    // Electron native file dialog - NEW SIMPLIFIED FLOW
    const handleElectronFileSelect = async () => {
        if (!window.bloodhound) return;

        // Action-triggered service verification before upload
        const serviceStatus = await verifyServicesForAction();
        if (!serviceStatus.ready) {
            setErrorMessage(serviceStatus.error || 'Services not available');
            return;
        }

        setIsUploading(true);
        setGlobalUploading(true, 'home'); // Set global state with 'home' as identifier
        setErrorMessage(null);
        setUploadStep('selecting');
        setUploadProgress('Opening file dialog...');
        setBhceImportSuccess(false);
        setLocalAnalysis(null);
        setUploadStartTime(Date.now());
        setElapsedSeconds(0);

        try {
            // Step 1: Select file (no parsing - just get file path)
            const selectResult = await window.bloodhound.selectFile();

            if (!selectResult.success) {
                if (selectResult.error !== 'No file selected') {
                    setErrorMessage(selectResult.error || 'Failed to select file');
                }
                setUploadStep('idle');
                setIsUploading(false);
                setGlobalUploading(false);
                return;
            }

            const fileName = selectResult.fileName || 'BloodHound Data';
            const filePath = selectResult.filePath;
            setSelectedFileName(fileName);

            // Step 2: Upload to BloodHound CE (it handles all parsing/ingestion)
            if (!hasBhceCredentials || !window.bloodhoundCE) {
                setErrorMessage('BloodHound CE API not configured. Please configure API token in Settings.');
                setUploadStep('idle');
                setIsUploading(false);
                setGlobalUploading(false);
                return;
            }

            setUploadStep('uploading');
            setUploadProgress('Clearing previous data...');

            // Clear existing data before uploading new file
            if (window.bloodhoundCE?.clearAllData) {
                console.log('[HomeContent] Clearing existing BloodHound data...');
                const clearResult = await window.bloodhoundCE.clearAllData();
                if (!clearResult.success) {
                    console.warn('[HomeContent] Failed to clear data:', clearResult.error);
                    // Continue anyway - the upload might still work
                }
            }

            setUploadProgress('Uploading to BloodHound CE...');

            const projectId = `${fileName.replace(/\.[^/.]+$/, '')}_${Date.now()}`;
            console.log('[HomeContent] Uploading to BloodHound CE:', filePath, 'projectId:', projectId);

            const uploadResult = await window.bloodhoundCE.uploadFile(filePath!, projectId);

            if (!uploadResult.success) {
                setErrorMessage(`BloodHound CE upload failed: ${uploadResult.error}`);
                setUploadStep('idle');
                setIsUploading(false);
                setGlobalUploading(false);
                return;
            }

            console.log('[HomeContent] BloodHound CE upload success:', uploadResult);
            setBhceImportSuccess(true);
            setUploadProgress('BloodHound CE import complete!');

            // Step 3: Wait for BloodHound CE to finish ingesting into Neo4j
            setUploadStep('extracting');
            setUploadProgress('Waiting for data ingestion...');

            await pollIngestionAndExtract(fileName);

        } catch (error) {
            console.error('Failed to process file:', error);
            setErrorMessage(error instanceof Error ? error.message : 'Failed to process file');
            setLocalAnalysis(null);
            setSelectedFileName(null);
            setUploadStep('idle');
        } finally {
            setIsUploading(false);
            setGlobalUploading(false);
            setUploadProgress('');
            setUploadStartTime(null);
        }
    };

    // Web file input handler (fallback for non-Electron)
    const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file) return;

        // Validate file type
        const isZip = file.name.toLowerCase().endsWith('.zip');
        const isJson = file.name.toLowerCase().endsWith('.json');

        if (!isZip && !isJson) {
            setErrorMessage('Only ZIP and JSON files are allowed.');
            setSelectedFileName(null);
            if (fileInputRef.current) fileInputRef.current.value = '';
            return;
        }

        setSelectedFileName(file.name);
        setErrorMessage(null);
        setLocalAnalysis(null);

        await processFileViaBuffer(file);
    };

    // Process file via buffer upload to BloodHound CE
    const processFileViaBuffer = async (file: File) => {
        // Action-triggered service verification before upload
        const serviceStatus = await verifyServicesForAction();
        if (!serviceStatus.ready) {
            setErrorMessage(serviceStatus.error || 'Services not available');
            return;
        }

        setIsUploading(true);
        setGlobalUploading(true, 'home'); // Set global state with 'home' as identifier
        setErrorMessage(null);
        setUploadStep('uploading');
        setUploadProgress('Reading file...');
        setBhceImportSuccess(false);
        setUploadStartTime(Date.now());
        setElapsedSeconds(0);

        try {
            const buffer = await file.arrayBuffer();

            if (!hasBhceCredentials || !window.bloodhoundCE) {
                setErrorMessage('BloodHound CE API not configured. Please configure API token in Settings.');
                setUploadStep('idle');
                setIsUploading(false);
                setGlobalUploading(false);
                return;
            }

            setUploadProgress('Clearing previous data...');

            // Clear existing data before uploading new file
            if (window.bloodhoundCE?.clearAllData) {
                console.log('[HomeContent] Clearing existing BloodHound data...');
                const clearResult = await window.bloodhoundCE.clearAllData();
                if (!clearResult.success) {
                    console.warn('[HomeContent] Failed to clear data:', clearResult.error);
                    // Continue anyway - the upload might still work
                }
            }

            setUploadProgress('Uploading to BloodHound CE...');

            const projectId = `${file.name.replace(/\.[^/.]+$/, '')}_${Date.now()}`;
            const uploadResult = await window.bloodhoundCE.uploadBuffer(buffer, file.name, projectId);

            if (!uploadResult.success) {
                setErrorMessage(`BloodHound CE upload failed: ${uploadResult.error}`);
                setUploadStep('idle');
                setIsUploading(false);
                setGlobalUploading(false);
                return;
            }

            console.log('[HomeContent] BloodHound CE upload success:', uploadResult);
            setBhceImportSuccess(true);
            setUploadProgress('BloodHound CE import complete!');

            // Wait for BloodHound CE to finish ingesting into Neo4j
            setUploadStep('extracting');
            setUploadProgress('Waiting for data ingestion...');

            await pollIngestionAndExtract(file.name);

        } catch (error) {
            console.error('Failed to process file:', error);
            setErrorMessage(error instanceof Error ? error.message : 'Failed to process file');
            setLocalAnalysis(null);
            setSelectedFileName(null);
            setUploadStep('idle');
            if (fileInputRef.current) fileInputRef.current.value = '';
        } finally {
            setIsUploading(false);
            setGlobalUploading(false);
            setUploadProgress('');
            setUploadStartTime(null);
        }
    };

    // ==================== REPORT GENERATION ====================

    const handleGenerateReport = () => {
        if (!localAnalysis) return;

        const baseName = selectedFileName?.replace('.zip', '').replace('.json', '') ||
            `Analysis - ${new Date().toLocaleDateString()}`;

        // Use user-configured T0 config, or auto-create from detected assets
        let effectiveT0Config = t0Config;
        if (!effectiveT0Config && t0AutoDetectedAssets.length > 0) {
            // Auto-create T0 config from detected assets
            const domains: Tier0Config['domains'] = {};
            for (const asset of t0AutoDetectedAssets) {
                const domainKey = asset.domain.toUpperCase();
                if (!domains[domainKey]) {
                    domains[domainKey] = { assets: [], excludedMembers: [] };
                }
                domains[domainKey].assets.push(asset);
            }
            effectiveT0Config = {
                domains,
                enabled: true,
                skipped: false
            };
            console.log('[HomeContent] Auto-created T0 config from detected assets:', effectiveT0Config);
        }

        // Build analysis object for compatibility
        const analysis = {
            summary: {
                totalNodes: localAnalysis.findings.summary.total_nodes,
                totalEdges: localAnalysis.findings.summary.total_edges,
                highRiskCount: localAnalysis.findings.summary.high_risk_count,
                mediumRiskCount: localAnalysis.findings.summary.medium_risk_count,
                lowRiskCount: localAnalysis.findings.summary.low_risk_count,
                totalFindings: localAnalysis.findings.summary.high_risk_count +
                    localAnalysis.findings.summary.medium_risk_count +
                    localAnalysis.findings.summary.low_risk_count
            },
            highRiskFindings: localAnalysis.findings.high_risk,
            mediumRiskFindings: localAnalysis.findings.medium_risk,
            lowRiskFindings: localAnalysis.findings.low_risk,
            // Additional context from Neo4j extraction
            domains: localAnalysis.findings.domains,
            domainAdminGroups: localAnalysis.findings.domain_admin_groups,
            edgeTypeCounts: localAnalysis.findings.edge_type_counts,
            // Tier 0 configuration for filtering findings
            tier0Config: effectiveT0Config
        };

        // Start background report job (navigates automatically when done)
        startReportJob({
            fileName: baseName,
            localAnalysis: localAnalysis,
            analysis: analysis as any,
            tier0Config: effectiveT0Config  // Pass T0 config for backend classification
        });

        // Small delay to ensure store state is committed before navigation
        // This allows React to process the isRunning=true state change
        setTimeout(() => {
            navigate('/report', {
                state: {
                    localAnalysis: localAnalysis,
                    fileName: baseName,
                    analysis: analysis,
                    tier0Config: effectiveT0Config,
                    viewingJob: true  // Flag to indicate viewing existing job
                }
            });
        }, 50);
    };

    const handleResetUpload = () => {
        storeResetUpload();
    };

    // ==================== TIER 0 DETECTION ====================

    const detectT0Candidates = async (domains: string[]) => {
        if (!window.neo4j) return;

        setIsDetectingT0(true);
        const assets: Tier0Asset[] = [];

        try {
            // Query for Domain Admins, Enterprise Admins, Schema Admins groups
            const privilegedGroupsQuery = `
                MATCH (g:Group)
                WHERE g.name =~ '(?i)DOMAIN ADMINS@.*' OR
                      g.name =~ '(?i)ENTERPRISE ADMINS@.*' OR
                      g.name =~ '(?i)SCHEMA ADMINS@.*' OR
                      g.name =~ '(?i)ADMINISTRATORS@.*' OR
                      g.name =~ '(?i)ACCOUNT OPERATORS@.*' OR
                      g.name =~ '(?i)BACKUP OPERATORS@.*' OR
                      g.name =~ '(?i)SERVER OPERATORS@.*' OR
                      g.name =~ '(?i)PRINT OPERATORS@.*'
                RETURN DISTINCT g.name AS name, labels(g) AS labels
            `;

            const groupsResult = await window.neo4j.runQuery(privilegedGroupsQuery);
            if (groupsResult.success && groupsResult.records) {
                groupsResult.records.forEach((record: any) => {
                    const name = record.name || record._fields?.[0];
                    if (name) {
                        const domain = name.split('@')[1] || domains[0] || 'UNKNOWN';
                        const groupName = name.split('@')[0];

                        let reason = 'Privileged group';
                        if (groupName.toUpperCase().includes('DOMAIN ADMINS')) reason = 'Domain Admins group';
                        else if (groupName.toUpperCase().includes('ENTERPRISE ADMINS')) reason = 'Enterprise Admins group';
                        else if (groupName.toUpperCase().includes('SCHEMA ADMINS')) reason = 'Schema Admins group';
                        else if (groupName.toUpperCase() === 'ADMINISTRATORS') reason = 'Built-in Administrators';

                        assets.push({
                            name: name,
                            type: 'Group',
                            domain: domain,
                            autoDetected: true,
                            reason: reason
                        });
                    }
                });
            }

            // Query for Domain Controllers
            const dcQuery = `
                MATCH (c:Computer)
                WHERE c.name =~ '(?i).*DC.*@.*' OR
                      c.distinguishedname CONTAINS 'Domain Controllers'
                RETURN DISTINCT c.name AS name
            `;

            const dcResult = await window.neo4j.runQuery(dcQuery);
            if (dcResult.success && dcResult.records) {
                dcResult.records.forEach((record: any) => {
                    const name = record.name || record._fields?.[0];
                    if (name) {
                        const domain = name.split('@')[1] || domains[0] || 'UNKNOWN';
                        assets.push({
                            name: name,
                            type: 'Computer',
                            domain: domain,
                            autoDetected: true,
                            reason: 'Domain Controller'
                        });
                    }
                });
            }

            // Query for KRBTGT accounts
            const krbtgtQuery = `
                MATCH (u:User)
                WHERE u.name =~ '(?i)KRBTGT@.*'
                RETURN DISTINCT u.name AS name
            `;

            const krbtgtResult = await window.neo4j.runQuery(krbtgtQuery);
            if (krbtgtResult.success && krbtgtResult.records) {
                krbtgtResult.records.forEach((record: any) => {
                    const name = record.name || record._fields?.[0];
                    if (name) {
                        const domain = name.split('@')[1] || domains[0] || 'UNKNOWN';
                        assets.push({
                            name: name,
                            type: 'User',
                            domain: domain,
                            autoDetected: true,
                            reason: 'KRBTGT account (Kerberos service)'
                        });
                    }
                });
            }

            console.log('[HomeContent] Detected T0 assets:', assets.length);
            setT0AutoDetectedAssets(assets);
        } catch (error) {
            console.error('[HomeContent] Error detecting T0 assets:', error);
        } finally {
            setIsDetectingT0(false);
        }
    };

    const handleT0Configure = () => {
        console.log('[HomeContent] Opening T0 modal with:', {
            domains: localAnalysis?.findings.domains,
            assetCount: t0AutoDetectedAssets.length,
            firstAsset: t0AutoDetectedAssets[0]?.name,
            key: `t0-modal-${localAnalysis?.findings.domains?.[0] || 'none'}-${t0AutoDetectedAssets.length}`
        });
        setT0ModalOpen(true);
    };

    const handleT0Save = (config: Tier0Config) => {
        console.log('[HomeContent] T0 config saved:', config);
        setT0Config(config);
        setT0Configured(true);
        setT0ModalOpen(false);
    };

    // ==================== EFFECTS ====================

    // Connection status is now handled by connectionStore polling in App.tsx
    // Manual refresh available via handleCheckConnections() from connectionStore

    // Generate AEGIS ASCII art on mount (ANSI Shadow)
    useEffect(() => {
        figlet.text('AEGIS', { font: 'ANSI Shadow' }, (err, data) => {
            if (!err && data) {
                const lines = data.split('\n');
                const maxWidth = Math.max(...lines.map(line => line.length));
                const centeredLines = lines.map(line => {
                    const padding = Math.floor((maxWidth - line.length) / 2);
                    return ' '.repeat(padding) + line;
                });
                setAsciiArt(centeredLines.join('\n'));
            }
        });
    }, []);

    // Load app version and check if latest release (same as Settings page)
    useEffect(() => {
        window.updater?.getVersion().then(setAppVersion);
    }, []);

    // Check for updates on mount to show "latest release" vs "current → latest" in version line
    useEffect(() => {
        if (!window.updater) return;
        const onAvailable = (info: { version: string }) => {
            setLatestReleaseVersion(info.version);
            setIsLatestRelease(false);
        };
        const onNotAvailable = () => setIsLatestRelease(true);
        const unsubAvailable = window.updater.onUpdateAvailable(onAvailable);
        const unsubNotAvailable = window.updater.onUpdateNotAvailable(onNotAvailable);
        window.updater.checkForUpdates().catch(() => { /* ignore; leave isLatestRelease null */ });
        return () => {
            unsubAvailable?.();
            unsubNotAvailable?.();
        };
    }, []);

    // ==================== COMPUTED VALUES ====================

    const totalFindings = localAnalysis
        ? localAnalysis.findings.summary.high_risk_count +
        localAnalysis.findings.summary.medium_risk_count +
        localAnalysis.findings.summary.low_risk_count
        : 0;

    // Check if another project is uploading (not from HomeContent)
    const isOtherProjectUploading = globalIsUploading && uploadingProjectId !== null && uploadingProjectId !== 'home';

    // All connections must be verified and connected before upload is allowed
    // Also disable when a report job is running (BloodHound CE only supports one project at a time)
    const canUpload = !isUploading &&
        !isOtherProjectUploading &&
        !isReportJobRunning &&
        !isCheckingBackend &&
        !isCheckingBloodhound &&
        isBackendConnected &&
        isBloodhoundConnected &&
        hasBhceCredentials;
    // const _hasElectronAPI = typeof window !== 'undefined' && !!window.bloodhound;

    // ==================== RENDER ====================

    return (
        <div className="h-full overflow-x-hidden">
            <div className="max-w-4xl mx-auto p-6 md:p-10">
                {/* Welcome Header - ANSI Shadow ASCII art (landing_page blue #58a6ff, no gradient) */}
                <div className="text-center mb-10">
                    {asciiArt ? (
                        <>
                            <div className="mb-4 mt-3 overflow-hidden flex justify-center">
                                <pre
                                    className="inline-block whitespace-pre font-mono text-sm sm:text-base md:text-lg lg:text-xl leading-[1.1] text-[#58a6ff] select-none"
                                    style={{ fontFamily: 'monospace', letterSpacing: '0.06em' }}
                                >
                                    {asciiArt}
                                </pre>
                            </div>
                            <p className="text-aegis-text-muted font-mono text-xs sm:text-sm tracking-wide mb-5">
                                {appVersion ? `v${appVersion}` : 'v—'}{' '}
                                <span className="text-aegis-text-subtle">•</span>{' '}
                                {isLatestRelease === true
                                    ? 'latest release'
                                    : isLatestRelease === false && latestReleaseVersion
                                        ? `v${appVersion} → v${latestReleaseVersion}`
                                        : 'AD Security Analysis Tool'}
                            </p>
                            <p className="text-[#58a6ff] font-mono text-base sm:text-lg uppercase tracking-widest mt-3 mb-4">
                                // see what attackers see
                            </p>
                        </>
                    ) : (
                        <h1 className="text-4xl md:text-6xl font-semibold text-[#58a6ff]">
                            AEGIS
                        </h1>
                    )}
                    <p className="text-aegis-text-muted text-lg">
                        Upload BloodHound data to analyze attack paths and generate security reports
                    </p>
                </div>

                {/* Upload Section */}
                <div className="mb-6">
                    {/* EMPTY STATE - Dropzone */}
                    {!isUploading && !localAnalysis && (
                        <div
                            onClick={canUpload ? handleBrowseClick : undefined}
                            className={`border-2 border-dashed rounded-xl p-12 text-center transition-all ${canUpload
                                ? 'border-aegis-border-light hover:border-aegis-accent hover:bg-aegis-accent/[0.03] cursor-pointer'
                                : 'border-aegis-border cursor-not-allowed opacity-60'
                                }`}
                        >
                            <svg className="w-12 h-12 mx-auto mb-4 text-aegis-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                            </svg>
                            <p className="text-aegis-text mb-2">Drop BloodHound file or click to browse</p>
                            <div className="flex gap-2 justify-center">
                                <span className="px-3 py-1 bg-aegis-gray rounded text-xs text-aegis-text-muted font-mono">.zip</span>
                            </div>

                            {/* Requirement notice */}
                            {!canUpload && (
                                <p className="mt-4 text-xs text-yellow-400">
                                    {isReportJobRunning
                                        ? 'A report is currently being generated. Please wait for it to complete.'
                                        : isOtherProjectUploading
                                            ? 'A BloodHound ZIP is currently being loaded in another project. Please wait for it to complete.'
                                            : isCheckingBackend || isCheckingBloodhound
                                                ? 'Checking connections...'
                                                : !isBackendConnected
                                                    ? 'Start the backend server first'
                                                    : !isBloodhoundConnected
                                                        ? 'Start BloodHound CE first'
                                                        : !hasBhceCredentials
                                                            ? 'Configure BloodHound CE API token first'
                                                            : 'Setup required'}
                                </p>
                            )}

                            {/* Upload in progress notice */}
                            {isOtherProjectUploading && (
                                <div className="mt-4 flex items-center justify-center gap-2 text-aegis-accent">
                                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                    <span className="text-xs">Upload in progress...</span>
                                </div>
                            )}
                        </div>
                    )}

                    {/* LOADING STATE */}
                    {isUploading && (
                        <div className="bg-aegis-dark border border-aegis-border-light rounded-xl overflow-hidden">
                            {/* File Header */}
                            <div className="px-5 py-4 border-b border-aegis-border-light flex items-center gap-3">
                                <div className="w-8 h-8 rounded-lg bg-aegis-gray-light flex items-center justify-center">
                                    <svg className="w-4 h-4 text-aegis-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                    </svg>
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium text-white truncate">{selectedFileName}</p>
                                </div>
                            </div>

                            {/* Progress Section */}
                            <AsciiProgressBar
                                progress={
                                    uploadStep === 'selecting' ? 10 :
                                        uploadStep === 'uploading' ? 45 :
                                            uploadStep === 'extracting' ? 75 :
                                                uploadStep === 'done' ? 100 : 0
                                }
                                step={
                                    uploadStep === 'selecting' ? 'select' :
                                        uploadStep === 'uploading' ? 'upload' :
                                            uploadStep === 'extracting' ? 'extract' :
                                                uploadStep === 'done' ? 'done' : 'init'
                                }
                                action={
                                    uploadStep === 'selecting' ? 'file dialog' :
                                        uploadStep === 'uploading' ? 'BloodHound CE' :
                                            uploadStep === 'extracting' ? 'Neo4j findings' :
                                                uploadStep === 'done' ? 'complete' : 'initializing'
                                }
                                elapsedSeconds={elapsedSeconds}
                                isComplete={uploadStep === 'done'}
                            />

                            {/* Cancel Button - shown during extracting */}
                            {uploadStep === 'extracting' && (
                                <div className="px-5 pb-5">
                                    <button
                                        onClick={handleCancelIngestion}
                                        className="px-3 py-1.5 text-xs text-aegis-error-muted border border-aegis-error-muted/30 rounded-lg hover:bg-aegis-error-muted/10 hover:border-aegis-error-muted/50 transition-all flex items-center gap-1.5"
                                    >
                                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                        </svg>
                                        Cancel Ingestion
                                    </button>
                                </div>
                            )}
                        </div>
                    )}

                    {/* SUCCESS STATE - New Unified Card Design */}
                    {!isUploading && localAnalysis && (
                        <div className="bg-aegis-dark border border-aegis-border-light rounded-xl overflow-hidden">
                            {/* File Header - matches loading state */}
                            <div className="px-5 py-4 border-b border-aegis-border-light flex items-center gap-3">
                                <div className="w-8 h-8 rounded-lg bg-aegis-gray-light flex items-center justify-center">
                                    <svg className="w-4 h-4 text-aegis-text-muted" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                    </svg>
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium text-white truncate">{selectedFileName}</p>
                                </div>
                                <button
                                    onClick={handleResetUpload}
                                    className="p-1.5 text-aegis-text-subtle hover:text-aegis-text hover:bg-aegis-gray-light rounded-lg transition-all"
                                >
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                    </svg>
                                </button>
                            </div>

                            {/* Meta Tags Section */}
                            <div className="px-5 py-4 border-b border-aegis-border-light">
                                {/* Meta Tags */}
                                <div className="flex flex-wrap gap-2">
                                    {/* Domain Badges - Show all domains */}
                                    {localAnalysis.findings.domains.map((domain, idx) => (
                                        <span
                                            key={domain}
                                            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[13px] font-medium border"
                                            style={{
                                                background: 'rgba(88, 166, 255, 0.1)',
                                                borderColor: 'rgba(88, 166, 255, 0.3)',
                                                color: '#58a6ff'
                                            }}>
                                            {idx === 0 && (
                                                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                                                </svg>
                                            )}
                                            {domain}
                                        </span>
                                    ))}
                                    {/* Findings Badge */}
                                    <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[13px] font-medium border"
                                        style={{
                                            background: 'rgba(251, 191, 36, 0.1)',
                                            borderColor: 'rgba(251, 191, 36, 0.3)',
                                            color: '#fbbf24'
                                        }}>
                                        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                        </svg>
                                        {totalFindings.toLocaleString()} findings
                                    </span>
                                    {/* BloodHound CE Badge */}
                                    {bhceImportSuccess && (
                                        <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[13px] font-medium border"
                                            style={{
                                                background: 'rgba(248, 81, 73, 0.1)',
                                                borderColor: 'rgba(248, 81, 73, 0.3)',
                                                color: '#f85149'
                                            }}>
                                            <BloodHoundIcon size={14} className="text-aegis-error-muted" />
                                            BloodHound CE
                                        </span>
                                    )}
                                </div>
                            </div>

                            {/* T0 Configuration Section - Integrated */}
                            <div className="px-5 py-5 bg-aegis-gray border-b border-aegis-border-light">
                                <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2">
                                        <svg className="w-[18px] h-[18px] text-aegis-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                        </svg>
                                        <span className="text-[15px] font-semibold text-white">Tier 0 Assets</span>
                                    </div>
                                    <span className="inline-flex items-center gap-1 px-2 py-1 text-[12px] font-semibold rounded"
                                        style={{
                                            background: 'rgba(88, 166, 255, 0.15)',
                                            border: '1px solid rgba(88, 166, 255, 0.3)',
                                            color: '#58a6ff'
                                        }}>
                                        {isDetectingT0 ? (
                                            <>
                                                <svg className="w-3 h-3 animate-spin" fill="none" viewBox="0 0 24 24">
                                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                                                </svg>
                                                detecting...
                                            </>
                                        ) : t0Configured ? (
                                            `${t0AutoDetectedAssets.length} configured`
                                        ) : (
                                            `${t0AutoDetectedAssets.length} detected`
                                        )}
                                    </span>
                                </div>
                                <p className="text-[13px] text-aegis-text-muted leading-relaxed mb-4">
                                    {t0Configured ? (
                                        <>T0 assets configured. Paths between these assets are classified as T0 lateral and are not counted as actionable findings in the report.</>
                                    ) : (
                                        <>We detected {t0AutoDetectedAssets.length} privileged assets (Domain Admins, Enterprise Admins, Domain Controllers, etc.). Paths between these are classified as T0 lateral and are not counted as actionable findings. Configure to add or remove assets, or generate to use defaults.</>
                                    )}
                                </p>
                                <button
                                    onClick={handleT0Configure}
                                    disabled={isDetectingT0}
                                    className="inline-flex items-center gap-2 px-4 py-2 bg-transparent border border-aegis-border rounded-lg text-[13px] font-medium text-aegis-text hover:border-aegis-accent hover:text-aegis-accent transition-colors disabled:opacity-50"
                                >
                                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                                    </svg>
                                    {t0Configured ? 'Edit T0 Configuration' : 'Configure T0 Assets'}
                                </button>
                            </div>

                            {/* Generate Button Section */}
                            <div className="px-5 py-5">
                                <button
                                    onClick={handleGenerateReport}
                                    disabled={isReportJobRunning}
                                    className={`w-full py-3.5 px-6 text-white rounded-xl text-base font-semibold flex items-center justify-center gap-2 transition-colors ${isReportJobRunning
                                        ? 'bg-gray-600 cursor-not-allowed opacity-60'
                                        : 'bg-aegis-info-dark hover:bg-aegis-info-muted'
                                        }`}
                                >
                                    {isReportJobRunning ? (
                                        <>
                                            <svg className="w-5 h-5 animate-spin" fill="none" viewBox="0 0 24 24">
                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                            </svg>
                                            Report In Progress...
                                        </>
                                    ) : (
                                        <>
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                            </svg>
                                            Generate Security Report
                                        </>
                                    )}
                                </button>

                                {/* Upload Different Link */}
                                <button
                                    onClick={handleResetUpload}
                                    className="w-full text-center mt-4 text-aegis-text-muted hover:text-aegis-text text-sm transition-colors"
                                >
                                    Upload different file
                                </button>
                            </div>
                        </div>
                    )}

                    <input
                        ref={fileInputRef}
                        type="file"
                        accept=".zip,.json"
                        onChange={handleFileSelect}
                        className="hidden"
                    />
                </div>

                {/* Connection Status - Terminal Style */}
                <div className="mb-6">
                    <div className="flex flex-col bg-black/90 overflow-hidden rounded-lg border border-white/10">
                        {/* Terminal Header */}
                        <div className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-white/10">
                            <div className="flex items-center gap-2">
                                <div className="flex gap-1.5">
                                    <div className="w-3 h-3 rounded-full bg-red-500"></div>
                                    <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                                    <div className="w-3 h-3 rounded-full bg-green-500"></div>
                                </div>
                                <span className="text-xs text-white/60 ml-2 font-mono">connection.status</span>
                            </div>
                            <div className="flex items-center gap-2">
                                <button
                                    onClick={handleCheckConnections}
                                    className="text-white/60 hover:text-white transition-colors p-1"
                                    title="Refresh status"
                                    disabled={isCheckingBackend || isCheckingBloodhound}
                                >
                                    <svg className={`w-3 h-3 ${isCheckingBackend || isCheckingBloodhound ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                    </svg>
                                </button>
                                <div className={`w-2 h-2 rounded-full ${isBackendConnected && isBloodhoundConnected && hasBhceCredentials ? 'bg-green-500' :
                                    isCheckingBackend || isCheckingBloodhound ? 'bg-yellow-500' : 'bg-red-500'
                                    } animate-pulse`}></div>
                                <span className="text-xs text-white/60 font-mono">
                                    {isCheckingBackend || isCheckingBloodhound ? 'Checking...' :
                                        isBackendConnected && isBloodhoundConnected && hasBhceCredentials ? 'Ready' :
                                            'Setup Required'}
                                </span>
                            </div>
                        </div>

                        {/* Terminal Content */}
                        <div className="p-4 font-mono text-sm">
                            <div className="space-y-2">
                                <ConnectionStatusRow
                                    label="Backend (RAG)"
                                    isChecking={isCheckingBackend}
                                    isConnected={isBackendConnected}
                                />
                                <ConnectionStatusRow
                                    label="BloodHound CE"
                                    isChecking={isCheckingBloodhound}
                                    isConnected={isBloodhoundConnected}
                                    subtext={isBloodhoundConnected ? 'Neo4j' : undefined}
                                />
                                <div className="flex items-center gap-2 text-xs">
                                    <span className="text-gray-500 font-mono shrink-0 w-32">
                                        API Token ({neo4jMode === 'docker' ? 'Docker' : 'Custom'}):
                                    </span>
                                    <span className={`text-xs font-mono ${hasBhceCredentials ? 'text-green-400' : 'text-yellow-400'}`}>
                                        {hasBhceCredentials ? '[CONFIGURED]' : '[NOT SET]'}
                                    </span>
                                    {bhceImportSuccess && <span className="text-green-400 text-xs">Data Imported</span>}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* BloodHound CE Setup Guide - Mode-aware */}
                {(!hasBhceCredentials || !isBloodhoundConnected) && (
                    <div className="mb-6">
                        <div className="aegis-card border-l-4 border-l-aegis-accent">
                            <div className="flex items-start space-x-3">
                                <div className="p-2 bg-aegis-accent/20 rounded-lg shrink-0">
                                    <svg className="w-5 h-5 text-aegis-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                </div>
                                <div className="flex-1">
                                    <h3 className="text-base font-bold text-aegis-accent mb-2">
                                        Setup Required: {neo4jMode === 'custom' ? 'Custom BloodHound Connection' : 'BloodHound CE'}
                                    </h3>
                                    <p className="text-sm text-white/70 mb-4">
                                        {neo4jMode === 'custom'
                                            ? 'Connect AEGIS to your existing BloodHound CE installation:'
                                            : 'BloodHound CE handles all data parsing and import. Follow these steps:'}
                                    </p>

                                    {neo4jMode === 'custom' ? (
                                        /* Custom Mode Instructions */
                                        <div className="space-y-3 text-sm">
                                            <div className="flex items-start space-x-3">
                                                <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${isBloodhoundConnected ? 'bg-green-500 text-white' : 'bg-aegis-accent/20 text-aegis-accent'}`}>
                                                    {isBloodhoundConnected ? '✓' : '1'}
                                                </span>
                                                <div>
                                                    <p className="text-white/90">Configure your Neo4j connection in <strong>Settings → Custom Connection</strong></p>
                                                    <p className="text-white/50 text-xs mt-1">Enter your Neo4j URI (e.g., bolt://localhost:7687) and credentials</p>
                                                </div>
                                            </div>

                                            <div className="flex items-start space-x-3">
                                                <span className="w-6 h-6 rounded-full bg-aegis-accent/20 text-aegis-accent flex items-center justify-center text-xs font-bold shrink-0">2</span>
                                                <div>
                                                    <p className="text-white/90">Open your BloodHound CE Web Interface</p>
                                                    <p className="text-white/50 text-xs mt-1">Navigate to your BloodHound CE instance and create an API token</p>
                                                </div>
                                            </div>

                                            <div className="flex items-start space-x-3">
                                                <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${hasBhceCredentials ? 'bg-green-500 text-white' : 'bg-aegis-accent/20 text-aegis-accent'}`}>
                                                    {hasBhceCredentials ? '✓' : '3'}
                                                </span>
                                                <div>
                                                    <p className="text-white/90">Configure the API token in <strong>Settings → BloodHound CE API</strong></p>
                                                    <p className="text-white/50 text-xs mt-1">Enter the BloodHound CE URL and API token credentials</p>
                                                </div>
                                            </div>
                                        </div>
                                    ) : (
                                        /* Docker Mode Instructions */
                                        <div className="space-y-3 text-sm">
                                            <div className="flex items-start space-x-3">
                                                <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${isBloodhoundConnected ? 'bg-green-500 text-white' : 'bg-aegis-accent/20 text-aegis-accent'}`}>
                                                    {isBloodhoundConnected ? '✓' : '1'}
                                                </span>
                                                <div>
                                                    <p className="text-white/90">Start BloodHound CE from <strong>Settings → Setup BloodHound CE</strong></p>
                                                </div>
                                            </div>

                                            <div className="flex items-start space-x-3">
                                                <span className="w-6 h-6 rounded-full bg-aegis-accent/20 text-aegis-accent flex items-center justify-center text-xs font-bold shrink-0">2</span>
                                                <div>
                                                    <p className="text-white/90 mb-1">Open BloodHound CE Web Interface:</p>
                                                    <a
                                                        href="http://localhost:8080"
                                                        target="_blank"
                                                        rel="noopener noreferrer"
                                                        className="inline-flex items-center space-x-2 px-3 py-1.5 bg-aegis-gray rounded-lg hover:bg-aegis-gray-light transition-colors"
                                                    >
                                                        <svg className="w-4 h-4 text-aegis-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                                                        </svg>
                                                        <span className="text-aegis-accent font-mono">http://localhost:8080</span>
                                                    </a>
                                                    <p className="text-white/70 text-xs mt-1.5">
                                                        Login: <code className="bg-aegis-gray px-1.5 py-0.5 rounded">admin</code> / <code className="bg-aegis-gray px-1.5 py-0.5 rounded">aegisadmin123</code>
                                                    </p>
                                                </div>
                                            </div>

                                            <div className="flex items-start space-x-3">
                                                <span className="w-6 h-6 rounded-full bg-aegis-accent/20 text-aegis-accent flex items-center justify-center text-xs font-bold shrink-0">3</span>
                                                <div>
                                                    <p className="text-white/90">Create an API Token: <strong>Profile → API Tokens → Create Token</strong></p>
                                                </div>
                                            </div>

                                            <div className="flex items-start space-x-3">
                                                <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${hasBhceCredentials ? 'bg-green-500 text-white' : 'bg-aegis-accent/20 text-aegis-accent'}`}>
                                                    {hasBhceCredentials ? '✓' : '4'}
                                                </span>
                                                <div>
                                                    <p className="text-white/90">Configure the token in <strong>Settings → BloodHound CE API</strong></p>
                                                </div>
                                            </div>
                                        </div>
                                    )}

                                    <div className="mt-4 p-3 bg-aegis-gray/50 rounded-lg">
                                        <p className="text-xs text-white/50">
                                            <strong className="text-white/70">Why BloodHound CE?</strong> BloodHound CE properly parses your data and imports it into Neo4j with all relationships intact,
                                            enabling accurate attack path visualization and Cypher queries.
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {/* Error Message */}
                {errorMessage && (
                    <div className="mb-6 px-4 py-4 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                            <svg className="w-5 h-5 text-red-300" fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                            </svg>
                            <p className="text-red-300">{errorMessage}</p>
                        </div>
                        <button onClick={() => setErrorMessage(null)} className="p-1 hover:bg-red-500/20 rounded transition-colors">
                            <svg className="w-4 h-4 text-red-300" fill="currentColor" viewBox="0 0 20 20">
                                <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                            </svg>
                        </button>
                    </div>
                )}

                {/* Quick Tips */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <QuickTip
                        icon={<UploadIcon />}
                        title="Upload Data"
                        description="Import BloodHound ZIP exports for analysis"
                    />
                    <QuickTip
                        icon={<AnalyzeIcon />}
                        title="Analyze Paths"
                        description="AI-powered attack path discovery"
                    />
                    <QuickTip
                        icon={<ShieldTipIcon />}
                        title="Get Remediation"
                        description="PowerShell scripts to fix vulnerabilities"
                    />
                </div>
            </div>

            {/* Tier 0 Configuration Modal - key forces remount when domain changes */}
            <Tier0ConfigModal
                key={`t0-modal-${localAnalysis?.findings.domains?.[0] || 'none'}-${t0AutoDetectedAssets.length}`}
                isOpen={t0ModalOpen}
                onClose={() => setT0ModalOpen(false)}
                onSave={handleT0Save}
                domains={localAnalysis?.findings.domains || []}
                autoDetectedAssets={t0AutoDetectedAssets}
                isLoading={isDetectingT0}
            />
        </div>
    );
};

// ==================== HELPER COMPONENTS ====================

interface ConnectionStatusRowProps {
    label: string;
    isChecking: boolean;
    isConnected: boolean;
    subtext?: string;
}

const ConnectionStatusRow: React.FC<ConnectionStatusRowProps> = ({ label, isChecking, isConnected, subtext }) => (
    <div className="flex items-center gap-2 text-xs">
        <span className="text-gray-500 font-mono shrink-0 w-32">{label}:</span>
        {subtext && <span className="text-gray-400 text-xs font-mono">{subtext}</span>}
        <span className={`text-xs font-mono ${isChecking ? 'text-yellow-400' : isConnected ? 'text-green-400' : 'text-red-400'
            }`}>
            {isChecking ? '[CHECKING...]' : isConnected ? '[OK]' : '[FAIL]'}
        </span>
    </div>
);

const QuickTip: React.FC<{ icon: React.ReactNode; title: string; description: string }> = ({ icon, title, description }) => (
    <div className="aegis-card p-4 flex items-start gap-3">
        <div className="p-2 bg-aegis-accent/10 rounded-lg text-aegis-accent">{icon}</div>
        <div>
            <h4 className="font-semibold text-sm text-aegis-text">{title}</h4>
            <p className="text-xs text-aegis-text-muted">{description}</p>
        </div>
    </div>
);

const UploadIcon = () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
    </svg>
);

const AnalyzeIcon = () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
);

const ShieldTipIcon = () => (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
);

export default HomeContent;

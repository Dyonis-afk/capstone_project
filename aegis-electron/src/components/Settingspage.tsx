/**
 * Settings Page for AEGIS
 * Location: src/pages/SettingsPage.tsx
 * 
 * Handles Neo4j connection configuration (Docker vs Custom),
 * API backend settings, and app preferences.
 */

import React, { useState, useEffect, useCallback } from 'react';
import toast from 'react-hot-toast';
import { API_URL } from '../config/api';
import {
    Settings,
    Database,
    Server,
    CheckCircle,
    XCircle,
    AlertCircle,
    Loader2,
    RefreshCw,
    Play,
    Square,
    Trash2,
    Download,
    Info,
    Shield
} from 'lucide-react';
import BloodHoundIcon from './BloodHoundIcon';
// import DockerProgressPanel, { DockerStep } from '../components/DockerProgressPanel';
import DockerProgressPanel, { DockerStep } from './Dockerprogresspanel';
import { useConnectionStore, setNeo4jMode as setGlobalNeo4jMode, useNeo4jMode } from '../stores/connectionStore';
import { useProjectStore } from '../stores/projectStore';

// ==================== TYPES ====================

interface Neo4jConfig {
    uri: string;
    username: string;
    password: string;
}

interface DockerStatus {
    dockerInstalled: boolean;
    dockerRunning: boolean;
    containerExists: boolean;
    containerRunning: boolean;
    neo4jReady: boolean;
    error?: string;
}

interface ConnectionStatus {
    connected: boolean;
    nodeCount?: number;
    relationshipCount?: number;
    error?: string;
}

type Neo4jMode = 'docker' | 'custom';

// ==================== DOCKER STEP DEFINITIONS ====================
// BloodHound CE stack: Neo4j + Postgres + BloodHound API

const SETUP_STEPS: DockerStep[] = [
    { id: 'docker-check', label: 'Checking Docker', status: 'pending' },
    { id: 'pull-images', label: 'Pulling Images', status: 'pending' },
    { id: 'start-stack', label: 'Starting BloodHound CE', status: 'pending' },
    { id: 'wait-neo4j', label: 'Neo4j Initializing', status: 'pending' },
    { id: 'wait-bloodhound', label: 'BloodHound Ready', status: 'pending' },
];

const START_STEPS: DockerStep[] = [
    { id: 'docker-check', label: 'Checking Docker', status: 'pending' },
    { id: 'start-stack', label: 'Starting BloodHound CE', status: 'pending' },
    { id: 'wait-ready', label: 'Waiting for Ready', status: 'pending' },
];

const STOP_STEPS: DockerStep[] = [
    { id: 'stop-stack', label: 'Stopping BloodHound CE', status: 'pending' },
    { id: 'cleanup', label: 'Cleanup', status: 'pending' },
];

const RESET_STEPS: DockerStep[] = [
    { id: 'stop-stack', label: 'Stopping BloodHound CE', status: 'pending' },
    { id: 'remove-containers', label: 'Removing Containers', status: 'pending' },
    { id: 'remove-volumes', label: 'Removing Data', status: 'pending' },
];

// ==================== SETTINGS PAGE ====================

const SettingsPage: React.FC = () => {
    // Currently ACTIVE mode from global store (what the app is actually using)
    const activeNeo4jMode = useNeo4jMode();

    // Local tab selection (which panel is being viewed - may differ from active mode)
    const [selectedTab, setSelectedTab] = useState<Neo4jMode>('docker');

    // Global connection store (for syncing status after operations)
    const { checkAll: syncGlobalConnectionStatus, checkToken } = useConnectionStore();

    // Project store (for resetting active project when switching modes)
    const { setActiveProjectId, activeProjectId } = useProjectStore();

    // Docker status (local detailed state for Settings UI)
    const [dockerStatus, setDockerStatus] = useState<DockerStatus | null>(null);
    const [refreshingDocker, setRefreshingDocker] = useState(false);

    // Docker Progress Panel State
    const [showProgress, setShowProgress] = useState(false);
    const [progressTitle, setProgressTitle] = useState('');
    const [progressSteps, setProgressSteps] = useState<DockerStep[]>([]);
    const [progressLogs, setProgressLogs] = useState<string[]>([]);
    const [progressPercent, setProgressPercent] = useState(0);
    const [progressStatus, setProgressStatus] = useState<'running' | 'success' | 'error'>('running');
    const [progressError, setProgressError] = useState<string | undefined>();

    // Custom Neo4j connection
    const [customConfig, setCustomConfig] = useState<Neo4jConfig>({
        uri: 'bolt://localhost:7687',
        username: 'neo4j',
        password: ''
    });
    const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus | null>(null);
    const [testingConnection, setTestingConnection] = useState(false);

    // API Backend
    const [apiUrl, setApiUrl] = useState(API_URL);
    const [apiStatus, setApiStatus] = useState<'connected' | 'disconnected' | 'checking'>('checking');
    const [refreshingApi, setRefreshingApi] = useState(false);

    // BloodHound CE API Credentials
    const [bhceCredentials, setBhceCredentials] = useState({
        url: 'http://localhost:8080',
        tokenId: '',
        tokenKey: ''
    });
    const [bhceStatus, setBhceStatus] = useState<'connected' | 'disconnected' | 'checking' | 'not_configured'>('not_configured');
    const [testingBhce, setTestingBhce] = useState(false);
    const [savingBhce, setSavingBhce] = useState(false);

    // Auto-updater state
    const [currentVersion, setCurrentVersion] = useState<string>('');
    const [updateState, setUpdateState] = useState<'idle' | 'checking' | 'available' | 'downloading' | 'ready' | 'error' | 'up-to-date'>('idle');
    const [updateInfo, setUpdateInfo] = useState<{ version: string; releaseNotes?: string | null } | null>(null);
    const [updateProgress, setUpdateProgress] = useState(0);
    const [updateError, setUpdateError] = useState<string | null>(null);

    // Existing BloodHound conflict detection
    const [showBloodHoundConflictModal, setShowBloodHoundConflictModal] = useState(false);
    const [existingBloodHoundInfo, setExistingBloodHoundInfo] = useState<{
        detected: boolean;
        containers: Array<{ name: string; status: string; ports: string }>;
        conflictingPorts: number[];
        recommendation: string;
    } | null>(null);
    const [pendingDockerAction, setPendingDockerAction] = useState<'setup' | 'start' | null>(null);
    const [stoppingExistingBH, setStoppingExistingBH] = useState(false);

    // ==================== PROGRESS HELPERS ====================

    const addLog = useCallback((message: string) => {
        setProgressLogs(prev => [...prev, message]);
    }, []);

    const updateStep = useCallback((stepId: string, status: DockerStep['status']) => {
        setProgressSteps(prev => prev.map(step =>
            step.id === stepId ? { ...step, status } : step
        ));
    }, []);

    const calculateProgress = useCallback((steps: DockerStep[]) => {
        const completed = steps.filter(s => s.status === 'completed').length;
        const running = steps.filter(s => s.status === 'running').length;
        const total = steps.length;
        return Math.round(((completed + running * 0.5) / total) * 100);
    }, []);

    const startProgress = useCallback((title: string, steps: DockerStep[]) => {
        setProgressTitle(title);
        setProgressSteps(steps.map(s => ({ ...s, status: 'pending' })));
        setProgressLogs([]);
        setProgressPercent(0);
        setProgressStatus('running');
        setProgressError(undefined);
        setShowProgress(true);
    }, []);

    const dismissProgress = useCallback(() => {
        setShowProgress(false);
    }, []);

    // ==================== EFFECTS ====================

    // Sync selected tab with active mode on mount and when active mode changes
    useEffect(() => {
        setSelectedTab(activeNeo4jMode);
    }, [activeNeo4jMode]);

    useEffect(() => {
        loadSettings();
        checkDockerStatus();
        checkApiStatus();
    }, []);

    // Listen for Docker progress events from main process
    useEffect(() => {
        if (window.docker?.onProgress) {
            const unsubscribe = window.docker.onProgress((message: string) => {
                addLog(message);
            });
            return () => unsubscribe();
        }
    }, [addLog]);

    // Update progress percentage when steps change
    useEffect(() => {
        setProgressPercent(calculateProgress(progressSteps));
    }, [progressSteps, calculateProgress]);

    // ==================== SETTINGS PERSISTENCE ====================

    const loadSettings = async () => {
        try {
            // Load saved config (mode is loaded from global store via useNeo4jMode)
            const savedConfig = localStorage.getItem('aegis_neo4j_config');
            if (savedConfig) setCustomConfig(JSON.parse(savedConfig));

            const savedApiUrl = localStorage.getItem('aegis_api_url');
            if (savedApiUrl) setApiUrl(savedApiUrl);

            if (window.neo4j?.getConfig) {
                const config = await window.neo4j.getConfig();
                if (config) {
                    setCustomConfig(prev => ({ ...prev, ...config }));
                }
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    };

    const saveSettings = () => {
        localStorage.setItem('aegis_neo4j_config', JSON.stringify(customConfig));
        localStorage.setItem('aegis_api_url', apiUrl);
    };

    // Activate a mode - switch to using this mode (updates global store)
    // IMPORTANT: This also resets the active project since Docker and Custom
    // connect to different BloodHound instances with different data
    const activateMode = (mode: Neo4jMode) => {
        const previousMode = activeNeo4jMode;

        // Save mode to localStorage and global store
        localStorage.setItem('aegis_neo4j_mode', mode);
        setGlobalNeo4jMode(mode);
        setSelectedTab(mode);

        // Reset active project since data won't transfer between modes
        if (previousMode !== mode && activeProjectId) {
            setActiveProjectId(null);
            toast.success(
                `Switched to ${mode === 'docker' ? 'Docker' : 'Custom'} mode. Active project cleared - upload data to activate a project.`,
                { duration: 5000 }
            );
        } else {
            toast.success(`Switched to ${mode === 'docker' ? 'Docker' : 'Custom'} mode`);
        }
    };

    // ==================== EXISTING BLOODHOUND DETECTION ====================

    /**
     * Check for existing non-AEGIS BloodHound containers before Docker operations.
     * Returns true if we should proceed, false if modal was shown.
     */
    const checkForExistingBloodHound = async (action: 'setup' | 'start'): Promise<boolean> => {
        if (!window.docker?.detectExistingBloodHound) {
            return true; // API not available, proceed anyway
        }

        try {
            const info = await window.docker.detectExistingBloodHound();

            if (info.detected && info.conflictingPorts.length > 0) {
                // Show conflict modal
                setExistingBloodHoundInfo(info);
                setPendingDockerAction(action);
                setShowBloodHoundConflictModal(true);
                return false; // Don't proceed, show modal instead
            }

            return true; // No conflict, proceed
        } catch (error) {
            console.error('Error checking for existing BloodHound:', error);
            return true; // On error, proceed anyway
        }
    };

    /**
     * User chose to proceed with AEGIS Docker, stop existing BloodHound first
     */
    const handleProceedWithAegisDocker = async () => {
        if (!window.docker?.stopExistingBloodHound) return;

        setStoppingExistingBH(true);

        try {
            const result = await window.docker.stopExistingBloodHound();

            if (result.success) {
                toast.success('Stopped existing BloodHound containers');
                setShowBloodHoundConflictModal(false);

                // Proceed with the pending action
                if (pendingDockerAction === 'setup') {
                    await performSetupDocker();
                } else if (pendingDockerAction === 'start') {
                    await performStartDocker();
                }
            } else {
                toast.error(result.error || 'Failed to stop existing BloodHound');
            }
        } catch (error: any) {
            toast.error('Error stopping existing BloodHound: ' + error.message);
        } finally {
            setStoppingExistingBH(false);
            setPendingDockerAction(null);
        }
    };

    /**
     * User chose to use Custom mode instead
     */
    const handleUseCustomMode = () => {
        setShowBloodHoundConflictModal(false);
        setPendingDockerAction(null);
        setSelectedTab('custom');
        activateMode('custom');
    };

    // ==================== DOCKER OPERATIONS ====================

    const checkDockerStatus = async () => {
        if (!window.docker) {
            console.warn('Docker API not available');
            toast.error('Docker API not available');
            return;
        }

        setRefreshingDocker(true);
        try {
            const status = await window.docker.getStatus();
            setDockerStatus(status);

            // Sync with global connection store
            await syncGlobalConnectionStatus();

            toast.success('Docker status refreshed');
        } catch (error: any) {
            console.error('Failed to check Docker status:', error);
            setDockerStatus({
                dockerInstalled: false,
                dockerRunning: false,
                containerExists: false,
                containerRunning: false,
                neo4jReady: false,
                error: error.message
            });
            const shortError = error.message ? error.message.substring(0, 60) : 'Failed to check Docker status';
            toast.error(shortError);
        } finally {
            setRefreshingDocker(false);
        }
    };

    const startDocker = async () => {
        if (!window.docker) return;

        // Check for existing BloodHound first
        const shouldProceed = await checkForExistingBloodHound('start');
        if (!shouldProceed) return; // Modal was shown

        await performStartDocker();
    };

    const performStartDocker = async () => {
        if (!window.docker) return;

        startProgress('Starting BloodHound CE', START_STEPS);

        try {
            // Step 1: Check Docker
            updateStep('docker-check', 'running');
            addLog('Checking Docker daemon...');
            await new Promise(r => setTimeout(r, 300));

            const status = await window.docker.getStatus();
            if (!status.dockerRunning) {
                throw new Error('Docker Desktop is not running');
            }
            updateStep('docker-check', 'completed');
            addLog('Docker is running ✓');

            // Step 2: Start BloodHound CE stack
            updateStep('start-stack', 'running');
            addLog('Starting BloodHound CE stack...');
            addLog('  - Neo4j, Postgres, BloodHound API');

            const result = await window.docker.start();
            if (!result.success) {
                throw new Error(result.error || 'Failed to start BloodHound CE');
            }
            updateStep('start-stack', 'completed');
            addLog('BloodHound CE started ✓');

            // Step 3: Wait for ready
            updateStep('wait-ready', 'running');
            addLog('Waiting for services to initialize...');

            let ready = false;
            for (let i = 0; i < 20; i++) {
                const currentStatus = await window.docker.getStatus();
                if (currentStatus.neo4jReady) {
                    ready = true;
                    break;
                }
                await new Promise(r => setTimeout(r, 1500));
            }

            updateStep('wait-ready', 'completed');
            addLog(ready ? 'BloodHound CE is ready! ✓' : 'Stack running (initializing...)');

            // Success
            setProgressStatus('success');
            setProgressPercent(100);
            toast.success('BloodHound CE started');
            await checkDockerStatus();

        } catch (error: any) {
            console.error('Docker start error:', error);
            const currentRunning = progressSteps.find(s => s.status === 'running');
            if (currentRunning) updateStep(currentRunning.id, 'error');
            setProgressStatus('error');
            setProgressError(error.message);
            addLog(`ERROR: ${error.message}`);
            toast.error('Failed to start BloodHound CE');
        }
    };

    const stopDocker = async () => {
        if (!window.docker) return;

        startProgress('Stopping BloodHound CE', STOP_STEPS);

        try {
            updateStep('stop-stack', 'running');
            addLog('Stopping BloodHound CE stack...');

            const result = await window.docker.stop();
            if (!result.success) {
                throw new Error(result.error || 'Failed to stop BloodHound CE');
            }
            updateStep('stop-stack', 'completed');
            addLog('BloodHound CE stopped ✓');

            updateStep('cleanup', 'running');
            addLog('Cleaning up...');
            await new Promise(r => setTimeout(r, 300));
            updateStep('cleanup', 'completed');
            addLog('Done ✓');

            setProgressStatus('success');
            setProgressPercent(100);
            toast.success('BloodHound CE stopped');
            await checkDockerStatus();

        } catch (error: any) {
            console.error('Docker stop error:', error);
            const currentRunning = progressSteps.find(s => s.status === 'running');
            if (currentRunning) updateStep(currentRunning.id, 'error');
            setProgressStatus('error');
            setProgressError(error.message);
            addLog(`ERROR: ${error.message}`);
            toast.error('Failed to stop BloodHound CE');
        }
    };

    const setupDocker = async () => {
        if (!window.docker) return;

        // Check for existing BloodHound first
        const shouldProceed = await checkForExistingBloodHound('setup');
        if (!shouldProceed) return; // Modal was shown

        await performSetupDocker();
    };

    const performSetupDocker = async () => {
        if (!window.docker) return;

        startProgress('Setting up BloodHound CE', SETUP_STEPS);

        try {
            // Step 1: Check Docker
            updateStep('docker-check', 'running');
            addLog('Checking Docker installation...');
            await new Promise(r => setTimeout(r, 300));

            const status = await window.docker.getStatus();
            if (!status.dockerInstalled) {
                throw new Error('Docker is not installed');
            }
            if (!status.dockerRunning) {
                throw new Error('Docker Desktop is not running');
            }
            updateStep('docker-check', 'completed');
            addLog('Docker is ready ✓');

            // Step 2: Pull images (BloodHound CE stack)
            updateStep('pull-images', 'running');
            addLog('Pulling BloodHound CE images...');
            addLog('  - specterops/bloodhound:latest');
            addLog('  - neo4j:4.4-community');
            addLog('  - postgres:16');
            addLog('This may take a few minutes...');

            const pullResult = await window.docker.pullImage();
            if (!pullResult.success && !pullResult.error?.includes('already')) {
                throw new Error(pullResult.error || 'Failed to pull images');
            }
            updateStep('pull-images', 'completed');
            addLog('Images ready ✓');

            // Step 3: Start BloodHound CE stack
            updateStep('start-stack', 'running');
            addLog('Starting BloodHound CE stack...');

            const startResult = await window.docker.start();
            if (!startResult.success) {
                throw new Error(startResult.error || 'Failed to start BloodHound CE');
            }
            updateStep('start-stack', 'completed');
            addLog('BloodHound CE stack started ✓');

            // Step 4: Wait for Neo4j
            updateStep('wait-neo4j', 'running');
            addLog('Waiting for Neo4j to initialize...');

            let neo4jReady = false;
            for (let i = 0; i < 30; i++) {
                const currentStatus = await window.docker.getStatus();
                if (currentStatus.neo4jReady) {
                    neo4jReady = true;
                    break;
                }
                await new Promise(r => setTimeout(r, 2000));
            }
            updateStep('wait-neo4j', 'completed');
            addLog(neo4jReady ? 'Neo4j is ready ✓' : 'Neo4j initializing...');

            // Step 5: Wait for BloodHound
            updateStep('wait-bloodhound', 'running');
            addLog('Waiting for BloodHound API...');
            await new Promise(r => setTimeout(r, 3000));
            updateStep('wait-bloodhound', 'completed');
            addLog('BloodHound CE is ready! ✓');

            setProgressStatus('success');
            setProgressPercent(100);
            toast.success('BloodHound CE setup complete!');
            await checkDockerStatus();

        } catch (error: any) {
            console.error('Docker setup error:', error);
            const currentRunning = progressSteps.find(s => s.status === 'running');
            if (currentRunning) updateStep(currentRunning.id, 'error');
            setProgressStatus('error');
            setProgressError(error.message);
            addLog(`ERROR: ${error.message}`);
            toast.error('Setup failed');
        }
    };

    const resetDocker = async () => {
        if (!window.docker) return;

        if (!confirm('This will delete all BloodHound CE data (Neo4j, Postgres). Are you sure?')) {
            return;
        }

        startProgress('Resetting BloodHound CE', RESET_STEPS);

        try {
            updateStep('stop-stack', 'running');
            addLog('Stopping BloodHound CE stack...');
            await window.docker.stop();
            updateStep('stop-stack', 'completed');
            addLog('Stopped ✓');

            updateStep('remove-containers', 'running');
            addLog('Removing containers...');
            await window.docker.remove();
            updateStep('remove-containers', 'completed');
            addLog('Containers removed ✓');

            updateStep('remove-volumes', 'running');
            addLog('Removing data volumes...');
            const resetResult = await window.docker.reset();
            if (!resetResult.success) {
                throw new Error(resetResult.error || 'Failed to remove volumes');
            }
            updateStep('remove-volumes', 'completed');
            addLog('All data removed ✓');

            setProgressStatus('success');
            setProgressPercent(100);
            toast.success('BloodHound CE has been reset');
            await checkDockerStatus();

        } catch (error: any) {
            console.error('Docker reset error:', error);
            const currentRunning = progressSteps.find(s => s.status === 'running');
            if (currentRunning) updateStep(currentRunning.id, 'error');
            setProgressStatus('error');
            setProgressError(error.message);
            addLog(`ERROR: ${error.message}`);
            toast.error('Reset failed');
        }
    };

    // ==================== NEO4J CONNECTION ====================

    const testConnection = async () => {
        setTestingConnection(true);
        setConnectionStatus(null);

        try {
            if (window.neo4j?.setConfig) {
                await window.neo4j.setConfig(customConfig);
            }

            if (window.neo4j?.testConnection) {
                const result = await window.neo4j.testConnection();
                setConnectionStatus(result);

                if (result.connected) {
                    saveSettings();
                    toast.success('Connected to Neo4j');
                } else {
                    toast.error(result.error || 'Connection failed');
                }
            }
        } catch (error: any) {
            setConnectionStatus({ connected: false, error: error.message });
            toast.error('Connection test failed');
        } finally {
            setTestingConnection(false);
        }
    };

    // ==================== API STATUS ====================

    const checkApiStatus = async () => {
        setRefreshingApi(true);
        setApiStatus('checking');

        try {
            const response = await fetch(`${apiUrl}/health`, {
                method: 'GET',
                signal: AbortSignal.timeout(5000)
            });

            if (response.ok) {
                setApiStatus('connected');
                toast.success('Backend connected');
            } else {
                setApiStatus('disconnected');
                toast.error('Backend not responding');
            }
        } catch (error) {
            setApiStatus('disconnected');
            toast.error('Failed to connect to backend');
        } finally {
            setRefreshingApi(false);
        }
    };

    // ==================== BLOODHOUND CE API ====================

    const loadBhceCredentials = async () => {
        if (!window.bloodhoundCE) return;

        try {
            // Load credentials for the current mode (Docker vs Custom have separate tokens)
            const creds = await window.bloodhoundCE.getCredentials(activeNeo4jMode);
            if (creds && creds.tokenId && creds.tokenKey) {
                setBhceCredentials(creds);
                setBhceStatus('checking');

                // Auto-test connection when credentials exist
                try {
                    const result = await window.bloodhoundCE.testConnection();
                    setBhceStatus(result.success ? 'connected' : 'disconnected');
                } catch {
                    setBhceStatus('disconnected');
                }
            } else {
                // No credentials for this mode - clear the input fields
                // URL defaults to localhost:8080 since BloodHound CE requires Docker either way
                setBhceCredentials({
                    url: 'http://localhost:8080',
                    tokenId: '',
                    tokenKey: ''
                });
                setBhceStatus('not_configured');
            }
        } catch (error) {
            console.error('Failed to load BHCE credentials:', error);
        }
    };

    const saveBhceCredentials = async () => {
        if (!window.bloodhoundCE) {
            console.error('[Settings] BloodHound CE API not available');
            toast.error('BloodHound CE API not available - please restart the app');
            return false;
        }

        setSavingBhce(true);
        try {
            // Save credentials for the current mode (Docker vs Custom have separate tokens)
            console.log(`[Settings] Saving BHCE credentials for mode: ${activeNeo4jMode}...`);
            const result = await window.bloodhoundCE.setCredentials(bhceCredentials, activeNeo4jMode);
            if (result.success) {
                toast.success('BloodHound CE credentials saved');
                setBhceStatus('disconnected'); // Saved but not tested
                // Update global connection store so other screens see the token is configured
                await checkToken(true);
                return true;
            } else {
                toast.error(result.error || 'Failed to save credentials');
                return false;
            }
        } catch (error: any) {
            console.error('[Settings] Failed to save credentials:', error);
            toast.error('Failed to save credentials: ' + (error.message || 'Unknown error'));
            return false;
        } finally {
            setSavingBhce(false);
        }
    };

    const testBhceConnection = async () => {
        console.log('[Settings] Testing BHCE connection...');

        if (!window.bloodhoundCE) {
            console.error('[Settings] BloodHound CE API not available');
            toast.error('BloodHound CE API not available - please restart the app');
            return;
        }

        // Check if credentials are filled
        if (!bhceCredentials.tokenId || !bhceCredentials.tokenKey) {
            toast.error('Please enter Token ID and Token Key');
            return;
        }

        // First save the credentials
        const saved = await saveBhceCredentials();
        if (!saved) {
            return;
        }

        setTestingBhce(true);
        setBhceStatus('checking');

        try {
            console.log('[Settings] Calling testConnection...');
            const result = await window.bloodhoundCE.testConnection();
            console.log('[Settings] Test result:', result);

            if (result.success) {
                setBhceStatus('connected');
                toast.success('BloodHound CE API connected!');
            } else {
                setBhceStatus('disconnected');
                toast.error(result.error || 'Connection failed');
            }
        } catch (error: any) {
            console.error('[Settings] Test connection error:', error);
            setBhceStatus('disconnected');
            toast.error('Failed to test connection: ' + (error.message || 'Unknown error'));
        } finally {
            setTestingBhce(false);
        }
    };

    // Load BHCE credentials on mount and when mode changes
    // Docker and Custom modes have separate credential storage
    useEffect(() => {
        loadBhceCredentials();
    }, [activeNeo4jMode]);

    // ==================== AUTO-UPDATER ====================

    // Load version and setup updater listeners
    useEffect(() => {
        // Get current version
        window.updater?.getVersion().then(setCurrentVersion);

        // Setup update listeners
        const unsubChecking = window.updater?.onChecking(() => setUpdateState('checking'));
        const unsubAvailable = window.updater?.onUpdateAvailable((info) => {
            setUpdateState('downloading');
            setUpdateInfo(info);
        });
        const unsubNotAvailable = window.updater?.onUpdateNotAvailable(() => setUpdateState('up-to-date'));
        const unsubProgress = window.updater?.onDownloadProgress((prog) => setUpdateProgress(prog.percent));
        const unsubDownloaded = window.updater?.onUpdateDownloaded((info) => {
            setUpdateState('ready');
            setUpdateInfo(info);
        });
        const unsubError = window.updater?.onError((err) => {
            setUpdateState('error');
            setUpdateError(err.message);
        });

        return () => {
            unsubChecking?.();
            unsubAvailable?.();
            unsubNotAvailable?.();
            unsubProgress?.();
            unsubDownloaded?.();
            unsubError?.();
        };
    }, []);

    const handleCheckForUpdates = async () => {
        setUpdateState('checking');
        setUpdateError(null);
        try {
            await window.updater?.checkForUpdates();
        } catch (err: any) {
            setUpdateState('error');
            setUpdateError(err.message);
        }
    };

    const handleInstallUpdate = async () => {
        await window.updater?.installUpdate();
    };

    // Check if operation is running
    const isOperationRunning = showProgress && progressStatus === 'running';

    // ==================== RENDER ====================

    return (
        <div className="min-h-full bg-aegis-darker p-6">
            <div className="max-w-4xl mx-auto space-y-6">
                {/* Header */}
                <div className="flex items-center gap-3 mb-8">
                    <div className="p-2 bg-aegis-gray rounded-lg">
                        <Settings className="w-6 h-6 text-aegis-info" />
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold text-aegis-text">Settings</h1>
                        <p className="text-aegis-text-muted text-sm">Configure AEGIS connections and preferences</p>
                    </div>
                </div>

                {/* BloodHound CE / Neo4j Configuration */}
                <div className="aegis-card bg-aegis-dark">
                    <div className="mb-6">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="flex items-center gap-2 mb-1">
                                    <Database className="w-5 h-5 text-aegis-info" />
                                    <h2 className="text-lg font-semibold text-aegis-text">BloodHound CE / Neo4j</h2>
                                </div>
                                <p className="text-xs text-aegis-text-muted">Configure graph database connection</p>
                            </div>
                            {/* Current Active Mode Indicator - Shows what's ACTUALLY being used */}
                            <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
                                <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse shadow-[0_0_8px_rgba(52,211,153,0.6)]"></span>
                                <span className="text-xs text-emerald-400 font-medium">
                                    Active: {activeNeo4jMode === 'docker' ? 'Docker' : 'Custom Connection'}
                                </span>
                            </div>
                        </div>
                    </div>

                    {/* Mode Selector Tabs */}
                    <div className="flex gap-2 mb-4">
                        <button
                            onClick={() => setSelectedTab('docker')}
                            className={`flex-1 py-3 px-4 rounded-lg border transition-all relative ${selectedTab === 'docker'
                                ? 'bg-aegis-gray border-aegis-info text-aegis-info'
                                : 'bg-aegis-gray-light border-aegis-border text-aegis-text-muted hover:border-aegis-border-muted hover:bg-aegis-gray'
                                }`}
                        >
                            {/* Active badge */}
                            {activeNeo4jMode === 'docker' && (
                                <div className="absolute -top-1.5 -right-1.5 flex items-center gap-1 bg-emerald-500 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-full">
                                    <span className="w-1 h-1 bg-white rounded-full"></span>
                                    IN USE
                                </div>
                            )}
                            <div className="flex items-center justify-center gap-2">
                                <Download className="w-4 h-4" />
                                <span className="font-medium">BloodHound CE (Docker)</span>
                            </div>
                            <p className="text-xs mt-1 opacity-70">Managed Neo4j + BloodHound stack</p>
                        </button>

                        <button
                            onClick={() => setSelectedTab('custom')}
                            className={`flex-1 py-3 px-4 rounded-lg border transition-all relative ${selectedTab === 'custom'
                                ? 'bg-aegis-gray border-aegis-info text-aegis-info'
                                : 'bg-aegis-gray-light border-aegis-border text-aegis-text-muted hover:border-aegis-border-muted hover:bg-aegis-gray'
                                }`}
                        >
                            {/* Active badge */}
                            {activeNeo4jMode === 'custom' && (
                                <div className="absolute -top-1.5 -right-1.5 flex items-center gap-1 bg-emerald-500 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-full">
                                    <span className="w-1 h-1 bg-white rounded-full"></span>
                                    IN USE
                                </div>
                            )}
                            <div className="flex items-center justify-center gap-2">
                                <Server className="w-4 h-4" />
                                <span className="font-medium">Custom Connection</span>
                            </div>
                            <p className="text-xs mt-1 opacity-70">Connect to existing BloodHound CE</p>
                        </button>
                    </div>

                    {/* Activate Mode Button - Shows when viewing a mode that's not active */}
                    {selectedTab !== activeNeo4jMode && (
                        <div className="mb-6 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg flex items-center justify-between">
                            <div className="flex items-center gap-2">
                                <AlertCircle className="w-4 h-4 text-amber-400" />
                                <span className="text-sm text-amber-300">
                                    You're viewing <strong>{selectedTab === 'docker' ? 'Docker' : 'Custom'}</strong> settings, but <strong>{activeNeo4jMode === 'docker' ? 'Docker' : 'Custom'}</strong> is currently active.
                                </span>
                            </div>
                            <button
                                onClick={() => activateMode(selectedTab)}
                                className="px-3 py-1.5 bg-amber-500 hover:bg-amber-400 text-black text-sm font-medium rounded-lg transition-colors"
                            >
                                Switch to {selectedTab === 'docker' ? 'Docker' : 'Custom'}
                            </button>
                        </div>
                    )}

                    {/* Docker Mode */}
                    {selectedTab === 'docker' && (
                        <div className="space-y-4">
                            {/* Docker Status - Terminal Style */}
                            <div className="flex flex-col bg-black/90 overflow-hidden rounded-lg border border-white/10">
                                {/* Terminal Header */}
                                <div className="flex items-center justify-between px-4 py-2 bg-gray-900 border-b border-white/10">
                                    <div className="flex items-center gap-2">
                                        <div className="flex gap-1.5">
                                            <div className="w-3 h-3 rounded-full bg-red-500"></div>
                                            <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                                            <div className="w-3 h-3 rounded-full bg-green-500"></div>
                                        </div>
                                        <span className="text-xs text-white/60 ml-2 font-mono">bloodhound-ce.status</span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <button
                                            onClick={checkDockerStatus}
                                            className="text-white/60 hover:text-white transition-colors p-1"
                                            title="Refresh status"
                                            disabled={refreshingDocker}
                                        >
                                            <RefreshCw className={`w-3 h-3 ${refreshingDocker ? 'animate-spin' : ''}`} />
                                        </button>
                                        <div className={`w-2 h-2 rounded-full ${dockerStatus?.neo4jReady ? 'bg-green-500' :
                                            dockerStatus?.containerRunning ? 'bg-yellow-500' : 'bg-red-500'
                                            } animate-pulse`}></div>
                                        <span className="text-xs text-white/60 font-mono">
                                            {dockerStatus?.neo4jReady ? 'Ready' :
                                                dockerStatus?.containerRunning ? 'Starting...' :
                                                    dockerStatus?.containerExists ? 'Stopped' :
                                                        dockerStatus?.dockerRunning ? 'Not Installed' :
                                                            'Checking...'}
                                        </span>
                                    </div>
                                </div>

                                {/* Terminal Content */}
                                <div className="p-4 font-mono text-sm">
                                    {dockerStatus ? (
                                        <div className="space-y-2">
                                            <StatusRow label="Docker Installed" status={dockerStatus.dockerInstalled} />
                                            <StatusRow label="Docker Running" status={dockerStatus.dockerRunning} />
                                            <StatusRow
                                                label="BloodHound CE"
                                                status={dockerStatus.containerExists}
                                                subtext={dockerStatus.containerRunning ? 'Running' : 'Stopped'}
                                            />
                                            <StatusRow label="Neo4j Ready" status={dockerStatus.neo4jReady} />
                                        </div>
                                    ) : (
                                        <div className="flex items-center gap-2 text-gray-500">
                                            <span className="animate-pulse">▋</span>
                                            <span>Checking status...</span>
                                        </div>
                                    )}

                                    {dockerStatus?.error && (
                                        <div className="mt-3 p-2 bg-red-500/10 border border-red-500/30 rounded text-red-400 text-xs">
                                            <span>ERROR:</span> {dockerStatus.error}
                                        </div>
                                    )}
                                </div>
                            </div>

                            {/* Show initializing message when container is running but Neo4j not ready */}
                            {dockerStatus?.containerRunning && !dockerStatus?.neo4jReady && !dockerStatus?.error && (
                                <div className="mt-3 p-2 bg-yellow-500/10 border border-yellow-500/30 rounded text-yellow-400 text-xs flex items-center gap-2">
                                    <Loader2 className="w-3 h-3 animate-spin" />
                                    <span>Neo4j is initializing... (this takes 20-60 seconds)</span>
                                </div>
                            )}

                            {/* Connection Info */}
                            {dockerStatus?.neo4jReady && (
                                <div className="bg-aegis-success/10 rounded-lg p-3 border border-aegis-success/20">
                                    <div className="flex flex-col gap-1 text-aegis-success-light text-sm">
                                        <div className="flex items-center gap-2">
                                            <CheckCircle className="w-4 h-4" />
                                            <span>BloodHound CE is ready!</span>
                                        </div>
                                        <div className="text-xs text-aegis-text-muted ml-6">
                                            Neo4j: <code className="aegis-code">bolt://localhost:7687</code> |
                                            BloodHound UI: <code className="aegis-code">http://localhost:8080</code>
                                        </div>
                                    </div>
                                </div>
                            )}


                            {/* Progress Panel - Inline Collapsible */}
                            <DockerProgressPanel
                                isVisible={showProgress}
                                onDismiss={dismissProgress}
                                title={progressTitle}
                                steps={progressSteps}
                                logs={progressLogs}
                                progress={progressPercent}
                                status={progressStatus}
                                errorMessage={progressError}
                            />

                            {/* Docker Actions */}
                            <div className="flex flex-wrap gap-2">
                                {/* Show loading button while status is being checked */}
                                {dockerStatus === null ? (
                                    <button
                                        disabled
                                        className="aegis-button flex items-center gap-2 opacity-50 cursor-not-allowed"
                                    >
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        Checking status...
                                    </button>
                                ) : !dockerStatus.containerExists ? (
                                    <button
                                        onClick={setupDocker}
                                        disabled={isOperationRunning || !dockerStatus.dockerRunning}
                                        className="aegis-button flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                                    >
                                        <Download className="w-4 h-4" />
                                        Setup BloodHound CE
                                    </button>
                                ) : dockerStatus.containerRunning ? (
                                    <button
                                        onClick={stopDocker}
                                        disabled={isOperationRunning}
                                        className="aegis-button-secondary flex items-center gap-2 disabled:opacity-50"
                                    >
                                        <Square className="w-4 h-4" />
                                        Stop
                                    </button>
                                ) : (
                                    <button
                                        onClick={startDocker}
                                        disabled={isOperationRunning}
                                        className="aegis-button-success flex items-center gap-2 disabled:opacity-50"
                                    >
                                        <Play className="w-4 h-4" />
                                        Start
                                    </button>
                                )}

                                {dockerStatus !== null && dockerStatus.containerExists && (
                                    <button
                                        onClick={resetDocker}
                                        disabled={isOperationRunning}
                                        className="aegis-button-danger flex items-center gap-2 disabled:opacity-50"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                        Reset
                                    </button>
                                )}
                            </div>




                            {/* Docker Not Installed Warning */}
                            {dockerStatus && !dockerStatus.dockerInstalled && (
                                <div className="aegis-alert-warning">
                                    <div className="flex items-start gap-2">
                                        <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
                                        <div>
                                            <p className="font-medium">Docker not installed</p>
                                            <p className="text-sm mt-1 opacity-80">
                                                Please install Docker Desktop to use managed Neo4j.
                                                <a
                                                    href="https://www.docker.com/products/docker-desktop/"
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="ml-1 underline hover:no-underline"
                                                >
                                                    Download Docker
                                                </a>
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Custom Mode */}
                    {selectedTab === 'custom' && (
                        <div className="space-y-4">
                            <div className="grid gap-4">
                                <div>
                                    <label className="block text-aegis-text-muted text-sm mb-1.5">
                                        Connection URI
                                    </label>
                                    <input
                                        type="text"
                                        value={customConfig.uri}
                                        onChange={(e) => setCustomConfig({ ...customConfig, uri: e.target.value })}
                                        placeholder="bolt://localhost:7687"
                                        className="aegis-input w-full"
                                    />
                                </div>

                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="block text-aegis-text-muted text-sm mb-1.5">
                                            Username
                                        </label>
                                        <input
                                            type="text"
                                            value={customConfig.username}
                                            onChange={(e) => setCustomConfig({ ...customConfig, username: e.target.value })}
                                            placeholder="neo4j"
                                            className="aegis-input w-full"
                                        />
                                    </div>

                                    <div>
                                        <label className="block text-aegis-text-muted text-sm mb-1.5">
                                            Password
                                        </label>
                                        <input
                                            type="password"
                                            value={customConfig.password}
                                            onChange={(e) => setCustomConfig({ ...customConfig, password: e.target.value })}
                                            placeholder="••••••••"
                                            className="aegis-input w-full"
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <button
                                    onClick={testConnection}
                                    disabled={testingConnection}
                                    className="aegis-button flex items-center gap-2 disabled:opacity-50"
                                >
                                    {testingConnection ? (
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                    ) : (
                                        <Database className="w-4 h-4" />
                                    )}
                                    Test Connection
                                </button>

                                {connectionStatus && (
                                    connectionStatus.connected ? (
                                        <div className="px-4 py-3 bg-green-500/10 border border-green-500/30 rounded-xl flex items-center gap-3">
                                            <CheckCircle className="w-5 h-5 text-green-300 shrink-0" />
                                            <span className="text-green-300 text-sm">
                                                Connected ({connectionStatus.nodeCount} nodes, {connectionStatus.relationshipCount} relationships)
                                            </span>
                                        </div>
                                    ) : (
                                        <div className="px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center gap-3">
                                            <XCircle className="w-5 h-5 text-red-300 shrink-0" />
                                            <span className="text-red-300 text-sm">{connectionStatus.error || 'Connection failed'}</span>
                                        </div>
                                    )
                                )}
                            </div>

                            {/* Help text for custom connection */}
                            <div className="p-3 bg-aegis-info-dark/10 border border-aegis-info/20 rounded-lg">
                                <p className="text-aegis-info text-xs">
                                    <strong>Custom Connection:</strong> Connect to your own Neo4j instance or remote BloodHound CE server.
                                    Make sure your Neo4j database is running and accessible.
                                </p>
                            </div>
                        </div>
                    )}
                </div>

                {/* BloodHound CE API Token */}
                <div className="aegis-card bg-aegis-dark">
                    <div className="flex items-center gap-2 mb-4">
                        <BloodHoundIcon size={28} className="text-red-500" />
                        <h2 className="text-lg font-semibold text-aegis-text">BloodHound CE API</h2>
                        <span className={`px-2 py-0.5 text-xs font-medium rounded ${
                            activeNeo4jMode === 'docker'
                                ? 'bg-blue-500/20 text-blue-400'
                                : 'bg-purple-500/20 text-purple-400'
                        }`}>
                            {activeNeo4jMode === 'docker' ? 'Docker' : 'Custom'}
                        </span>
                    </div>

                    <div className="space-y-4">
                        <p className="text-aegis-text-muted text-sm">
                            Configure API credentials to enable automatic data import to BloodHound CE.
                            You can generate API tokens from the BloodHound CE UI at{' '}
                            <a
                                href="http://localhost:8080"
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-aegis-accent hover:underline"
                            >
                                http://localhost:8080
                            </a>
                        </p>

                        <div className="grid gap-4">
                            <div>
                                <label className="block text-aegis-text-muted text-sm mb-1.5">
                                    BloodHound CE URL
                                </label>
                                <input
                                    type="text"
                                    value={bhceCredentials.url}
                                    onChange={(e) => setBhceCredentials({ ...bhceCredentials, url: e.target.value })}
                                    placeholder="http://localhost:8080"
                                    className="aegis-input w-full"
                                />
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="block text-aegis-text-muted text-sm mb-1.5">
                                        Token ID
                                    </label>
                                    <input
                                        type="text"
                                        value={bhceCredentials.tokenId}
                                        onChange={(e) => setBhceCredentials({ ...bhceCredentials, tokenId: e.target.value })}
                                        placeholder="Enter Token ID"
                                        className="aegis-input w-full font-mono text-sm"
                                    />
                                </div>

                                <div>
                                    <label className="block text-aegis-text-muted text-sm mb-1.5">
                                        Token Key
                                    </label>
                                    <input
                                        type="password"
                                        value={bhceCredentials.tokenKey}
                                        onChange={(e) => setBhceCredentials({ ...bhceCredentials, tokenKey: e.target.value })}
                                        placeholder="Enter Token Key"
                                        className="aegis-input w-full"
                                    />
                                </div>
                            </div>
                        </div>

                        <div className="flex items-center gap-4">
                            <button
                                onClick={testBhceConnection}
                                disabled={testingBhce || savingBhce || !bhceCredentials.tokenId || !bhceCredentials.tokenKey}
                                className="aegis-button flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {testingBhce ? (
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                ) : (
                                    <CheckCircle className="w-4 h-4" />
                                )}
                                {testingBhce ? 'Testing...' : 'Save & Test Connection'}
                            </button>

                            <div className="flex items-center gap-2">
                                <span className="text-aegis-text-muted text-sm">Status:</span>
                                {bhceStatus === 'checking' ? (
                                    <span className="flex items-center gap-1.5 text-aegis-text-muted text-sm">
                                        <Loader2 className="w-3 h-3 animate-spin" />
                                        Checking...
                                    </span>
                                ) : bhceStatus === 'connected' ? (
                                    <span className="aegis-badge-success">
                                        <CheckCircle className="w-3 h-3 mr-1" />
                                        Connected ({activeNeo4jMode === 'docker' ? 'Docker' : 'Custom'})
                                    </span>
                                ) : bhceStatus === 'not_configured' ? (
                                    <span className="flex items-center gap-1.5 text-aegis-text-muted text-sm">
                                        <AlertCircle className="w-3 h-3" />
                                        Not Configured ({activeNeo4jMode === 'docker' ? 'Docker' : 'Custom'})
                                    </span>
                                ) : (
                                    <span className="aegis-badge-error">
                                        <XCircle className="w-3 h-3 mr-1" />
                                        Disconnected ({activeNeo4jMode === 'docker' ? 'Docker' : 'Custom'})
                                    </span>
                                )}
                            </div>
                        </div>

                        <div className="p-3 bg-aegis-info-dark/10 border border-aegis-info/20 rounded-lg space-y-2">
                            <p className="text-aegis-info text-xs">
                                <strong>How to get API tokens:</strong> Open BloodHound CE → Click your profile →
                                API Tokens → Create Token. Copy both the Token ID and Token Key.
                            </p>
                            {activeNeo4jMode === 'docker' ? (
                                <p className="text-aegis-text-muted text-xs">
                                    <strong className="text-aegis-info">AEGIS Docker Login:</strong>{' '}
                                    <code className="bg-aegis-gray px-1.5 py-0.5 rounded text-aegis-text">admin</code>{' / '}
                                    <code className="bg-aegis-gray px-1.5 py-0.5 rounded text-aegis-text">aegisadmin123</code>
                                </p>
                            ) : (
                                <p className="text-aegis-text-muted text-xs">
                                    <strong className="text-aegis-info">Custom Setup:</strong>{' '}
                                    Use the credentials from your own BloodHound CE installation.
                                </p>
                            )}
                            <p className="text-aegis-text-subtle text-xs border-t border-aegis-info/10 pt-2 mt-2">
                                <strong>Note:</strong> Credentials are stored separately for Docker and Custom modes.
                                Switching modes will load the saved credentials for that mode.
                            </p>
                        </div>
                    </div>
                </div>

                {/* API Backend */}
                <div className="aegis-card bg-aegis-dark">
                    <div className="flex items-center gap-2 mb-4">
                        <Server className="w-5 h-5 text-aegis-info" />
                        <h2 className="text-lg font-semibold text-aegis-text">API Backend</h2>
                    </div>

                    <div className="space-y-4">
                        <div>
                            <label className="block text-aegis-text-muted text-sm mb-1.5">
                                Backend URL
                            </label>
                            <input
                                type="text"
                                value={apiUrl}
                                readOnly
                                disabled
                                className="aegis-input w-full opacity-60 cursor-not-allowed"
                            />
                        </div>

                        <div className="flex items-center gap-2">
                            <span className="text-aegis-text-muted text-sm">Status:</span>
                            {apiStatus === 'checking' ? (
                                <span className="flex items-center gap-1.5 text-aegis-text-muted text-sm">
                                    <Loader2 className="w-3 h-3 animate-spin" />
                                    Checking...
                                </span>
                            ) : apiStatus === 'connected' ? (
                                <span className="aegis-badge-success">
                                    <CheckCircle className="w-3 h-3 mr-1" />
                                    Connected
                                </span>
                            ) : (
                                <span className="aegis-badge-error">
                                    <XCircle className="w-3 h-3 mr-1" />
                                    Disconnected
                                </span>
                            )}

                            <button
                                onClick={checkApiStatus}
                                className={`text-aegis-text-subtle hover:text-aegis-text transition-colors ml-2 ${refreshingApi ? 'cursor-wait' : ''}`}
                                title="Refresh"
                                disabled={refreshingApi}
                            >
                                <RefreshCw className={`w-4 h-4 ${refreshingApi ? 'animate-spin' : ''}`} />
                            </button>
                        </div>

                        <p className="text-aegis-text-subtle text-xs">
                            The AEGIS backend handles RAG analysis and report generation. Your BloodHound data stays local.
                        </p>
                    </div>
                </div>

                {/* Updates Section */}
                <div className="aegis-card bg-aegis-dark">
                    <div className="flex items-center gap-3 mb-6">
                        <div className="p-2 bg-purple-500/10 rounded-lg">
                            <Download className="w-5 h-5 text-purple-400" />
                        </div>
                        <div>
                            <h2 className="text-lg font-semibold text-aegis-text">Updates</h2>
                            <p className="text-sm text-aegis-text-muted">Current version: {currentVersion || 'Loading...'}</p>
                        </div>
                    </div>

                    <div className="space-y-4">
                        {/* Status Display */}
                        <div className="flex items-center justify-between p-4 bg-aegis-darker rounded-lg border border-aegis-border">
                            <div className="flex items-center gap-3">
                                {updateState === 'checking' && (
                                    <>
                                        <Loader2 className="w-5 h-5 text-aegis-info animate-spin" />
                                        <span className="text-aegis-text-muted">Checking for updates...</span>
                                    </>
                                )}
                                {updateState === 'up-to-date' && (
                                    <>
                                        <CheckCircle className="w-5 h-5 text-aegis-success" />
                                        <span className="text-aegis-text-muted">You're up to date!</span>
                                    </>
                                )}
                                {updateState === 'downloading' && (
                                    <>
                                        <Download className="w-5 h-5 text-aegis-info" />
                                        <div className="flex-1">
                                            <span className="text-aegis-text-muted">Downloading {updateInfo?.version}...</span>
                                            <div className="w-48 bg-aegis-gray rounded-full h-1.5 mt-1">
                                                <div
                                                    className="bg-aegis-info h-1.5 rounded-full transition-all"
                                                    style={{ width: `${updateProgress}%` }}
                                                />
                                            </div>
                                        </div>
                                    </>
                                )}
                                {updateState === 'ready' && (
                                    <>
                                        <CheckCircle className="w-5 h-5 text-aegis-success" />
                                        <span className="text-aegis-text-muted">Version {updateInfo?.version} ready to install</span>
                                    </>
                                )}
                                {updateState === 'error' && (
                                    <>
                                        <XCircle className="w-5 h-5 text-aegis-error" />
                                        <span className="text-aegis-error">{updateError}</span>
                                    </>
                                )}
                                {updateState === 'idle' && (
                                    <>
                                        <Info className="w-5 h-5 text-aegis-text-subtle" />
                                        <span className="text-aegis-text-subtle">Click to check for updates</span>
                                    </>
                                )}
                            </div>

                            {/* Action Buttons */}
                            {updateState === 'ready' ? (
                                <button
                                    onClick={handleInstallUpdate}
                                    className="aegis-button-success flex items-center gap-2 text-sm"
                                >
                                    <RefreshCw className="w-4 h-4" />
                                    Restart & Update
                                </button>
                            ) : (
                                <button
                                    onClick={handleCheckForUpdates}
                                    disabled={updateState === 'checking' || updateState === 'downloading'}
                                    className="aegis-button-secondary flex items-center gap-2 text-sm disabled:opacity-50"
                                >
                                    <RefreshCw className={`w-4 h-4 ${updateState === 'checking' ? 'animate-spin' : ''}`} />
                                    Check for Updates
                                </button>
                            )}
                        </div>
                    </div>
                </div>

                {/* About */}
                <div className="aegis-card bg-aegis-dark">
                    <div className="flex items-center gap-2 mb-4">
                        <Info className="w-5 h-5 text-aegis-info" />
                        <h2 className="text-lg font-semibold text-aegis-text">About AEGIS</h2>
                    </div>

                    <div className="flex items-start gap-4">
                        <div className="p-3 bg-aegis-info-dark/20 rounded-lg">
                            <Shield className="w-8 h-8 text-aegis-info" />
                        </div>
                        <div className="space-y-2">
                            <p className="text-aegis-text font-medium">
                                AI-Enhanced Guardian for Enterprise Infrastructure Security
                            </p>
                            <p className="text-aegis-text-muted text-sm">
                                AEGIS helps security analysts understand Active Directory attack paths
                                and generate remediation scripts using AI-powered analysis.
                            </p>
                            <div className="flex items-center gap-4 text-aegis-text-subtle text-xs mt-3">
                                <span>Version 1.0.0</span>
                                <span>•</span>
                                <span>Ashesi University Capstone Project</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Existing BloodHound Conflict Modal */}
            {showBloodHoundConflictModal && existingBloodHoundInfo && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
                    <div className="bg-aegis-dark border border-aegis-border rounded-xl shadow-2xl max-w-lg w-full mx-4 overflow-hidden relative">
                        {/* Modal Header */}
                        <div className="p-4 bg-amber-500/10 border-b border-amber-500/30">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-amber-500/20 rounded-lg">
                                    <AlertCircle className="w-6 h-6 text-amber-400" />
                                </div>
                                <div>
                                    <h3 className="text-lg font-semibold text-amber-300">Existing BloodHound CE Detected</h3>
                                    <p className="text-sm text-amber-200/80">Port conflict with your BloodHound installation</p>
                                </div>
                            </div>
                        </div>

                        {/* Modal Content */}
                        <div className="p-5 space-y-4">
                            <p className="text-aegis-text text-sm">
                                We detected that you already have BloodHound CE running with Docker. Starting AEGIS's Docker stack would conflict with your existing installation.
                            </p>

                            {/* Detected Containers */}
                            <div className="bg-black/30 rounded-lg p-3 border border-aegis-border">
                                <p className="text-xs text-aegis-text-muted mb-2 font-medium">Running BloodHound Containers:</p>
                                <div className="space-y-1 font-mono text-xs">
                                    {existingBloodHoundInfo.containers.map((container, i) => (
                                        <div key={i} className="flex items-center gap-2 text-aegis-text-muted">
                                            <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                                            <span className="text-green-400">{container.name}</span>
                                            <span className="text-aegis-text-subtle">- {container.ports || 'no exposed ports'}</span>
                                        </div>
                                    ))}
                                </div>
                                {existingBloodHoundInfo.conflictingPorts.length > 0 && (
                                    <p className="text-xs text-red-400 mt-2">
                                        Conflicting ports: {existingBloodHoundInfo.conflictingPorts.join(', ')}
                                    </p>
                                )}
                            </div>

                            {/* Recommendation */}
                            <div className="border border-aegis-info rounded-lg p-3">
                                <p className="text-aegis-info text-sm">
                                    <strong>Recommended:</strong> Use <strong>Custom Mode</strong> to connect AEGIS to your existing BloodHound CE's Neo4j database. This way you can use AEGIS alongside your BloodHound installation.
                                </p>
                            </div>

                            {/* Switch Back Instructions */}
                            <div className="bg-aegis-gray/50 rounded-lg p-3 border border-aegis-border">
                                <p className="text-xs text-aegis-text-muted">
                                    <strong className="text-aegis-text">To switch back to your BloodHound:</strong><br/>
                                    If you proceed with AEGIS Docker, your containers will be stopped. To restart them later:
                                </p>
                                <code className="block mt-2 text-xs bg-black/50 p-2 rounded text-aegis-accent">
                                    cd ~/your-bloodhound-folder && docker compose up -d
                                </code>
                            </div>
                        </div>

                        {/* Modal Actions */}
                        <div className="p-4 bg-aegis-darker border-t border-aegis-border flex flex-col gap-3">
                            <button
                                onClick={handleUseCustomMode}
                                className="w-full aegis-button flex items-center justify-center gap-2"
                            >
                                <Server className="w-4 h-4" />
                                Use Custom Mode (Recommended)
                            </button>
                            <button
                                onClick={handleProceedWithAegisDocker}
                                disabled={stoppingExistingBH}
                                className="w-full aegis-button-secondary flex items-center justify-center gap-2 disabled:opacity-50"
                            >
                                {stoppingExistingBH ? (
                                    <>
                                        <Loader2 className="w-4 h-4 animate-spin" />
                                        Stopping...
                                    </>
                                ) : (
                                    <>
                                        <Play className="w-4 h-4" />
                                        Stop & Use AEGIS Docker
                                    </>
                                )}
                            </button>
                        </div>

                        {/* Close Button */}
                        <button
                            onClick={() => {
                                setShowBloodHoundConflictModal(false);
                                setPendingDockerAction(null);
                            }}
                            className="absolute top-4 right-4 text-aegis-text-muted hover:text-aegis-text transition-colors"
                        >
                            <XCircle className="w-5 h-5" />
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

// ==================== HELPER COMPONENTS ====================

interface StatusRowProps {
    label: string;
    status: boolean;
    subtext?: string;
}

const StatusRow: React.FC<StatusRowProps> = ({ label, status, subtext }) => (
    <div className="flex items-center gap-2 text-xs">
        <span className="text-gray-500 font-mono shrink-0 w-32">{label}:</span>
        {subtext && <span className="text-gray-400 text-xs font-mono">{subtext}</span>}
        <span className={`text-xs font-mono ${status ? 'text-green-400' : 'text-red-400'}`}>
            {status ? '[OK]' : '[FAIL]'}
        </span>
    </div>
);

export default SettingsPage;
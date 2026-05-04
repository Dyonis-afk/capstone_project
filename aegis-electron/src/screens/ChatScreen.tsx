/**
 * ChatScreen - Claude-Style UI
 * Location: src/screens/chat/ChatScreen.tsx
 * 
 * Features:
 * - Centered content column (like Claude.ai)
 * - No speech bubbles for assistant messages
 * - Clean, minimal typography-focused design
 * - Centered input area with max-width
 * - User messages shown with subtle styling
 */

import React, { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import toast from 'react-hot-toast';
import { apiService } from '../services/api';
import { chatService } from '../services/chat_service';
import UnifiedAttackPathReport from '../components/UnifiedAttackPathReport';
import { Tier0Config } from '../components/Tier0ConfigModal';
import ReactMarkdown from 'react-markdown';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import ShieldIcon from '../components/ShieldIcon';
import { useProjectStore } from '../stores/projectStore';
import { useConnectionStore } from '../stores/connectionStore';
import { useIsReportJobRunning, useReportJobProgress } from '../stores/reportJobStore';
import { useChatRequestStore } from '../stores/chatRequestStore';
import { QueryResponse, ViewMode, SuggestedQuery, ChatGraphData } from '../types/chat';
import { ReportSummaryData } from '../components/chat/SecurityReportSummary';
import { Finding } from '../components/attack-components/types';
import { ChatResponseRenderer, AddToReportModal, SecurityReportSummary, ChatTerminalLogViewer } from '../components/chat';
import CypherQueryDisplay from '../components/attack-components/CypherQueryDisplay';

// Types
interface Message {
    id: string;
    chat_id: string;
    role: 'user' | 'assistant';
    content: string;
    artifact_type?: string;
    artifact_id?: string;
    response_data?: string;  // JSON string from database (parsed into responseMetadata Map)
    created_at: string;
    // Extended fields for local state
    view_mode?: ViewMode;  // The format selected when message was sent
}

interface Chat {
    id: string;
    project_id: string;
    title: string;
    report_id?: string;
    created_at: string;
    updated_at: string;
}

const ChatScreen: React.FC = () => {
    const { projectId } = useParams<{ projectId: string }>();
    const navigate = useNavigate();
    const location = useLocation();

    // Zustand store
    const {
        setCurrentProject,
        isUploading: globalIsUploading,
        setUploading: setGlobalUploading,
        setActiveProjectId,
        activeProjectId
    } = useProjectStore();

    // Check if we should auto-open report from navigation state
    const initialReportData = location.state?.reportData;
    const initialAnalysisId = location.state?.analysisId;
    const shouldOpenReport = location.state?.openReport;
    const initialNeo4jProjectId = location.state?.neo4jProjectId;
    const initialChatId = location.state?.chatId;

    // State
    const [chat, setChat] = useState<Chat | null>(null);
    const [messages, setMessages] = useState<Message[]>([]);
    const [inputValue, setInputValue] = useState('');
    const [isLoading, setIsLoading] = useState(true);
    const [isSending, setIsSending] = useState(false);
    const abortControllerRef = useRef<AbortController | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [projectName, setProjectName] = useState<string>('');
    const [tier0Config, setTier0Config] = useState<Tier0Config | null>(null);

    // Neo4j project ID for query filtering
    const [neo4jProjectId, setNeo4jProjectId] = useState<string>(initialNeo4jProjectId || '');
    const [_neo4jAvailable, setNeo4jAvailable] = useState<boolean>(false);

    // Connection status from central store (polling handled in App.tsx)
    const {
        neo4jMode,
        dockerRunning,
        bloodhoundRunning,
        neo4jReady,
        customNeo4jConnected,
        isChecking: isCheckingConnections,
        checkAll: refreshConnections
    } = useConnectionStore();

    // Report generation status (disable chat while generating)
    const isReportGenerating = useIsReportJobRunning();
    const reportProgress = useReportJobProgress();

    // Determine if this project has data CURRENTLY loaded in BloodHound CE
    // Only true if this is THE active project (data is loaded right now)
    // Having neo4jProjectId just means it was used before, not that data is loaded
    const hasBloodHoundData = activeProjectId === projectId;

    // Report panel state
    const [reportPanelOpen, setReportPanelOpen] = useState(shouldOpenReport || false);
    const [currentReport, setCurrentReport] = useState<any>(initialReportData || null);
    const [currentAnalysisId, setCurrentAnalysisId] = useState<string>(initialAnalysisId || '');
    const [isReportFullScreen, setIsReportFullScreen] = useState(false);

    // Intelligent chat state - Add to Report modal
    const [showAddToReportModal, setShowAddToReportModal] = useState(false);
    const [pendingFinding, setPendingFinding] = useState<Finding | null>(null);
    const [pendingSourceQuery, setPendingSourceQuery] = useState('');
    const [pendingResultCount, setPendingResultCount] = useState(0);
    const [pendingGraphData, setPendingGraphData] = useState<ChatGraphData | undefined>(undefined);

    // Response metadata storage (for messages with intelligent chat data)
    const [responseMetadata, setResponseMetadata] = useState<Map<string, QueryResponse>>(new Map());

    // Response format toggle - user selects before sending
    const [responseFormat, setResponseFormat] = useState<ViewMode>('normal');
    // Track which format was used for each message (messageId -> ViewMode)
    const [messageViewModes, setMessageViewModes] = useState<Map<string, ViewMode>>(new Map());

    // Suggestions state (for structured query system)
    const [suggestions, setSuggestions] = useState<SuggestedQuery[]>([]);
    const [aiSuggestions, setAiSuggestions] = useState<SuggestedQuery[]>([]);
    const [showSuggestions, setShowSuggestions] = useState(false);
    const [loadingSuggestions, setLoadingSuggestions] = useState(false);

    // Upload warning modal state
    const [showUploadWarningModal, setShowUploadWarningModal] = useState(false);
    const [selectedFileName, setSelectedFileName] = useState<string>('');
    const [uploadError, setUploadError] = useState<string | null>(null);
    // Note: isUploading comes from global store (globalIsUploading)

    // Project domain name for re-upload validation
    const [projectDomainName, setProjectDomainName] = useState<string>('');
    const [uploadedFileDomains, setUploadedFileDomains] = useState<string[]>([]);

    const messagesEndRef = useRef<HTMLDivElement>(null);
    const messagesContainerRef = useRef<HTMLDivElement>(null);  // Scroll container for infinite scroll
    const inputRef = useRef<HTMLTextAreaElement>(null);
    const loadingStartedRef = useRef<string | null>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);
    const isInitialLoadRef = useRef<boolean>(true);  // Track if this is the first message load

    // Infinite scroll state
    const MESSAGES_PER_PAGE = 50;
    const [hasMoreMessages, setHasMoreMessages] = useState(false);
    const [loadingOlderMessages, setLoadingOlderMessages] = useState(false);
    const [messageOffset, setMessageOffset] = useState(0);  // Track how many messages we've loaded

    // Load project and its chat on mount
    useEffect(() => {
        if (projectId && loadingStartedRef.current !== projectId) {
            loadingStartedRef.current = projectId;
            isInitialLoadRef.current = true;  // Reset for new project
            // Reset pagination state for new project
            setMessageOffset(0);
            setHasMoreMessages(false);
            loadProjectAndChat(projectId);
        }
    }, [projectId]);

    // Check Neo4j availability on mount (connection status handled by connectionStore)
    useEffect(() => {
        checkNeo4jAvailability();
    }, []);

    // Auto-scroll to bottom when messages change
    useEffect(() => {
        if (messages.length > 0) {
            // Use instant scroll for initial load, smooth for new messages
            if (isInitialLoadRef.current) {
                // Small delay to ensure DOM is rendered before scrolling
                setTimeout(() => {
                    scrollToBottom(true);  // instant scroll
                    isInitialLoadRef.current = false;
                }, 50);
            } else {
                scrollToBottom(false);  // smooth scroll for new messages
            }
        }
    }, [messages]);

    // Auto-resize textarea
    useEffect(() => {
        if (inputRef.current) {
            inputRef.current.style.height = 'auto';
            inputRef.current.style.height = Math.min(inputRef.current.scrollHeight, 200) + 'px';
        }
    }, [inputValue]);

    const checkNeo4jAvailability = async () => {
        if (!window.neo4j) {
            setNeo4jAvailable(false);
            return;
        }
        try {
            const result = await window.neo4j.testConnection();
            setNeo4jAvailable(result.connected);
        } catch (err) {
            setNeo4jAvailable(false);
        }
    };

    const loadProjectAndChat = async (projId: string) => {
        try {
            setIsLoading(true);
            setError(null);

            const projectResult = await window.database.getProject(projId);
            if (!projectResult.success || !projectResult.data) {
                throw new Error('Project not found');
            }

            const project = projectResult.data;
            setProjectName(project.name);
            setCurrentProject(project);

            // Store domain name for re-upload validation
            if (project.domain_name) {
                setProjectDomainName(project.domain_name);
            }

            // Parse and store Tier 0 configuration for report filtering
            if (project.tier0_config) {
                try {
                    const parsedT0Config = JSON.parse(project.tier0_config) as Tier0Config;
                    setTier0Config(parsedT0Config);
                } catch (err) {
                    console.warn('[ChatScreen] Failed to parse tier0_config:', err);
                }
            }

            if (project.neo4j_database) {
                setNeo4jProjectId(project.neo4j_database);
            } else if (initialNeo4jProjectId) {
                setNeo4jProjectId(initialNeo4jProjectId);
            }

            let projectChat: Chat | null = null;

            // If a chat ID was passed from navigation (e.g., from ReportScreen),
            // prioritize finding that specific chat to avoid creating duplicates
            if (initialChatId) {
                console.log(`[ChatScreen] Looking for chat with ID: ${initialChatId}`);
                const chatResult = await window.database.getChat(initialChatId);
                if (chatResult.success && chatResult.data) {
                    projectChat = chatResult.data;
                    console.log(`[ChatScreen] Found chat from navigation: ${projectChat.id}`);
                } else {
                    // If the specific chat wasn't found, try to find any existing chat for this project
                    // This handles edge cases where the chat might not be immediately available
                    console.log(`[ChatScreen] Chat ${initialChatId} not found, checking for existing chats...`);
                }
            }

            // Only look for other chats if we didn't find the specific one
            if (!projectChat) {
                const chatsResult = await window.database.getChatsForProject(projId);
                if (chatsResult.success && chatsResult.data && chatsResult.data.length > 0) {
                    // If we had an initialChatId, try to find it in the list
                    if (initialChatId) {
                        const matchingChat = chatsResult.data.find((c: Chat) => c.id === initialChatId);
                        if (matchingChat) {
                            projectChat = matchingChat;
                            console.log(`[ChatScreen] Found matching chat in list: ${projectChat.id}`);
                        }
                    }
                    // If still not found, use the first chat (most recent)
                    if (!projectChat) {
                        projectChat = chatsResult.data[0];
                        console.log(`[ChatScreen] Using existing chat: ${projectChat.id}`);
                    }
                }
            }

            // Only create a new chat if:
            // 1. No initialChatId was provided (not coming from ReportScreen), AND
            // 2. No existing chats were found for this project
            if (!projectChat && !initialChatId) {
                console.log(`[ChatScreen] No existing chats found, creating new chat`);
                const newChatResult = await window.database.createChat(projId, project.name);
                if (!newChatResult.success || !newChatResult.data) {
                    throw new Error('Failed to create chat');
                }
                projectChat = newChatResult.data;
            }

            // If we still don't have a chat (shouldn't happen, but safety check)
            if (!projectChat) {
                throw new Error('Could not find or create chat');
            }

            setChat(projectChat);

            // Load messages with pagination - load most recent messages first
            const messagesResult = await window.database.getMessagesForChatPaginated(projectChat.id, MESSAGES_PER_PAGE, 0);
            if (messagesResult.success && messagesResult.data) {
                const { messages: loadedMessages, hasMore, totalCount } = messagesResult.data;
                setMessages(loadedMessages);
                setHasMoreMessages(hasMore);
                setMessageOffset(loadedMessages.length);
                console.log(`[ChatScreen] Loaded ${loadedMessages.length} of ${totalCount} messages, hasMore: ${hasMore}`);

                // Restore response metadata and view modes from persisted response_data
                const metadataMap = new Map<string, QueryResponse>();
                const viewModesMap = new Map<string, ViewMode>();
                loadedMessages.forEach((msg: Message) => {
                    if (msg.response_data) {
                        try {
                            const parsed = JSON.parse(msg.response_data) as QueryResponse;
                            metadataMap.set(msg.id, parsed);
                            // Restore view mode if it was persisted
                            if (parsed.view_mode) {
                                viewModesMap.set(msg.id, parsed.view_mode);
                            }
                        } catch (e) {
                            console.warn(`[ChatScreen] Failed to parse response_data for message ${msg.id}:`, e);
                        }
                    }
                });
                if (metadataMap.size > 0) {
                    setResponseMetadata(metadataMap);
                }
                if (viewModesMap.size > 0) {
                    setMessageViewModes(viewModesMap);
                }
            }

            // Always load report from database to ensure we have the latest data (including additional findings)
            if (projectChat.report_id) {
                try {
                    const reportResult = await window.database.getReport(projectChat.report_id);
                    if (reportResult.success && reportResult.data) {
                        const reportData = JSON.parse(reportResult.data.report_data);
                        setCurrentReport(reportData);
                        setCurrentAnalysisId(reportResult.data.id);
                        console.log('[ChatScreen] Report loaded from database:', {
                            reportId: reportResult.data.id,
                            additionalFindingsCount: reportData.additional_findings?.length || 0
                        });
                    }
                } catch (err) {
                    console.error('Failed to load report:', err);
                    // Fallback to initialReportData if database load fails
                    if (initialReportData) {
                        setCurrentReport(initialReportData);
                    }
                }
            } else if (initialReportData) {
                // No report_id yet but we have initial data (fresh report generation)
                setCurrentReport(initialReportData);
            }

        } catch (err: any) {
            console.error('Failed to load project:', err);
            setError(err.message || 'Failed to load project');
        } finally {
            setIsLoading(false);
        }
    };

    const scrollToBottom = (instant: boolean = false) => {
        messagesEndRef.current?.scrollIntoView({
            behavior: instant ? 'instant' : 'smooth'
        });
    };

    // Load older messages when user scrolls to the top
    const loadOlderMessages = async () => {
        if (!chat || loadingOlderMessages || !hasMoreMessages) return;

        setLoadingOlderMessages(true);

        try {
            // Save scroll position before loading
            const container = messagesContainerRef.current;
            const previousScrollHeight = container?.scrollHeight || 0;

            const result = await window.database.getMessagesForChatPaginated(chat.id, MESSAGES_PER_PAGE, messageOffset);
            if (result.success && result.data) {
                const { messages: olderMessages, hasMore } = result.data;

                if (olderMessages.length > 0) {
                    // Prepend older messages to existing messages
                    setMessages(prev => [...olderMessages, ...prev]);
                    setHasMoreMessages(hasMore);
                    setMessageOffset(prev => prev + olderMessages.length);

                    // Restore response metadata for older messages
                    const metadataMap = new Map<string, QueryResponse>(responseMetadata);
                    const viewModesMap = new Map<string, ViewMode>(messageViewModes);
                    olderMessages.forEach((msg: Message) => {
                        if (msg.response_data) {
                            try {
                                const parsed = JSON.parse(msg.response_data) as QueryResponse;
                                metadataMap.set(msg.id, parsed);
                                if (parsed.view_mode) {
                                    viewModesMap.set(msg.id, parsed.view_mode);
                                }
                            } catch (e) {
                                console.warn(`[ChatScreen] Failed to parse response_data for message ${msg.id}:`, e);
                            }
                        }
                    });
                    setResponseMetadata(metadataMap);
                    setMessageViewModes(viewModesMap);

                    // Maintain scroll position after prepending
                    // Use requestAnimationFrame to wait for DOM update
                    requestAnimationFrame(() => {
                        if (container) {
                            const newScrollHeight = container.scrollHeight;
                            const scrollDiff = newScrollHeight - previousScrollHeight;
                            container.scrollTop = scrollDiff;
                        }
                    });

                    console.log(`[ChatScreen] Loaded ${olderMessages.length} older messages, hasMore: ${hasMore}`);
                }
            }
        } catch (error) {
            console.error('[ChatScreen] Error loading older messages:', error);
        } finally {
            setLoadingOlderMessages(false);
        }
    };

    // Scroll event handler for infinite scroll
    const handleScroll = (event: React.UIEvent<HTMLDivElement>) => {
        const container = event.currentTarget;
        // Load more when user scrolls within 100px of the top
        if (container.scrollTop < 100 && hasMoreMessages && !loadingOlderMessages) {
            loadOlderMessages();
        }
    };

    // State for tracking AI suggestions loading separately
    const [loadingAiSuggestions, setLoadingAiSuggestions] = useState(false);
    // Track if suggestions have been loaded for this session (cache flag)
    const [suggestionsLoaded, setSuggestionsLoaded] = useState(false);

    // Validate a suggestion by running a COUNT query to check if it returns results
    const validateSuggestion = async (suggestion: SuggestedQuery): Promise<SuggestedQuery | null> => {
        if (!window.neo4j) return suggestion; // Can't validate without Neo4j

        try {
            // Convert the query to a COUNT query for fast validation
            let countQuery = suggestion.cypher;

            // Handle different query patterns to create COUNT versions
            if (countQuery.includes('RETURN p')) {
                // Path queries: count paths
                countQuery = countQuery.replace(/RETURN p.*$/i, 'RETURN count(p) AS count');
            } else if (countQuery.includes('RETURN DISTINCT')) {
                // Distinct queries: wrap in count
                countQuery = countQuery.replace(/RETURN DISTINCT (.+?) (AS \w+)?.*$/i, 'RETURN count(DISTINCT $1) AS count');
            } else if (countQuery.match(/RETURN .+ AS \w+,/)) {
                // Multi-column returns: just count the first match
                countQuery = countQuery.replace(/RETURN .+$/i, 'RETURN count(*) AS count');
            } else if (countQuery.includes('RETURN')) {
                // Simple returns: wrap in count
                countQuery = countQuery.replace(/RETURN .+$/i, 'RETURN count(*) AS count');
            }

            // Remove LIMIT for accurate count
            countQuery = countQuery.replace(/LIMIT \d+/gi, '');

            const result = await window.neo4j.runQuery(countQuery);
            const records = result?.records || (Array.isArray(result) ? result : []);
            const count = records[0]?.count || 0;

            // Convert Neo4j Integer if needed
            const numericCount = typeof count === 'object' && count.low !== undefined
                ? count.low
                : Number(count);

            if (numericCount === 0) {
                console.log(`[Suggest] Filtered out "${suggestion.name}" - no results`);
                return null; // Filter out suggestions with no results
            }

            // Update description with actual count
            return {
                ...suggestion,
                description: `${numericCount} result${numericCount !== 1 ? 's' : ''} found`
            };
        } catch (err) {
            console.warn(`[Suggest] Validation failed for "${suggestion.name}":`, err);
            return suggestion; // Keep suggestion if validation fails
        }
    };

    // Validate multiple suggestions in parallel
    const validateSuggestions = async (suggestions: SuggestedQuery[]): Promise<SuggestedQuery[]> => {
        const validationPromises = suggestions.map(s => validateSuggestion(s));
        const results = await Promise.all(validationPromises);
        return results.filter((s): s is SuggestedQuery => s !== null);
    };

    // Handle Suggest button click - use cached suggestions if available
    const handleSuggestClick = async (forceRefresh: boolean = false) => {
        console.log('[Suggest] Button clicked, loadingSuggestions:', loadingSuggestions, 'cached:', suggestionsLoaded);
        if (loadingSuggestions) return;

        // If suggestions are already cached and not forcing refresh, just show the panel
        if (suggestionsLoaded && !forceRefresh) {
            console.log('[Suggest] Using cached suggestions');
            setShowSuggestions(true);
            return;
        }

        setLoadingSuggestions(true);
        setShowSuggestions(true);
        setSuggestions([]);
        setAiSuggestions([]);

        try {
            // Step 1: Get quick suggestions (fast, predefined)
            console.log('[Suggest] Fetching quick suggestions...');
            const quickSuggestions = await chatService.getQuickSuggestions(projectId);
            console.log('[Suggest] Quick response:', quickSuggestions);

            // Step 2: Validate quick suggestions in parallel (filter out empty ones)
            console.log('[Suggest] Validating quick suggestions...');
            const validatedQuickSuggestions = await validateSuggestions(quickSuggestions);
            console.log('[Suggest] Validated:', validatedQuickSuggestions.length, '/', quickSuggestions.length);
            setSuggestions(validatedQuickSuggestions);
            setLoadingSuggestions(false);

            // Step 3: Get AI suggestions in background (slower)
            setLoadingAiSuggestions(true);
            console.log('[Suggest] Fetching AI suggestions...');
            const suggestionsResponse = await chatService.getSuggestions(projectId, true);
            console.log('[Suggest] AI response:', suggestionsResponse);

            if (suggestionsResponse.ai_suggestions) {
                // Validate AI suggestions too
                const validatedAiSuggestions = await validateSuggestions(suggestionsResponse.ai_suggestions);
                console.log('[Suggest] Validated AI:', validatedAiSuggestions.length, '/', suggestionsResponse.ai_suggestions.length);
                setAiSuggestions(validatedAiSuggestions);
            }

            // Mark suggestions as loaded (cached for this session)
            setSuggestionsLoaded(true);
        } catch (err) {
            console.error('[Suggest] Error fetching suggestions:', err);
        } finally {
            setLoadingSuggestions(false);
            setLoadingAiSuggestions(false);
        }
    };

    // Refresh suggestions (force re-fetch)
    const handleRefreshSuggestions = () => {
        handleSuggestClick(true);
    };

    // Execute a suggestion directly (auto-execute) - primary click action
    const handleSuggestionExecute = async (suggestion: SuggestedQuery) => {
        if (!chat || isSending) return;

        setIsSending(true);
        setShowSuggestions(false);

        try {
            // Add suggestion name as user message for context
            const savedUserResult = await window.database.addMessage(chat.id, 'user', suggestion.name);
            if (savedUserResult.success && savedUserResult.data) {
                setMessages(prev => [...prev, savedUserResult.data!]);
            }

            // Execute the query directly using the pre-defined Cypher
            const response = await getAIResponse(suggestion.cypher);

            // Save assistant response
            const savedAssistantResult = await window.database.addMessage(
                chat.id,
                'assistant',
                response.content,
                response.artifactType,
                response.artifactId,
                response.responseData
            );

            if (savedAssistantResult.success && savedAssistantResult.data) {
                if (response.responseData) {
                    setResponseMetadata(prev => {
                        const next = new Map(prev);
                        next.set(savedAssistantResult.data!.id, response.responseData!);
                        return next;
                    });
                }
                setMessageViewModes(prev => {
                    const next = new Map(prev);
                    next.set(savedAssistantResult.data!.id, response.viewMode || 'normal');
                    return next;
                });
                setMessages(prev => [...prev, savedAssistantResult.data!]);
            }
        } catch (err: any) {
            console.error('Failed to execute suggestion:', err);
            const errorResult = await window.database.addMessage(
                chat.id,
                'assistant',
                `Failed to execute query: ${err.message}`
            );
            if (errorResult.success && errorResult.data) {
                setMessages(prev => [...prev, errorResult.data!]);
            }
        } finally {
            setIsSending(false);
        }
    };

    // Copy suggestion to input (right-click behavior) - for power users
    const handleSuggestionCopy = (suggestion: SuggestedQuery) => {
        setInputValue(suggestion.cypher);
        setShowSuggestions(false);
        inputRef.current?.focus();
    };

    // Chat request persistence store
    const { pendingRequest, startRequest, completeRequest, failRequest, cancelRequest: storeCancelRequest, clearRequest } = useChatRequestStore();

    // On mount / chat switch: check if there's a pending request for THIS chat
    useEffect(() => {
        if (!chat?.id) return;

        if (pendingRequest?.chatId === chat.id) {
            if (pendingRequest.status === 'pending') {
                setIsSending(true);
            } else if (pendingRequest.status === 'completed') {
                setIsSending(false);
                clearRequest();
            } else if (pendingRequest.status === 'failed' || pendingRequest.status === 'cancelled') {
                setIsSending(false);
                clearRequest();
            }
        } else {
            // Different chat or no pending request — ensure loading is off
            setIsSending(false);
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [chat?.id]);

    // Watch for background request completion while on this screen
    useEffect(() => {
        if (!chat?.id || pendingRequest?.chatId !== chat.id) return;

        if (pendingRequest?.status === 'completed' || pendingRequest?.status === 'failed') {
            setIsSending(false);
            clearRequest();
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [pendingRequest?.status]);

    const handleCancelRequest = () => {
        // Cancel on frontend
        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
            abortControllerRef.current = null;
        }
        // Cancel on backend (prevents remaining LLM generators from starting)
        chatService.cancelCurrentRequest();
        storeCancelRequest();
        setIsSending(false);
    };

    const handleSendMessage = async () => {
        if (!inputValue.trim() || !chat || isSending) return;

        const userMessage = inputValue.trim();
        setInputValue('');
        setIsSending(true);

        // Generate a temporary message ID for the store
        const tempMessageId = `pending-${Date.now()}`;
        startRequest(chat.id, tempMessageId, userMessage, responseFormat);

        try {
            const savedUserResult = await window.database.addMessage(chat.id, 'user', userMessage);
            if (savedUserResult.success && savedUserResult.data) {
                setMessages(prev => [...prev, savedUserResult.data!]);
            }

            const response = await getAIResponse(userMessage);

            const savedAssistantResult = await window.database.addMessage(
                chat.id,
                'assistant',
                response.content,
                response.artifactType,
                response.artifactId,
                response.responseData
            );
            if (savedAssistantResult.success && savedAssistantResult.data) {
                if (response.responseData) {
                    setResponseMetadata(prev => {
                        const next = new Map(prev);
                        next.set(savedAssistantResult.data!.id, response.responseData!);
                        return next;
                    });
                }
                setMessageViewModes(prev => {
                    const next = new Map(prev);
                    next.set(savedAssistantResult.data!.id, response.viewMode || 'normal');
                    return next;
                });
                setMessages(prev => [...prev, savedAssistantResult.data!]);
            }

            // Mark request as completed in store
            if (response.responseData) {
                completeRequest(response.responseData);
            } else {
                clearRequest();
            }

        } catch (err: any) {
            console.error('Failed to send message:', err);
            failRequest(err.message || 'Unknown error');

            const errorResult = await window.database.addMessage(
                chat.id,
                'assistant',
                `Sorry, I encountered an error: ${err.message}. Please try again.`
            );
            if (errorResult.success && errorResult.data) {
                setMessages(prev => [...prev, errorResult.data!]);
            }
        } finally {
            setIsSending(false);
            inputRef.current?.focus();
        }
    };

    // Safety gate patterns for dangerous Cypher operations
    const DANGEROUS_CYPHER_PATTERNS = [
        /\bDELETE\b/i,
        /\bDETACH\s+DELETE\b/i,
        /\bCREATE\b/i,
        /\bMERGE\b/i,
        /\bSET\s+\w+\./i,      // SET n.property = value
        /\bSET\s+\w+\s*=/i,    // SET n = value
        /\bREMOVE\b/i,
        /\bDROP\b/i,
        /\bCALL\s+\{/i,        // CALL {} subqueries that might modify
        /\bFOREACH\b/i,        // FOREACH can be used for writes
    ];

    const isSafeCypherQuery = (query: string): boolean => {
        return !DANGEROUS_CYPHER_PATTERNS.some(pattern => pattern.test(query));
    };

    // Extract Cypher query from natural language wrapper (e.g., "execute this: MATCH...")
    const extractCypherQuery = (message: string): string | null => {
        // Pattern to detect if message contains a Cypher query
        const cypherIndicators = [
            /^MATCH\s/i,
            /^OPTIONAL\s+MATCH\s/i,
            /:\s*MATCH\s/i,           // "execute this: MATCH..."
            /query[:\s]+MATCH\s/i,    // "run this query: MATCH..."
            /```(?:cypher)?\s*(MATCH[\s\S]*?)```/i,  // Code block with MATCH
        ];

        for (const pattern of cypherIndicators) {
            const match = message.match(pattern);
            if (match) {
                // If it starts with MATCH, the whole message might be the query
                if (/^(MATCH|OPTIONAL\s+MATCH)\s/i.test(message.trim())) {
                    return message.trim();
                }
                // Extract query after colon or from code block
                const colonMatch = message.match(/[:]\s*(MATCH[\s\S]*)/i);
                if (colonMatch) return colonMatch[1].trim();

                const codeBlockMatch = message.match(/```(?:cypher)?\s*(MATCH[\s\S]*?)```/i);
                if (codeBlockMatch) return codeBlockMatch[1].trim();
            }
        }
        return null;
    };

    const getAIResponse = async (userMessage: string): Promise<{ content: string; artifactType?: string; artifactId?: string; responseData?: QueryResponse; viewMode?: ViewMode }> => {
        // Check if message contains a Cypher query for safety check
        const extractedQuery = extractCypherQuery(userMessage);

        // Safety gate: Block dangerous queries before sending anywhere
        if (extractedQuery && !isSafeCypherQuery(extractedQuery)) {
            return {
                content: `**Query Blocked for Safety**\n\nThis query contains write operations that could modify or delete data. For security reasons, only read-only queries (MATCH...RETURN) are allowed.\n\n**Blocked patterns detected:** DELETE, DETACH DELETE, CREATE, MERGE, SET, REMOVE, DROP\n\nIf you need to modify data, please use the Neo4j Browser directly with appropriate permissions.`,
                viewMode: 'normal'
            };
        }

        // Use chat service for ALL queries (Cypher and natural language)
        // The chat service will:
        // - Detect query type (raw Cypher vs natural language)
        // - Execute the query
        // - Generate RAG explanation for results
        try {
            const queryResponse = await chatService.executeQuery(userMessage, responseFormat, projectId);

            // Build content from response fields
            let content = '';
            if (queryResponse.explanation) {
                content = queryResponse.explanation;
            }
            if (queryResponse.error) {
                content = queryResponse.error;
            }

            // Return response with metadata for ChatResponseRenderer
            // Include view_mode in responseData so it persists to database
            return {
                content,
                responseData: { ...queryResponse, view_mode: responseFormat },
                viewMode: responseFormat  // Use the format selected in input area
            };
        } catch (err: any) {
            console.error('Chat service error, falling back to RAG:', err);
            // Fallback to direct RAG query if chat service fails
            try {
                const ragResponse = await apiService.queryRAG(userMessage);
                return {
                    content: ragResponse.answer || 'I could not find relevant information for your query.',
                    viewMode: 'normal'
                };
            } catch (ragErr: any) {
                return {
                    content: `I'm having trouble connecting to the analysis backend. Error: ${ragErr.message}`,
                    viewMode: 'normal'
                };
            }
        }
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSendMessage();
        }
    };

    const copyToClipboard = async (text: string) => {
        try {
            await navigator.clipboard.writeText(text);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    // Handler for "Add to Report" button click in ChatResponseRenderer
    const handleAddToReport = (finding: Finding, sourceQuery: string, resultCount: number, graphData?: ChatGraphData) => {
        if (!currentAnalysisId) {
            console.warn('No report available to add finding to');
            toast.error('No report available. Generate a report first.');
            return;
        }
        setPendingFinding(finding);
        setPendingSourceQuery(sourceQuery);
        setPendingResultCount(resultCount);
        setPendingGraphData(graphData);
        setShowAddToReportModal(true);
    };

    // Handler for confirming add to report in modal
    const handleConfirmAddToReport = async (notes?: string) => {
        if (!pendingFinding || !currentAnalysisId) {
            console.warn('[ChatScreen] Cannot add finding: missing pendingFinding or currentAnalysisId');
            return;
        }

        console.log('[ChatScreen] Adding finding to report:', {
            reportId: currentAnalysisId,
            findingTitle: pendingFinding.title,
            hasGraphData: !!pendingGraphData
        });

        try {
            await chatService.addFindingToReport(
                currentAnalysisId,
                pendingFinding,
                pendingSourceQuery,
                undefined,  // cypherQuery (not available in this context)
                pendingResultCount,
                notes,
                pendingGraphData  // Pass graph data for visualization in report
            );

            // Refresh report data to show the new finding
            if (currentAnalysisId && window.database) {
                const reportResult = await window.database.getReport(currentAnalysisId);
                if (reportResult.success && reportResult.data) {
                    try {
                        const parsedReport = JSON.parse(reportResult.data.report_data);
                        setCurrentReport(parsedReport);
                        console.log('[ChatScreen] Report refreshed after adding finding:', {
                            additionalFindingsCount: parsedReport.additional_findings?.length || 0
                        });
                    } catch (e) {
                        console.error('Failed to parse updated report:', e);
                    }
                }
            }

            setShowAddToReportModal(false);
            setPendingFinding(null);
            setPendingSourceQuery('');
            setPendingResultCount(0);
            setPendingGraphData(undefined);

            // Show success toast
            toast.success('Finding added to report');
        } catch (err) {
            console.error('Failed to add finding to report:', err);
            toast.error('Failed to add finding to report');
        }
    };

    // Handler for removing a finding from the report
    const handleRemoveFinding = async (findingId: string) => {
        if (!currentAnalysisId) return;

        try {
            await chatService.removeFindingFromReport(currentAnalysisId, findingId);

            // Refresh report data to remove the finding from UI
            if (currentAnalysisId && window.database) {
                const reportResult = await window.database.getReport(currentAnalysisId);
                if (reportResult.success && reportResult.data) {
                    try {
                        const parsedReport = JSON.parse(reportResult.data.report_data);
                        setCurrentReport(parsedReport);
                    } catch (e) {
                        console.error('Failed to parse updated report:', e);
                    }
                }
            }

            toast.success('Finding removed from report');
        } catch (err) {
            console.error('Failed to remove finding from report:', err);
            toast.error('Failed to remove finding');
        }
    };

    const toggleReportPanel = () => {
        setReportPanelOpen((prev: boolean) => !prev);
    };

    const toggleReportFullScreen = () => {
        setIsReportFullScreen((prev: boolean) => !prev);
    };

    const closeReportFullScreen = () => {
        setIsReportFullScreen(false);
    };

    // Two-state model:
    // Active: This project's data is currently loaded in BloodHound CE
    // Inactive: Data is not loaded (need to upload to use)
    const isActiveProject = activeProjectId === projectId && !globalIsUploading;

    // Determine if services are available for input (using connectionStore, mode-aware)
    // Docker mode: Need Docker + BloodHound container + Neo4j
    // Custom mode: Need custom Neo4j connected
    const isServicesReady = neo4jMode === 'custom'
        ? customNeo4jConnected && neo4jReady
        : dockerRunning && bloodhoundRunning && neo4jReady;
    const canUseChat = isServicesReady && hasBloodHoundData && !globalIsUploading && !isReportGenerating;

    // Get the reason why chat is disabled (mode-aware)
    const getDisabledReason = (): { title: string; subtitle: string; action?: 'settings' | 'upload' | 'refresh' } | null => {
        if (isCheckingConnections) return null; // Still loading

        // Report is being generated - highest priority block
        if (isReportGenerating) {
            return {
                title: 'Report generating...',
                subtitle: reportProgress?.message || 'Please wait while the report is being created'
            };
        }

        if (neo4jMode === 'custom') {
            // Custom mode: Check custom Neo4j connection
            if (!customNeo4jConnected) {
                return { title: 'Neo4j not connected', subtitle: 'Check your custom Neo4j connection in Settings', action: 'settings' };
            }
            if (!neo4jReady) {
                return { title: 'Neo4j is starting...', subtitle: 'Please wait while the database initializes', action: 'refresh' };
            }
        } else {
            // Docker mode: Check Docker and BloodHound container
            if (!dockerRunning) {
                return { title: 'Docker not running', subtitle: 'Start Docker Desktop to use AEGIS', action: 'settings' };
            }
            if (!bloodhoundRunning) {
                return { title: 'BloodHound CE not running', subtitle: 'Go to Settings to start BloodHound CE', action: 'settings' };
            }
            if (!neo4jReady) {
                return { title: 'Neo4j is starting...', subtitle: 'Please wait while the database initializes', action: 'refresh' };
            }
        }

        if (!hasBloodHoundData && !globalIsUploading) {
            // Check if project was used before but is now inactive
            if (neo4jProjectId) {
                return {
                    title: 'Project inactive',
                    subtitle: 'Re-upload BloodHound data to activate this project',
                    action: 'upload'
                };
            }
            return { title: 'No BloodHound data', subtitle: 'Upload data to enable AI queries', action: 'upload' };
        }
        return null;
    };

    const disabledReason = getDisabledReason();

    // Infrastructure is down (mode-aware)
    // Docker mode: Docker or Neo4j is not running
    // Custom mode: Custom Neo4j is not connected
    const isInfrastructureDown = neo4jMode === 'custom'
        ? !customNeo4jConnected || !neo4jReady
        : !dockerRunning || !neo4jReady;

    // Get project status text based on current state (Stopped/Active/Inactive + uploading)
    const getProjectStatusText = (): string => {
        // Show stopped if Docker or Neo4j is down
        if (isInfrastructureDown) {
            return 'Stopped';
        }
        if (globalIsUploading) {
            return 'Processing data...';
        }
        if (isActiveProject) {
            return 'Active';
        }
        return 'Inactive';
    };

    // Get project status color class based on current state
    const getProjectStatusColor = (): string => {
        // Show red if Docker or Neo4j is down
        if (isInfrastructureDown) {
            return 'text-red-500'; // Red for stopped
        }
        if (globalIsUploading) {
            return 'text-aegis-accent'; // Blue for processing
        }
        if (isActiveProject) {
            return 'text-emerald-400'; // Green for active
        }
        return 'text-amber-500'; // Amber for inactive
    };

    // Handle upload button click - opens file picker
    const handleUploadClick = () => {
        fileInputRef.current?.click();
    };

    // Check if uploaded file's domains match the project's stored domain
    const doDomainsMatch = (uploadedDomains: string[], storedDomain: string): boolean => {
        if (!storedDomain || uploadedDomains.length === 0) {
            // If we don't have domain info, we can't validate - allow upload
            console.log('[ChatScreen] No domain info available for comparison, allowing upload');
            return true;
        }

        // Stored domain might be comma-separated if multiple domains
        const storedDomains = storedDomain.split(',').map(d => d.trim().toUpperCase());

        // Check if any uploaded domain matches any stored domain
        return uploadedDomains.some(uploaded =>
            storedDomains.some(stored =>
                stored === uploaded.toUpperCase() ||
                stored.includes(uploaded.toUpperCase()) ||
                uploaded.toUpperCase().includes(stored)
            )
        );
    };

    // Extract domains from uploaded file
    const extractDomainsFromFile = async (file: File): Promise<string[]> => {
        try {
            if (!window.bloodhound?.extractDomainsFromBuffer) {
                console.warn('[ChatScreen] Domain extraction not available');
                return [];
            }

            const buffer = await file.arrayBuffer();
            const result = await window.bloodhound.extractDomainsFromBuffer(buffer, file.name);

            if (result.success && result.domains) {
                console.log(`[ChatScreen] Extracted domains from ${file.name}:`, result.domains);
                return result.domains;
            }

            console.warn('[ChatScreen] Failed to extract domains:', result.error);
            return [];
        } catch (error) {
            console.error('[ChatScreen] Error extracting domains:', error);
            return [];
        }
    };

    // Handle file selection - check if matching domain, then upload or warn
    const handleFileSelect = async (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file) return;

        const isZip = file.name.toLowerCase().endsWith('.zip');
        const isJson = file.name.toLowerCase().endsWith('.json');

        if (!isZip && !isJson) {
            setUploadError('Only ZIP and JSON files are allowed.');
            return;
        }

        setSelectedFileName(file.name);

        // Reset file input so the same file can be selected again
        event.target.value = '';

        // Extract domains from the uploaded file to verify it matches the project
        const uploadedDomains = await extractDomainsFromFile(file);
        setUploadedFileDomains(uploadedDomains);

        // Check if domains match the project's stored domain
        if (doDomainsMatch(uploadedDomains, projectDomainName)) {
            // Same domain - proceed with upload
            console.log(`[ChatScreen] Domain match confirmed, proceeding with upload`);
            await processFileUpload(file);
        } else {
            // Different domain - show warning modal
            console.log(`[ChatScreen] Domain mismatch! File domains: ${uploadedDomains.join(', ')}, Project domain: ${projectDomainName}`);
            setShowUploadWarningModal(true);
        }
    };

    // Process file upload to BloodHound CE (same domain data)
    const processFileUpload = async (file: File) => {
        if (!projectId) return;

        // Use global upload state to disable uploads in all screens
        setGlobalUploading(true, projectId);
        setUploadError(null);

        try {
            // Check if BloodHound CE API is available
            if (!window.bloodhoundCE) {
                throw new Error('BloodHound CE API not available. Please check Settings.');
            }

            const hasCredentials = await window.bloodhoundCE.hasCredentials(neo4jMode);
            if (!hasCredentials) {
                throw new Error(`BloodHound CE API not configured for ${neo4jMode === 'custom' ? 'Custom' : 'Docker'} mode. Please configure API token in Settings.`);
            }

            // Read file as buffer
            const buffer = await file.arrayBuffer();

            // Use the existing project ID for BloodHound CE
            const bhceProjectId = projectId;

            // Upload to BloodHound CE
            const uploadResult = await window.bloodhoundCE.uploadBuffer(
                buffer,
                file.name,
                bhceProjectId
            );

            if (!uploadResult.success) {
                throw new Error(uploadResult.error || 'Upload failed');
            }

            console.log('[ChatScreen] BloodHound CE upload success:', uploadResult);

            // Wait for BloodHound CE to process
            await new Promise(resolve => setTimeout(resolve, 2000));

            // Update project with neo4j_database reference
            // Use the project ID we created for this upload (BloodHound CE doesn't return a projectId)
            const newNeo4jId = bhceProjectId;

            // If we don't have a domain stored yet, try to extract and store it
            const updateData: { neo4j_database: string; domain_name?: string } = {
                neo4j_database: newNeo4jId
            };

            // Store domain if we extracted it and project doesn't have one
            if (!projectDomainName && uploadedFileDomains.length > 0) {
                updateData.domain_name = uploadedFileDomains.join(',');
                setProjectDomainName(uploadedFileDomains.join(','));
                console.log(`[ChatScreen] Storing domain name: ${updateData.domain_name}`);
            }

            await window.database.updateProject(projectId, updateData);
            setNeo4jProjectId(newNeo4jId);

            // Set this project as the active one (data loaded in BloodHound CE)
            setActiveProjectId(projectId);

            // Check Neo4j availability
            await checkNeo4jAvailability();

            // Reload project data
            await loadProjectAndChat(projectId);

            setSelectedFileName('');

        } catch (err: any) {
            console.error('Upload failed:', err);
            setUploadError(err.message || 'Failed to upload file');
        } finally {
            // Clear global upload state
            setGlobalUploading(false);
        }
    };

    // Loading state
    if (isLoading) {
        return (
            <div className="h-full flex items-center justify-center bg-aegis-dark">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-8 w-8 border-2 border-aegis-border border-t-aegis-accent mx-auto mb-4"></div>
                    <p className="text-aegis-text-muted text-sm">Loading...</p>
                </div>
            </div>
        );
    }

    // Error state
    if (error) {
        return (
            <div className="h-full flex items-center justify-center bg-aegis-dark">
                <div className="text-center">
                    <p className="text-aegis-error mb-4">{error}</p>
                    <button
                        onClick={() => navigate('/')}
                        className="px-4 py-2 bg-aegis-gray hover:bg-aegis-gray-hover rounded-lg transition-colors text-sm text-aegis-text"
                    >
                        Go Back
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="h-full flex overflow-hidden bg-aegis-dark">
            {/* Main Chat Area */}
            <div className={`flex flex-col ${reportPanelOpen ? 'w-1/2' : 'w-full'} transition-all duration-300`}>

                {/* Minimal Header */}
                <header className="bg-aegis-dark">
                    {/* Main Header */}
                    <div className="h-[60px] flex items-center justify-between px-5">
                        <div className="flex items-center gap-3">
                            <svg className="w-5 h-5 text-aegis-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={1.5}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                            </svg>

                            <div>
                                <h1 className="text-[15px] font-semibold text-aegis-text m-0">
                                    {projectName || 'Untitled Project'}
                                </h1>
                                <p className={`text-xs m-0 ${getProjectStatusColor()}`}>
                                    {getProjectStatusText()}
                                </p>
                            </div>
                        </div>
                        {currentReport && (
                            <button
                                onClick={toggleReportPanel}
                                className="text-xs text-aegis-text-muted hover:text-aegis-text transition-colors flex items-center gap-1"
                            >
                                {reportPanelOpen ? <div></div> : <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                </svg>}
                                {reportPanelOpen ? '' : 'View Report'}
                            </button>
                        )}
                    </div>
                </header>

                {/* Messages Area - Centered Column */}
                <div
                    ref={messagesContainerRef}
                    className="flex-1 overflow-y-auto"
                    onScroll={handleScroll}
                >
                    <div className="max-w-3xl mx-auto px-4 py-8">
                        {/* Loading indicator for older messages */}
                        {loadingOlderMessages && (
                            <div className="flex justify-center py-4 mb-4">
                                <div className="flex items-center gap-2 text-aegis-text-muted text-sm">
                                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                    </svg>
                                    Loading older messages...
                                </div>
                            </div>
                        )}
                        {/* "Load more" indicator when there are more messages */}
                        {hasMoreMessages && !loadingOlderMessages && messages.length > 0 && (
                            <div className="flex justify-center py-2 mb-4">
                                <button
                                    onClick={loadOlderMessages}
                                    className="text-xs text-aegis-text-muted hover:text-aegis-text transition-colors"
                                >
                                    ↑ Scroll up or click to load older messages
                                </button>
                            </div>
                        )}
                        {messages.length === 0 ? (
                            <EmptyState
                                projectName={projectName}
                                currentReport={currentReport}
                                onViewReport={toggleReportPanel}
                                onSuggestionClick={(text) => {
                                    setInputValue(text);
                                    inputRef.current?.focus();
                                }}
                            />
                        ) : (
                            <div className="space-y-6">
                                {messages.map((message, index) => {
                                    const isFirstAssistantMessage = message.role === 'assistant' &&
                                        messages.slice(0, index).every(m => m.role !== 'assistant');

                                    return (
                                        <React.Fragment key={message.id}>
                                            <MessageBlock
                                                message={message}
                                                onCopy={copyToClipboard}
                                                responseData={responseMetadata.get(message.id)}
                                                onAddToReport={(finding) => {
                                                    const respData = responseMetadata.get(message.id);
                                                    handleAddToReport(
                                                        finding,
                                                        respData?.cypher_query || message.content,
                                                        respData?.result_count || 0,
                                                        respData?.graph_data  // Pass graph data for visualization in report
                                                    );
                                                }}
                                                onViewReport={toggleReportPanel}
                                                hasReport={!!currentAnalysisId}
                                                preSelectedViewMode={messageViewModes.get(message.id)}
                                            />
                                            {/* Report Card - Shows after first assistant message */}
                                            {isFirstAssistantMessage && currentReport && (
                                                <ReportCard
                                                    report={currentReport}
                                                    projectName={projectName}
                                                    onClick={toggleReportPanel}
                                                    isOpen={reportPanelOpen}
                                                />
                                            )}
                                        </React.Fragment>
                                    );
                                })}
                                {isSending && (
                                    <ChatTerminalLogViewer
                                        isActive={isSending}
                                        viewMode={responseFormat}
                                        onCancel={handleCancelRequest}
                                    />
                                )}
                            </div>
                        )}
                        <div ref={messagesEndRef} />
                    </div>

                    {/* Input Area - Sticky at bottom inside scroll container */}
                    <div className="sticky bottom-0 bg-aegis-dark pt-2">
                        <div className="max-w-3xl mx-auto px-4 py-4">
                            {/* Main Input Container */}
                            <div className={`
                            relative bg-aegis-gray rounded-2xl border transition-all duration-200 overflow-hidden
                            ${!canUseChat
                                    ? 'border-aegis-border-light'
                                    : 'border-aegis-border hover:border-aegis-border-muted focus-within:border-aegis-accent focus-within:ring-1 focus-within:ring-aegis-accent/50'
                                }
                        `}>
                                {/* Disabled Reason Banner - Shows when chat is disabled */}
                                {disabledReason && !globalIsUploading && (
                                    <div
                                        onClick={disabledReason.action === 'settings' ? () => navigate('/settings') : undefined}
                                        className={`flex items-center justify-between px-4 py-3 border-b transition-colors ${disabledReason.action === 'settings'
                                            ? 'border-red-500/30 bg-red-500/5 cursor-pointer hover:bg-red-500/10'
                                            : disabledReason.title.includes('starting')
                                                ? 'border-yellow-500/30 bg-yellow-500/5'
                                                : 'border-amber-500/30 bg-amber-500/5'
                                            }`}
                                    >
                                        <div className="flex items-center gap-3">
                                            <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${disabledReason.action === 'settings'
                                                ? 'bg-red-500/15'
                                                : disabledReason.title.includes('starting')
                                                    ? 'bg-yellow-500/15'
                                                    : 'bg-amber-500/15'
                                                }`}>
                                                {disabledReason.title.includes('starting') ? (
                                                    <svg className="w-[18px] h-[18px] text-yellow-500 animate-spin" fill="none" viewBox="0 0 24 24">
                                                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                                    </svg>
                                                ) : (
                                                    <svg className={`w-[18px] h-[18px] ${disabledReason.action === 'settings' ? 'text-red-500' : 'text-amber-500'
                                                        }`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                                                    </svg>
                                                )}
                                            </div>
                                            <div>
                                                <p className={`text-sm font-medium ${disabledReason.action === 'settings'
                                                    ? 'text-red-400'
                                                    : disabledReason.title.includes('starting')
                                                        ? 'text-yellow-400'
                                                        : 'text-aegis-text'
                                                    }`}>{disabledReason.title}</p>
                                                <p className={`text-xs ${disabledReason.action === 'settings'
                                                    ? 'text-red-400/70'
                                                    : disabledReason.title.includes('starting')
                                                        ? 'text-yellow-400/70'
                                                        : 'text-aegis-text-subtle'
                                                    }`}>{disabledReason.subtitle}</p>
                                            </div>
                                        </div>
                                        {disabledReason.action === 'settings' && (
                                            <div className="flex items-center gap-2 text-red-400 text-xs font-medium">
                                                <span>Go to Settings</span>
                                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                                </svg>
                                            </div>
                                        )}
                                        {disabledReason.action === 'upload' && (
                                            <button
                                                onClick={(e) => { e.stopPropagation(); handleUploadClick(); }}
                                                className="flex items-center gap-2 px-4 py-2.5 bg-amber-500/15 hover:bg-amber-500/25 text-amber-500 text-sm font-medium rounded-lg transition-colors"
                                            >
                                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
                                                </svg>
                                                Upload
                                            </button>
                                        )}
                                        {disabledReason.action === 'refresh' && (
                                            <button
                                                onClick={refreshConnections}
                                                className="flex items-center gap-2 text-yellow-400 text-xs font-medium hover:text-yellow-300 transition-colors"
                                            >
                                                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                                </svg>
                                                Refresh
                                            </button>
                                        )}
                                    </div>
                                )}

                                {/* Uploading State */}
                                {globalIsUploading && (
                                    <div className="flex items-center justify-between px-4 py-3 border-b border-aegis-border-light bg-aegis-accent/5">
                                        <div className="flex items-center gap-3">
                                            <div className="w-9 h-9 rounded-lg bg-aegis-accent/15 flex items-center justify-center">
                                                <svg className="w-[18px] h-[18px] text-aegis-accent animate-spin" fill="none" viewBox="0 0 24 24">
                                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                                </svg>
                                            </div>
                                            <div>
                                                <p className="text-sm font-medium text-aegis-text">Uploading to BloodHound CE...</p>
                                                <p className="text-xs text-aegis-text-subtle truncate max-w-[200px]">{selectedFileName}</p>
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-2">
                                            <div className="w-32 h-1.5 bg-aegis-dark rounded-full overflow-hidden">
                                                <div className="h-full bg-aegis-accent rounded-full animate-pulse" style={{ width: '60%' }}></div>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Upload Error */}
                                {uploadError && !globalIsUploading && (
                                    <div className="flex items-center justify-between px-4 py-3 border-b border-red-500/30 bg-red-500/5">
                                        <div className="flex items-center gap-3">
                                            <div className="w-9 h-9 rounded-lg bg-red-500/15 flex items-center justify-center">
                                                <svg className="w-[18px] h-[18px] text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                                </svg>
                                            </div>
                                            <div>
                                                <p className="text-sm font-medium text-red-400">Upload failed</p>
                                                <p className="text-xs text-red-400/70 truncate max-w-[250px]">{uploadError}</p>
                                            </div>
                                        </div>
                                        <button
                                            onClick={() => setUploadError(null)}
                                            className="p-2 text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                                        >
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                            </svg>
                                        </button>
                                    </div>
                                )}

                                {/* Hidden file input */}
                                <input
                                    ref={fileInputRef}
                                    type="file"
                                    accept=".zip,.json"
                                    onChange={handleFileSelect}
                                    className="hidden"
                                />

                                {/* Suggestions Panel */}
                                {showSuggestions && (
                                    <div className="border-b border-aegis-border-light bg-aegis-dark/50 max-h-[400px] overflow-y-auto">
                                        <div className="flex items-center justify-between px-4 py-2 border-b border-aegis-border-light sticky top-0 bg-aegis-dark z-10">
                                            <span className="text-xs font-medium text-aegis-text-muted">
                                                {loadingSuggestions ? 'Loading suggestions...' : 'Query Suggestions'}
                                                {suggestionsLoaded && !loadingSuggestions && (
                                                    <span className="ml-2 text-[10px] text-aegis-accent">(cached)</span>
                                                )}
                                            </span>
                                            <div className="flex items-center gap-2">
                                                <button
                                                    onClick={handleRefreshSuggestions}
                                                    disabled={loadingSuggestions}
                                                    className="text-aegis-text-muted hover:text-aegis-accent text-xs flex items-center gap-1 disabled:opacity-50"
                                                    title="Refresh suggestions"
                                                >
                                                    <svg className={`w-3 h-3 ${loadingSuggestions ? 'animate-spin' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                                                    </svg>
                                                    Refresh
                                                </button>
                                                <button
                                                    onClick={() => setShowSuggestions(false)}
                                                    className="text-aegis-text-muted hover:text-aegis-text text-xs"
                                                >
                                                    Close
                                                </button>
                                            </div>
                                        </div>
                                        {loadingSuggestions ? (
                                            <div className="p-4 text-center text-aegis-text-muted text-sm">
                                                <div className="animate-pulse">Analyzing your environment...</div>
                                            </div>
                                        ) : suggestions.length === 0 && aiSuggestions.length === 0 ? (
                                            <div className="p-4 text-center text-aegis-text-muted text-sm">
                                                No suggestions available. Make sure BloodHound data is loaded.
                                            </div>
                                        ) : (
                                            <>
                                                {/* Quick Suggestions (Predefined) */}
                                                {suggestions.length > 0 && (
                                                    <div>
                                                        <div className="px-4 py-2 bg-aegis-gray/30 border-b border-aegis-border-light">
                                                            <span className="text-[10px] font-semibold text-aegis-text-muted uppercase tracking-wider">
                                                                Quick Suggestions
                                                            </span>
                                                        </div>
                                                        <div className="divide-y divide-aegis-border-light">
                                                            {suggestions.map((suggestion, idx) => (
                                                                <button
                                                                    key={`quick-${idx}`}
                                                                    onClick={() => handleSuggestionExecute(suggestion)}
                                                                    onContextMenu={(e) => {
                                                                        e.preventDefault();
                                                                        handleSuggestionCopy(suggestion);
                                                                    }}
                                                                    disabled={isSending}
                                                                    className={`w-full text-left px-4 py-3 hover:bg-aegis-gray/50 transition-colors group ${isSending ? 'opacity-50 cursor-not-allowed' : ''}`}
                                                                >
                                                                    <div className="flex items-start justify-between gap-3">
                                                                        <div className="flex-1 min-w-0">
                                                                            <div className="flex items-center gap-2 mb-1">
                                                                                <span className="text-sm font-medium text-aegis-text">{suggestion.name}</span>
                                                                                <span className={`text-[10px] px-1.5 py-0.5 rounded ${suggestion.category === 'Cross-Domain' ? 'bg-amber-500/20 text-amber-400' : 'bg-aegis-accent/20 text-aegis-accent'}`}>
                                                                                    {suggestion.category}
                                                                                </span>
                                                                            </div>
                                                                            <p className="text-xs text-aegis-text-muted mb-2">{suggestion.description}</p>
                                                                            <code className="text-[11px] text-aegis-text-subtle font-mono block truncate">
                                                                                {suggestion.cypher}
                                                                            </code>
                                                                        </div>
                                                                        <div className="flex flex-col items-end gap-0.5 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                                                                            <span className="text-xs text-aegis-accent">
                                                                                {isSending ? 'Running...' : 'Run'}
                                                                            </span>
                                                                            <span className="text-[9px] text-aegis-text-subtle">
                                                                                Right-click to copy
                                                                            </span>
                                                                        </div>
                                                                    </div>
                                                                </button>
                                                            ))}
                                                        </div>
                                                    </div>
                                                )}

                                                {/* AI Suggestions (Model-generated) */}
                                                {(aiSuggestions.length > 0 || loadingAiSuggestions) && (
                                                    <div>
                                                        <div className="px-4 py-2 bg-purple-500/10 border-b border-aegis-border-light">
                                                            <div className="flex items-center gap-2">
                                                                <svg className="w-3 h-3 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                                                                </svg>
                                                                <span className="text-[10px] font-semibold text-purple-400 uppercase tracking-wider">
                                                                    AI Suggestions
                                                                </span>
                                                                {loadingAiSuggestions && (
                                                                    <span className="text-[10px] text-purple-400/70 animate-pulse ml-2">
                                                                        generating...
                                                                    </span>
                                                                )}
                                                            </div>
                                                        </div>
                                                        {loadingAiSuggestions && aiSuggestions.length === 0 ? (
                                                            <div className="px-4 py-3 text-xs text-purple-400/70 animate-pulse">
                                                                Analyzing environment and generating custom queries...
                                                            </div>
                                                        ) : (
                                                            <div className="divide-y divide-aegis-border-light">
                                                                {aiSuggestions.map((suggestion, idx) => (
                                                                    <button
                                                                        key={`ai-${idx}`}
                                                                        onClick={() => handleSuggestionExecute(suggestion)}
                                                                        onContextMenu={(e) => {
                                                                            e.preventDefault();
                                                                            handleSuggestionCopy(suggestion);
                                                                        }}
                                                                        disabled={isSending}
                                                                        className={`w-full text-left px-4 py-3 hover:bg-purple-500/10 transition-colors group ${isSending ? 'opacity-50 cursor-not-allowed' : ''}`}
                                                                    >
                                                                        <div className="flex items-start justify-between gap-3">
                                                                            <div className="flex-1 min-w-0">
                                                                                <div className="flex items-center gap-2 mb-1">
                                                                                    <span className="text-sm font-medium text-aegis-text">{suggestion.name}</span>
                                                                                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400">
                                                                                        {suggestion.category}
                                                                                    </span>
                                                                                </div>
                                                                                <p className="text-xs text-aegis-text-muted mb-2">{suggestion.description}</p>
                                                                                <code className="text-[11px] text-aegis-text-subtle font-mono block truncate">
                                                                                    {suggestion.cypher}
                                                                                </code>
                                                                            </div>
                                                                            <div className="flex flex-col items-end gap-0.5 flex-shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                                                                                <span className="text-xs text-purple-400">
                                                                                    {isSending ? 'Running...' : 'Run'}
                                                                                </span>
                                                                                <span className="text-[9px] text-aegis-text-subtle">
                                                                                    Right-click to copy
                                                                                </span>
                                                                            </div>
                                                                        </div>
                                                                    </button>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                            </>
                                        )}
                                    </div>
                                )}

                                {/* Input Area */}
                                <div className="flex items-end gap-3 p-3.5">
                                    <div className="flex-1 relative">
                                        <textarea
                                            ref={inputRef}
                                            value={inputValue}
                                            onChange={(e) => setInputValue(e.target.value)}
                                            onKeyDown={handleKeyDown}
                                            placeholder={
                                                isCheckingConnections
                                                    ? "Checking services..."
                                                    : isReportGenerating
                                                        ? "Report generating... Please wait"
                                                        : neo4jMode === 'custom'
                                                            ? !customNeo4jConnected
                                                                ? "Neo4j not connected..."
                                                                : !hasBloodHoundData
                                                                    ? "Upload BloodHound data to start..."
                                                                    : "e.g., 'Show Domain Admins' or MATCH (n:User)..."
                                                            : !dockerRunning
                                                                ? "Docker not running..."
                                                                : !bloodhoundRunning
                                                                    ? "BloodHound CE not running..."
                                                                    : !neo4jReady
                                                                        ? "Waiting for Neo4j..."
                                                                        : !hasBloodHoundData
                                                                            ? "Upload BloodHound data to start..."
                                                                            : "e.g., 'Show Domain Admins' or MATCH (n:User)..."
                                            }
                                            className={`
                                            w-full bg-transparent text-aegis-text placeholder-aegis-text-subtle
                                            resize-none focus:outline-none text-[15px] leading-relaxed
                                            min-h-[28px] max-h-[180px] py-1 pr-16
                                            ${!canUseChat ? 'cursor-not-allowed opacity-50' : ''}
                                        `}
                                            rows={1}
                                            disabled={isSending || !canUseChat}
                                        />
                                        {/* Suggest button at tail end of input area */}
                                        {canUseChat && !inputValue.trim() && !isSending && (
                                            <button
                                                onClick={() => handleSuggestClick()}
                                                className="absolute right-0 top-1/2 -translate-y-1/2 text-xs text-aegis-accent hover:text-aegis-accent-hover transition-colors font-medium"
                                                title="Get query suggestions based on your environment"
                                            >
                                                Suggest
                                            </button>
                                        )}
                                    </div>

                                    {/* Send Button */}
                                    <button
                                        onClick={handleSendMessage}
                                        disabled={!inputValue.trim() || isSending || !canUseChat}
                                        className={`
                                        flex-shrink-0 w-9 h-9 rounded-xl flex items-center justify-center
                                        transition-all duration-200
                                        ${inputValue.trim() && canUseChat && !isSending
                                                ? 'bg-aegis-accent text-white hover:bg-aegis-accent-hover'
                                                : 'bg-aegis-gray-light text-aegis-text-subtle cursor-not-allowed'
                                            }
                                    `}
                                    >
                                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 10l7-7m0 0l7 7m-7-7v18" />
                                        </svg>
                                    </button>
                                </div>

                                {/* Bottom Bar - Format Toggle (only when chat is usable) */}
                                {canUseChat && (
                                    <div className="flex items-center justify-between px-3.5 py-2.5 border-t border-aegis-border-light bg-black/20">
                                        <div className="flex items-center gap-2.5">
                                            <span className="text-xs text-aegis-text-subtle">Response:</span>
                                            <ResponseFormatToggle
                                                format={responseFormat}
                                                onChange={setResponseFormat}
                                                disabled={isSending}
                                            />
                                        </div>
                                        <span className="text-[11px] text-aegis-text-subtle">
                                            Shift + Enter for new line
                                        </span>
                                    </div>
                                )}
                            </div>

                            {/* Disclaimer */}
                            <p className="text-xs text-aegis-text-subtle mt-3 text-center">
                                {canUseChat
                                    ? "AEGIS can make mistakes. Always verify security recommendations."
                                    : disabledReason
                                        ? disabledReason.subtitle
                                        : "Previous messages shown for reference only."
                                }
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            {/* Report Panel (Side Panel Mode) */}
            {reportPanelOpen && currentReport && !isReportFullScreen && (
                <div className="w-1/2 border-l border-aegis-border-light h-full overflow-hidden bg-aegis-dark flex flex-col">
                    <div className="flex-1 overflow-y-auto">
                        <UnifiedAttackPathReport
                            report={currentReport}
                            analysisId={currentAnalysisId}
                            onBack={toggleReportPanel}
                            onRemoveFinding={handleRemoveFinding}
                            onFullScreen={toggleReportFullScreen}
                            isFullScreen={false}
                            tier0Config={tier0Config}
                        />
                    </div>
                </div>
            )}

            {/* Report Fullscreen Modal */}
            {isReportFullScreen && currentReport && (
                <div
                    className="fixed inset-0 z-[60] bg-aegis-dark overflow-y-auto"
                    style={{ WebkitAppRegion: 'no-drag' } as React.CSSProperties}
                >
                    <UnifiedAttackPathReport
                        report={currentReport}
                        analysisId={currentAnalysisId}
                        onBack={closeReportFullScreen}
                        onRemoveFinding={handleRemoveFinding}
                        isFullScreen={true}
                        tier0Config={tier0Config}
                    />
                </div>
            )}

            {/* Add to Report Modal */}
            {showAddToReportModal && pendingFinding && (
                <AddToReportModal
                    isOpen={showAddToReportModal}
                    onClose={() => {
                        setShowAddToReportModal(false);
                        setPendingFinding(null);
                    }}
                    onAdd={handleConfirmAddToReport}
                    finding={pendingFinding}
                    sourceQuery={pendingSourceQuery}
                    resultCount={pendingResultCount}
                />
            )}

            {/* Upload Warning Modal */}
            {showUploadWarningModal && (
                <UploadWarningModal
                    isOpen={showUploadWarningModal}
                    projectDomain={projectDomainName}
                    uploadedDomains={uploadedFileDomains}
                    onClose={() => setShowUploadWarningModal(false)}
                    onGoToHome={() => {
                        setShowUploadWarningModal(false);
                        navigate('/');
                    }}
                />
            )}
        </div>
    );
};

const ReportCard: React.FC<{
    report: any;
    projectName: string;
    onClick: () => void;
    isOpen: boolean;
}> = ({ report, projectName, onClick, isOpen }) => {
    const attackPathCount = report?.paths?.length || report?.critical_attack_paths?.length || 0;
    const riskLevel = attackPathCount > 5 ? 'Critical' : attackPathCount > 2 ? 'High' : 'Medium';

    return (
        <div className="-mt-6 mb-4 w-full">
            <button
                onClick={onClick}
                className="group flex items-center gap-3 p-3 bg-aegis-gray hover:bg-aegis-gray-hover border border-aegis-border hover:border-aegis-accent/50 rounded-xl transition-all duration-200 text-left w-full"
            >
                <div className="w-10 h-10 rounded-lg bg-aegis-dark flex items-center justify-center shrink-0">
                    <svg className="w-5 h-5 text-aegis-accent" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                </div>
                <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-aegis-text truncate">{projectName || 'Security Report'}</div>
                    <div className="flex items-center gap-2 mt-0.5">
                        <span className="text-xs text-aegis-text-muted">{attackPathCount} Attack Paths</span>
                        <span className="text-aegis-text-subtle">·</span>
                        <span className={`text-xs ${riskLevel === 'Critical' ? 'text-red-400' : riskLevel === 'High' ? 'text-orange-400' : 'text-yellow-400'}`}>{riskLevel} Risk</span>
                    </div>
                </div>
                <span className={`px-2 py-1 text-xs rounded-md ${isOpen ? 'bg-aegis-accent/20 text-aegis-accent' : 'bg-aegis-gray-light text-aegis-text-muted'}`}>
                    {isOpen ? 'VIEWING' : 'VIEW'}
                </span>
            </button>
        </div>
    );
};

// Empty State - Claude Style
const EmptyState: React.FC<{
    projectName: string;
    currentReport: any;
    onViewReport: () => void;
    onSuggestionClick: (text: string) => void;
}> = ({ projectName, currentReport, onViewReport, onSuggestionClick }) => (
    <div className="flex flex-col items-center justify-center min-h-[60vh]">
        <div className="w-12 h-12 rounded-full bg-gradient-to-br from-cyan-400 to-blue-500 flex items-center justify-center mb-6">
            <ShieldIcon className="w-6 h-6 text-white" />
        </div>

        <h1 className="text-2xl font-medium text-aegis-text mb-2">
            {projectName || 'Security Analysis'}
        </h1>

        <p className="text-aegis-text-muted text-center max-w-md mb-8">
            Ask questions about your Active Directory security, run Cypher queries, or explore the analysis report.
        </p>

        {currentReport && (
            <button
                onClick={onViewReport}
                className="mb-8 px-5 py-2.5 bg-aegis-gray hover:bg-aegis-gray-hover border border-aegis-border rounded-xl text-sm font-medium transition-colors flex items-center gap-2 text-aegis-text"
            >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                View Security Report
            </button>
        )}

        <div className="w-full max-w-md space-y-2">
            <p className="text-xs text-aegis-text-subtle mb-3">Try asking:</p>
            <SuggestionButton
                text="How do I remediate Kerberoasting vulnerabilities?"
                onClick={onSuggestionClick}
            />
            <SuggestionButton
                text="MATCH (u:User) WHERE u.enabled = true RETURN u.name LIMIT 10"
                onClick={onSuggestionClick}
            />
            <SuggestionButton
                text="What are the most critical attack paths in my environment?"
                onClick={onSuggestionClick}
            />
        </div>
    </div>
);

// Suggestion Button
const SuggestionButton: React.FC<{ text: string; onClick: (text: string) => void }> = ({ text, onClick }) => (
    <button
        onClick={() => onClick(text)}
        className="w-full text-left px-4 py-3 bg-aegis-gray hover:bg-aegis-gray-hover border border-aegis-border rounded-xl text-sm text-aegis-text-muted hover:text-aegis-text transition-colors"
    >
        {text}
    </button>
);

// Response Format Toggle - In input area
const ResponseFormatToggle: React.FC<{
    format: ViewMode;
    onChange: (format: ViewMode) => void;
    disabled?: boolean;
}> = ({ format, onChange, disabled }) => (
    <div className="flex items-center gap-0.5 bg-aegis-dark rounded-lg p-[3px]">
        <button
            onClick={() => onChange('normal')}
            disabled={disabled}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-150 ${format === 'normal'
                ? 'bg-aegis-accent text-white'
                : 'text-aegis-text-muted hover:text-aegis-text'
                } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
            title="Standard chat response"
        >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            Chat
        </button>
        <button
            onClick={() => onChange('report')}
            disabled={disabled}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-150 ${format === 'report'
                ? 'bg-emerald-600 text-white'
                : 'text-aegis-text-muted hover:text-aegis-text'
                } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
            title="Generate finding for report"
        >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Report
        </button>
    </div>
);

// Helper to check if a message is a raw Cypher query
const isCypherQuery = (content: string): boolean => {
    const trimmed = content.trim().toUpperCase();
    return (
        trimmed.startsWith('MATCH') ||
        trimmed.startsWith('OPTIONAL MATCH') ||
        trimmed.startsWith('WITH') ||
        trimmed.startsWith('CALL') ||
        trimmed.startsWith('UNWIND')
    );
};

// Message Block - Claude Style (no bubbles for assistant)
const MessageBlock: React.FC<{
    message: Message;
    onCopy: (text: string) => void;
    responseData?: QueryResponse;
    onAddToReport?: (finding: Finding) => void;
    onViewReport?: () => void;
    hasReport?: boolean;
    preSelectedViewMode?: ViewMode;  // The format selected before sending
}> = ({ message, onCopy, responseData, onAddToReport, onViewReport, hasReport, preSelectedViewMode }) => {
    const isUser = message.role === 'user';

    // User message - check if it's a Cypher query
    if (isUser) {
        const isCypher = isCypherQuery(message.content);

        // If it's a Cypher query, render with CypherQueryDisplay
        if (isCypher) {
            return (
                <div className="flex justify-end mb-4">
                    <div className="max-w-[85%]">
                        <div className="text-xs text-aegis-text-muted mb-1.5 text-right">Your query</div>
                        <CypherQueryDisplay
                            query={message.content}
                            queryName="Cypher Query"
                            description="User-submitted query"
                            onCopy={onCopy}
                        />
                    </div>
                </div>
            );
        }

        // Regular text message
        return (
            <div className="flex justify-end mb-4">
                <div className="max-w-[85%] bg-aegis-gray border border-aegis-border rounded-2xl px-4 py-3">
                    <p className="text-aegis-text whitespace-pre-wrap text-[15px]">{message.content}</p>
                </div>
            </div>
        );
    }

    // Check for structured report summary (messages with $$REPORT_SUMMARY$$ marker)
    if (message.content.startsWith('$$REPORT_SUMMARY$$')) {
        try {
            const jsonData = message.content.slice('$$REPORT_SUMMARY$$'.length);
            const summaryData: ReportSummaryData = JSON.parse(jsonData);
            return (
                <div className="py-2">
                    <SecurityReportSummary
                        data={summaryData}
                        onViewReport={onViewReport}
                    />
                </div>
            );
        } catch (err) {
            console.error('Failed to parse report summary:', err);
            // Fall through to default rendering
        }
    }

    // Assistant message with intelligent chat response data - use ChatResponseRenderer
    if (responseData) {
        return (
            <div className="py-2">
                <ChatResponseRenderer
                    response={responseData}
                    viewMode={preSelectedViewMode || 'normal'}
                    onAddToReport={hasReport ? onAddToReport : undefined}
                    onCopy={onCopy}
                />
            </div>
        );
    }

    // Default assistant message - plain text, document style (fallback for old messages)
    return (
        <div className="py-2">
            <div className="prose prose-invert max-w-none">
                <ReactMarkdown
                    components={{
                        h1: ({ children, ...props }: any) => (
                            <h1 className="text-xl font-semibold text-aegis-text mt-6 mb-4" {...props}>{children}</h1>
                        ),
                        h2: ({ children, ...props }: any) => (
                            <h2 className="text-lg font-semibold text-aegis-text mt-6 mb-3" {...props}>{children}</h2>
                        ),
                        h3: ({ children, ...props }: any) => (
                            <h3 className="text-base font-semibold text-aegis-text mt-4 mb-2" {...props}>{children}</h3>
                        ),
                        p: ({ children, ...props }: any) => (
                            <p className="text-aegis-text mb-4 leading-relaxed text-[15px]" {...props}>{children}</p>
                        ),
                        ul: ({ ...props }: any) => (
                            <ul className="mb-4 space-y-1 text-[15px]" {...props} />
                        ),
                        ol: ({ ...props }: any) => (
                            <ol className="mb-4 space-y-1 list-decimal list-inside text-[15px]" {...props} />
                        ),
                        li: ({ children, ...props }: any) => (
                            <li className="text-aegis-text leading-relaxed" {...props}>
                                {children}
                            </li>
                        ),
                        code: ({ inline, className, children, ...props }: any) => {
                            if (inline) {
                                return (
                                    <code className="bg-aegis-gray-light px-1.5 py-0.5 rounded text-aegis-accent text-sm font-mono" {...props}>
                                        {children}
                                    </code>
                                );
                            }
                            const match = /language-(\w+)/.exec(className || '');
                            const language = match ? match[1] : 'text';
                            return (
                                <div className="my-4 rounded-lg overflow-hidden border border-aegis-border">
                                    <div className="bg-aegis-dark px-4 py-2 border-b border-aegis-border flex items-center justify-between">
                                        <span className="text-xs font-mono text-aegis-text-subtle">{language}</span>
                                        <button
                                            onClick={() => onCopy(String(children))}
                                            className="text-aegis-text-muted hover:text-aegis-text transition-colors"
                                            title="Copy code"
                                        >
                                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                            </svg>
                                        </button>
                                    </div>
                                    <SyntaxHighlighter
                                        language={language}
                                        style={vscDarkPlus}
                                        customStyle={{
                                            margin: 0,
                                            padding: '1rem',
                                            backgroundColor: '#010409',
                                            fontSize: '0.875rem',
                                        }}
                                        wrapLongLines={true}
                                    >
                                        {String(children).replace(/\n$/, '')}
                                    </SyntaxHighlighter>
                                </div>
                            );
                        },
                        strong: ({ children, ...props }: any) => (
                            <strong className="text-aegis-text font-semibold" {...props}>{children}</strong>
                        ),
                        a: ({ children, href, ...props }: any) => (
                            <a href={href} className="text-aegis-accent hover:text-aegis-accent-hover hover:underline" target="_blank" rel="noopener noreferrer" {...props}>
                                {children}
                            </a>
                        ),
                        blockquote: ({ children, ...props }: any) => (
                            <blockquote className="border-l-2 border-aegis-border-muted pl-4 my-4 italic text-aegis-text-muted" {...props}>
                                {children}
                            </blockquote>
                        ),
                        // Table components for proper rendering
                        table: ({ children, ...props }: any) => (
                            <div className="my-4 overflow-x-auto rounded-lg border border-aegis-border">
                                <table className="w-full text-sm" {...props}>
                                    {children}
                                </table>
                            </div>
                        ),
                        thead: ({ children, ...props }: any) => (
                            <thead className="bg-aegis-dark border-b border-aegis-border" {...props}>
                                {children}
                            </thead>
                        ),
                        tbody: ({ children, ...props }: any) => (
                            <tbody className="divide-y divide-aegis-border" {...props}>
                                {children}
                            </tbody>
                        ),
                        tr: ({ children, ...props }: any) => (
                            <tr className="hover:bg-aegis-gray/30 transition-colors" {...props}>
                                {children}
                            </tr>
                        ),
                        th: ({ children, ...props }: any) => (
                            <th className="px-4 py-2 text-left text-xs font-semibold text-aegis-text-muted uppercase tracking-wider" {...props}>
                                {children}
                            </th>
                        ),
                        td: ({ children, ...props }: any) => (
                            <td className="px-4 py-2 text-aegis-text font-mono text-xs" {...props}>
                                {children}
                            </td>
                        ),
                    }}
                >
                    {message.content}
                </ReactMarkdown>
            </div>
        </div>
    );
};

// Upload Warning Modal - Shows when user tries to upload different domain data
const UploadWarningModal: React.FC<{
    isOpen: boolean;
    projectDomain: string;
    uploadedDomains: string[];
    onClose: () => void;
    onGoToHome: () => void;
}> = ({ isOpen, projectDomain, uploadedDomains, onClose, onGoToHome }) => {
    if (!isOpen) return null;

    const uploadedDomainText = uploadedDomains.length > 0
        ? uploadedDomains.join(', ')
        : 'Unknown domain';

    const projectDomainText = projectDomain || 'Unknown';

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
            {/* Backdrop */}
            <div
                className="absolute inset-0 bg-black/60 backdrop-blur-sm"
                onClick={onClose}
            />

            {/* Modal */}
            <div className="relative bg-aegis-dark border border-aegis-border rounded-2xl shadow-2xl max-w-md w-full mx-4 overflow-hidden">
                {/* Header */}
                <div className="px-6 py-4 border-b border-aegis-border bg-amber-500/5">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-xl bg-amber-500/15 flex items-center justify-center">
                            <svg className="w-5 h-5 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                            </svg>
                        </div>
                        <div>
                            <h3 className="text-lg font-semibold text-aegis-text">Different Domain Detected</h3>
                            <p className="text-sm text-aegis-text-muted">This file contains data from a different domain</p>
                        </div>
                    </div>
                </div>

                {/* Content */}
                <div className="px-6 py-5">
                    {/* Domain Comparison */}
                    <div className="mb-4 space-y-2">
                        <div className="flex items-center justify-between text-sm">
                            <span className="text-aegis-text-muted">Uploaded file domain:</span>
                            <span className="px-2 py-1 bg-red-500/15 text-red-400 rounded font-mono text-xs">
                                {uploadedDomainText}
                            </span>
                        </div>
                        <div className="flex items-center justify-between text-sm">
                            <span className="text-aegis-text-muted">Project domain:</span>
                            <span className="px-2 py-1 bg-emerald-500/15 text-emerald-400 rounded font-mono text-xs">
                                {projectDomainText}
                            </span>
                        </div>
                    </div>

                    <div className="bg-aegis-gray/50 border border-aegis-border rounded-xl p-4 mb-4">
                        <p className="text-sm text-aegis-text-muted">
                            <span className="text-amber-500 font-medium">Why?</span> BloodHound CE can only work with one domain's data at a time. Uploading data from <span className="text-aegis-text font-medium">{uploadedDomainText}</span> would overwrite the <span className="text-aegis-text font-medium">{projectDomainText}</span> data and break your chat history.
                        </p>
                    </div>

                    <div className="flex items-start gap-2 text-xs text-aegis-text-subtle">
                        <svg className="w-4 h-4 text-aegis-accent shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <span>To analyze <span className="text-aegis-text">{uploadedDomainText}</span> data, go to the Home screen and create a new project.</span>
                    </div>
                </div>

                {/* Actions */}
                <div className="px-6 py-4 border-t border-aegis-border bg-aegis-gray/30 flex items-center justify-end gap-3">
                    <button
                        onClick={onClose}
                        className="px-4 py-2 text-sm font-medium text-aegis-text-muted hover:text-aegis-text transition-colors"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={onGoToHome}
                        className="flex items-center gap-2 px-4 py-2 bg-aegis-accent hover:bg-aegis-accent-hover text-white text-sm font-medium rounded-lg transition-colors"
                    >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                        </svg>
                        Create New Project
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ChatScreen;
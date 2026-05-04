/**
 * Chat Request Store using Zustand
 * Location: src/stores/chatRequestStore.ts
 *
 * Persists in-flight chat requests across navigation so users can leave
 * ChatScreen and come back without losing the response being generated.
 *
 * Flow:
 * 1. User sends query → store starts request
 * 2. User navigates away → request continues in background
 * 3. User returns to ChatScreen → sees completed/in-progress response
 */

import { create } from 'zustand';
import type { QueryResponse, ViewMode } from '../types/chat';

// ==================== TYPES ====================

interface PendingRequest {
    chatId: string;
    messageId: string;       // ID of the assistant message being generated
    query: string;
    viewMode: ViewMode;
    startedAt: number;       // Date.now()
    status: 'pending' | 'completed' | 'failed' | 'cancelled';
    response?: QueryResponse;
    error?: string;
}

interface ChatRequestState {
    // Current pending request (only one at a time)
    pendingRequest: PendingRequest | null;

    // Actions
    startRequest: (chatId: string, messageId: string, query: string, viewMode: ViewMode) => void;
    completeRequest: (response: QueryResponse) => void;
    failRequest: (error: string) => void;
    cancelRequest: () => void;
    clearRequest: () => void;

    // Consume: get and clear the completed response (used when ChatScreen mounts)
    consumeCompleted: (chatId: string) => QueryResponse | null;
}

// ==================== STORE ====================

export const useChatRequestStore = create<ChatRequestState>((set, get) => ({
    pendingRequest: null,

    startRequest: (chatId, messageId, query, viewMode) => {
        // Cancel any existing request
        const current = get().pendingRequest;
        if (current && current.status === 'pending') {
            console.log('[ChatRequestStore] Cancelling previous pending request');
        }

        set({
            pendingRequest: {
                chatId,
                messageId,
                query,
                viewMode,
                startedAt: Date.now(),
                status: 'pending',
            }
        });
    },

    completeRequest: (response) => {
        const current = get().pendingRequest;
        if (current && current.status === 'pending') {
            set({
                pendingRequest: {
                    ...current,
                    status: 'completed',
                    response,
                }
            });
            console.log('[ChatRequestStore] Request completed');
        }
    },

    failRequest: (error) => {
        const current = get().pendingRequest;
        if (current && current.status === 'pending') {
            set({
                pendingRequest: {
                    ...current,
                    status: 'failed',
                    error,
                }
            });
            console.log('[ChatRequestStore] Request failed:', error);
        }
    },

    cancelRequest: () => {
        const current = get().pendingRequest;
        if (current && current.status === 'pending') {
            set({
                pendingRequest: {
                    ...current,
                    status: 'cancelled',
                }
            });
            console.log('[ChatRequestStore] Request cancelled');
        }
    },

    clearRequest: () => {
        set({ pendingRequest: null });
    },

    consumeCompleted: (chatId) => {
        const current = get().pendingRequest;
        if (current && current.chatId === chatId && current.status === 'completed' && current.response) {
            const response = current.response;
            set({ pendingRequest: null });
            return response;
        }
        return null;
    },
}));

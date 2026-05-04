/**
 * Discord Webhook Service
 * Sends feedback to Discord channels via webhooks
 */

import https from 'https';
import { URL } from 'url';

// Get webhook URLs at runtime (not module load time)
function getWebhooks() {
    return {
        bugs: process.env.DISCORD_WEBHOOK_BUGS || '',
        features: process.env.DISCORD_WEBHOOK_FEATURES || '',
        all: process.env.DISCORD_WEBHOOK_ALL || '',
    };
}

// Embed colors by feedback type
const EMBED_COLORS = {
    bug: 0xED4245,      // Red
    feature: 0x57F287,  // Green
    feedback: 0x5865F2, // Blurple
};

// Emoji by feedback type
const TYPE_EMOJI = {
    bug: '🐛',
    feature: '✨',
    feedback: '💬',
};

export interface FeedbackPayload {
    type: 'bug' | 'feature' | 'feedback';
    title: string;
    description: string;
    email?: string;
    systemInfo?: {
        platform: string;
        osVersion: string;
        arch: string;
        aegisVersion: string;
        electronVersion: string;
        memory: string;
        nodeVersion: string;
        cpuCores: number;
    };
    logs?: string[];
    timestamp: string;
}

interface DiscordEmbed {
    title: string;
    description: string;
    color: number;
    fields: Array<{ name: string; value: string; inline?: boolean }>;
    footer: { text: string };
    timestamp: string;
}

interface DiscordWebhookPayload {
    username: string;
    avatar_url?: string;
    embeds: DiscordEmbed[];
}

/**
 * Sanitize user input to prevent Discord mention abuse
 */
function sanitize(text: string): string {
    return text
        .slice(0, 2000) // Discord embed limit
        .replace(/@everyone/gi, '@\u200beveryone')
        .replace(/@here/gi, '@\u200bhere');
}

/**
 * Format feedback as Discord embed
 */
function formatEmbed(feedback: FeedbackPayload): DiscordEmbed {
    const emoji = TYPE_EMOJI[feedback.type];
    const color = EMBED_COLORS[feedback.type];

    const fields: Array<{ name: string; value: string; inline?: boolean }> = [];

    // Add system info fields if provided
    if (feedback.systemInfo) {
        fields.push({
            name: '💻 Platform',
            value: `${feedback.systemInfo.platform} ${feedback.systemInfo.osVersion} (${feedback.systemInfo.arch})`,
            inline: true,
        });
        fields.push({
            name: '📦 Version',
            value: feedback.systemInfo.aegisVersion,
            inline: true,
        });
        fields.push({
            name: '🧠 Memory',
            value: feedback.systemInfo.memory,
            inline: true,
        });
    }

    // Add contact email if provided
    if (feedback.email) {
        fields.push({
            name: '📧 Contact',
            value: feedback.email,
            inline: true,
        });
    }

    // Add truncated logs if provided
    if (feedback.logs && feedback.logs.length > 0) {
        const logsText = feedback.logs.slice(-10).join('\n');
        const truncated = logsText.length > 1000
            ? logsText.slice(-1000) + '\n...(truncated)'
            : logsText;
        fields.push({
            name: '📋 Recent Logs',
            value: `\`\`\`\n${truncated}\n\`\`\``,
            inline: false,
        });
    }

    return {
        title: `${emoji} ${sanitize(feedback.title)}`,
        description: sanitize(feedback.description),
        color,
        fields,
        footer: {
            text: `AEGIS Feedback • ${feedback.type.charAt(0).toUpperCase() + feedback.type.slice(1)}`,
        },
        timestamp: feedback.timestamp,
    };
}

/**
 * Send feedback to Discord webhook
 */
export async function sendToDiscord(feedback: FeedbackPayload): Promise<{ success: boolean; error?: string }> {
    // Get webhooks at runtime (after env vars are loaded)
    const webhooks = getWebhooks();

    // Determine which webhook to use based on type
    let webhookUrl = webhooks.all; // Default to all

    if (feedback.type === 'bug' && webhooks.bugs) {
        webhookUrl = webhooks.bugs;
    } else if (feedback.type === 'feature' && webhooks.features) {
        webhookUrl = webhooks.features;
    }

    if (!webhookUrl) {
        console.error('[Discord] No webhook URL configured');
        return { success: false, error: 'Feedback system not configured' };
    }

    const embed = formatEmbed(feedback);

    const payload: DiscordWebhookPayload = {
        username: 'AEGIS Feedback',
        embeds: [embed],
    };

    try {
        const url = new URL(webhookUrl);
        const postData = JSON.stringify(payload);

        const options = {
            hostname: url.hostname,
            port: 443,
            path: url.pathname + url.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData),
            },
        };

        return new Promise((resolve) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk; });
                res.on('end', () => {
                    if (res.statusCode === 204 || res.statusCode === 200) {
                        console.log('[Discord] Feedback sent successfully');
                        resolve({ success: true });
                    } else {
                        console.error('[Discord] Failed to send:', res.statusCode, data);
                        resolve({ success: false, error: `Discord returned ${res.statusCode}` });
                    }
                });
            });

            req.on('error', (err) => {
                console.error('[Discord] Request error:', err.message);
                resolve({ success: false, error: err.message });
            });

            req.write(postData);
            req.end();
        });

    } catch (err: any) {
        console.error('[Discord] Error:', err.message);
        return { success: false, error: err.message };
    }
}

/**
 * Check if feedback webhooks are configured
 */
export function isWebhookConfigured(): boolean {
    const webhooks = getWebhooks();
    return !!(webhooks.bugs || webhooks.features || webhooks.all);
}

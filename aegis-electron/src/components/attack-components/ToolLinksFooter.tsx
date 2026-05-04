/**
 * Tool Links Footer Component
 * Location: src/components/attack-components/ToolLinksFooter.tsx
 *
 * Displays links to offensive security tools detected in attack commands.
 * Shared between FindingCard and T0 lateral movement sections.
 */

import React from 'react';

// Tool download links mapping
export const TOOL_LINKS: Record<string, { name: string; url: string; description: string }> = {
    // Impacket suite tools
    'psexec.py': { name: 'PsExec.py', url: 'https://github.com/fortra/impacket', description: 'Impacket suite' },
    'wmiexec': { name: 'WMIExec', url: 'https://github.com/fortra/impacket', description: 'Impacket suite' },
    'smbexec': { name: 'SMBExec', url: 'https://github.com/fortra/impacket', description: 'Impacket suite' },
    'secretsdump': { name: 'secretsdump', url: 'https://github.com/fortra/impacket', description: 'Impacket suite' },
    'getuserspns': { name: 'GetUserSPNs', url: 'https://github.com/fortra/impacket', description: 'Impacket suite' },
    'getnpusers': { name: 'GetNPUsers', url: 'https://github.com/fortra/impacket', description: 'Impacket suite' },
    'dcsync': { name: 'secretsdump (DCSync)', url: 'https://github.com/fortra/impacket', description: 'Impacket suite' },
    'impacket': { name: 'Impacket', url: 'https://github.com/fortra/impacket', description: 'Python AD toolkit' },
    'atexec': { name: 'atexec', url: 'https://github.com/fortra/impacket', description: 'Impacket suite' },
    'dcomexec': { name: 'dcomexec', url: 'https://github.com/fortra/impacket', description: 'Impacket suite' },
    // Sysinternals
    'psexec': { name: 'PsExec', url: 'https://learn.microsoft.com/en-us/sysinternals/downloads/psexec', description: 'Sysinternals' },
    // Kerberos tools
    'rubeus': { name: 'Rubeus', url: 'https://github.com/GhostPack/Rubeus', description: 'Kerberos abuse toolkit' },
    'mimikatz': { name: 'Mimikatz', url: 'https://github.com/gentilkiwi/mimikatz', description: 'Credential extraction' },
    'pypykatz': { name: 'pypykatz', url: 'https://github.com/skelsec/pypykatz', description: 'Python Mimikatz' },
    // AD enumeration
    'bloodhound': { name: 'BloodHound', url: 'https://github.com/BloodHoundAD/BloodHound', description: 'AD attack path mapping' },
    'sharphound': { name: 'SharpHound', url: 'https://github.com/BloodHoundAD/SharpHound', description: 'BloodHound collector' },
    'powerview': { name: 'PowerView', url: 'https://github.com/PowerShellMafia/PowerSploit', description: 'PowerSploit module' },
    'powerup': { name: 'PowerUp', url: 'https://github.com/PowerShellMafia/PowerSploit', description: 'Privilege escalation' },
    // Certificate abuse
    'certipy': { name: 'Certipy', url: 'https://github.com/ly4k/Certipy', description: 'AD CS abuse toolkit' },
    'certify': { name: 'Certify', url: 'https://github.com/GhostPack/Certify', description: 'Certificate enumeration' },
    // Remote access
    'evil-winrm': { name: 'Evil-WinRM', url: 'https://github.com/Hackplayers/evil-winrm', description: 'WinRM shell' },
    'crackmapexec': { name: 'CrackMapExec', url: 'https://github.com/Pennyw0rth/NetExec', description: 'Network execution' },
    'netexec': { name: 'NetExec', url: 'https://github.com/Pennyw0rth/NetExec', description: 'Network execution' },
    'nxc': { name: 'NetExec', url: 'https://github.com/Pennyw0rth/NetExec', description: 'Network execution' },
    // LDAP tools
    'ldapsearch': { name: 'ldapsearch', url: 'https://github.com/fortra/impacket', description: 'LDAP enumeration' },
    'ldapdomaindump': { name: 'ldapdomaindump', url: 'https://github.com/dirkjanm/ldapdomaindump', description: 'LDAP dumper' },
    // RBCD/Delegation
    'rbcd': { name: 'rbcd.py', url: 'https://github.com/fortra/impacket', description: 'RBCD attack tool' },
    'addcomputer': { name: 'addcomputer.py', url: 'https://github.com/fortra/impacket', description: 'Machine account creation' },
    // Hashcat/John
    'hashcat': { name: 'Hashcat', url: 'https://hashcat.net/hashcat/', description: 'Password cracker' },
    'john': { name: 'John the Ripper', url: 'https://github.com/openwall/john', description: 'Password cracker' },
    // Shadow Credentials
    'whisker': { name: 'Whisker', url: 'https://github.com/eladshamir/Whisker', description: 'Shadow credentials tool' },
    // Additional Impacket tools
    'ticketer': { name: 'ticketer.py', url: 'https://github.com/fortra/impacket', description: 'Ticket creation (Golden/Silver)' },
    // RDP tools
    'xfreerdp': { name: 'xfreerdp', url: 'https://github.com/FreeRDP/FreeRDP', description: 'Linux RDP client' },
    'freerdp': { name: 'FreeRDP', url: 'https://github.com/FreeRDP/FreeRDP', description: 'Linux RDP client' },
    // Credential dumping
    'sharpsecdump': { name: 'SharpSecDump', url: 'https://github.com/G0ldenGunSec/SharpSecDump', description: 'Remote SAM dump' },
    // Kerberos tools
    'gettgt': { name: 'getTGT.py', url: 'https://github.com/fortra/impacket', description: 'Request TGT' },
    'getst': { name: 'getST.py', url: 'https://github.com/fortra/impacket', description: 'Request service ticket' },
    // Token manipulation
    'invoke-tokenmanipulation': { name: 'Invoke-TokenManipulation', url: 'https://github.com/PowerShellMafia/PowerSploit', description: 'Token impersonation' },
    // Machine account tools
    'powermad': { name: 'Powermad', url: 'https://github.com/Kevin-Robertson/Powermad', description: 'Machine account creation' },
    'new-machineaccount': { name: 'Powermad', url: 'https://github.com/Kevin-Robertson/Powermad', description: 'Machine account creation' },
    // Lsadump
    'lsadump': { name: 'Mimikatz', url: 'https://github.com/gentilkiwi/mimikatz', description: 'Credential extraction' },
};

/**
 * Detect tools mentioned in command text
 */
export function detectToolsFromCommand(command: string, toolName?: string): string[] {
    const detectedTools = new Set<string>();
    const searchText = `${command} ${toolName || ''}`.toLowerCase();

    for (const [key, _] of Object.entries(TOOL_LINKS)) {
        // Check for tool name in command (with word boundary awareness)
        const patterns = [
            key, // exact match
            key.replace('.py', ''), // without .py extension
            key.replace('-', ''), // without hyphens
        ];

        for (const pattern of patterns) {
            if (searchText.includes(pattern)) {
                detectedTools.add(key);
                break;
            }
        }
    }

    return Array.from(detectedTools);
}

/**
 * Detect tools from attack step with opsec options
 */
export function detectToolsFromStep(step: any): string[] {
    const commandTexts: string[] = [];

    // Collect commands from opsec_options
    if (step.opsec_options && Array.isArray(step.opsec_options)) {
        for (const option of step.opsec_options) {
            if (option.command) commandTexts.push(option.command);
            if (option.tool_name) commandTexts.push(option.tool_name);
        }
    }

    // Also check legacy command field
    if (step.command) commandTexts.push(step.command);
    if (step.tool) commandTexts.push(step.tool);
    if (step.title) commandTexts.push(step.title);

    return detectToolsFromCommand(commandTexts.join(' '));
}

interface ToolLinksFooterProps {
    tools: string[];
}

/**
 * Tool Links Footer - displays download links for detected tools
 */
const ToolLinksFooter: React.FC<ToolLinksFooterProps> = ({ tools }) => {
    if (tools.length === 0) return null;

    // Deduplicate by URL (Impacket tools share same URL)
    const uniqueByUrl = new Map<string, { name: string; url: string; description: string }>();
    for (const toolKey of tools) {
        const tool = TOOL_LINKS[toolKey];
        if (tool && !uniqueByUrl.has(tool.url)) {
            uniqueByUrl.set(tool.url, tool);
        }
    }

    const uniqueTools = Array.from(uniqueByUrl.values());

    if (uniqueTools.length === 0) return null;

    return (
        <div className="px-4 py-2.5 bg-[#0d1117] border-t border-[#30363d] flex items-center flex-wrap gap-3">
            <span className="text-[10px] text-[#6e7681] uppercase tracking-wider font-semibold">Tools:</span>
            {uniqueTools.map((tool, idx) => (
                <a
                    key={idx}
                    href={tool.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-xs text-[#8b949e] hover:text-[#58a6ff] transition-colors group"
                    title={tool.description}
                >
                    <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                    <span className="group-hover:underline">{tool.name}</span>
                </a>
            ))}
        </div>
    );
};

export default ToolLinksFooter;

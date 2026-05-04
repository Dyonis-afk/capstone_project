"""
Obfuscation Helpers for Attack Path Analysis
Location: backend/routers/attack_paths/services/obfuscation_helpers.py

Provides PowerShell command detection for OPSEC-aware attack steps.

NOTE: Command obfuscation (backtick insertion, string splitting) has been
DISABLED. It was making commands non-copy-pasteable and unreadable in
reports. AMSI bypasses are handled separately by amsi_injector.py which
adds appendix references. The obfuscation_service.py is still used for
generating AMSI bypass code in the appendix section only.
"""

import logging
from typing import List, Dict

logger = logging.getLogger(__name__)


def is_powershell_command(command: str) -> bool:
    """
    Detect if a command is PowerShell-based.
    Returns True for commands that would benefit from AMSI bypass.
    """
    if not command:
        return False

    command_lower = command.lower()

    # PowerShell indicators
    powershell_indicators = [
        'get-', 'set-', 'new-', 'add-', 'remove-', 'invoke-',
        'import-', 'export-', 'start-', 'stop-', 'write-',
        'powershell', '.ps1', '$_', '$env:', 'foreach',
        'where-object', 'select-object', '-identity', '-filter',
        'get-aduser', 'get-adgroup', 'get-adcomputer',
        'convertto-', 'convertfrom-', '[ref]', '[system.',
        'add-type', 'new-object', '-credential',
        # PowerView/offensive PowerShell
        'get-domain', 'set-domain', 'find-domain', 'invoke-mimikatz',
        'invoke-kerberoast', 'invoke-rubeus', 'invoke-bloodhound'
    ]

    # Exclude indicators (tools that run outside PowerShell - Linux/Python tools)
    exclude_indicators = [
        # Hash cracking tools
        'hashcat', 'john',
        # Python/Impacket tools (run on Linux/Kali)
        'impacket', '.py', 'secretsdump', 'psexec.py', 'wmiexec.py',
        'smbexec.py', 'getuserspns.py', 'getnpusers.py', 'ticketer.py',
        'gettgt.py', 'getst.py', 'rbcd.py', 'owneredit.py', 'dacledit.py',
        'changepasswd.py', 'ntlmrelayx.py', 'petitpotam.py', 'printerbug.py',
        # NetExec/CrackMapExec (Python, runs on Linux)
        'nxc ', 'nxc.', 'netexec', 'crackmapexec', 'cme ',
        # Certipy (Python, runs on Linux)
        'certipy', 'pywhisker', 'bloodyad',
        # Other Linux tools
        'evil-winrm', 'responder', 'ntlmrelayx',
        # Windows binaries (don't need obfuscation, already compiled)
        'rubeus.exe', 'mimikatz.exe', 'certify.exe', 'whisker.exe',
        'sharpgpoabuse.exe', 'sharphound.exe',
        # Native Windows commands (not PowerShell)
        'net user', 'net group', 'certutil', 'certreq'
    ]

    # Check for exclusions first
    for indicator in exclude_indicators:
        if indicator in command_lower:
            return False

    # Check for PowerShell indicators
    for indicator in powershell_indicators:
        if indicator in command_lower:
            return True

    return False


def apply_obfuscation_to_attack_steps(
    attack_steps: List[Dict],
    obfuscation_level: str = "medium",
    add_amsi_bypass: bool = True
) -> List[Dict]:
    """
    Passthrough — returns attack steps unchanged.

    Command obfuscation (backtick insertion, string splitting, case randomization)
    has been disabled because it made commands non-copy-pasteable, broke tool names,
    and reduced report quality. AMSI bypass references are handled by amsi_injector.py.

    This function is kept as a passthrough to avoid breaking the call site at
    parallel_processor.py:600.
    """
    return attack_steps

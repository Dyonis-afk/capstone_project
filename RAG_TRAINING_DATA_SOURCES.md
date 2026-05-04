# RAG Training Data Sources

This document lists all resources for training the AEGIS RAG model, with **specific extraction paths** for each source.

---

## Training Philosophy

We're training a model that understands the **holistic picture of penetration testing**, not just isolated techniques:

```
Initial Access → Post-Exploitation → Privilege Escalation → Lateral Movement → Persistence → Exfiltration
       ↓                ↓                    ↓                    ↓               ↓
   Phishing        Enumeration          AD Attacks           Pivoting        Backdoors
   Exploits        Credential Dump      Kerberos Abuse       Tunneling       Golden Ticket
```

---

## Source Summary

| # | Source | What We Need | File Types | Priority |
|---|--------|--------------|------------|----------|
| 1 | Sigma | Detection rules only | `.yaml` | High |
| 2 | Splunk | Detection rules only | `.yml`, `.md` | High |
| 3 | Mimikatz Wiki | Everything | `.md` | High |
| 4 | Rubeus | Everything (wiki) | `.md` | High |
| 5 | Certify Wiki | Everything | `.md` | High |
| 6 | NetExec Wiki | Everything | `.md` | High |
| 7 | PsMapExec Wiki | Everything | `.md` | High |
| 8 | InternalAllTheThings | Specific directories | `.md` | High |
| 9 | adPEAS | README only | `.md` | Medium |
| 10 | CRTP Cheatsheet | Everything | `.md` | High |
| 11 | AD Cheatsheet (S1ckB0y1337) | Everything | `.md` | High |
| 12 | AD Cheatsheet (Integration-IT) | Everything | `.md` | High |
| 13 | Pentest-Everything | Specific sections | `.md` | High |
| 14 | Exploit Notes | Windows section | `.md` | High |
| 15 | Win-Linux-AD-Pentesting | Specific directories | `.md` | High |
| 16 | RedTeaming CheatSheet | Specific directories | `.md` | High |
| 17 | CRTE Cheatsheet | Everything | `.md` | High |
| 18 | Red-Teaming Notes | Everything | `.md` | High |

---

## Detailed Extraction Plan

### 1. Sigma Rules (Detection)
**URL:** https://github.com/SigmaHQ/sigma

**Extract:** Detection rules only
```
/rules/                            # All detection rules
```

**Training Value:** Event IDs, detection signatures, attack indicators, MITRE mappings

---

### 2. Splunk Security Content
**URL:** https://github.com/splunk/security_content

**Extract:** Detection rules only
```
/detections/                       # Detection rules
/stories/                          # Attack narratives
```

**Training Value:** SPL queries, attack stories with context, detection logic

---

### 3. Mimikatz Wiki
**URL:** https://github.com/gentilkiwi/mimikatz/wiki

**Extract:** **EVERYTHING**

**Training Value:** Mimikatz command reference, credential attack techniques, all modules

---

### 4. Rubeus
**URL:** https://github.com/GhostPack/Rubeus

**Extract:** **EVERYTHING** (wiki/documentation)

**Training Value:** Kerberos attacks, S4U abuse, ticket manipulation, roasting attacks

---

### 5. Certify Wiki
**URL:** https://github.com/GhostPack/Certify/wiki

**Extract:** **EVERYTHING**

**Training Value:** Complete ADCS attack coverage, ESC1-ESC8

---

### 6. NetExec Wiki
**URL:** https://github.com/Pennyw0rth/NetExec-Wiki

**Extract:** **EVERYTHING**

**Training Value:** Multi-protocol lateral movement, comprehensive AD tooling

---

### 7. PsMapExec Wiki
**URL:** https://github.com/The-Viper-One/PsMapExec/wiki

**Extract:** **EVERYTHING**

**Training Value:** PowerShell-native lateral movement, OPSEC-safe techniques

---

### 8. InternalAllTheThings
**URL:** https://github.com/swisskyrepo/InternalAllTheThings

**Extract:** Specific directories only
```
/docs/active-directory/            # AD attacks
/docs/pivoting/                    # Network pivoting
/docs/evasion/                     # Defense evasion
/docs/persistence/                 # Persistence mechanisms
/docs/cheatsheets/                 # Quick reference
/docs/redteam/                     # Red team operations
/docs/databases/                   # Database attacks
/docs/cloud/                       # Cloud attacks
/docs/devops/                      # DevOps/CI-CD attacks
```

**Training Value:** Comprehensive attacks, methodology, cheatsheets, cloud/devops coverage

---

### 9. adPEAS
**URL:** https://github.com/61106960/adPEAS

**Extract:** README only
```
/README.md
```

**Training Value:** AD enumeration, privilege escalation checks

---

### 10. CRTP Cheatsheet
**URL:** https://github.com/0xJs/CRTP-cheatsheet

**Extract:** **EVERYTHING**

**Training Value:** Structured AD exploitation, exam-focused techniques

---

### 11. AD Exploitation Cheatsheet (S1ckB0y1337)
**URL:** https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet

**Extract:** **EVERYTHING**

**Training Value:** End-to-end AD exploitation reference

---

### 12. AD Exploitation Cheatsheet (Integration-IT)
**URL:** https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet

**Extract:** **EVERYTHING**

**Training Value:** Categorized AD exploitation with detailed examples

---

### 13. Pentest-Everything
**URL:** https://github.com/The-Viper-One/Pentest-Everything

**Extract:** Specific sections only
```
/everything/pivoting-and-portforwarding.md
/everything/powershell/
/everything/everything-active-directory/
/psmapexec/
/resources/
/to-do-wip/work-in-progress/mimikatz.md
```

**Training Value:** AD attacks, pivoting, PowerShell techniques

---

### 14. Exploit Notes
**URL:** https://github.com/hdks-bug/exploit-notes

**Extract:** Windows section only
```
/docs/exploit/windows/             # Everything in Windows section
```

**Training Value:** Windows exploitation, AD attacks, privilege escalation

---

### 15. Win-Linux-AD-Pentesting
**URL:** https://github.com/iptracej-education/Win-Linux-AD-pentesting

**Extract:** Specific directories
```
/windows-priv/                     # Windows privilege escalation
/pivoting-network/                 # Network pivoting
/post-exploitation/                # Post-exploitation
/file-transfer/                    # File transfer techniques
/enumeration/                      # Enumeration techniques
/credential-access/                # Credential access
/active-directory/                 # AD attacks
```

**Training Value:** Educational content, holistic pentest coverage

---

### 16. RedTeaming CheatSheet
**URL:** https://github.com/0xJs/RedTeaming_CheatSheet

**Extract:** Specific directories only
```
/defense-evasion/                  # Defense evasion techniques
/infrastructure/                   # Red team infrastructure
/windows-ad/                       # Windows/AD attacks
/cloud/                            # Cloud attacks
```

**Training Value:** Red team operations, evasion, infrastructure setup, cloud attacks

---

### 17. CRTE Cheatsheet
**URL:** https://github.com/0xJs/CRTE-Cheatsheet

**Extract:** **EVERYTHING**

**Training Value:** CRTE exam techniques, advanced AD attacks, cross-forest attacks

---

### 18. Red-Teaming Notes
**URL:** https://github.com/0xn1k5/Red-Teaming

**Extract:** **EVERYTHING** (Red Team Certifications - Notes & Cheat Sheets)
```
/Red Team Certifications - Notes & Cheat Sheets/
```

**Training Value:** Comprehensive red team certification notes, structured attack methodologies

---

## Holistic Coverage Matrix

| Attack Phase | Sources Covering It |
|--------------|---------------------|
| **Reconnaissance/Enumeration** | InternalAllTheThings, NetExec, Win-Linux-AD |
| **Initial Access** | Pentest-Everything, Win-Linux-AD |
| **Credential Access** | Mimikatz, Rubeus, NetExec, Sigma/Splunk, Win-Linux-AD |
| **Privilege Escalation** | All AD cheatsheets, adPEAS, Win-Linux-AD |
| **Lateral Movement** | NetExec, PsMapExec, InternalAllTheThings |
| **Persistence** | InternalAllTheThings, Mimikatz (Golden Ticket) |
| **Defense Evasion** | CRTP, InternalAllTheThings, RedTeaming CheatSheet |
| **ADCS Attacks** | Certify Wiki, InternalAllTheThings |
| **Kerberos Attacks** | Rubeus, CRTP, CRTE, all cheatsheets |
| **Detection/SIEM** | Sigma, Splunk Security Content |
| **Post-Exploitation** | Win-Linux-AD, Pentest-Everything |
| **Pivoting/Tunneling** | Win-Linux-AD, Pentest-Everything, InternalAllTheThings |
| **File Transfer** | Win-Linux-AD |
| **Cloud Attacks** | InternalAllTheThings, RedTeaming CheatSheet |
| **Database Attacks** | InternalAllTheThings |
| **DevOps/CI-CD** | InternalAllTheThings |
| **Red Team Infrastructure** | RedTeaming CheatSheet |
| **Cross-Forest Attacks** | CRTE Cheatsheet, Red-Teaming Notes |

---

## Download Commands

```bash
# Create directory structure
mkdir -p backend/training_data/raw
cd backend/training_data/raw

# === WIKIS (full clone) ===
git clone https://github.com/gentilkiwi/mimikatz.wiki.git mimikatz-wiki
git clone https://github.com/GhostPack/Certify.wiki.git certify-wiki
git clone https://github.com/The-Viper-One/PsMapExec.wiki.git psmapexec-wiki

# === REPOS (shallow clone) ===
git clone --depth 1 https://github.com/SigmaHQ/sigma.git sigma
git clone --depth 1 https://github.com/splunk/security_content.git splunk-security
git clone --depth 1 https://github.com/GhostPack/Rubeus.git rubeus
git clone --depth 1 https://github.com/swisskyrepo/InternalAllTheThings.git internal-all-the-things
git clone --depth 1 https://github.com/Pennyw0rth/NetExec-Wiki.git netexec-wiki
git clone --depth 1 https://github.com/61106960/adPEAS.git adpeas
git clone --depth 1 https://github.com/0xJs/CRTP-cheatsheet.git crtp-cheatsheet
git clone --depth 1 https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet.git ad-cheatsheet-s1ck
git clone --depth 1 https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet.git ad-cheatsheet-integration
git clone --depth 1 https://github.com/The-Viper-One/Pentest-Everything.git pentest-everything
git clone --depth 1 https://github.com/hdks-bug/exploit-notes.git exploit-notes
git clone --depth 1 https://github.com/iptracej-education/Win-Linux-AD-pentesting.git win-linux-ad-pentesting
git clone --depth 1 https://github.com/0xJs/RedTeaming_CheatSheet.git redteaming-cheatsheet
git clone --depth 1 https://github.com/0xJs/CRTE-Cheatsheet.git crte-cheatsheet
git clone --depth 1 https://github.com/0xn1k5/Red-Teaming.git red-teaming-notes
```

---

## Progress Tracking

| Step | Status | Notes |
|------|--------|-------|
| Documentation created | ✅ | This file |
| User review complete | ✅ | Specific paths confirmed |
| New additions added | ✅ | Added 3 more sources (18 total) |
| Repos cloned | ⬜ | |
| Content extracted | ⬜ | |
| Content processed | ⬜ | |
| Added to ChromaDB | ⬜ | |
| Quality tested | ⬜ | |

---

## Notes

- **Focus:** Quality over quantity - curate relevant content only
- **Attribution:** Maintain licensing and attribution for all sources
- **Testing:** Re-run quality evaluation after training

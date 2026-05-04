"""Generates PowerShell remediation scripts for BloodHound findings via RAG."""

import re
import logging
from typing import Dict, List, Any, Optional, Callable

logger = logging.getLogger(__name__)


class RemediationService:
    """
    Service for generating remediation scripts for BloodHound findings.
    Uses RAG to generate context-aware PowerShell remediation.
    """

    def __init__(self, log_callback: Optional[Callable[[str, str], None]] = None):
        """
        Initialize the remediation service with RAG.

        Args:
            log_callback: Optional callback function for terminal logging.
                         Should accept (level: str, message: str)
        """
        import sys
        self.log_callback = log_callback
        print(f"[RemediationService.__init__] Created with log_callback={'set' if log_callback else 'None'}", file=sys.stderr)

        try:
            from services.rag_service import RAGService
            self._log("INFO", "🔧 Initializing Remediation service with RAG...")
            self.rag = RAGService()
            self._log("INFO", "✅ Remediation service initialized successfully")
        except Exception as e:
            self._log("ERROR", f"❌ Failed to initialize Remediation service: {e}")
            self.rag = None

        # Risk classification for edge types
        self.high_risk_edges = {
            'AdminTo', 'DCSync', 'GenericAll', 'WriteDacl', 'WriteOwner',
            'ForceChangePassword', 'AllowedToDelegate', 'GetChanges',
            'GetChangesAll', 'Owns', 'GenericWrite', 'AddAllowedToAct',
            'AllowedToAct', 'SQLAdmin', 'HasSPN', 'DontReqPreAuth'
        }

        self.medium_risk_edges = {
            'CanRDP', 'CanPSRemote', 'ExecuteDCOM', 'AllowedToAct',
            'AddMember', 'ReadLAPSPassword', 'ReadGMSAPassword',
            'AddSelf', 'WriteSPN', 'AddKeyCredentialLink', 'HasSession'
        }

        # Dangerous PowerShell commands to flag
        self.dangerous_commands = [
            'Remove-ADObject', 'Remove-ADUser', 'Remove-ADComputer',
            'Remove-ADGroup', 'Format-', 'Clear-', 'Delete',
            '-Force', 'Invoke-Expression', 'iex',
            'Remove-Item -Path C:', 'Remove-Item -Path /'
        ]

        self.security_control_groups = {
            "DENIED RODC PASSWORD REPLICATION GROUP",
            "ALLOWED RODC PASSWORD REPLICATION GROUP",
            "PROTECTED USERS",
            "DOMAIN PROTECTED USERS",
            "ACCOUNT OPERATORS",
            "BACKUP OPERATORS",
            "PRINT OPERATORS",
            "SERVER OPERATORS",
            "READ-ONLY DOMAIN CONTROLLERS",
            "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS",
            "CERT PUBLISHERS",
            "RAS AND IAS SERVERS",
            "EXCHANGE WINDOWS PERMISSIONS",
            "EXCHANGE TRUSTED SUBSYSTEM",
        }

        self.security_control_patterns = [
            "DENIED",
            "PROTECTED",
            "READ-ONLY",
            "READONLY",
            "AUDIT",
            "COMPLIANCE",
        ]

        self.protective_edge_types = {
            "Contains",
            "GPLink",
            "TrustedBy",
        }

        # Tools used for exploiting specific edge types
        self.edge_tools_map = {
            'GenericAll': ['PowerView', 'BloodHound', 'Mimikatz'],
            'GenericWrite': ['PowerView', 'Whisker', 'Rubeus'],
            'WriteDacl': ['PowerView', 'Impacket dacledit.py'],
            'WriteOwner': ['PowerView', 'Impacket owneredit.py'],
            'ForceChangePassword': ['PowerView', 'net.exe', 'rpcclient'],
            'DCSync': ['Mimikatz', 'Impacket secretsdump.py'],
            'GetChanges': ['Mimikatz', 'Impacket secretsdump.py'],
            'GetChangesAll': ['Mimikatz', 'Impacket secretsdump.py'],
            'AdminTo': ['PsExec', 'WMIExec', 'Evil-WinRM', 'Mimikatz'],
            'CanRDP': ['xfreerdp', 'mstsc.exe', 'rdesktop'],
            'CanPSRemote': ['PowerShell Enter-PSSession', 'Evil-WinRM'],
            'HasSession': ['Mimikatz', 'Incognito'],
            'ReadLAPSPassword': ['PowerView', 'LAPSToolkit', 'crackmapexec'],
            'ReadGMSAPassword': ['gMSADumper', 'PowerView', 'GMSAPasswordReader'],
            'AllowedToDelegate': ['Rubeus', 'Impacket getST.py'],
            'AllowedToAct': ['Rubeus', 'Impacket getST.py'],
            'HasSPN': ['Rubeus kerberoast', 'Impacket GetUserSPNs.py'],
            'AddMember': ['PowerView Add-DomainGroupMember', 'net group'],
            'Owns': ['PowerView', 'Impacket owneredit.py'],
            'AddAllowedToAct': ['Rubeus', 'PowerView'],
            'DontReqPreAuth': ['Rubeus asreproast', 'Impacket GetNPUsers.py'],
        }

    def detect_false_positive(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detect if a finding is a false positive (security control, not vulnerability).

        Args:
            finding: Dictionary with edge_type, source, target, source_type, target_type

        Returns:
            FalsePositive dict if detected, None otherwise.
        """
        source = finding.get('source', '').upper()
        target = finding.get('target', '').upper()
        edge_type = finding.get('edge_type', '')

        # Check 1: Target is a known security control group
        for control_group in self.security_control_groups:
            if control_group in target:
                return {
                    'finding': finding,
                    'reason': "Security control group membership",
                    'recommendation': f"No action needed - '{target.split('@')[0]}' is a security control group that restricts access. This is a PROTECTIVE relationship.",
                    'confidence': 0.95
                }

        # Check 2: Source is a security control group affecting other objects
        for control_group in self.security_control_groups:
            if control_group in source:
                return {
                    'finding': finding,
                    'reason': "Security group enforcement",
                    'recommendation': f"This relationship shows security control enforcement by '{source.split('@')[0]}'. This is expected behavior.",
                    'confidence': 0.90
                }

        # Check 3: Edge type is protective/structural
        if edge_type in self.protective_edge_types:
            return {
                'finding': finding,
                'reason': "Structural/protective relationship",
                'recommendation': f"'{edge_type}' is a structural AD relationship, not an attack vector. No remediation needed.",
                'confidence': 0.85
            }

        # Check 4: Target contains security control patterns
        for pattern in self.security_control_patterns:
            if pattern in target:
                return {
                    'finding': finding,
                    'reason': f"Likely security control (contains '{pattern}')",
                    'recommendation': f"Review manually - target appears to be a security control based on naming convention.",
                    'confidence': 0.70
                }

        # Check 5: MemberOf to Protected Users (defensive, not offensive)
        if edge_type == 'MemberOf' and 'PROTECTED USERS' in target:
            return {
                'finding': finding,
                'reason': "Protected Users membership (defensive control)",
                'recommendation': "This is a GOOD security practice - Protected Users membership provides credential theft protection. Do NOT remove.",
                'confidence': 0.99
            }

        return None

    def get_tools_for_edge(self, edge_type: str) -> List[str]:
        """Get common tools used for exploiting an edge type."""
        return self.edge_tools_map.get(edge_type, ['PowerView', 'BloodHound'])

    def _log(self, level: str, message: str):
        import sys

        level_upper = level.upper()
        if level_upper == "ERROR":
            logger.error(message)
        elif level_upper == "WARNING":
            logger.warning(message)
        elif level_upper == "DEBUG":
            logger.debug(message)
        else:
            logger.info(message)

        if self.log_callback:
            try:
                self.log_callback(level, message)
            except Exception as e:
                print(f"[RemediationService] Callback error: {e}", file=sys.stderr)
        else:
            print(f"[RemediationService] WARNING: log_callback is None, message lost: {message[:50]}...", file=sys.stderr)

    def set_log_callback(self, callback: Callable[[str, str], None]):
        """Set the log callback after initialization"""
        import sys
        self.log_callback = callback
        print(f"[RemediationService] set_log_callback called, callback is {'set' if callback else 'None'}", file=sys.stderr)
        # Immediately test the callback
        if callback:
            try:
                callback("INFO", "🔗 RemediationService log callback connected to TerminalLogViewer")
                print("[RemediationService] Test callback succeeded!", file=sys.stderr)
            except Exception as e:
                print(f"[RemediationService] Test callback failed: {e}", file=sys.stderr)

    def _clean_markdown_formatting(self, text: str) -> str:
        """
        Clean up stray markdown formatting characters from text.
        Removes orphaned **, *, •, and other artifacts.
        Fixes common RAG markdown generation issues.
        """
        if not text:
            return text

        # Fix incomplete bold markers - "Something:**" or "Step 1:**" should be "**Something:**"
        # Pattern: text ending with :** but no opening **
        text = re.sub(r'^([^*\n]+):\*\*\s*$', r'**\1:**', text, flags=re.MULTILINE)

        # Fix "Step N: Title**" pattern (missing opening **)
        text = re.sub(r'^(Step \d+[:\s]+[^*\n]+)\*\*\s*$', r'**\1**', text, flags=re.MULTILINE)

        # Fix "Something (details):**" pattern
        text = re.sub(r'^([^*\n]+\([^)]+\)):\*\*', r'**\1:**', text, flags=re.MULTILINE)

        # Fix trailing ** without opening (e.g., "Some text**")
        text = re.sub(r'^([^*\n]{5,})\*\*\s*$', r'\1', text, flags=re.MULTILINE)

        # Remove orphaned ** at start of lines or standalone
        text = re.sub(r'^\*\*\s*$', '', text, flags=re.MULTILINE)
        text = re.sub(r'^\*\*\s*\n', '\n', text, flags=re.MULTILINE)
        text = re.sub(r'^\*\*\s+(?![^*]+\*\*)', '', text, flags=re.MULTILINE)  # ** at line start with space but no closing

        # Replace bullet points with clean dashes
        text = re.sub(r'^[•·]\s*', '- ', text, flags=re.MULTILINE)
        text = re.sub(r'^\*\s+(?!\*)', '- ', text, flags=re.MULTILINE)

        # Clean up double asterisks that aren't wrapping text properly
        # Keep **text** but remove ** on their own
        text = re.sub(r'\*\*\s*\*\*', '', text)
        text = re.sub(r'^\*\*\s*-', '-', text, flags=re.MULTILINE)

        # Remove ** at start of line followed by colon (like "** Something:")
        text = re.sub(r'^\*\*\s*([^*]+):\s*\*\*', r'\1:', text, flags=re.MULTILINE)

        # Fix bold text that has opening ** but wrong closing
        # e.g., "**Services or applications" -> "**Services or applications**"
        text = re.sub(r'\*\*([^*\n:]+)(?::\s*)(?!\*\*)', r'**\1:** ', text)

        # Remove ** that appear at the end of lines without matching start
        # But only if there's no ** earlier in the same segment
        lines = text.split('\n')
        cleaned_lines = []
        for line in lines:
            # Count ** occurrences
            count = line.count('**')
            if count == 1 and line.rstrip().endswith('**'):
                # Single ** at end - remove it
                line = line.rstrip().rstrip('*').rstrip()
            elif count == 1 and line.lstrip().startswith('**'):
                # Single ** at start - remove it
                line = line.lstrip().lstrip('*').lstrip()
            cleaned_lines.append(line)
        text = '\n'.join(cleaned_lines)

        # Clean stray ** in the middle of text (not wrapping anything)
        text = re.sub(r'\s\*\*\s', ' ', text)  # " ** " -> " "
        text = re.sub(r'^\*\*$', '', text, flags=re.MULTILINE)  # Just ** on a line

        # Clean multiple blank lines
        text = re.sub(r'\n{3,}', '\n\n', text)

        # Remove any remaining orphaned asterisks at line starts
        text = re.sub(r'^[\*]+\s*$', '', text, flags=re.MULTILINE)

        # Final cleanup: remove lines that are just whitespace
        text = re.sub(r'^\s+$', '', text, flags=re.MULTILINE)

        return text.strip()
    
    def assess_risk(self, edge_type: str) -> str:
        """Assess the risk level of an edge type"""
        if edge_type in self.high_risk_edges:
            return "High"
        elif edge_type in self.medium_risk_edges:
            return "Medium"
        else:
            return "Low"
    
    def generate_remediation(
        self,
        edge_type: str,
        source: str,
        target: str,
        source_type: str = "User",
        target_type: str = "Computer"
    ) -> Dict[str, Any]:
        self._log("INFO", f"     🔍 Generating remediation for {edge_type}: {source} → {target}")
        """
        Generate remediation for a single finding.
        
        Args:
            edge_type: BloodHound edge type (e.g., AdminTo, DCSync)
            source: Source principal
            target: Target object
            source_type: Type of source (User, Group, Computer)
            target_type: Type of target (Computer, User, Group, Domain)
            
        Returns:
            Dictionary with remediation details
        """
        
        finding = {
            "edge_type": edge_type,
            "source": source,
            "target": target,
            "source_type": source_type,
            "target_type": target_type
        }
        
        risk_level = self.assess_risk(edge_type)
        
        # Create detailed prompt for RAG
        prompt = f"""You are a senior Active Directory security engineer and penetration tester. Generate comprehensive remediation guidance for this BloodHound finding.

CRITICAL FORMATTING RULES - YOU MUST USE MARKDOWN:
1. Use markdown syntax for all formatting
2. Use ## for section headers (e.g., ## Explanation)
3. Use ### for subsections
4. Use numbered lists (1. 2. 3.) for ordered steps
5. Use - or * for bullet points
6. Wrap ALL commands, code, and technical terms in triple backticks (```)
7. Use **bold** for emphasis on important terms
8. Use `backticks` for inline code or technical terms

FINDING DETAILS:
- **Edge Type:** {edge_type}
- **Source Principal:** {source} (Type: {source_type})
- **Target Object:** {target} (Type: {target_type})
- **Risk Level:** {risk_level}

PROVIDE THE FOLLOWING SECTIONS WITH EXACT MARKDOWN HEADERS:

## Explanation
Write 4-5 sentences explaining:
- What the **{edge_type}** relationship means in Active Directory
- Why this specific path from **{source}** to **{target}** is dangerous
- What an attacker could achieve by exploiting this (e.g., credential theft, lateral movement, domain compromise)
- **Real-world attack scenario:** How would a threat actor discover and exploit this? (mention specific tools: BloodHound, PowerView, Rubeus, Mimikatz, Impacket)

### Attack Commands
Provide example commands an attacker would use:

```powershell
# Example reconnaissance
# (provide realistic commands based on the finding)

# Example exploitation
# (provide realistic commands)
```

## Remediation Steps
Provide 5-8 numbered steps with:
1. **Specific GUI navigation paths** (e.g., "Active Directory Users and Computers > Right-click {target} > Properties > Security")
2. **Exact settings** to change
3. **Order of operations** to avoid breaking dependencies
4. **Verification step** after each change

## PowerShell Script
Generate a production-ready PowerShell script that:
- Uses the actual values: Source="{source}", Target="{target}"
- Includes proper error handling (try/catch)
- Has -WhatIf support for dry-run testing
- Includes comments explaining each step
- Uses the ActiveDirectory module cmdlets

```powershell
# Example for {edge_type}:
# For ACL issues: Use Get-Acl, Set-Acl, or Remove-ADPermission
# For group membership: Use Remove-ADGroupMember
# For delegation: Use Set-ADComputer/Set-ADUser with delegation properties
# For SPNs: Use Set-ADUser -ServicePrincipalNames

# Your script here with actual values
```

## Rollback Script
Generate a rollback script that:
- Captures current state before changes
- Can restore the original configuration
- Includes the original ACE/permission being removed

```powershell
# Rollback script here
```

## MITRE ATT&CK Mapping
List all applicable techniques with IDs and names:

- **T1078.002** - Valid Accounts: Domain Accounts
- (Add related techniques for the attack chain)
- (Add detection-relevant techniques)

## Detection Methods
Specify exact detection mechanisms:

- **Windows Event IDs** to monitor (e.g., 4662, 4738, 5136)
- **Event log sources** (Security, Directory Service, PowerShell)
- **Specific event field values** to alert on
- **SIEM query examples** if applicable
- **Signs of active exploitation**

## Warnings
List critical warnings:

- Services or applications that may break
- Required prerequisites (RSAT, admin rights, backup)
- Testing recommendations (always test in non-prod first)
- Compliance considerations
- Change management requirements

Be specific and actionable - vague guidance is not helpful.
"""
        
        # Query RAG system
        self._log("INFO", f"     📚 Querying RAG for remediation guidance...")
        response = self.rag.query(prompt)
        answer = response['result']
        self._log("INFO", f"     📝 RAG response received ({len(answer)} characters)")

        # Parse the response
        self._log("INFO", f"     🔄 Parsing remediation response...")
        parsed = self._parse_remediation_response(answer, finding, risk_level)

        # Clean up markdown formatting in text fields
        for field in ['explanation', 'rollback_script']:
            if parsed.get(field):
                parsed[field] = self._clean_markdown_formatting(parsed[field])

        # Clean remediation steps
        if parsed.get('remediation_steps'):
            parsed['remediation_steps'] = [
                self._clean_markdown_formatting(step) for step in parsed['remediation_steps']
            ]

        # Clean warnings
        if parsed.get('warnings'):
            parsed['warnings'] = [
                self._clean_markdown_formatting(w) for w in parsed['warnings']
            ]

        self._log("INFO", f"     ✅ Parsed: {len(parsed.get('remediation_steps', []))} steps, {len(parsed.get('powershell_script', ''))} char script")

        # Validate the PowerShell script if present
        if parsed.get('powershell_script'):
            validation = self.validate_script(parsed['powershell_script'])
            parsed['script_validation'] = validation

            # Add warnings for dangerous commands
            if validation['dangerous_commands']:
                self._log("WARNING", f"     ⚠️ Script contains {len(validation['dangerous_commands'])} dangerous commands")
                parsed['warnings'].extend([
                    f"Script contains potentially dangerous command: {cmd}"
                    for cmd in validation['dangerous_commands']
                ])

        # Add sources
        parsed['sources'] = [
            doc.metadata.get('source', 'Unknown')
            for doc in response.get('source_documents', [])
        ]

        return parsed
    
    def _parse_remediation_response(
        self,
        answer: str,
        finding: dict,
        risk_level: str
    ) -> Dict[str, Any]:
        """
        Parse RAG response into structured format.
        
        Args:
            answer: RAG response text
            finding: Original finding dictionary
            risk_level: Risk level assessment
            
        Returns:
            Parsed remediation dictionary
        """
        
        result = {
            "finding": finding,
            "risk_level": risk_level,
            "explanation": "",
            "remediation_steps": [],
            "powershell_script": "",
            "rollback_script": "",
            "mitre_mapping": [],
            "detection_methods": [],
            "warnings": []
        }
        
        # Extract explanation - now in markdown format, just extract the explanation section
        # Look for markdown headers (## Explanation or ## Technical Analysis)
        explanation_match = re.search(
            r'##\s+(?:Explanation|Technical Analysis|EXPLANATION|TECHNICAL ANALYSIS)[:\s]*(.+?)(?=\n##|\n###|$)',
            answer,
            re.IGNORECASE | re.DOTALL
        )
        
        if explanation_match:
            # Get the explanation content
            explanation_content = explanation_match.group(1).strip()
            
            # Also try to get Attack Scenario and Impact if they exist
            attack_match = re.search(
                r'##\s+(?:Attack Scenario|ATTACK SCENARIO)[:\s]*(.+?)(?=\n##|\n###|$)',
                answer,
                re.IGNORECASE | re.DOTALL
            )
            
            impact_match = re.search(
                r'##\s+(?:Impact|IMPACT)[:\s]*(.+?)(?=\n##|\n###|$)',
                answer,
                re.IGNORECASE | re.DOTALL
            )
            
            # Combine all sections
            result['explanation'] = explanation_content
            if attack_match:
                result['explanation'] += "\n\n## Attack Scenario\n\n" + attack_match.group(1).strip()
            if impact_match:
                result['explanation'] += "\n\n## Impact\n\n" + impact_match.group(1).strip()
        else:
            # Fallback: use everything up to the first ## Remediation or ## PowerShell
            fallback_match = re.search(
                r'(.+?)(?=\n##\s+(?:Remediation|PowerShell|REMEDIATION|POWERSHELL))',
                answer,
                re.IGNORECASE | re.DOTALL
            )
            if fallback_match:
                result['explanation'] = fallback_match.group(1).strip()
            else:
                # Last fallback: use first 1000 chars
                result['explanation'] = answer[:1000]
        
        # Extract remediation steps
        steps_match = re.search(
            r'(?:REMEDIATION STEPS|remediation steps|steps)[:\s]*(.+?)(?=\n\n[A-Z]|\nPOWERSHELL|\n```)',
            answer,
            re.IGNORECASE | re.DOTALL
        )
        if steps_match:
            steps_text = steps_match.group(1)
            steps = re.findall(r'\d+\.\s*(.+?)(?=\n\d+\.|\n\n|$)', steps_text, re.DOTALL)
            result['remediation_steps'] = [s.strip() for s in steps if s.strip()]
        
        # Extract PowerShell script - now in markdown code blocks
        ps_patterns = [
            r'##\s+PowerShell Script[:\s]*\n```powershell\s*(.+?)```',  # Markdown code block with header
            r'##\s+PowerShell Script[:\s]*\n```\s*(.+?)```',  # Markdown code block without language
            r'```powershell\s*(.+?)```',  # Any PowerShell code block
            r'```\s*(.+?)```',  # Any code block (fallback)
        ]
        
        for pattern in ps_patterns:
            ps_match = re.search(pattern, answer, re.IGNORECASE | re.DOTALL)
            if ps_match:
                script = ps_match.group(1).strip()
                # Clean up - remove leading dashes, bullets
                script = re.sub(r'^[-•*]\s*', '', script, flags=re.MULTILINE)
                if script and len(script) > 20:  # Only use if substantial content
                    result['powershell_script'] = script
                    break
        
        # Extract rollback script - now in markdown code blocks
        rollback_patterns = [
            r'##\s+Rollback Script[:\s]*\n```powershell\s*(.+?)```',
            r'##\s+Rollback Script[:\s]*\n```\s*(.+?)```',
            r'```powershell\s*(.+?)```',  # Any PowerShell code block after rollback mention
        ]
        
        for pattern in rollback_patterns:
            rollback_match = re.search(pattern, answer, re.IGNORECASE | re.DOTALL)
            if rollback_match:
                result['rollback_script'] = rollback_match.group(1).strip()
                break
        
        # Extract MITRE mapping
        mitre_match = re.search(
            r'(?:MITRE|mitre)[:\s]*(.+?)(?=\n\n[A-Z]|\nDETECTION|\nWARNING|$)',
            answer,
            re.IGNORECASE | re.DOTALL
        )
        if mitre_match:
            mitre_text = mitre_match.group(1)
            # Extract T-codes (e.g., T1078, T1078.003)
            techniques = re.findall(r'T\d{4}(?:\.\d{3})?', mitre_text)
            result['mitre_mapping'] = list(set(techniques))
        
        # Extract detection methods
        detection_match = re.search(
            r'(?:DETECTION|detection)[:\s]*(.+?)(?=\n\n[A-Z]|\nWARNING|$)',
            answer,
            re.IGNORECASE | re.DOTALL
        )
        if detection_match:
            detection_text = detection_match.group(1)
            # Extract Event IDs
            event_ids = re.findall(r'Event\s*(?:ID)?\s*(\d{4})', detection_text, re.IGNORECASE)
            result['detection_methods'] = [f"Event ID {eid}" for eid in event_ids]
            
            # If no Event IDs found, use the text itself
            if not result['detection_methods']:
                result['detection_methods'] = [detection_text.strip()[:200]]
        
        # Extract warnings
        warnings_match = re.search(
            r'(?:WARNINGS|warnings)[:\s]*(.+?)(?=\n\n[A-Z]|$)',
            answer,
            re.IGNORECASE | re.DOTALL
        )
        if warnings_match:
            warnings_text = warnings_match.group(1)
            # Split by newlines or bullet points
            warning_items = re.split(r'\n[-•*]|\n\d+\.', warnings_text)
            result['warnings'] = [w.strip() for w in warning_items if w.strip()]
        
        # Add default warnings for high-risk items
        if risk_level == "High" and not result['warnings']:
            result['warnings'] = [
                "This is a high-risk remediation. Test in non-production environment first.",
                "Ensure you have a rollback plan before executing."
            ]
        
        return result
    
    def validate_script(self, script: str) -> Dict[str, Any]:
        """
        Validate a PowerShell script for safety.
        
        Args:
            script: PowerShell script to validate
            
        Returns:
            Validation results dictionary
        """
        
        result = {
            "is_valid": True,
            "is_safe": True,
            "dangerous_commands": [],
            "warnings": [],
            "suggestions": []
        }
        
        script_upper = script.upper()
        
        # Check for dangerous commands
        for cmd in self.dangerous_commands:
            if cmd.upper() in script_upper:
                result['dangerous_commands'].append(cmd)
                result['is_safe'] = False
        
        # Check for other risky patterns
        if '-Confirm:$false' in script:
            result['warnings'].append("Script bypasses confirmation prompts")
        
        if '-ErrorAction SilentlyContinue' in script:
            result['warnings'].append("Script silently continues on errors")
        
        if 'Invoke-Expression' in script or 'iex ' in script.lower():
            result['warnings'].append("Script uses Invoke-Expression which can be dangerous")
            result['is_safe'] = False
        
        # Suggestions for improvement
        if '-WhatIf' not in script:
            result['suggestions'].append("Consider adding -WhatIf parameter for dry run testing")
        
        if 'try' not in script.lower() and 'catch' not in script.lower():
            result['suggestions'].append("Consider adding try/catch error handling")
        
        if '-Confirm' not in script and result['dangerous_commands']:
            result['suggestions'].append("Consider adding -Confirm parameter for safety")
        
        return result
    
    def generate_batch_remediation(
        self,
        findings: List[Dict[str, Any]],
        priority: str = "high_first"
    ) -> Dict[str, Any]:
        """
        Generate remediation for multiple findings.
        
        Args:
            findings: List of finding dictionaries
            priority: Priority order (high_first, low_first, as_provided)
            
        Returns:
            Batch remediation results
        """
        self._log("INFO", f"📦 Starting batch remediation for {len(findings)} findings (priority: {priority})")
        
        # Sort findings by priority if requested
        if priority == "high_first":
            findings = sorted(
                findings,
                key=lambda f: (
                    0 if self.assess_risk(f['edge_type']) == "High"
                    else 1 if self.assess_risk(f['edge_type']) == "Medium"
                    else 2
                )
            )
        elif priority == "low_first":
            findings = sorted(
                findings,
                key=lambda f: (
                    2 if self.assess_risk(f['edge_type']) == "High"
                    else 1 if self.assess_risk(f['edge_type']) == "Medium"
                    else 0
                )
            )
        # else: as_provided - no sorting
        
        results = {
            "total": len(findings),
            "successful": 0,
            "failed": 0,
            "remediations": []
        }
        
        for idx, finding in enumerate(findings, 1):
            try:
                self._log("INFO", f"  📝 Generating {idx}/{len(findings)}: {finding['edge_type']} - {finding['source']} → {finding['target']}")
                remediation = self.generate_remediation(
                    edge_type=finding['edge_type'],
                    source=finding['source'],
                    target=finding['target'],
                    source_type=finding.get('source_type', 'User'),
                    target_type=finding.get('target_type', 'Computer')
                )
                results['remediations'].append(remediation)
                results['successful'] += 1
            except Exception as e:
                self._log("ERROR", f"  ❌ Failed {idx}/{len(findings)}: {e}")
                results['failed'] += 1
                results['remediations'].append({
                    "finding": finding,
                    "error": str(e)
                })

        self._log("INFO", f"✅ Batch complete: {results['successful']}/{results['total']} successful")
        return results
    
    def get_quick_remediation(self, edge_type: str) -> Dict[str, str]:
        """
        Get quick remediation template for an edge type.

        Args:
            edge_type: BloodHound edge type

        Returns:
            Quick remediation information
        """

        prompt = f"""You are an experienced AD security expert and penetration tester. Provide comprehensive remediation guidance for the BloodHound edge type "{edge_type}".

CRITICAL FORMATTING RULES:
1. Write in plain text only - NO markdown (no **, *, #, ```, etc.)
2. Use the exact UPPERCASE headers shown below followed by colon
3. Be thorough and detailed in your explanations

FORMAT YOUR RESPONSE WITH THESE SECTIONS:

DESCRIPTION:
Explain what {edge_type} means in Active Directory terms. What permission or access does the source principal have over the target object? What capabilities does this grant?

ATTACK VECTOR:
Provide a detailed explanation of how an attacker would exploit this relationship. Include:
- The reconnaissance steps to discover this path
- Specific tools that would be used (PowerView, Rubeus, Mimikatz, Impacket, BloodHound)
- The exact commands or techniques an attacker would execute
- What access or privileges they gain after exploitation
- How this could chain into further attacks

REMEDIATION:
Provide comprehensive remediation guidance including:
- The primary fix to address this vulnerability
- Step-by-step instructions for implementing the fix
- GUI-based approach (Active Directory Users and Computers, etc.)
- Any prerequisites or dependencies to consider
- How to verify the remediation was successful

POWERSHELL:
Provide a production-ready PowerShell script or commands to remediate this issue. Use placeholders $Source and $Target for the principal names. Include error handling and comments.

RISK:
State the risk level (High/Medium/Low) and provide detailed justification explaining the potential business impact, likelihood of exploitation, and why this risk rating is appropriate.

Now provide this comprehensive guidance for "{edge_type}":
"""
        
        response = self.rag.query(prompt)
        
        return {
            "edge_type": edge_type,
            "risk_level": self.assess_risk(edge_type),
            "quick_info": response['result'],
            "sources": [
                doc.metadata.get('source', 'Unknown')
                for doc in response.get('source_documents', [])
            ]
        }
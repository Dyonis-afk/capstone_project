import type { Finding, AnalysisSummary, SecurityReport, DetailedRemediation } from '@/types';
import apiService from './api';

/**
 * Report Service - COMPREHENSIVE REPORT GENERATION
 * Generates complete reports with all content included upfront
 */
class ReportService {
    /**
     * Generate a comprehensive report with ALL content included
     */
    async generateReport(
        summary: AnalysisSummary,
        allFindings: Finding[]
    ): Promise<SecurityReport> {
        const reportId = `AEGIS-${Date.now()}`;

        console.log('🔄 Generating comprehensive security report...');
        console.log('📊 Step 1/5: Executive summary...');
        const executiveSummary = await this.generateExecutiveSummary(summary, allFindings);

        console.log('📊 Step 2/5: Analyzing critical findings...');
        await this.generateFindingAnalysisForReport(allFindings);

        console.log('📊 Step 3/5: Attack path analysis...');
        await this.generateAttackPathAnalysis(allFindings);

        console.log('📊 Step 4/5: Remediation guidance...');
        const remediations = await this.generateDetailedRemediations(allFindings);

        console.log('📊 Step 5/5: Strategic recommendations...');
        const recommendations = await this.generateStrategicRecommendations(summary, allFindings);

        // Calculate findings by type
        const findingsByType: Record<string, number> = {};
        for (const finding of allFindings) {
            findingsByType[finding.edgeType] = (findingsByType[finding.edgeType] || 0) + 1;
        }

        console.log('✅ Report generation complete!');

        return {
            reportId,
            generatedAt: new Date(),
            executiveSummary,
            summary,
            findings: allFindings, // Now includes explanations
            recommendations,
            overallRiskAssessment: this.assessOverallRisk(summary),
            findingsByType,
            detailedRemediations: remediations
        };
    }




    /**
     * Generate executive summary for business leadership
     */
    private async generateExecutiveSummary(
        summary: AnalysisSummary,
        findings: Finding[]
    ): Promise<string> {
        const topFindings = findings.filter(f => f.riskLevel === 'High').slice(0, 5);
        const criticalTargets = [...new Set(topFindings.map(f => f.target))];
        const attackVectors = [...new Set(topFindings.map(f => f.edgeType))];

        const prompt = `
You are writing an executive summary for a BloodHound security assessment based on these actual findings.

CRITICAL FINDINGS DISCOVERED:
${topFindings.map(f => `- ${f.source} has ${f.edgeType} permission on ${f.target}`).join('\n')}

ASSESSMENT STATISTICS:
- Total AD objects analyzed: ${summary.totalNodes}
- Total relationships mapped: ${summary.totalEdges}
- Critical/High risk findings: ${summary.highRiskCount}
- Medium risk findings: ${summary.mediumRiskCount}
- Low risk findings: ${summary.lowRiskCount}
- Key attack vectors found: ${attackVectors.join(', ')}
- Critical targets at risk: ${criticalTargets.slice(0, 5).join(', ')}

Write a 5-paragraph executive summary covering:
1. Overall security posture and risk level
2. Most dangerous attack paths found
3. Realistic exploitation scenarios
4. Business impact and compliance risks
5. Immediate action priorities

Be specific to these actual findings, not generic advice.
`;

        try {
            const response = await apiService.queryRAG(prompt);
            return response.answer || this.getDefaultExecutiveSummary(summary);
        } catch (error) {
            console.error('❌ Executive summary generation failed:', error);
            return this.getDefaultExecutiveSummary(summary);
        }
    }

    /**
     * Generate explanations for top findings (modifies findings in-place)
     */
    private async generateFindingAnalysisForReport(findings: Finding[]): Promise<void> {
        const criticalFindings = findings.filter(f => f.riskLevel === 'High').slice(0, 10);

        for (let i = 0; i < criticalFindings.length; i++) {
            const finding = criticalFindings[i];

            if (finding.explanation && finding.explanation.length > 0) {
                continue; // Skip if already has explanation
            }

            console.log(`   Analyzing finding ${i + 1}/${criticalFindings.length}: ${finding.edgeType}`);

            try {
                const explanation = await this.generateFindingAnalysis(finding);
                finding.explanation = explanation;
            } catch (error) {
                console.log(`   ❌ Failed to analyze ${finding.edgeType}:`, error);
                finding.explanation = this.getDefaultExplanation(finding);
            }
        }
    }

    /**
     * Generate comprehensive analysis for a single finding using RAG
     */
    async generateFindingAnalysis(finding: Finding): Promise<string> {
        const prompt = `
Analyze this Active Directory security finding and provide comprehensive analysis:

FINDING DETAILS:
- Edge Type: ${finding.edgeType}
- Source: ${finding.source} (${finding.sourceType})
- Target: ${finding.target} (${finding.targetType})
- Risk Level: ${finding.riskLevel}

Provide a complete analysis covering technical explanation, attack scenario, business impact, and MITRE ATT&CK mapping for this specific finding.
`;

        try {
            const response = await apiService.queryRAG(prompt);
            return response.answer || this.getDefaultExplanation(finding);
        } catch (error) {
            throw new Error(`Finding analysis failed: ${error}`);
        }
    }

    /**
     * Generate attack path analysis using RAG
     */
    async generateAttackPathAnalysis(findings: Finding[]): Promise<string> {
        const highRiskFindings = findings.filter(f => f.riskLevel === 'High').slice(0, 8);

        const prompt = `
Analyze these attack paths and provide comprehensive exploitation guidance:

HIGH RISK ATTACK PATHS:
${highRiskFindings.map(f => `${f.source} --[${f.edgeType}]--> ${f.target}`).join('\n')}

Provide detailed analysis including:
1. How these paths chain together for domain compromise
2. Specific exploitation commands and tools
3. Detection opportunities
4. Simulation testing guidance

Focus on these actual findings, not generic examples.
`;

        try {
            const response = await apiService.queryRAG(prompt);
            return response.answer || 'Attack path analysis generation failed.';
        } catch (error) {
            throw new Error(`Attack path analysis failed: ${error}`);
        }
    }

    /**
     * Generate detailed remediations for top findings
     */
    private async generateDetailedRemediations(findings: Finding[]): Promise<DetailedRemediation[]> {
        const remediations: DetailedRemediation[] = [];
        const highRiskFindings = findings.filter(f => f.riskLevel === 'High').slice(0, 5);

        for (let i = 0; i < highRiskFindings.length; i++) {
            const finding = highRiskFindings[i];
            console.log(`   Generating remediation ${i + 1}/${highRiskFindings.length}: ${finding.edgeType}`);

            try {
                // Use backend remediation API which has proper parsing
                const remediation = await apiService.generateRemediation(finding);
                remediations.push(remediation);
            } catch (error) {
                console.log(`   ❌ Remediation failed for ${finding.edgeType}:`, error);
                // Add fallback remediation
                remediations.push(this.getDefaultRemediation(finding));
            }
        }

        return remediations;
    }

    /**
     * Generate remediation guidance using RAG
     */
    async generateRemediationGuidance(finding: Finding): Promise<string> {
        const prompt = `
Generate comprehensive remediation guidance for this specific finding:

FINDING TO REMEDIATE:
- Edge Type: ${finding.edgeType}
- Source: ${finding.source} (${finding.sourceType})
- Target: ${finding.target} (${finding.targetType})

Provide complete remediation guidance including detailed steps, PowerShell commands, verification procedures, and rollback instructions for this specific relationship.
`;

        try {
            const response = await apiService.queryRAG(prompt);
            return response.answer || 'Remediation guidance generation failed.';
        } catch (error) {
            throw new Error(`Remediation guidance failed: ${error}`);
        }
    }

    /**
     * Generate strategic security recommendations
     */
    private async generateStrategicRecommendations(
        summary: AnalysisSummary,
        findings: Finding[]
    ): Promise<string[]> {
        const uniqueEdgeTypes = [...new Set(findings.map(f => f.edgeType))];
        const highRiskEdges = [...new Set(findings.filter(f => f.riskLevel === 'High').map(f => f.edgeType))];

        const prompt = `
Generate strategic security recommendations based on this Active Directory assessment:

VULNERABILITY SUMMARY:
- Critical/High risk findings: ${summary.highRiskCount}
- Medium risk findings: ${summary.mediumRiskCount}
- Low risk findings: ${summary.lowRiskCount}
- Attack vectors discovered: ${uniqueEdgeTypes.join(', ')}
- Most dangerous edge types: ${highRiskEdges.join(', ')}

SAMPLE HIGH-RISK FINDINGS:
${findings.filter(f => f.riskLevel === 'High').slice(0, 5).map(f => `- ${f.source} has ${f.edgeType} on ${f.target}`).join('\n')}

Provide 6-8 strategic recommendations in format:
[PRIORITY] CATEGORY: Action needed. Explanation based on findings. Business impact.

Base recommendations on actual findings, not generic advice.
`;

        try {
            const response = await apiService.queryRAG(prompt);
            return this.parseRecommendations(response.answer || '', summary);
        } catch (error) {
            console.error('❌ Recommendations generation failed:', error);
            return this.getDefaultRecommendations(summary);
        }
    }

    /**
     * Assess overall risk level based on findings
     */
    private assessOverallRisk(summary: AnalysisSummary): string {
        if (summary.highRiskCount > 20) {
            return 'CRITICAL - Immediate action required. The environment has extensive privilege escalation paths and critical vulnerabilities.';
        } else if (summary.highRiskCount > 10) {
            return 'HIGH - Urgent remediation needed. Multiple critical security issues present significant risk.';
        } else if (summary.highRiskCount > 5) {
            return 'HIGH - Several critical findings require prompt attention to reduce attack surface.';
        } else if (summary.mediumRiskCount > 30) {
            return 'MEDIUM - While no critical issues, numerous medium-risk findings create cumulative risk.';
        } else if (summary.mediumRiskCount > 15) {
            return 'MEDIUM - Moderate security concerns present. Systematic remediation recommended.';
        } else {
            return 'LOW - Security posture is relatively strong. Continue monitoring and maintaining current controls.';
        }
    }

    // Parsing helper methods
    private parseRecommendations(responseText: string, summary: AnalysisSummary): string[] {
        const recommendations: string[] = [];
        const lines = responseText.split('\n');

        let currentRecommendation = '';
        for (const line of lines) {
            const trimmedLine = line.trim();
            if (!trimmedLine) continue;

            if (/^\[(CRITICAL|HIGH|MEDIUM|LOW)\]/.test(trimmedLine)) {
                if (currentRecommendation) {
                    recommendations.push(currentRecommendation.trim());
                }
                currentRecommendation = trimmedLine;
            } else {
                currentRecommendation += ' ' + trimmedLine;
            }
        }

        if (currentRecommendation) {
            recommendations.push(currentRecommendation.trim());
        }

        return recommendations.length > 0 ? recommendations : this.getDefaultRecommendations(summary);
    }




    // Default fallbacks
    private getDefaultExecutiveSummary(summary: AnalysisSummary): string {
        return `This Active Directory environment presents a ${summary.overallRisk.toLowerCase()} risk profile based on comprehensive BloodHound analysis. The assessment identified ${summary.totalFindings} security findings across ${summary.totalNodes} AD objects and ${summary.totalEdges} relationships, with ${summary.highRiskCount} critical issues requiring immediate attention.

The analysis reveals potential privilege escalation paths and excessive permissions that could be exploited by malicious actors to gain unauthorized access to sensitive systems and data. These vulnerabilities represent significant risk to the organization's security posture and require prompt remediation.

Key attack vectors include misconfigured permissions, service accounts with excessive privileges, and trust relationships that create unintended privilege escalation paths. These issues collectively create opportunities for attackers to move laterally through the environment and potentially achieve domain compromise.

The business impact includes potential for complete domain takeover, data exfiltration, ransomware deployment, and prolonged undetected access to critical systems. Regulatory compliance implications may also arise from inadequate access controls and privilege management.

Immediate priorities include reviewing and removing unnecessary administrative permissions, implementing least privilege principles, and enhancing monitoring for privilege escalation attempts. A systematic approach to addressing these findings will significantly improve the security posture.`;
    }

    private getDefaultExplanation(finding: Finding): string {
        const explanations: Record<string, string> = {
            'GenericAll': `Full control over ${finding.target}. ${finding.source} can modify any attribute, reset passwords, or grant additional permissions.`,
            'WriteDacl': `Can modify the access control list of ${finding.target}. ${finding.source} can grant themselves additional permissions.`,
            'WriteOwner': `Can change ownership of ${finding.target}. After taking ownership, can modify permissions.`,
            'DCSync': `${finding.source} can perform DCSync attack to extract password hashes from the domain.`,
            'AdminTo': `Local administrator access to ${finding.target}. Can execute commands and extract credentials.`,
            'MemberOf': `Member of ${finding.target}. Inherits all permissions granted to the group.`
        };

        return explanations[finding.edgeType] ||
            `The ${finding.edgeType} relationship from ${finding.source} to ${finding.target} represents a potential security risk requiring review.`;
    }

    private getDefaultRemediation(finding: Finding): DetailedRemediation {
        return {
            edgeType: finding.edgeType,
            source: finding.source,
            target: finding.target,
            riskLevel: finding.riskLevel,
            explanation: `Default remediation guidance for ${finding.edgeType}`,
            remediationSteps: [
                `Review permissions for ${finding.source}`,
                'Apply least privilege principles',
                'Test changes in non-production environment',
                'Monitor for impact after implementation'
            ],
            powershellScript: this.getDefaultRemediationScript(finding),
            mitreMapping: [],
            detectionMethods: [],
            warnings: [
                'Test changes in non-production environment first',
                'Ensure proper backup and rollback procedures',
                'Monitor for service disruptions after implementation'
            ]
        };
    }

    private getDefaultRemediationScript(finding: Finding): string {
        switch (finding.edgeType) {
            case 'GenericAll':
            case 'WriteDacl':
            case 'WriteOwner':
                return `# Remove excessive permissions for ${finding.source} on ${finding.target}
# WARNING: Test in non-production first

try {
    $principal = "${finding.source}"
    $target = "${finding.target}"
    
    # Get current ACL
    $acl = Get-Acl $target -ErrorAction Stop
    
    # Review and remove unnecessary permissions
    # Note: Specific implementation depends on object type
    Write-Host "Current permissions for $principal on $target:"
    $acl.Access | Where-Object { $_.IdentityReference -like "*$principal*" }
    
    # Uncomment to remove (after testing):
    # $acl.RemoveAccessRule($accessRule)
    # Set-Acl $target $acl
    
    Write-Host "Review complete. Uncomment removal commands after verification."
} catch {
    Write-Error "Failed to process ACL: $($_.Exception.Message)"
}`;

            case 'MemberOf':
                return `# Remove ${finding.source} from ${finding.target}
# WARNING: Test in non-production first

try {
    $member = "${finding.source}"
    $group = "${finding.target}"
    
    # Verify membership
    $membership = Get-ADGroupMember -Identity $group | Where-Object { $_.Name -eq $member }
    if ($membership) {
        Write-Host "Confirmed: $member is member of $group"
        # Remove from group
        Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
        Write-Host "Successfully removed $member from $group"
    } else {
        Write-Host "Member not found in group"
    }
} catch {
    Write-Error "Failed to modify group membership: $($_.Exception.Message)"
}`;

            default:
                return `# Review and remediate ${finding.edgeType} relationship
# Source: ${finding.source}
# Target: ${finding.target}

# Implement least privilege principles
# Test changes in non-production environment
# Document changes for audit purposes`;
        }
    }

    private getDefaultRecommendations(_summary: AnalysisSummary): string[] {
        return [
            '[CRITICAL] Privilege Management: Review and remove excessive administrative permissions identified in findings.',
            '[HIGH] Access Control: Implement least privilege principles for all accounts.',
            '[MEDIUM] Monitoring: Deploy enhanced logging for privilege escalation attempts.',
            '[MEDIUM] Authentication: Implement multi-factor authentication for administrative accounts.'
        ];
    }

}

// Export singleton instance
export const reportService = new ReportService();
export default reportService;
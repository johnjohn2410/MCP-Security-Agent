import crypto from 'crypto';
import { VEXDocument, Finding, VulnerabilityType } from '../types/index.js';
import { Logger } from './Logger.js';

export class VEXGenerator {
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  /**
   * Create a VEX document for a finding
   */
  private createVEXDocument(
    finding: Finding,
    author: string,
    justification: string
  ): VEXDocument {
    return {
      id: `vex-${finding.id}`,
      timestamp: new Date().toISOString(),
      author,
      status: 'not_affected',
      description: `VEX for ${finding.title} in ${finding.file}`,
      affected: [{
        component: finding.file,
        vulnerability: finding.stableId,
        justification: this.generateJustification(finding, justification),
        impact: finding.impact
      }],
      references: finding.references
    };
  }

  /**
   * Assess impact of a finding
   */
  private assessImpact(finding: Finding): 'low' | 'medium' | 'high' | 'critical' {
    if (finding.impact === 'low') {
      return 'low';
    } else if (finding.impact === 'medium') {
      return 'medium';
    } else if (finding.impact === 'high') {
      return 'high';
    } else if (finding.impact === 'critical') {
      return 'critical';
    }
    return 'low'; // Default to low if impact is not explicitly set
  }

  /**
   * Generate VEX document for findings that are not exploitable
   */
  generateVEX(
    findings: Finding[],
    author: string,
    justification: string
  ): VEXDocument[] {
    const vexDocuments: VEXDocument[] = [];
    const nonExploitableFindings = findings.filter(finding => 
      finding.status === 'false_positive' || 
      finding.exploitability === 'low' ||
      finding.impact === 'low'
    );

    for (const finding of nonExploitableFindings) {
      const vex: VEXDocument = {
        id: `vex-${crypto.randomUUID()}`,
        timestamp: new Date().toISOString(),
        author,
        status: this.determineVEXStatus(finding),
        description: `VEX for ${finding.title} in ${finding.file}`,
        affected: [{
          component: finding.file,
          vulnerability: finding.stableId,
          justification: this.generateJustification(finding, justification),
          impact: finding.impact
        }],
        references: this.generateReferences(finding)
      };

      vexDocuments.push(vex);
    }

    this.logger.info('VEX documents generated', {
      totalFindings: findings.length,
      nonExploitableFindings: nonExploitableFindings.length,
      vexDocumentsGenerated: vexDocuments.length
    });

    return vexDocuments;
  }

  /**
   * Determine VEX status based on finding
   */
  private determineVEXStatus(finding: Finding): 'not_affected' | 'affected' | 'fixed' | 'under_investigation' {
    if (finding.status === 'false_positive') {
      return 'not_affected';
    } else if (finding.exploitability === 'low' && finding.impact === 'low') {
      return 'not_affected';
    } else if (finding.status === 'fixed') {
      return 'fixed';
    } else {
      return 'under_investigation';
    }
  }

  /**
   * Generate justification for VEX
   */
  private generateJustification(finding: Finding, baseJustification: string): string {
    const justifications: string[] = [];

    if (finding.status === 'false_positive') {
      justifications.push('False positive - vulnerability not actually present');
    }

    if (finding.exploitability === 'low') {
      justifications.push('Low exploitability - requires specific conditions to exploit');
    }

    if (finding.impact === 'low') {
      justifications.push('Low impact - minimal security risk if exploited');
    }

    // Add context-specific justifications
    switch (finding.type) {
      case VulnerabilityType.SQL_INJECTION:
        justifications.push('Input validation prevents exploitation');
        break;
      case VulnerabilityType.XSS:
        justifications.push('Content Security Policy mitigates risk');
        break;
      case VulnerabilityType.HARDCODED_SECRET:
        justifications.push('Secret is in test environment only');
        break;
      case VulnerabilityType.WEAK_CRYPTO:
        justifications.push('Legacy system with compensating controls');
        break;
      case VulnerabilityType.INSECURE_DESERIALIZATION:
        justifications.push('Input validation prevents malicious payloads');
        break;
      case VulnerabilityType.PATH_TRAVERSAL:
        justifications.push('Path validation prevents directory traversal');
        break;
      case VulnerabilityType.INSECURE_DEPENDENCY:
        justifications.push('Vulnerable dependency is not used in production');
        break;
      case VulnerabilityType.CONFIGURATION_ISSUE:
        justifications.push('Configuration is appropriate for this environment');
        break;
      case VulnerabilityType.INPUT_VALIDATION:
        justifications.push('Additional validation layers exist');
        break;
    }

    return `${baseJustification}. ${justifications.join('. ')}`;
  }

  /**
   * Generate references for VEX
   */
  private generateReferences(finding: Finding): Array<{type: string, url: string}> {
    const references: Array<{type: string, url: string}> = [];

    // Add CWE references
    if (finding.cwe) {
      finding.cwe.forEach(cwe => {
        references.push({
          type: 'CWE',
          url: `https://cwe.mitre.org/data/definitions/${cwe}.html`
        });
      });
    }

    // Add OWASP references
    if (finding.owasp) {
      finding.owasp.forEach(owasp => {
        references.push({
          type: 'OWASP',
          url: `https://owasp.org/www-project-top-ten/${owasp}`
        });
      });
    }

    // Add NIST references
    if (finding.nist) {
      finding.nist.forEach(nist => {
        references.push({
          type: 'NIST',
          url: `https://nvd.nist.gov/vuln/detail/${nist}`
        });
      });
    }

    // Add finding-specific references
    if (finding.references) {
      references.push(...finding.references);
    }

    return references;
  }

  /**
   * Generate VEX for dependency vulnerabilities
   */
  generateDependencyVEX(
    componentName: string,
    componentVersion: string,
    vulnerabilityId: string,
    author: string,
    justification: string
  ): VEXDocument {
    const vex: VEXDocument = {
      id: `vex-dep-${crypto.randomUUID()}`,
      timestamp: new Date().toISOString(),
      author,
      status: 'not_affected',
      description: `VEX for dependency vulnerability ${vulnerabilityId} in ${componentName}@${componentVersion}`,
      affected: [{
        component: `${componentName}@${componentVersion}`,
        vulnerability: vulnerabilityId,
        justification,
        impact: 'low'
      }],
      references: [{
        type: 'CVE',
        url: `https://nvd.nist.gov/vuln/detail/${vulnerabilityId}`
      }]
    };

    this.logger.info('Dependency VEX generated', {
      componentName,
      componentVersion,
      vulnerabilityId
    });

    return vex;
  }

  /**
   * Generate VEX for configuration issues
   */
  generateConfigurationVEX(
    configFile: string,
    configKey: string,
    author: string,
    justification: string
  ): VEXDocument {
    const vex: VEXDocument = {
      id: `vex-config-${crypto.randomUUID()}`,
      timestamp: new Date().toISOString(),
      author,
      status: 'not_affected',
      description: `VEX for configuration issue in ${configFile}`,
      affected: [{
        component: configFile,
        vulnerability: `config-${configKey}`,
        justification,
        impact: 'low'
      }],
      references: [{
        type: 'CONFIG',
        url: `file://${configFile}`
      }]
    };

    this.logger.info('Configuration VEX generated', {
      configFile,
      configKey
    });

    return vex;
  }

  /**
   * Validate VEX document
   */
  validateVEX(vex: VEXDocument): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!vex.id) {
      errors.push('VEX ID is required');
    }

    if (!vex.timestamp) {
      errors.push('VEX timestamp is required');
    }

    if (!vex.author) {
      errors.push('VEX author is required');
    }

    if (!vex.status) {
      errors.push('VEX status is required');
    }

    if (!vex.description) {
      errors.push('VEX description is required');
    }

    if (!vex.affected || vex.affected.length === 0) {
      errors.push('VEX must have at least one affected component');
    }

    for (const affected of vex.affected) {
      if (!affected.component) {
        errors.push('Affected component is required');
      }
      if (!affected.vulnerability) {
        errors.push('Affected vulnerability is required');
      }
      if (!affected.justification) {
        errors.push('Affected justification is required');
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Save VEX documents to file
   */
  async saveVEX(vexDocuments: VEXDocument[], outputPath: string): Promise<void> {
    const fs = await import('fs-extra');
    const path = await import('path');

    const filename = `vex-${new Date().toISOString().split('T')[0]}.json`;
    const fullPath = path.join(outputPath, filename);

    await fs.ensureDir(outputPath);
    await fs.writeJson(fullPath, vexDocuments, { spaces: 2 });

    this.logger.info('VEX documents saved to file', { path: fullPath });
  }

  /**
   * Generate VEX summary
   */
  generateVEXSummary(vexDocuments: VEXDocument[]): {
    total: number;
    notAffected: number;
    affected: number;
    fixed: number;
    underInvestigation: number;
  } {
    const summary = {
      total: vexDocuments.length,
      notAffected: 0,
      affected: 0,
      fixed: 0,
      underInvestigation: 0
    };

    for (const vex of vexDocuments) {
      switch (vex.status) {
        case 'not_affected':
          summary.notAffected++;
          break;
        case 'affected':
          summary.affected++;
          break;
        case 'fixed':
          summary.fixed++;
          break;
        case 'under_investigation':
          summary.underInvestigation++;
          break;
      }
    }

    return summary;
  }
}

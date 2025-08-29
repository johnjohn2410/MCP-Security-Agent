import { ScanResult, ScanConfig, Finding, SeverityLevel, VulnerabilityType } from '../types/index.js';
import { Logger } from './Logger.js';
import fs from 'fs-extra';
import path from 'path';

export class ReportGenerator {
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  /**
   * Generate reports in the specified formats
   */
  async generateReports(scanResult: ScanResult, config: ScanConfig): Promise<void> {
    const outputs = new Set(
      (config as any).outputFormats ?? [config.outputFormat ?? 'json']
    );
    const outputDir = path.join(process.cwd(), 'reports');
    
    // Ensure output directory exists
    await fs.ensureDir(outputDir);

    this.logger.info('Generating reports', {
      formats: Array.from(outputs),
      outputDir,
      findingsCount: scanResult.findings.length
    });

    for (const format of outputs) {
      try {
        switch (format) {
          case 'json':
            await this.generateJSONReport(scanResult, outputDir);
            break;
          case 'html':
            await this.generateHTMLReport(scanResult, outputDir);
            break;
          case 'csv':
            await this.generateCSVReport(scanResult, outputDir);
            break;
          case 'pdf':
            await this.generatePDFReport(scanResult, outputDir);
            break;
          case 'sarif':
            await this.generateSARIFReport(scanResult, outputDir);
            break;
          default:
            this.logger.warn('Unsupported output format', { format });
        }
      } catch (error) {
        this.logger.error('Failed to generate report', error instanceof Error ? error : new Error(String(error)));
      }
    }

    this.logger.info('Report generation completed', { outputDir });
  }

  /**
   * Generate JSON report
   */
  private async generateJSONReport(scanResult: ScanResult, outputDir: string): Promise<void> {
    const filename = `security-scan-${scanResult.id}.json`;
    const filepath = path.join(outputDir, filename);

    const report = {
      metadata: {
        generatedAt: scanResult.metadata.generatedAt,
        version: scanResult.metadata.version,
        scanId: scanResult.id,
        scanner: scanResult.scanner,
        summary: this.generateSummary(scanResult)
      },
      scanResult,
      findings: scanResult.findings,
      performance: scanResult.performance,
      compliance: scanResult.metadata.compliance
    };

    await fs.writeJson(filepath, report, { spaces: 2 });
    this.logger.info('JSON report generated', { filepath });
  }

  /**
   * Generate HTML report
   */
  private async generateHTMLReport(scanResult: ScanResult, outputDir: string): Promise<void> {
    const filename = `security-scan-${scanResult.id}.html`;
    const filepath = path.join(outputDir, filename);

    const html = this.generateHTMLContent(scanResult);
    await fs.writeFile(filepath, html, 'utf-8');
    this.logger.info('HTML report generated', { filepath });
  }

  /**
   * Generate CSV report
   */
  private async generateCSVReport(scanResult: ScanResult, outputDir: string): Promise<void> {
    const filename = `security-scan-${scanResult.id}.csv`;
    const filepath = path.join(outputDir, filename);

    const csv = this.generateCSVContent(scanResult);
    await fs.writeFile(filepath, csv, 'utf-8');
    this.logger.info('CSV report generated', { filepath });
  }

  /**
   * Generate PDF report
   */
  private async generatePDFReport(scanResult: ScanResult, outputDir: string): Promise<void> {
    const filename = `security-scan-${scanResult.id}.pdf`;
    const filepath = path.join(outputDir, filename);

    // For now, we'll generate a simple text-based PDF
    // In a production environment, you might want to use a library like puppeteer or jsPDF
    const pdfContent = this.generatePDFContent(scanResult);
    await fs.writeFile(filepath, pdfContent, 'utf-8');
    this.logger.info('PDF report generated', { filepath });
  }

  /**
   * Generate SARIF report
   */
  private async generateSARIFReport(scanResult: ScanResult, outputDir: string): Promise<void> {
    const filename = `security-scan-${scanResult.id}.sarif`;
    const filepath = path.join(outputDir, filename);

    const sarif = this.generateSARIFContent(scanResult);
    await fs.writeJson(filepath, sarif, { spaces: 2 });
    this.logger.info('SARIF report generated', { filepath });
  }

  /**
   * Generate summary statistics
   */
  private generateSummary(scanResult: ScanResult): any {
    const findings = scanResult.findings;
    const severityCounts = {
      critical: findings.filter(f => f.severity === SeverityLevel.CRITICAL).length,
      high: findings.filter(f => f.severity === SeverityLevel.HIGH).length,
      medium: findings.filter(f => f.severity === SeverityLevel.MEDIUM).length,
      low: findings.filter(f => f.severity === SeverityLevel.LOW).length,
      info: findings.filter(f => f.severity === SeverityLevel.INFO).length
    };

    const typeCounts = findings.reduce((acc, finding) => {
      acc[finding.type] = (acc[finding.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    return {
      totalFindings: findings.length,
      severityBreakdown: severityCounts,
      typeBreakdown: typeCounts,
      riskScore: scanResult.performance.throughput,
      scanDuration: scanResult.performance.scanDuration,
      filesScanned: scanResult.performance.filesScanned
    };
  }

  /**
   * Generate HTML content
   */
  private generateHTMLContent(scanResult: ScanResult): string {
    const summary = this.generateSummary(scanResult);
    const findings = scanResult.findings;

    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - ${scanResult.id}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; color: #333; }
        .summary-card .number { font-size: 2em; font-weight: bold; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .info { color: #17a2b8; }
        .findings { margin-top: 30px; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .finding-title { font-weight: bold; font-size: 1.1em; }
        .finding-severity { padding: 5px 10px; border-radius: 3px; color: white; font-weight: bold; }
        .finding-severity.critical { background: #dc3545; }
        .finding-severity.high { background: #fd7e14; }
        .finding-severity.medium { background: #ffc107; color: #333; }
        .finding-severity.low { background: #28a745; }
        .finding-severity.info { background: #17a2b8; }
        .finding-details { margin: 10px 0; }
        .finding-location { font-family: monospace; background: #f8f9fa; padding: 5px; border-radius: 3px; }
        .finding-recommendation { background: #e7f3ff; padding: 10px; border-radius: 5px; margin-top: 10px; }
        .metadata { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 30px; }
        .metadata h3 { margin-top: 0; }
        .metadata-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Report</h1>
            <p>Generated on ${new Date(scanResult.metadata.generatedAt).toLocaleString()}</p>
            <p>Scan ID: ${scanResult.id}</p>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="number">${summary.totalFindings}</div>
            </div>
            <div class="summary-card">
                <h3>Critical</h3>
                <div class="number critical">${summary.severityBreakdown.critical}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div class="number high">${summary.severityBreakdown.high}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div class="number medium">${summary.severityBreakdown.medium}</div>
            </div>
            <div class="summary-card">
                <h3>Low</h3>
                <div class="number low">${summary.severityBreakdown.low}</div>
            </div>
            <div class="summary-card">
                <h3>Info</h3>
                <div class="number info">${summary.severityBreakdown.info}</div>
            </div>
        </div>

        <div class="findings">
            <h2>Findings</h2>
            ${findings.map(finding => `
                <div class="finding">
                    <div class="finding-header">
                        <div class="finding-title">${finding.title}</div>
                        <div class="finding-severity ${finding.severity}">${finding.severity.toUpperCase()}</div>
                    </div>
                    <div class="finding-details">
                        <p><strong>Description:</strong> ${finding.description}</p>
                        <p><strong>Location:</strong> <span class="finding-location">${finding.file}:${finding.line}</span></p>
                        <p><strong>Type:</strong> ${finding.type}</p>
                        <p><strong>Confidence:</strong> ${Math.round(finding.confidence * 100)}%</p>
                        ${finding.cwe ? `<p><strong>CWE:</strong> ${finding.cwe}</p>` : ''}
                    </div>
                    <div class="finding-recommendation">
                        <strong>Recommendation:</strong> ${finding.remediation}
                    </div>
                </div>
            `).join('')}
        </div>

        <div class="metadata">
            <h3>Scan Metadata</h3>
            <div class="metadata-grid">
                <div><strong>Scanner:</strong> ${scanResult.scanner}</div>
                <div><strong>Version:</strong> ${scanResult.metadata.version}</div>
                <div><strong>Duration:</strong> ${scanResult.performance.scanDuration}ms</div>
                <div><strong>Files Scanned:</strong> ${scanResult.performance.filesScanned}</div>
                <div><strong>Memory Usage:</strong> ${Math.round(scanResult.performance.memoryUsage)}MB</div>
                <div><strong>CPU Usage:</strong> ${scanResult.performance.cpuUsage}%</div>
            </div>
        </div>
    </div>
</body>
</html>`;
  }

  /**
   * Generate CSV content
   */
  private generateCSVContent(scanResult: ScanResult): string {
    const findings = scanResult.findings;
    
    const headers = [
      'ID', 'Title', 'Severity', 'Type', 'File', 'Line', 'Description', 
      'Recommendation', 'Confidence', 'CWE', 'Tags'
    ];

    const rows = findings.map(finding => [
      finding.id,
      `"${finding.title.replace(/"/g, '""')}"`,
      finding.severity,
      finding.type,
      `"${finding.file}"`,
      finding.line || '',
      `"${finding.description.replace(/"/g, '""')}"`,
      `"${finding.remediation.replace(/"/g, '""')}"`,
      finding.confidence,
      finding.cwe || '',
      `"${finding.tags.join(', ')}"`
    ]);

    return [headers.join(','), ...rows.map(row => row.join(','))].join('\n');
  }

  /**
   * Generate PDF content (simplified text-based)
   */
  private generatePDFContent(scanResult: ScanResult): string {
    const summary = this.generateSummary(scanResult);
    const findings = scanResult.findings;

    return `SECURITY SCAN REPORT
Generated: ${new Date(scanResult.metadata.generatedAt).toLocaleString()}
Scan ID: ${scanResult.id}
Scanner: ${scanResult.scanner}
Version: ${scanResult.metadata.version}

SUMMARY
=======
Total Findings: ${summary.totalFindings}
Critical: ${summary.severityBreakdown.critical}
High: ${summary.severityBreakdown.high}
Medium: ${summary.severityBreakdown.medium}
Low: ${summary.severityBreakdown.low}
Info: ${summary.severityBreakdown.info}

Scan Duration: ${scanResult.performance.scanDuration}ms
Files Scanned: ${scanResult.performance.filesScanned}

FINDINGS
========
${findings.map((finding, index) => `
${index + 1}. ${finding.title}
   Severity: ${finding.severity.toUpperCase()}
   Type: ${finding.type}
   Location: ${finding.file}:${finding.line}
   Description: ${finding.description}
   Recommendation: ${finding.remediation}
   Confidence: ${Math.round(finding.confidence * 100)}%
   ${finding.cwe ? `CWE: ${finding.cwe}` : ''}
   Tags: ${finding.tags.join(', ')}
`).join('\n')}

PERFORMANCE METRICS
==================
Scan Duration: ${scanResult.performance.scanDuration}ms
Memory Usage: ${Math.round(scanResult.performance.memoryUsage)}MB
CPU Usage: ${scanResult.performance.cpuUsage}%
Network Requests: ${scanResult.performance.networkRequests}
Throughput: ${scanResult.performance.throughput} findings/sec

COMPLIANCE MAPPING
=================
SOC 2: ${scanResult.metadata.compliance.soc2.join(', ') || 'None'}
ISO 27001: ${scanResult.metadata.compliance.iso27001.join(', ') || 'None'}
PCI: ${scanResult.metadata.compliance.pci.join(', ') || 'None'}
GDPR: ${scanResult.metadata.compliance.gdpr.join(', ') || 'None'}
HIPAA: ${scanResult.metadata.compliance.hipaa.join(', ') || 'None'}
NIST: ${scanResult.metadata.compliance.nist.join(', ') || 'None'}

END OF REPORT`;
  }

  /**
   * Generate SARIF content
   */
  private generateSARIFContent(scanResult: ScanResult): any {
    const findings = scanResult.findings;

    return {
      $schema: "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: scanResult.scanner,
              version: scanResult.metadata.version,
              informationUri: "https://github.com/your-org/mcp-security-agent"
            }
          },
          automationDetails: {
            id: scanResult.id
          },
          results: findings.map(finding => ({
            ruleId: finding.type,
            level: this.mapSeverityToSARIF(finding.severity),
            message: {
              text: finding.description
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: finding.file
                  },
                  region: {
                    startLine: finding.line || 1,
                    startColumn: finding.column || 1
                  }
                }
              }
            ],
            properties: {
              tags: finding.tags,
              confidence: finding.confidence,
              cwe: finding.cwe,
              recommendation: finding.remediation
            }
          })),
          invocations: [
            {
              executionSuccessful: true,
              startTimeUtc: scanResult.metadata.generatedAt,
              endTimeUtc: new Date().toISOString(),
              toolExecutionNotifications: []
            }
          ]
        }
      ]
    };
  }

  /**
   * Map severity levels to SARIF levels
   */
  private mapSeverityToSARIF(severity: SeverityLevel): string {
    switch (severity) {
      case SeverityLevel.CRITICAL:
        return 'error';
      case SeverityLevel.HIGH:
        return 'error';
      case SeverityLevel.MEDIUM:
        return 'warning';
      case SeverityLevel.LOW:
        return 'note';
      case SeverityLevel.INFO:
        return 'note';
      default:
        return 'note';
    }
  }
}

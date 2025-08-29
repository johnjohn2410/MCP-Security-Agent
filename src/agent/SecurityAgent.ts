import { ScanConfig, ScanResult, Finding, VulnerabilityType, SeverityLevel, ReportMetadata, PerformanceMetrics, PolicyResult, SecurityPolicy } from '../types/index.js';
import { CodeSecurityScanner } from '../scanner/CodeSecurityScanner.js';
import { DependencyScanner } from '../scanner/DependencyScanner.js';
import { SecretScanner } from '../scanner/SecretScanner.js';
import { ConfigurationScanner } from '../scanner/ConfigurationScanner.js';
import { PolicyEngine } from '../policies/PolicyEngine.js';
import { AIAnalyzer } from '../ai/AIAnalyzer.js';
import { ReportGenerator } from '../utils/ReportGenerator.js';
import { DataHandler } from '../utils/DataHandler.js';
import { SBOMGenerator } from '../utils/SBOMGenerator.js';
import { VEXGenerator } from '../utils/VEXGenerator.js';
import { Logger } from '../utils/Logger.js';
import { randomUUID, createHash } from 'node:crypto';
import * as path from 'node:path';
import fs from 'fs-extra';

export class SecurityAgent {
  private logger: Logger;
  private codeScanner: CodeSecurityScanner;
  private dependencyScanner: DependencyScanner;
  private secretScanner: SecretScanner;
  private configScanner: ConfigurationScanner;
  private policyEngine: PolicyEngine;
  private aiAnalyzer: AIAnalyzer;
  private reportGenerator: ReportGenerator;
  private dataHandler: DataHandler;
  private sbomGenerator: SBOMGenerator;
  private vexGenerator: VEXGenerator;
  private scanId: string;
  private sessionId: string;
  private startTime: number;

  constructor(config: ScanConfig) {
    this.logger = new Logger('SecurityAgent');
    this.scanId = randomUUID();
    this.sessionId = randomUUID();
    this.startTime = Date.now();

    // Initialize data handler with privacy controls
    this.dataHandler = new DataHandler(config.dataHandling, this.logger);

    // Initialize scanners
    this.codeScanner = new CodeSecurityScanner();
    this.dependencyScanner = new DependencyScanner();
    this.secretScanner = new SecretScanner();
    this.configScanner = new ConfigurationScanner();

    // Initialize policy engine
    this.policyEngine = new PolicyEngine(this.logger);

    // Initialize AI analyzer with privacy controls
    this.aiAnalyzer = new AIAnalyzer(
      this.logger,
      this.dataHandler,
      {
        offlineMode: config.offlineMode,
        costLimit: config.aiAnalysis.costLimit,
        latencyLimit: config.aiAnalysis.latencyLimit,
        privacyControls: config.aiAnalysis.privacyControls
      }
    );

    // Initialize utilities
    this.reportGenerator = new ReportGenerator(this.logger);
    this.sbomGenerator = new SBOMGenerator(this.logger);
    this.vexGenerator = new VEXGenerator(this.logger);

    this.logger.info('Security Agent initialized', {
      scanId: this.scanId,
      sessionId: this.sessionId,
      offlineMode: config.offlineMode,
      privacyControls: config.aiAnalysis.privacyControls
    });
  }

  /**
   * Perform comprehensive security scan
   */
  async scan(targetPath: string, config: ScanConfig): Promise<ScanResult> {
    // Compile safely with current ScanConfig
    const cfg = config as ScanConfig & {
      scanTypes?: Array<'code'|'secrets'|'dependencies'|'config'|'policy'>;
      outputFormats?: Array<'json'|'html'|'pdf'|'csv'|'sarif'>;
    };

    // derive effective scanTypes when only scanType is provided
    const effectiveScanTypes =
      cfg.scanTypes && cfg.scanTypes.length
        ? new Set(cfg.scanTypes)
        : new Set(
            cfg.scanType === 'quick'
              ? ['secrets','dependencies']
              : cfg.scanType === 'targeted'
              ? ['code'] // pick your default targeted subset
              : ['code','secrets','dependencies','config','policy']
          );

    this.logger.info('Starting comprehensive security scan', {
      targetPath,
      scanId: this.scanId,
      config: {
        scanTypes: Array.from(effectiveScanTypes),
        generateSBOM: config.generateSBOM,
        generateVEX: config.generateVEX,
        auditLogging: config.auditLogging
      }
    });

    const findings: Finding[] = [];
    let sbom: any = null;
    let vex: any[] = [];

    try {
      // Perform code security scan
      if (effectiveScanTypes.has('code')) {
        this.logger.info('Starting code security scan');
        const codeResults = await this.codeScanner.scan(targetPath, config);
        findings.push(...this.convertToFindings(codeResults, 'code'));
      }

      // Perform dependency scan
      if (effectiveScanTypes.has('dependencies')) {
        this.logger.info('Starting dependency scan');
        const depResults = await this.dependencyScanner.scan(targetPath, config);
        findings.push(...this.convertToFindings(depResults, 'dependencies'));
      }

      // Perform secret scan
      if (effectiveScanTypes.has('secrets')) {
        this.logger.info('Starting secret scan');
        const secretResults = await this.secretScanner.scan(targetPath, config);
        findings.push(...this.convertToFindings(secretResults, 'secrets'));
      }

      // Perform configuration scan
      if (effectiveScanTypes.has('config')) {
        this.logger.info('Starting configuration scan');
        const configResults = await this.configScanner.scan(targetPath, config);
        findings.push(...this.convertToFindings(configResults, 'config'));
      }

      // Generate SBOM if requested
      if (config.generateSBOM) {
        this.logger.info('Generating SBOM');
        sbom = await this.sbomGenerator.generateSBOM(targetPath, 'CycloneDX');
      }

      // Generate VEX documents for non-exploitable findings
      if (config.generateVEX && findings.length > 0) {
        this.logger.info('Generating VEX documents');
        vex = this.vexGenerator.generateVEX(
          findings,
          'Security Agent',
          'Automated analysis indicates low risk or false positive'
        );
      }

      // Perform AI analysis
      let aiAnalysis = null;
      if (config.aiAnalysis.enabled && findings.length > 0) {
        this.logger.info('Starting AI analysis');
        const projectContext = await this.extractProjectContext(targetPath);
        aiAnalysis = await this.aiAnalyzer.analyzeFindings(findings, projectContext);
      }

      // Evaluate policies using the interface
      const policyResults: PolicyResult[] = [];
      for (const finding of findings) {
        try {
          const policy: SecurityPolicy = {
            id: "active-policy",
            name: "Active Policy",
            description: "Organization policy",
            version: "1.0.0",
            scope: "global",
            inheritance: "merge",
            enabled: true,
            priority: 0,
            rules: [],
            metadata: {}
          };
          const pr = await this.policyEngine.evaluatePolicy(
            policy,
            { finding, projectPath: targetPath, config }
          );
          policyResults.push(pr);
        } catch (err) {
          this.logger.warn('Policy evaluation failed', err as Error);
        }
      }

      // Generate performance metrics
      const performance = this.generatePerformanceMetrics(findings.length);

      // Generate report metadata
      const metadata = this.generateReportMetadata(config, performance, sbom, aiAnalysis, targetPath);

      // Choose a representative top finding (or synthesize a neutral one)
      const top = findings[0];

      const result: ScanResult = {
        id: this.scanId,
        type: top?.type ?? VulnerabilityType.CONFIGURATION_ISSUE,
        severity: top?.severity ?? SeverityLevel.INFO,
        title: "MCP Security Agent Scan",
        description: `Scan of ${targetPath}`,
        location: { file: top?.file ?? targetPath },
        evidence: "",
        recommendation: "",
        timestamp: new Date(),
        scanner: "mcp-security-agent",
        confidence: 1.0,
        tags: Array.from(effectiveScanTypes),
        findings,
        auditLog: config.auditLogging ? this.dataHandler.getAuditLog() : [],
        sbom: sbom ?? undefined,
        vex: vex?.length ? vex : undefined,
        policyResults,
        performance,
        metadata
      };

      this.logger.info('Security scan completed successfully', {
        scanId: this.scanId,
        totalFindings: findings.length,
        scanDuration: performance.scanDuration,
        aiAnalysis: !!aiAnalysis
      });

      return result;

    } catch (error) {
      this.logger.error('Security scan failed', error as Error);
      throw error;
    }
  }

  /**
   * Convert scanner results to Finding objects
   */
  private convertToFindings(results: any[], source: string): Finding[] {
    return results.map(result => ({
      id: randomUUID(),
      stableId: this.generateStableId(result, source),
      type: result.type as VulnerabilityType,
      severity: result.severity as SeverityLevel,
      title: result.title,
      description: result.description,
      file: result.file,
      line: result.line || 0,
      column: result.column,
      snippet: result.snippet || '',
      evidence: result.evidence,
      confidence: result.confidence || 0.8,
      cwe: result.cwe,
      owasp: result.owasp,
      nist: result.nist,
      cis: result.cis,
      references: result.references || [],
      remediation: result.remediation || '',
      patch: result.patch,
      riskScore: this.calculateFindingRiskScore(result),
      exploitability: this.assessExploitability(result),
      impact: this.assessImpact(result),
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      status: 'open',
      tags: [source],
      metadata: { source }
    }));
  }

  /**
   * Generate stable ID for findings
   */
  private generateStableId(result: any, source: string): string {
    const snippet = (result.snippet ?? '').slice(0, 200);
    const content = `${source}:${result.file}:${result.line}:${result.type}:${snippet}`;
    return createHash('sha256').update(content).digest('hex').slice(0, 16);
  }

  /**
   * Calculate risk score for a finding
   */
  private calculateFindingRiskScore(finding: any): number {
    const severityScores: Record<string, number> = {
      [SeverityLevel.CRITICAL]: 10,
      [SeverityLevel.HIGH]: 7,
      [SeverityLevel.MEDIUM]: 4,
      [SeverityLevel.LOW]: 2,
      [SeverityLevel.INFO]: 1
    };

    const baseScore = severityScores[finding.severity] || 1;
    const confidenceMultiplier = finding.confidence || 0.8;
    
    return Math.round(baseScore * confidenceMultiplier);
  }

  /**
   * Assess exploitability of a finding
   */
  private assessExploitability(finding: any): 'low' | 'medium' | 'high' | 'critical' {
    switch (finding.type) {
      case VulnerabilityType.SQL_INJECTION:
      case VulnerabilityType.COMMAND_INJECTION:
        return 'high';
      case VulnerabilityType.XSS:
      case VulnerabilityType.PATH_TRAVERSAL:
        return 'medium';
      case VulnerabilityType.HARDCODED_SECRET:
      case VulnerabilityType.INSECURE_DEPENDENCY:
        return 'low';
      default:
        return 'medium';
    }
  }

  /**
   * Assess impact of a finding
   */
  private assessImpact(finding: any): 'low' | 'medium' | 'high' | 'critical' {
    switch (finding.severity) {
      case SeverityLevel.CRITICAL:
        return 'critical';
      case SeverityLevel.HIGH:
        return 'high';
      case SeverityLevel.MEDIUM:
        return 'medium';
      case SeverityLevel.LOW:
      case SeverityLevel.INFO:
        return 'low';
      default:
        return 'medium';
    }
  }

  /**
   * Extract project context for AI analysis
   */
  private async extractProjectContext(targetPath: string): Promise<Record<string, any>> {
    const context: Record<string, any> = {
      projectPath: targetPath,
      projectType: 'unknown',
      technologyStack: [],
      environment: 'development',
      complianceRequirements: []
    };

    try {
      // Detect project type
      const packageJsonPath = path.join(targetPath, 'package.json');
      if (await fs.pathExists(packageJsonPath)) {
        context.projectType = 'Node.js';
        context.technologyStack.push('JavaScript/TypeScript');
        
        const packageJson = await fs.readJson(packageJsonPath);
        if (packageJson.dependencies) {
          Object.keys(packageJson.dependencies).forEach(dep => {
            if (dep.includes('react')) context.technologyStack.push('React');
            if (dep.includes('vue')) context.technologyStack.push('Vue');
            if (dep.includes('angular')) context.technologyStack.push('Angular');
            if (dep.includes('express')) context.technologyStack.push('Express');
            if (dep.includes('next')) context.technologyStack.push('Next.js');
          });
        }
      }

      const requirementsPath = path.join(targetPath, 'requirements.txt');
      if (await fs.pathExists(requirementsPath)) {
        context.projectType = 'Python';
        context.technologyStack.push('Python');
      }

      const pomXmlPath = path.join(targetPath, 'pom.xml');
      if (await fs.pathExists(pomXmlPath)) {
        context.projectType = 'Java';
        context.technologyStack.push('Java');
      }

      // Detect environment
      const envFiles = ['.env.production', '.env.staging', '.env.development'];
      for (const envFile of envFiles) {
        if (await fs.pathExists(path.join(targetPath, envFile))) {
          context.environment = envFile.split('.')[1];
          break;
        }
      }

    } catch (error) {
      this.logger.warn('Failed to extract project context', error as Error);
    }

    return context;
  }

  /**
   * Generate performance metrics
   */
  private generatePerformanceMetrics(findingsCount: number): PerformanceMetrics {
    const endTime = Date.now();
    const scanDuration = endTime - this.startTime;

    return {
      scanDuration,
      filesScanned: 0, // Would need to track during scan
      findingsFound: findingsCount,
      memoryUsage: process.memoryUsage().heapUsed / 1024 / 1024, // MB
      cpuUsage: 0, // Would need to track during scan
      networkRequests: 0, // Would need to track during scan
      p95Latency: 0, // Would need to track during scan
      p99Latency: 0, // Would need to track during scan
      throughput: findingsCount / (scanDuration / 1000) // findings per second
    };
  }

  /**
   * Generate report metadata
   */
  private generateReportMetadata(
    config: ScanConfig,
    performance: PerformanceMetrics,
    sbom: any,
    aiAnalysis: any,
    targetPath: string
  ): ReportMetadata {
    return {
      generatedAt: new Date().toISOString(),
      version: '1.0.0',
      scanId: this.scanId,
      sessionId: this.sessionId,
      userAgent: 'MCP-Security-Agent/1.0.0',
      compliance: {
        soc2: [],
        iso27001: [],
        pci: [],
        gdpr: [],
        hipaa: [],
        nist: []
      },
      performance,
      auditLogHash: this.dataHandler.generateHash(JSON.stringify(this.dataHandler.getAuditLog())),
      sbomHash: sbom ? this.dataHandler.generateHash(JSON.stringify(sbom)) : ''
    };
  }

  /**
   * Calculate overall risk score
   */
  private calculateRiskScore(findings: Finding[]): number {
    if (findings.length === 0) return 0;

    const totalScore = findings.reduce((sum, finding) => sum + finding.riskScore, 0);
    return Math.round(totalScore / findings.length);
  }

  /**
   * Calculate overall confidence
   */
  private calculateConfidence(findings: Finding[]): number {
    if (findings.length === 0) return 1.0;

    const totalConfidence = findings.reduce((sum, finding) => sum + finding.confidence, 0);
    return Math.round((totalConfidence / findings.length) * 100) / 100;
  }

  /**
   * Get available scanners
   */
  getAvailableScanners(): string[] {
    return ['code', 'dependencies', 'secrets', 'config'];
  }

  /**
   * Get scan statistics
   */
  getScanStats(): {
    scanId: string;
    sessionId: string;
    startTime: number;
    duration: number;
    aiStats: any;
  } {
    const duration = Date.now() - this.startTime;
    return {
      scanId: this.scanId,
      sessionId: this.sessionId,
      startTime: this.startTime,
      duration,
      aiStats: this.aiAnalyzer.getAnalysisStats()
    };
  }

  /**
   * Get privacy statement
   */
  getPrivacyStatement(): string {
    return this.dataHandler.getPrivacyStatement();
  }

  /**
   * Clean up resources
   */
  async cleanup(): Promise<void> {
    this.dataHandler.cleanupOldAuditLogs();
    this.logger.info('Security Agent cleanup completed');
  }
}

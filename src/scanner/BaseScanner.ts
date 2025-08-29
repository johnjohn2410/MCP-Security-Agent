import { Finding, ScanConfig, SeverityLevel, VulnerabilityType } from '../types/index.js';
import { Logger } from '../utils/Logger.js';

export abstract class BaseScanner {
  protected logger: Logger;
  protected name: string;
  protected description: string;
  protected supportedFileTypes: string[];

  constructor(name: string, description: string, supportedFileTypes: string[] = []) {
    this.name = name;
    this.description = description;
    this.supportedFileTypes = supportedFileTypes;
    this.logger = new Logger(`Scanner:${name}`);
  }

  /**
   * Main scan method that should be implemented by subclasses
   */
  abstract scan(path: string, config?: Partial<ScanConfig>): Promise<Finding[]>;

  /**
   * Check if this scanner can handle the given file type
   */
  canScan(filePath: string): boolean {
    if (this.supportedFileTypes.length === 0) {
      return true; // Can scan any file type
    }

    const extension = filePath.split('.').pop()?.toLowerCase();
    return extension ? this.supportedFileTypes.includes(extension) : false;
  }

  /**
   * Get scanner information
   */
  getInfo() {
    return {
      name: this.name,
      description: this.description,
      supportedFileTypes: this.supportedFileTypes
    };
  }

  /**
   * Create a finding with common fields
   */
  protected createFinding(
    type: VulnerabilityType,
    severity: SeverityLevel,
    title: string,
    description: string,
    location: { file: string; line?: number; column?: number; function?: string; context?: string },
    evidence: string,
    recommendation: string,
    options: { cwe?: string[]; confidence?: number; tags?: string[] } = {}
  ): Finding {
    const id = this.generateId();
    const snippet = location.context ?? '';
    return {
      id,
      stableId: id,                 // or compute a stable hash here
      type,
      severity,
      title,
      description,
      file: location.file,
      line: location.line ?? 0,
      column: location.column,
      snippet,
      evidence,
      confidence: options.confidence ?? 0.8,
      cwe: options.cwe,
      owasp: [],
      nist: [],
      cis: [],
      references: [],
      remediation: recommendation,
      riskScore: 0,
      exploitability: 'medium',
      impact: 'medium',
      firstSeen: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      status: 'open',
      tags: options.tags ?? [],
      metadata: {},
    };
  }

  /**
   * Generate a unique ID for scan results
   */
  protected generateId(): string {
    return `${this.name}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Log scan progress
   */
  protected logProgress(message: string, data?: any) {
    this.logger.info(message, data);
  }

  /**
   * Log scan error
   */
  protected logError(message: string, error?: Error) {
    this.logger.error(message, error);
  }

  /**
   * Validate scan configuration
   */
  protected validateConfig(config: Partial<ScanConfig>): void {
    if (config.path && !config.path.trim()) {
      throw new Error('Scan path cannot be empty');
    }

    if (config.timeout && config.timeout <= 0) {
      throw new Error('Timeout must be positive');
    }

    if (config.maxDepth && config.maxDepth < 0) {
      throw new Error('Max depth cannot be negative');
    }
  }

  /**
   * Get file extension from path
   */
  protected getFileExtension(filePath: string): string {
    return filePath.split('.').pop()?.toLowerCase() || '';
  }

  /**
   * Check if file should be excluded based on patterns
   */
  protected shouldExclude(filePath: string, excludePatterns: string[] = []): boolean {
    return excludePatterns.some(pattern => {
      if (pattern.includes('*')) {
        // Simple glob pattern matching
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return regex.test(filePath);
      }
      return filePath.includes(pattern);
    });
  }

  /**
   * Check if file should be included based on patterns
   */
  protected shouldInclude(filePath: string, includePatterns: string[] = []): boolean {
    if (includePatterns.length === 0) {
      return true; // Include all files if no patterns specified
    }

    return includePatterns.some(pattern => {
      if (pattern.includes('*')) {
        // Simple glob pattern matching
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return regex.test(filePath);
      }
      return filePath.includes(pattern);
    });
  }

  /**
   * Extract line context from file content
   */
  protected getLineContext(content: string, lineNumber: number, contextLines: number = 3): string {
    const lines = content.split('\n');
    const start = Math.max(0, lineNumber - contextLines - 1);
    const end = Math.min(lines.length, lineNumber + contextLines);
    
    return lines.slice(start, end).join('\n');
  }

  /**
   * Calculate confidence score based on evidence strength
   */
  protected calculateConfidence(evidence: string, pattern: string): number {
    // Simple confidence calculation based on pattern match strength
    const matchStrength = evidence.toLowerCase().includes(pattern.toLowerCase()) ? 1 : 0;
    const contextStrength = evidence.length > 50 ? 0.2 : 0;
    return Math.min(1, matchStrength + contextStrength);
  }

  /**
   * Get severity level based on vulnerability type and context
   */
  protected getSeverityLevel(type: VulnerabilityType, context: any = {}): SeverityLevel {
    const severityMap: Record<VulnerabilityType, SeverityLevel> = {
      [VulnerabilityType.SQL_INJECTION]: SeverityLevel.CRITICAL,
      [VulnerabilityType.XSS]: SeverityLevel.HIGH,
      [VulnerabilityType.COMMAND_INJECTION]: SeverityLevel.CRITICAL,
      [VulnerabilityType.PATH_TRAVERSAL]: SeverityLevel.HIGH,
      [VulnerabilityType.INSECURE_DESERIALIZATION]: SeverityLevel.HIGH,
      [VulnerabilityType.HARDCODED_SECRET]: SeverityLevel.HIGH,
      [VulnerabilityType.WEAK_CRYPTO]: SeverityLevel.MEDIUM,
      [VulnerabilityType.INSECURE_DEPENDENCY]: SeverityLevel.MEDIUM,
      [VulnerabilityType.CONFIGURATION_ISSUE]: SeverityLevel.MEDIUM,
      [VulnerabilityType.PERMISSION_ISSUE]: SeverityLevel.MEDIUM,
      [VulnerabilityType.LOGGING_ISSUE]: SeverityLevel.LOW,
      [VulnerabilityType.AUTHENTICATION_ISSUE]: SeverityLevel.HIGH,
      [VulnerabilityType.AUTHORIZATION_ISSUE]: SeverityLevel.HIGH,
      [VulnerabilityType.INPUT_VALIDATION]: SeverityLevel.MEDIUM,
      [VulnerabilityType.OUTPUT_ENCODING]: SeverityLevel.MEDIUM
    };

    return severityMap[type] || SeverityLevel.MEDIUM;
  }
}

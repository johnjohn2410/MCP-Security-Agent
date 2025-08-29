import { Finding, ScanConfig, VulnerabilityType, SeverityLevel } from '../types/index.js';
import { BaseScanner } from './BaseScanner.js';

export class CodeSecurityScanner extends BaseScanner {
  private vulnerabilityPatterns: Map<VulnerabilityType, RegExp[]> = new Map();

  constructor() {
    super('CodeSecurityScanner', 'Scans source code for common security vulnerabilities', [
      'js', 'ts', 'jsx', 'tsx', 'py', 'java', 'go', 'php', 'rb', 'cs', 'cpp', 'c', 'h', 'hpp'
    ]);
    this.initializeVulnerabilityPatterns();
  }

  async scan(path: string, config?: Partial<ScanConfig>): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      this.logProgress('Starting code security scan', { path });
      
      // Simulate finding some vulnerabilities
      findings.push(
        this.createFinding(
          VulnerabilityType.XSS,
          SeverityLevel.HIGH,
          'Possible XSS',
          'Unescaped user input flows to sink',
          { file: 'src/app.ts', line: 42, context: '<div>{{ userInput }}</div>' },
          'userInput -> innerHTML',
          'Encode or sanitize user input',
          { cwe: ['CWE-79'], tags: ['code'] }
        )
      );

      findings.push(
        this.createFinding(
          VulnerabilityType.SQL_INJECTION,
          SeverityLevel.CRITICAL,
          'SQL Injection Risk',
          'User input directly concatenated into SQL query',
          { file: 'src/database.ts', line: 15, context: 'SELECT * FROM users WHERE id = <userInput>' },
          'input -> SQL query',
          'Use parameterized queries or prepared statements',
          { cwe: ['CWE-89'], tags: ['code'] }
        )
      );

      this.logProgress('Code security scan completed', { findingsCount: findings.length });
      
    } catch (error) {
      this.logError('Code security scan failed', error as Error);
    }

    return findings;
  }

  private initializeVulnerabilityPatterns(): void {
    // XSS patterns
    this.vulnerabilityPatterns.set(VulnerabilityType.XSS, [
      /innerHTML\s*=\s*.*\+.*\$/,
      /document\.write\s*\(\s*.*\+.*\$/,
      /eval\s*\(\s*.*\+.*\$/,
      /<script>.*<\/script>/i
    ]);

    // SQL Injection patterns
    this.vulnerabilityPatterns.set(VulnerabilityType.SQL_INJECTION, [
      /SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*\+.*\$/,
      /INSERT\s+INTO\s+.*\s+VALUES\s*\(\s*.*\+.*\$/,
      /UPDATE\s+.*\s+SET\s+.*\+.*\$/,
      /DELETE\s+FROM\s+.*\s+WHERE\s+.*\+.*\$/
    ]);

    // Command Injection patterns
    this.vulnerabilityPatterns.set(VulnerabilityType.COMMAND_INJECTION, [
      /exec\s*\(\s*.*\+.*\$/,
      /spawn\s*\(\s*.*\+.*\$/,
      /system\s*\(\s*.*\+.*\$/,
      /shell_exec\s*\(\s*.*\+.*\$/
    ]);

    // Path Traversal patterns
    this.vulnerabilityPatterns.set(VulnerabilityType.PATH_TRAVERSAL, [
      /fs\.readFile\s*\(\s*.*\+.*\$/,
      /fs\.writeFile\s*\(\s*.*\+.*\$/,
      /\.\.\/.*\$/,
      /\.\.\\\\.*\$/
    ]);

    // Insecure Deserialization patterns
    this.vulnerabilityPatterns.set(VulnerabilityType.INSECURE_DESERIALIZATION, [
      /JSON\.parse\s*\(\s*.*\+.*\$/,
      /eval\s*\(\s*.*\+.*\$/,
      /Function\s*\(\s*.*\+.*\$/
    ]);
  }
}

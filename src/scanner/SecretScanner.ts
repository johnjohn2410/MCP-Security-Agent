import { Finding, ScanConfig, VulnerabilityType, SeverityLevel } from '../types/index.js';
import { BaseScanner } from './BaseScanner.js';
import { Logger } from '../utils/Logger.js';
import fs from 'fs-extra';
import path from 'path';

export class SecretScanner extends BaseScanner {
  private secretPatterns: Map<string, RegExp>;

  constructor() {
    super('SecretScanner', 'Scans for hardcoded secrets, API keys, and tokens', [
      'js', 'ts', 'jsx', 'tsx', 'py', 'java', 'go', 'php', 'rb', 'cs', 'cpp', 'c', 'h', 'hpp',
      'json', 'yaml', 'yml', 'env', 'properties', 'xml', 'toml', 'ini', 'cfg', 'conf'
    ]);
    this.secretPatterns = this.initializeSecretPatterns();
  }

  async scan(targetPath: string, config: ScanConfig): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      this.logProgress('Starting secret scan', { path: targetPath });
      
      const files = await this.findFilesToScan(targetPath, config);
      
      for (const file of files) {
        const fileFindings = await this.scanFileForSecrets(file);
        findings.push(...fileFindings);
      }

      this.logProgress('Secret scan completed', { findingsCount: findings.length });
      
    } catch (error) {
      this.logError('Secret scan failed', error as Error);
    }

    return findings;
  }

  private async findFilesToScan(rootPath: string, config: ScanConfig): Promise<string[]> {
    const files: string[] = [];
    const patterns = [
      '**/*.{js,ts,jsx,tsx,py,java,go,php,rb,cs,cpp,c,h,hpp}',
      '**/*.{json,yaml,yml,env,properties,xml,toml,ini,cfg,conf}',
      '**/.env*',
      '**/config.*',
      '**/secrets.*'
    ];

    for (const pattern of patterns) {
      try {
        const matchedFiles = await this.glob(pattern, { 
          cwd: rootPath, 
          absolute: true,
          ignore: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/.git/**']
        });
        files.push(...matchedFiles);
      } catch (error) {
        // Pattern not found, continue
      }
    }

    return [...new Set(files)]; // Remove duplicates
  }

  private async scanFileForSecrets(filePath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const lines = content.split('\n');
      
      for (let lineNumber = 0; lineNumber < lines.length; lineNumber++) {
        const line = lines[lineNumber];
        const lineFindings = this.scanLineForSecrets(line, lineNumber + 1, filePath);
        findings.push(...lineFindings);
      }
    } catch (error) {
      this.logError(`Error reading file ${filePath}`, error as Error);
    }

    return findings;
  }

  private scanLineForSecrets(line: string, lineNumber: number, filePath: string): Finding[] {
    const findings: Finding[] = [];
    
    for (const [secretType, pattern] of this.secretPatterns) {
      const matches = line.matchAll(pattern);
      
      for (const match of matches) {
        const secret = match[0];
        
        // Filter out false positives
        if (!this.isFalsePositive(secret, line, filePath)) {
          findings.push(
            this.createFinding(
              VulnerabilityType.HARDCODED_SECRET,
              this.getSecretSeverity(secretType),
              `Hardcoded ${secretType} detected`,
              `A ${secretType} was found hardcoded in the source code`,
              { file: filePath, line: lineNumber, context: line },
              secret,
              `Move the ${secretType} to environment variables or a secure configuration management system`,
              { cwe: ['CWE-259'], tags: ['secrets', secretType] }
            )
          );
        }
      }
    }

    return findings;
  }

  private initializeSecretPatterns(): Map<string, RegExp> {
    const patterns = new Map<string, RegExp>();
    
    // API Keys
    patterns.set('API Key', /(api[_-]?key|apikey)\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi);
    patterns.set('API Key', /(api[_-]?key|apikey)\s*[:=]\s*['"`][a-zA-Z0-9_-]{20,}['"`]/gi);
    
    // Passwords
    patterns.set('Password', /password\s*[:=]\s*['"`][^'"`]{8,}['"`]/gi);
    patterns.set('Password', /passwd\s*[:=]\s*['"`][^'"`]{8,}['"`]/gi);
    patterns.set('Password', /pwd\s*[:=]\s*['"`][^'"`]{8,}['"`]/gi);
    
    // Tokens
    patterns.set('Token', /token\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi);
    patterns.set('Token', /access[_-]?token\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi);
    patterns.set('Token', /auth[_-]?token\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi);
    
    // Private Keys
    patterns.set('Private Key', /private[_-]?key\s*[:=]\s*['"`]-----BEGIN\s+PRIVATE\s+KEY-----/gi);
    patterns.set('Private Key', /private[_-]?key\s*[:=]\s*['"`]-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----/gi);
    
    // Database URLs
    patterns.set('Database URL', /database[_-]?url\s*[:=]\s*['"`](mysql|postgresql|mongodb|redis):\/\/[^'"`]+['"`]/gi);
    patterns.set('Database URL', /db[_-]?url\s*[:=]\s*['"`](mysql|postgresql|mongodb|redis):\/\/[^'"`]+['"`]/gi);
    
    // AWS Keys
    patterns.set('AWS Key', /aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*['"`][A-Z0-9]{20}['"`]/gi);
    patterns.set('AWS Key', /aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"`][A-Za-z0-9/+=]{40}['"`]/gi);
    
    // SSH Keys
    patterns.set('SSH Key', /ssh[_-]?private[_-]?key\s*[:=]\s*['"`]-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/gi);
    patterns.set('SSH Key', /ssh[_-]?key\s*[:=]\s*['"`]-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/gi);
    
    // OAuth Secrets
    patterns.set('OAuth Secret', /oauth[_-]?secret\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi);
    patterns.set('OAuth Secret', /client[_-]?secret\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi);
    
    // JWT Secrets
    patterns.set('JWT Secret', /jwt[_-]?secret\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi);
    patterns.set('JWT Secret', /jwt[_-]?key\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi);
    
    // Generic Secrets
    patterns.set('Secret', /secret\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi);
    patterns.set('Secret', /key\s*[:=]\s*['"`][a-zA-Z0-9]{20,}['"`]/gi);

    return patterns;
  }

  private isFalsePositive(secret: string, line: string, filePath: string): boolean {
    // Check for common false positive patterns
    const falsePositivePatterns = [
      // Comments
      /\/\/.*$/,
      /\/\*.*\*\//,
      /#.*$/,
      
      // Example/test patterns
      /example/i,
      /test/i,
      /sample/i,
      /demo/i,
      /placeholder/i,
      /dummy/i,
      /fake/i,
      
      // Environment variable references
      /process\.env\./,
      /os\.environ\[/,
      /\$\{[A-Z_]+}/,
      
      // Configuration patterns
      /config\./,
      /settings\./,
      /default/i,
      
      // Safe patterns
      /safe_string/,
      /not_a_secret/,
      /public_key/,
      /certificate/
    ];

    // Check if the line contains false positive patterns
    for (const pattern of falsePositivePatterns) {
      if (pattern.test(line)) {
        return true;
      }
    }

    // Check if the secret looks like a placeholder
    if (secret.includes('YOUR_') || secret.includes('PLACEHOLDER') || secret.includes('EXAMPLE')) {
      return true;
    }

    // Check if the file is in a test directory
    if (filePath.includes('/test/') || filePath.includes('/tests/') || filePath.includes('/spec/')) {
      return true;
    }

    return false;
  }

  private getSecretSeverity(secretType: string): SeverityLevel {
    const highSeveritySecrets = [
      'Private Key',
      'AWS Key',
      'SSH Key',
      'Database URL',
      'OAuth Secret',
      'JWT Secret'
    ];

    const mediumSeveritySecrets = [
      'API Key',
      'Token',
      'Secret'
    ];

    if (highSeveritySecrets.includes(secretType)) {
      return SeverityLevel.HIGH;
    } else if (mediumSeveritySecrets.includes(secretType)) {
      return SeverityLevel.MEDIUM;
    } else {
      return SeverityLevel.LOW;
    }
  }

  private async glob(pattern: string, options: any): Promise<string[]> {
    // Simple glob implementation - in a real implementation, use a proper glob library
    const { glob } = await import('glob');
    return glob(pattern, options);
  }
}

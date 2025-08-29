import { Finding, ScanConfig, VulnerabilityType, SeverityLevel } from '../types/index.js';
import { BaseScanner } from './BaseScanner.js';
import { Logger } from '../utils/Logger.js';
import fs from 'fs-extra';
import path from 'path';

export class ConfigurationScanner extends BaseScanner {
  private configPatterns: Map<string, any[]>;

  constructor() {
    super('ConfigurationScanner', 'Scans configuration files for security misconfigurations', [
      'json', 'yaml', 'yml', 'toml', 'ini', 'conf', 'cfg', 'properties', 'xml', 'env', 'config'
    ]);
    this.configPatterns = this.initializeConfigPatterns();
  }

  async scan(targetPath: string, config: ScanConfig): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      this.logProgress('Starting configuration scan', { path: targetPath });
      
      const configFiles = await this.findConfigFiles(targetPath);
      
      for (const configFile of configFiles) {
        const fileFindings = await this.scanConfigFile(configFile);
        findings.push(...fileFindings);
      }

      this.logProgress('Configuration scan completed', { findingsCount: findings.length });
      
    } catch (error) {
      this.logError('Configuration scan failed', error as Error);
    }

    return findings;
  }

  private async findConfigFiles(rootPath: string): Promise<string[]> {
    const configFiles: string[] = [];
    const patterns = [
      '**/*.json',
      '**/*.yaml',
      '**/*.yml',
      '**/*.toml',
      '**/*.ini',
      '**/*.conf',
      '**/*.cfg',
      '**/*.properties',
      '**/*.xml',
      '**/.env*',
      '**/config.*',
      '**/application.*',
      '**/settings.*'
    ];

    for (const pattern of patterns) {
      try {
        const files = await this.glob(pattern, { 
          cwd: rootPath, 
          absolute: true,
          ignore: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/.git/**']
        });
        configFiles.push(...files);
      } catch (error) {
        // Pattern not found, continue
      }
    }

    return [...new Set(configFiles)]; // Remove duplicates
  }

  private async scanConfigFile(configPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      const content = await fs.readFile(configPath, 'utf-8');
      const ext = path.extname(configPath);
      
      switch (ext) {
        case '.json':
          findings.push(...await this.scanJsonConfig(configPath, content));
          break;
        case '.yaml':
        case '.yml':
          findings.push(...await this.scanYamlConfig(configPath, content));
          break;
        case '.toml':
          findings.push(...await this.scanTomlConfig(configPath, content));
          break;
        case '.ini':
        case '.conf':
        case '.cfg':
          findings.push(...await this.scanIniConfig(configPath, content));
          break;
        case '.properties':
          findings.push(...await this.scanPropertiesConfig(configPath, content));
          break;
        case '.xml':
          findings.push(...await this.scanXmlConfig(configPath, content));
          break;
        default:
          // Generic config file scanning
          findings.push(...await this.scanGenericConfig(configPath, content));
      }
    } catch (error) {
      this.logError(`Error scanning config file ${configPath}`, error as Error);
    }

    return findings;
  }

  private async scanJsonConfig(configPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      const config = JSON.parse(content);
      
      // Check for common security misconfigurations
      findings.push(...this.checkSecurityHeaders(config, configPath));
      findings.push(...this.checkCorsConfig(config, configPath));
      findings.push(...this.checkAuthenticationConfig(config, configPath));
      findings.push(...this.checkDatabaseConfig(config, configPath));
      findings.push(...this.checkLoggingConfig(config, configPath));
      findings.push(...this.checkSslConfig(config, configPath));
      findings.push(...this.checkFileUploadConfig(config, configPath));
      findings.push(...this.checkRateLimitingConfig(config, configPath));
      findings.push(...this.checkEnvironmentConfig(config, configPath));
      
    } catch (error) {
      this.logError(`Error parsing JSON config ${configPath}`, error as Error);
    }

    return findings;
  }

  private async scanYamlConfig(configPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      const { parse } = await import('yaml');
      const config = parse(content);
      
      // Same checks as JSON
      findings.push(...this.checkSecurityHeaders(config, configPath));
      findings.push(...this.checkCorsConfig(config, configPath));
      findings.push(...this.checkAuthenticationConfig(config, configPath));
      findings.push(...this.checkDatabaseConfig(config, configPath));
      findings.push(...this.checkLoggingConfig(config, configPath));
      findings.push(...this.checkSslConfig(config, configPath));
      findings.push(...this.checkFileUploadConfig(config, configPath));
      findings.push(...this.checkRateLimitingConfig(config, configPath));
      findings.push(...this.checkEnvironmentConfig(config, configPath));
      
    } catch (error) {
      this.logError(`Error parsing YAML config ${configPath}`, error as Error);
    }

    return findings;
  }

  private async scanTomlConfig(configPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      // For now, use a simple regex-based TOML parser
      // In a real implementation, you would use a proper TOML parser
      const config = this.parseTomlSimple(content);
      
      // Same checks as JSON
      findings.push(...this.checkSecurityHeaders(config, configPath));
      findings.push(...this.checkCorsConfig(config, configPath));
      findings.push(...this.checkAuthenticationConfig(config, configPath));
      findings.push(...this.checkDatabaseConfig(config, configPath));
      findings.push(...this.checkLoggingConfig(config, configPath));
      findings.push(...this.checkSslConfig(config, configPath));
      findings.push(...this.checkFileUploadConfig(config, configPath));
      findings.push(...this.checkRateLimitingConfig(config, configPath));
      findings.push(...this.checkEnvironmentConfig(config, configPath));
      
    } catch (error) {
      this.logError(`Error parsing TOML config ${configPath}`, error as Error);
    }

    return findings;
  }

  private parseTomlSimple(content: string): any {
    // Simple TOML parser for basic key-value pairs
    const config: any = {};
    const lines = content.split('\n');
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const match = trimmed.match(/^([^=]+)\s*=\s*(.+)$/);
        if (match) {
          const [, key, value] = match;
          config[key.trim()] = value.trim().replace(/^["']|["']$/g, '');
        }
      }
    }
    
    return config;
  }

  private async scanIniConfig(configPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line && !line.startsWith('#')) {
        const [key, value] = line.split('=').map(s => s.trim());
        if (key && value) {
          findings.push(...this.checkIniSetting(key, value, configPath, i + 1, line));
        }
      }
    }

    return findings;
  }

  private async scanPropertiesConfig(configPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line && !line.startsWith('#')) {
        const [key, value] = line.split('=').map(s => s.trim());
        if (key && value) {
          findings.push(...this.checkPropertiesSetting(key, value, configPath, i + 1, line));
        }
      }
    }

    return findings;
  }

  private async scanXmlConfig(configPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    // Simple regex-based XML parsing for common security settings
    const securityPatterns = [
      { pattern: /<debug>true<\/debug>/gi, issue: 'Debug mode enabled', severity: SeverityLevel.MEDIUM },
      { pattern: /<cors.*origin="\*".*>/gi, issue: 'CORS allows all origins', severity: SeverityLevel.MEDIUM },
      { pattern: /<ssl.*enabled="false".*>/gi, issue: 'SSL/TLS disabled', severity: SeverityLevel.HIGH },
      { pattern: /<authentication.*enabled="false".*>/gi, issue: 'Authentication disabled', severity: SeverityLevel.HIGH }
    ];

    for (const { pattern, issue, severity } of securityPatterns) {
      if (pattern.test(content)) {
        findings.push(
          this.createFinding(
            VulnerabilityType.CONFIGURATION_ISSUE,
            severity,
            issue,
            `Security misconfiguration found: ${issue}`,
            { file: configPath, line: 1, context: content.substring(0, 200) },
            `Found ${issue} in XML configuration`,
            'Review and fix security configuration settings',
            { cwe: ['CWE-16'], tags: ['configuration', 'xml'] }
          )
        );
      }
    }

    return findings;
  }

  private async scanGenericConfig(configPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    // Check for common security issues in any config file
    const securityIssues = [
      { pattern: /debug\s*=\s*true/gi, issue: 'Debug mode enabled', severity: SeverityLevel.MEDIUM },
      { pattern: /cors.*origin.*\*/gi, issue: 'CORS allows all origins', severity: SeverityLevel.MEDIUM },
      { pattern: /ssl.*=.*false/gi, issue: 'SSL/TLS disabled', severity: SeverityLevel.HIGH },
      { pattern: /auth.*=.*false/gi, issue: 'Authentication disabled', severity: SeverityLevel.HIGH },
      { pattern: /password.*=.*[^\\s]+/gi, issue: 'Hardcoded password', severity: SeverityLevel.HIGH }
    ];

    for (const { pattern, issue, severity } of securityIssues) {
      if (pattern.test(content)) {
        findings.push(
          this.createFinding(
            VulnerabilityType.CONFIGURATION_ISSUE,
            severity,
            issue,
            `Security misconfiguration found: ${issue}`,
            { file: configPath, line: 1, context: content.substring(0, 200) },
            `Found ${issue} in configuration`,
            'Review and fix security configuration settings',
            { cwe: ['CWE-16'], tags: ['configuration'] }
          )
        );
      }
    }

    return findings;
  }

  private checkSecurityHeaders(config: any, configPath: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for missing security headers
    const securityHeaders = ['X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Strict-Transport-Security'];
    
    for (const header of securityHeaders) {
      if (!this.hasSecurityHeader(config, header)) {
        findings.push(
          this.createFinding(
            VulnerabilityType.CONFIGURATION_ISSUE,
            SeverityLevel.MEDIUM,
            `Missing security header: ${header}`,
            `Security header ${header} is not configured`,
            { file: configPath, line: 1, context: JSON.stringify(config).substring(0, 200) },
            `Missing ${header} header configuration`,
            `Add ${header} header to improve security`,
            { cwe: ['CWE-693'], tags: ['configuration', 'headers'] }
          )
        );
      }
    }

    return findings;
  }

  private checkCorsConfig(config: any, configPath: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for overly permissive CORS configuration
    if (this.hasOverlyPermissiveCors(config)) {
      findings.push(
        this.createFinding(
          VulnerabilityType.CONFIGURATION_ISSUE,
          SeverityLevel.MEDIUM,
          'Overly permissive CORS configuration',
          'CORS is configured to allow all origins, which can lead to security issues',
          { file: configPath, line: 1, context: JSON.stringify(config).substring(0, 200) },
          'CORS allows all origins (*)',
          'Configure CORS to only allow specific trusted origins',
          { cwe: ['CWE-942'], tags: ['configuration', 'cors'] }
        )
      );
    }

    return findings;
  }

  private checkAuthenticationConfig(config: any, configPath: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for weak authentication settings
    if (this.hasWeakAuthentication(config)) {
      findings.push(
        this.createFinding(
          VulnerabilityType.AUTHENTICATION_ISSUE,
          SeverityLevel.HIGH,
          'Weak authentication configuration',
          'Authentication is configured with weak settings',
          { file: configPath, line: 1, context: JSON.stringify(config).substring(0, 200) },
          'Weak authentication settings detected',
          'Configure strong authentication with proper password policies and session management',
          { cwe: ['CWE-287'], tags: ['configuration', 'authentication'] }
        )
      );
    }

    return findings;
  }

  private checkDatabaseConfig(config: any, configPath: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for insecure database configuration
    if (this.hasInsecureDatabaseConfig(config)) {
      findings.push(
        this.createFinding(
          VulnerabilityType.CONFIGURATION_ISSUE,
          SeverityLevel.HIGH,
          'Insecure database configuration',
          'Database is configured with insecure settings',
          { file: configPath, line: 1, context: JSON.stringify(config).substring(0, 200) },
          'Insecure database configuration detected',
          'Configure database with proper authentication, encryption, and access controls',
          { cwe: ['CWE-89'], tags: ['configuration', 'database'] }
        )
      );
    }

    return findings;
  }

  private checkLoggingConfig(config: any, configPath: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for sensitive information in logs
    if (this.hasSensitiveLogging(config)) {
      findings.push(
        this.createFinding(
          VulnerabilityType.LOGGING_ISSUE,
          SeverityLevel.MEDIUM,
          'Sensitive information in logs',
          'Logging configuration may expose sensitive information',
          { file: configPath, line: 1, context: JSON.stringify(config).substring(0, 200) },
          'Sensitive information may be logged',
          'Configure logging to exclude sensitive information like passwords, tokens, and PII',
          { cwe: ['CWE-532'], tags: ['configuration', 'logging'] }
        )
      );
    }

    return findings;
  }

  private checkSslConfig(config: any, configPath: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for SSL/TLS misconfigurations
    if (this.hasWeakSslConfig(config)) {
      findings.push(
        this.createFinding(
          VulnerabilityType.CONFIGURATION_ISSUE,
          SeverityLevel.HIGH,
          'Weak SSL/TLS configuration',
          'SSL/TLS is configured with weak settings',
          { file: configPath, line: 1, context: JSON.stringify(config).substring(0, 200) },
          'Weak SSL/TLS configuration detected',
          'Configure SSL/TLS with strong ciphers and proper certificate validation',
          { cwe: ['CWE-327'], tags: ['configuration', 'ssl'] }
        )
      );
    }

    return findings;
  }

  private checkFileUploadConfig(config: any, configPath: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for insecure file upload settings
    if (this.hasInsecureFileUpload(config)) {
      findings.push(
        this.createFinding(
          VulnerabilityType.CONFIGURATION_ISSUE,
          SeverityLevel.MEDIUM,
          'Insecure file upload configuration',
          'File upload is configured with insecure settings',
          { file: configPath, line: 1, context: JSON.stringify(config).substring(0, 200) },
          'Insecure file upload configuration detected',
          'Configure file upload with proper validation, size limits, and type restrictions',
          { cwe: ['CWE-434'], tags: ['configuration', 'file-upload'] }
        )
      );
    }

    return findings;
  }

  private checkRateLimitingConfig(config: any, configPath: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for missing rate limiting
    if (this.hasNoRateLimiting(config)) {
      findings.push(
        this.createFinding(
          VulnerabilityType.CONFIGURATION_ISSUE,
          SeverityLevel.MEDIUM,
          'Missing rate limiting configuration',
          'Rate limiting is not configured, which can lead to abuse',
          { file: configPath, line: 1, context: JSON.stringify(config).substring(0, 200) },
          'No rate limiting configuration found',
          'Configure rate limiting to prevent abuse and DoS attacks',
          { cwe: ['CWE-400'], tags: ['configuration', 'rate-limiting'] }
        )
      );
    }

    return findings;
  }

  private checkEnvironmentConfig(config: any, configPath: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for development settings in production
    if (this.hasDevelopmentSettings(config)) {
      findings.push(
        this.createFinding(
          VulnerabilityType.CONFIGURATION_ISSUE,
          SeverityLevel.MEDIUM,
          'Development settings in production',
          'Configuration contains development settings that should not be in production',
          { file: configPath, line: 1, context: JSON.stringify(config).substring(0, 200) },
          'Development settings detected in production configuration',
          'Remove development settings and use production-appropriate configuration',
          { cwe: ['CWE-16'], tags: ['configuration', 'environment'] }
        )
      );
    }

    return findings;
  }

  private checkIniSetting(key: string, value: string, configPath: string, lineNumber: number, lineContent: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for common security issues in INI files
    if (key.toLowerCase().includes('debug') && value.toLowerCase() === 'true') {
      findings.push(
        this.createFinding(
          VulnerabilityType.CONFIGURATION_ISSUE,
          SeverityLevel.MEDIUM,
          'Debug mode enabled',
          'Debug mode is enabled in configuration',
          { file: configPath, line: lineNumber, context: lineContent },
          `Debug setting: ${key}=${value}`,
          'Disable debug mode in production environments',
          { cwe: ['CWE-489'], tags: ['configuration', 'debug'] }
        )
      );
    }

    return findings;
  }

  private checkPropertiesSetting(key: string, value: string, configPath: string, lineNumber: number, lineContent: string): Finding[] {
    const findings: Finding[] = [];
    
    // Check for common security issues in properties files
    if (key.toLowerCase().includes('password') && value.length > 0) {
      findings.push(
        this.createFinding(
          VulnerabilityType.HARDCODED_SECRET,
          SeverityLevel.HIGH,
          'Hardcoded password in properties',
          'Password is hardcoded in configuration file',
          { file: configPath, line: lineNumber, context: lineContent },
          `Hardcoded password: ${key}=${value}`,
          'Use environment variables or secure secret management for passwords',
          { cwe: ['CWE-259'], tags: ['configuration', 'password'] }
        )
      );
    }

    return findings;
  }

  private initializeConfigPatterns(): Map<string, any[]> {
    const patterns = new Map<string, any[]>();
    
    // Security Headers patterns
    patterns.set('security_headers', [
      { pattern: /X-Frame-Options/i, required: true },
      { pattern: /X-Content-Type-Options/i, required: true },
      { pattern: /X-XSS-Protection/i, required: true },
      { pattern: /Strict-Transport-Security/i, required: true }
    ]);

    // CORS patterns
    patterns.set('cors', [
      { pattern: /origin.*\*/i, issue: 'Wildcard origin' },
      { pattern: /credentials.*true/i, issue: 'Credentials with wildcard origin' }
    ]);

    // Authentication patterns
    patterns.set('authentication', [
      { pattern: /auth.*false/i, issue: 'Authentication disabled' },
      { pattern: /password.*policy/i, required: true }
    ]);

    return patterns;
  }

  private hasSecurityHeader(config: any, header: string): boolean {
    // Check if security header is configured
    return this.searchConfig(config, header) !== null;
  }

  private hasOverlyPermissiveCors(config: any): boolean {
    // Check for wildcard CORS origin
    return this.searchConfig(config, 'origin.*\\*') !== null;
  }

  private hasWeakAuthentication(config: any): boolean {
    // Check for weak authentication settings
    return this.searchConfig(config, 'auth.*false') !== null;
  }

  private hasInsecureDatabaseConfig(config: any): boolean {
    // Check for insecure database settings
    return this.searchConfig(config, 'ssl.*false') !== null;
  }

  private hasSensitiveLogging(config: any): boolean {
    // Check for sensitive information in logging
    return this.searchConfig(config, 'log.*password') !== null;
  }

  private hasWeakSslConfig(config: any): boolean {
    // Check for weak SSL settings
    return this.searchConfig(config, 'ssl.*weak') !== null;
  }

  private hasInsecureFileUpload(config: any): boolean {
    // Check for insecure file upload settings
    return this.searchConfig(config, 'upload.*unrestricted') !== null;
  }

  private hasNoRateLimiting(config: any): boolean {
    // Check for missing rate limiting
    return this.searchConfig(config, 'rate.*limit') === null;
  }

  private hasDevelopmentSettings(config: any): boolean {
    // Check for development settings
    return this.searchConfig(config, 'debug.*true') !== null;
  }

  private searchConfig(config: any, pattern: string): any {
    // Recursively search configuration object for pattern
    const regex = new RegExp(pattern, 'i');
    
    const search = (obj: any): any => {
      if (typeof obj === 'string' && regex.test(obj)) {
        return obj;
      }
      if (typeof obj === 'object' && obj !== null) {
        for (const [key, value] of Object.entries(obj)) {
          if (regex.test(key)) {
            return { key, value };
          }
          const result = search(value);
          if (result) {
            return result;
          }
        }
      }
      return null;
    };
    
    return search(config);
  }

  private async glob(pattern: string, options: any): Promise<string[]> {
    // Simple glob implementation - in a real implementation, use a proper glob library
    const { glob } = await import('glob');
    return glob(pattern, options);
  }
}

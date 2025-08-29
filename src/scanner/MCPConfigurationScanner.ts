import { BaseScanner } from './BaseScanner.js';
import { Finding, VulnerabilityType, SeverityLevel } from '../types/index.js';

export interface MCPConfigCheck {
  name: string;
  description: string;
  severity: SeverityLevel;
  category: 'auth' | 'transport' | 'cors' | 'rate-limiting' | 'sandboxing' | 'stdio';
  required: boolean;
  check: (config: any) => boolean;
  remediation: string;
}

export class MCPConfigurationScanner extends BaseScanner {
  private mcpConfigChecks: MCPConfigCheck[];

  constructor() {
    super('MCP Configuration Scanner');
    this.initializeMCPChecks();
  }

  /**
   * Initialize MCP-specific security checks
   */
  private initializeMCPChecks(): void {
    this.mcpConfigChecks = [
      // Authentication checks
      {
        name: 'Authentication Required',
        description: 'MCP server must require authentication',
        severity: SeverityLevel.HIGH,
        category: 'auth',
        required: true,
        check: (config: any) => {
          return config.auth && (
            config.auth.type === 'bearer' ||
            config.auth.type === 'api-key' ||
            config.auth.type === 'oauth2'
          );
        },
        remediation: 'Add authentication configuration with bearer token, API key, or OAuth2'
      },
      {
        name: 'TLS Encryption',
        description: 'MCP server must use TLS encryption',
        severity: SeverityLevel.HIGH,
        category: 'transport',
        required: true,
        check: (config: any) => {
          return config.transport && config.transport.tls === true;
        },
        remediation: 'Enable TLS encryption in transport configuration'
      },

      // CORS and CSP checks
      {
        name: 'CORS Configuration',
        description: 'MCP server must have restrictive CORS policy',
        severity: SeverityLevel.MEDIUM,
        category: 'cors',
        required: true,
        check: (config: any) => {
          return config.cors && 
                 config.cors.origin && 
                 config.cors.origin !== '*' &&
                 config.cors.methods &&
                 config.cors.methods.length > 0;
        },
        remediation: 'Configure restrictive CORS policy with specific origins and methods'
      },
      {
        name: 'Content Security Policy',
        description: 'MCP server should have CSP headers',
        severity: SeverityLevel.MEDIUM,
        category: 'cors',
        required: false,
        check: (config: any) => {
          return config.csp && config.csp.directives && Object.keys(config.csp.directives).length > 0;
        },
        remediation: 'Add Content Security Policy headers with restrictive directives'
      },

      // Rate limiting checks
      {
        name: 'Rate Limiting',
        description: 'MCP server must implement rate limiting',
        severity: SeverityLevel.MEDIUM,
        category: 'rate-limiting',
        required: true,
        check: (config: any) => {
          return config.rateLimit && 
                 config.rateLimit.requests && 
                 config.rateLimit.window &&
                 config.rateLimit.requests > 0 &&
                 config.rateLimit.window > 0;
        },
        remediation: 'Configure rate limiting with requests per time window'
      },
      {
        name: 'Quota Management',
        description: 'MCP server should have resource quotas',
        severity: SeverityLevel.MEDIUM,
        category: 'rate-limiting',
        required: false,
        check: (config: any) => {
          return config.quotas && (
            config.quotas.memory ||
            config.quotas.cpu ||
            config.quotas.requests ||
            config.quotas.storage
          );
        },
        remediation: 'Add resource quotas for memory, CPU, requests, and storage'
      },

      // Sandboxing checks
      {
        name: 'Sandboxing Enabled',
        description: 'MCP server should run in sandboxed environment',
        severity: SeverityLevel.HIGH,
        category: 'sandboxing',
        required: true,
        check: (config: any) => {
          return config.sandbox && (
            config.sandbox.enabled === true ||
            config.sandbox.mode === 'docker' ||
            config.sandbox.mode === 'process'
          );
        },
        remediation: 'Enable sandboxing with Docker or process isolation'
      },
      {
        name: 'Resource Limits',
        description: 'MCP server should have resource limits',
        severity: SeverityLevel.MEDIUM,
        category: 'sandboxing',
        required: false,
        check: (config: any) => {
          return config.limits && (
            config.limits.memory ||
            config.limits.cpu ||
            config.limits.pids ||
            config.limits.fileSize
          );
        },
        remediation: 'Set resource limits for memory, CPU, PIDs, and file size'
      },

      // stdio security checks
      {
        name: 'Public stdio Disabled',
        description: 'MCP server should not expose public stdio',
        severity: SeverityLevel.HIGH,
        category: 'stdio',
        required: true,
        check: (config: any) => {
          return !config.stdio || config.stdio.public !== true;
        },
        remediation: 'Disable public stdio access or restrict to authenticated users'
      },
      {
        name: 'stdio Authentication',
        description: 'stdio access should require authentication',
        severity: SeverityLevel.MEDIUM,
        category: 'stdio',
        required: false,
        check: (config: any) => {
          return !config.stdio || config.stdio.auth === true;
        },
        remediation: 'Require authentication for stdio access'
      }
    ];
  }

  /**
   * Scan for MCP configuration vulnerabilities
   */
  async scan(targetPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      // Look for MCP configuration files
      const configFiles = await this.findMCPConfigFiles(targetPath);
      
      for (const configFile of configFiles) {
        const config = await this.loadMCPConfig(configFile);
        if (config) {
          const fileFindings = this.analyzeMCPConfig(config, configFile);
          findings.push(...fileFindings);
        }
      }

      // If no MCP config found, create a finding for missing configuration
      if (configFiles.length === 0) {
        findings.push(this.createFinding({
          type: VulnerabilityType.CONFIGURATION,
          severity: SeverityLevel.HIGH,
          title: 'Missing MCP Configuration',
          description: 'No MCP configuration file found. Server may be running with insecure defaults.',
          file: 'mcp-config.json',
          line: 1,
          snippet: 'No MCP configuration detected',
          remediation: 'Create mcp-config.json with security hardening settings',
          tags: ['mcp', 'configuration', 'missing']
        }));
      }

    } catch (error) {
      console.error('Error scanning MCP configuration:', error);
    }

    return findings;
  }

  /**
   * Find MCP configuration files
   */
  private async findMCPConfigFiles(targetPath: string): Promise<string[]> {
    const patterns = [
      '**/mcp-config.json',
      '**/mcp-config.yaml',
      '**/mcp-config.yml',
      '**/.mcp/config.json',
      '**/.mcp/config.yaml',
      '**/config/mcp.json',
      '**/config/mcp.yaml'
    ];

    const files: string[] = [];
    
    for (const pattern of patterns) {
      try {
        const matches = await this.glob(pattern, { cwd: targetPath });
        files.push(...matches);
      } catch (error) {
        // Pattern not found, continue
      }
    }

    return files;
  }

  /**
   * Load MCP configuration from file
   */
  private async loadMCPConfig(configFile: string): Promise<any> {
    try {
      const fs = await import('fs-extra');
      const content = await fs.readFile(configFile, 'utf8');
      
      if (configFile.endsWith('.json')) {
        return JSON.parse(content);
      } else if (configFile.endsWith('.yaml') || configFile.endsWith('.yml')) {
        const yaml = await import('js-yaml');
        return yaml.load(content);
      }
    } catch (error) {
      console.error(`Error loading MCP config ${configFile}:`, error);
    }
    
    return null;
  }

  /**
   * Analyze MCP configuration for security issues
   */
  private analyzeMCPConfig(config: any, configFile: string): Finding[] {
    const findings: Finding[] = [];

    for (const check of this.mcpConfigChecks) {
      const isCompliant = check.check(config);
      
      if (!isCompliant) {
        findings.push(this.createFinding({
          type: VulnerabilityType.CONFIGURATION,
          severity: check.severity,
          title: check.name,
          description: check.description,
          file: configFile,
          line: 1,
          snippet: JSON.stringify(config, null, 2).substring(0, 200),
          remediation: check.remediation,
          tags: ['mcp', 'configuration', check.category]
        }));
      }
    }

    return findings;
  }

  /**
   * Generate MCP hardened configuration template
   */
  generateHardenedConfig(): string {
    return JSON.stringify({
      auth: {
        type: 'bearer',
        required: true
      },
      transport: {
        tls: true,
        certFile: '/path/to/cert.pem',
        keyFile: '/path/to/key.pem'
      },
      cors: {
        origin: ['https://trusted-client.com'],
        methods: ['GET', 'POST'],
        credentials: true
      },
      csp: {
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"]
        }
      },
      rateLimit: {
        requests: 100,
        window: 60000 // 1 minute
      },
      quotas: {
        memory: '512MB',
        cpu: '1.0',
        requests: 1000,
        storage: '1GB'
      },
      sandbox: {
        enabled: true,
        mode: 'docker',
        image: 'mcp-server:latest'
      },
      limits: {
        memory: '512MB',
        cpu: '1.0',
        pids: 100,
        fileSize: '10MB'
      },
      stdio: {
        public: false,
        auth: true
      }
    }, null, 2);
  }
}

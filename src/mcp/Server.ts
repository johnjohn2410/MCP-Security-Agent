import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { SecurityAgent } from '../agent/SecurityAgent.js';
import { ScanConfig } from "../types/index.js";
import { Logger } from '../utils/Logger.js';

export class MCPSecurityServer {
  private server: Server;
  private securityAgent: SecurityAgent;
  private logger: Logger;

  constructor() {
    this.logger = new Logger('MCPServer');
    
    // Initialize with a default config
    const cfg: ScanConfig = {
      path: process.cwd(),
      scanType: "comprehensive",
      // @ts-ignore (optional)
      scanTypes: ["code", "secrets", "dependencies", "config"],
      outputFormat: "json",

      includePatterns: [],
      excludePatterns: [],
      maxDepth: 10,
      timeout: 300_000,
      concurrent: 4,

      dataHandling: {
        redactSecrets: true,
        redactPII: true,
        tokenizeCode: false,
        maxCodeSnippetSize: 400,
        maxFileSize: 5_000_000,
        allowedFileTypes: [],
        excludedPaths: [],
        privacyStatement: "",
        dataRetentionDays: 30,
      },
      auditLogging: true,
      generateSBOM: true,
      generateVEX: true,
      performanceMonitoring: true,
      complianceMapping: true,
      offlineMode: false,
      aiAnalysis: { enabled: false, costLimit: 0, latencyLimit: 2000, privacyControls: true },
    };

    this.securityAgent = new SecurityAgent(cfg);

    this.server = new Server(
      {
        name: 'mcp-security-agent',
        version: '1.0.0',
      }
    );

    this.setupToolHandlers();
  }

  private setupToolHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'scan_security',
            description: 'Perform a comprehensive security scan on a directory or file',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to scan (file or directory)',
                },
                scanType: {
                  type: 'string',
                  enum: ['quick', 'comprehensive', 'targeted'],
                  description: 'Type of scan to perform',
                  default: 'comprehensive',
                },
                targets: {
                  type: 'string',
                  description: 'Comma-separated scan targets: code,secrets,dependencies,config,policy',
                },
                outputFormat: {
                  type: 'string',
                  enum: ['json', 'html', 'csv', 'pdf', 'sarif'],
                  description: 'Output format for results',
                  default: 'json',
                },
              },
              required: ['path'],
            },
          },
          {
            name: 'analyze_vulnerabilities',
            description: 'Analyze specific vulnerability types in a codebase',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to analyze',
                },
                vulnerabilityTypes: {
                  type: 'string',
                  description: 'Comma-separated vulnerability types to analyze',
                },
              },
              required: ['path'],
            },
          },
          {
            name: 'scan_dependencies',
            description: 'Scan project dependencies for vulnerabilities',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Project path to scan',
                },
                packageManagers: {
                  type: 'string',
                  description: 'Comma-separated package managers to check',
                },
              },
              required: ['path'],
            },
          },
          {
            name: 'scan_secrets',
            description: 'Scan for hardcoded secrets and sensitive information',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to scan for secrets',
                },
                secretTypes: {
                  type: 'string',
                  description: 'Comma-separated secret types to scan for',
                },
              },
              required: ['path'],
            },
          },
          {
            name: 'generate_report',
            description: 'Generate a comprehensive security report',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to scan for report',
                },
                format: {
                  type: 'string',
                  enum: ['json', 'html', 'csv', 'pdf', 'sarif'],
                  description: 'Report format',
                  default: 'html',
                },
              },
              required: ['path'],
            },
          },
          {
            name: 'check_policies',
            description: 'Check security policies against a codebase',
            inputSchema: {
              type: 'object',
              properties: {
                path: {
                  type: 'string',
                  description: 'Path to check policies against',
                },
                policyNames: {
                  type: 'string',
                  description: 'Comma-separated policy names to check',
                },
              },
              required: ['path'],
            },
          },
          {
            name: 'perform_ai_analysis',
            description: 'Perform AI-powered security analysis on findings',
            inputSchema: {
              type: 'object',
              properties: {
                findings: {
                  type: 'array',
                  description: 'Array of security findings to analyze',
                },
                context: {
                  type: 'object',
                  description: 'Additional context for analysis',
                },
              },
              required: ['findings'],
            },
          },
        ],
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'scan_security': {
            const { path, scanType = 'comprehensive', targets, outputFormat = 'json' } = args as any;
            
            const cfg: ScanConfig = {
              path,
              scanType,
              // @ts-ignore (optional)
              scanTypes: targets ? targets.split(',') : undefined,
              outputFormat,

              includePatterns: [],
              excludePatterns: [],
              maxDepth: 10,
              timeout: 300_000,
              concurrent: 4,

              dataHandling: {
                redactSecrets: true,
                redactPII: true,
                tokenizeCode: false,
                maxCodeSnippetSize: 400,
                maxFileSize: 5_000_000,
                allowedFileTypes: [],
                excludedPaths: [],
                privacyStatement: "",
                dataRetentionDays: 30,
              },
              auditLogging: true,
              generateSBOM: true,
              generateVEX: true,
              performanceMonitoring: true,
              complianceMapping: true,
              offlineMode: false,
              aiAnalysis: { enabled: false, costLimit: 0, latencyLimit: 2000, privacyControls: true },
            };

            const results = await this.securityAgent.scan(path, cfg);

            return {
              content: [
                {
                  type: 'text',
                  text: `Security scan completed. Found ${results.findings.length} vulnerabilities.`,
                },
                {
                  type: 'text',
                  text: JSON.stringify(results, null, 2),
                },
              ],
            };
          }

          case 'analyze_vulnerabilities': {
            const { path, vulnerabilityTypes } = args as any;
            
            const cfg: ScanConfig = {
              path,
              scanType: 'targeted',
              // @ts-ignore (optional)
              scanTypes: vulnerabilityTypes ? vulnerabilityTypes.split(',') : ['code'],
              outputFormat: 'json',

              includePatterns: [],
              excludePatterns: [],
              maxDepth: 10,
              timeout: 300_000,
              concurrent: 4,

              dataHandling: {
                redactSecrets: true,
                redactPII: true,
                tokenizeCode: false,
                maxCodeSnippetSize: 400,
                maxFileSize: 5_000_000,
                allowedFileTypes: [],
                excludedPaths: [],
                privacyStatement: "",
                dataRetentionDays: 30,
              },
              auditLogging: true,
              generateSBOM: true,
              generateVEX: true,
              performanceMonitoring: true,
              complianceMapping: true,
              offlineMode: false,
              aiAnalysis: { enabled: false, costLimit: 0, latencyLimit: 2000, privacyControls: true },
            };

            const results = await this.securityAgent.scan(path, cfg);

            return {
              content: [
                {
                  type: 'text',
                  text: `Vulnerability analysis completed. Found ${results.findings.length} issues.`,
                },
                {
                  type: 'text',
                  text: JSON.stringify(results, null, 2),
                },
              ],
            };
          }

          case 'scan_dependencies': {
            const { path, packageManagers } = args as any;
            
            const cfg: ScanConfig = {
              path,
              scanType: 'quick',
              // @ts-ignore (optional)
              scanTypes: ['dependencies'],
              outputFormat: 'json',

              includePatterns: [],
              excludePatterns: [],
              maxDepth: 10,
              timeout: 300_000,
              concurrent: 4,

              dataHandling: {
                redactSecrets: true,
                redactPII: true,
                tokenizeCode: false,
                maxCodeSnippetSize: 400,
                maxFileSize: 5_000_000,
                allowedFileTypes: [],
                excludedPaths: [],
                privacyStatement: "",
                dataRetentionDays: 30,
              },
              auditLogging: true,
              generateSBOM: true,
              generateVEX: true,
              performanceMonitoring: true,
              complianceMapping: true,
              offlineMode: false,
              aiAnalysis: { enabled: false, costLimit: 0, latencyLimit: 2000, privacyControls: true },
            };

            const results = await this.securityAgent.scan(path, cfg);

            return {
              content: [
                {
                  type: 'text',
                  text: `Dependency scan completed. Found ${results.findings.length} vulnerable dependencies.`,
                },
                {
                  type: 'text',
                  text: JSON.stringify(results, null, 2),
                },
              ],
            };
          }

          case 'scan_secrets': {
            const { path, secretTypes } = args as any;
            
            const cfg: ScanConfig = {
              path,
              scanType: 'quick',
              // @ts-ignore (optional)
              scanTypes: ['secrets'],
              outputFormat: 'json',

              includePatterns: [],
              excludePatterns: [],
              maxDepth: 10,
              timeout: 300_000,
              concurrent: 4,

              dataHandling: {
                redactSecrets: true,
                redactPII: true,
                tokenizeCode: false,
                maxCodeSnippetSize: 400,
                maxFileSize: 5_000_000,
                allowedFileTypes: [],
                excludedPaths: [],
                privacyStatement: "",
                dataRetentionDays: 30,
              },
              auditLogging: true,
              generateSBOM: true,
              generateVEX: true,
              performanceMonitoring: true,
              complianceMapping: true,
              offlineMode: false,
              aiAnalysis: { enabled: false, costLimit: 0, latencyLimit: 2000, privacyControls: true },
            };

            const results = await this.securityAgent.scan(path, cfg);

            return {
              content: [
                {
                  type: 'text',
                  text: `Secret scan completed. Found ${results.findings.length} potential secrets.`,
                },
                {
                  type: 'text',
                  text: JSON.stringify(results, null, 2),
                },
              ],
            };
          }

          case 'generate_report': {
            const { path, format = 'html' } = args as any;
            
            const cfg: ScanConfig = {
              path,
              scanType: 'comprehensive',
              outputFormat: format,

              includePatterns: [],
              excludePatterns: [],
              maxDepth: 10,
              timeout: 300_000,
              concurrent: 4,

              dataHandling: {
                redactSecrets: true,
                redactPII: true,
                tokenizeCode: false,
                maxCodeSnippetSize: 400,
                maxFileSize: 5_000_000,
                allowedFileTypes: [],
                excludedPaths: [],
                privacyStatement: "",
                dataRetentionDays: 30,
              },
              auditLogging: true,
              generateSBOM: true,
              generateVEX: true,
              performanceMonitoring: true,
              complianceMapping: true,
              offlineMode: false,
              aiAnalysis: { enabled: false, costLimit: 0, latencyLimit: 2000, privacyControls: true },
            };

            const report = await this.securityAgent.scan(path, cfg);

            return {
              content: [
                {
                  type: 'text',
                  text: `Security report generated. Found ${report.findings.length} findings.`,
                },
                {
                  type: 'text',
                  text: JSON.stringify(report, null, 2),
                },
              ],
            };
          }

          case 'check_policies': {
            const { path, policyNames } = args as any;
            
            const cfg: ScanConfig = {
              path,
              scanType: 'targeted',
              // @ts-ignore (optional)
              scanTypes: ['policy'],
              outputFormat: 'json',

              includePatterns: [],
              excludePatterns: [],
              maxDepth: 10,
              timeout: 300_000,
              concurrent: 4,

              dataHandling: {
                redactSecrets: true,
                redactPII: true,
                tokenizeCode: false,
                maxCodeSnippetSize: 400,
                maxFileSize: 5_000_000,
                allowedFileTypes: [],
                excludedPaths: [],
                privacyStatement: "",
                dataRetentionDays: 30,
              },
              auditLogging: true,
              generateSBOM: true,
              generateVEX: true,
              performanceMonitoring: true,
              complianceMapping: true,
              offlineMode: false,
              aiAnalysis: { enabled: false, costLimit: 0, latencyLimit: 2000, privacyControls: true },
            };

            const results = await this.securityAgent.scan(path, cfg);

            return {
              content: [
                {
                  type: 'text',
                  text: `Policy check completed. Found ${results.policyResults.length} policy violations.`,
                },
                {
                  type: 'text',
                  text: JSON.stringify(results, null, 2),
                },
              ],
            };
          }

          case 'perform_ai_analysis': {
            const { findings, context } = args as any;
            
            // For now, return a placeholder response
            return {
              content: [
                {
                  type: 'text',
                  text: 'AI analysis feature is not yet implemented.',
                },
              ],
            };
          }

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        this.logger.error(`Error executing tool ${name}`, error as Error);
        throw error;
      }
    });
  }

  async start() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    this.logger.info('MCP Security Server started');
  }

  async stop() {
    await this.server.close();
    this.logger.info('MCP Security Server stopped');
  }
}

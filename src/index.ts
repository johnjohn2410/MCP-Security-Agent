#!/usr/bin/env node

import { Command } from 'commander';
import { ScanConfig } from "./types/index.js";
import { SecurityAgent } from "./agent/SecurityAgent.js";
import { Logger } from './utils/Logger.js';
import path from 'path';
import fs from 'fs-extra';

const program = new Command();
const logger = new Logger('CLI');

function buildConfig(opts: {
  path: string;
  type?: "quick" | "comprehensive" | "targeted";
  targets?: string; // comma-separated: code,secrets,dependencies,config,policy
  format?: "json" | "html" | "csv" | "pdf" | "sarif";
}): ScanConfig {
  return {
    path: opts.path,
    scanType: opts.type ?? "comprehensive",
    // @ts-ignore (compiled types may not have scanTypes yet)
    scanTypes: opts.targets ? (opts.targets.split(",") as any) : undefined,
    outputFormat: opts.format ?? "json",
    // @ts-ignore (optional multi-format)
    outputFormats: undefined,

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
}

program
  .name('mcp-security-agent')
  .description('MCP Security Agent - Comprehensive security scanning and analysis')
  .version('1.0.0');

// Main scan command
program
  .command('scan')
  .description('Perform comprehensive security scan')
  .argument('<path>', 'Path to scan (file or directory)')
  .option('-t, --type <type>', 'Scan type: quick, comprehensive, or targeted', 'comprehensive')
  .option('--targets <targets>', 'Comma-separated scan targets: code,secrets,dependencies,config,policy')
  .option('-f, --format <format>', 'Output format: json, html, csv, pdf, sarif', 'json')
  .option('--include <patterns>', 'Include file patterns (comma-separated)')
  .option('--exclude <patterns>', 'Exclude file patterns (comma-separated)')
  .option('--max-depth <depth>', 'Maximum directory depth', '10')
  .option('--timeout <ms>', 'Scan timeout in milliseconds', '300000')
  .action(async (scanPath, options) => {
    try {
      logger.info('Starting security scan', { path: scanPath, options });

      const cfg = buildConfig({ 
        path: scanPath, 
        type: options.type, 
        targets: options.targets, 
        format: options.format 
      });
      const agent = new SecurityAgent(cfg);
      const report = await agent.scan(scanPath, cfg);

      // Print results
      console.log(JSON.stringify(report, null, 2));
      
      logger.info('Scan completed successfully', {
        findings: report.findings.length,
        scanDuration: report.performance.scanDuration
      });

    } catch (error) {
      logger.error('Scan failed', error as Error);
      process.exit(1);
    }
  });

// Policy management command
program
  .command('policy')
  .description('Manage security policies')
  .option('--list', 'List all policies')
  .option('--add <policy-file>', 'Add policy from file')
  .option('--remove <policy-id>', 'Remove policy by ID')
  .action(async (options) => {
    try {
      logger.info('Policy management', { options });

      const cfg = buildConfig({ path: process.cwd() });
      const agent = new SecurityAgent(cfg);

      if (options.list) {
        // For now, just show that policies are managed by the PolicyEngine
        console.log('Policies are managed internally by the PolicyEngine');
      } else if (options.add) {
        console.log('Policy addition not yet implemented');
      } else if (options.remove) {
        console.log('Policy removal not yet implemented');
      } else {
        console.log('Use --list, --add, or --remove options');
      }

    } catch (error) {
      logger.error('Policy operation failed', error as Error);
      process.exit(1);
    }
  });

// Vulnerability analysis command
program
  .command('analyze')
  .description('Analyze specific vulnerabilities')
  .argument('<path>', 'Path to analyze')
  .option('--types <types>', 'Vulnerability types to analyze (comma-separated)')
  .option('-f, --format <format>', 'Output format', 'json')
  .action(async (analyzePath, options) => {
    try {
      logger.info('Starting vulnerability analysis', { path: analyzePath, options });

      const cfg = buildConfig({ 
        path: analyzePath, 
        type: 'targeted',
        targets: options.types,
        format: options.format 
      });
      const agent = new SecurityAgent(cfg);
      const report = await agent.scan(analyzePath, cfg);

      // Print results
      console.log(JSON.stringify(report, null, 2));

    } catch (error) {
      logger.error('Analysis failed', error as Error);
      process.exit(1);
    }
  });

// Dependency scan command
program
  .command('deps')
  .description('Scan dependencies for vulnerabilities')
  .argument('<path>', 'Project path to scan')
  .option('--managers <managers>', 'Package managers to check (comma-separated)')
  .option('-f, --format <format>', 'Output format', 'json')
  .action(async (projectPath, options) => {
    try {
      logger.info('Starting dependency scan', { path: projectPath, options });

      const cfg = buildConfig({ 
        path: projectPath, 
        type: 'quick',
        targets: 'dependencies',
        format: options.format 
      });
      const agent = new SecurityAgent(cfg);
      const report = await agent.scan(projectPath, cfg);

      // Print results
      console.log(JSON.stringify(report, null, 2));

    } catch (error) {
      logger.error('Dependency scan failed', error as Error);
      process.exit(1);
    }
  });

// Secret scan command
program
  .command('secrets')
  .description('Scan for hardcoded secrets')
  .argument('<path>', 'Path to scan')
  .option('--types <types>', 'Secret types to scan for (comma-separated)')
  .option('-f, --format <format>', 'Output format', 'json')
  .action(async (scanPath, options) => {
    try {
      logger.info('Starting secret scan', { path: scanPath, options });

      const cfg = buildConfig({ 
        path: scanPath, 
        type: 'quick',
        targets: 'secrets',
        format: options.format 
      });
      const agent = new SecurityAgent(cfg);
      const report = await agent.scan(scanPath, cfg);

      // Print results
      console.log(JSON.stringify(report, null, 2));

    } catch (error) {
      logger.error('Secret scan failed', error as Error);
      process.exit(1);
    }
  });

// Report generation command
program
  .command('report')
  .description('Generate security report')
  .argument('<path>', 'Path to scan for report')
  .option('-f, --format <format>', 'Report format: json, html, csv, pdf, sarif', 'html')
  .action(async (reportPath, options) => {
    try {
      logger.info('Generating security report', { path: reportPath, options });

      const cfg = buildConfig({ 
        path: reportPath, 
        format: options.format 
      });
      const agent = new SecurityAgent(cfg);
      const report = await agent.scan(reportPath, cfg);

      // Print results
      console.log(JSON.stringify(report, null, 2));

    } catch (error) {
      logger.error('Report generation failed', error as Error);
      process.exit(1);
    }
  });

program.parse();

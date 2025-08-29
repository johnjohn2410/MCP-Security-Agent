import { Finding, ScanConfig, VulnerabilityType, SeverityLevel } from '../types/index.js';
import { BaseScanner } from './BaseScanner.js';
import { Logger } from '../utils/Logger.js';
import fs from 'fs-extra';
import path from 'path';

export class DependencyScanner extends BaseScanner {
  constructor() {
    super('DependencyScanner', 'Scans for vulnerable and outdated dependencies', [
      'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
      'requirements.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock',
      'pom.xml', 'build.gradle', 'build.gradle.kts',
      'go.mod', 'go.sum', 'Cargo.toml', 'Cargo.lock',
      'composer.json', 'composer.lock', 'Gemfile', 'Gemfile.lock',
      'mix.exs', 'mix.lock'
    ]);
  }

  async scan(targetPath: string, config: ScanConfig): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      this.logProgress('Starting dependency scan', { path: targetPath });
      
      // Find package manifest files
      const manifestFiles = await this.findPackageManifests(targetPath);
      
      for (const manifestFile of manifestFiles) {
        const fileFindings = await this.scanManifestFile(manifestFile);
        findings.push(...fileFindings);
      }

      this.logProgress('Dependency scan completed', { findingsCount: findings.length });
      
    } catch (error) {
      this.logError('Dependency scan failed', error as Error);
    }

    return findings;
  }

  private async findPackageManifests(rootPath: string): Promise<string[]> {
    const manifestFiles: string[] = [];
    const patterns = [
      '**/package.json',
      '**/requirements.txt',
      '**/Pipfile',
      '**/poetry.lock',
      '**/pom.xml',
      '**/build.gradle',
      '**/build.gradle.kts',
      '**/go.mod',
      '**/Cargo.toml',
      '**/composer.json',
      '**/Gemfile'
    ];

    for (const pattern of patterns) {
      try {
        const files = await this.glob(pattern, { cwd: rootPath, absolute: true });
        manifestFiles.push(...files);
      } catch (error) {
        // Pattern not found, continue
      }
    }

    return manifestFiles;
  }

  private async scanManifestFile(manifestPath: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      const content = await fs.readFile(manifestPath, 'utf-8');
      const ext = path.extname(manifestPath);
      
      switch (ext) {
        case '.json':
          if (path.basename(manifestPath) === 'package.json') {
            findings.push(...await this.scanNpmPackage(manifestPath, content));
          }
          break;
        case '.txt':
          if (path.basename(manifestPath) === 'requirements.txt') {
            findings.push(...await this.scanPythonRequirements(manifestPath, content));
          }
          break;
        case '.xml':
          if (path.basename(manifestPath) === 'pom.xml') {
            findings.push(...await this.scanMavenPom(manifestPath, content));
          }
          break;
        case '.toml':
          if (path.basename(manifestPath) === 'Cargo.toml') {
            findings.push(...await this.scanCargoToml(manifestPath, content));
          }
          break;
      }
    } catch (error) {
      this.logError(`Error scanning manifest file ${manifestPath}`, error as Error);
    }

    return findings;
  }

  private async scanNpmPackage(manifestPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    try {
      const packageJson = JSON.parse(content);
      const dependencies = {
        ...packageJson.dependencies,
        ...packageJson.devDependencies,
        ...packageJson.peerDependencies
      };

      for (const [packageName, version] of Object.entries(dependencies)) {
        const vulnerabilities = await this.checkPackageVulnerabilities(packageName, version as string);
        
        if (vulnerabilities.length > 0) {
          findings.push(
            this.createFinding(
              VulnerabilityType.INSECURE_DEPENDENCY,
              SeverityLevel.HIGH,
              `Vulnerable dependency: ${packageName}`,
              `Package ${packageName}@${version} has known security vulnerabilities`,
              { file: manifestPath, line: 1, context: `"${packageName}": "${version}"` },
              `Found ${vulnerabilities.length} vulnerabilities in ${packageName}@${version}`,
              'Update to a secure version or apply security patches',
              { cwe: ['CWE-1104'], tags: ['dependencies', 'npm'] }
            )
          );
        }
      }
    } catch (error) {
      this.logError(`Error parsing package.json ${manifestPath}`, error as Error);
    }

    return findings;
  }

  private async scanPythonRequirements(manifestPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const lines = content.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line && !line.startsWith('#')) {
        const packageMatch = line.match(/^([a-zA-Z0-9_-]+)/);
        if (packageMatch) {
          const packageName = packageMatch[1];
          const vulnerabilities = await this.checkPackageVulnerabilities(packageName, 'latest');
          
          if (vulnerabilities.length > 0) {
            findings.push(
              this.createFinding(
                VulnerabilityType.INSECURE_DEPENDENCY,
                SeverityLevel.HIGH,
                `Vulnerable dependency: ${packageName}`,
                `Python package ${packageName} has known security vulnerabilities`,
                { file: manifestPath, line: i + 1, context: line },
                `Found ${vulnerabilities.length} vulnerabilities in ${packageName}`,
                'Update to a secure version or apply security patches',
                { cwe: ['CWE-1104'], tags: ['dependencies', 'python'] }
              )
            );
          }
        }
      }
    }

    return findings;
  }

  private async scanMavenPom(manifestPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    // Simple regex-based parsing for Maven dependencies
    const dependencyRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g;
    let match;
    
    while ((match = dependencyRegex.exec(content)) !== null) {
      const groupId = match[1];
      const artifactId = match[2];
      const version = match[3];
      const packageName = `${groupId}:${artifactId}`;
      
      const vulnerabilities = await this.checkPackageVulnerabilities(packageName, version);
      
      if (vulnerabilities.length > 0) {
        findings.push(
          this.createFinding(
            VulnerabilityType.INSECURE_DEPENDENCY,
            SeverityLevel.HIGH,
            `Vulnerable dependency: ${packageName}`,
            `Maven dependency ${packageName}:${version} has known security vulnerabilities`,
            { file: manifestPath, line: 1, context: match[0] },
            `Found ${vulnerabilities.length} vulnerabilities in ${packageName}:${version}`,
            'Update to a secure version or apply security patches',
            { cwe: ['CWE-1104'], tags: ['dependencies', 'maven'] }
          )
        );
      }
    }

    return findings;
  }

  private async scanCargoToml(manifestPath: string, content: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    // Simple regex-based parsing for Cargo dependencies
    const dependencyRegex = /^([a-zA-Z0-9_-]+)\s*=\s*["']([^"']+)["']/gm;
    let match;
    
    while ((match = dependencyRegex.exec(content)) !== null) {
      const packageName = match[1];
      const version = match[2];
      
      const vulnerabilities = await this.checkPackageVulnerabilities(packageName, version);
      
      if (vulnerabilities.length > 0) {
        findings.push(
          this.createFinding(
            VulnerabilityType.INSECURE_DEPENDENCY,
            SeverityLevel.HIGH,
            `Vulnerable dependency: ${packageName}`,
            `Rust crate ${packageName}@${version} has known security vulnerabilities`,
            { file: manifestPath, line: 1, context: match[0] },
            `Found ${vulnerabilities.length} vulnerabilities in ${packageName}@${version}`,
            'Update to a secure version or apply security patches',
            { cwe: ['CWE-1104'], tags: ['dependencies', 'rust'] }
          )
        );
      }
    }

    return findings;
  }

  private async checkPackageVulnerabilities(packageName: string, version: string): Promise<string[]> {
    // Simulate vulnerability check - in a real implementation, this would query
    // vulnerability databases like NVD, GitHub Security Advisories, etc.
    const mockVulnerabilities: Record<string, string[]> = {
      'lodash': ['CVE-2021-23337', 'CVE-2021-23336'],
      'axios': ['CVE-2023-45857'],
      'moment': ['CVE-2022-24785'],
      'request': ['CVE-2022-24999'],
      'express': ['CVE-2022-24999'],
      'flask': ['CVE-2022-21797'],
      'django': ['CVE-2022-22817'],
      'spring-boot': ['CVE-2022-22965'],
      'log4j': ['CVE-2021-44228', 'CVE-2021-45046'],
      'serde': ['CVE-2021-28032']
    };

    return mockVulnerabilities[packageName] || [];
  }

  private async glob(pattern: string, options: any): Promise<string[]> {
    // Simple glob implementation - in a real implementation, use a proper glob library
    const { glob } = await import('glob');
    return glob(pattern, options);
  }
}

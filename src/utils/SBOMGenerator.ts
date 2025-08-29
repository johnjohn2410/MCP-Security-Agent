import fs from 'fs-extra';
import path from 'path';
import { SBOM, SBOMComponent } from '../types/index.js';
import { Logger } from './Logger.js';

export class SBOMGenerator {
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  /**
   * Generate SBOM from project dependencies
   */
  async generateSBOM(projectPath: string, format: 'CycloneDX' | 'SPDX' = 'CycloneDX'): Promise<SBOM> {
    this.logger.info('Generating SBOM', { projectPath, format });

    const components: SBOMComponent[] = [];
    const dependencies: Array<{ref: string, dependsOn: string[]}> = [];

    // Scan for package manifests
    const packageManifests = await this.findPackageManifests(projectPath);
    
    for (const manifest of packageManifests) {
      const manifestComponents = await this.parsePackageManifest(manifest);
      components.push(...manifestComponents);
    }

    // Add project root component
    const projectComponent: SBOMComponent = {
      name: path.basename(projectPath),
      version: await this.getProjectVersion(projectPath),
      type: 'application',
      description: `Security scan target: ${projectPath}`,
      purl: `pkg:generic/${path.basename(projectPath)}@${await this.getProjectVersion(projectPath)}`,
    };

    components.unshift(projectComponent);

    // Build dependency relationships
    dependencies.push({
      ref: projectComponent.purl!,
      dependsOn: components.slice(1).map(c => c.purl!).filter(Boolean)
    });

    const sbom: SBOM = {
      bomFormat: format,
      specVersion: format === 'CycloneDX' ? '1.5' : '2.3',
      serialNumber: `urn:uuid:${this.generateUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [
          {
            name: 'mcp-security-agent',
            version: await this.getProjectVersion(process.cwd())
          }
        ],
        component: projectComponent
      },
      components,
      dependencies
    };

    this.logger.info('SBOM generated successfully', {
      format,
      componentCount: components.length,
      dependencyCount: dependencies.length
    });

    return sbom;
  }

  /**
   * Find package manifest files
   */
  private async findPackageManifests(projectPath: string): Promise<string[]> {
    const manifests: string[] = [];
    const manifestPatterns = [
      'package.json',
      'package-lock.json',
      'yarn.lock',
      'pnpm-lock.yaml',
      'requirements.txt',
      'Pipfile',
      'Pipfile.lock',
      'poetry.lock',
      'pom.xml',
      'build.gradle',
      'build.gradle.kts',
      'go.mod',
      'go.sum',
      'Cargo.toml',
      'Cargo.lock',
      'composer.json',
      'composer.lock',
      'Gemfile',
      'Gemfile.lock',
      'mix.exs',
      'mix.lock'
    ];

    for (const pattern of manifestPatterns) {
      const manifestPath = path.join(projectPath, pattern);
      if (await fs.pathExists(manifestPath)) {
        manifests.push(manifestPath);
      }
    }

    // Also check subdirectories for nested projects
    const subdirs = await fs.readdir(projectPath);
    for (const subdir of subdirs) {
      const subdirPath = path.join(projectPath, subdir);
      const stat = await fs.stat(subdirPath);
      if (stat.isDirectory() && !subdir.startsWith('.') && subdir !== 'node_modules') {
        const subManifests = await this.findPackageManifests(subdirPath);
        manifests.push(...subManifests);
      }
    }

    return manifests;
  }

  /**
   * Parse package manifest and extract components
   */
  private async parsePackageManifest(manifestPath: string): Promise<SBOMComponent[]> {
    const components: SBOMComponent[] = [];
    const ext = path.extname(manifestPath);

    try {
      if (ext === '.json') {
        const content = await fs.readJson(manifestPath);
        
        if (content.name && content.version) {
          // Main package
          components.push({
            name: content.name,
            version: content.version,
            type: 'application',
            description: content.description,
            licenses: content.license ? [content.license] : undefined,
            purl: `pkg:npm/${content.name}@${content.version}`,
            cpe: `cpe:2.3:a:${content.name}:${content.name}:${content.version}:*:*:*:*:*:*:*:*`
          });

          // Dependencies
          const deps = {
            ...content.dependencies,
            ...content.devDependencies,
            ...content.peerDependencies,
            ...content.optionalDependencies
          };

          for (const [name, version] of Object.entries(deps)) {
            const versionStr = typeof version === 'string' ? version : JSON.stringify(version);
            components.push({
              name,
              version: versionStr,
              type: 'library',
              purl: `pkg:npm/${name}@${versionStr}`,
              cpe: `cpe:2.3:a:${name}:${name}:${versionStr}:*:*:*:*:*:*:*:*`
            });
          }
        }
      } else if (ext === '.txt' && path.basename(manifestPath) === 'requirements.txt') {
        const content = await fs.readFile(manifestPath, 'utf-8');
        const lines = content.split('\n').filter(line => line.trim() && !line.startsWith('#'));

        for (const line of lines) {
          const match = line.match(/^([a-zA-Z0-9_-]+)([<>=!~]+)(.+)$/);
          if (match) {
            const [, name, operator, version] = match;
            components.push({
              name,
              version: `${operator}${version}`,
              type: 'library',
              purl: `pkg:pypi/${name}@${version}`,
              cpe: `cpe:2.3:a:${name}:${name}:${version}:*:*:*:*:*:*:*:*`
            });
          }
        }
      } else if (ext === '.toml' && path.basename(manifestPath) === 'Cargo.toml') {
        const content = await fs.readFile(manifestPath, 'utf-8');
        const packageMatch = content.match(/\[package\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"/);
        
        if (packageMatch) {
          const [, name, version] = packageMatch;
          components.push({
            name,
            version,
            type: 'application',
            purl: `pkg:cargo/${name}@${version}`,
            cpe: `cpe:2.3:a:${name}:${name}:${version}:*:*:*:*:*:*:*:*`
          });
        }

        // Parse dependencies
        const depMatches = content.matchAll(/\[dependencies\.([^\]]+)\]\s+version\s*=\s*"([^"]+)"/g);
        for (const match of depMatches) {
          const [, name, version] = match;
          components.push({
            name,
            version,
            type: 'library',
            purl: `pkg:cargo/${name}@${version}`,
            cpe: `cpe:2.3:a:${name}:${name}:${version}:*:*:*:*:*:*:*:*`
          });
        }
      } else if (ext === '.mod' && path.basename(manifestPath) === 'go.mod') {
        const content = await fs.readFile(manifestPath, 'utf-8');
        const moduleMatch = content.match(/^module\s+([^\s]+)/m);
        
        if (moduleMatch) {
          const moduleName = moduleMatch[1];
          const versionMatch = content.match(/^go\s+([^\s]+)/m);
          const version = versionMatch ? versionMatch[1] : 'unknown';
          
          components.push({
            name: moduleName,
            version,
            type: 'application',
            purl: `pkg:golang/${moduleName}@${version}`,
            cpe: `cpe:2.3:a:${moduleName}:${moduleName}:${version}:*:*:*:*:*:*:*:*`
          });
        }

        // Parse require statements
        const requireMatches = content.matchAll(/^require\s+([^\s]+)\s+([^\s]+)/gm);
        for (const match of requireMatches) {
          const [, name, version] = match;
          components.push({
            name,
            version,
            type: 'library',
            purl: `pkg:golang/${name}@${version}`,
            cpe: `cpe:2.3:a:${name}:${name}:${version}:*:*:*:*:*:*:*:*`
          });
        }
      }
    } catch (error) {
      this.logger.warn('Failed to parse package manifest', {
        manifestPath,
        error: error instanceof Error ? error.message : String(error)
      });
    }

    return components;
  }

  /**
   * Get project version from package.json or git
   */
  private async getProjectVersion(projectPath: string): Promise<string> {
    try {
      const packageJsonPath = path.join(projectPath, 'package.json');
      if (await fs.pathExists(packageJsonPath)) {
        const packageJson = await fs.readJson(packageJsonPath);
        return packageJson.version || '0.0.0';
      }
    } catch (error) {
      this.logger.warn('Failed to read package.json for version', { projectPath });
    }

    // Fallback to git tag or commit hash
    try {
      const { execSync } = await import('child_process');
      const gitVersion = execSync('git describe --tags --always', { 
        cwd: projectPath, 
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'ignore']
      });
      return gitVersion.trim();
    } catch (error) {
      return '0.0.0';
    }
  }

  /**
   * Generate UUID for SBOM serial number
   */
  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * Save SBOM to file
   */
  async saveSBOM(sbom: SBOM, outputPath: string): Promise<void> {
    const ext = sbom.bomFormat === 'CycloneDX' ? 'json' : 'spdx';
    const filename = `sbom-${new Date().toISOString().split('T')[0]}.${ext}`;
    const fullPath = path.join(outputPath, filename);

    await fs.ensureDir(outputPath);
    await fs.writeJson(fullPath, sbom, { spaces: 2 });

    this.logger.info('SBOM saved to file', { path: fullPath });
  }

  /**
   * Convert SBOM to SPDX format
   */
  convertToSPDX(sbom: SBOM): any {
    // This is a simplified SPDX conversion
    // In a real implementation, you'd want to use a proper SPDX library
    const spdx = {
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      SPDXID: 'SPDXRef-DOCUMENT',
      documentName: `SBOM for ${sbom.metadata.component.name}`,
      documentNamespace: `http://spdx.org/spdxdocs/${sbom.metadata.component.name}-${sbom.metadata.component.version}`,
      creator: `Tool: mcp-security-agent-${sbom.metadata.tools[0].version}`,
      created: sbom.metadata.timestamp,
      packages: sbom.components.map(component => ({
        SPDXID: `SPDXRef-Package-${component.name.replace(/[^a-zA-Z0-9]/g, '-')}`,
        name: component.name,
        versionInfo: component.version,
        description: component.description,
        packageFileName: component.name,
        packageVerificationCode: {
          packageVerificationCodeValue: 'NONE'
        },
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        copyrightText: 'NOASSERTION'
      }))
    };

    return spdx;
  }
}

import { SecurityPolicy, PolicyRule, PolicyCondition, PolicyResult, PolicyTrace, SeverityLevel, RuleAction } from '../types/index.js';
import { Logger } from '../utils/Logger.js';

export class PolicyEngine {
  private logger: Logger;
  private policies: Map<string, SecurityPolicy> = new Map();
  private defaultPolicies: SecurityPolicy[] = [];

  constructor(logger: Logger) {
    this.logger = logger;
    this.initializeDefaultPolicies();
  }

  /**
   * Initialize default security policies
   */
  private initializeDefaultPolicies(): void {
    // Global security policies
    const globalPolicies: SecurityPolicy[] = [
      {
        id: 'global-security',
        name: 'Global Security Policy',
        description: 'Default security policies for all projects',
        version: '1.0.0',
        scope: 'global',
        inheritance: 'allow',
        enabled: true,
        priority: 0,
        rules: [
          {
            id: 'no-hardcoded-secrets',
            name: 'No Hardcoded Secrets',
            description: 'Prevent hardcoded API keys, passwords, and tokens',
            type: 'regex',
            action: RuleAction.BLOCK,
            pattern: '(api[_-]?key|password|secret|token)\\s*[:=]\\s*[\'"][^\'"]+[\'"]',
            conditions: [
              {
                field: 'content',
                operator: 'regex',
                value: '(api[_-]?key|password|secret|token)\\s*[:=]\\s*[\'"][^\'"]+[\'"]',
                description: 'Contains hardcoded secret pattern'
              }
            ],
            severity: SeverityLevel.HIGH,
            enabled: true,
            scope: 'global',
            inheritance: 'deny',
            references: [
              { type: 'CWE', id: 'CWE-259', url: 'https://cwe.mitre.org/data/definitions/259.html' },
              { type: 'OWASP', id: 'A02:2021', url: 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/' }
            ],
            metadata: {}
          },
          {
            id: 'no-sql-injection',
            name: 'No SQL Injection',
            description: 'Prevent SQL injection vulnerabilities',
            type: 'regex',
            action: RuleAction.BLOCK,
            pattern: 'SELECT\\s+.*\\s+FROM\\s+.*\\s+WHERE\\s+.*\\+\\s*\\$',
            conditions: [
              {
                field: 'content',
                operator: 'regex',
                value: 'SELECT\\s+.*\\s+FROM\\s+.*\\s+WHERE\\s+.*\\+\\s*\\$',
                description: 'Contains potential SQL injection pattern'
              }
            ],
            severity: SeverityLevel.CRITICAL,
            enabled: true,
            scope: 'global',
            inheritance: 'deny',
            references: [
              { type: 'CWE', id: 'CWE-89', url: 'https://cwe.mitre.org/data/definitions/89.html' },
              { type: 'OWASP', id: 'A03:2021', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
            ],
            metadata: {}
          },
          {
            id: 'no-xss',
            name: 'No Cross-Site Scripting',
            description: 'Prevent XSS vulnerabilities',
            type: 'regex',
            action: RuleAction.WARN,
            pattern: 'innerHTML\\s*=\\s*.*\\+\\s*\\$',
            conditions: [
              {
                field: 'content',
                operator: 'regex',
                value: 'innerHTML\\s*=\\s*.*\\+\\s*\\$',
                description: 'Contains potential XSS pattern'
              }
            ],
            severity: SeverityLevel.HIGH,
            enabled: true,
            scope: 'global',
            inheritance: 'deny',
            references: [
              { type: 'CWE', id: 'CWE-79', url: 'https://cwe.mitre.org/data/definitions/79.html' },
              { type: 'OWASP', id: 'A03:2021', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
            ],
            metadata: {}
          },
          {
            id: 'no-command-injection',
            name: 'No Command Injection',
            description: 'Prevent command injection vulnerabilities',
            type: 'regex',
            action: RuleAction.BLOCK,
            pattern: 'exec\\s*\\(\\s*.*\\+\\s*\\$',
            conditions: [
              {
                field: 'content',
                operator: 'regex',
                value: 'exec\\s*\\(\\s*.*\\+\\s*\\$',
                description: 'Contains potential command injection pattern'
              }
            ],
            severity: SeverityLevel.CRITICAL,
            enabled: true,
            scope: 'global',
            inheritance: 'deny',
            references: [
              { type: 'CWE', id: 'CWE-78', url: 'https://cwe.mitre.org/data/definitions/78.html' },
              { type: 'OWASP', id: 'A03:2021', url: 'https://owasp.org/Top10/A03_2021-Injection/' }
            ],
            metadata: {}
          },
          {
            id: 'no-path-traversal',
            name: 'No Path Traversal',
            description: 'Prevent path traversal vulnerabilities',
            type: 'regex',
            action: RuleAction.BLOCK,
            pattern: 'fs\\.readFile\\s*\\(\\s*.*\\+\\s*\\$',
            conditions: [
              {
                field: 'content',
                operator: 'regex',
                value: 'fs\\.readFile\\s*\\(\\s*.*\\+\\s*\\$',
                description: 'Contains potential path traversal pattern'
              }
            ],
            severity: SeverityLevel.HIGH,
            enabled: true,
            scope: 'global',
            inheritance: 'deny',
            references: [
              { type: 'CWE', id: 'CWE-22', url: 'https://cwe.mitre.org/data/definitions/22.html' },
              { type: 'OWASP', id: 'A01:2021', url: 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/' }
            ],
            metadata: {}
          }
        ],
        metadata: {}
      },
      {
        id: 'dependency-security',
        name: 'Dependency Security Policy',
        description: 'Security policies for dependency management',
        version: '1.0.0',
        scope: 'global',
        inheritance: 'allow',
        enabled: true,
        priority: 1,
        rules: [
          {
            id: 'no-critical-vulnerabilities',
            name: 'No Critical Vulnerabilities',
            description: 'Prevent dependencies with critical vulnerabilities',
            type: 'dependency',
            action: RuleAction.BLOCK,
            conditions: [
              {
                field: 'severity',
                operator: 'equals',
                value: 'critical',
                description: 'Dependency has critical vulnerability'
              }
            ],
            severity: SeverityLevel.CRITICAL,
            enabled: true,
            scope: 'global',
            inheritance: 'deny',
            references: [
              { type: 'CWE', id: 'CWE-1104', url: 'https://cwe.mitre.org/data/definitions/1104.html' },
              { type: 'OWASP', id: 'A06:2021', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' }
            ],
            metadata: {}
          },
          {
            id: 'no-outdated-dependencies',
            name: 'No Outdated Dependencies',
            description: 'Prevent severely outdated dependencies',
            type: 'dependency',
            action: RuleAction.WARN,
            conditions: [
              {
                field: 'daysOutdated',
                operator: 'greater_than',
                value: 365,
                description: 'Dependency is more than 1 year outdated'
              }
            ],
            severity: SeverityLevel.MEDIUM,
            enabled: true,
            scope: 'global',
            inheritance: 'allow',
            references: [
              { type: 'CWE', id: 'CWE-1104', url: 'https://cwe.mitre.org/data/definitions/1104.html' },
              { type: 'OWASP', id: 'A06:2021', url: 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/' }
            ],
            metadata: {}
          }
        ],
        metadata: {}
      },
      {
        id: 'configuration-security',
        name: 'Configuration Security Policy',
        description: 'Security policies for configuration files',
        version: '1.0.0',
        scope: 'global',
        inheritance: 'allow',
        enabled: true,
        priority: 2,
        rules: [
          {
            id: 'no-debug-mode',
            name: 'No Debug Mode in Production',
            description: 'Prevent debug mode in production configurations',
            type: 'config',
            action: RuleAction.WARN,
            conditions: [
              {
                field: 'debug',
                operator: 'equals',
                value: true,
                description: 'Debug mode is enabled'
              },
              {
                field: 'environment',
                operator: 'equals',
                value: 'production',
                description: 'Environment is production'
              }
            ],
            severity: SeverityLevel.MEDIUM,
            enabled: true,
            scope: 'global',
            inheritance: 'deny',
            references: [
              { type: 'CWE', id: 'CWE-489', url: 'https://cwe.mitre.org/data/definitions/489.html' },
              { type: 'OWASP', id: 'A05:2021', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' }
            ],
            metadata: {}
          },
          {
            id: 'secure-cors',
            name: 'Secure CORS Configuration',
            description: 'Ensure CORS is properly configured',
            type: 'config',
            action: RuleAction.WARN,
            conditions: [
              {
                field: 'cors.origin',
                operator: 'equals',
                value: '*',
                description: 'CORS origin is set to wildcard'
              }
            ],
            severity: SeverityLevel.MEDIUM,
            enabled: true,
            scope: 'global',
            inheritance: 'allow',
            references: [
              { type: 'CWE', id: 'CWE-942', url: 'https://cwe.mitre.org/data/definitions/942.html' },
              { type: 'OWASP', id: 'A05:2021', url: 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/' }
            ],
            metadata: {}
          }
        ],
        metadata: {}
      }
    ];

    // Add default policies
    globalPolicies.forEach(policy => {
      this.policies.set(policy.id, policy);
      this.defaultPolicies.push(policy);
    });

    this.logger.info('Default security policies initialized', {
      policyCount: globalPolicies.length,
      ruleCount: globalPolicies.reduce((sum, policy) => sum + policy.rules.length, 0)
    });
  }

  /**
   * Add a new security policy
   */
  addPolicy(policy: SecurityPolicy): void {
    if (this.policies.has(policy.id)) {
      throw new Error(`Policy with ID ${policy.id} already exists`);
    }

    this.policies.set(policy.id, policy);
    this.logger.info('Security policy added', {
      policyId: policy.id,
      policyName: policy.name,
      ruleCount: policy.rules.length,
      scope: policy.scope
    });
  }

  /**
   * Remove a security policy
   */
  removePolicy(policyId: string): boolean {
    const policy = this.policies.get(policyId);
    if (!policy) {
      return false;
    }

    // Don't allow removal of default policies
    if (this.defaultPolicies.some(p => p.id === policyId)) {
      throw new Error(`Cannot remove default policy: ${policyId}`);
    }

    this.policies.delete(policyId);
    this.logger.info('Security policy removed', { policyId });
    return true;
  }

  /**
   * Get a security policy by ID
   */
  getPolicy(policyId: string): SecurityPolicy | undefined {
    return this.policies.get(policyId);
  }

  /**
   * Get all policies
   */
  getAllPolicies(): SecurityPolicy[] {
    return Array.from(this.policies.values());
  }

  /**
   * Get policies by scope
   */
  getPoliciesByScope(scope: 'global' | 'team' | 'repo'): SecurityPolicy[] {
    return Array.from(this.policies.values()).filter(policy => policy.scope === scope);
  }

  /**
   * Enable or disable a policy
   */
  setPolicyEnabled(policyId: string, enabled: boolean): boolean {
    const policy = this.policies.get(policyId);
    if (!policy) {
      return false;
    }

    policy.enabled = enabled;
    this.logger.info('Policy enabled/disabled', { policyId, enabled });
    return true;
  }

  /**
   * Update a policy rule
   */
  updatePolicyRule(policyId: string, ruleId: string, updatedRule: PolicyRule): boolean {
    const policy = this.policies.get(policyId);
    if (!policy) {
      return false;
    }

    const ruleIndex = policy.rules.findIndex(rule => rule.id === ruleId);
    if (ruleIndex === -1) {
      return false;
    }

    policy.rules[ruleIndex] = updatedRule;
    this.logger.info('Policy rule updated', { policyId, ruleId });
    return true;
  }

  /**
   * Evaluate a policy against a context
   */
  async evaluatePolicy(policy: SecurityPolicy, context: any): Promise<PolicyResult> {
    const results = this.evaluatePolicyRules(policy, context);
    return results[0] || {
      policyId: policy.id,
      ruleId: 'default',
      matched: false,
      severity: SeverityLevel.INFO,
      evidence: 'No rules matched',
      trace: {
        ruleId: 'default',
        ruleName: 'Default',
        matched: false,
        evidence: 'No rules matched',
        conditions: [],
        context: {}
      },
      recommendations: [],
      metadata: {}
    };
  }

  /**
   * Evaluate all rules in a policy against a context
   */
  private evaluatePolicyRules(policy: SecurityPolicy, context: Record<string, any>): PolicyResult[] {
    if (!policy.enabled) {
      return [];
    }

    const results: PolicyResult[] = [];

    for (const rule of policy.rules) {
      if (!rule.enabled) {
        continue;
      }

      const result = this.evaluateRule(rule, context);
      if (result.matched) {
        const allowed = rule.action !== RuleAction.BLOCK || !result.matched;
        results.push({
          policyId: policy.id,
          ruleId: rule.id,
          matched: true,
          severity: rule.severity,
          evidence: result.evidence,
          trace: result.trace,
          recommendations: this.generateRecommendations(rule),
          allowed,
          metadata: {}
        });
      }
    }

    return results;
  }

  /**
   * Evaluate all applicable policies against a context
   */
  async evaluateAllPolicies(context: Record<string, any>): Promise<PolicyResult[]> {
    const results: PolicyResult[] = [];

    for (const policy of this.policies.values()) {
      if (!policy.enabled) {
        continue;
      }

      const policyResult = await this.evaluatePolicy(policy, context);
      results.push(policyResult);
    }

    return results;
  }

  /**
   * Evaluate a single rule against a context
   */
  private evaluateRule(rule: PolicyRule, context: Record<string, any>): {
    matched: boolean;
    evidence: string;
    trace: PolicyTrace;
  } {
    const trace: PolicyTrace = {
      ruleId: rule.id,
      ruleName: rule.name,
      matched: false,
      evidence: '',
      conditions: [],
      context: { ...context }
    };

    let matched = true;
    const evidence: string[] = [];

    for (const condition of rule.conditions) {
      const conditionResult = this.evaluateCondition(condition, context);
      trace.conditions.push(conditionResult);

      if (!conditionResult.matched) {
        matched = false;
      } else {
        evidence.push(conditionResult.actualValue);
      }
    }

    trace.matched = matched;
    trace.evidence = evidence.join(', ');

    return {
      matched,
      evidence: trace.evidence,
      trace
    };
  }

  /**
   * Evaluate a single condition against a context
   */
  private evaluateCondition(condition: PolicyCondition, context: Record<string, any>): {
    condition: PolicyCondition;
    matched: boolean;
    actualValue: any;
  } {
    const actualValue = this.getFieldValue(context, condition.field);
    let matched = false;

    switch (condition.operator) {
      case 'equals':
        matched = actualValue === condition.value;
        break;
      case 'contains':
        matched = String(actualValue).includes(String(condition.value));
        break;
      case 'regex':
        try {
          const regex = new RegExp(String(condition.value), 'i');
          matched = regex.test(String(actualValue));
        } catch (error) {
          matched = false;
        }
        break;
      case 'greater_than':
        matched = Number(actualValue) > Number(condition.value);
        break;
      case 'less_than':
        matched = Number(actualValue) < Number(condition.value);
        break;
      case 'in':
        matched = Array.isArray(condition.value) && condition.value.includes(actualValue);
        break;
      case 'not_in':
        matched = Array.isArray(condition.value) && !condition.value.includes(actualValue);
        break;
    }

    return {
      condition,
      matched,
      actualValue
    };
  }

  /**
   * Get field value from context using dot notation
   */
  private getFieldValue(context: Record<string, any>, field: string): any {
    const keys = field.split('.');
    let value = context;

    for (const key of keys) {
      if (value && typeof value === 'object' && key in value) {
        value = value[key];
      } else {
        return undefined;
      }
    }

    return value;
  }

  /**
   * Generate recommendations for a rule
   */
  private generateRecommendations(rule: PolicyRule): string[] {
    const recommendations: string[] = [];

    switch (rule.id) {
      case 'no-hardcoded-secrets':
        recommendations.push('Use environment variables or secure secret management');
        recommendations.push('Consider using a secrets manager like AWS Secrets Manager or HashiCorp Vault');
        break;
      case 'no-sql-injection':
        recommendations.push('Use parameterized queries or prepared statements');
        recommendations.push('Implement input validation and sanitization');
        break;
      case 'no-xss':
        recommendations.push('Use proper output encoding');
        recommendations.push('Implement Content Security Policy (CSP)');
        break;
      case 'no-command-injection':
        recommendations.push('Avoid command execution with user input');
        recommendations.push('Use built-in APIs instead of shell commands');
        break;
      case 'no-path-traversal':
        recommendations.push('Validate and sanitize file paths');
        recommendations.push('Use path normalization and whitelist allowed directories');
        break;
      case 'no-critical-vulnerabilities':
        recommendations.push('Update vulnerable dependencies to latest secure versions');
        recommendations.push('Consider alternative packages if updates are not available');
        break;
      case 'no-debug-mode':
        recommendations.push('Disable debug mode in production environments');
        recommendations.push('Use environment-specific configuration files');
        break;
      case 'secure-cors':
        recommendations.push('Configure CORS with specific allowed origins');
        recommendations.push('Avoid using wildcard (*) for CORS origins');
        break;
      default:
        recommendations.push('Review and address the security issue');
        recommendations.push('Follow security best practices for the specific vulnerability type');
    }

    return recommendations;
  }

  /**
   * Get policy inheritance chain
   */
  getPolicyInheritance(policyId: string): SecurityPolicy[] {
    const policy = this.policies.get(policyId);
    if (!policy) {
      return [];
    }

    const inheritance: SecurityPolicy[] = [policy];

    // Add parent policies based on scope
    if (policy.scope === 'repo') {
      const teamPolicies = this.getPoliciesByScope('team');
      inheritance.push(...teamPolicies);
    }

    if (policy.scope === 'repo' || policy.scope === 'team') {
      const globalPolicies = this.getPoliciesByScope('global');
      inheritance.push(...globalPolicies);
    }

    return inheritance;
  }

  /**
   * Export policies to human-readable format
   */
  exportPolicies(format: 'json' | 'yaml' | 'rego' = 'json'): string {
    const policies = Array.from(this.policies.values());

    switch (format) {
      case 'json':
        return JSON.stringify(policies, null, 2);
      case 'yaml':
        // Simple YAML conversion
        return this.convertToYAML(policies);
      case 'rego':
        return this.convertToRego(policies);
      default:
        return JSON.stringify(policies, null, 2);
    }
  }

  /**
   * Convert policies to YAML format
   */
  private convertToYAML(policies: SecurityPolicy[]): string {
    let yaml = '# Security Policies\n\n';
    
    for (const policy of policies) {
      yaml += `# ${policy.name}\n`;
      yaml += `# ${policy.description}\n`;
      yaml += `policy_${policy.id}:\n`;
      yaml += `  scope: ${policy.scope}\n`;
      yaml += `  enabled: ${policy.enabled}\n`;
      yaml += `  rules:\n`;
      
      for (const rule of policy.rules) {
        yaml += `    - id: ${rule.id}\n`;
        yaml += `      name: ${rule.name}\n`;
        yaml += `      severity: ${rule.severity}\n`;
        yaml += `      enabled: ${rule.enabled}\n`;
        if (rule.pattern) {
          yaml += `      pattern: ${rule.pattern}\n`;
        }
        yaml += `      conditions:\n`;
        for (const condition of rule.conditions) {
          yaml += `        - field: ${condition.field}\n`;
          yaml += `          operator: ${condition.operator}\n`;
          yaml += `          value: ${condition.value}\n`;
        }
        yaml += '\n';
      }
    }
    
    return yaml;
  }

  /**
   * Convert policies to Rego format
   */
  private convertToRego(policies: SecurityPolicy[]): string {
    let rego = 'package security.policies\n\n';
    
    for (const policy of policies) {
      rego += `# ${policy.name}\n`;
      rego += `# ${policy.description}\n`;
      
      for (const rule of policy.rules) {
        rego += `violation[{"msg": msg, "severity": "${rule.severity}", "rule": "${rule.id}"}] {\n`;
        
        if (rule.pattern) {
          rego += `  input.content = data.patterns.${rule.id}\n`;
        }
        
        for (const condition of rule.conditions) {
          rego += `  ${condition.field} ${this.convertOperatorToRego(condition.operator)} ${this.convertValueToRego(condition.value)}\n`;
        }
        
        rego += `  msg := "${rule.description}"\n`;
        rego += `}\n\n`;
      }
    }
    
    return rego;
  }

  /**
   * Convert operator to Rego syntax
   */
  private convertOperatorToRego(operator: string): string {
    switch (operator) {
      case 'equals': return '==';
      case 'contains': return 'contains';
      case 'greater_than': return '>';
      case 'less_than': return '<';
      case 'in': return 'in';
      case 'not_in': return 'not in';
      default: return '==';
    }
  }

  /**
   * Convert value to Rego syntax
   */
  private convertValueToRego(value: any): string {
    if (typeof value === 'string') {
      return `"${value}"`;
    }
    if (Array.isArray(value)) {
      return `[${value.map(v => this.convertValueToRego(v)).join(', ')}]`;
    }
    return String(value);
  }
}

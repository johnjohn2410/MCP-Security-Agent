import { SecurityPolicy, PolicyRule, RuleAction, SeverityLevel } from '../types/index.js';

export class MCPHardenedPolicy {
  /**
   * Get MCP hardened security policy
   */
  static getPolicy(): SecurityPolicy {
    return {
      id: 'mcp-hardened',
      name: 'MCP Hardened Security Policy',
      description: 'Enterprise-grade security policy for MCP servers with defensive-by-default settings',
      version: '1.0.0',
      priority: 100, // High priority
      enabled: true,
      rules: [
        // Authentication & Authorization
        {
          id: 'mcp-auth-required',
          name: 'Authentication Required',
          description: 'All MCP servers must require authentication',
          severity: SeverityLevel.HIGH,
          action: RuleAction.BLOCK,
          conditions: {
            type: 'mcp_config',
            field: 'auth.required',
            operator: 'equals',
            value: true
          },
          remediation: 'Configure authentication with bearer token, API key, or OAuth2'
        },
        {
          id: 'mcp-tls-required',
          name: 'TLS Encryption Required',
          description: 'All MCP communications must use TLS encryption',
          severity: SeverityLevel.HIGH,
          action: RuleAction.BLOCK,
          conditions: {
            type: 'mcp_config',
            field: 'transport.tls',
            operator: 'equals',
            value: true
          },
          remediation: 'Enable TLS encryption in transport configuration'
        },

        // CORS & CSP
        {
          id: 'mcp-cors-restrictive',
          name: 'Restrictive CORS Policy',
          description: 'CORS policy must be restrictive and not allow wildcard origins',
          severity: SeverityLevel.MEDIUM,
          action: RuleAction.WARN,
          conditions: {
            type: 'mcp_config',
            field: 'cors.origin',
            operator: 'not_equals',
            value: '*'
          },
          remediation: 'Configure specific origins instead of wildcard (*)'
        },
        {
          id: 'mcp-csp-required',
          name: 'Content Security Policy Required',
          description: 'Content Security Policy headers should be configured',
          severity: SeverityLevel.MEDIUM,
          action: RuleAction.WARN,
          conditions: {
            type: 'mcp_config',
            field: 'csp.directives',
            operator: 'exists',
            value: true
          },
          remediation: 'Add CSP headers with restrictive directives'
        },

        // Rate Limiting & Quotas
        {
          id: 'mcp-rate-limit-required',
          name: 'Rate Limiting Required',
          description: 'Rate limiting must be configured to prevent abuse',
          severity: SeverityLevel.MEDIUM,
          action: RuleAction.BLOCK,
          conditions: {
            type: 'mcp_config',
            field: 'rateLimit.requests',
            operator: 'greater_than',
            value: 0
          },
          remediation: 'Configure rate limiting with appropriate request limits'
        },
        {
          id: 'mcp-quotas-required',
          name: 'Resource Quotas Required',
          description: 'Resource quotas should be configured to prevent resource exhaustion',
          severity: SeverityLevel.MEDIUM,
          action: RuleAction.WARN,
          conditions: {
            type: 'mcp_config',
            field: 'quotas.memory',
            operator: 'exists',
            value: true
          },
          remediation: 'Configure resource quotas for memory, CPU, and storage'
        },

        // Sandboxing & Isolation
        {
          id: 'mcp-sandbox-required',
          name: 'Sandboxing Required',
          description: 'MCP servers must run in sandboxed environment',
          severity: SeverityLevel.HIGH,
          action: RuleAction.BLOCK,
          conditions: {
            type: 'mcp_config',
            field: 'sandbox.enabled',
            operator: 'equals',
            value: true
          },
          remediation: 'Enable sandboxing with Docker or process isolation'
        },
        {
          id: 'mcp-resource-limits',
          name: 'Resource Limits Required',
          description: 'Resource limits must be configured for sandboxed environments',
          severity: SeverityLevel.MEDIUM,
          action: RuleAction.WARN,
          conditions: {
            type: 'mcp_config',
            field: 'limits.memory',
            operator: 'exists',
            value: true
          },
          remediation: 'Set resource limits for memory, CPU, PIDs, and file size'
        },

        // stdio Security
        {
          id: 'mcp-stdio-public-disabled',
          name: 'Public stdio Disabled',
          description: 'Public stdio access must be disabled',
          severity: SeverityLevel.HIGH,
          action: RuleAction.BLOCK,
          conditions: {
            type: 'mcp_config',
            field: 'stdio.public',
            operator: 'equals',
            value: false
          },
          remediation: 'Disable public stdio access or restrict to authenticated users'
        },
        {
          id: 'mcp-stdio-auth-required',
          name: 'stdio Authentication Required',
          description: 'stdio access should require authentication',
          severity: SeverityLevel.MEDIUM,
          action: RuleAction.WARN,
          conditions: {
            type: 'mcp_config',
            field: 'stdio.auth',
            operator: 'equals',
            value: true
          },
          remediation: 'Require authentication for stdio access'
        },

        // Trust & Provenance
        {
          id: 'mcp-trust-required',
          name: 'Trust Verification Required',
          description: 'MCP servers must be verified through trust store',
          severity: SeverityLevel.HIGH,
          action: RuleAction.BLOCK,
          conditions: {
            type: 'trust_verification',
            field: 'verified',
            operator: 'equals',
            value: true
          },
          remediation: 'Add server to trust store with valid public key and signature'
        },
        {
          id: 'mcp-provenance-required',
          name: 'Provenance Verification Required',
          description: 'Server provenance must be verified through attestations',
          severity: SeverityLevel.MEDIUM,
          action: RuleAction.WARN,
          conditions: {
            type: 'provenance_verification',
            field: 'attestation_valid',
            operator: 'equals',
            value: true
          },
          remediation: 'Verify server provenance through SLSA/cosign attestations'
        },

        // Payload Security
        {
          id: 'mcp-payload-size-limit',
          name: 'Payload Size Limits',
          description: 'MCP payloads must not exceed size limits',
          severity: SeverityLevel.MEDIUM,
          action: RuleAction.WARN,
          conditions: {
            type: 'payload_validation',
            field: 'size',
            operator: 'less_than_or_equal',
            value: 1048576 // 1MB
          },
          remediation: 'Reduce payload size or implement pagination'
        },
        {
          id: 'mcp-json-only',
          name: 'JSON-Only Content',
          description: 'MCP payloads must contain only JSON-safe content',
          severity: SeverityLevel.MEDIUM,
          action: RuleAction.WARN,
          conditions: {
            type: 'payload_validation',
            field: 'json_only',
            operator: 'equals',
            value: true
          },
          remediation: 'Ensure payload contains only JSON-safe characters'
        },

        // Prompt Injection Protection
        {
          id: 'mcp-prompt-injection-block',
          name: 'Prompt Injection Blocked',
          description: 'Potential prompt injection attempts must be blocked',
          severity: SeverityLevel.HIGH,
          action: RuleAction.BLOCK,
          conditions: {
            type: 'prompt_injection_detection',
            field: 'detected',
            operator: 'equals',
            value: false
          },
          remediation: 'Sanitize response content to remove suspicious directives'
        }
      ]
    };
  }

  /**
   * Get policy configuration template
   */
  static getConfigTemplate(): string {
    return JSON.stringify({
      auth: {
        type: 'bearer',
        required: true,
        tokenValidation: true
      },
      transport: {
        tls: true,
        certFile: '/path/to/cert.pem',
        keyFile: '/path/to/key.pem',
        minTlsVersion: '1.2'
      },
      cors: {
        origin: ['https://trusted-client.com'],
        methods: ['GET', 'POST'],
        credentials: true,
        maxAge: 86400
      },
      csp: {
        directives: {
          'default-src': ["'self'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"],
          'img-src': ["'self'"],
          'connect-src': ["'self'"]
        }
      },
      rateLimit: {
        requests: 100,
        window: 60000,
        burst: 10
      },
      quotas: {
        memory: '512MB',
        cpu: '1.0',
        requests: 1000,
        storage: '1GB',
        concurrent: 10
      },
      sandbox: {
        enabled: true,
        mode: 'docker',
        image: 'mcp-server:latest',
        readOnly: true,
        capDrop: ['ALL']
      },
      limits: {
        memory: '512MB',
        cpu: '1.0',
        pids: 100,
        fileSize: '10MB',
        openFiles: 1000
      },
      stdio: {
        public: false,
        auth: true,
        logLevel: 'info'
      },
      trust: {
        requireVerification: true,
        allowUntrusted: false,
        pinPublicKeys: true
      },
      validation: {
        maxPayloadSize: 1048576,
        enforceJsonOnly: true,
        validateEnvelopes: true
      }
    }, null, 2);
  }

  /**
   * Get policy compliance checklist
   */
  static getComplianceChecklist(): string[] {
    return [
      '✅ Authentication configured and required',
      '✅ TLS encryption enabled',
      '✅ Restrictive CORS policy configured',
      '✅ Content Security Policy headers set',
      '✅ Rate limiting implemented',
      '✅ Resource quotas configured',
      '✅ Sandboxing enabled',
      '✅ Resource limits set',
      '✅ Public stdio access disabled',
      '✅ stdio authentication required',
      '✅ Trust verification enabled',
      '✅ Provenance verification enabled',
      '✅ Payload size limits enforced',
      '✅ JSON-only content enforced',
      '✅ Prompt injection protection active'
    ];
  }
}

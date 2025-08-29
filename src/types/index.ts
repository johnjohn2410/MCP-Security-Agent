// Core types for the MCP Security Agent

// ========= Data handling, auditing, SBOM/VEX =========

export interface DataHandlingConfig {
  redactSecrets: boolean;
  redactPII: boolean;
  tokenizeCode: boolean;
  maxCodeSnippetSize: number;
  maxFileSize: number;
  allowedFileTypes: string[];
  excludedPaths: string[];
  privacyStatement: string;
  dataRetentionDays: number;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  operation: string;
  userId?: string;
  sessionId: string;
  resource: string;
  action: string;
  result: 'success' | 'failure' | 'denied';
  evidence: string;
  dataHash: string;
  previousHash?: string;
  signature?: string;
  metadata: Record<string, any>;
}

export interface SBOMComponent {
  name: string;
  version: string;
  type: 'application' | 'framework' | 'library' | 'container' | 'operating-system';
  supplier?: string;
  description?: string;
  licenses?: string[];
  vulnerabilities?: string[];
  purl?: string;
  cpe?: string;
}

export interface SBOM {
  bomFormat: 'CycloneDX' | 'SPDX';
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{ name: string; version: string }>;
    component: SBOMComponent;
  };
  components: SBOMComponent[];
  dependencies: Array<{ ref: string; dependsOn: string[] }>;
}

export interface VEXDocument {
  id: string;
  timestamp: string;
  author: string;
  status: 'not_affected' | 'affected' | 'fixed' | 'under_investigation';
  description: string;
  affected: Array<{
    component: string;
    vulnerability: string;
    justification: string;
    impact: string;
  }>;
  references: Array<{ type: string; url: string }>;
}

// ========= Findings & reporting =========

export enum VulnerabilityType {
  SQL_INJECTION = 'sql_injection',
  XSS = 'cross_site_scripting',
  COMMAND_INJECTION = 'command_injection',
  PATH_TRAVERSAL = 'path_traversal',
  INSECURE_DESERIALIZATION = 'insecure_deserialization',
  HARDCODED_SECRET = 'hardcoded_secret',
  WEAK_CRYPTO = 'weak_cryptography',
  INSECURE_DEPENDENCY = 'insecure_dependency',
  CONFIGURATION_ISSUE = 'configuration_issue',
  PERMISSION_ISSUE = 'permission_issue',
  LOGGING_ISSUE = 'logging_issue',
  AUTHENTICATION_ISSUE = 'authentication_issue',
  AUTHORIZATION_ISSUE = 'authorization_issue',
  INPUT_VALIDATION = 'input_validation',
  OUTPUT_ENCODING = 'output_encoding'
}

export enum SeverityLevel {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info'
}

export interface Finding {
  id: string;
  stableId: string;
  type: VulnerabilityType;
  severity: SeverityLevel;
  title: string;
  description: string;
  file: string;
  line: number;
  column?: number;
  snippet: string;
  evidence: string;
  confidence: number;
  cwe?: string[];
  owasp?: string[];
  nist?: string[];
  cis?: string[];
  references: Array<{ type: string; url: string }>;
  remediation: string;
  patch?: string;
  riskScore: number;
  exploitability: 'low' | 'medium' | 'high' | 'critical';
  impact: 'low' | 'medium' | 'high' | 'critical';
  firstSeen: string;
  lastSeen: string;
  status: 'open' | 'fixed' | 'suppressed' | 'false_positive';
  suppressionReason?: string;
  suppressionExpiry?: string;
  tags: string[];
  metadata: Record<string, any>;
}

export interface Location {
  file: string;
  line?: number;
  column?: number;
  function?: string;
  context?: string;
}

export interface ScanResult {
  id: string;
  type: VulnerabilityType;
  severity: SeverityLevel;
  title: string;
  description: string;
  location: Location;
  evidence: string;
  recommendation: string;
  cwe?: string;
  cvss?: number;
  timestamp: Date;
  scanner: string;
  confidence: number;
  tags: string[];
  findings: Finding[]; // detailed per-file findings
  auditLog: AuditLogEntry[];
  sbom?: SBOM;
  vex?: VEXDocument[];
  policyResults: PolicyResult[]; // uses unified PolicyResult below
  performance: PerformanceMetrics;
  metadata: ReportMetadata;
}

export interface PerformanceMetrics {
  scanDuration: number;
  filesScanned: number;
  findingsFound: number;
  memoryUsage: number;
  cpuUsage: number;
  networkRequests: number;
  p95Latency: number;
  p99Latency: number;
  throughput: number;
}

export interface ComplianceMapping {
  soc2: string[];
  iso27001: string[];
  pci: string[];
  gdpr: string[];
  hipaa: string[];
  nist: string[];
}

export interface ReportMetadata {
  generatedAt: string;
  version: string;
  scanId: string;
  sessionId: string;
  userAgent: string;
  compliance: ComplianceMapping;
  performance: PerformanceMetrics;
  auditLogHash: string;
  sbomHash: string;
  signature?: string;
}

// ========= Policy model (DE-DUPLICATED & unified) =========

export enum RuleType {
  REGEX = 'regex',
  AST_PATTERN = 'ast_pattern',
  DEPENDENCY_CHECK = 'dependency_check',
  CONFIG_CHECK = 'config_check',
  PERMISSION_CHECK = 'permission_check',
}

export enum RuleAction {
  BLOCK = 'block',
  WARN = 'warn',
  ALLOW = 'allow',
  LOG = 'log',
}

export interface PolicyCondition {
  field: string;
  operator: 'equals' | 'contains' | 'regex' | 'greater_than' | 'less_than' | 'in' | 'not_in';
  value: any;
  description: string;
}

export interface PolicyTrace {
  ruleId: string;
  ruleName: string;
  matched: boolean;
  evidence: string;
  conditions: Array<{
    condition: PolicyCondition;
    matched: boolean;
    actualValue: any;
  }>;
  context: Record<string, any>;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  // keep the broader union for compatibility with existing rules
  type: 'regex' | 'ast' | 'dependency' | 'config' | 'permission' | 'custom';
  // optional action using your enums (compatible extension)
  action: RuleAction;
  pattern?: string;
  astPattern?: string;
  conditions: PolicyCondition[];
  severity: SeverityLevel;
  enabled: boolean;
  scope: 'global' | 'team' | 'repo' | 'file';
  inheritance: 'allow' | 'deny' | 'merge';
  references: Array<{ type: string; id: string; url: string }>;
  metadata: Record<string, any>;
}

export interface SecurityPolicy {
  id: string;
  name: string;
  description: string;
  version: string;
  rules: PolicyRule[];
  scope: 'global' | 'team' | 'repo';
  inheritance: 'allow' | 'deny' | 'merge';
  enabled: boolean;
  priority: number;
  metadata: Record<string, any>;
}

export interface PolicyResult {
  // unified, richer result used both by engine and in ScanResult
  policyId: string;
  ruleId: string;
  matched: boolean;
  severity: SeverityLevel;
  evidence: string;
  trace: PolicyTrace;
  recommendations: string[];
  allowed: boolean;
  metadata: Record<string, any>;
}

// ========= Agent, MCP, policy engine contracts =========

export interface MCPToolConfig {
  name: string;
  description: string;
  parameters: MCPToolParameter[];
  dryRun: boolean;
  fileGlobs: string[];
  languageFilters: string[];
  sizeLimit: number;
  timeLimit: number;
  exclusions: string[];
  streaming: boolean;
  incremental: boolean;
}

export interface MCPToolParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  required: boolean;
  description: string;
  default?: any;
  validation?: string;
}

export interface MCPTool {
  name: string;
  description: string;
  parameters: MCPParameter[];
  returns: MCPReturnType;
  permissions: string[];
}

export interface MCPParameter {
  name: string;
  type: string;
  description: string;
  required: boolean;
  default?: any;
}

export interface MCPReturnType {
  type: string;
  description: string;
}

export interface AgentContext {
  projectRoot: string;
  fileSystem: FileSystemAccess;
  networkAccess: NetworkAccess;
  toolRegistry: ToolRegistry;
  policyEngine: PolicyEngine;
  memory: AgentMemory;
}

export interface FileSystemAccess {
  readFile(path: string): Promise<string>;
  writeFile(path: string, content: string): Promise<void>;
  listFiles(pattern: string): Promise<string[]>;
  getFileInfo(path: string): Promise<FileInfo>;
}

export interface FileInfo {
  path: string;
  size: number;
  modified: Date;
  permissions: string;
  type: 'file' | 'directory';
}

export interface NetworkAccess {
  get(url: string, options?: any): Promise<any>;
  post(url: string, data: any, options?: any): Promise<any>;
  isAllowed(url: string): boolean;
}

export interface ToolRegistry {
  registerTool(tool: MCPTool): void;
  getTool(name: string): MCPTool | undefined;
  listTools(): MCPTool[];
  executeTool(name: string, params: any): Promise<any>;
}

export interface PolicyEngine {
  evaluatePolicy(policy: SecurityPolicy, context: any): Promise<PolicyResult>;
  getPolicies(): SecurityPolicy[];
  addPolicy(policy: SecurityPolicy): void;
  removePolicy(policyId: string): void;
}

export interface AgentMemory {
  store(key: string, value: any): Promise<void>;
  retrieve(key: string): Promise<any>;
  search(query: string): Promise<any[]>;
  clear(): Promise<void>;
}

// ========= Scan orchestration & AI analysis =========

export type ScanTarget =
  | 'code'
  | 'secrets'
  | 'dependencies'
  | 'config'
  | 'policy';

export interface ScanConfig {
  path: string;
  // NEW: allow multiple targets per run
  scanTypes?: ScanTarget[];
  // keep original singular for backward compat (optional)
  scanType?: 'quick' | 'comprehensive' | 'targeted';
  // NEW: allow multiple outputs (includes SARIF), keep old single too
  outputFormats?: Array<'json' | 'html' | 'pdf' | 'csv' | 'sarif'>;
  outputFormat?: 'json' | 'html' | 'pdf' | 'csv' | 'sarif';

  includePatterns?: string[];
  excludePatterns?: string[];
  maxDepth?: number;
  timeout?: number;
  concurrent?: number;

  dataHandling: DataHandlingConfig;
  auditLogging: boolean;
  generateSBOM: boolean;
  generateVEX: boolean;
  performanceMonitoring: boolean;
  complianceMapping: boolean;
  offlineMode: boolean;

  aiAnalysis: {
    enabled: boolean;
    costLimit: number;
    latencyLimit: number;
    privacyControls: boolean;
  };
}

export interface ScanReport {
  summary: ScanSummary;
  findings: ScanResult[];
  recommendations: string[];
  metadata: ScanMetadata;
}

export interface ScanSummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  riskScore: number;
  scanDuration: number;
}

export interface ScanMetadata {
  scannerVersion: string;
  scanDate: Date;
  targetPath: string;
  scanType: string;
  configuration: ScanConfig;
}

export interface AIAnalysis {
  riskAssessment: RiskAssessment;
  contextAnalysis: ContextAnalysis;
  remediationPlan: RemediationPlan;
  falsePositiveAnalysis: FalsePositiveAnalysis;
}

export interface RiskAssessment {
  overallRisk: SeverityLevel;
  riskFactors: RiskFactor[];
  businessImpact: string;
  exploitability: string;
}

export interface RiskFactor {
  factor: string;
  weight: number;
  description: string;
}

export interface ContextAnalysis {
  projectType: string;
  technologyStack: string[];
  architecture: string;
  securityContext: string;
}

export interface RemediationPlan {
  priority: RemediationPriority[];
  automatedFixes: AutomatedFix[];
  manualSteps: ManualStep[];
  timeline: string;
}

export interface RemediationPriority {
  findingId: string;
  priority: number;
  effort: string;
  impact: string;
}

export interface AutomatedFix {
  findingId: string;
  fixType: string;
  code: string;
  confidence: number;
}

export interface ManualStep {
  findingId: string;
  step: string;
  description: string;
  resources: string[];
}

export interface FalsePositiveAnalysis {
  confidence: number;
  reasoning: string;
  evidence: string[];
  recommendation: string;
}

// ========= Alerts =========

export interface SecurityAlert {
  id: string;
  type: AlertType;
  severity: SeverityLevel;
  title: string;
  message: string;
  timestamp: Date;
  source: string;
  actions: AlertAction[];
}

export enum AlertType {
  VULNERABILITY_DETECTED = 'vulnerability_detected',
  POLICY_VIOLATION = 'policy_violation',
  SYSTEM_COMPROMISE = 'system_compromise',
  CONFIGURATION_CHANGE = 'configuration_change',
  DEPENDENCY_UPDATE = 'dependency_update'
}

export interface AlertAction {
  type: string;
  description: string;
  url?: string;
  automated: boolean;
}

// Trust & Provenance Types
export interface TrustStore {
  servers: TrustedServer[];
  publicKeys: PublicKey[];
  allowlist: string[];
  denylist: string[];
  lastUpdated: string;
}

export interface TrustedServer {
  name: string;
  url: string;
  publicKey: string;
  sha256: string;
  version: string;
  capabilities: string[];
  verifiedAt: string;
  expiresAt?: string;
}

export interface PublicKey {
  id: string;
  key: string;
  algorithm: string;
  verifiedAt: string;
}

export interface ProvenanceAttestation {
  type: 'slsa' | 'cosign' | 'in-toto';
  payload: any;
  signature: string;
  publicKey: string;
  timestamp: string;
}

// MCP Security Configuration
export interface MCPSecurityConfig {
  trustStore: TrustStore;
  requireSignedServers: boolean;
  allowUntrustedServers: boolean;
  maxPayloadSize: number;
  enableResponseSanitization: boolean;
  enablePromptInjectionDetection: boolean;
  sandboxMode: 'docker' | 'process' | 'none';
  resourceLimits: {
    cpu: string;
    memory: string;
    disk: string;
  };
}

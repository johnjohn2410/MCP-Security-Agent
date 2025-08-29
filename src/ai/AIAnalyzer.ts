import OpenAI from 'openai';
import { AIAnalysis, Finding, VulnerabilityType, SeverityLevel, RiskAssessment, ContextAnalysis, RemediationPlan, FalsePositiveAnalysis } from '../types/index.js';
import { Logger } from '../utils/Logger.js';
import { DataHandler } from '../utils/DataHandler.js';

export class AIAnalyzer {
  private logger: Logger;
  private dataHandler: DataHandler;
  private openai: OpenAI | null = null;
  private offlineMode: boolean = false;
  private costLimit: number = 10.0; // USD
  private latencyLimit: number = 30000; // 30 seconds
  private privacyControls: boolean = true;
  private totalCost: number = 0;
  private requestCount: number = 0;

  constructor(
    logger: Logger,
    dataHandler: DataHandler,
    config: {
      offlineMode?: boolean;
      costLimit?: number;
      latencyLimit?: number;
      privacyControls?: boolean;
    } = {}
  ) {
    this.logger = logger;
    this.dataHandler = dataHandler;
    this.offlineMode = config.offlineMode ?? false;
    this.costLimit = config.costLimit ?? 10.0;
    this.latencyLimit = config.latencyLimit ?? 30000;
    this.privacyControls = config.privacyControls ?? true;

    // Initialize OpenAI if API key is available and not in offline mode
    if (!this.offlineMode && process.env.OPENAI_API_KEY) {
      this.openai = new OpenAI({
        apiKey: process.env.OPENAI_API_KEY,
        timeout: this.latencyLimit,
      });
      this.logger.info('OpenAI client initialized');
    } else if (this.offlineMode) {
      this.logger.info('AI Analyzer running in offline mode');
    } else {
      this.logger.warn('OpenAI API key not found, falling back to offline mode');
      this.offlineMode = true;
    }
  }

  /**
   * Analyze findings with AI
   */
  async analyzeFindings(
    findings: Finding[],
    projectContext: Record<string, any>
  ): Promise<AIAnalysis> {
    this.logger.info('Starting AI analysis', {
      findingsCount: findings.length,
      offlineMode: this.offlineMode,
      privacyControls: this.privacyControls
    });

    // Check cost limits
    if (this.totalCost >= this.costLimit) {
      this.logger.warn('Cost limit reached, falling back to offline analysis', {
        totalCost: this.totalCost,
        costLimit: this.costLimit
      });
      return this.performBasicAnalysis(findings, projectContext);
    }

    if (this.offlineMode || !this.openai) {
      return this.performBasicAnalysis(findings, projectContext);
    }

    try {
      // Process data for AI with privacy controls
      const analysisData = this.prepareAnalysisData(findings, projectContext);
      
      if (this.privacyControls) {
        const processed = this.dataHandler.processForAI(
          JSON.stringify(analysisData),
          'ai_analysis',
          'analyze_findings'
        );
        
        this.logger.info('Data processed for AI analysis', {
          originalSize: JSON.stringify(analysisData).length,
          processedSize: processed.processedData.length,
          redactionsCount: processed.redactions.size,
          tokensCount: processed.tokens.size
        });

        return await this.performAIAnalysis(processed.processedData, processed.auditEntry);
      } else {
        return await this.performAIAnalysis(JSON.stringify(analysisData));
      }
    } catch (error) {
      this.logger.error('AI analysis failed, falling back to basic analysis', error as Error);
      return this.performBasicAnalysis(findings, projectContext);
    }
  }

  /**
   * Perform AI analysis with OpenAI
   */
  private async performAIAnalysis(
    processedData: string,
    auditEntry?: any
  ): Promise<AIAnalysis> {
    if (!this.openai) {
      throw new Error('OpenAI client not initialized');
    }

    const startTime = Date.now();
    const prompt = this.buildAnalysisPrompt(processedData);

    try {
      const response = await this.openai.chat.completions.create({
        model: 'gpt-4',
        messages: [
          {
            role: 'system',
            content: this.getSystemPrompt()
          },
          {
            role: 'user',
            content: prompt
          }
        ],
        temperature: 0.1,
        max_tokens: 2000,
        response_format: { type: 'json_object' }
      });

      const endTime = Date.now();
      const latency = endTime - startTime;
      const cost = this.calculateCost(response.usage);

      this.totalCost += cost;
      this.requestCount++;

      // Log the analysis request
      this.logger.info('AI analysis completed', {
        latency,
        cost,
        totalCost: this.totalCost,
        requestCount: this.requestCount,
        tokensUsed: response.usage?.total_tokens,
        auditEntryId: auditEntry?.id
      });

      // Check latency limits
      if (latency > this.latencyLimit) {
        this.logger.warn('AI analysis exceeded latency limit', {
          latency,
          latencyLimit: this.latencyLimit
        });
      }

      const content = response.choices[0]?.message?.content;
      if (!content) {
        throw new Error('No content received from OpenAI');
      }

      return this.parseAIAnalysis(content);

    } catch (error) {
      this.logger.error('OpenAI API call failed', error as Error);
      throw error;
    }
  }

  /**
   * Perform basic analysis without AI
   */
  private performBasicAnalysis(
    findings: Finding[],
    projectContext: Record<string, any>
  ): AIAnalysis {
    this.logger.info('Performing basic analysis');

    const criticalFindings = findings.filter(f => f.severity === SeverityLevel.CRITICAL);
    const highFindings = findings.filter(f => f.severity === SeverityLevel.HIGH);
    const mediumFindings = findings.filter(f => f.severity === SeverityLevel.MEDIUM);
    const lowFindings = findings.filter(f => f.severity === SeverityLevel.LOW);

    const riskAssessment: RiskAssessment = {
      overallRisk: this.calculateOverallRisk(findings),
      riskFactors: this.generateRiskFactors(findings),
      businessImpact: this.assessBusinessImpact(findings),
      exploitability: this.assessExploitability(findings)
    };

    const contextAnalysis: ContextAnalysis = {
      projectType: projectContext.projectType || 'unknown',
      technologyStack: this.extractTechnologyStack(projectContext),
      architecture: 'Unknown - requires manual analysis',
      securityContext: 'Standard web application security context'
    };

    const remediationPlan: RemediationPlan = {
      priority: this.generatePriorityList(findings),
      automatedFixes: this.generateAutomatedFixes(findings),
      manualSteps: this.generateManualSteps(findings),
      timeline: this.calculateTimeline(findings)
    };

    const falsePositiveAnalysis: FalsePositiveAnalysis = {
      confidence: 0.7,
      reasoning: 'Basic analysis - manual review recommended for accuracy',
      evidence: this.identifyLikelyFalsePositives(findings),
      recommendation: 'Review findings manually and verify in context'
    };

    return {
      riskAssessment,
      contextAnalysis,
      remediationPlan,
      falsePositiveAnalysis
    };
  }

  /**
   * Prepare data for AI analysis
   */
  private prepareAnalysisData(
    findings: Finding[],
    projectContext: Record<string, any>
  ): Record<string, any> {
    return {
      findings: findings.map(finding => ({
        id: finding.id,
        type: finding.type,
        severity: finding.severity,
        title: finding.title,
        description: finding.description,
        file: finding.file,
        line: finding.line,
        evidence: finding.evidence,
        confidence: finding.confidence,
        cwe: finding.cwe,
        owasp: finding.owasp,
        nist: finding.nist,
        references: finding.references
      })),
      projectContext: {
        projectType: projectContext.projectType,
        technologyStack: projectContext.technologyStack,
        environment: projectContext.environment,
        complianceRequirements: projectContext.complianceRequirements
      },
      summary: {
        totalFindings: findings.length,
        criticalCount: findings.filter(f => f.severity === SeverityLevel.CRITICAL).length,
        highCount: findings.filter(f => f.severity === SeverityLevel.HIGH).length,
        mediumCount: findings.filter(f => f.severity === SeverityLevel.MEDIUM).length,
        lowCount: findings.filter(f => f.severity === SeverityLevel.LOW).length
      }
    };
  }

  /**
   * Build analysis prompt for AI
   */
  private buildAnalysisPrompt(data: string): string {
    return `Please analyze the following security findings and provide a comprehensive security assessment:

${data}

Please provide your analysis in the following JSON format:
{
  "riskAssessment": {
    "overallRisk": "low|medium|high|critical",
    "riskFactors": [
      {
        "factor": "string",
        "weight": 0.0-1.0,
        "description": "string"
      }
    ],
    "businessImpact": "string",
    "exploitability": "string"
  },
  "contextAnalysis": {
    "projectType": "string",
    "technologyStack": ["string"],
    "architecture": "string",
    "securityContext": "string"
  },
  "remediationPlan": {
    "priority": [
      {
        "findingId": "string",
        "priority": 1-10,
        "effort": "low|medium|high",
        "impact": "low|medium|high"
      }
    ],
    "automatedFixes": [
      {
        "findingId": "string",
        "fixType": "string",
        "code": "string",
        "confidence": 0.0-1.0
      }
    ],
    "manualSteps": [
      {
        "findingId": "string",
        "step": "string",
        "description": "string",
        "resources": ["string"]
      }
    ],
    "timeline": "string"
  },
  "falsePositiveAnalysis": {
    "confidence": 0.0-1.0,
    "reasoning": "string",
    "evidence": ["string"],
    "recommendation": "string"
  }
}`;
  }

  /**
   * Get system prompt for AI
   */
  private getSystemPrompt(): string {
    return `You are a security expert analyzing code vulnerabilities. Your role is to:

1. Assess the overall security risk of the findings
2. Provide context-aware analysis based on the project type and technology stack
3. Create actionable remediation plans with prioritized actions
4. Identify potential false positives and suggest verification steps
5. Consider compliance implications and security best practices

Be concise, practical, and focus on actionable insights. Prioritize findings by severity and exploitability.`;
  }

  /**
   * Parse AI analysis response
   */
  private parseAIAnalysis(content: string): AIAnalysis {
    try {
      const parsed = JSON.parse(content);
      
      return {
        riskAssessment: parsed.riskAssessment,
        contextAnalysis: parsed.contextAnalysis,
        remediationPlan: parsed.remediationPlan,
        falsePositiveAnalysis: parsed.falsePositiveAnalysis
      };
    } catch (error) {
      this.logger.error('Failed to parse AI analysis response', error as Error);
      throw new Error('Invalid AI analysis response format');
    }
  }

  /**
   * Calculate cost of OpenAI API call
   */
  private calculateCost(usage: any): number {
    if (!usage) return 0;
    
    // GPT-4 pricing (approximate)
    const inputCostPer1k = 0.03;
    const outputCostPer1k = 0.06;
    
    const inputCost = (usage.prompt_tokens / 1000) * inputCostPer1k;
    const outputCost = (usage.completion_tokens / 1000) * outputCostPer1k;
    
    return inputCost + outputCost;
  }

  /**
   * Calculate overall risk score
   */
  private calculateOverallRisk(findings: Finding[]): SeverityLevel {
    const criticalCount = findings.filter(f => f.severity === SeverityLevel.CRITICAL).length;
    const highCount = findings.filter(f => f.severity === SeverityLevel.HIGH).length;
    const mediumCount = findings.filter(f => f.severity === SeverityLevel.MEDIUM).length;

    if (criticalCount > 0) return SeverityLevel.CRITICAL;
    if (highCount > 2) return SeverityLevel.HIGH;
    if (highCount > 0 || mediumCount > 5) return SeverityLevel.MEDIUM;
    return SeverityLevel.LOW;
  }

  /**
   * Generate risk factors
   */
  private generateRiskFactors(findings: Finding[]): Array<{factor: string, weight: number, description: string}> {
    const criticalCount = findings.filter(f => f.severity === SeverityLevel.CRITICAL).length;
    const highCount = findings.filter(f => f.severity === SeverityLevel.HIGH).length;
    const totalCount = findings.length;

    const factors = [];

    if (criticalCount > 0) {
      factors.push({
        factor: 'Critical Vulnerabilities',
        weight: 1.0,
        description: `${criticalCount} critical vulnerabilities detected`
      });
    }

    if (highCount > 0) {
      factors.push({
        factor: 'High Severity Issues',
        weight: 0.8,
        description: `${highCount} high severity issues detected`
      });
    }

    if (totalCount > 10) {
      factors.push({
        factor: 'High Finding Count',
        weight: 0.6,
        description: `${totalCount} total security findings`
      });
    }

    return factors;
  }

  /**
   * Assess business impact
   */
  private assessBusinessImpact(findings: Finding[]): string {
    const criticalCount = findings.filter(f => f.severity === SeverityLevel.CRITICAL).length;
    const highCount = findings.filter(f => f.severity === SeverityLevel.HIGH).length;

    if (criticalCount > 0) {
      return 'Critical business impact - immediate action required';
    } else if (highCount > 0) {
      return 'High business impact - urgent attention needed';
    } else if (findings.length > 5) {
      return 'Moderate business impact - should be addressed soon';
    } else {
      return 'Low business impact - can be addressed during regular maintenance';
    }
  }

  /**
   * Assess exploitability
   */
  private assessExploitability(findings: Finding[]): string {
    const criticalCount = findings.filter(f => f.severity === SeverityLevel.CRITICAL).length;
    const highCount = findings.filter(f => f.severity === SeverityLevel.HIGH).length;

    if (criticalCount > 0) {
      return 'Highly exploitable - immediate remediation required';
    } else if (highCount > 0) {
      return 'Easily exploitable - should be fixed quickly';
    } else if (findings.length > 5) {
      return 'Moderately exploitable - requires some effort';
    } else {
      return 'Low exploitability - minimal risk';
    }
  }

  /**
   * Extract technology stack from context
   */
  private extractTechnologyStack(context: Record<string, any>): string[] {
    const stack: string[] = [];
    
    if (context.technologyStack) {
      stack.push(...context.technologyStack);
    }

    // Infer from file extensions or other context
    if (context.fileTypes) {
      if (context.fileTypes.includes('js') || context.fileTypes.includes('ts')) {
        stack.push('JavaScript/TypeScript');
      }
      if (context.fileTypes.includes('py')) {
        stack.push('Python');
      }
      if (context.fileTypes.includes('java')) {
        stack.push('Java');
      }
    }

    return [...new Set(stack)];
  }

  /**
   * Generate priority list
   */
  private generatePriorityList(findings: Finding[]): Array<{findingId: string, priority: number, effort: string, impact: string}> {
    return findings
      .sort((a, b) => {
        const severityOrder = { 
          [SeverityLevel.CRITICAL]: 4, 
          [SeverityLevel.HIGH]: 3, 
          [SeverityLevel.MEDIUM]: 2, 
          [SeverityLevel.LOW]: 1,
          [SeverityLevel.INFO]: 0
        };
        return severityOrder[b.severity] - severityOrder[a.severity];
      })
      .map((finding, index) => ({
        findingId: finding.id,
        priority: index + 1,
        effort: this.assessEffort(finding),
        impact: finding.severity
      }));
  }

  /**
   * Assess effort required for fixing a finding
   */
  private assessEffort(finding: Finding): string {
    switch (finding.type) {
      case VulnerabilityType.HARDCODED_SECRET:
        return 'medium';
      case VulnerabilityType.SQL_INJECTION:
        return 'high';
      case VulnerabilityType.XSS:
        return 'medium';
      case VulnerabilityType.INSECURE_DEPENDENCY:
        return 'low';
      default:
        return 'medium';
    }
  }

  /**
   * Generate automated fixes
   */
  private generateAutomatedFixes(findings: Finding[]): Array<{findingId: string, fixType: string, code: string, confidence: number}> {
    const fixes = [];

    for (const finding of findings) {
      if (finding.type === 'hardcoded_secret') {
        fixes.push({
          findingId: finding.id,
          fixType: 'Environment Variable',
          code: `// Replace: ${finding.evidence}\n// With: process.env.SECRET_NAME`,
          confidence: 0.8
        });
      }
    }

    return fixes;
  }

  /**
   * Generate manual steps
   */
  private generateManualSteps(findings: Finding[]): Array<{findingId: string, step: string, description: string, resources: string[]}> {
    return findings.map(finding => ({
      findingId: finding.id,
      step: `Fix ${finding.type.replace('_', ' ')}`,
      description: finding.remediation || 'Review and fix the security issue',
      resources: ['OWASP Guidelines', 'Security Best Practices']
    }));
  }

  /**
   * Calculate timeline
   */
  private calculateTimeline(findings: Finding[]): string {
    const criticalCount = findings.filter(f => f.severity === SeverityLevel.CRITICAL).length;
    const highCount = findings.filter(f => f.severity === SeverityLevel.HIGH).length;
    
    if (criticalCount > 0) return '1-2 weeks (critical issues)';
    if (highCount > 0) return '2-4 weeks';
    if (findings.length > 10) return '4-6 weeks';
    return '1-2 weeks';
  }

  /**
   * Identify likely false positives
   */
  private identifyLikelyFalsePositives(findings: Finding[]): string[] {
    const falsePositives: string[] = [];

    findings.forEach(finding => {
      if (finding.confidence < 0.5) {
        falsePositives.push(`${finding.title} in ${finding.file}:${finding.line} (low confidence)`);
      }
      
      if (finding.type === 'hardcoded_secret' && finding.file.includes('test')) {
        falsePositives.push(`${finding.title} in ${finding.file}:${finding.line} (test environment)`);
      }
    });

    return falsePositives;
  }

  /**
   * Get analysis statistics
   */
  getAnalysisStats(): {
    totalCost: number;
    requestCount: number;
    averageLatency: number;
    offlineMode: boolean;
  } {
    return {
      totalCost: this.totalCost,
      requestCount: this.requestCount,
      averageLatency: 0, // Would need to track individual latencies
      offlineMode: this.offlineMode
    };
  }

  /**
   * Reset cost tracking
   */
  resetCostTracking(): void {
    this.totalCost = 0;
    this.requestCount = 0;
    this.logger.info('Cost tracking reset');
  }

  /**
   * Get privacy statement
   */
  getPrivacyStatement(): string {
    return this.dataHandler.getPrivacyStatement();
  }
}

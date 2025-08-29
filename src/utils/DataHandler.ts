import { createHash, randomUUID } from 'node:crypto';
import { AuditLogEntry, DataHandlingConfig } from '../types/index.js';
import { Logger } from './Logger.js';

export class DataHandler {
  private readonly config: DataHandlingConfig;
  private readonly logger: Logger;

  private readonly audit: AuditLogEntry[] = [];
  private readonly sessionId: string;
  private readonly userId?: string;
  private readonly ipAddress?: string;
  private readonly userAgent?: string;

  constructor(
    config: DataHandlingConfig,
    logger: Logger,
    identity?: { sessionId?: string; userId?: string; ipAddress?: string; userAgent?: string }
  ) {
    this.config = config;
    this.logger = logger;
    this.sessionId = identity?.sessionId ?? randomUUID();
    this.userId = identity?.userId;
    this.ipAddress = identity?.ipAddress;
    this.userAgent = identity?.userAgent;
  }

  private generateId(): string {
    return randomUUID();
  }

  public generateHash(input: string): string {
    return createHash('sha256').update(input).digest('hex');
  }

  public getAuditLog(): AuditLogEntry[] {
    return this.audit;
  }

  public recordAuditEvent(params: {
    operation: string;
    resource: string;
    action: string;
    result: 'success' | 'failure' | 'denied';
    evidence?: string;                      // optional, will default to ''
    dataHash: string;
    extra?: Record<string, any>;
  }) {
    const { operation, resource, action, result, evidence, dataHash, extra } = params;

    const entry: AuditLogEntry = {
      id: this.generateId(),
      timestamp: new Date().toISOString(),
      operation,
      sessionId: this.sessionId,            // <-- REQUIRED
      resource,
      action,
      result,
      evidence: evidence ?? '',             // <-- REQUIRED
      dataHash,
      previousHash: this.audit.length ? this.audit[this.audit.length - 1].dataHash : undefined,
      signature: undefined,
      metadata: {
        sessionId: this.sessionId,
        userId: this.userId ?? 'anonymous',
        ipAddress: this.ipAddress ?? 'unknown',
        userAgent: this.userAgent ?? 'unknown',
        ...extra,
      },
    };

    this.audit.push(entry);
    this.logger.audit('Audit log entry created', entry); // Logger.audit(message, meta?)
  }

  /**
   * Create an audit log entry (legacy method for compatibility)
   */
  createAuditEntry(operation: string, resource: string, action: string, result: 'success' | 'failure' | 'denied', data?: any): AuditLogEntry {
    const dataHash = data ? this.generateHash(JSON.stringify(data)) : '';
    
    this.recordAuditEvent({
      operation,
      resource,
      action,
      result,
      evidence: `Operation: ${operation}, Resource: ${resource}, Action: ${action}, Result: ${result}`,
      dataHash,
      extra: data
    });

    return this.audit[this.audit.length - 1];
  }

  /**
   * Redact sensitive data from input
   */
  redactSensitiveData(data: string): { redactedData: string; redactions: Map<string, string> } {
    const redactions = new Map<string, string>();
    let redactedData = data;

    if (this.config.redactSecrets) {
      // Redact API keys, tokens, passwords
      const secretPatterns = [
        /(api[_-]?key|token|password|secret|private[_-]?key)\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{16,}['"]?/gi,
        /(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['"]?[A-Z0-9]{20}['"]?/gi,
        /(sk-[a-zA-Z0-9]{24})/g,
        /(pk-[a-zA-Z0-9]{24})/g,
        /(ghp_[a-zA-Z0-9]{36})/g,
        /(gho_[a-zA-Z0-9]{36})/g,
        /(ghu_[a-zA-Z0-9]{36})/g,
        /(ghs_[a-zA-Z0-9]{36})/g,
        /(ghr_[a-zA-Z0-9]{36})/g,
        /(xoxb-[a-zA-Z0-9-]+)/g,
        /(xoxp-[a-zA-Z0-9-]+)/g,
        /(xoxa-[a-zA-Z0-9-]+)/g,
        /(xoxr-[a-zA-Z0-9-]+)/g,
        /(xoxs-[a-zA-Z0-9-]+)/g,
        /(xoxo-[a-zA-Z0-9-]+)/g,
        /(AIza[0-9A-Za-z\-_]{35})/g,
        /(1[0-9]{9,11}|[0-9]{9,11})/g, // Phone numbers
        /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g, // Email addresses
      ];

      secretPatterns.forEach((pattern, index) => {
        redactedData = redactedData.replace(pattern, (match) => {
          const token = `[REDACTED_SECRET_${index}_${randomUUID().substring(0, 8)}]`;
          redactions.set(token, match);
          return token;
        });
      });
    }

    if (this.config.redactPII) {
      // Redact PII patterns
      const piiPatterns = [
        /(\b\d{3}-\d{2}-\d{4}\b)/g, // SSN
        /(\b\d{4}-\d{4}-\d{4}-\d{4}\b)/g, // Credit card
        /(\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b)/g, // IBAN
        /(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/g, // IP addresses
        /(\b[A-Fa-f0-9]{2}(:[A-Fa-f0-9]{2}){5}\b)/g, // MAC addresses
      ];

      piiPatterns.forEach((pattern, index) => {
        redactedData = redactedData.replace(pattern, (match) => {
          const token = `[REDACTED_PII_${index}_${randomUUID().substring(0, 8)}]`;
          redactions.set(token, match);
          return token;
        });
      });
    }

    return { redactedData, redactions };
  }

  /**
   * Tokenize code snippets to reduce size and scope
   */
  tokenizeCode(code: string): { tokenizedCode: string; tokens: Map<string, string> } {
    const tokens = new Map<string, string>();
    let tokenizedCode = code;

    if (this.config.tokenizeCode) {
      // Tokenize long variable names, function names, etc.
      const codePatterns = [
        /([a-zA-Z_][a-zA-Z0-9_]{20,})/g, // Long identifiers
        /(\b(?:function|class|const|let|var)\s+([a-zA-Z_][a-zA-Z0-9_]{15,}))/g, // Long declarations
        /(\b(?:import|from)\s+['"][^'"]{50,}['"])/g, // Long import paths
      ];

      codePatterns.forEach((pattern, index) => {
        tokenizedCode = tokenizedCode.replace(pattern, (match) => {
          const token = `[TOKEN_${index}_${randomUUID().substring(0, 8)}]`;
          tokens.set(token, match);
          return token;
        });
      });

      // Limit code snippet size
      if (tokenizedCode.length > this.config.maxCodeSnippetSize) {
        const truncated = tokenizedCode.substring(0, this.config.maxCodeSnippetSize);
        tokenizedCode = truncated + '\n// ... [TRUNCATED] ...';
      }
    }

    return { tokenizedCode, tokens };
  }

  /**
   * Process data for AI analysis with all security controls
   */
  processForAI(
    data: string,
    context: string,
    operation: string
  ): {
    processedData: string;
    auditEntry: AuditLogEntry;
    redactions: Map<string, string>;
    tokens: Map<string, string>;
  } {
    // Validate data size
    if (data.length > this.config.maxCodeSnippetSize) {
      throw new Error(`Data size ${data.length} exceeds maximum allowed size ${this.config.maxCodeSnippetSize}`);
    }

    // Redact sensitive data
    const { redactedData, redactions } = this.redactSensitiveData(data);

    // Tokenize code
    const { tokenizedCode, tokens } = this.tokenizeCode(redactedData);

    // Create audit entry
    const auditEntry = this.createAuditEntry(
      operation,
      context,
      'ai_analysis',
      'success',
      {
        originalSize: data.length,
        processedSize: tokenizedCode.length,
        redactionsCount: redactions.size,
        tokensCount: tokens.size,
        processedData: tokenizedCode
      }
    );

    this.logger.info('Data processed for AI analysis', {
      operation,
      context,
      originalSize: data.length,
      processedSize: tokenizedCode.length,
      redactionsCount: redactions.size,
      tokensCount: tokens.size,
    });

    return {
      processedData: tokenizedCode,
      auditEntry,
      redactions,
      tokens,
    };
  }

  /**
   * Restore original data from tokens and redactions
   */
  restoreData(
    processedData: string,
    redactions: Map<string, string>,
    tokens: Map<string, string>
  ): string {
    let restoredData = processedData;

    // Restore tokens
    tokens.forEach((original, token) => {
      restoredData = restoredData.replace(new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), original);
    });

    // Restore redactions
    redactions.forEach((original, token) => {
      restoredData = restoredData.replace(new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), original);
    });

    return restoredData;
  }

  /**
   * Get privacy statement
   */
  getPrivacyStatement(): string {
    return this.config.privacyStatement;
  }

  /**
   * Clean up old audit logs based on retention policy
   */
  cleanupOldAuditLogs(): void {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.dataRetentionDays);

    const originalLength = this.audit.length;
    this.audit.splice(0, this.audit.length, ...this.audit.filter(entry => {
      const entryDate = new Date(entry.timestamp);
      return entryDate > cutoffDate;
    }));

    this.logger.info('Cleaned up old audit logs', {
      retentionDays: this.config.dataRetentionDays,
      remainingEntries: this.audit.length,
      removedEntries: originalLength - this.audit.length,
    });
  }

  /**
   * Get audit log statistics
   */
  getAuditStats(): {
    totalEntries: number;
    sessionId: string;
    oldestEntry?: string;
    newestEntry?: string;
  } {
    if (this.audit.length === 0) {
      return {
        totalEntries: 0,
        sessionId: this.sessionId,
      };
    }

    const timestamps = this.audit.map(entry => new Date(entry.timestamp));
    const oldest = new Date(Math.min(...timestamps.map(t => t.getTime())));
    const newest = new Date(Math.max(...timestamps.map(t => t.getTime())));

    return {
      totalEntries: this.audit.length,
      sessionId: this.sessionId,
      oldestEntry: oldest.toISOString(),
      newestEntry: newest.toISOString(),
    };
  }
}

import { Logger } from './Logger.js';

export interface SanitizationConfig {
  maxPayloadSize: number;
  enablePromptInjectionDetection: boolean;
  stripSuspiciousDirectives: boolean;
  enforceJsonOnly: boolean;
  allowedContentTypes: string[];
}

export class ResponseSanitizer {
  private logger: Logger;
  private config: SanitizationConfig;

  constructor(logger: Logger, config: SanitizationConfig) {
    this.logger = logger;
    this.config = config;
  }

  /**
   * Sanitize MCP response payload
   */
  sanitizeResponse(payload: any): { sanitized: any; warnings: string[] } {
    const warnings: string[] = [];
    let sanitized = payload;

    try {
      // Check payload size
      const payloadSize = JSON.stringify(payload).length;
      if (payloadSize > this.config.maxPayloadSize) {
        warnings.push(`Payload size ${payloadSize} exceeds limit ${this.config.maxPayloadSize}`);
        sanitized = this.truncatePayload(payload);
      }

      // Enforce JSON-only mode
      if (this.config.enforceJsonOnly) {
        sanitized = this.enforceJsonOnly(sanitized);
      }

      // Strip suspicious directives
      if (this.config.stripSuspiciousDirectives) {
        sanitized = this.stripSuspiciousDirectives(sanitized);
      }

      // Detect prompt injection
      if (this.config.enablePromptInjectionDetection) {
        const injectionDetected = this.detectPromptInjection(sanitized);
        if (injectionDetected) {
          warnings.push('Potential prompt injection detected');
          sanitized = this.sanitizePromptInjection(sanitized);
        }
      }

      this.logger.info(`Response sanitized with ${warnings.length} warnings`);
      return { sanitized, warnings };
    } catch (error) {
      this.logger.error('Error sanitizing response:', error as Error);
      return { sanitized: payload, warnings: ['Sanitization failed'] };
    }
  }

  /**
   * Truncate oversized payloads
   */
  private truncatePayload(payload: any): any {
    if (typeof payload === 'string') {
      return payload.substring(0, this.config.maxPayloadSize / 2);
    }

    if (typeof payload === 'object') {
      const truncated: any = {};
      const maxKeys = Math.floor(this.config.maxPayloadSize / 1000);
      let keyCount = 0;

      for (const [key, value] of Object.entries(payload)) {
        if (keyCount >= maxKeys) break;
        truncated[key] = value;
        keyCount++;
      }

      return truncated;
    }

    return payload;
  }

  /**
   * Enforce JSON-only content
   */
  private enforceJsonOnly(payload: any): any {
    if (typeof payload === 'string') {
      // Remove any non-JSON content
      return payload.replace(/[^\x20-\x7E]/g, '');
    }

    if (typeof payload === 'object') {
      const cleaned: any = {};
      for (const [key, value] of Object.entries(payload)) {
        if (typeof value === 'string') {
          cleaned[key] = this.enforceJsonOnly(value);
        } else if (typeof value === 'object' && value !== null) {
          cleaned[key] = this.enforceJsonOnly(value);
        } else {
          cleaned[key] = value;
        }
      }
      return cleaned;
    }

    return payload;
  }

  /**
   * Strip suspicious directives from content
   */
  private stripSuspiciousDirectives(payload: any): any {
    const suspiciousPatterns = [
      /ignore previous instructions/gi,
      /ignore above instructions/gi,
      /forget everything/gi,
      /new instructions/gi,
      /system prompt/gi,
      /roleplay/gi,
      /pretend to be/gi,
      /act as if/gi
    ];

    if (typeof payload === 'string') {
      let cleaned = payload;
      for (const pattern of suspiciousPatterns) {
        cleaned = cleaned.replace(pattern, '[REDACTED]');
      }
      return cleaned;
    }

    if (typeof payload === 'object') {
      const cleaned: any = {};
      for (const [key, value] of Object.entries(payload)) {
        if (typeof value === 'string') {
          cleaned[key] = this.stripSuspiciousDirectives(value);
        } else if (typeof value === 'object' && value !== null) {
          cleaned[key] = this.stripSuspiciousDirectives(value);
        } else {
          cleaned[key] = value;
        }
      }
      return cleaned;
    }

    return payload;
  }

  /**
   * Detect potential prompt injection
   */
  private detectPromptInjection(payload: any): boolean {
    const injectionPatterns = [
      /ignore previous instructions/gi,
      /ignore above instructions/gi,
      /forget everything/gi,
      /new instructions/gi,
      /system prompt/gi,
      /roleplay/gi,
      /pretend to be/gi,
      /act as if/gi,
      /override/gi,
      /bypass/gi,
      /ignore safety/gi,
      /ignore ethics/gi
    ];

    const payloadStr = JSON.stringify(payload).toLowerCase();
    
    for (const pattern of injectionPatterns) {
      if (pattern.test(payloadStr)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Sanitize detected prompt injection
   */
  private sanitizePromptInjection(payload: any): any {
    if (typeof payload === 'string') {
      return '[SANITIZED: Potential prompt injection detected]';
    }

    if (typeof payload === 'object') {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(payload)) {
        if (typeof value === 'string' && this.detectPromptInjection(value)) {
          sanitized[key] = '[SANITIZED]';
        } else if (typeof value === 'object' && value !== null) {
          sanitized[key] = this.sanitizePromptInjection(value);
        } else {
          sanitized[key] = value;
        }
      }
      return sanitized;
    }

    return payload;
  }

  /**
   * Validate content type
   */
  validateContentType(contentType: string): boolean {
    return this.config.allowedContentTypes.includes(contentType);
  }

  /**
   * Get sanitization statistics
   */
  getStats(): { totalSanitized: number; warningsGenerated: number } {
    // In a real implementation, this would track statistics
    return { totalSanitized: 0, warningsGenerated: 0 };
  }
}

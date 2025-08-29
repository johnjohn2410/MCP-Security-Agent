import { Logger } from './Logger.js';

export interface MCPSchemaValidationResult {
  isValid: boolean;
  errors: string[];
  warnings: string[];
  payloadSize: number;
  isOversized: boolean;
}

export interface MCPSchemaConfig {
  maxPayloadSize: number;
  enforceJsonOnly: boolean;
  validateEnvelopes: boolean;
  allowUnknownFields: boolean;
}

export class MCPSchemaValidator {
  private logger: Logger;
  private config: MCPSchemaConfig;
  private mcpSchemas: Map<string, any>;

  constructor(logger: Logger, config: MCPSchemaConfig) {
    this.logger = logger;
    this.config = config;
    this.mcpSchemas = new Map();
    this.initializeMCPSchemas();
  }

  /**
   * Initialize MCP protocol schemas
   */
  private initializeMCPSchemas(): void {
    // MCP Request Schema
    this.mcpSchemas.set('request', {
      type: 'object',
      required: ['jsonrpc', 'id', 'method', 'params'],
      properties: {
        jsonrpc: { type: 'string', enum: ['2.0'] },
        id: { oneOf: [{ type: 'string' }, { type: 'number' }] },
        method: { type: 'string', pattern: '^[a-zA-Z_][a-zA-Z0-9_]*$' },
        params: { type: 'object' }
      },
      additionalProperties: this.config.allowUnknownFields
    });

    // MCP Response Schema
    this.mcpSchemas.set('response', {
      type: 'object',
      required: ['jsonrpc', 'id'],
      properties: {
        jsonrpc: { type: 'string', enum: ['2.0'] },
        id: { oneOf: [{ type: 'string' }, { type: 'number' }] },
        result: { type: 'object' },
        error: {
          type: 'object',
          properties: {
            code: { type: 'number' },
            message: { type: 'string' },
            data: { type: 'object' }
          },
          required: ['code', 'message']
        }
      },
      additionalProperties: this.config.allowUnknownFields
    });

    // MCP Notification Schema
    this.mcpSchemas.set('notification', {
      type: 'object',
      required: ['jsonrpc', 'method'],
      properties: {
        jsonrpc: { type: 'string', enum: ['2.0'] },
        method: { type: 'string', pattern: '^[a-zA-Z_][a-zA-Z0-9_]*$' },
        params: { type: 'object' }
      },
      additionalProperties: this.config.allowUnknownFields
    });

    // MCP Tool Call Schema
    this.mcpSchemas.set('tool_call', {
      type: 'object',
      required: ['jsonrpc', 'id', 'method', 'params'],
      properties: {
        jsonrpc: { type: 'string', enum: ['2.0'] },
        id: { oneOf: [{ type: 'string' }, { type: 'number' }] },
        method: { type: 'string', pattern: '^tools/call$' },
        params: {
          type: 'object',
          required: ['name', 'arguments'],
          properties: {
            name: { type: 'string' },
            arguments: { type: 'object' }
          }
        }
      },
      additionalProperties: this.config.allowUnknownFields
    });

    // MCP Tool Result Schema
    this.mcpSchemas.set('tool_result', {
      type: 'object',
      required: ['jsonrpc', 'id', 'result'],
      properties: {
        jsonrpc: { type: 'string', enum: ['2.0'] },
        id: { oneOf: [{ type: 'string' }, { type: 'number' }] },
        result: {
          type: 'object',
          required: ['content'],
          properties: {
            content: {
              type: 'array',
              items: {
                type: 'object',
                required: ['type'],
                properties: {
                  type: { type: 'string', enum: ['text', 'image_url'] },
                  text: { type: 'string' },
                  image_url: {
                    type: 'object',
                    properties: {
                      url: { type: 'string' }
                    }
                  }
                }
              }
            }
          }
        }
      },
      additionalProperties: this.config.allowUnknownFields
    });
  }

  /**
   * Validate MCP envelope
   */
  validateEnvelope(
    payload: any,
    envelopeType: 'request' | 'response' | 'notification' | 'tool_call' | 'tool_result'
  ): MCPSchemaValidationResult {
    const result: MCPSchemaValidationResult = {
      isValid: true,
      errors: [],
      warnings: [],
      payloadSize: 0,
      isOversized: false
    };

    try {
      // Check payload size
      const payloadStr = JSON.stringify(payload);
      result.payloadSize = payloadStr.length;
      result.isOversized = result.payloadSize > this.config.maxPayloadSize;

      if (result.isOversized) {
        result.errors.push(`Payload size ${result.payloadSize} exceeds limit ${this.config.maxPayloadSize}`);
        result.isValid = false;
      }

      // Enforce JSON-only mode
      if (this.config.enforceJsonOnly) {
        const jsonOnlyResult = this.validateJsonOnly(payload);
        if (!jsonOnlyResult.isValid) {
          result.errors.push(...jsonOnlyResult.errors);
          result.isValid = false;
        }
      }

      // Validate against MCP schema
      if (this.config.validateEnvelopes) {
        const schema = this.mcpSchemas.get(envelopeType);
        if (schema) {
          const schemaResult = this.validateAgainstSchema(payload, schema);
          if (!schemaResult.isValid) {
            result.errors.push(...schemaResult.errors);
            result.isValid = false;
          }
          result.warnings.push(...schemaResult.warnings);
        }
      }

      // Additional MCP-specific validations
      const mcpResult = this.validateMCPSpecific(payload, envelopeType);
      if (!mcpResult.isValid) {
        result.errors.push(...mcpResult.errors);
        result.isValid = false;
      }
      result.warnings.push(...mcpResult.warnings);

    } catch (error) {
      result.errors.push(`Validation error: ${error instanceof Error ? error.message : 'Unknown error'}`);
      result.isValid = false;
    }

    this.logger.info(`MCP envelope validation: ${envelopeType}`, {
      isValid: result.isValid,
      errors: result.errors.length,
      warnings: result.warnings.length,
      payloadSize: result.payloadSize
    });

    return result;
  }

  /**
   * Validate JSON-only content
   */
  private validateJsonOnly(payload: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    const checkValue = (value: any, path: string = ''): void => {
      if (typeof value === 'string') {
        // Check for non-JSON characters
        if (/[^\x20-\x7E]/.test(value)) {
          errors.push(`Non-JSON characters found in ${path || 'root'}`);
        }
      } else if (typeof value === 'object' && value !== null) {
        if (Array.isArray(value)) {
          value.forEach((item, index) => checkValue(item, `${path}[${index}]`));
        } else {
          Object.entries(value).forEach(([key, val]) => {
            checkValue(val, path ? `${path}.${key}` : key);
          });
        }
      }
    };

    checkValue(payload);
    return { isValid: errors.length === 0, errors };
  }

  /**
   * Validate against JSON schema
   */
  private validateAgainstSchema(payload: any, schema: any): { isValid: boolean; errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Simple schema validation (in production, use a proper JSON Schema validator)
    const validate = (obj: any, schema: any, path: string = ''): void => {
      if (schema.type && typeof obj !== schema.type) {
        errors.push(`Type mismatch at ${path}: expected ${schema.type}, got ${typeof obj}`);
        return;
      }

      if (schema.required && Array.isArray(schema.required)) {
        for (const field of schema.required) {
          if (!(field in obj)) {
            errors.push(`Missing required field: ${path ? `${path}.${field}` : field}`);
          }
        }
      }

      if (schema.properties && typeof obj === 'object' && obj !== null) {
        for (const [key, value] of Object.entries(obj)) {
          if (schema.properties[key]) {
            validate(value, schema.properties[key], path ? `${path}.${key}` : key);
          } else if (!schema.additionalProperties) {
            warnings.push(`Unknown field: ${path ? `${path}.${key}` : key}`);
          }
        }
      }

      if (schema.enum && !schema.enum.includes(obj)) {
        errors.push(`Invalid enum value at ${path}: ${obj}, expected one of ${schema.enum.join(', ')}`);
      }

      if (schema.pattern && typeof obj === 'string') {
        const regex = new RegExp(schema.pattern);
        if (!regex.test(obj)) {
          errors.push(`Pattern mismatch at ${path}: ${obj} does not match ${schema.pattern}`);
        }
      }
    };

    validate(payload, schema);
    return { isValid: errors.length === 0, errors, warnings };
  }

  /**
   * MCP-specific validations
   */
  private validateMCPSpecific(payload: any, envelopeType: string): { isValid: boolean; errors: string[]; warnings: string[] } {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Validate jsonrpc version
    if (payload.jsonrpc !== '2.0') {
      errors.push(`Invalid jsonrpc version: ${payload.jsonrpc}, expected 2.0`);
    }

    // Validate method names
    if (payload.method) {
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(payload.method)) {
        errors.push(`Invalid method name: ${payload.method}`);
      }
    }

    // Validate ID format
    if (payload.id !== undefined) {
      if (typeof payload.id !== 'string' && typeof payload.id !== 'number') {
        errors.push(`Invalid ID type: ${typeof payload.id}, expected string or number`);
      }
    }

    // Check for both result and error (invalid)
    if (payload.result !== undefined && payload.error !== undefined) {
      errors.push('Response cannot have both result and error');
    }

    // Validate error structure
    if (payload.error) {
      if (typeof payload.error.code !== 'number') {
        errors.push('Error code must be a number');
      }
      if (typeof payload.error.message !== 'string') {
        errors.push('Error message must be a string');
      }
    }

    return { isValid: errors.length === 0, errors, warnings };
  }

  /**
   * Suggest pagination for oversized payloads
   */
  suggestPagination(payload: any, maxSize: number): { shouldPaginate: boolean; suggestion: string } {
    const payloadSize = JSON.stringify(payload).length;
    
    if (payloadSize <= maxSize) {
      return { shouldPaginate: false, suggestion: '' };
    }

    return {
      shouldPaginate: true,
      suggestion: `Consider paginating results. Current size: ${payloadSize}, limit: ${maxSize}. Use 'limit' and 'offset' parameters.`
    };
  }

  /**
   * Get validation statistics
   */
  getValidationStats(): { totalValidated: number; validEnvelopes: number; oversizedPayloads: number } {
    // In a real implementation, this would track statistics
    return { totalValidated: 0, validEnvelopes: 0, oversizedPayloads: 0 };
  }
}

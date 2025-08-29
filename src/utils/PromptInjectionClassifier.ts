import { Logger } from './Logger.js';

export interface PromptInjectionResult {
  detected: boolean;
  confidence: number;
  score: number;
  patterns: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  explanation: string;
}

export interface PromptInjectionConfig {
  enableMLDetection: boolean;
  enableRuleDetection: boolean;
  confidenceThreshold: number;
  maxPatterns: number;
}

export class PromptInjectionClassifier {
  private logger: Logger;
  private config: PromptInjectionConfig;
  private injectionPatterns: Map<string, { pattern: RegExp; weight: number; description: string }>;
  private mlModel: any; // In production, this would be a proper ML model

  constructor(logger: Logger, config: PromptInjectionConfig) {
    this.logger = logger;
    this.config = config;
    this.injectionPatterns = new Map();
    this.initializePatterns();
  }

  /**
   * Initialize prompt injection detection patterns
   */
  private initializePatterns(): void {
    // High-risk patterns (weight: 1.0)
    this.injectionPatterns.set('ignore_previous', {
      pattern: /ignore\s+(?:all\s+)?(?:previous|above|earlier)\s+(?:instructions?|commands?|prompts?)/gi,
      weight: 1.0,
      description: 'Attempt to ignore previous instructions'
    });
    this.injectionPatterns.set('forget_everything', {
      pattern: /forget\s+(?:everything|all|what\s+you\s+know)/gi,
      weight: 1.0,
      description: 'Attempt to clear context'
    });
    this.injectionPatterns.set('new_instructions', {
      pattern: /new\s+(?:instructions?|commands?|prompts?|rules?)/gi,
      weight: 1.0,
      description: 'Attempt to provide new instructions'
    });
    this.injectionPatterns.set('system_prompt', {
      pattern: /system\s+prompt|system\s+message|system\s+instruction/gi,
      weight: 1.0,
      description: 'Reference to system prompt'
    });

    // Medium-risk patterns (weight: 0.7)
    this.injectionPatterns.set('roleplay', {
      pattern: /roleplay|pretend\s+to\s+be|act\s+as|play\s+the\s+role/gi,
      weight: 0.7,
      description: 'Roleplay directive'
    });
    this.injectionPatterns.set('override', {
      pattern: /override|bypass|ignore\s+safety|ignore\s+ethics/gi,
      weight: 0.7,
      description: 'Override or bypass directive'
    });
    this.injectionPatterns.set('confidential', {
      pattern: /confidential|secret|private|internal\s+only/gi,
      weight: 0.7,
      description: 'Confidentiality directive'
    });

    // Low-risk patterns (weight: 0.3)
    this.injectionPatterns.set('hypothetical', {
      pattern: /hypothetical|theoretical|what\s+if|imagine/gi,
      weight: 0.3,
      description: 'Hypothetical scenario'
    });
    this.injectionPatterns.set('creative', {
      pattern: /creative|artistic|fictional|story/gi,
      weight: 0.3,
      description: 'Creative content directive'
    });
    this.injectionPatterns.set('educational', {
      pattern: /educational|learning|teaching|example/gi,
      weight: 0.3,
      description: 'Educational content'
    });
  }

  /**
   * Classify content for prompt injection
   */
  classify(content: string): PromptInjectionResult {
    const result: PromptInjectionResult = {
      detected: false,
      confidence: 0.0,
      score: 0.0,
      patterns: [],
      riskLevel: 'low',
      explanation: ''
    };

    try {
      // Rule-based detection
      if (this.config.enableRuleDetection) {
        const ruleResult = this.ruleBasedDetection(content);
        result.score += ruleResult.score;
        result.patterns.push(...ruleResult.patterns);
      }

      // ML-based detection (if enabled)
      if (this.config.enableMLDetection) {
        const mlResult = this.mlBasedDetection(content);
        result.score += mlResult.score;
        if (mlResult.patterns.length > 0) {
          result.patterns.push(...mlResult.patterns);
        }
      }

      // Calculate confidence and risk level
      result.confidence = Math.min(result.score, 1.0);
      result.detected = result.confidence >= this.config.confidenceThreshold;
      result.riskLevel = this.calculateRiskLevel(result.score);
      result.explanation = this.generateExplanation(result);

      this.logger.info('Prompt injection classification', {
        detected: result.detected,
        confidence: result.confidence,
        riskLevel: result.riskLevel,
        patterns: result.patterns.length
      });

    } catch (error) {
      this.logger.error('Error in prompt injection classification:', error as Error);
      result.explanation = 'Classification failed due to error';
    }

    return result;
  }

  /**
   * Rule-based prompt injection detection
   */
  private ruleBasedDetection(content: string): { score: number; patterns: string[] } {
    let totalScore = 0.0;
    const detectedPatterns: string[] = [];

    for (const [name, pattern] of this.injectionPatterns) {
      const matches = content.match(pattern.pattern);
      if (matches) {
        const patternScore = pattern.weight * matches.length;
        totalScore += patternScore;
        detectedPatterns.push(`${name}: ${pattern.description}`);
      }
    }

    // Additional heuristics
    const heuristics = this.applyHeuristics(content);
    totalScore += heuristics.score;
    if (heuristics.patterns.length > 0) {
      detectedPatterns.push(...heuristics.patterns);
    }

    return { score: totalScore, patterns: detectedPatterns };
  }

  /**
   * Apply additional heuristics for detection
   */
  private applyHeuristics(content: string): { score: number; patterns: string[] } {
    let score = 0.0;
    const patterns: string[] = [];

    // Check for unusual character patterns
    const unusualChars = (content.match(/[^\x20-\x7E]/g) || []).length;
    if (unusualChars > 10) {
      score += 0.2;
      patterns.push('unusual_characters: High number of non-ASCII characters');
    }

    // Check for repetitive patterns
    const repetitivePatterns = this.detectRepetitivePatterns(content);
    if (repetitivePatterns > 0) {
      score += repetitivePatterns * 0.1;
      patterns.push(`repetitive_patterns: ${repetitivePatterns} repetitive sequences detected`);
    }

    // Check for context switching indicators
    const contextSwitches = this.detectContextSwitches(content);
    if (contextSwitches > 0) {
      score += contextSwitches * 0.15;
      patterns.push(`context_switches: ${contextSwitches} context switching indicators`);
    }

    // Check for urgency indicators
    const urgencyIndicators = this.detectUrgencyIndicators(content);
    if (urgencyIndicators > 0) {
      score += urgencyIndicators * 0.1;
      patterns.push(`urgency_indicators: ${urgencyIndicators} urgency indicators detected`);
    }

    return { score, patterns };
  }

  /**
   * Detect repetitive patterns in content
   */
  private detectRepetitivePatterns(content: string): number {
    const words = content.toLowerCase().split(/\s+/);
    const wordCounts = new Map<string, number>();
    
    for (const word of words) {
      wordCounts.set(word, (wordCounts.get(word) || 0) + 1);
    }

    let repetitiveCount = 0;
    for (const [word, count] of wordCounts) {
      if (count > 5 && word.length > 3) {
        repetitiveCount++;
      }
    }

    return repetitiveCount;
  }

  /**
   * Detect context switching indicators
   */
  private detectContextSwitches(content: string): number {
    const contextSwitchPatterns = [
      /now\s+(?:let|suppose|imagine|assume)/gi,
      /switch\s+(?:to|context|mode)/gi,
      /change\s+(?:topic|subject|focus)/gi,
      /forget\s+(?:about|that)/gi,
      /ignore\s+(?:the\s+)?(?:above|previous)/gi
    ];

    let switchCount = 0;
    for (const pattern of contextSwitchPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        switchCount += matches.length;
      }
    }

    return switchCount;
  }

  /**
   * Detect urgency indicators
   */
  private detectUrgencyIndicators(content: string): number {
    const urgencyPatterns = [
      /urgent|emergency|critical|immediate/gi,
      /asap|quickly|hurry|fast/gi,
      /important|vital|essential/gi,
      /now|immediately|right\s+away/gi
    ];

    let urgencyCount = 0;
    for (const pattern of urgencyPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        urgencyCount += matches.length;
      }
    }

    return urgencyCount;
  }

  /**
   * ML-based detection (placeholder for future implementation)
   */
  private mlBasedDetection(content: string): { score: number; patterns: string[] } {
    // In production, this would use a proper ML model
    // For now, we'll use a simple statistical approach
    
    let score = 0.0;
    const patterns: string[] = [];

    // Simple statistical features
    const features = this.extractFeatures(content);
    
    // Calculate anomaly score based on features
    const anomalyScore = this.calculateAnomalyScore(features);
    if (anomalyScore > 0.5) {
      score += anomalyScore * 0.3;
      patterns.push(`ml_anomaly: Statistical anomaly detected (score: ${anomalyScore.toFixed(2)})`);
    }

    return { score, patterns };
  }

  /**
   * Extract features for ML detection
   */
  private extractFeatures(content: string): Record<string, number> {
    const features: Record<string, number> = {};

    // Text length features
    features.length = content.length;
    features.wordCount = content.split(/\s+/).length;
    features.sentenceCount = content.split(/[.!?]+/).length;

    // Character distribution features
    features.uppercaseRatio = (content.match(/[A-Z]/g) || []).length / content.length;
    features.punctuationRatio = (content.match(/[^\w\s]/g) || []).length / content.length;
    features.digitRatio = (content.match(/\d/g) || []).length / content.length;

    // Entropy-based features
    features.entropy = this.calculateEntropy(content);

    return features;
  }

  /**
   * Calculate text entropy
   */
  private calculateEntropy(text: string): number {
    const charCounts = new Map<string, number>();
    for (const char of text) {
      charCounts.set(char, (charCounts.get(char) || 0) + 1);
    }

    let entropy = 0;
    const length = text.length;
    
    for (const count of charCounts.values()) {
      const probability = count / length;
      entropy -= probability * Math.log2(probability);
    }

    return entropy;
  }

  /**
   * Calculate anomaly score based on features
   */
  private calculateAnomalyScore(features: Record<string, number>): number {
    // Simple anomaly detection based on feature thresholds
    let anomalyScore = 0.0;

    // Length anomalies
    if (features.length > 10000) anomalyScore += 0.2;
    if (features.wordCount > 2000) anomalyScore += 0.2;

    // Character distribution anomalies
    if (features.uppercaseRatio > 0.3) anomalyScore += 0.15;
    if (features.punctuationRatio > 0.2) anomalyScore += 0.15;
    if (features.digitRatio > 0.1) anomalyScore += 0.1;

    // Entropy anomalies
    if (features.entropy > 4.5) anomalyScore += 0.2;

    return Math.min(anomalyScore, 1.0);
  }

  /**
   * Calculate risk level based on score
   */
  private calculateRiskLevel(score: number): 'low' | 'medium' | 'high' | 'critical' {
    if (score >= 2.0) return 'critical';
    if (score >= 1.0) return 'high';
    if (score >= 0.5) return 'medium';
    return 'low';
  }

  /**
   * Generate explanation for classification result
   */
  private generateExplanation(result: PromptInjectionResult): string {
    if (!result.detected) {
      return 'No prompt injection patterns detected';
    }

    const explanations = [];
    
    if (result.patterns.length > 0) {
      explanations.push(`Detected patterns: ${result.patterns.slice(0, 3).join(', ')}`);
    }

    explanations.push(`Confidence: ${(result.confidence * 100).toFixed(1)}%`);
    explanations.push(`Risk level: ${result.riskLevel}`);

    if (result.score > 1.0) {
      explanations.push('Multiple high-risk patterns detected');
    }

    return explanations.join('. ');
  }

  /**
   * Get classification statistics
   */
  getClassificationStats(): { totalClassified: number; detections: number; averageConfidence: number } {
    // In a real implementation, this would track statistics
    return { totalClassified: 0, detections: 0, averageConfidence: 0.0 };
  }
}

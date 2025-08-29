#!/usr/bin/env node

// Simple test script to demonstrate the MCP Security Agent
const { SecurityAgent } = require('./dist/agent/SecurityAgent.js');

async function testSecurityScanner() {
  console.log('🔒 MCP Security Agent - Test Scanner');
  console.log('=====================================\n');

  try {
    const agent = new SecurityAgent();
    
    console.log('📋 Available scanners:');
    const scanners = agent.getScanners();
    scanners.forEach(scanner => {
      const info = agent.getScannerInfo(scanner);
      console.log(`  - ${info.name}: ${info.description}`);
    });
    console.log('');

    console.log('🔍 Starting security scan on examples directory...');
    
    const config = {
      path: './examples',
      scanType: 'comprehensive',
      outputFormat: 'json',
      includePatterns: ['**/*.{js,ts,json,yml,yaml}'],
      excludePatterns: ['**/node_modules/**', '**/dist/**'],
      maxDepth: 5
    };

    const report = await agent.scan(config);

    console.log('\n📊 Scan Results:');
    console.log(`  Total Findings: ${report.summary.totalFindings}`);
    console.log(`  Critical: ${report.summary.criticalCount}`);
    console.log(`  High: ${report.summary.highCount}`);
    console.log(`  Medium: ${report.summary.mediumCount}`);
    console.log(`  Low: ${report.summary.lowCount}`);
    console.log(`  Info: ${report.summary.infoCount}`);
    console.log(`  Risk Score: ${report.summary.riskScore.toFixed(2)}`);
    console.log(`  Scan Duration: ${(report.summary.scanDuration / 1000).toFixed(2)}s`);

    if (report.findings.length > 0) {
      console.log('\n🚨 Top Findings:');
      const topFindings = report.findings
        .sort((a, b) => {
          const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
          return severityOrder[b.severity] - severityOrder[a.severity];
        })
        .slice(0, 5);

      topFindings.forEach((finding, index) => {
        console.log(`  ${index + 1}. ${finding.title}`);
        console.log(`     Severity: ${finding.severity.toUpperCase()}`);
        console.log(`     File: ${finding.location.file}:${finding.location.line || 'N/A'}`);
        console.log(`     Type: ${finding.type}`);
        console.log(`     Confidence: ${Math.round(finding.confidence * 100)}%`);
        console.log('');
      });
    }

    console.log('✅ Security scan completed successfully!');
    
    // Generate a simple report
    console.log('\n📄 Generating HTML report...');
    const htmlReport = await agent.generateReport('./examples', {
      format: 'html',
      includeRemediation: true,
      includeAIAnalysis: true
    });
    
    console.log('📄 HTML report generated successfully!');
    console.log('   You can find the report content in the returned object.');

  } catch (error) {
    console.error('❌ Error during security scan:', error.message);
    process.exit(1);
  }
}

// Run the test if this file is executed directly
if (require.main === module) {
  testSecurityScanner();
}

module.exports = { testSecurityScanner };

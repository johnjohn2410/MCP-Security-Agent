# MCP Security Agent - Quick Start Guide

## 🚀 Getting Started

### Prerequisites
- Node.js 18+ 
- npm or yarn
- OpenAI API key (optional, for AI analysis)

### Installation

1. **Clone and setup:**
```bash
git clone <repository-url>
cd mcp-security-agent
node setup.js
```

2. **Configure environment:**
```bash
cp env.example .env
# Edit .env with your configuration
```

3. **Build the project:**
```bash
npm run build
```

## 🔧 Basic Usage

### Command Line Interface

**Perform a security scan:**
```bash
# Scan a directory
node dist/index.js scan ./src

# Scan with specific options
node dist/index.js scan ./src --type comprehensive --format html --output ./reports

# Scan for specific vulnerabilities
node dist/index.js analyze ./src --types sql_injection,xss,hardcoded_secret

# Scan dependencies
node dist/index.js dependencies ./src --managers npm,yarn

# Scan for secrets
node dist/index.js secrets ./src --types api_keys,passwords,tokens
```

**Generate reports:**
```bash
# Generate HTML report
node dist/index.js report ./src --format html --output ./reports

# Generate CSV report
node dist/index.js report ./src --format csv --output ./reports
```

**Manage policies:**
```bash
# List all policies
node dist/index.js policy --list

# Add custom policy
node dist/index.js policy --add ./my-policy.json
```

### MCP Server

**Start the MCP server:**
```bash
node dist/index.js server
```

**Use with MCP clients:**
```json
{
  "mcpServers": {
    "security-agent": {
      "command": "node",
      "args": ["dist/index.js", "server"]
    }
  }
}
```

## 🛠️ Available Tools

### Security Scanning Tools

1. **security_scan** - Comprehensive security scan
   - Parameters: path, scanType, includePatterns, excludePatterns, maxDepth
   - Returns: Detailed security findings

2. **vulnerability_analysis** - Analyze specific vulnerabilities
   - Parameters: filePath, vulnerabilityTypes
   - Returns: Targeted vulnerability analysis

3. **dependency_scan** - Scan for vulnerable dependencies
   - Parameters: path, packageManagers
   - Returns: Dependency vulnerability report

4. **secret_scan** - Scan for hardcoded secrets
   - Parameters: path, secretTypes
   - Returns: Secret detection results

5. **security_report** - Generate comprehensive reports
   - Parameters: path, format, includeRemediation
   - Returns: Formatted security report

6. **policy_check** - Check against security policies
   - Parameters: path, policyNames
   - Returns: Policy compliance results

7. **ai_analysis** - AI-powered security analysis
   - Parameters: findings, context
   - Returns: Intelligent analysis and recommendations

## 🔍 Security Scanners

### Code Security Scanner
- **SQL Injection Detection**
- **Cross-Site Scripting (XSS)**
- **Command Injection**
- **Path Traversal**
- **Insecure Deserialization**
- **Input Validation Issues**

### Secret Scanner
- **API Keys**
- **Passwords**
- **Tokens**
- **Private Keys**
- **Database URLs**
- **OAuth Secrets**

### Dependency Scanner
- **Vulnerable Packages**
- **Outdated Dependencies**
- **License Compliance**
- **Supply Chain Attacks**

### Configuration Scanner
- **Debug Mode**
- **CORS Misconfiguration**
- **File Permissions**
- **SSL/TLS Settings**
- **Authentication Issues**

## 📊 Report Formats

### JSON Reports
```bash
node dist/index.js scan ./src --format json
```

### HTML Reports
```bash
node dist/index.js scan ./src --format html --output ./reports
```

### CSV Reports
```bash
node dist/index.js scan ./src --format csv --output ./reports
```

## 🤖 AI Analysis

Enable AI-powered analysis by setting your OpenAI API key:

```bash
# In .env file
OPENAI_API_KEY=your_openai_api_key_here
```

AI analysis provides:
- **Risk Assessment** - Overall risk scoring
- **Context Analysis** - Project type and technology stack
- **Remediation Plan** - Prioritized fixes and timeline
- **False Positive Analysis** - Confidence scoring

## 🔒 Security Policies

### Default Policies
- **No Hardcoded Secrets** - Prevents secrets in code
- **No SQL Injection** - Detects SQL injection patterns
- **No XSS** - Prevents cross-site scripting
- **Secure Dependencies** - Checks for vulnerable packages
- **Secure Configuration** - Validates security settings

### Custom Policies
Create custom policies in JSON format:

```json
{
  "id": "custom-policy",
  "name": "Custom Security Policy",
  "description": "Custom security rules",
  "enabled": true,
  "priority": 1,
  "rules": [
    {
      "id": "custom-rule",
      "type": "regex",
      "pattern": "custom_pattern",
      "action": "block",
      "severity": "high",
      "description": "Custom security rule"
    }
  ]
}
```

## 🧪 Testing

### Test with Example Code
```bash
# Scan the example vulnerable code
node dist/index.js scan ./examples --format html --output ./reports
```

### Run Test Script
```bash
node test-scanner.js
```

## 📁 Project Structure

```
mcp-security-agent/
├── src/
│   ├── agent/           # Main security agent
│   ├── scanner/         # Security scanners
│   ├── mcp/            # MCP integration
│   ├── policies/       # Security policies
│   ├── ai/             # AI analysis
│   ├── utils/          # Utilities
│   └── types/          # TypeScript types
├── examples/           # Example code for testing
├── logs/              # Log files
├── reports/           # Generated reports
├── dist/              # Compiled JavaScript
└── docs/              # Documentation
```

## 🔧 Configuration

### Environment Variables
- `OPENAI_API_KEY` - OpenAI API key for AI analysis
- `SCAN_DEPTH` - Scan depth (quick, comprehensive, targeted)
- `SCAN_TIMEOUT` - Scan timeout in milliseconds
- `LOG_LEVEL` - Logging level (debug, info, warn, error)
- `MCP_SERVER_PORT` - MCP server port
- `MCP_SERVER_HOST` - MCP server host

### Scan Configuration
```javascript
const config = {
  path: './src',
  scanType: 'comprehensive',
  outputFormat: 'json',
  includePatterns: ['**/*.{js,ts,py,java}'],
  excludePatterns: ['**/node_modules/**'],
  maxDepth: 10,
  timeout: 300000
};
```

## 🚨 Troubleshooting

### Common Issues

1. **Build errors:**
```bash
npm run build
```

2. **Permission errors:**
```bash
chmod +x dist/index.js
```

3. **Missing dependencies:**
```bash
npm install
```

4. **OpenAI API errors:**
- Check your API key in `.env`
- Verify API key has sufficient credits

### Logs
Check logs in the `logs/` directory:
- `security-agent.log` - General logs
- `error.log` - Error logs

## 📚 Next Steps

1. **Read the full README.md** for detailed documentation
2. **Explore the examples/** directory for test cases
3. **Customize security policies** for your needs
4. **Integrate with CI/CD** for automated scanning
5. **Set up MCP clients** for IDE integration

## 🆘 Support

- **Documentation**: Check README.md and docs/
- **Issues**: Report on GitHub
- **Examples**: See examples/ directory
- **Configuration**: Check env.example

---

**Happy Security Scanning! 🔒**

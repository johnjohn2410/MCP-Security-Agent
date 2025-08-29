# MCP Security Agent

An intelligent, agentic AI security scanner built on the Model Context Protocol (MCP) that actively scans for vulnerabilities and provides automated security analysis.

## 2-Minute Quickstart

### 1. Install & Setup
```bash
# Clone and install
git clone https://github.com/your-org/mcp-security-agent.git
cd mcp-security-agent
npm install
npm run build

# Configure environment
cp env.example .env
# Edit .env with your OpenAI API key (optional, for AI analysis)
```

### 2. Run Your First Scan
```bash
# Scan a directory for vulnerabilities
npm start scan ./your-project

# Or use the CLI directly
node dist/index.js scan ./your-project --type comprehensive
```

### 3. View Results
```bash
# Results are displayed in JSON format
# For HTML report, use:
node dist/index.js scan ./your-project --format html
```

**That's it!** Your security scan is complete. The agent will detect:
- Code vulnerabilities (SQL injection, XSS, etc.)
- Dependency vulnerabilities
- Hardcoded secrets
- Configuration issues

## Features

### Core Security Scanning
- **Code Vulnerability Analysis**: Detects security issues in source code
- **Dependency Scanning**: Identifies vulnerable packages and outdated dependencies
- **Configuration Security**: Validates security configurations and best practices
- **Secret Detection**: Finds hardcoded secrets, API keys, and sensitive data
- **Infrastructure Security**: Scans cloud configurations and infrastructure as code

### MCP Integration
- **Secure Tool Access**: Uses MCP for standardized, secure system interactions
- **Dynamic Tool Discovery**: Automatically discovers available security tools
- **Policy Enforcement**: Implements security policies and access controls
- **Audit Trail**: Comprehensive logging of all security operations

### Agentic AI Capabilities
- **Intelligent Analysis**: AI-powered vulnerability assessment and prioritization
- **Automated Remediation**: Suggests and can implement security fixes
- **Context-Aware Scanning**: Understands project context and architecture
- **Continuous Monitoring**: Real-time security monitoring and alerting

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI Agent      │    │   MCP Client    │    │   Security      │
│   Core          │◄──►│   Layer         │◄──►│   Scanner       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Policy        │    │   Tool          │    │   Vulnerability │
│   Engine        │    │   Registry      │    │   Database      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Installation

### Prerequisites
- Node.js 18.0.0 or higher
- npm or yarn

### Quick Install
```bash
# Clone the repository
git clone https://github.com/your-org/mcp-security-agent.git
cd mcp-security-agent

# Install dependencies
npm install

# Build the project
npm run build

# Set up environment variables
cp env.example .env
# Edit .env with your configuration
```

## Configuration

Create a `.env` file with the following variables:

```env
# OpenAI API Key for AI analysis (optional)
OPENAI_API_KEY=your_openai_api_key

# Security scanning configuration
SCAN_DEPTH=deep
SCAN_TIMEOUT=300000
MAX_CONCURRENT_SCANS=5

# MCP Server configuration
MCP_SERVER_PORT=3000
MCP_SERVER_HOST=localhost

# Logging
LOG_LEVEL=info
LOG_FILE=logs/security-agent.log

# Security policies
ALLOWED_FILE_TYPES=js,ts,py,java,go,yml,yaml,json
BLOCKED_PATTERNS=password,secret,key,token
```

## Usage

### Command Line Interface

```bash
# Comprehensive security scan
npm start scan ./path/to/project --type comprehensive

# Quick scan (secrets and dependencies only)
npm start scan ./path/to/project --type quick

# Targeted scan (specific vulnerability types)
npm start scan ./path/to/project --targets code,secrets

# Generate HTML report
npm start scan ./path/to/project --format html

# Start MCP server for AI assistant integration
npm start server
```

### Available Commands

```bash
# Main scan command
scan <path>                    # Scan a directory or file
  --type <type>               # quick, comprehensive, targeted
  --targets <targets>         # code,secrets,dependencies,config,policy
  --format <format>           # json, html, csv, pdf, sarif
  --include <patterns>        # File patterns to include
  --exclude <patterns>        # File patterns to exclude

# Policy management
policy --list                 # List all policies
policy --add <file>           # Add policy from file
policy --remove <id>          # Remove policy by ID

# Specialized scans
deps <path>                   # Scan dependencies only
secrets <path>                # Scan for secrets only
analyze <path>                # AI-powered analysis

# Report generation
report <path> --format html   # Generate security report
```

### Programmatic Usage

```typescript
import { SecurityAgent } from './dist/agent/SecurityAgent.js';

const agent = new SecurityAgent({
  path: './my-project',
  scanType: 'comprehensive',
  outputFormat: 'json'
});

const results = await agent.scan('./my-project', config);
console.log(`Found ${results.findings.length} vulnerabilities`);
```

### MCP Integration

The agent can be used as an MCP server for AI assistant integration:

```bash
# Start MCP server
npm start server

# Connect from MCP client
# The agent will be available as security scanning tools
```

## Output Formats

The agent supports multiple output formats:

- **JSON**: Machine-readable format for integration
- **HTML**: Human-readable report with charts and details
- **CSV**: Spreadsheet-friendly format
- **PDF**: Printable security report
- **SARIF**: Standard format for CI/CD integration

## Security Features

### Privacy & Data Protection
- **Data Redaction**: Automatically redacts sensitive information
- **Tokenization**: Replaces sensitive data with tokens
- **Audit Logging**: Complete audit trail of all operations
- **Privacy Controls**: Configurable data handling policies

### Policy Enforcement
- **Custom Rules**: Define your own security policies
- **Rule Inheritance**: Hierarchical policy management
- **Dry-Run Mode**: Test policies before enforcement
- **Policy Tracing**: Understand why rules were triggered

## Testing

```bash
# Run tests
npm test

# Test with example vulnerable code
npm start scan ./examples --type comprehensive
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Install dependencies
npm install

# Build in development mode
npm run dev

# Run tests
npm test

# Lint code
npm run lint
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/mcp-security-agent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/mcp-security-agent/discussions)
- **Security**: [SECURITY.md](SECURITY.md)

## Roadmap

- [ ] Advanced AI analysis with multiple models
- [ ] Real-time monitoring and alerting
- [ ] Integration with popular CI/CD platforms
- [ ] Cloud security scanning (AWS, Azure, GCP)
- [ ] Container and Kubernetes security
- [ ] Compliance reporting (SOC 2, ISO 27001, PCI)

## Acknowledgments

- Built on the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- Inspired by modern security scanning tools
- Community contributions and feedback

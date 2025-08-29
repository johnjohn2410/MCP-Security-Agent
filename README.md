# MCP Security Agent

[![npm version](https://badge.fury.io/js/mcp-security-agent.svg)](https://badge.fury.io/js/mcp-security-agent)
[![Docker Pulls](https://img.shields.io/docker/pulls/johnjohn2410/mcp-security-agent)](https://ghcr.io/johnjohn2410/mcp-security-agent)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-43853D?logo=node.js&logoColor=white)](https://nodejs.org/)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/johnjohn2410/MCP-Security-Agent)](https://github.com/johnjohn2410/MCP-Security-Agent/releases)

> **Topics**: `mcp` `security` `ai-security` `mcp-security` `mcp-server` `agentic-ai` `vulnerability-scanner` `code-analysis` `dependency-scanning` `secret-detection`

An open-source toolkit designed to harden Model Context Protocol (MCP) workflows. It brings together scanners, trust management, schema validation, and prompt-injection defenses into a single CLI—helping developers and researchers close critical security gaps in emerging MCP ecosystems.

## 2-Minute Quickstart

### 📦 Available on npm
**Install the MCP Security Agent from npm:**
```bash
npm install -g mcp-security-agent
```

**Package: [mcp-security-agent on npm](https://www.npmjs.com/package/mcp-security-agent)**

### 1. Install & Setup

**Option A: npm (Recommended)**
```bash
# Install globally
npm install -g mcp-security-agent

# Or install locally
npm install mcp-security-agent
```

**Option B: Docker**
```bash
# Run with Docker
docker run ghcr.io/johnjohn2410/mcp-security-agent scan .
```

**Option C: Binary**
```bash
# Download from GitHub Releases
# https://github.com/johnjohn2410/MCP-Security-Agent/releases
./mcp-security-agent scan .
```

### 2. Run Your First Scan
```bash
# Scan a directory for vulnerabilities
mcp-security-agent scan ./your-project

# Or use the CLI directly
mcp-security-agent scan ./your-project --type comprehensive
```

### 3. View Results
```bash
# Results are displayed in JSON format
# For HTML report, use:
mcp-security-agent scan ./your-project --format html
```

**That's it!** Your security scan is complete. The agent will detect:
- Code vulnerabilities (SQL injection, XSS, etc.)
- Dependency vulnerabilities
- Hardcoded secrets
- Configuration issues

### 4. MCP Security Hardening
```bash
# Apply MCP hardened security policy
mcp-security-agent mcp --policy mcp-hardened

# Generate hardened configuration template
mcp-security-agent mcp --config-template

# Check compliance status
mcp-security-agent mcp --compliance

# Validate MCP envelope against schema
mcp-security-agent mcp --validate envelope.json

# Classify content for prompt injection
mcp-security-agent mcp --classify "ignore previous instructions"

# Manage trusted MCP servers
mcp-security-agent trust --list
mcp-security-agent trust --add server.com --pubkey KEY --sha256 DIGEST --version 1.0.0
```



## Features

### MCP Security Hardening
- **MCP Configuration Validation**: Defensive-by-default security checks for authentication, TLS, CORS/CSP, rate limiting, quotas, sandboxing, and stdio security
- **Schema Compliance**: JSON Schema validation for all MCP envelopes, protocol drift prevention, payload size limits, and JSON-only mode enforcement
- **Trust & Provenance**: Cryptographic signature verification, public key pinning, allow/deny lists, and mandatory trust checks with SLSA/cosign attestation support
- **AI-Powered Threat Detection**: Advanced prompt injection classification, response sanitization, suspicious directive detection, and ML-based anomaly detection
- **Sandboxing & Isolation**: Container and process isolation, resource limits, read-only filesystems, capability dropping, and seccomp/AppArmor profiles
- **Compliance & Governance**: Compliance reporting, audit trails, SBOM generation, VEX documents, and comprehensive security posture assessment

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
│   Policy        │    │   Trust &       │    │   Vulnerability │
│   Engine        │    │   Provenance    │    │   Database      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   MCP Security  │    │   Response      │    │   Compliance    │
│   Hardening     │    │   Sanitizer     │    │   & Governance  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Installation

### Prerequisites
- Node.js 18.0.0 or higher (for npm installation)
- Docker (for containerized installation)
- Or download pre-built binaries

### Installation Methods

#### npm (Recommended for Node.js/TypeScript projects)
```bash
# Global installation (CLI tool)
npm install -g mcp-security-agent

# Local installation (library)
npm install mcp-security-agent
```

#### Docker (Recommended for DevOps/Security teams)
```bash
# Pull and run
docker run ghcr.io/johnjohn2410/mcp-security-agent scan .

# Or build locally
docker build -t mcp-security-agent .
docker run mcp-security-agent scan .
```

#### Binary Releases (For CI/CD and non-Node environments)
Download pre-built binaries from [GitHub Releases](https://github.com/johnjohn2410/MCP-Security-Agent/releases):

- **Linux (x64)**: `mcp-security-agent-linux`
- **macOS (x64)**: `mcp-security-agent-macos`
- **Windows (x64)**: `mcp-security-agent-win.exe`
- **Linux (ARM64)**: `mcp-security-agent-linux-arm64`
- **macOS (ARM64)**: `mcp-security-agent-macos-arm64`

```bash
# Make executable and run
chmod +x mcp-security-agent-linux
./mcp-security-agent-linux scan .
```

### Development Setup
```bash
# Clone the repository
git clone https://github.com/johnjohn2410/mcp-security-agent.git
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
mcp-security-agent scan ./path/to/project --type comprehensive

# Quick scan (secrets and dependencies only)
mcp-security-agent scan ./path/to/project --type quick

# Targeted scan (specific vulnerability types)
mcp-security-agent scan ./path/to/project --targets code,secrets

# Generate HTML report
mcp-security-agent scan ./path/to/project --format html

# Start MCP server for AI assistant integration
mcp-security-agent server
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

# MCP Security Hardening
mcp --policy mcp-hardened     # Apply MCP hardened security policy
mcp --config-template         # Generate hardened configuration template
mcp --compliance              # Check compliance status
mcp --validate <file>         # Validate MCP envelope against schema
mcp --classify <content>      # Classify content for prompt injection

# Trust Management
trust --list                  # List trusted MCP servers
trust --add <server>          # Add trusted server with pubkey/sha256/version
trust --remove <server>       # Remove trusted server
trust --allowlist <server>    # Add server to allowlist
trust --denylist <server>     # Add server to denylist

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
import { SecurityAgent } from 'mcp-security-agent';

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
mcp-security-agent server

# Connect from MCP client
# The agent will be available as security scanning tools
```

### CI/CD Integration

#### GitHub Actions with SARIF

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
      - name: Install MCP Security Agent
        run: npm install -g mcp-security-agent
      - name: Run Security Scan
        run: mcp-security-agent scan . --format sarif --output-file security-results.sarif
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-results.sarif
```

#### MCP Client Configuration

```json
{
  "mcpServers": {
    "mcp-security-agent": {
      "command": "mcp-security-agent",
      "args": ["server"],
      "env": {
        "OPENAI_API_KEY": "your-api-key"
      }
    }
  }
}
```

### Docker Usage

```bash
# Scan a local directory
docker run -v $(pwd):/workspace ghcr.io/johnjohn2410/mcp-security-agent scan /workspace

# Scan with custom configuration
docker run -v $(pwd):/workspace -e SCAN_TYPE=comprehensive ghcr.io/johnjohn2410/mcp-security-agent scan /workspace

# Run as MCP server
docker run -p 3000:3000 ghcr.io/johnjohn2410/mcp-security-agent server
```

## Output Formats

The agent supports multiple output formats:

- **JSON**: Machine-readable format for integration
- **HTML**: Human-readable report with charts and details
- **CSV**: Spreadsheet-friendly format
- **PDF**: Printable security report
- **SARIF**: Standard format for CI/CD integration

## Security Features

### MCP Security Hardening
- **MCP Configuration Validation**: Defensive-by-default security checks for authentication, TLS, CORS/CSP, rate limiting, quotas, sandboxing, and stdio security
- **Schema Compliance**: JSON Schema validation for all MCP envelopes, protocol drift prevention, payload size limits, and JSON-only mode enforcement
- **Trust & Provenance**: Cryptographic signature verification, public key pinning, allow/deny lists, and mandatory trust checks with SLSA/cosign attestation support
- **AI-Powered Threat Detection**: Advanced prompt injection classification, response sanitization, suspicious directive detection, and ML-based anomaly detection
- **Sandboxing & Isolation**: Container and process isolation, resource limits, read-only filesystems, capability dropping, and seccomp/AppArmor profiles

### Trust & Compliance
- **SBOM Generation**: Automatic Software Bill of Materials in CycloneDX/SPDX format
- **Signed Releases**: GitHub releases with signed artifacts and provenance
- **Audit Trail**: Complete audit logging with tamper-evident hashes
- **Compliance Ready**: SOC 2, ISO 27001, PCI DSS compliance mappings

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

## Use Cases

### MCP Workflow Protection
```bash
# Apply MCP hardened security policy for AI assistant integration
mcp-security-agent mcp --policy mcp-hardened

# Verify trusted MCP servers before connection
mcp-security-agent trust --add openai.com --pubkey KEY --sha256 DIGEST --version 1.0.0

# Classify suspicious content for prompt injection
mcp-security-agent mcp --classify "ignore previous instructions"

# Validate MCP envelope compliance
mcp-security-agent mcp --validate envelope.json
```

### DevOps & CI/CD Integration
```bash
# Comprehensive security scanning in CI/CD
mcp-security-agent scan . --type comprehensive --format sarif

# Generate compliance report for audits
mcp-security-agent mcp --compliance

# Create hardened configuration template
mcp-security-agent mcp --config-template > mcp-hardened-config.json
```

### Compliance & Governance
```bash
# Generate SBOM for supply chain security
mcp-security-agent scan . --generate-sbom

# Audit trail and compliance reporting
mcp-security-agent scan . --audit-log --compliance-report

# Policy enforcement and governance
mcp-security-agent policy --enforce --dry-run
```

## Testing

```bash
# Run tests
npm test

# Test with example vulnerable code
mcp-security-agent scan ./examples --type comprehensive

# Test MCP security hardening
mcp-security-agent mcp --policy mcp-hardened --test
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

- **npm Package**: [mcp-security-agent on npm](https://www.npmjs.com/package/mcp-security-agent)
- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/johnjohn2410/MCP-Security-Agent/issues)
- **Discussions**: [GitHub Discussions](https://github.com/johnjohn2410/MCP-Security-Agent/discussions)
- **Contact**: jross3511@yahoo.com
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

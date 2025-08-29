# Contributing to MCP Security Agent

Thank you for your interest in contributing to MCP Security Agent! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Project Structure](#project-structure)
- [Adding New Scanners](#adding-new-scanners)
- [Adding New Policies](#adding-new-policies)
- [Documentation](#documentation)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Node.js 18.0.0 or higher
- npm or yarn
- Git

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/mcp-security-agent.git
   cd mcp-security-agent
   ```

3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/original-org/mcp-security-agent.git
   ```

## Development Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Build the Project

```bash
npm run build
```

### 3. Set Up Environment

```bash
cp env.example .env
# Edit .env with your configuration
```

### 4. Run Tests

```bash
npm test
```

### 5. Start Development Mode

```bash
npm run dev
```

## Making Changes

### 1. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 2. Make Your Changes

- Write clear, well-documented code
- Follow the existing code style and conventions
- Add tests for new functionality
- Update documentation as needed

### 3. Commit Your Changes

Use conventional commit messages:

```bash
git commit -m "feat: add new security scanner for Docker images"
git commit -m "fix: resolve issue with dependency scanning"
git commit -m "docs: update README with new installation steps"
```

### 4. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

## Testing

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm test -- --coverage

# Run specific test file
npm test -- scanner/CodeSecurityScanner.test.ts

# Run tests in watch mode
npm test -- --watch
```

### Writing Tests

- Tests should be written in Jest
- Place test files next to the source files with `.test.ts` extension
- Aim for high test coverage (80%+)
- Test both success and error cases

Example test structure:

```typescript
import { CodeSecurityScanner } from '../CodeSecurityScanner';

describe('CodeSecurityScanner', () => {
  let scanner: CodeSecurityScanner;

  beforeEach(() => {
    scanner = new CodeSecurityScanner();
  });

  describe('scan', () => {
    it('should detect SQL injection vulnerabilities', async () => {
      const results = await scanner.scan('./test-fixtures/sql-injection.js');
      expect(results).toHaveLength(1);
      expect(results[0].type).toBe('sql_injection');
    });

    it('should handle empty files gracefully', async () => {
      const results = await scanner.scan('./test-fixtures/empty.js');
      expect(results).toHaveLength(0);
    });
  });
});
```

## Submitting Changes

### 1. Create a Pull Request

1. Go to your fork on GitHub
2. Click "New Pull Request"
3. Select your feature branch
4. Fill out the pull request template

### 2. Pull Request Guidelines

- Provide a clear description of the changes
- Include any relevant issue numbers
- Add screenshots for UI changes
- Ensure all tests pass
- Update documentation if needed

### 3. Review Process

- All pull requests require review
- Address feedback and make requested changes
- Maintainers will merge after approval

## Project Structure

```
src/
├── agent/           # AI agent core
│   ├── SecurityAgent.ts
│   └── AIAnalyzer.ts
├── scanner/         # Security scanners
│   ├── BaseScanner.ts
│   ├── CodeSecurityScanner.ts
│   ├── DependencyScanner.ts
│   ├── SecretScanner.ts
│   └── ConfigurationScanner.ts
├── mcp/            # MCP integration
│   └── Server.ts
├── policies/       # Security policies
│   └── PolicyEngine.ts
├── types/          # TypeScript types
│   └── index.ts
├── utils/          # Utility functions
│   ├── Logger.ts
│   ├── DataHandler.ts
│   ├── ReportGenerator.ts
│   ├── SBOMGenerator.ts
│   └── VEXGenerator.ts
└── index.ts        # Main entry point
```

## Adding New Scanners

### 1. Create Scanner Class

```typescript
import { BaseScanner } from './BaseScanner';
import { Finding, ScanConfig, VulnerabilityType, SeverityLevel } from '../types/index.js';

export class CustomScanner extends BaseScanner {
  constructor() {
    super('CustomScanner', 'Description of what this scanner does', [
      'file-extension-1',
      'file-extension-2'
    ]);
  }

  async scan(path: string, config?: Partial<ScanConfig>): Promise<Finding[]> {
    const findings: Finding[] = [];
    
    // Implement your scanning logic here
    
    return findings;
  }
}
```

### 2. Register Scanner

Add your scanner to the SecurityAgent:

```typescript
// In SecurityAgent.ts
import { CustomScanner } from './CustomScanner';

// In constructor or initialization
this.customScanner = new CustomScanner();
```

### 3. Add Tests

Create comprehensive tests for your scanner:

```typescript
// CustomScanner.test.ts
import { CustomScanner } from './CustomScanner';

describe('CustomScanner', () => {
  // Test implementation
});
```

## Adding New Policies

### 1. Define Policy

```typescript
// In PolicyEngine.ts
const customPolicy: SecurityPolicy = {
  id: 'custom-policy',
  name: 'Custom Security Policy',
  description: 'Description of the policy',
  version: '1.0.0',
  rules: [
    {
      id: 'custom-rule',
      name: 'Custom Rule',
      description: 'Description of the rule',
      type: 'regex',
      action: RuleAction.BLOCK,
      pattern: 'your-regex-pattern',
      severity: SeverityLevel.HIGH,
      enabled: true
    }
  ],
  scope: 'global',
  inheritance: 'allow',
  enabled: true,
  priority: 0,
  metadata: {}
};
```

### 2. Add Policy Logic

Implement the policy evaluation logic in PolicyEngine.

## Documentation

### Code Documentation

- Use JSDoc comments for all public APIs
- Include examples in documentation
- Keep documentation up to date with code changes

### README Updates

- Update README.md for new features
- Add usage examples
- Update installation instructions if needed

### API Documentation

- Document all public interfaces and classes
- Include type definitions
- Provide usage examples

## Code Style

### TypeScript

- Use strict TypeScript configuration
- Prefer interfaces over types for object shapes
- Use proper type annotations
- Avoid `any` type when possible

### Naming Conventions

- Use camelCase for variables and functions
- Use PascalCase for classes and interfaces
- Use UPPER_SNAKE_CASE for constants
- Use descriptive names

### File Organization

- One class per file
- Group related functionality
- Use index files for clean imports
- Keep files under 500 lines when possible

## Getting Help

- **Issues**: Open an issue on GitHub for bugs or feature requests
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Documentation**: Check the docs/ directory for detailed documentation
- **Security**: Report security issues to security@mcp-security-agent.org

## Recognition

Contributors will be recognized in:

- The project README
- Release notes
- GitHub contributors page
- Project documentation

Thank you for contributing to MCP Security Agent! 🚀

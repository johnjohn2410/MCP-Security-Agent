# Issues for Contributors

Here are 5 well-defined issues that would be great for contributors to work on:

## Issue 1: Add JSON Schema Validation Library Integration

**Title**: `[FEATURE] Integrate Ajv for robust JSON Schema validation`

**Description**: 
Currently, the MCP Schema Validator uses a simple custom validation approach. We need to integrate a proper JSON Schema validation library like Ajv to provide more robust and standards-compliant validation.

**Problem**: 
The current schema validation is basic and doesn't handle complex JSON Schema features like `oneOf`, `allOf`, `anyOf`, `dependencies`, etc. This limits our ability to validate complex MCP envelopes properly.

**Acceptance Criteria**:
- [ ] Integrate Ajv library for JSON Schema validation
- [ ] Update `MCPSchemaValidator` to use Ajv instead of custom validation
- [ ] Add support for complex JSON Schema features
- [ ] Maintain backward compatibility with existing validation calls
- [ ] Add comprehensive tests for schema validation
- [ ] Update documentation with new validation capabilities

**Technical Details**:
- Replace the `validateAgainstSchema` method in `src/utils/MCPSchemaValidator.ts`
- Add Ajv as a dependency in `package.json`
- Ensure performance is maintained for large payloads
- Add proper error handling for invalid schemas

**Difficulty**: Medium
**Labels**: `enhancement`, `help wanted`, `good first issue`

---

## Issue 2: Implement Persistent Trust Store

**Title**: `[FEATURE] Add persistent trust store with file-based storage`

**Description**: 
The current trust store is in-memory only and gets reset when the application restarts. We need to implement persistent storage for trusted servers, allowlists, and denylists.

**Problem**: 
Users have to re-add trusted servers every time they restart the application, which is not practical for production use.

**Acceptance Criteria**:
- [ ] Implement file-based trust store persistence (JSON format)
- [ ] Add configuration option for trust store file location
- [ ] Implement atomic writes to prevent corruption
- [ ] Add trust store migration/backup functionality
- [ ] Add CLI commands for trust store management
- [ ] Add validation for trust store file format
- [ ] Include comprehensive error handling for file operations

**Technical Details**:
- Create `src/utils/TrustStoreManager.ts` for file operations
- Use `fs-extra` for atomic file operations
- Store trust store in `~/.mcp-security-agent/trust-store.json` by default
- Add configuration option in `ScanConfig` for custom trust store location
- Implement proper error handling for file permissions and corruption

**Difficulty**: Medium
**Labels**: `enhancement`, `help wanted`, `good first issue`

---

## Issue 3: Add MCP Configuration Scanner Integration

**Title**: `[FEATURE] Integrate MCPConfigurationScanner into main SecurityAgent`

**Description**: 
The `MCPConfigurationScanner` exists but isn't integrated into the main scanning workflow. We need to integrate it so it runs automatically during security scans.

**Problem**: 
MCP configuration security checks are not being performed during regular scans, leaving a critical security gap.

**Acceptance Criteria**:
- [ ] Integrate `MCPConfigurationScanner` into `SecurityAgent.scan()` method
- [ ] Add MCP configuration scanning to the default scan types
- [ ] Update CLI to include MCP configuration scanning options
- [ ] Add MCP configuration findings to scan reports
- [ ] Create example MCP configuration files for testing
- [ ] Add tests for MCP configuration scanning integration

**Technical Details**:
- Import and instantiate `MCPConfigurationScanner` in `SecurityAgent` constructor
- Add `mcp-config` to the default scan types
- Update `ScanConfig` type to include MCP configuration scanning options
- Ensure MCP configuration findings are properly formatted and included in reports
- Add CLI flag `--include-mcp-config` to enable/disable this scanning

**Difficulty**: Easy
**Labels**: `enhancement`, `help wanted`, `good first issue`

---

## Issue 4: Implement Response Streaming for Large Payloads

**Title**: `[FEATURE] Add response streaming support for large scan results`

**Description**: 
Currently, all scan results are returned at once, which can cause memory issues and slow response times for large projects. We need to implement streaming responses.

**Problem**: 
Large security scans can generate massive amounts of data that overwhelm memory and cause timeouts, especially in CI/CD environments.

**Acceptance Criteria**:
- [ ] Implement streaming response interface for scan results
- [ ] Add CLI option for streaming output (`--stream`)
- [ ] Support streaming in JSON, CSV, and SARIF formats
- [ ] Maintain backward compatibility with non-streaming mode
- [ ] Add progress indicators for streaming responses
- [ ] Implement proper error handling for stream interruptions
- [ ] Add tests for streaming functionality

**Technical Details**:
- Create `src/utils/StreamingResponse.ts` for handling streaming
- Use Node.js streams for efficient data processing
- Add streaming support to `ReportGenerator`
- Update CLI to handle streaming output
- Ensure MCP server can handle streaming responses
- Add configuration options for stream buffer sizes and timeouts

**Difficulty**: Hard
**Labels**: `enhancement`, `help wanted`, `performance`

---

## Issue 5: Add Comprehensive Test Suite

**Title**: `[FEATURE] Expand test coverage with comprehensive test suite`

**Description**: 
The project currently lacks comprehensive tests. We need to add unit tests, integration tests, and end-to-end tests to ensure reliability and make contributions safer.

**Problem**: 
Without proper test coverage, it's difficult to verify that changes work correctly and don't introduce regressions.

**Acceptance Criteria**:
- [ ] Add unit tests for all scanner classes (CodeSecurityScanner, DependencyScanner, etc.)
- [ ] Add unit tests for utility classes (TrustManager, ResponseSanitizer, etc.)
- [ ] Add integration tests for SecurityAgent workflow
- [ ] Add end-to-end tests for CLI commands
- [ ] Add test fixtures and mock data
- [ ] Set up CI/CD pipeline for automated testing
- [ ] Achieve minimum 80% code coverage
- [ ] Add performance tests for large-scale scanning

**Technical Details**:
- Use Jest for unit and integration tests
- Create test fixtures in `tests/fixtures/`
- Add mock implementations for external dependencies
- Set up GitHub Actions for automated testing
- Add test utilities in `tests/utils/`
- Create test configuration for different environments
- Add performance benchmarks for critical paths

**Difficulty**: Medium
**Labels**: `enhancement`, `help wanted`, `testing`, `good first issue`

---

## How to Contribute

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/issue-description`
3. **Make your changes** following the project's coding standards
4. **Add tests** for new functionality
5. **Update documentation** as needed
6. **Commit your changes**: `git commit -m 'Add feature: description'`
7. **Push to your fork**: `git push origin feature/issue-description`
8. **Create a Pull Request** with a clear description of your changes

## Getting Started

- Read the [Contributing Guide](CONTRIBUTING.md)
- Check the [Development Setup](README.md#development-setup) section
- Join our [Discussions](https://github.com/johnjohn2410/MCP-Security-Agent/discussions) for questions
- Review existing issues and pull requests

## Questions?

If you have questions about any of these issues or need help getting started, please:
- Open a [Discussion](https://github.com/johnjohn2410/MCP-Security-Agent/discussions)
- Comment on the specific issue
- Reach out via email: jross3511@yahoo.com

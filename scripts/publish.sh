#!/bin/bash

# MCP Security Agent - Publish Script
# This script helps publish the package to npm

echo "🚀 MCP Security Agent - Publishing to npm"
echo "=========================================="

# Check if we're logged into npm
if ! npm whoami > /dev/null 2>&1; then
    echo "❌ Not logged into npm. Please run: npm login"
    exit 1
fi

# Build the project
echo "📦 Building project..."
npm run build

# Check if build was successful
if [ $? -ne 0 ]; then
    echo "❌ Build failed. Please fix the errors and try again."
    exit 1
fi

# Show what will be published
echo "📋 Files to be published:"
npm pack --dry-run

# Confirm before publishing
echo ""
read -p "🤔 Ready to publish to npm? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Publishing cancelled."
    exit 1
fi

# Publish to npm
echo "🚀 Publishing to npm..."
npm publish --access public

if [ $? -eq 0 ]; then
    echo "✅ Successfully published to npm!"
    echo "📦 Package: https://www.npmjs.com/package/mcp-security-agent"
    echo "🔗 Repository: https://github.com/johnjohn2410/MCP-Security-Agent"
else
    echo "❌ Publishing failed. Please check the error messages above."
    exit 1
fi

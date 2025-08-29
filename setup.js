#!/usr/bin/env node

const fs = require('fs-extra');
const path = require('path');
const { execSync } = require('child_process');

console.log('🔒 MCP Security Agent - Setup');
console.log('==============================\n');

async function setup() {
  try {
    console.log('📦 Installing dependencies...');
    execSync('npm install', { stdio: 'inherit' });
    console.log('✅ Dependencies installed successfully!\n');

    console.log('🔨 Building the project...');
    execSync('npm run build', { stdio: 'inherit' });
    console.log('✅ Project built successfully!\n');

    console.log('📁 Creating necessary directories...');
    await fs.ensureDir('logs');
    await fs.ensureDir('reports');
    await fs.ensureDir('examples');
    console.log('✅ Directories created successfully!\n');

    console.log('⚙️  Setting up environment configuration...');
    const envExamplePath = path.join(__dirname, 'env.example');
    const envPath = path.join(__dirname, '.env');
    
    if (!await fs.pathExists(envPath)) {
      await fs.copy(envExamplePath, envPath);
      console.log('✅ Environment file created from template!');
      console.log('   Please edit .env file with your configuration.\n');
    } else {
      console.log('ℹ️  Environment file already exists.\n');
    }

    console.log('🧪 Running basic tests...');
    try {
      execSync('node test-scanner.js', { stdio: 'inherit' });
      console.log('✅ Basic tests passed!\n');
    } catch (error) {
      console.log('⚠️  Basic tests failed, but setup completed.\n');
    }

    console.log('🎉 Setup completed successfully!');
    console.log('\n📋 Next steps:');
    console.log('1. Edit .env file with your configuration');
    console.log('2. Add your OpenAI API key for AI analysis');
    console.log('3. Run: npm start to start the MCP server');
    console.log('4. Run: node dist/index.js scan ./examples to test scanning');
    console.log('5. Check the README.md for more usage examples');
    
    console.log('\n🚀 You\'re ready to use the MCP Security Agent!');

  } catch (error) {
    console.error('❌ Setup failed:', error.message);
    process.exit(1);
  }
}

// Run setup if this file is executed directly
if (require.main === module) {
  setup();
}

module.exports = { setup };

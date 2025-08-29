// Example file with intentional security vulnerabilities for testing
// DO NOT USE IN PRODUCTION!

const express = require('express');
const mysql = require('mysql');
const fs = require('fs');

const app = express();

// VULNERABILITY: Hardcoded database credentials
const dbConfig = {
  host: 'localhost',
  user: 'admin',
  password: 'super_secret_password_123', // This is a vulnerability
  database: 'users'
};

// VULNERABILITY: Hardcoded API key
const apiKey = 'sk-1234567890abcdef1234567890abcdef12345678'; // This is a vulnerability

// VULNERABILITY: SQL Injection vulnerable function
function getUserById(userId) {
  const query = `SELECT * FROM users WHERE id = ${userId}`; // SQL Injection vulnerability
  return mysql.query(query);
}

// VULNERABILITY: XSS vulnerable endpoint
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const user = getUserById(userId);
  
  // XSS vulnerability - user input directly inserted into HTML
  res.send(`
    <html>
      <body>
        <h1>User Profile</h1>
        <div id="user-data">${user.name}</div>
        <script>
          document.getElementById('user-data').innerHTML = '${user.name}'; // XSS vulnerability
        </script>
      </body>
    </html>
  `);
});

// VULNERABILITY: Command injection vulnerable function
function executeCommand(command) {
  const { exec } = require('child_process');
  return exec(command); // Command injection vulnerability
}

// VULNERABILITY: Path traversal vulnerable function
function readFile(filePath) {
  return fs.readFileSync(filePath, 'utf-8'); // Path traversal vulnerability
}

// VULNERABILITY: Insecure deserialization
function parseUserData(data) {
  return eval(data); // Insecure deserialization vulnerability
}

// VULNERABILITY: Weak cryptography
const crypto = require('crypto');
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex'); // Weak crypto
}

// VULNERABILITY: Insecure file upload
app.post('/upload', (req, res) => {
  const uploadedFile = req.files.file;
  const uploadPath = './uploads/' + uploadedFile.name;
  
  uploadedFile.mv(uploadPath, (err) => {
    if (err) {
      res.status(500).send(err);
    } else {
      res.send('File uploaded successfully');
    }
  });
});

// VULNERABILITY: Missing input validation
app.post('/user', (req, res) => {
  const userData = req.body;
  // No input validation - direct use of user input
  const newUser = {
    name: userData.name,
    email: userData.email,
    age: userData.age
  };
  
  // Save user without validation
  saveUser(newUser);
  res.json({ success: true });
});

// VULNERABILITY: Insecure session handling
app.use(session({
  secret: 'my-secret-key', // Weak secret
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false, // Should be true in production
    httpOnly: false // Should be true
  }
}));

// VULNERABILITY: Debug mode enabled in production
app.set('debug', true); // Should be false in production

// VULNERABILITY: CORS misconfiguration
app.use(cors({
  origin: '*' // Too permissive
}));

// VULNERABILITY: Error information disclosure
app.use((err, req, res, next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack // Exposes sensitive information
  });
});

// VULNERABILITY: Hardcoded JWT secret
const jwt = require('jsonwebtoken');
const jwtSecret = 'my-super-secret-jwt-key-123'; // Should be in environment variables

function generateToken(user) {
  return jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '24h' });
}

// VULNERABILITY: Insecure random number generation
function generateRandomToken() {
  return Math.random().toString(36).substring(2); // Not cryptographically secure
}

// VULNERABILITY: Logging sensitive information
function logUserActivity(user, action) {
  console.log(`User ${user.id} performed action: ${action}`);
  console.log(`User email: ${user.email}`); // Logging sensitive data
  console.log(`User password hash: ${user.passwordHash}`); // Logging sensitive data
}

// VULNERABILITY: Insecure redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.redirect(url); // Open redirect vulnerability
});

// VULNERABILITY: Missing CSRF protection
app.post('/transfer', (req, res) => {
  const { amount, toAccount } = req.body;
  // No CSRF token validation
  transferMoney(amount, toAccount);
  res.json({ success: true });
});

// VULNERABILITY: Insecure password policy
function validatePassword(password) {
  return password.length >= 6; // Too weak
}

// VULNERABILITY: Insecure file permissions
function createLogFile() {
  fs.writeFileSync('./app.log', 'Application started', { mode: 0o777 }); // Too permissive
}

// VULNERABILITY: Insecure environment variable handling
const databaseUrl = process.env.DATABASE_URL || 'mysql://user:pass@localhost/db'; // Fallback with hardcoded credentials

// VULNERABILITY: Insecure cookie settings
app.use(cookieParser());
app.use((req, res, next) => {
  res.cookie('sessionId', req.session.id, {
    secure: false, // Should be true in production
    httpOnly: false, // Should be true
    sameSite: 'none' // Should be 'strict' or 'lax'
  });
  next();
});

// VULNERABILITY: Insecure headers
app.use((req, res, next) => {
  res.removeHeader('X-Frame-Options'); // Removes security header
  res.removeHeader('X-Content-Type-Options'); // Removes security header
  next();
});

// VULNERABILITY: Insecure dependency (example)
// This would be detected by the dependency scanner
// const vulnerablePackage = require('lodash@4.17.20');

app.listen(3000, () => {
  console.log('Server running on port 3000');
  console.log('Database URL:', databaseUrl); // Logging sensitive information
});

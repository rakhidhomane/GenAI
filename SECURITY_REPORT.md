# OWASP Top 10 Security Vulnerability Report

**Repository:** OWASP Security POC  
**Date:** April 13, 2026  
**Reviewed By:** GitHub Copilot Security Scan  

---

## Executive Summary

This security review identified **10 critical to high severity vulnerabilities** mapped to the OWASP Top 10 (2021). This application is intentionally vulnerable for educational purposes, but this report provides detailed remediation guidance for each issue.

| Severity | Count |
|----------|-------|
| 🔴 Critical | 4 |
| 🟠 High | 4 |
| 🟡 Medium | 2 |

---

## Vulnerabilities Identified

### 1. A03:2021 – Injection (SQL Injection)

**Severity:** 🔴 Critical  
**CVSS Score:** 9.8  
**Location:** `src/app.js` (Lines 17-35, 77-86)

#### Description
User input is directly concatenated into SQL queries without sanitization or parameterization, allowing attackers to execute arbitrary SQL commands.

#### Vulnerable Code
```javascript
// Login endpoint - Line 20
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

// Register endpoint - Line 80
const query = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`;
```

#### Attack Example
```
Username: admin' OR '1'='1' --
Password: anything
```
This bypasses authentication entirely.

#### Remediation
Use parameterized queries (prepared statements):

```javascript
// Secure Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  const query = "SELECT * FROM users WHERE username = ? AND password = ?";
  
  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Internal server error" });
    }
    
    if (results.length > 0) {
      const token = jwt.sign(
        { username: username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.json({ message: "Login successful", token });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  });
});

// Secure Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  
  // Input validation
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }

  // Hash the password before storing
  const bcrypt = require('bcrypt');
  const hashedPassword = await bcrypt.hash(password, 12);
  
  const query = "INSERT INTO users (username, password) VALUES (?, ?)";
  
  db.query(query, [username, hashedPassword], (err) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Internal server error" });
    }
    res.status(201).json({ message: "User registered successfully" });
  });
});
```

---

### 2. A01:2021 – Broken Access Control

**Severity:** 🔴 Critical  
**CVSS Score:** 9.1  
**Location:** `src/app.js` (Lines 37-40)

#### Description
The `/admin` endpoint is publicly accessible without any authentication or authorization checks, exposing sensitive administrative functions.

#### Vulnerable Code
```javascript
// A01: Broken Access Control
app.get("/admin", (req, res) => {
  res.send("Welcome Admin! Sensitive data exposed.");
});
```

#### Attack Example
Any unauthenticated user can access `http://localhost:3000/admin` and view admin content.

#### Remediation
Implement proper authentication and role-based access control (RBAC):

```javascript
// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: "Authentication required" });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

// Authorization middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
};

// Secure admin endpoint
app.get("/admin", authenticateToken, requireAdmin, (req, res) => {
  res.json({ message: "Welcome Admin!", data: "Sensitive admin data" });
});
```

---

### 3. A02:2021 – Cryptographic Failures

**Severity:** 🔴 Critical  
**CVSS Score:** 9.0  
**Location:** `config/config.js` (Lines 1-9), `src/app.js` (Lines 26-29)

#### Description
Multiple cryptographic failures were identified:
1. Hardcoded database credentials in source code
2. Hardcoded JWT secret key
3. Weak/predictable JWT secret ("mysecretkey")
4. Passwords stored in plain text (no hashing)

#### Vulnerable Code
```javascript
// config/config.js
module.exports = {
  db: {
    host: "localhost",
    user: "root",
    password: "root123", // Hardcoded credentials
    database: "users_db"
  },
  jwtSecret: "mysecretkey" // Hardcoded secret
};
```

#### Attack Example
- Secrets in source control can be extracted from git history
- Weak JWT secrets can be brute-forced to forge tokens
- Plain text passwords can be directly read from database dumps

#### Remediation

**1. Use Environment Variables:**
```javascript
// config/config.js - Secure version
require('dotenv').config();

module.exports = {
  db: {
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
  },
  jwtSecret: process.env.JWT_SECRET
};
```

**2. Create .env file (add to .gitignore):**
```env
DB_HOST=localhost
DB_USER=app_user
DB_PASSWORD=<strong-generated-password>
DB_NAME=users_db
JWT_SECRET=<generate-with: openssl rand -base64 64>
```

**3. Add .gitignore entries:**
```
.env
.env.local
.env.*.local
```

**4. Generate strong JWT secret:**
```bash
openssl rand -base64 64
```

---

### 4. A04:2021 – Insecure Design

**Severity:** 🟠 High  
**CVSS Score:** 8.0  
**Location:** `src/app.js` (Lines 76-86)

#### Description
Passwords are stored in plain text without hashing, representing a fundamental design flaw in security architecture.

#### Vulnerable Code
```javascript
// Plain text password storage
const query = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`;
```

#### Attack Example
If the database is compromised, all passwords are immediately exposed in readable form.

#### Remediation
Implement proper password hashing using bcrypt:

```javascript
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 12;

// Password hashing during registration
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Password strength validation
    if (password.length < 8) {
      return res.status(400).json({ 
        message: "Password must be at least 8 characters" 
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    
    const query = "INSERT INTO users (username, password) VALUES (?, ?)";
    db.query(query, [username, hashedPassword], (err) => {
      if (err) {
        return res.status(500).json({ message: "Registration failed" });
      }
      res.status(201).json({ message: "User registered successfully" });
    });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

// Password verification during login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  
  const query = "SELECT * FROM users WHERE username = ?";
  db.query(query, [username], async (err, results) => {
    if (err || results.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    
    const user = results[0];
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    
    const token = jwt.sign(
      { username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ message: "Login successful", token });
  });
});
```

---

### 5. A05:2021 – Security Misconfiguration

**Severity:** 🔴 Critical  
**CVSS Score:** 9.0  
**Location:** `src/app.js` (Lines 11-14)

#### Description
The `/config` endpoint exposes all application configuration including database credentials and JWT secret to any user.

#### Vulnerable Code
```javascript
// A05: Security Misconfiguration (Sensitive Information Exposure)
app.get("/config", (req, res) => {
  res.json(config);
});
```

#### Attack Example
```bash
curl http://localhost:3000/config
# Returns: {"db":{"host":"localhost","user":"root","password":"root123"...},"jwtSecret":"mysecretkey"}
```

#### Remediation
Remove this endpoint entirely, or if needed for debugging, restrict to development only:

```javascript
// REMOVE THIS ENDPOINT IN PRODUCTION
// If absolutely needed for development:
if (process.env.NODE_ENV === 'development') {
  app.get("/config", authenticateToken, requireAdmin, (req, res) => {
    // Only return non-sensitive configuration
    res.json({
      environment: process.env.NODE_ENV,
      version: require('../package.json').version
    });
  });
}
```

---

### 6. A07:2021 – Identification and Authentication Failures

**Severity:** 🟠 High  
**CVSS Score:** 7.5  
**Location:** `src/app.js` (Lines 55-69)

#### Description
Multiple authentication weaknesses:
1. JWT tokens have no expiration
2. Weak JWT secret makes token forgery possible
3. No token refresh mechanism
4. No rate limiting on authentication endpoints
5. No account lockout after failed attempts

#### Vulnerable Code
```javascript
// No expiration set on JWT
const token = jwt.sign(
  { username: username },
  config.jwtSecret // Weak secret
);
```

#### Remediation
```javascript
const rateLimit = require('express-rate-limit');

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { message: "Too many login attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false
});

app.post("/login", authLimiter, async (req, res) => {
  // ... authentication logic ...
  
  // Generate token with expiration and additional claims
  const token = jwt.sign(
    { 
      username: user.username,
      role: user.role,
      iat: Math.floor(Date.now() / 1000)
    },
    process.env.JWT_SECRET,
    { 
      expiresIn: '15m',  // Short-lived access token
      issuer: 'your-app-name',
      audience: 'your-app-users'
    }
  );
  
  // Optionally issue a refresh token
  const refreshToken = jwt.sign(
    { username: user.username },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );
  
  res.json({ 
    message: "Login successful", 
    accessToken: token,
    refreshToken: refreshToken,
    expiresIn: 900 // 15 minutes in seconds
  });
});
```

---

### 7. A09:2021 – Security Logging and Monitoring Failures

**Severity:** 🟡 Medium  
**CVSS Score:** 5.5  
**Location:** `src/app.js` (Lines 71-74)

#### Description
1. Error handler exposes full stack traces to users
2. No logging of security-relevant events
3. No monitoring or alerting mechanisms
4. Failed login attempts not logged

#### Vulnerable Code
```javascript
// A09: Security Logging and Monitoring Failures
app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});
```

#### Remediation
```javascript
const winston = require('winston');

// Configure secure logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/security.log' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Security event logging middleware
const logSecurityEvent = (event, details) => {
  logger.info({
    type: 'security',
    event: event,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// Log failed login attempts
app.post("/login", authLimiter, async (req, res) => {
  const { username } = req.body;
  
  // ... authentication logic ...
  
  if (!passwordMatch) {
    logSecurityEvent('LOGIN_FAILED', {
      username: username,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    return res.status(401).json({ message: "Invalid credentials" });
  }
  
  logSecurityEvent('LOGIN_SUCCESS', {
    username: username,
    ip: req.ip
  });
  
  // ... generate token ...
});

// Secure error handler
app.use((err, req, res, next) => {
  // Log the full error internally
  logger.error({
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });
  
  // Return generic error to user
  res.status(500).json({ 
    message: "An internal error occurred. Please try again later.",
    errorId: require('crypto').randomUUID() // For support reference
  });
});
```

---

### 8. A10:2021 – Server-Side Request Forgery (SSRF)

**Severity:** 🟠 High  
**CVSS Score:** 8.6  
**Location:** `src/app.js` (Lines 42-53)

#### Description
The `/fetch` endpoint accepts arbitrary URLs from user input without validation, allowing attackers to:
- Access internal services (e.g., `http://localhost:8080/admin`)
- Scan internal network
- Access cloud metadata endpoints (e.g., `http://169.254.169.254/`)
- Exfiltrate data

#### Vulnerable Code
```javascript
// A10: Server-Side Request Forgery (SSRF)
app.get("/fetch", async (req, res) => {
  const url = req.query.url;
  const axios = require("axios");

  try {
    const response = await axios.get(url);
    res.send(response.data);
  } catch (error) {
    res.status(500).send("Error fetching URL");
  }
});
```

#### Attack Example
```bash
# Access cloud metadata
curl "http://localhost:3000/fetch?url=http://169.254.169.254/latest/meta-data/"

# Scan internal network
curl "http://localhost:3000/fetch?url=http://192.168.1.1/admin"
```

#### Remediation
```javascript
const { URL } = require('url');
const dns = require('dns').promises;

// Allowlist of permitted domains
const ALLOWED_DOMAINS = [
  'api.example.com',
  'cdn.example.com'
];

// Blocklist of private IP ranges
const isPrivateIP = (ip) => {
  const parts = ip.split('.').map(Number);
  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 169 && parts[1] === 254) // Link-local
  );
};

app.get("/fetch", authenticateToken, async (req, res) => {
  try {
    const urlString = req.query.url;
    
    if (!urlString) {
      return res.status(400).json({ message: "URL parameter required" });
    }
    
    // Parse and validate URL
    let parsedUrl;
    try {
      parsedUrl = new URL(urlString);
    } catch {
      return res.status(400).json({ message: "Invalid URL format" });
    }
    
    // Only allow HTTPS
    if (parsedUrl.protocol !== 'https:') {
      return res.status(400).json({ message: "Only HTTPS URLs are allowed" });
    }
    
    // Check against allowlist
    if (!ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
      return res.status(403).json({ message: "Domain not in allowlist" });
    }
    
    // Resolve hostname and check for private IPs
    const addresses = await dns.resolve4(parsedUrl.hostname);
    for (const ip of addresses) {
      if (isPrivateIP(ip)) {
        return res.status(403).json({ message: "Access to private networks denied" });
      }
    }
    
    // Make request with timeout and size limits
    const response = await axios.get(urlString, {
      timeout: 5000,
      maxContentLength: 1024 * 1024, // 1MB limit
      maxRedirects: 0 // Prevent redirect-based bypasses
    });
    
    res.send(response.data);
  } catch (error) {
    res.status(500).json({ message: "Error fetching URL" });
  }
});
```

---

### 9. A06:2021 – Vulnerable and Outdated Components

**Severity:** 🟠 High  
**CVSS Score:** 7.5  
**Location:** `package.json`

#### Description
The application uses outdated dependencies with known vulnerabilities:
- `express@4.17.1` - Multiple security patches available
- `mysql@2.18.1` - Consider using `mysql2` with better security
- `jsonwebtoken@8.5.1` - Updates available

#### Current Dependencies
```json
{
  "express": "4.17.1",
  "mysql": "2.18.1",
  "body-parser": "1.19.0",
  "jsonwebtoken": "8.5.1"
}
```

#### Remediation
1. Audit dependencies regularly:
```bash
npm audit
```

2. Update to latest secure versions:
```json
{
  "express": "^4.19.2",
  "mysql2": "^3.9.7",
  "jsonwebtoken": "^9.0.2",
  "bcrypt": "^5.1.1",
  "dotenv": "^16.4.5",
  "helmet": "^7.1.0",
  "express-rate-limit": "^7.2.0",
  "winston": "^3.13.0"
}
```

3. Use automated dependency updates (Dependabot, Snyk).

---

### 10. Additional Security Issues

#### 10.1 Missing Security Headers
**Severity:** 🟡 Medium  
**CVSS Score:** 5.0

The application lacks essential security headers like CSP, HSTS, X-Frame-Options.

**Remediation:**
```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-site" },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  noSniff: true,
  frameguard: { action: 'deny' },
  xssFilter: true
}));
```

#### 10.2 Insecure Form Submission (HTTP)
**Severity:** 🟡 Medium  
**Location:** `public/login.html` (Line 8)

The login form submits to HTTP, not HTTPS.

**Remediation:**
```html
<!-- Use relative URL and enforce HTTPS -->
<form action="/login" method="POST">
```

---

## Summary of Required Fixes

| Priority | Vulnerability | Fix Required |
|----------|--------------|--------------|
| 1 | SQL Injection | Use parameterized queries |
| 2 | Broken Access Control | Implement auth middleware |
| 3 | Cryptographic Failures | Environment variables + password hashing |
| 4 | Sensitive Data Exposure | Remove /config endpoint |
| 5 | SSRF | URL validation and allowlisting |
| 6 | Authentication Failures | Rate limiting + JWT expiration |
| 7 | Insecure Design | bcrypt password hashing |
| 8 | Logging Failures | Implement winston logging |
| 9 | Outdated Components | Update npm dependencies |
| 10 | Missing Headers | Add helmet middleware |

---

## Recommended Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Layer Stack                     │
├─────────────────────────────────────────────────────────────┤
│  1. WAF / Rate Limiting (express-rate-limit)               │
│  2. Security Headers (helmet)                               │
│  3. Input Validation & Sanitization                         │
│  4. Authentication (JWT with short expiry)                  │
│  5. Authorization (RBAC middleware)                         │
│  6. Parameterized Queries (mysql2)                          │
│  7. Password Hashing (bcrypt)                               │
│  8. Secure Configuration (dotenv)                           │
│  9. Security Logging (winston)                              │
│  10. Error Handling (generic messages)                      │
└─────────────────────────────────────────────────────────────┘
```

---

## Updated Secure package.json

```json
{
  "name": "owasp-security-poc",
  "version": "1.0.0",
  "description": "Secure Node.js application",
  "main": "src/app.js",
  "scripts": {
    "start": "node src/app.js",
    "audit": "npm audit --audit-level=moderate",
    "audit:fix": "npm audit fix"
  },
  "dependencies": {
    "express": "^4.19.2",
    "mysql2": "^3.9.7",
    "jsonwebtoken": "^9.0.2",
    "bcrypt": "^5.1.1",
    "dotenv": "^16.4.5",
    "helmet": "^7.1.0",
    "express-rate-limit": "^7.2.0",
    "winston": "^3.13.0",
    "express-validator": "^7.0.1"
  },
  "devDependencies": {
    "eslint": "^8.57.0",
    "eslint-plugin-security": "^2.1.1"
  }
}
```

---

## Conclusion

This application contains multiple critical security vulnerabilities that would allow complete system compromise in a production environment. The most severe issues are:

1. **SQL Injection** - Allows database manipulation and data theft
2. **Broken Access Control** - Allows unauthorized access to admin functions
3. **Cryptographic Failures** - Exposes credentials and allows token forgery
4. **SSRF** - Allows access to internal network resources

Immediate remediation is required before any production deployment. All fixes should be implemented and verified through security testing (SAST, DAST, penetration testing) before release.

---

*Report generated by GitHub Copilot Security Review*

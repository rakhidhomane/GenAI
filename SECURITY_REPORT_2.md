# OWASP Top 10 Security Vulnerability Report

**Repository:** rakhidhomane/GenAI  
**Review Date:** April 13, 2026  
**Model Used:** Claude Opus 4.2  
**Reviewer:** GitHub Copilot Security Review  

---

## Executive Summary

This security assessment identifies **10 critical to high severity vulnerabilities** across the OWASP Top 10 categories in this Node.js application. The application was intentionally designed with security flaws for testing purposes but serves as an excellent example of common vulnerabilities that should be avoided in production systems.

| Category | Vulnerabilities Found | Severity |
|----------|----------------------|----------|
| A01:2021 - Broken Access Control | 1 | Critical |
| A02:2021 - Cryptographic Failures | 2 | Critical |
| A03:2021 - Injection | 2 | Critical |
| A04:2021 - Insecure Design | 1 | High |
| A05:2021 - Security Misconfiguration | 2 | High |
| A06:2021 - Vulnerable and Outdated Components | 1 | Medium |
| A07:2021 - Identification and Authentication Failures | 2 | High |
| A08:2021 - Software and Data Integrity Failures | 1 | Medium |
| A09:2021 - Security Logging and Monitoring Failures | 1 | High |
| A10:2021 - Server-Side Request Forgery (SSRF) | 1 | Critical |

---

## Detailed Vulnerability Analysis

---

### A01:2021 - Broken Access Control

#### Vulnerability #1: Unprotected Admin Endpoint

**Severity:** 🔴 Critical  
**File:** `src/app.js`  
**Lines:** 37-40

**Description:**  
The `/admin` endpoint exposes sensitive administrative functionality without any authentication or authorization checks. Any user can access this endpoint.

**Vulnerable Code:**
```javascript
// A01: Broken Access Control
app.get("/admin", (req, res) => {
  res.send("Welcome Admin! Sensitive data exposed.");
});
```

**Attack Vector:**  
An attacker can simply navigate to `http://localhost:3000/admin` to access administrative functions without any credentials.

**Remediation Steps:**
1. Implement authentication middleware to verify user identity
2. Implement authorization checks to verify user has admin privileges
3. Use role-based access control (RBAC)

**Secure Code Example:**
```javascript
const authMiddleware = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  
  if (!token) {
    return res.status(401).json({ message: "Authentication required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
};

app.get("/admin", authMiddleware, requireAdmin, (req, res) => {
  res.send("Welcome Admin! You have been authenticated and authorized.");
});
```

---

### A02:2021 - Cryptographic Failures

#### Vulnerability #2: Hardcoded JWT Secret

**Severity:** 🔴 Critical  
**File:** `config/config.js`  
**Lines:** 8

**Description:**  
The JWT signing secret is hardcoded as a weak, predictable string `"mysecretkey"`. This allows attackers to forge valid JWT tokens.

**Vulnerable Code:**
```javascript
module.exports = {
  // ...
  jwtSecret: "mysecretkey" // Hardcoded secret
};
```

**Attack Vector:**  
An attacker can create forged JWT tokens signed with the known secret, impersonating any user including administrators.

**Remediation Steps:**
1. Use environment variables for secrets
2. Generate cryptographically strong secrets (minimum 256 bits)
3. Rotate secrets periodically
4. Never commit secrets to source control

**Secure Code Example:**
```javascript
// config/config.js
module.exports = {
  db: {
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
  },
  jwtSecret: process.env.JWT_SECRET // Must be set in environment
};

// Validation on startup
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be set and at least 32 characters long");
}
```

#### Vulnerability #3: Hardcoded Database Credentials

**Severity:** 🔴 Critical  
**File:** `config/config.js`  
**Lines:** 2-6

**Description:**  
Database credentials are hardcoded in the source code with a weak password `"root123"`.

**Vulnerable Code:**
```javascript
module.exports = {
  db: {
    host: "localhost",
    user: "root",
    password: "root123", // Hardcoded credentials
    database: "users_db"
  },
  // ...
};
```

**Attack Vector:**  
Anyone with access to the source code repository can obtain database credentials. Additionally, using "root" as the database user provides maximum privileges.

**Remediation Steps:**
1. Use environment variables for all credentials
2. Use a least-privilege database user
3. Use secrets management solutions (AWS Secrets Manager, HashiCorp Vault, etc.)
4. Add config files with secrets to `.gitignore`

**Secure Code Example:**
```javascript
// config/config.js
require('dotenv').config();

module.exports = {
  db: {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    // Additional security options
    ssl: {
      rejectUnauthorized: true
    }
  },
  jwtSecret: process.env.JWT_SECRET
};

// Validate required environment variables
const required = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'JWT_SECRET'];
for (const varName of required) {
  if (!process.env[varName]) {
    throw new Error(`Environment variable ${varName} is required`);
  }
}
```

---

### A03:2021 - Injection

#### Vulnerability #4: SQL Injection in Login Endpoint

**Severity:** 🔴 Critical  
**File:** `src/app.js`  
**Lines:** 17-34

**Description:**  
User input is directly concatenated into SQL queries without sanitization, allowing SQL injection attacks.

**Vulnerable Code:**
```javascript
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  db.query(query, (err, results) => {
    // ...
  });
});
```

**Attack Vector:**  
An attacker can bypass authentication using:
- Username: `admin' --`
- Password: `anything`

This transforms the query to:
```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
```

**Remediation Steps:**
1. Use parameterized queries (prepared statements)
2. Implement input validation
3. Use an ORM with built-in SQL injection protection
4. Apply principle of least privilege to database user

**Secure Code Example:**
```javascript
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Input validation
  if (!username || !password || 
      typeof username !== 'string' || 
      typeof password !== 'string') {
    return res.status(400).json({ message: "Invalid input" });
  }

  // Parameterized query - the '?' placeholders prevent SQL injection
  const query = "SELECT * FROM users WHERE username = ?";
  
  db.query(query, [username], async (err, results) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Internal server error" });
    }

    if (results.length > 0) {
      // Use bcrypt.compare to verify the password against the stored hash
      const isMatch = await bcrypt.compare(password, results[0].password_hash);
      
      if (isMatch) {
        const token = jwt.sign(
          { userId: results[0].id, username: username },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        );
        res.json({ message: "Login successful", token });
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      }
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  });
});
```

#### Vulnerability #5: SQL Injection in Registration Endpoint

**Severity:** 🔴 Critical  
**File:** `src/app.js`  
**Lines:** 76-86

**Description:**  
The registration endpoint is also vulnerable to SQL injection through string concatenation.

**Vulnerable Code:**
```javascript
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  const query = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`;

  db.query(query, (err) => {
    if (err) throw err;
    res.send("User registered successfully");
  });
});
```

**Attack Vector:**  
An attacker could inject malicious SQL to:
- Extract data from other tables
- Modify existing records
- Delete data
- Execute administrative operations

**Remediation Steps:**  
Same as Vulnerability #4

**Secure Code Example:**
```javascript
const bcrypt = require('bcrypt');

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Input validation
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password required" });
    }

    if (username.length < 3 || username.length > 50) {
      return res.status(400).json({ message: "Username must be 3-50 characters" });
    }

    if (password.length < 8) {
      return res.status(400).json({ message: "Password must be at least 8 characters" });
    }

    // Hash password before storing
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Parameterized query
    const query = "INSERT INTO users (username, password_hash) VALUES (?, ?)";
    
    db.query(query, [username, passwordHash], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ message: "Username already exists" });
        }
        console.error("Registration error:", err);
        return res.status(500).json({ message: "Registration failed" });
      }
      res.status(201).json({ message: "User registered successfully" });
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});
```

---

### A04:2021 - Insecure Design

#### Vulnerability #6: Plain Text Password Storage

**Severity:** 🔴 High  
**File:** `src/app.js`  
**Lines:** 76-86

**Description:**  
Passwords are stored in plain text in the database without hashing, violating fundamental security principles.

**Vulnerable Code:**
```javascript
const query = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`;
```

**Attack Vector:**  
If the database is compromised, all user passwords are immediately exposed. Password reuse by users could lead to account compromise on other platforms.

**Remediation Steps:**
1. Use bcrypt, Argon2, or scrypt for password hashing
2. Use a high cost factor/work factor
3. Never store or log plain text passwords
4. Implement password complexity requirements

**Secure Code Example:**
```javascript
const bcrypt = require('bcrypt');

// Registration
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  
  // Password complexity validation
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({ 
      message: "Password must contain uppercase, lowercase, number, and special character" 
    });
  }

  const saltRounds = 12;
  const passwordHash = await bcrypt.hash(password, saltRounds);
  
  const query = "INSERT INTO users (username, password_hash) VALUES (?, ?)";
  db.query(query, [username, passwordHash], (err) => {
    // ... handle response
  });
});

// Login - compare hashed passwords
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  
  const query = "SELECT * FROM users WHERE username = ?";
  db.query(query, [username], async (err, results) => {
    if (results.length > 0) {
      const match = await bcrypt.compare(password, results[0].password_hash);
      if (match) {
        // Generate token
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      }
    }
  });
});
```

---

### A05:2021 - Security Misconfiguration

#### Vulnerability #7: Sensitive Configuration Exposure

**Severity:** 🔴 High  
**File:** `src/app.js`  
**Lines:** 11-14

**Description:**  
An endpoint exposes the entire application configuration including database credentials and JWT secrets.

**Vulnerable Code:**
```javascript
// A05: Security Misconfiguration (Sensitive Information Exposure)
app.get("/config", (req, res) => {
  res.json(config);
});
```

**Attack Vector:**  
Any user can access `http://localhost:3000/config` to obtain database credentials and JWT secrets.

**Remediation Steps:**
1. Remove this endpoint entirely
2. Never expose sensitive configuration through any endpoint
3. If configuration needs to be exposed, only show non-sensitive data
4. Implement access control for any debugging endpoints

**Secure Code Example:**
```javascript
// Remove the /config endpoint entirely

// If absolutely needed for debugging (development only):
if (process.env.NODE_ENV === 'development') {
  app.get("/config", authMiddleware, requireAdmin, (req, res) => {
    // Only expose non-sensitive configuration
    res.json({
      appVersion: require('../package.json').version,
      nodeEnv: process.env.NODE_ENV,
      // Never include: passwords, secrets, database credentials
    });
  });
}
```

#### Vulnerability #8: Error Stack Trace Exposure

**Severity:** 🟡 Medium  
**File:** `src/app.js`  
**Lines:** 71-74

**Description:**  
Error stack traces are sent directly to clients, potentially revealing internal application structure and sensitive information.

**Vulnerable Code:**
```javascript
// A09: Security Logging and Monitoring Failures
app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});
```

**Attack Vector:**  
Attackers can trigger errors to learn about application internals, file paths, library versions, and database schema.

**Remediation Steps:**
1. Log detailed errors server-side only
2. Send generic error messages to clients
3. Implement proper error handling middleware
4. Use different error handling for production vs development

**Secure Code Example:**
```javascript
// Error handling middleware
app.use((err, req, res, next) => {
  // Log detailed error for debugging
  console.error('Error:', {
    message: err.message,
    stack: err.stack,
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method,
    ip: req.ip
  });

  // Send generic message to client
  const statusCode = err.statusCode || 500;
  const message = process.env.NODE_ENV === 'production' 
    ? 'An unexpected error occurred' 
    : err.message;

  res.status(statusCode).json({
    error: message,
    requestId: req.id // For support correlation
  });
});
```

---

### A06:2021 - Vulnerable and Outdated Components

#### Vulnerability #9: Outdated Dependencies

**Severity:** 🟡 Medium  
**File:** `package.json`  
**Lines:** 9-14

**Description:**  
The application uses outdated package versions that may contain known vulnerabilities.

**Vulnerable Code:**
```json
{
  "dependencies": {
    "express": "4.17.1",
    "mysql": "2.18.1",
    "body-parser": "1.19.0",
    "jsonwebtoken": "8.5.1"
  }
}
```

**Known Issues:**
- `express@4.17.1` - Released January 2020, multiple security updates since
- `jsonwebtoken@8.5.1` - Has known vulnerabilities related to algorithm confusion and signature validation (see npm security advisories)
- `mysql@2.18.1` - Consider using `mysql2` with better prepared statement support

**Remediation Steps:**
1. Update all dependencies to latest stable versions
2. Use `npm audit` to identify vulnerabilities
3. Implement automated dependency scanning
4. Set up Dependabot or similar tools

**Secure Code Example:**
```json
{
  "dependencies": {
    "express": "^4.21.0",
    "mysql2": "^3.11.0",
    "jsonwebtoken": "^9.0.2",
    "helmet": "^7.1.0",
    "bcrypt": "^5.1.1",
    "express-rate-limit": "^7.4.0",
    "express-validator": "^7.2.0"
  }
}
```

Run `npm audit fix` and regularly update dependencies.

---

### A07:2021 - Identification and Authentication Failures

#### Vulnerability #10: Weak JWT Implementation

**Severity:** 🔴 High  
**File:** `src/app.js`  
**Lines:** 26-29, 55-68

**Description:**  
The JWT implementation has multiple weaknesses:
1. Weak signing secret
2. No token expiration
3. No algorithm specification (vulnerable to algorithm confusion)

**Vulnerable Code:**
```javascript
const token = jwt.sign(
  { username: username },
  config.jwtSecret // Weak secret, no expiration
);

// Verification without algorithm specification
const decoded = jwt.verify(token, config.jwtSecret);
```

**Attack Vector:**  
- Tokens never expire, so stolen tokens remain valid indefinitely
- Algorithm confusion attacks could allow forged tokens
- Weak secret can be brute-forced

**Remediation Steps:**
1. Use strong, environment-based secrets
2. Always set token expiration
3. Explicitly specify algorithms
4. Implement token refresh mechanism
5. Store token metadata for revocation capability

**Secure Code Example:**
```javascript
// Token generation with security best practices
const generateToken = (user) => {
  return jwt.sign(
    { 
      userId: user.id,
      username: user.username,
      role: user.role,
      iat: Math.floor(Date.now() / 1000)
    },
    process.env.JWT_SECRET,
    { 
      algorithm: 'HS256',
      expiresIn: '1h',
      issuer: 'your-app-name',
      audience: 'your-app-users'
    }
  );
};

// Token verification with explicit algorithm
const verifyToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'], // Explicitly specify allowed algorithms
    issuer: 'your-app-name',
    audience: 'your-app-users'
  });
};

// Middleware with proper error handling
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: "Missing or invalid authorization header" });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = verifyToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: "Token expired" });
    }
    return res.status(401).json({ message: "Invalid token" });
  }
};
```

#### Vulnerability #11: No Rate Limiting

**Severity:** 🟡 Medium  
**File:** `src/app.js`

**Description:**  
The login endpoint has no rate limiting, allowing unlimited login attempts (brute force attacks).

**Remediation Steps:**
1. Implement rate limiting on authentication endpoints
2. Add account lockout after failed attempts
3. Implement CAPTCHA after several failures
4. Use exponential backoff

**Secure Code Example:**
```javascript
const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');

// Rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { 
    message: 'Too many login attempts. Please try again later.' 
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Speed limiter - progressively slow down responses
const speedLimiter = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 3,
  delayMs: (hits) => hits * 500,
});

app.post("/login", loginLimiter, speedLimiter, async (req, res) => {
  // ... login logic
});
```

---

### A08:2021 - Software and Data Integrity Failures

#### Vulnerability #12: Insecure Form Submission

**Severity:** 🟡 Medium  
**File:** `public/login.html`  
**Lines:** 8

**Description:**  
The login form submits credentials over HTTP instead of HTTPS, allowing credentials to be intercepted.

**Vulnerable Code:**
```html
<form action="http://localhost:3000/login" method="POST">
```

**Remediation Steps:**
1. Use HTTPS for all traffic
2. Implement HSTS (HTTP Strict Transport Security)
3. Use relative URLs or protocol-relative URLs
4. Add CSRF protection

**Secure Code Example:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <h2>Login</h2>
    <form action="/login" method="POST">
        <!-- CSRF Token -->
        <input type="hidden" name="_csrf" value="{{csrfToken}}">
        
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required 
               autocomplete="username" maxlength="50" />

        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required 
               autocomplete="current-password" />

        <button type="submit">Login</button>
    </form>
</body>
</html>
```

Server-side HTTPS and security headers:
```javascript
const helmet = require('helmet');
const csrf = require('csurf');

// Security headers
app.use(helmet());
app.use(helmet.hsts({
  maxAge: 31536000, // 1 year
  includeSubDomains: true,
  preload: true
}));

// CSRF protection
app.use(csrf());
```

---

### A09:2021 - Security Logging and Monitoring Failures

#### Vulnerability #13: Insufficient Logging

**Severity:** 🔴 High  
**File:** `src/app.js`

**Description:**  
The application lacks proper security logging for:
- Failed login attempts
- Successful logins
- Access to sensitive endpoints
- Error details

**Vulnerable Code:**
```javascript
// No logging throughout the application
app.post("/login", (req, res) => {
  // No logging of authentication attempts
});
```

**Remediation Steps:**
1. Implement structured logging
2. Log all authentication events (success/failure)
3. Log access to sensitive endpoints
4. Include relevant context (IP, user agent, timestamp)
5. Set up log aggregation and alerting
6. Never log sensitive data (passwords, tokens)

**Secure Code Example:**
```javascript
const winston = require('winston');

// Configure structured logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'user-service' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.File({ filename: 'security.log', level: 'warn' })
  ]
});

// Security event logging middleware
const securityLogger = (eventType, details) => {
  logger.warn({
    type: 'security_event',
    eventType,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// Usage in login
app.post("/login", async (req, res) => {
  const { username } = req.body;
  const clientInfo = {
    ip: req.ip,
    userAgent: req.headers['user-agent']
  };

  // ... validation

  db.query(query, [username], async (err, results) => {
    if (results.length > 0 && await bcrypt.compare(password, results[0].password_hash)) {
      securityLogger('LOGIN_SUCCESS', { username, ...clientInfo });
      // Generate token
    } else {
      securityLogger('LOGIN_FAILURE', { username, ...clientInfo });
      res.status(401).json({ message: "Invalid credentials" });
    }
  });
});

// Log access to sensitive endpoints
app.get("/admin", authMiddleware, requireAdmin, (req, res) => {
  securityLogger('ADMIN_ACCESS', { 
    userId: req.user.id,
    username: req.user.username,
    ip: req.ip 
  });
  res.send("Welcome Admin!");
});
```

---

### A10:2021 - Server-Side Request Forgery (SSRF)

#### Vulnerability #14: SSRF in URL Fetch Endpoint

**Severity:** 🔴 Critical  
**File:** `src/app.js`  
**Lines:** 42-53

**Description:**  
The `/fetch` endpoint accepts arbitrary URLs from user input and makes server-side requests without validation, allowing SSRF attacks.

**Vulnerable Code:**
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

**Attack Vector:**
- Access internal services: `http://localhost:3000/fetch?url=http://169.254.169.254/latest/meta-data/` (AWS metadata)
- Port scanning: `http://localhost:3000/fetch?url=http://internal-server:22`
- Access internal APIs: `http://localhost:3000/fetch?url=http://internal-api/admin`

**Remediation Steps:**
1. Remove endpoint if not necessary
2. Implement strict URL allowlist
3. Block private IP ranges and metadata endpoints
4. Use URL parsing and validation
5. Limit response size and timeout
6. Disable redirects or limit redirect chain

**Secure Code Example:**
```javascript
const { URL } = require('url');
const dns = require('dns').promises;
const net = require('net');

// Allowed domains whitelist
const ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com'];

// Private IP ranges to block
const isPrivateIP = (ip) => {
  const parts = ip.split('.').map(Number);
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    parts[0] === 127 ||
    ip.startsWith('169.254.') || // Link-local
    ip === '0.0.0.0'
  );
};

const validateUrl = async (urlString) => {
  let url;
  
  try {
    url = new URL(urlString);
  } catch {
    throw new Error('Invalid URL format');
  }

  // Only allow HTTPS
  if (url.protocol !== 'https:') {
    throw new Error('Only HTTPS URLs are allowed');
  }

  // Check domain allowlist
  if (!ALLOWED_DOMAINS.includes(url.hostname)) {
    throw new Error('Domain not in allowlist');
  }

  // Resolve hostname and check for private IPs
  const addresses = await dns.resolve4(url.hostname);
  for (const ip of addresses) {
    if (isPrivateIP(ip)) {
      throw new Error('Access to internal resources is forbidden');
    }
  }

  return url.toString();
};

app.get("/fetch", authMiddleware, async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).json({ message: 'URL parameter required' });
  }

  try {
    const validatedUrl = await validateUrl(url);
    
    const response = await axios.get(validatedUrl, {
      timeout: 5000,
      maxRedirects: 0, // Disable redirects
      maxContentLength: 1024 * 1024, // 1MB limit
      validateStatus: (status) => status === 200
    });
    
    res.json({ data: response.data });
  } catch (error) {
    res.status(400).json({ message: error.message || 'Failed to fetch URL' });
  }
});
```

---

## Additional Security Recommendations

### 1. Implement Security Headers

```javascript
const helmet = require('helmet');

app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameSrc: ["'none'"],
    upgradeInsecureRequests: []
  }
}));
```

### 2. Input Validation Middleware

```javascript
const { body, validationResult } = require('express-validator');

const validateLogin = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 50 })
    .escape()
    .matches(/^[a-zA-Z0-9_]+$/),
  body('password')
    .isLength({ min: 8, max: 128 }),
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  }
];

app.post("/login", validateLogin, async (req, res) => {
  // ... login logic
});
```

### 3. Database Security Improvements

```javascript
const mysql = require('mysql2/promise');

// Use connection pooling with SSL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: true
  }
});

// Use prepared statements
const [rows] = await pool.execute(
  'SELECT * FROM users WHERE username = ?',
  [username]
);
```

### 4. Environment Configuration

Create a `.env.example` file (commit this, but not `.env`):

```
# Database Configuration
DB_HOST=localhost
DB_USER=app_user
DB_PASSWORD=
DB_NAME=users_db

# JWT Configuration
JWT_SECRET=

# Application
NODE_ENV=development
PORT=3000
```

Add to `.gitignore`:
```
.env
*.pem
*.key
```

---

## Summary of Vulnerabilities Found

| # | Vulnerability | OWASP Category | Severity | File | Status |
|---|--------------|----------------|----------|------|--------|
| 1 | Unprotected Admin Endpoint | A01 - Broken Access Control | Critical | src/app.js | Open |
| 2 | Hardcoded JWT Secret | A02 - Cryptographic Failures | Critical | config/config.js | Open |
| 3 | Hardcoded Database Credentials | A02 - Cryptographic Failures | Critical | config/config.js | Open |
| 4 | SQL Injection (Login) | A03 - Injection | Critical | src/app.js | Open |
| 5 | SQL Injection (Register) | A03 - Injection | Critical | src/app.js | Open |
| 6 | Plain Text Password Storage | A04 - Insecure Design | High | src/app.js | Open |
| 7 | Configuration Exposure Endpoint | A05 - Security Misconfiguration | High | src/app.js | Open |
| 8 | Error Stack Trace Exposure | A05 - Security Misconfiguration | Medium | src/app.js | Open |
| 9 | Outdated Dependencies | A06 - Vulnerable Components | Medium | package.json | Open |
| 10 | Weak JWT Implementation | A07 - Auth Failures | High | src/app.js | Open |
| 11 | No Rate Limiting | A07 - Auth Failures | Medium | src/app.js | Open |
| 12 | Insecure Form Submission | A08 - Data Integrity Failures | Medium | public/login.html | Open |
| 13 | Insufficient Logging | A09 - Logging Failures | High | src/app.js | Open |
| 14 | Server-Side Request Forgery | A10 - SSRF | Critical | src/app.js | Open |

---

## Risk Assessment Matrix

```
                        Impact
                  Low    Medium    High
           ┌─────────┬─────────┬─────────┐
     High  │  Medium │  High   │Critical │ ← #1,2,3,4,5,14
           ├─────────┼─────────┼─────────┤
Likelihood │  Low    │  Medium │  High   │ ← #6,7,10,13
     Med   ├─────────┼─────────┼─────────┤
           │  Info   │  Low    │  Medium │ ← #8,9,11,12
     Low   └─────────┴─────────┴─────────┘
```

---

## Recommended Remediation Priority

### Immediate (Critical - Fix Within 24-48 Hours)
1. **SQL Injection vulnerabilities** (#4, #5) - Can lead to complete database compromise
2. **SSRF vulnerability** (#14) - Can expose cloud metadata and internal services
3. **Configuration exposure endpoint** (#7) - Directly exposes all secrets
4. **Hardcoded credentials** (#2, #3) - All secrets are publicly visible

### Short-term (High - Fix Within 1 Week)
5. **Broken Access Control** (#1) - Admin functionality unprotected
6. **Plain text password storage** (#6) - Violates data protection requirements
7. **Weak JWT implementation** (#10) - Tokens can be forged
8. **Insufficient logging** (#13) - Cannot detect or respond to attacks

### Medium-term (Medium - Fix Within 2 Weeks)
9. **Outdated dependencies** (#9) - Known vulnerabilities in libraries
10. **Error stack exposure** (#8) - Information leakage
11. **No rate limiting** (#11) - Allows brute force attacks
12. **Insecure form submission** (#12) - Credentials sent over HTTP

---

## Conclusion

This security assessment identified **14 vulnerabilities** spanning all OWASP Top 10 categories. The application demonstrates common security anti-patterns that should be avoided in production systems.

**Key Findings:**
- **5 Critical vulnerabilities** requiring immediate attention
- **4 High severity vulnerabilities** that could lead to significant compromise
- **5 Medium severity vulnerabilities** that should be addressed promptly

The most severe issues are the SQL injection vulnerabilities and SSRF, which could allow attackers to completely compromise the application and potentially the underlying infrastructure.

---

*Report generated by GitHub Copilot Security Review using Claude Opus 4.2*

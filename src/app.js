const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const db = require("./db");
const config = require("../config/config");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// A05: Security Misconfiguration (Sensitive Information Exposure)
app.get("/config", (req, res) => {
  res.json(config);
});

// A03: SQL Injection
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  db.query(query, (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      const token = jwt.sign(
        { username: username },
        config.jwtSecret // Weak secret
      );
      res.json({ message: "Login successful", token });
    } else {
      res.status(401).json({ message: "Invalid credentials" });
    }
  });
});

// A01: Broken Access Control
app.get("/admin", (req, res) => {
  res.send("Welcome Admin! Sensitive data exposed.");
});

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

// A07: Identification and Authentication Failures
app.get("/profile", (req, res) => {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(403).send("Token missing");
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret);
    res.json({ message: "User profile", user: decoded });
  } catch (err) {
    res.status(401).send("Invalid token");
  }
});

// A09: Security Logging and Monitoring Failures
app.use((err, req, res, next) => {
  res.status(500).send(err.stack);
});

// A04: Insecure Design (Plain Text Password Storage)
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  const query = `INSERT INTO users (username, password) VALUES ('${username}', '${password}')`;

  db.query(query, (err) => {
    if (err) throw err;
    res.send("User registered successfully");
  });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Application running on http://localhost:${PORT}`);
});

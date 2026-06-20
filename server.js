// Run: npm init -y && npm i express jsonwebtoken bcryptjs swagger-ui-express cors dotenv
// Start: node server.js

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const swaggerUi = require('swagger-ui-express');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json()); // Parses JSON body from requests
app.use(cors()); // Allows frontend to call this API

// ===== MOCK DATABASE - No MongoDB needed for demo =====
let users = []; // Stores users
let accounts = []; // Stores bank accounts
let transactions = []; // Stores transfers

// ===== JWT SECRET - In real job, put in .env file =====
const JWT_SECRET = process.env.JWT_SECRET || 'sanjay-secret-key-2026';

// ===== SWAGGER DOCS SETUP - HR LOVES THIS =====
const swaggerDocument = {
  openapi: '3.0.0',
  info: {
    title: 'Sanjay Banking API',
    version: '1.0.0',
    description: 'Secure Banking API with JWT Auth. Built by Sanjay for portfolio.',
  },
  servers: [{ url: 'http://localhost:3000' }],
  components: {
    securitySchemes: {
      bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' }
    }
  },
  paths: {
    '/api/register': {
      post: {
        summary: 'Register new user',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', properties: { username: {type: 'string'}, password: {type: 'string'} } } } }
        },
        responses: { '201': { description: 'User created' } }
      }
    },
    '/api/login': {
      post: {
        summary: 'Login + Get JWT Token',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', properties: { username: {type: 'string'}, password: {type: 'string'} } } } }
        },
        responses: { '200': { description: 'JWT Token returned' } }
      }
    },
    '/api/balance': {
      get: {
        summary: 'Get account balance - JWT Required',
        security: [{ bearerAuth: [] }],
        responses: { '200': { description: 'Balance returned' }, '401': { description: 'No token' } }
      }
    },
    '/api/transfer': {
      post: {
        summary: 'Transfer money - JWT Required',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', properties: { to: {type: 'string'}, amount: {type: 'number'} } } } }
        },
        responses: { '200': { description: 'Transfer success' } }
      }
    }
  }
};

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// ===== MIDDLEWARE: CHECK JWT TOKEN =====
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', ''); // Get token from "Bearer xyz"
  if (!token) return res.status(401).json({ error: 'Access denied. No token.' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET); // Verify token is real
    req.user = decoded; // Save user data for next function
    next(); // Go to actual route
  } catch (ex) {
    res.status(400).json({ error: 'Invalid token.' });
  }
};

// ===== ROUTE 1: REGISTER =====
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  
  // Check if user exists
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'User already exists' });
  }
  
  // Hash password - Never store plain passwords
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { id: users.length + 1, username, password: hashedPassword };
  users.push(user);
  
  // Create bank account with ₹10,000 free money
  accounts.push({ userId: user.id, balance: 10000 });
  
  res.status(201).json({ message: 'User registered. ₹10,000 credited.' });
});

// ===== ROUTE 2: LOGIN =====
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  
  if (!user) return res.status(400).json({ error: 'Invalid username' });
  
  // Compare hashed password
  const validPass = await bcrypt.compare(password, user.password);
  if (!validPass) return res.status(400).json({ error: 'Invalid password' });
  
  // Create JWT Token - Valid for 1 hour
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, message: 'Login success. Use this token in Authorization header.' });
});

// ===== ROUTE 3: CHECK BALANCE - PROTECTED =====
app.get('/api/balance', authMiddleware, (req, res) => {
  const account = accounts.find(a => a.userId === req.user.id);
  res.json({ username: req.user.username, balance: account.balance });
});

// ===== ROUTE 4: TRANSFER MONEY - PROTECTED =====
app.post('/api/transfer', authMiddleware, (req, res) => {
  const { to, amount } = req.body;
  const fromAccount = accounts.find(a => a.userId === req.user.id);
  const toUser = users.find(u => u.username === to);
  
  if (!toUser) return res.status(400).json({ error: 'Receiver not found' });
  if (fromAccount.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
  
  const toAccount = accounts.find(a => a.userId === toUser.id);
  fromAccount.balance -= amount; // Deduct money
  toAccount.balance += amount; // Add money
  
  transactions.push({ from: req.user.username, to, amount, date: new Date() });
  res.json({ message: `₹${amount} transferred to ${to}`, newBalance: fromAccount.balance });
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Banking API running on port ${PORT}`);
  console.log(`Swagger Docs: http://localhost:${PORT}/api-docs`);
});

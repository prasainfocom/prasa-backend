const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const apiRoutes = require("./routes");
const mysql = require("mysql2");

// Load environment variables
dotenv.config();
const app = express();

// CORS middleware
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://prasa-main.vercel.app');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

app.use(cors({
  origin: [
    'http://localhost:5500',
    'http://127.0.0.1:5501',
    'https://prasa-main.vercel.app'
  ],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint that doesn't require database
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "Server is running" });
});

// Create a connection pool instead of a single connection
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: 25644,
  ssl: {
    rejectUnauthorized: false,
  },
  connectTimeout: 30000, // 30 seconds timeout
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Database connection test
app.get("/api/db-test", (req, res) => {
  pool.query("SELECT 1 as result", (err, results) => {
    if (err) {
      console.error("Database test failed:", err);
      return res.status(500).json({ 
        message: "Database connection failed", 
        error: err.message 
      });
    }
    res.json({ 
      status: "Database connection successful", 
      result: results[0] 
    });
  });
});

// Middleware to check database connection before proceeding
app.use((req, res, next) => {
  if (req.path.startsWith('/api') && req.path !== '/api/health' && req.path !== '/api/db-test') {
    pool.getConnection((err, connection) => {
      if (err) {
        console.error("Database connection error:", err);
        return res.status(503).json({ 
          message: "Database service temporarily unavailable", 
          error: err.message 
        });
      }
      // Release the connection back to the pool
      connection.release();
      next();
    });
  } else {
    next();
  }
});

// Mount API routes
app.use("/api", apiRoutes);

// API route for user profile
app.get("/api/profile/:email", (req, res) => {
  const email = req.params.email;
  
  const query = "SELECT * FROM user_data WHERE email = ?";
  pool.query(query, [email], (err, result) => {
    if (err) {
      console.error("Database error:", err);
      return res.status(500).json({ message: "Internal Server Error" });
    }
    if (result.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(result[0]);
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong!" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;
const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const apiRoutes = require("./routes");
const mysql = require("mysql2");

// Load environment variables
dotenv.config();
const app = express();



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



app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Database connection
const db = mysql.createConnection({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: 12464,
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed: " + err.message);
  } else {
    console.log("Connected to MySQL Database ✅");
    db.query("SHOW TABLES", (err, tables) => {
      if (err) {
        console.error("Error checking tables:", err);
      } else {
        console.log("Available tables:", tables.map(t => Object.values(t)[0]));
      }
    });
  }
});

// Test DB connection
db.query("SELECT 1", (err, result) => {
  if (err) {
    console.error("Database connection failed:", err);
  } else {
    console.log("Database connection successful");
  }
});

// Mount API routes
app.use("/api", apiRoutes);

// API route for user profile
app.get("/api/profile/:email", (req, res) => {
  const email = req.params.email;
  
  const query = "SELECT * FROM user_data WHERE email = ?";
  db.query(query, [email], (err, result) => {
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

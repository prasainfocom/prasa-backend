const mysql = require("mysql2");
const dotenv = require("dotenv");

dotenv.config();

const db = mysql.createConnection({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: 12464,
  ssl: {
    rejectUnauthorized: false, // Ensures SSL verification
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

module.exports = db;  
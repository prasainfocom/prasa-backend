
const jwt = require('jsonwebtoken');
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  console.log("Authorization header:", authHeader);
  console.log("Token extracted:", token);
  
  if (!token) {
    console.log("No token provided in request");
    return res.status(401).json({ message: "Access denied. No token provided." });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log("JWT verification error:", err);
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    
    console.log("Decoded JWT payload:", user);
    req.user = user;
    next();
  });
};

// In middleware.js, check that you have this at the end:
module.exports = { authenticateToken };
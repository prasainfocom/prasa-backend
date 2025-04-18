const express = require ("express");
const router = express.Router();
//const db = require("./config");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const controllers = require("./controllers");
const { authenticateToken } = require("./middleware");
const mysql = require("mysql2");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const db = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: 25644,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    rejectUnauthorized: false,
  },
});


db.getConnection((err, connection) => {
  if (err) {
    console.error("❌ DataB connection failed: hello hiii ", err.message);
  } else {
    console.log("✅ DB connected successfully");
    connection.release(); // release after testing
  }
});

// Use environment variable for consistency with other files
const SECRET_KEY = process.env.JWT_SECRET;

// 🔹 Register User
router.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    // Check if email already exists
    const checkQuery = "SELECT * FROM users WHERE email = ?";
    db.query(checkQuery, [email], async (err, results) => {
        console.log(err)
        if (err) return res.status(500).json({ message: "issues in regitration"});
        if (results.length > 0) return res.status(400).json({ message: "Email already registered" });

        // Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10);
        const insertQuery = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)";

        db.query(insertQuery, [username, email, hashedPassword], (err) => {
            if (err) return res.status(500).json({ message: "Error registering user" });
            res.json({ message: "User registered successfully!" });
        });
    });
});

// 🔹 Login User
router.post("/login", (req, res) => {
    const { email, password } = req.body;
    const query = "SELECT * FROM users WHERE email = ?";

    db.query(query, [email], async (err, results) => {
        if (err) return res.status(500).json({ message: err});
        if (results.length === 0) return res.status(401).json({ message: "Invalid email or password" });

        const user = results[0];

        // Compare hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: "Invalid email or password" });

        // Generate JWT token
        const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ token, email: user.email, message: "Login successful" });
    });
});

router.post("/forgot-password", (req, res) => {
    try {
        console.log('Request received with body:', req.body);
        
        // Safety check for missing body
        if (!req.body || typeof req.body !== 'object') {
            return res.status(400).json({ error: "Invalid request body" });
        }
        
        const email = req.body.email;
        console.log('Email extracted:', email);
        
        if (!email) {
            return res.status(400).json({ error: "Email is required" });
        }
        
        console.log('Processing reset request for email:', email);
        
        db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
            if (err) {
                console.log(err)
                return res.status(500).json({ error: err.message });
            }
            
            if (results.length === 0) {
                return res.status(404).json({ error: "User with this email does not exist." });
            }
            
            // Generate a random token
            const resetToken = crypto.randomBytes(20).toString('hex');
            const resetTokenExpiry = new Date(Date.now() + 3600000); // Token valid for 1 hour
            
            // Update user with the reset token
            db.query(
                "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE email = ?",
                [resetToken, resetTokenExpiry, email],
                (updateErr) => {
                    if (updateErr) {
                        console.error("Update error:", updateErr);
                        return res.status(500).json({ error: updateErr.message });
                    }
                    
                    try {
                        // Send password reset email
                        sendPasswordResetEmail(email, resetToken);
                        res.json({ message: "Password reset link sent to your email" });
                    } catch (emailErr) {
                        console.error("Email sending error:", emailErr);
                        res.status(500).json({ error: "Failed to send reset email" });
                    }
                }
            );
        });
    } catch (error) {
        console.error("General error in forgot-password route:", error);
        res.status(500).json({ error: "Internal server error" });
    }
});
// Reset password route
router.post("/reset-password", (req, res) => {
    const { token, newPassword } = req.body;
    
    // Find user with the provided token that hasn't expired
    db.query(
        "SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?",
        [token, new Date()],
        async (err, results) => {
          console.log(err)
          console.log(results)
            if (err) return res.status(500).json({ error: err.message });
            
            if (results.length === 0) {
                return res.status(400).json({ error: "Invalid or expired reset token" });
            }
            
            const user = results[0];
            
            // Hash the new password
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            
            // Update user's password and remove reset token
            db.query(
                "UPDATE users SET password = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?",
                [hashedPassword, user.id],
                (updateErr) => {
                    if (updateErr) return res.status(500).json({ error: updateErr.message });
                    
                    res.json({ message: "Password has been reset successfully" });
                }
            );
        }
    );
});

// Function to send password reset email
async function sendPasswordResetEmail(email, token) {
    try {
      console.log("jay ho")
        // Create a nodemailer transporter using Gmail
        const transporter = nodemailer.createTransport({
             host: 'smtp.gmail.com',
  port: 587, // use 587 (TLS), not 465 (SSL)
  secure: false, // TLS requires secure=false
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS  // Use App Password for Gmail
            }
        });
        
        // Reset password URL - pointing to your FRONTEND
        const resetUrl = `https://prasa-main.vercel.app/reset-password.html?token=${token}`;
        
        // Email options
        const mailOptions = {
            from: `"Password Reset" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset',
            html: `
                <h1>Password Reset Request</h1>
                <p>You requested a password reset. Click the link below to reset your password:</p>
                <a href="${resetUrl}" style="background-color: #4CAF50; color: white; padding: 10px 15px; text-decoration: none; border-radius: 5px;">Reset Password</a>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request this, please ignore this email.</p>
            `
        };
        console.log("hello")
        // Send email and wait for result
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent:'+email, info.response);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        return false;
    }
}

// 🔹 Submit User Form (Update or Insert)
router.post("/submit-form", authenticateToken, (req, res) => { 
    console.log("Form submission - Request body:", req.body);
    console.log("Form submission - User from token:", req.user);
    const email = req.user.email;
    console.log("Using email from token:", email);
    
    // Log the user info from token for debugging
    console.log("User from token:", req.user);
    
    const { 
        title, firstName, middleName, lastName, dob, age, address, phone, 
        aadharNo, city, state, country, pinCode, religion, nationality, 
        drivingLicenseNo, esicNo, panNo, passportNo, rationCardNo, 
        votingCardNo, uanNo,
        // New fields
        bankName, ifscCode, accountNo, bankBranch,
        maritalStatus, spouseName, children,
        dateOfJoining, department, designation, reportingTo, totalexperience
    } = req.body;
    
    // First verify the user exists in the users table
    const checkUserQuery = "SELECT * FROM users WHERE email = ?";
    console.log("Checking user existence with query:", checkUserQuery, "and email:", email);
    db.query(checkUserQuery, [email], (err, userResults) => {
        if (err) {
            console.error("Database error while checking user:", err);
            return res.status(500).json({ message: "Database error while checking user" });
        }
        
        console.log("User check results:", userResults);
        
        if (userResults.length === 0) {
            return res.status(404).json({ message: "User not found in users table" });
        }
        
        // Now check if user already has data in user_data table
        const checkDataQuery = "SELECT * FROM user_data WHERE email = ?";
        
        db.query(checkDataQuery, [email], (err, dataResults) => {
            if (err) {
                console.error("Database error while checking user data:", err);
                return res.status(500).json({ message: "Database error while checking user data" });
            }
            
            console.log("User data check results:", dataResults);

            // Create full name from components
            const fullName = `${title || ''} ${firstName || ''} ${middleName || ''} ${lastName || ''}`.trim();

            if (dataResults.length === 0) {
                // User not found in user_data: INSERT a new record
                console.log("Inserting new user data for:", email);
                const insertQuery = `INSERT INTO user_data 
                    (email, full_name, title, first_name, middle_name, last_name, dob, age, address, phone, 
                    aadhar_no, city, state, country, pin_code, religion, nationality, 
                    driving_license_no, esic_no, pan_no, passport_no, ration_card_no, 
                    voting_card_no, uan_no,
                    bankName, ifscCode, accountNo, bankBranch,
                    maritalStatus, spouseName, children,
                    dateOfJoining, department, designation, reportingTo, totalexperience) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

                db.query(insertQuery, [
                    email, fullName, title, firstName, middleName, lastName, dob, age, address, phone, 
                    aadharNo, city, state, country, pinCode, religion, nationality, 
                    drivingLicenseNo, esicNo, panNo, passportNo, rationCardNo, 
                    votingCardNo, uanNo,
                    bankName, ifscCode, accountNo, bankBranch,
                    maritalStatus, spouseName, children,
                    dateOfJoining, department, designation, reportingTo, totalexperience
                ], (err, insertResult) => {
                    if (err) {
                        console.error("Error inserting new user data:", err);
                        return res.status(500).json({ message: "Error inserting new user data" });
                    }
                    
                    console.log("Insert successful:", insertResult);
                    return res.status(201).json({ message: "User data created successfully!", nextStep: "family" });
                });
            } else {
                // User exists in user_data: UPDATE the record
                console.log("Updating existing user data for:", email);
                const updateQuery = `UPDATE user_data 
                    SET full_name = ?, title = ?, first_name = ?, middle_name = ?, last_name = ?, dob = ?, 
                        age = ?, address = ?, phone = ?, aadhar_no = ?, city = ?, state = ?, 
                        country = ?, pin_code = ?, religion = ?, nationality = ?, 
                        driving_license_no = ?, esic_no = ?, pan_no = ?, passport_no = ?, 
                        ration_card_no = ?, voting_card_no = ?, uan_no = ?,
                        bankName = ?, ifscCode= ?, accountNo= ?, bankBranch = ?,
                        maritalStatus = ?, spouseName = ?, children = ?,
                        dateOfJoining = ?, department = ?, designation = ?, reportingTo = ?, 
                        totalexperience = ?
                    WHERE email = ?`;
            
                db.query(updateQuery, [
                    fullName, title, firstName, middleName, lastName, dob, age, address, phone, 
                    aadharNo, city, state, country, pinCode, religion, nationality, 
                    drivingLicenseNo, esicNo, panNo, passportNo, rationCardNo, 
                    votingCardNo, uanNo,
                    // Use the camelCase variables from req.body:
                    bankName, ifscCode, accountNo, bankBranch,
                    maritalStatus, spouseName, children,
                    dateOfJoining, department, designation, reportingTo, totalexperience,
                    email  // Add the email parameter here
                ], (err, updateResult) => {
                    if (err) {
                        console.error("Error updating user data:", err);
                        return res.status(500).json({ message: "Error updating form" });
                    }
                    
                    console.log("Update successful:", updateResult);
                    res.json({ message: "Form updated successfully!", nextStep: "family" });
                });
            }
        });
    });
});

// 🔹 Submit Family Details
router.post("/submit-family", authenticateToken, (req, res) => {
    console.log("Family details submission - Request body:", req.body);
    console.log("Family details submission - User from token:", req.user);
    
    const email = req.user.email;
    const userId = req.user.id;
    
    // Extract all the family details from the request body
    const {
        nominee1_name, nominee1_relationship, nominee1_share,
        nominee2_name, nominee2_relationship, nominee2_share,
        emergency1_name, emergency1_relationship, emergency1_contact, emergency1_email,
        emergency2_name, emergency2_relationship, emergency2_contact, emergency2_email,
        family1_name, family1_dob, family1_relationship, family1_occupation, family1_aadhar,
        family2_name, family2_dob, family2_relationship, family2_occupation, family2_aadhar,
        family3_name, family3_dob, family3_relationship, family3_occupation, family3_aadhar,
        family4_name, family4_dob, family4_relationship, family4_occupation, family4_aadhar
    } = req.body;
    
    // First check if the user already has family details in the database
    const checkFamilyQuery = "SELECT * FROM family_details WHERE user_id = ?";
    
    db.query(checkFamilyQuery, [userId], (err, familyResults) => {
        if (err) {
            console.error("Database error while checking family details:", err);
            return res.status(500).json({ message: "Database error while checking family details" });
        }
        
        console.log("Family details check results:", familyResults);
        
        if (familyResults.length === 0) {
            // User doesn't have family details yet: INSERT a new record
            console.log("Inserting new family details for user ID:", userId);
            const insertQuery = `INSERT INTO family_details 
                (user_id, nominee1_name, nominee1_relationship, nominee1_share, 
                nominee2_name, nominee2_relationship, nominee2_share, 
                emergency1_name, emergency1_relationship, emergency1_contact, emergency1_email, 
                emergency2_name, emergency2_relationship, emergency2_contact, emergency2_email, 
                family1_name, family1_dob, family1_relationship, family1_occupation, family1_aadhar, 
                family2_name, family2_dob, family2_relationship, family2_occupation, family2_aadhar, 
                family3_name, family3_dob, family3_relationship, family3_occupation, family3_aadhar, 
                family4_name, family4_dob, family4_relationship, family4_occupation, family4_aadhar) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
            
            db.query(insertQuery, [
                userId, 
                nominee1_name, nominee1_relationship, nominee1_share,
                nominee2_name || null, nominee2_relationship || null, nominee2_share || null,
                emergency1_name, emergency1_relationship, emergency1_contact, emergency1_email,
                emergency2_name || null, emergency2_relationship || null, emergency2_contact || null, emergency2_email || null,
                family1_name, family1_dob, family1_relationship, family1_occupation, family1_aadhar,
                family2_name || null, family2_dob || null, family2_relationship || null, family2_occupation || null, family2_aadhar || null,
                family3_name || null, family3_dob || null, family3_relationship || null, family3_occupation || null, family3_aadhar || null,
                family4_name || null, family4_dob || null, family4_relationship || null, family4_occupation || null, family4_aadhar || null
            ], (err, insertResult) => {
                if (err) {
                    console.error("Error inserting family details:", err);
                    return res.status(500).json({ message: "Error inserting family details: " + err.message });
                }
                
                console.log("Family details insert successful:", insertResult);
                return res.status(201).json({ message: "Family details saved successfully!", nextStep: "experience" });
            });
        } else {
            // User already has family details: UPDATE the record
            console.log("Updating existing family details for user ID:", userId);
            const updateQuery = `UPDATE family_details 
                SET nominee1_name = ?, nominee1_relationship = ?, nominee1_share = ?, 
                    nominee2_name = ?, nominee2_relationship = ?, nominee2_share = ?, 
                    emergency1_name = ?, emergency1_relationship = ?, emergency1_contact = ?, emergency1_email = ?, 
                    emergency2_name = ?, emergency2_relationship = ?, emergency2_contact = ?, emergency2_email = ?, 
                    family1_name = ?, family1_dob = ?, family1_relationship = ?, family1_occupation = ?, family1_aadhar = ?, 
                    family2_name = ?, family2_dob = ?, family2_relationship = ?, family2_occupation = ?, family2_aadhar = ?, 
                    family3_name = ?, family3_dob = ?, family3_relationship = ?, family3_occupation = ?, family3_aadhar = ?, 
                    family4_name = ?, family4_dob = ?, family4_relationship = ?, family4_occupation = ?, family4_aadhar = ? 
                WHERE user_id = ?`;
            
            db.query(updateQuery, [
                nominee1_name, nominee1_relationship, nominee1_share,
                nominee2_name || null, nominee2_relationship || null, nominee2_share || null,
                emergency1_name, emergency1_relationship, emergency1_contact, emergency1_email,
                emergency2_name || null, emergency2_relationship || null, emergency2_contact || null, emergency2_email || null,
                family1_name, family1_dob, family1_relationship, family1_occupation, family1_aadhar,
                family2_name || null, family2_dob || null, family2_relationship || null, family2_occupation || null, family2_aadhar || null,
                family3_name || null, family3_dob || null, family3_relationship || null, family3_occupation || null, family3_aadhar || null,
                family4_name || null, family4_dob || null, family4_relationship || null, family4_occupation || null, family4_aadhar || null,
                userId
            ], (err, updateResult) => {
                if (err) {
                    console.error("Error updating family details:", err);
                    return res.status(500).json({ message: "Error updating family details: " + err.message });
                }
                
                console.log("Family details update successful:", updateResult);
                res.json({ message: "Family details updated successfully!", nextStep: "experience" });
            });
        }
    });
});

// 🔹 Submit Experience Form
router.post("/submit-experience", authenticateToken, (req, res) => {
    console.log("Experience form submission - Request body:", req.body);
    const email = req.user.email;
    
    // Validate required fields
    if (!req.body || (!req.body.company && !Array.isArray(req.body.company))) {
        return res.status(400).json({ message: "Invalid request data" });
    }
    
    const { company, fromDate, toDate, designation, reasonForLeaving, achievements, kraHandle, teamSize, contactDetails } = req.body;
    
    // First delete existing experiences for this user
    const deleteQuery = "DELETE FROM user_experiences WHERE email = ?";
    
    db.query(deleteQuery, [email], (err) => {
        if (err) {
            console.error("Error deleting existing experiences:", err);
            return res.status(500).json({ message: "Error processing experience data: " + err.message });
        }

        // Check if we have arrays of experience data
        if (Array.isArray(company) && company.length > 0) {
            // Multiple experiences
            let insertedCount = 0;
            let errorOccurred = false;
            
            for (let i = 0; i < company.length; i++) {
                // Skip empty entries
                if (!company[i]) continue;
                
                const insertQuery = `INSERT INTO user_experiences 
                    (email, company, from_date, to_date, designation, reason_for_leaving, achievements, kra_handle, team_size, contact_details) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

                db.query(insertQuery, [
                    email, 
                    company[i],
                    fromDate[i] || null,
                    toDate[i] || null,
                    designation[i] || null,
                    reasonForLeaving[i] || null,
                    achievements[i] || null,
                    kraHandle[i] || null,
                    teamSize[i] || null,
                    contactDetails[i] || null
                ], (err, result) => {
                    if (err) {
                        console.error(`Error inserting experience #${i}:`, err);
                        errorOccurred = true;
                    } else {
                        insertedCount++;
                    }
                    
                    // If this is the last insertion, send the response
                    if (i === company.length - 1) {
                        if (errorOccurred) {
                            res.status(500).json({ message: "Error saving some experience data" });
                        } else {
                            res.json({ message: `${insertedCount} experience entries saved successfully!`, nextStep: "qualification" });
                        }
                    }
                });
            }
            
            // Handle case where no entries were submitted (all were empty)
            if (company.length === 0) {
                res.json({ message: "No experience data provided, moving to next step", nextStep: "qualification" });
            }
        } else if (company) {
            // Single experience
            const insertQuery = `INSERT INTO user_experiences 
                (email, company, from_date, to_date, designation, reason_for_leaving, achievements, kra_handle, team_size, contact_details) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

            db.query(insertQuery, [
                email, 
                company,
                fromDate || null,
                toDate || null,
                designation || null,
                reasonForLeaving || null,
                achievements || null,
                kraHandle || null,
                teamSize || null,
                contactDetails || null
            ], (err, result) => {
                if (err) {
                    console.error("Error inserting experience:", err);
                    return res.status(500).json({ message: "Error saving experience data: " + err.message });
                }
                
                res.json({ message: "Experience data saved successfully!", nextStep: "qualification" });
            });
        } else {
            // No experience data provided
            res.json({ message: "No experience data provided, moving to next step", nextStep: "qualification" });
        }
    });
});

router.post("/submit-qualification", authenticateToken, async (req, res) => {
  console.log("Qualification form submission - Request body:", req.body);
  const email = req.user.email;

  const {
    educationType, eduFromDate, eduToDate, instituteName, specialization,
    nacAccretion, boardUniversity, eduType, score, status, proofsSubmitted,
    skills, certificationName, certFromDate, certToDate
  } = req.body;

  try {
    // 1. Delete existing qualifications, certifications, and skills
    await queryPromise("DELETE FROM user_qualifications WHERE email = ?", [email]);
    await queryPromise("DELETE FROM user_certifications WHERE email = ?", [email]);
    await queryPromise("DELETE FROM user_skills WHERE email = ?", [email]);

    // 2. Insert qualifications
    if (Array.isArray(educationType)) {
      for (let i = 0; i < educationType.length; i++) {
        await queryPromise(
          `INSERT INTO user_qualifications
          (email, education_type, from_date, to_date, institute_name, specialization,
          nac_accretion, board_university, edu_type, score, status, proofs_submitted)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [
            email, educationType[i], eduFromDate[i], eduToDate[i], instituteName[i],
            specialization[i] || null, nacAccretion[i] || null, boardUniversity[i],
            eduType[i], score[i], status[i], proofsSubmitted[i]
          ]
        );
      }
    } else if (educationType) {
      await queryPromise(
        `INSERT INTO user_qualifications
        (email, education_type, from_date, to_date, institute_name, specialization,
        nac_accretion, board_university, edu_type, score, status, proofs_submitted)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          email, educationType, eduFromDate, eduToDate, instituteName,
          specialization || null, nacAccretion || null, boardUniversity,
          eduType, score, status, proofsSubmitted
        ]
      );
    }

    // 3. Insert skills if provided
    if (skills) {
      await queryPromise(
        "INSERT INTO user_skills (email, skills) VALUES (?, ?)",
        [email, skills]
      );
    }

    // 4. Insert certifications
    if (Array.isArray(certificationName)) {
      for (let i = 0; i < certificationName.length; i++) {
        if (certificationName[i]) {
          await queryPromise(
            "INSERT INTO user_certifications (email, certification_name, from_date, to_date) VALUES (?, ?, ?, ?)",
            [email, certificationName[i], certFromDate[i] || null, certToDate[i] || null]
          );
        }
      }
    } else if (certificationName) {
      await queryPromise(
        "INSERT INTO user_certifications (email, certification_name, from_date, to_date) VALUES (?, ?, ?, ?)",
        [email, certificationName, certFromDate || null, certToDate || null]
      );
    }

    res.json({ message: "All Data Saved Successfully!" });

  } catch (error) {
    console.error("❌ Error in qualification submission:", error);
    res.status(500).json({ message: "Error saving qualification data" });
  }

  // ✅ Helper for promise-based DB calls
  function queryPromise(sql, params) {
    return new Promise((resolve, reject) => {
      db.query(sql, params, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    });
  }
});

router.post("/submit-medical-info", authenticateToken, (req, res) => {
    console.log("Medical info submission - Request body:", req.body);
    const userId = req.user.id;
    const email = req.user.email;

    // Convert and validate numeric fields
    const height_cm = req.body.height_cm ? parseFloat(req.body.height_cm) : null;
    const weight_kg = req.body.weight_kg ? parseFloat(req.body.weight_kg) : null;
    
    // Convert radio button values to proper boolean (1/0) for database
    const handicap = req.body.handicap === 'Yes' ? 1 : 0;
    const is_allergic = req.body.is_allergic === 'Yes' ? 1 : 0;
    const has_medical_ailment = req.body.has_medical_ailment === 'Yes' ? 1 : 0;
    const operation_last_year = req.body.operation_last_year === 'Yes' ? 1 : 0;
    const operation_before_year = req.body.operation_before_year === 'Yes' ? 1 : 0;
    const is_asthmatic = req.body.is_asthmatic === 'Yes' ? 1 : 0;
    const has_heart_problem = req.body.has_heart_problem === 'Yes' ? 1 : 0;
    const is_diabetic = req.body.is_diabetic === 'Yes' ? 1 : 0;
    const had_stress_test = req.body.had_stress_test === 'Yes' ? 1 : 0;
    const had_mental_health_screening = req.body.had_mental_health_screening === 'Yes' ? 1 : 0;
    const had_fatal_accident = req.body.had_fatal_accident === 'Yes' ? 1 : 0;
    const has_eyesight_issue = req.body.has_eyesight_issue === 'Yes' ? 1 : 0;
    const has_hearing_issue = req.body.has_hearing_issue === 'Yes' ? 1 : 0;
    const is_smoker = req.body.is_smoker === 'Yes' ? 1 : 0;
    const consumes_alcohol = req.body.consumes_alcohol === 'Yes' ? 1 : 0;
    const exercises_regularly = req.body.exercises_regularly === 'Yes' ? 1 : 0;

    // Validate required fields
    if (!height_cm || !weight_kg || !req.body.blood_group || 
        !req.body.emergency_contact_name || !req.body.emergency_contact_phone) {
        return res.status(400).json({ 
            message: "Missing required fields",
            requiredFields: ["height_cm", "weight_kg", "blood_group", 
                           "emergency_contact_name", "emergency_contact_phone"]
        });
    }

    const checkQuery = "SELECT * FROM health_info WHERE email = ?";
    
    db.query(checkQuery, [email], (err, results) => {
        if (err) {
            console.error("Database check error:", err);
            return res.status(500).json({ 
                message: "Database error",
                error: err.message 
            });
        }
        
        if (results.length === 0) {
            // Insert new medical info
            const insertQuery = `INSERT INTO health_info SET ?`;
            const medicalData = {
                email,
                height_cm,
                weight_kg,
                blood_group: req.body.blood_group,
                handicap,
                is_allergic,
                allergic_details: req.body.allergic_details || null,
                has_medical_ailment,
                medical_ailment_details: req.body.medical_ailment_details || null,
                operation_last_year,
                operation_last_year_details: req.body.operation_last_year_details || null,
                operation_before_year,
                operation_before_year_details: req.body.operation_before_year_details || null,
                is_asthmatic,
                blood_pressure: req.body.blood_pressure || null,
                has_heart_problem,
                is_diabetic,
               // sugar_check_frequency: req.body.sugar_check_frequency || null,
                had_stress_test,
                stress_test_details: req.body.stress_test_details || null,
                had_mental_health_screening,
                mental_health_details: req.body.mental_health_details || null,
                had_fatal_accident,
                fatal_accident_details: req.body.fatal_accident_details || null,
                has_eyesight_issue,
                has_hearing_issue,
                is_smoker,
                smoking_frequency: req.body.smoking_frequency || null,
                consumes_alcohol,
                alcohol_frequency: req.body.alcohol_frequency || null,
                exercises_regularly,
                exercise_frequency: req.body.exercise_frequency || null,
                emergency_contact_name: req.body.emergency_contact_name,
                emergency_contact_phone: req.body.emergency_contact_phone,
                emergency_contact_relation: req.body.emergency_contact_relation || null
            };

            db.query(insertQuery, medicalData, (err, result) => {
                if (err) {
                    console.error("Insert error:", err);
                    return res.status(500).json({ 
                        message: "Error inserting medical info",
                        error: err.message,
                        sql: err.sql 
                    });
                }
                res.json({ 
                    message: "Medical info saved successfully", 
                    nextStep: "profile",
                    insertedId: result.insertId 
                });
            });
        } else {
            // Update existing medical info
            const updateQuery = `UPDATE health_info SET ? WHERE email = ?`;
            const medicalData = {
                height_cm,
                weight_kg,
                blood_group: req.body.blood_group,
                handicap,
                is_allergic,
                allergic_details: req.body.allergic_details || null,
                has_medical_ailment,
                medical_ailment_details: req.body.medical_ailment_details || null,
                operation_last_year,
                operation_last_year_details: req.body.operation_last_year_details || null,
                operation_before_year,
                operation_before_year_details: req.body.operation_before_year_details || null,
                is_asthmatic,
                blood_pressure: req.body.blood_pressure || null,
                has_heart_problem,
                is_diabetic,
                sugar_check_frequency: req.body.sugar_check_frequency || null,
                had_stress_test,
                stress_test_details: req.body.stress_test_details || null,
                had_mental_health_screening,
                mental_health_details: req.body.mental_health_details || null,
                had_fatal_accident,
                fatal_accident_details: req.body.fatal_accident_details || null,
                has_eyesight_issue,
                has_hearing_issue,
                is_smoker,
                smoking_frequency: req.body.smoking_frequency || null,
                consumes_alcohol,
                alcohol_frequency: req.body.alcohol_frequency || null,
                exercises_regularly,
                exercise_frequency: req.body.exercise_frequency || null,
                emergency_contact_name: req.body.emergency_contact_name,
                emergency_contact_phone: req.body.emergency_contact_phone,
                emergency_contact_relation: req.body.emergency_contact_relation || null
            };

            db.query(updateQuery, [medicalData, email], (err, result) => {
                if (err) {
                    console.error("Update error:", err);
                    return res.status(500).json({ 
                        message: "Error updating medical info",
                        error: err.message,
                        sql: err.sql 
                    });
                }
                res.json({ 
                    message: "Medical info updated successfully", 
                    nextStep: "profile",
                    affectedRows: result.affectedRows 
                });
            });
        }
    });
});


// 🔹 Get User Data (for pre-filling forms)
router.get("/user-data", authenticateToken, (req, res) => {
    const email = req.user.email;
    const userId = req.user.id;
    
    console.log("Running from query where email",email);
    // Get user personal data
    db.query("SELECT * FROM user_data WHERE email = ?", [email], (err, userData) => {
        if (err) return res.status(500).json({ message: "Database error" });
        
        // Get user family details
        db.query("SELECT * FROM family_details WHERE user_id = ?", [userId], (err, familyData) => {
            if (err) return res.status(500).json({ message: "Database error" });

            // Get user experience data
            db.query("SELECT * FROM user_experiences WHERE email = ?", [email], (err, experienceData) => {
                if (err) return res.status(500).json({ message: "Database error" });

                // Get user qualification data
                db.query("SELECT * FROM user_qualifications WHERE email = ?", [email], (err, qualificationData) => {
                    if (err) return res.status(500).json({ message: "Database error" });

                    // Get user certification data
                    db.query("SELECT * FROM user_certifications WHERE email = ?", [email], (err, certificationData) => {
                        if (err) return res.status(500).json({ message: "Database error" });

                        // Get user skills data
                        db.query("SELECT * FROM user_skills WHERE email = ?", [email], (err, skillsData) => {
                            if (err) return res.status(500).json({ message: "Database error" });

                            // Get user medical information
                            db.query("SELECT * FROM health_info WHERE email = ?", [email], (err, medicalData) => {
                                if (err) return res.status(500).json({ message: "Database error" });

                                res.json({
                                    userData: userData[0] || null,
                                    familyData: familyData[0] || null,
                                    experiences: experienceData || [],
                                    qualifications: qualificationData || [],
                                    certifications: certificationData || [],
                                    skills: skillsData[0]?.skills || "",
                                    medicalInfo: medicalData[0] || null // Include medical data
                                });
                            });
                        });
                    });
                });
            });
        });
    });
});

router.get("/profile/:email", authenticateToken, (req, res) => {
    const email = req.params.email;

    const query = `
        SELECT full_name, email, phone, address, dob, age, city, state, country, nationality, 
               aadhar_no, pan_no, passport_no, bankName, accountNo, department, designation 
        FROM user_data WHERE email = ?`;

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

module.exports = router;

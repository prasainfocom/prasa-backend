const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./config");

// User Registration
const register = (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  db.query(
    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
    [username, email, hashedPassword],
    (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "User registered successfully!" });
    }
  );
};

// User Login
const login = (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, users) => {
    if (err) return res.status(500).json({ error: err.message });

    if (users.length === 0) return res.status(401).json({ error: "User not found" });

    const user = users[0];
    if (!bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: "Incorrect password" });

    // Include user ID in token
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ message: "Login successful!", token, email: user.email });
  });
};

const crypto = require('crypto');
const nodemailer = require('nodemailer');
const forgotPassword = (req, res) => {
  const { email } = req.body;
  
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, users) => {
      if (err) return res.status(500).json({ error: err.message });
      
      if (users.length === 0) {
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
              if (updateErr) return res.status(500).json({ error: updateErr.message });
              
              // Send password reset email
              sendPasswordResetEmail(email, resetToken);
              
              res.json({ message: "Password reset link sent to your email" });
          }
      );
  });
};
const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  
  // Find user with the provided token that hasn't expired
  db.query(
      "SELECT * FROM users WHERE reset_token = ? AND reset_token_expiry > ?",
      [token, new Date()],
      async (err, users) => {
          if (err) return res.status(500).json({ error: err.message });
          
          if (users.length === 0) {
              return res.status(400).json({ error: "Invalid or expired reset token" });
          }
          
          const user = users[0];
          
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
};
const sendPasswordResetEmail = async (email, token) => {
  try {
    // Create a nodemailer transporter using Gmail
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,  // Set up environment variables for email credentials
        pass: process.env.EMAIL_PASS
      }
    });
    
    // Use the frontend URL, not backend
    const resetUrl = `https://prasa-main.app/api/reset-password.html?token=${token}`;
    
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
    
    // Send email and wait for result
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.response);
    return true;
  } catch (error) {
    console.error('Error sending email:', error);
    throw error; // Re-throw to handle in the controller
  }
};

// Updated Form Submission to include all personal information fields
const submitForm = (req, res) => {
  const userId = req.user.id;
  const email = req.user.email;
  
  // Personal Information
  const { 
    title, firstName, middleName, lastName, dob, age, address, phone,
    
    // Temporary Address
    city, state, pinCode, country,
    
    // Other Details
    nationality, religion, aadharNo, drivingLicenseNo, panNo, passportNo, 
    votingCardNo, rationCardNo, uanNo, esicNo,
    
    // Bank Details
    bankName, ifscCode, accountNo, bankBranch,
    
    // Family Details
    maritalStatus, spouseName, children,
    
    // Joining Details
    dateOfJoining, department, designation, reportingTo, totalexperience
  } = req.body;

  // SQL query to insert all personal information
  const query = `
    INSERT INTO user_personal_info (
      user_id, email, title, first_name, middle_name, last_name, dob, age, address, phone,
      city, state, pin_code, country, nationality, religion, aadhar_no, driving_license_no,
      pan_no, passport_no, voting_card_no, ration_card_no, uan_no, esic_no,
      bankName, ifscCode, accountNo, bankBranch,
      maritalStatus, spouseName, children,
      dateOfJoining, department, designation, reportingTo, totalexperience
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      title = VALUES(title),
      first_name = VALUES(first_name),
      middle_name = VALUES(middle_name),
      last_name = VALUES(last_name),
      dob = VALUES(dob),
      age = VALUES(age),
      address = VALUES(address),
      phone = VALUES(phone),
      city = VALUES(city),
      state = VALUES(state),
      pin_code = VALUES(pin_code),
      country = VALUES(country),
      nationality = VALUES(nationality),
      religion = VALUES(religion),
      aadhar_no = VALUES(aadhar_no),
      driving_license_no = VALUES(driving_license_no),
      pan_no = VALUES(pan_no),
      passport_no = VALUES(passport_no),
      voting_card_no = VALUES(voting_card_no),
      ration_card_no = VALUES(ration_card_no),
      uan_no = VALUES(uan_no),
      esic_no = VALUES(esic_no),
      bankName = VALUES(bankName),
      ifscCode = VALUES(ifscCode),
      accountNo = VALUES(accountNo),
      bankBranch = VALUES(bankBranch),
      maritalStatus = VALUES(maritalStatus),
      spouseName = VALUES(spouseName),
      children = VALUES(children),
      dateOfJoining = VALUES(dateOfJoining),
      department = VALUES(department),
      designation = VALUES(designation),
      reportingTo = VALUES(reporting_to),
      totalexperience = VALUES(totalexperience)
  `;

  db.query(
    query,
    [
      userId, email, title, firstName, middleName, lastName, dob, age, address, phone,
      city, state, pinCode, country, nationality, religion, aadharNo, drivingLicenseNo,
      panNo, passportNo, votingCardNo, rationCardNo, uanNo, esicNo,
      bankName, ifscCode, accountNo, bankBranch,
      maritalStatus, spouseName, children,
      dateOfJoining, department, designation, reportingTo, totalexperience
    ],
    (err, result) => {
      if (err) {
        console.error("Error submitting personal information form:", err);
        return res.status(500).json({ error: err.message });
      }
      res.json({ 
        message: "Personal information submitted successfully!",
        nextStep: "family"
      });
    }
  );
};

// Submit Family Details
const submitFamilyDetails = (req, res) => {
  const userId = req.user.id;
  const {
    // Nominee Details
    nominee1Name, nominee1Relationship, nominee1Share,
    nominee2Name, nominee2Relationship, nominee2Share,
    
    // Emergency Contact Details
    emergency1Name, emergency1Relationship, emergency1Contact, emergency1Email,
    emergency2Name, emergency2Relationship, emergency2Contact, emergency2Email,
    
    // Family Members
    family1Name, family1DOB, family1Relationship, family1Occupation, family1Aadhar,
    family2Name, family2DOB, family2Relationship, family2Occupation, family2Aadhar,
    family3Name, family3DOB, family3Relationship, family3Occupation, family3Aadhar,
    family4Name, family4DOB, family4Relationship, family4Occupation, family4Aadhar
  } = req.body;

  // First check if the user already has family details
  const checkQuery = "SELECT * FROM family_details WHERE user_id = ?";
  
  db.query(checkQuery, [userId], (err, results) => {
    if (err) {
      console.error("Error checking for existing family details:", err);
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length > 0) {
      // Update existing record
      const updateQuery = `
        UPDATE family_details SET
          nominee1_name = ?, nominee1_relationship = ?, nominee1_share = ?,
          nominee2_name = ?, nominee2_relationship = ?, nominee2_share = ?,
          emergency1_name = ?, emergency1_relationship = ?, emergency1_contact = ?, emergency1_email = ?,
          emergency2_name = ?, emergency2_relationship = ?, emergency2_contact = ?, emergency2_email = ?,
          family1_name = ?, family1_dob = ?, family1_relationship = ?, family1_occupation = ?, family1_aadhar = ?,
          family2_name = ?, family2_dob = ?, family2_relationship = ?, family2_occupation = ?, family2_aadhar = ?,
          family3_name = ?, family3_dob = ?, family3_relationship = ?, family3_occupation = ?, family3_aadhar = ?,
          family4_name = ?, family4_dob = ?, family4_relationship = ?, family4_occupation = ?, family4_aadhar = ?
        WHERE user_id = ?
      `;
      
      db.query(
        updateQuery,
        [
          nominee1Name, nominee1Relationship, nominee1Share,
          nominee2Name || null, nominee2Relationship || null, nominee2Share || null,
          emergency1Name, emergency1Relationship, emergency1Contact, emergency1Email,
          emergency2Name || null, emergency2Relationship || null, emergency2Contact || null, emergency2Email || null,
          family1Name, family1DOB, family1Relationship, family1Occupation, family1Aadhar,
          family2Name || null, family2DOB || null, family2Relationship || null, family2Occupation || null, family2Aadhar || null,
          family3Name || null, family3DOB || null, family3Relationship || null, family3Occupation || null, family3Aadhar || null,
          family4Name || null, family4DOB || null, family4Relationship || null, family4Occupation || null, family4Aadhar || null,
          userId
        ],
        (err, result) => {
          if (err) {
            console.error("Error updating family details:", err);
            return res.status(500).json({ error: err.message });
          }
          res.json({ message: "Family details updated successfully!" });
        }
      );
    } else {
      // Insert new record
      const insertQuery = `
        INSERT INTO family_details (
          user_id, nominee1_name, nominee1_relationship, nominee1_share,
          nominee2_name, nominee2_relationship, nominee2_share,
          emergency1_name, emergency1_relationship, emergency1_contact, emergency1_email,
          emergency2_name, emergency2_relationship, emergency2_contact, emergency2_email,
          family1_name, family1_dob, family1_relationship, family1_occupation, family1_aadhar,
          family2_name, family2_dob, family2_relationship, family2_occupation, family2_aadhar,
          family3_name, family3_dob, family3_relationship, family3_occupation, family3_aadhar,
          family4_name, family4_dob, family4_relationship, family4_occupation, family4_aadhar
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;
      
      db.query(
        insertQuery,
        [
          userId, nominee1Name, nominee1Relationship, nominee1Share,
          nominee2Name || null, nominee2Relationship || null, nominee2Share || null,
          emergency1Name, emergency1Relationship, emergency1Contact, emergency1Email,
          emergency2Name || null, emergency2Relationship || null, emergency2Contact || null, emergency2Email || null,
          family1Name, family1DOB, family1Relationship, family1Occupation, family1Aadhar,
          family2Name || null, family2DOB || null, family2Relationship || null, family2Occupation || null, family2Aadhar || null,
          family3Name || null, family3DOB || null, family3Relationship || null, family3Occupation || null, family3Aadhar || null,
          family4Name || null, family4DOB || null, family4Relationship || null, family4Occupation || null, family4Aadhar || null
        ],
        (err, result) => {
          if (err) {
            console.error("Error inserting family details:", err);
            return res.status(500).json({ error: err.message });
          }
          res.json({ message: "Family details submitted successfully!" });
          nextStep: "experience" 
        }
      );
    }
  });
};

// Experience Submission
const submitExperience = (req, res) => {
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
};

// Submit Qualification and Skills
const submitQualification = (req, res) => {
  console.log("Qualification form submission - Request body:", req.body);
  const email = req.user.email;
  
  const { 
    educationType, eduFromDate, eduToDate, instituteName, specialization, 
    nacAccretion, boardUniversity, eduType, score, status, proofsSubmitted,
    skills, certificationName, certFromDate, certToDate
  } = req.body;
  
  // Start a transaction to ensure all data is saved or nothing is saved
  db.beginTransaction(async err => {
    if (err) {
      console.error("Error starting transaction:", err);
      return res.status(500).json({ message: "Database error" });
    }
    
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
      
      // Commit the transaction
      db.commit(err => {
        if (err) {
          console.error("Error committing transaction:", err);
          return db.rollback(() => {
            res.status(500).json({ message: "Error saving qualification data" });
          });
        }
        
        res.json({ message: "All data saved successfully! Your profile is complete." });
      });
      
    } catch (error) {
      console.error("Error in qualification submission:", error);
      db.rollback(() => {
        res.status(500).json({ message: "Error saving qualification data" });
      });
    }
  });
  
  // Helper function to promisify database queries
  function queryPromise(sql, params) {
    return new Promise((resolve, reject) => {
      db.query(sql, params, (err, result) => {
        if (err) reject(err);
        else resolve(result);
      });
    });
  }
};

// Get Family Details
const getFamilyDetails = (req, res) => {
  const userId = req.user.id;
  
  db.query("SELECT * FROM family_details WHERE user_id = ?", [userId], (err, results) => {
    if (err) {
      console.error("Error retrieving family details:", err);
      return res.status(500).json({ error: err.message });
    }
    
    if (results.length === 0) {
      return res.json({ message: "No family details found", data: null });
    }
    
    res.json({ message: "Family details retrieved successfully", data: results[0] });
  });
};

const submitMedicalInfo = (req, res) => {
  const userId = req.user.id;
  const email = req.user.email; 

  // Convert and validate input data
  const height_cm = req.body.height_cm ? parseFloat(req.body.height_cm) : null;
  const weight_kg = req.body.weight_kg ? parseFloat(req.body.weight_kg) : null;
  
  // Convert radio button values to proper database values (1/0)
  const convertRadioValue = (value) => value === 'Yes' ? 1 : 0;
  
  const handicap = convertRadioValue(req.body.handicap);
  const is_allergic = convertRadioValue(req.body.is_allergic);
  const has_medical_ailment = convertRadioValue(req.body.has_medical_ailment);
  const operation_last_year = convertRadioValue(req.body.operation_last_year);
  const operation_before_year = convertRadioValue(req.body.operation_before_year);
  const is_asthmatic = convertRadioValue(req.body.is_asthmatic);
  const has_heart_problem = convertRadioValue(req.body.has_heart_problem);
  const is_diabetic = convertRadioValue(req.body.is_diabetic);
  const had_stress_test = convertRadioValue(req.body.had_stress_test);
  const had_mental_health_screening = convertRadioValue(req.body.had_mental_health_screening);
  const had_fatal_accident = convertRadioValue(req.body.had_fatal_accident);
  const has_eyesight_issue = convertRadioValue(req.body.has_eyesight_issue);
  const has_hearing_issue = convertRadioValue(req.body.has_hearing_issue);
  const is_smoker = convertRadioValue(req.body.is_smoker);
  const consumes_alcohol = convertRadioValue(req.body.consumes_alcohol);
  const exercises_regularly = convertRadioValue(req.body.exercises_regularly);

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
};

module.exports = { 
  register, 
  login, 
  submitForm, 
  submitExperience, 
  submitQualification, 
  submitFamilyDetails, 
  getFamilyDetails ,
  submitMedicalInfo,
  resetPassword
};


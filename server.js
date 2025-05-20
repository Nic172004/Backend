require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const CryptoJS = require('crypto-js');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 3000;
const SALT_ROUNDS = 10; // For bcrypt password hashing

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, 'profile-' + uniqueSuffix + ext);
  }
});

// Create multer upload instance
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: function(req, file, cb) {
    // Accept images only
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/i)) {
      return cb(new Error('Only image files are allowed!'), false);
    }
    cb(null, true);
  }
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// MongoDB Connection with retry functionality
let connectionAttempts = 0;
const maxRetries = 3;

// For date parsing
const months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];

// MongoDB Connection URL - Using the exact provided connection string
const MONGODB_URI = 'mongodb+srv://markbalilahon12:mDbDpzhffzE9Xzp2@cluster0.8kfpmtp.mongodb.net/clinq?retryWrites=true&w=majority&appName=Cluster0';

// Define MongoDB Schemas and Models
const studentSchema = new mongoose.Schema({
  fname: { type: String, required: true },
  lname: { type: String, required: true },
  student_id: { type: String, required: true, unique: true },
  university_email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  pnumber: { type: String },
  birthdate: { type: String },
  agreed_to_terms: { type: String, default: 'agree' },
  created_at: { type: Date, default: Date.now },
  // Medical information
  medical_info: {
    allergies: { type: String, default: '' },
    current_medications: { type: String, default: '' },
    medical_conditions: { type: String, default: '' }
  },
  isActive: { type: Boolean, default: true },
  profileImageUrl: { type: String }
});

// Admin Schema
const adminSchema = new mongoose.Schema({
  fname: { type: String, required: true },
  lname: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  is_super_admin: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now }
});

// Appointment Schema
const appointmentSchema = new mongoose.Schema({
  student: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Student',
    required: true 
  },
  doctor: {
    id: { type: mongoose.Schema.Types.ObjectId, ref: 'Doctor', required: true },
    name: { type: String, required: true },
    specialty: { type: String, required: true }
  },
  type: { type: String, required: true },
  dateTime: { type: String, required: true },
  notes: { type: String, default: '' },
  status: { 
    type: String, 
    enum: ['Confirmed', 'Pending', 'Cancelled', 'In Progress', 'Completed', 'Archived'],
    default: 'Pending'
  },
  queueNumber: { type: Number },
  formattedQueueNumber: { type: String },
  created_at: { type: Date, default: Date.now },
  archived: { type: Boolean, default: false }
});

// Doctor Schema
const doctorSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phoneNumber: { type: String, required: true },
  specialty: { type: String, required: true },
  qualifications: { type: String, required: true },
  biography: { type: String },
  workingHours: { type: String, required: true },
  workingDays: [{ type: String }],
  status: { 
    type: String, 
    enum: ['Available', 'On Leave'],
    default: 'Available'
  },
  username: { type: String, unique: true },
  password: { type: String },
  created_at: { type: Date, default: Date.now }
});

// Notification Schema
const notificationSchema = new mongoose.Schema({
  studentId: { 
    type: String,  // Changed from ObjectId to String to support student IDs like "2022-7070"
    required: true 
  },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['appointment', 'queue', 'message', 'info'],
    default: 'info'
  },
  appointmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Appointment' },
  doctorName: { type: String },
  isRead: { type: Boolean, default: false },
  created_at: { type: Date, default: Date.now }
});

// Called Patient Schema - Tracks patients who have been called by a doctor
const calledPatientSchema = new mongoose.Schema({
  patientId: { 
    type: String,  // Support for string IDs like "2022-7070" 
    required: true 
  },
  doctorId: { 
    type: String,  // Doctor who called the patient
    required: true 
  },
  patientName: { type: String },
  doctorName: { type: String },
  appointmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Appointment' },
  calledTime: { type: Date, default: Date.now },
  date: { type: String }, // Store the date as string (e.g., "2023-05-17")
  status: { 
    type: String, 
    enum: ['Called', 'In Progress', 'Completed', 'No-Show'],
    default: 'Called'
  }
});

// Vitals Schema
const vitalsSchema = new mongoose.Schema({
  patientId: { type: String, required: true },
  doctorId: { type: String, required: true },
  appointmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Appointment' },
  temperature: { type: Number },
  heartRate: { type: Number },
  bloodPressure: { type: String },
  respiratoryRate: { type: Number },
  oxygenSaturation: { type: Number },
  weight: { type: Number },
  height: { type: String },
  date: { type: Date, default: Date.now },
  notes: { type: String }
});

// Medicine Schema
const medicineSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  strength: {
    type: String,
    required: true
  },
  quantity: {
    type: Number,
    required: true
  },
  unit: {
    type: String,
    required: true
  },
  manufacturer: {
    type: String,
    required: true
  },
  expiryDate: {
    type: String
  },
  status: {
    type: String,
    enum: ['In Stock', 'Low Stock', 'Out of Stock'],
    default: 'In Stock'
  },
  created_at: {
    type: Date,
    default: Date.now
  },
  updated_at: {
    type: Date,
    default: Date.now
  }
});

// Add after other schemas
const prescriptionSchema = new mongoose.Schema({
  medication: {
    type: String,
    required: true
  },
  dosage: {
    type: String,
    required: true
  },
  quantity: {
    type: String,
    required: true
  },
  frequency: {
    type: String,
    required: true
  },
  instructions: String,
  patientId: {
    type: String,
    required: true
  },
  doctorId: {
    type: String,
    required: true
  },
  appointmentId: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['Active', 'Completed', 'Cancelled'],
    default: 'Active'
  },
  dateIssued: {
    type: Date,
    default: Date.now
  }
});

// Add after other schemas
const diagnosisSchema = new mongoose.Schema({
  appointmentId: {
    type: String,
    required: true
  },
  patientId: {
    type: String,
    required: true
  },
  doctorId: {
    type: String,
    required: true
  },
  notes: {
    type: String,
    required: true
  },
  diagnosis: {
    type: String,
    required: true
  },
  date: {
    type: Date,
    default: Date.now
  }
});

// Add after other schemas
const patientHistorySchema = new mongoose.Schema({
  patientId: {
    type: String,
    required: true
  },
  doctorId: {
    type: String,
    required: true
  },
  appointmentId: {
    type: String,
    required: true
  },
  appointmentDate: {
    type: Date,
    required: true
  },
  reason: String,
  diagnosis: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Diagnosis'
  },
  prescription: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Prescription'
  }],
  vitals: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Vitals'
  },
  completedAt: {
    type: Date,
    default: Date.now
  }
});

// Add this new Patient schema
const patientSchema = new mongoose.Schema({
  studentId: {
    type: String,
    required: true,
    ref: 'Student'
  },
  doctorId: {
    type: String,
    required: true
  },
  appointmentId: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['Confirmed', 'Completed'],
    required: true
  },
  notes: String,
  lastVisit: {
    type: Date,
    default: Date.now
  },
  medicalHistory: {
    allergies: String,
    medications: String,
    conditions: String
  },
  created_at: {
    type: Date,
    default: Date.now
  },
  updated_at: {
    type: Date,
    default: Date.now
  }
});

// Add this new Settings schema
const settingsSchema = new mongoose.Schema({
  clinicName: { type: String, default: 'Campus Health Center' },
  address: { type: String, default: '' },
  hours: { type: String, default: 'Monday-Friday: 8:00 AM - 5:00 PM' },
  phoneNumber: { type: String, default: '' },
  email: { type: String, default: '' },
  logoUrl: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Create Models
const Student = mongoose.model('Student', studentSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Appointment = mongoose.model('Appointment', appointmentSchema);
const Doctor = mongoose.model('Doctor', doctorSchema);
const Notification = mongoose.model('Notification', notificationSchema);
const CalledPatient = mongoose.model('CalledPatient', calledPatientSchema);
const Vitals = mongoose.model('Vitals', vitalsSchema);
const Medicine = mongoose.model('Medicine', medicineSchema);
const Prescription = mongoose.model('Prescription', prescriptionSchema);
const Diagnosis = mongoose.model('Diagnosis', diagnosisSchema);
const PatientHistory = mongoose.model('PatientHistory', patientHistorySchema);
const Patient = mongoose.model('Patient', patientSchema);
const Settings = mongoose.model('Settings', settingsSchema);

// Email configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: 'demonloveph@gmail.com',
    pass: 'qwiq cfhv nwnk jwjz'
  }
});

// Function to send welcome email
async function sendWelcomeEmail(doctor, password) {
  console.log('Starting email send process...');
  console.log('Sending to doctor email:', doctor.email);
  
  const emailTemplate = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
        body {
          font-family: Arial, sans-serif;
          line-height: 1.6;
          margin: 0;
          padding: 0;
          background-color: #f4f4f4;
        }
        .container {
          max-width: 600px;
          margin: 20px auto;
          padding: 20px;
          background-color: #ffffff;
          border-radius: 10px;
          box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header {
          background-color: #26A69A;
          color: white;
          padding: 30px 20px;
          text-align: center;
          border-radius: 10px 10px 0 0;
          margin: -20px -20px 20px -20px;
        }
        .welcome-text {
          font-size: 24px;
          margin: 0;
          font-weight: 300;
        }
        .credentials-box {
          background-color: #f8f9fa;
          border: 1px solid #e9ecef;
          border-radius: 5px;
          padding: 20px;
          margin: 20px 0;
        }
        .credential-item {
          margin: 15px 0;
        }
        .label {
          font-weight: bold;
          color: #495057;
          font-size: 16px;
          margin-bottom: 5px;
        }
        .value {
          color: #26A69A;
          font-family: monospace;
          font-size: 18px;
          background: #e8f5f3;
          padding: 8px 12px;
          border-radius: 4px;
          display: inline-block;
          margin-top: 5px;
        }
        .notice {
          background-color: #fff3cd;
          border: 1px solid #ffeeba;
          color: #856404;
          padding: 15px;
          border-radius: 5px;
          margin: 20px 0;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .notice strong {
          color: #664d03;
        }
        .footer {
          text-align: center;
          margin-top: 30px;
          padding-top: 20px;
          border-top: 1px solid #e9ecef;
          color: #6c757d;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <div class="welcome-text">Welcome to ClinQ, Dr. ${doctor.firstName} ${doctor.lastName}!</div>
        </div>
        
        <p>Your account has been created successfully. Here are your login credentials:</p>
        
        <div class="credentials-box">
          <div class="credential-item">
            <div class="label">Username:</div>
            <div class="value">${doctor.email}</div>
          </div>
          <div class="credential-item">
            <div class="label">Password:</div>
            <div class="value">${password}</div>
          </div>
        </div>
        
        <div class="notice">
          <strong>⚠️ Important:</strong> Please change your password after your first login for security purposes.
        </div>
        
        <div class="footer">
          <p>Best regards,<br>The ClinQ Team</p>
          <p style="font-size: 12px; color: #999;">
            This is an automated message, please do not reply to this email.
          </p>
        </div>
      </div>
    </body>
    </html>
  `;

  const mailOptions = {
    from: {
      name: 'ClinQ Healthcare System',
      address: 'demonloveph@gmail.com'
    },
    to: doctor.email,
    subject: 'Welcome to ClinQ - Your Account Credentials',
    html: emailTemplate,
    headers: {
      'priority': 'high'
    }
  };

  try {
    console.log('Sending credentials to:', doctor.email);
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent successfully to:', doctor.email);
    console.log('Message ID:', info.messageId);
    return true;
  } catch (error) {
    console.error('Failed to send email to:', doctor.email);
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      code: error.code
    });
    return false;
  }
}

// Verify email configuration on startup
transporter.verify(function(error, success) {
  if (error) {
    console.error('Email configuration error:', error);
    console.error('Error details:', {
      name: error.name,
      message: error.message,
      code: error.code,
      command: error.command,
      response: error.response
    });
  } else {
    console.log('Email server is ready to send messages');
  }
});

function connectToDatabase() {
  if (connectionAttempts >= maxRetries) {
    console.error(`Failed to connect to MongoDB after ${maxRetries} attempts`);
    console.error('Please ensure MongoDB connection details are correct');
    console.error('The server will continue running, but database features will not work');
    return;
  }
  
  connectionAttempts++;
  console.log(`Connecting to MongoDB... Attempt ${connectionAttempts}`);
  console.log(`Using connection string: ${MONGODB_URI.replace(/\/\/([^:]+):([^@]+)@/, '//****:****@')}`);
  
  mongoose.connect(MONGODB_URI.replace('clinq?', '?'), {})
  .then(async () => {
    connectionAttempts = 0; // Reset counter on successful connection
    console.log('MongoDB connected successfully');
    
    // Check if we can access the database by performing a simple operation
    try {
      const count = await Student.countDocuments();
      console.log(`Database contains ${count} student records`);
      // Test data creation is disabled
      // Do not uncomment these lines in production:
      // createTestUser();
      // createAdminUser();
    } catch (err) {
      console.error('Error accessing database:', err.message);
    }
  })
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    if (err.name === 'MongoServerSelectionError') {
      console.error('Could not connect to any MongoDB server. Please check:');
      console.error('1. Your network connection');
      console.error('2. MongoDB Atlas whitelist settings (allow access from all IPs)');
      console.error('3. Credentials in the connection string');
    }
    console.log(`Connection attempt ${connectionAttempts} failed. Retrying in 5 seconds...`);
    
    // Try to reconnect after 5 seconds
    setTimeout(connectToDatabase, 5000);
  });
}

// Function to create a test user for login
async function createTestUser() {
  try {
    // Check if test user already exists
    const existingUser = await Student.findOne({ university_email: 'marknicholas.balilahon@dorsu.edu.ph' });
    
    if (existingUser) {
      console.log('Test user already exists:');
      console.log('Email: marknicholas.balilahon@dorsu.edu.ph');
      console.log('User ID:', existingUser._id.toString());
      console.log('Full name:', existingUser.fname, existingUser.lname);
      
      // Ensure the user has required fields for profile
      let needsUpdate = false;
      const updates = {};
      
      if (!existingUser.fname || existingUser.fname.trim() === '') {
        updates.fname = 'Mark Nicholas';
        needsUpdate = true;
      }
      
      if (!existingUser.lname || existingUser.lname.trim() === '') {
        updates.lname = 'Balilahon';
        needsUpdate = true;
      }
      
      // Check if password needs to be hashed
      if (!existingUser.password.startsWith('$2b$') && !existingUser.password.startsWith('$2a$')) {
        // Hash the existing password
        updates.password = await bcrypt.hash(existingUser.password, SALT_ROUNDS);
        needsUpdate = true;
        console.log('Updating password to hashed version');
      }
      
      // Update the user if needed
      if (needsUpdate) {
        console.log('Updating existing user with missing fields:', updates);
        await Student.updateOne({ _id: existingUser._id }, updates);
        console.log('User updated successfully');
      }
      
      return;
    }
    
    // Hash the password for the test user
    const hashedPassword = await bcrypt.hash('password123', SALT_ROUNDS);
    
    // Create test user with hashed password
    const testUser = new Student({
      fname: 'Mark Nicholas',
      lname: 'Balilahon',
      student_id: 'MNB12345',
      university_email: 'marknicholas.balilahon@dorsu.edu.ph',
      password: hashedPassword,
      pnumber: '',
      birthdate: '',
      agreed_to_terms: 'agree'
    });
    
    // Save to database
    const savedUser = await testUser.save();
    
    console.log('Test user created successfully with hashed password!');
    console.log('Email: marknicholas.balilahon@dorsu.edu.ph');
    console.log('Password: password123 (stored as hashed)');
    console.log('User ID:', savedUser._id.toString());
  } catch (err) {
    console.error('Error creating test user:', err);
    console.error('Error stack:', err.stack);
  }
}

// Function to create an admin user
async function createAdminUser() {
  try {
    // Check if admin already exists
    const existingAdmin = await Admin.findOne({ username: 'Nic' });
    
    if (existingAdmin) {
      console.log('Admin user already exists:');
      console.log('Name:', existingAdmin.fname, existingAdmin.lname);
      console.log('Username:', existingAdmin.username);
      return;
    }
    
    // Create admin user
    const adminUser = new Admin({
      fname: 'Mark Nicholas',
      lname: 'Balilahon',
      username: 'Nic',
      password: '123',
      is_super_admin: true
    });
    
    // Save to database
    const savedAdmin = await adminUser.save();
    
    console.log('Admin user created successfully!');
    console.log('Name:', savedAdmin.fname, savedAdmin.lname);
    console.log('Username:', savedAdmin.username);
    console.log('Admin ID:', savedAdmin._id.toString());
  } catch (err) {
    console.error('Error creating admin user:', err);
    console.error('Error stack:', err.stack);
  }
}

// Function to generate random password
function generatePassword() {
  return 'CLINQ-' + CryptoJS.lib.WordArray.random(8).toString();
}

// Function to generate username
function generateUsername(firstName, lastName, email) {
  // Use email as username for simplicity and uniqueness
  return email;
}

// Add this function after the generatePassword function
function generateInitials(firstName, lastName) {
  // Split the full name and get initials
  const names = `${firstName} ${lastName}`.split(' ');
  const initials = names.map(name => name.charAt(0).toUpperCase()).join('');
  return initials;
}

// Initial connection
connectToDatabase();

// Connection Events
mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected');
  connectToDatabase();
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB error:', err);
});

// Helper function to check database before handling requests
const dbMiddleware = (req, res, next) => {
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      success: false,
      message: 'Database connection is not available'
    });
  }
  next();
};

// Routes with database checking middleware
app.get('/api/test', (req, res) => {
  // Return more detailed information about the server and database state
  const dbState = mongoose.connection.readyState;
  const dbStateText = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  }[dbState] || 'unknown';
  
  res.json({ 
    message: 'Server is running',
    serverInfo: {
      timestamp: new Date().toISOString(),
      databaseState: dbStateText,
      databaseConnected: dbState === 1,
      nodeVersion: process.version,
      endpoints: [
        '/api/test',
        '/api/register',
        '/api/login',
        '/api/user/:id',
        '/api/update-profile/:id',
        '/api/admin/login',
        '/api/admin/students',
        '/api/admin/appointments',
        '/api/admin/appointments/today',
        '/api/doctors',
        '/api/appointments',
        '/api/appointments/queue-numbers/:date',
        '/api/student/appointments/:studentId',
        '/api/doctor/login',
        '/api/doctor/appointments/:doctorId',
        '/api/students',
        '/api/student/notifications/:studentId',
        '/api/student/notifications/:notificationId/read',
        '/api/student/notifications/:notificationId/unread',
        '/api/student/notifications/:notificationId'
      ]
    }
  });
});

// Create student endpoint (Admin only)
app.post('/api/students', dbMiddleware, async (req, res) => {
  const {
    fname,
    lname,
    university_email,
    student_id,
    pnumber,
    birthdate,
    password
  } = req.body;

  console.log('Creating new student:', { fname, lname, university_email, student_id });

  try {
    // Basic validation
    if (!fname?.trim() || !lname?.trim() || !university_email?.trim() || !student_id?.trim()) {
      return res.status(400).json({
        success: false,
        message: 'First name, last name, email, and student ID are required'
      });
    }

    // Check if student with email or ID already exists
    const existingStudent = await Student.findOne({
      $or: [
        { university_email: university_email.trim() },
        { student_id: student_id.trim() }
      ]
    });
    
    if (existingStudent) {
      return res.status(409).json({
        success: false,
        message: 'Student with this email or ID already exists'
      });
    }

    // Set default password if not provided
    const rawPassword = password || 'clinq123';
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(rawPassword, SALT_ROUNDS);
    console.log('Student password hashed successfully');

    // Create new student with hashed password
    const newStudent = new Student({
      fname: fname.trim(),
      lname: lname.trim(),
      university_email: university_email.trim(),
      student_id: student_id.trim(),
      password: hashedPassword,
      pnumber: pnumber?.trim() || '',
      birthdate: birthdate?.trim() || '',
      agreed_to_terms: 'agree'
    });

    // Save to database
    const savedStudent = await newStudent.save();
    console.log('Student created successfully with hashed password:', savedStudent._id);

    res.status(201).json({
      success: true,
      message: 'Student created successfully',
      student: {
        id: savedStudent._id,
        fname: savedStudent.fname,
        lname: savedStudent.lname,
        university_email: savedStudent.university_email,
        student_id: savedStudent.student_id,
        pnumber: savedStudent.pnumber,
        birthdate: savedStudent.birthdate,
        created_at: savedStudent.created_at
      }
    });

  } catch (err) {
    console.error('Error creating student:', err);
    
    if (err.name === 'ValidationError') {
      const validationErrors = Object.values(err.errors).map(error => error.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed: ' + validationErrors.join(', ')
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to create student'
    });
  }
});

// Registration endpoint
app.post('/api/register', dbMiddleware, async (req, res) => {
  const { firstName, lastName, studentId, email, password, agreeToTerms } = req.body;
  
  // Validate required fields
  if (!firstName || !lastName || !studentId || !email || !password) {
    return res.status(400).json({
      success: false,
      message: 'All fields are required'
    });
  }
  
  // Ensure terms are agreed to
  if (!agreeToTerms) {
    return res.status(400).json({
      success: false,
      message: 'You must agree to the terms of service'
    });
  }
  
  try {
    // Check if user already exists
    const existingUser = await Student.findOne({
      $or: [
        { student_id: studentId },
        { university_email: email }
      ]
    });
    
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: 'Student ID or email already exists'
      });
    }
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    console.log('Password hashed successfully');
    
    // Create new user with hashed password
    const newStudent = new Student({
      fname: firstName,
      lname: lastName,
      student_id: studentId,
      university_email: email,
      password: hashedPassword,
      agreed_to_terms: 'agree'
    });
    
    // Save to database
    const savedStudent = await newStudent.save();
    
    console.log('User registered with agreed_to_terms = "agree" and hashed password');
    
    // Create welcome notifications for the new user
    try {
      // Welcome notification
      const welcomeNotification = new Notification({
        studentId: savedStudent._id,
        title: 'Welcome to ClinQ',
        message: 'Welcome to the ClinQ health service! This is your notifications center.',
        type: 'info',
        isRead: false,
        created_at: new Date()
      });
      
      // Booking information notification
      const bookingNotification = new Notification({
        studentId: savedStudent._id,
        title: 'Book Your First Appointment',
        message: 'You can now book appointments with our doctors through the app.',
        type: 'info',
        isRead: false,
        created_at: new Date(Date.now() - 60000) // 1 minute ago
      });
      
      // Queue notification
      const queueNotification = new Notification({
        studentId: savedStudent._id,
        title: 'Queue Update',
        message: 'You are next in line for your appointment with Dr. Emily Rodriguez. Estimated wait time: 10 minutes.',
        type: 'queue',
        isRead: false,
        doctorName: 'Dr. Emily Rodriguez',
        created_at: new Date(Date.now() - 30000) // 30 seconds ago
      });
      
      await Promise.all([
        welcomeNotification.save(),
        bookingNotification.save(),
        queueNotification.save()
      ]);
      
      console.log(`Created welcome notifications for new user ${savedStudent._id}`);
    } catch (notificationError) {
      console.error('Error creating welcome notifications:', notificationError);
      // Don't fail the whole request if notification creation fails
    }
    
    res.status(201).json({
      success: true,
      message: 'Registration successful',
      userId: savedStudent._id
    });
    
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to register user'
    });
  }
});

// Login endpoint
app.post('/api/login', dbMiddleware, async (req, res) => {
  const { email, password } = req.body;
  
  console.log('Login attempt with email:', email);
  
  // Validate required fields
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required'
    });
  }
  
  try {
    // Find user by email
    const user = await Student.findOne({ university_email: email });
    
    // No user found with that email
    if (!user) {
      console.log('No user found with email:', email);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    // Check if the student is deactivated
    if (user.isActive === false) {
      console.log('Login attempt by deactivated student account:', email);
      return res.status(403).json({
        success: false,
        message: 'Your account has been deactivated. Please contact the administrator.'
      });
    }
    
    // Check if password matches using bcrypt
    let isPasswordValid = false;
    
    // Check if the password is stored as a hash (starts with $2b$ or $2a$)
    if (user.password.startsWith('$2b$') || user.password.startsWith('$2a$')) {
      // Use bcrypt to compare the password
      isPasswordValid = await bcrypt.compare(password, user.password);
    } else {
      // For backward compatibility with old non-hashed passwords
      isPasswordValid = user.password === password;
    }
    
    if (!isPasswordValid) {
      console.log('Password mismatch for user:', email);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    console.log('Login successful for user:', email);
    
    // Login successful
    res.status(200).json({
      success: true,
      message: 'Login successful',
      user: {
        id: user._id,
        firstName: user.fname,
        lastName: user.lname,
        email: user.university_email,
        studentId: user.student_id
      }
    });
    
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get user profile endpoint
app.get('/api/user/:id', dbMiddleware, async (req, res) => {
  const userId = req.params.id;
  
  try {
    let user;
    
    // First try to find by MongoDB _id if it's a valid ObjectId
    if (mongoose.Types.ObjectId.isValid(userId)) {
      user = await Student.findById(userId).select('fname lname student_id university_email pnumber birthdate medical_info created_at profileImageUrl');
    }
    
    // If not found, try to find by student_id
    if (!user) {
      user = await Student.findOne({ student_id: userId }).select('fname lname student_id university_email pnumber birthdate medical_info created_at profileImageUrl');
    }
    
    // No user found with either ID
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    console.log('Returning user profile:', user.fname, user.lname, 'Phone:', user.pnumber || 'none');
    
    // Prepare medical info response
    const medicalInfoResponse = {
      allergies: user.medical_info?.allergies || '',
      currentMedications: user.medical_info?.current_medications || '',
      medicalConditions: user.medical_info?.medical_conditions || ''
    };
    
    // Return user data with phone, birthdate, medical info, and profile image
    res.status(200).json({
      success: true,
      user: {
        id: user._id,
        firstName: user.fname,
        lastName: user.lname,
        email: user.university_email,
        studentId: user.student_id,
        phoneNumber: user.pnumber || '',
        birthdate: user.birthdate || '',
        profileImageUrl: user.profileImageUrl || '',
        medicalInfo: medicalInfoResponse,
        joinDate: user.created_at
      }
    });
    
  } catch (err) {
    console.error('Error fetching user profile:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update user profile endpoint
app.put('/api/update-profile/:id', dbMiddleware, async (req, res) => {
  const userId = req.params.id;
  const { 
    firstName, 
    lastName, 
    pnumber, 
    birthdate,
    medicalInfo 
  } = req.body;
  
  console.log('Received update profile request for user ID:', userId);
  console.log('Request body:', req.body);
  console.log('MongoDB connection state:', mongoose.connection.readyState);
  
  // Set proper content type for all responses
  res.setHeader('Content-Type', 'application/json');
  
  // Ensure first name and last name are provided
  if (!firstName && !lastName) {
    console.log('Validation failed: no first name or last name provided');
    return res.status(400).json({
      success: false,
      message: 'At least one of first name or last name is required'
    });
  }
  
  try {
    // First check if user exists
    const userExists = await Student.findById(userId);
    if (!userExists) {
      console.log('User not found with ID:', userId);
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    console.log('Found existing user:', userExists.fname, userExists.lname, userExists.university_email);
    
    // Create update object with only provided fields
    const updateData = {};
    
    // Only add fields that are provided and not empty
    if (firstName !== undefined && firstName !== '') updateData.fname = firstName;
    if (lastName !== undefined && lastName !== '') updateData.lname = lastName;
    if (pnumber !== undefined) updateData.pnumber = pnumber;
    if (birthdate !== undefined) updateData.birthdate = birthdate;
    
    // Handle medical information if provided
    if (medicalInfo) {
      updateData.medical_info = {};
      
      if (medicalInfo.allergies !== undefined) 
        updateData.medical_info.allergies = medicalInfo.allergies;
      
      if (medicalInfo.currentMedications !== undefined) 
        updateData.medical_info.current_medications = medicalInfo.currentMedications;
      
      if (medicalInfo.medicalConditions !== undefined) 
        updateData.medical_info.medical_conditions = medicalInfo.medicalConditions;
      
      console.log('Medical info to be updated:', updateData.medical_info);
    }
    
    console.log('Update data to be saved:', updateData);
    
    // Update user profile with findOneAndUpdate for better error handling
    const updatedUser = await Student.findOneAndUpdate(
      { _id: userId },
      updateData,
      { new: true, runValidators: true, upsert: false }
    );
    
    if (!updatedUser) {
      console.log('Update failed: No document returned');
      return res.status(500).json({
        success: false,
        message: 'Failed to update user profile'
      });
    }
    
    console.log('Profile updated successfully for user:', updatedUser.university_email);
    console.log('Updated fields:', 
      updatedUser.fname, 
      updatedUser.lname, 
      updatedUser.pnumber || 'no phone', 
      updatedUser.birthdate || 'no birthdate'
    );
    
    // Prepare medical info for response
    const medicalInfoResponse = {
      allergies: updatedUser.medical_info?.allergies || '',
      currentMedications: updatedUser.medical_info?.current_medications || '',
      medicalConditions: updatedUser.medical_info?.medical_conditions || ''
    };
    
    res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: updatedUser._id,
        firstName: updatedUser.fname,
        lastName: updatedUser.lname,
        email: updatedUser.university_email,
        phoneNumber: updatedUser.pnumber || '',
        birthdate: updatedUser.birthdate || '',
        profileImageUrl: updatedUser.profileImageUrl || '',
        medicalInfo: medicalInfoResponse
      }
    });
    
  } catch (err) {
    console.error('Update error:', err);
    console.error('Error details:', err.stack);
    res.status(500).json({
      success: false,
      message: 'Failed to update profile: ' + err.message
    });
  }
});

// Admin login endpoint
app.post('/api/admin/login', dbMiddleware, async (req, res) => {
  const { username, password } = req.body;
  
  console.log('Admin login attempt with username:', username);
  
  // Validate required fields
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Username and password are required'
    });
  }
  
  try {
    // Find admin by username
    const admin = await Admin.findOne({ username: username });
    
    // No admin found with that username
    if (!admin) {
      console.log('No admin found with username:', username);
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }
    
    // Check if password matches
    if (admin.password !== password) {
      console.log('Password mismatch for admin:', username);
      return res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
    }
    
    console.log('Admin login successful for:', username);
    
    // Login successful
    res.status(200).json({
      success: true,
      message: 'Login successful',
      admin: {
        id: admin._id,
        firstName: admin.fname,
        lastName: admin.lname,
        username: admin.username,
        isSuperAdmin: admin.is_super_admin
      }
    });
    
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get all students (Admin only)
app.get('/api/admin/students', dbMiddleware, async (req, res) => {
  try {
    // Find all students, excluding sensitive data like passwords
    const students = await Student.find({}).select('fname lname student_id university_email pnumber birthdate created_at isActive');
    
    console.log(`Returning list of ${students.length} students`);
    
    // Return the list of students
    res.status(200).json({
      success: true,
      count: students.length,
      students: students.map(student => ({
        id: student._id,
        firstName: student.fname,
        lastName: student.lname,
        studentId: student.student_id,
        email: student.university_email,
        phoneNumber: student.pnumber || '',
        birthdate: student.birthdate || '',
        joinDate: student.created_at,
        isActive: student.isActive !== false // default to true if isActive is undefined
      }))
    });
    
  } catch (err) {
    console.error('Error fetching students list:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get all appointments (Admin only)
app.get('/api/admin/appointments', dbMiddleware, async (req, res) => {
  try {
    // Find all appointments and populate student information
    const appointments = await Appointment.find({})
      .populate('student', 'fname lname student_id')
      .sort({ dateTime: -1 });
    
    console.log(`Returning list of ${appointments.length} appointments`);
    
    // Return the list of appointments
    res.status(200).json({
      success: true,
      count: appointments.length,
      appointments: appointments.map(appointment => {
        // Format queue number with leading zeros
        const formattedQueueNumber = appointment.queueNumber ? String(appointment.queueNumber).padStart(3, '0') : '000';
        
        // Safely extract student data, handling potential null values
        const studentFname = appointment.student ? appointment.student.fname || 'Unknown' : 'Unknown';
        const studentLname = appointment.student ? appointment.student.lname || 'Student' : 'Student';
        
        // Safely extract doctor data, handling potential null values
        const doctorName = appointment.doctor && appointment.doctor.name ? appointment.doctor.name : 'Unassigned';
        const doctorSpecialty = appointment.doctor && appointment.doctor.specialty ? appointment.doctor.specialty : 'General';
        
        return {
          id: appointment._id,
          studentName: `${studentFname} ${studentLname}`,
          doctorName: doctorName,
          doctorSpecialty: doctorSpecialty,
          type: appointment.type || 'Consultation',
          dateTime: appointment.dateTime,
          notes: appointment.notes || '',
          status: appointment.status || 'Pending',
          queueNumber: formattedQueueNumber,
          created_at: appointment.created_at
        };
      })
    });
    
  } catch (err) {
    console.error('Error fetching appointments list:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get today's appointments count (Admin only)
app.get('/api/admin/appointments/today', dbMiddleware, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    const count = await Appointment.countDocuments({
      dateTime: {
        $gte: today,
        $lt: tomorrow
      }
    });

    res.status(200).json({
      success: true,
      count
    });
  } catch (err) {
    console.error('Error fetching today\'s appointments count:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Create doctor endpoint (Admin only)
app.post('/api/doctors', dbMiddleware, async (req, res) => {
  const {
    firstName,
    lastName,
    email,
    phoneNumber,
    specialty,
    qualifications,
    biography,
    workingHours,
    workingDays
  } = req.body;

  console.log('Creating new doctor:', { firstName, lastName, email, phoneNumber });

  try {
    // Basic validation
    if (!firstName?.trim() || !lastName?.trim() || !email?.trim() || !phoneNumber?.trim()) {
      return res.status(400).json({
        success: false,
        message: 'First name, last name, email, and phone number are required'
      });
    }

    // Check if doctor with email already exists
    const existingDoctor = await Doctor.findOne({ email: email.trim() });
    if (existingDoctor) {
      return res.status(409).json({
        success: false,
        message: 'Doctor with this email already exists'
      });
    }

    // Generate password with CLINQ prefix
    const temporaryPassword = generatePassword();
    console.log('Generated password:', temporaryPassword);

    // Hash the temporary password
    const hashedPassword = await bcrypt.hash(temporaryPassword, SALT_ROUNDS);
    console.log('Password hashed for security');

    // Create new doctor using email as username
    const newDoctor = new Doctor({
      firstName: firstName.trim(),
      lastName: lastName.trim(),
      email: email.trim(),
      phoneNumber: phoneNumber.trim(),
      specialty: specialty?.trim() || '',
      qualifications: qualifications?.trim() || '',
      biography: biography?.trim() || '',
      workingHours: workingHours || '9:00 AM - 5:00 PM',
      workingDays: workingDays || ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'],
      status: 'Available',
      username: email.trim(), // Use email as username
      password: hashedPassword // Save the hashed password
    });

    // Save to database
    const savedDoctor = await newDoctor.save();
    console.log('Doctor created successfully:', savedDoctor._id);

    // Send welcome email with credentials
    const emailSent = await sendWelcomeEmail(savedDoctor, temporaryPassword);

    res.status(201).json({
      success: true,
      message: emailSent 
        ? 'Doctor created successfully and welcome email sent'
        : 'Doctor created successfully but failed to send welcome email. Please check server logs.',
      doctor: {
        id: savedDoctor._id,
        firstName: savedDoctor.firstName,
        lastName: savedDoctor.lastName,
        email: savedDoctor.email,
        specialty: savedDoctor.specialty,
        status: savedDoctor.status,
        username: savedDoctor.email,
        temporaryPassword: temporaryPassword // Only sending back if email failed
      }
    });

  } catch (err) {
    console.error('Error creating doctor:', err);
    
    if (err.name === 'ValidationError') {
      const validationErrors = Object.values(err.errors).map(error => error.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed: ' + validationErrors.join(', ')
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to create doctor'
    });
  }
});

// Get all doctors (Admin only)
app.get('/api/doctors', dbMiddleware, async (req, res) => {
  try {
    console.log('Fetching all doctors');
    const doctors = await Doctor.find({}).sort({ created_at: -1 });
    console.log(`Found ${doctors.length} doctors`);

    // Get upcoming appointments to calculate next available slots
    const today = new Date();
    const nextWeek = new Date(today);
    nextWeek.setDate(today.getDate() + 7);

    // Get all appointments for the next 7 days
    const upcomingAppointments = await Appointment.find({
      status: { $in: ['Confirmed', 'Pending'] }
    });

    console.log(`Found ${upcomingAppointments.length} upcoming appointments for availability calculation`);

    const doctorsWithCounts = await Promise.all(doctors.map(async (doctor) => {
      const initials = generateInitials(doctor.firstName, doctor.lastName);
      
      // Get doctor's appointments
      const doctorAppointments = upcomingAppointments.filter(
        app => app.doctor && app.doctor.id && app.doctor.id.toString() === doctor._id.toString()
      );

      // Calculate next available time slot (simplified version)
      let nextAvailable = "";
      if (doctorAppointments.length > 0 && doctor.status === 'Available') {
        // Sort appointments by date
        doctorAppointments.sort((a, b) => {
          const dateA = new Date(a.dateTime);
          const dateB = new Date(b.dateTime);
          return dateA - dateB;
        });
        
        // Just use the last appointment's date + 30 minutes as a simple approximation
        const lastAppointment = doctorAppointments[doctorAppointments.length - 1];
        if (lastAppointment.dateTime) {
          nextAvailable = `After ${lastAppointment.dateTime}`;
        } else {
          nextAvailable = "Today";
        }
      } else if (doctor.status === 'Available') {
        nextAvailable = "Today";
      }
      
      return {
        id: doctor._id,
        name: `${doctor.firstName} ${doctor.lastName}`,
        email: doctor.email,
        specialty: doctor.specialty,
        status: doctor.status,
        initials: initials,
        workingHours: doctor.workingHours || "9:00 AM - 5:00 PM",
        nextAvailable: nextAvailable
      };
    }));

    res.status(200).json({
      success: true,
      count: doctors.length,
      doctors: doctorsWithCounts
    });

  } catch (err) {
    console.error('Error fetching doctors list:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get taken queue numbers for a specific date
app.get('/api/appointments/queue-numbers/:date', dbMiddleware, async (req, res) => {
  try {
    const date = req.params.date;

    // Find appointments for the exact date without timezone adjustment
    const appointments = await Appointment.find({
      dateTime: {
        $regex: `^${date}`  // Match appointments that start with this date
      }
    }).select('queueNumber').sort({ queueNumber: 1 });

    const takenQueueNumbers = appointments.map(app => app.queueNumber);

    console.log('Found queue numbers for date:', {
      requestedDate: date,
      appointments: appointments.map(app => ({
        dateTime: app.dateTime,
        queueNumber: app.queueNumber
      })),
      takenNumbers: takenQueueNumbers
    });

    // Check if we've reached the daily limit
    if (takenQueueNumbers.length >= 100) {
      return res.status(200).json({
        success: true,
        message: 'Daily limit reached',
        takenQueueNumbers: Array.from({ length: 100 }, (_, i) => i + 1)
      });
    }

    res.status(200).json({
      success: true,
      takenQueueNumbers
    });
  } catch (err) {
    console.error('Error fetching taken queue numbers:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Create appointment endpoint
app.post('/api/appointments', dbMiddleware, async (req, res) => {
  const { studentId, doctor, type, dateTime, notes, queueNumber } = req.body;

  console.log('Received appointment request:', { 
    studentId, 
    doctor,
    type, 
    dateTime,
    requestedQueueNumber: queueNumber,
    notes 
  });

  try {
    // Basic validation
    if (!studentId || !doctor || !doctor.id || !type || !dateTime) {
      return res.status(400).json({
        success: false,
        message: 'Student ID, doctor (with ID), appointment type, and date/time are required'
      });
    }

    // Check if student exists
    const student = await Student.findById(studentId);
    if (!student) {
      return res.status(404).json({
        success: false,
        message: 'Student not found'
      });
    }

    // Check if doctor exists
    const doctorExists = await Doctor.findById(doctor.id);
    if (!doctorExists) {
      return res.status(404).json({
        success: false,
        message: 'Doctor not found'
      });
    }

    // Get the date part of the appointment
    const appointmentDate = dateTime.split(' ')[0];
    
    // Find the next available queue number for the date
    let nextQueueNumber = queueNumber ? parseInt(queueNumber) : 1;
    
    // If no specific queue number is requested or the requested one is taken, find the next available
    if (!queueNumber || (await isQueueNumberTaken(appointmentDate, nextQueueNumber))) {
      nextQueueNumber = await findNextAvailableQueueNumber(appointmentDate);
      console.log(`Assigned next available queue number: ${nextQueueNumber}`);
    }

    // Format queue number with leading zeros
    const formattedQueueNumber = String(nextQueueNumber).padStart(3, '0');

    // Create new appointment with exact date/time string and doctor ID
    const newAppointment = new Appointment({
      student: studentId,
      doctor: {
        id: doctor.id,
        name: doctor.name,
        specialty: doctor.specialty
      },
      type: type,
      dateTime: dateTime,
      notes: notes || '',
      status: 'Pending',
      queueNumber: nextQueueNumber,
      formattedQueueNumber: formattedQueueNumber
    });

    // Save to database
    const savedAppointment = await newAppointment.save();
    console.log('Appointment saved successfully:', {
      id: savedAppointment._id,
      doctorId: savedAppointment.doctor.id,
      doctorName: savedAppointment.doctor.name,
      dateTime: savedAppointment.dateTime,
      queueNumber: savedAppointment.queueNumber,
      formattedQueueNumber: savedAppointment.formattedQueueNumber
    });

    // Create booking notification for the student
    try {
      const notification = new Notification({
        studentId: studentId,
        title: 'Appointment Booked',
        message: `You have booked an appointment with Dr. ${doctor.name} on ${dateTime}. Your booking is pending confirmation.`,
        type: 'appointment',
        appointmentId: savedAppointment._id,
        doctorName: `Dr. ${doctor.name}`,
        isRead: false
      });
      
      await notification.save();
      console.log(`Created appointment booking notification for student ${studentId}`);
    } catch (notificationError) {
      console.error('Error creating notification:', notificationError);
      // Don't fail the whole request if notification creation fails
    }

    res.status(201).json({
      success: true,
      message: 'Appointment created successfully',
      appointment: {
        id: savedAppointment._id,
        studentName: `${student.fname} ${student.lname}`,
        doctorId: savedAppointment.doctor.id,
        doctorName: savedAppointment.doctor.name,
        type: savedAppointment.type,
        dateTime: savedAppointment.dateTime,
        status: savedAppointment.status,
        queueNumber: formattedQueueNumber
      }
    });

  } catch (err) {
    console.error('Error creating appointment:', err);
    
    if (err.name === 'ValidationError') {
      const validationErrors = Object.values(err.errors).map(error => error.message);
      return res.status(400).json({
        success: false,
        message: 'Validation failed: ' + validationErrors.join(', ')
      });
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to create appointment'
    });
  }
});

// Update appointment status endpoint
app.put('/api/appointments/status', dbMiddleware, async (req, res) => {
  const { appointmentId, status, doctorId, notes } = req.body;
  
  console.log('Updating appointment status:', { appointmentId, status, doctorId });
  
  try {
    // Basic validation
    if (!appointmentId || !status) {
      return res.status(400).json({
        success: false,
        message: 'Appointment ID and status are required'
      });
    }
    
    // Find the appointment
    const appointment = await Appointment.findById(appointmentId);
    if (!appointment) {
      return res.status(404).json({
        success: false,
        message: 'Appointment not found'
      });
    }
    
    // Update appointment status
    appointment.status = status;
    await appointment.save();
    
    console.log(`Appointment ${appointmentId} status updated to ${status}`);
    
    // Save to Patient table when status is Completed or Confirmed
    if (status === 'Completed' || status === 'Confirmed') {
      try {
        // Get patient/student information
        let studentId;
        
        if (appointment.student && typeof appointment.student === 'object' && appointment.student._id) {
          studentId = appointment.student._id;
        } else if (appointment.student && typeof appointment.student === 'string') {
          studentId = appointment.student;
        } else if (appointment.patientId) {
          studentId = appointment.patientId;
        }
        
        if (!studentId) {
          console.log('Could not find valid student ID in appointment');
          return;
        }
        
        // Get student's medical info if available
        let medicalInfo = {
          allergies: '',
          medications: '',
          conditions: ''
        };
        
        try {
          const student = await Student.findById(studentId);
          if (student && student.medical_info) {
            medicalInfo = {
              allergies: student.medical_info.allergies || '',
              medications: student.medical_info.current_medications || '',
              conditions: student.medical_info.medical_conditions || ''
            };
          }
        } catch (error) {
          console.error('Error fetching student medical info:', error);
        }
        
        // Check if a patient record already exists
        let patient = await Patient.findOne({
          studentId: studentId,
          appointmentId: appointmentId
        });
        
        if (patient) {
          // Update existing patient record
          patient.status = status;
          patient.lastVisit = new Date();
          patient.updated_at = new Date();
          
          await patient.save();
          console.log(`Updated patient record for student ${studentId} and appointment ${appointmentId}`);
        } else {
          // Create new patient record
          patient = new Patient({
            studentId: studentId,
            doctorId: doctorId,
            appointmentId: appointmentId,
            status: status,
            notes: notes || appointment.notes || '',
            medicalHistory: medicalInfo
          });
          
          await patient.save();
          console.log(`Created new patient record for student ${studentId} with ID: ${patient._id}`);
        }
      } catch (patientError) {
        console.error('Error saving to Patient table:', patientError);
        // Continue with the process even if this fails
      }
    }
    
    // If this is a status change to In Progress or Completed, update any existing CalledPatient record
    if (status === 'In Progress' || status === 'Completed') {
      try {
        // Get patient information from the appointment
        let patientId;
        
        if (appointment.student && typeof appointment.student === 'object' && appointment.student.student_id) {
          patientId = appointment.student.student_id;
        } else if (appointment.patientId) {
          patientId = appointment.patientId;
        }
        
        if (patientId) {
          // Find existing called patient records for this patient
          const calledPatient = await CalledPatient.findOne({
            patientId: patientId,
            appointmentId: appointmentId
          });
          
          if (calledPatient) {
            // Update the status
            calledPatient.status = status;
            await calledPatient.save();
            console.log(`Updated CalledPatient record for ${patientId} to status: ${status}`);
          } else {
            // If no record exists, create one
            const today = new Date();
            const dateString = today.toISOString().split('T')[0];
            
            // Get patient name
            const patientName = appointment.student && appointment.student.fname && appointment.student.lname ? 
              `${appointment.student.fname} ${appointment.student.lname}` : patientId;
            
            // Get doctor info
            const doctor = appointment.doctor;
            const doctorName = doctor && doctor.name ? 
              doctor.name : (doctor && doctor.id ? doctor.id : doctorId);
            
            // Create a new called patient record
            const newCalledPatient = new CalledPatient({
              patientId: patientId,
              doctorId: doctorId,
              patientName: patientName,
              doctorName: doctorName,
              appointmentId: appointmentId,
              date: dateString,
              status: status
            });
            
            await newCalledPatient.save();
            console.log(`Created new CalledPatient record for ${patientId} with status: ${status}`);
          }
        }
      } catch (error) {
        console.error('Error updating CalledPatient record:', error);
        // Continue even if this fails
      }
    }
    
    // If the status is "In Progress" or "Completed", also mark any other pending appointments
    // for the same patient as "Called" to remove them from the queue
    if (status === 'In Progress' || status === 'Completed') {
      try {
        // Get patient information from the appointment
        let patientId;
        
        if (appointment.student && typeof appointment.student === 'object' && appointment.student.student_id) {
          patientId = appointment.student.student_id;
        } else if (appointment.patientId) {
          patientId = appointment.patientId;
        }
        
        if (patientId) {
          console.log(`Looking for other appointments for patient ${patientId}`);
          
          // Find all other pending appointments for this patient
          const otherAppointments = await Appointment.find({
            _id: { $ne: appointmentId }, // Not the current appointment
            'student.student_id': patientId, // Same patient
            status: { $in: ['Confirmed', 'Pending'] } // Only pending appointments
          });
          
          console.log(`Found ${otherAppointments.length} other pending appointments for this patient`);
          
          // Update all other appointments to "Called" status
          for (const otherAppointment of otherAppointments) {
            otherAppointment.status = 'Called';
            await otherAppointment.save();
            console.log(`Marked appointment ${otherAppointment._id} as Called`);
            
            // Also add to CalledPatient table
            try {
              // Get current date in YYYY-MM-DD format for filtering
              const today = new Date();
              const dateString = today.toISOString().split('T')[0];
              
              // Get patient info
              const patient = otherAppointment.student;
              const patientName = patient && patient.fname && patient.lname ? 
                `${patient.fname} ${patient.lname}` : patientId;
              
              // Get doctor info
              const doctor = otherAppointment.doctor;
              const doctorName = doctor && doctor.name ? 
                doctor.name : 'Unknown Doctor';
              
              // Create a new called patient record
              const calledPatient = new CalledPatient({
                patientId: patientId,
                doctorId: doctorId,
                patientName: patientName,
                doctorName: doctorName,
                appointmentId: otherAppointment._id,
                date: dateString,
                status: 'Called'
              });
              
              await calledPatient.save();
              console.log(`Added patient to CalledPatient collection via status update with ID: ${calledPatient._id}`);
            } catch (calledPatientError) {
              console.error('Error creating called patient record:', calledPatientError);
              // Continue with the process even if this fails
            }
          }
        }
      } catch (error) {
        console.error('Error updating other appointments:', error);
        // Continue even if there's an error
      }
    }
    
    // Create notification for the student
    if (status === 'Confirmed') {
      const doctor = appointment.doctor;
      const doctorName = doctor ? doctor.name : 'Unknown Doctor';
      
      // Get appointment date in readable format
      const dateTime = appointment.dateTime;
      
      try {
        // Convert student ID to valid format if needed
        let studentId = appointment.student;
        
        // Make sure we have a string version of the ID
        if (typeof studentId === 'object' && studentId !== null) {
          studentId = studentId.toString();
        }
        
        console.log(`Creating confirmation notification for student ${studentId}`);
        
        // Create notification with queue number and arrival instructions
        const formattedQueueNumber = String(appointment.queueNumber).padStart(3, '0');
        
        const notification = new Notification({
          studentId: studentId,
          title: 'Appointment Confirmed',
          message: `Your appointment with Dr. ${doctorName} on ${dateTime} has been confirmed. Your queue number is ${formattedQueueNumber}. Please arrive 30 minutes before your scheduled time.`,
          type: 'appointment',
          appointmentId: appointment._id,
          doctorName: `Dr. ${doctorName}`,
          isRead: false
        });
        
        await notification.save();
        console.log(`Created confirmation notification with ID: ${notification._id}`);
      } catch (notificationError) {
        console.error('Error creating notification:', notificationError);
        // Don't fail the whole request if notification creation fails
      }
    }
    
    // Create notification when an appointment is cancelled
    else if (status === 'Cancelled') {
      const doctor = appointment.doctor;
      const doctorName = doctor ? doctor.name : 'Unknown Doctor';
      const dateTime = appointment.dateTime;
      
      try {
        // Convert student ID to valid format if needed
        let studentId = appointment.student;
        
        // Make sure we have a string version of the ID
        if (typeof studentId === 'object' && studentId !== null) {
          studentId = studentId.toString();
        }
        
        console.log(`Creating cancellation notification for student ${studentId}`);
        
        // Create cancellation notification
        const notification = new Notification({
          studentId: studentId,
          title: 'Appointment Cancelled',
          message: `Your appointment with Dr. ${doctorName} on ${dateTime} has been cancelled. Please book a new appointment at your convenience.`,
          type: 'appointment',
          appointmentId: appointment._id,
          doctorName: `Dr. ${doctorName}`,
          isRead: false
        });
        
        await notification.save();
        console.log(`Created cancellation notification with ID: ${notification._id}`);
      } catch (notificationError) {
        console.error('Error creating cancellation notification:', notificationError);
        // Don't fail the whole request if notification creation fails
      }
    }
    
    res.status(200).json({
      success: true,
      message: 'Appointment status updated successfully',
      appointment: {
        id: appointment._id,
        status: appointment.status
      }
    });
    
  } catch (err) {
    console.error('Error updating appointment status:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to update appointment status'
    });
  }
});

// GET student notifications
app.get('/api/student/notifications/:studentId', dbMiddleware, async (req, res) => {
  const studentId = req.params.studentId;
  
  console.log(`Fetching notifications for student: ${studentId}`);
  
  try {
    // Try a more comprehensive approach for finding notifications
    // First, check if we can find the student record
    let student;
    let objectId;
    
    try {
      // Try to convert to MongoDB ObjectId for query
      if (mongoose.Types.ObjectId.isValid(studentId)) {
        objectId = new mongoose.Types.ObjectId(studentId);
      }
    } catch (err) {
      console.log('Not a valid ObjectId, will search by string ID');
    }
    
    // Try to find the student by various ID formats
    if (objectId) {
      student = await Student.findById(objectId);
    }
    
    if (!student) {
      // Try finding by student_id field
      student = await Student.findOne({ student_id: studentId });
      console.log(`Looked up student by student_id: ${studentId}, found: ${student ? 'yes' : 'no'}`);
    }
    
    // Build a more inclusive query
    let query = {
      $or: []
    };
    
    // Add all possible ID formats to the query
    if (objectId) {
      query.$or.push({ studentId: objectId });
    }
    
    // Add the raw studentId string
    query.$or.push({ studentId: studentId });
    
    // If we found the student, also search by their MongoDB _id
    if (student && student._id) {
      query.$or.push({ studentId: student._id });
      query.$or.push({ studentId: student._id.toString() });
    }
    
    console.log('Enhanced query for notifications:', JSON.stringify(query));
    const notifications = await Notification.find(query)
      .sort({ created_at: -1 }); // Sort by creation date, newest first
    
    console.log(`Found ${notifications.length} notifications for student ${studentId}`);
    
    const formattedNotifications = notifications.map(notification => {
      // Format date for display
      const createdAt = new Date(notification.created_at);
      const now = new Date();
      
      // Format date as "Today", "Yesterday", or the actual date
      let date;
      if (createdAt.toDateString() === now.toDateString()) {
        date = 'Today';
      } else if (new Date(now.setDate(now.getDate() - 1)).toDateString() === createdAt.toDateString()) {
        date = 'Yesterday';
      } else {
        date = createdAt.toLocaleDateString('en-US', { 
          month: 'short',
          day: 'numeric'
        });
      }
      
      // Format time
      const time = createdAt.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
      });
      
      return {
        id: notification._id,
        title: notification.title,
        message: notification.message,
        type: notification.type,
        time: time,
        date: date,
        isRead: notification.isRead,
        appointmentId: notification.appointmentId,
        doctorName: notification.doctorName
      };
    });
    
    // If no notifications found, create a welcome notification
    if (formattedNotifications.length === 0) {
      console.log(`No notifications found for student ${studentId}, returning empty list`);
    }
    
    res.status(200).json({
      success: true,
      notifications: formattedNotifications
    });
    
  } catch (err) {
    console.error('Error fetching student notifications:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch notifications'
    });
  }
});

// Mark notification as read
app.put('/api/student/notifications/:notificationId/read', dbMiddleware, async (req, res) => {
  const notificationId = req.params.notificationId;
  
  console.log(`Marking notification as read: ${notificationId}`);
  
  try {
    let query = {};
    
    try {
      if (mongoose.Types.ObjectId.isValid(notificationId)) {
        // If valid ObjectId, search by ID directly
        query._id = new mongoose.Types.ObjectId(notificationId);
      } else {
        // Use string ID if not a valid ObjectId
        query._id = notificationId;
      }
    } catch (err) {
      console.error('Error converting notificationId to ObjectID:', err);
      query._id = notificationId; // Fallback to string ID
    }
    
    console.log('Finding notification with query:', query);
    const notification = await Notification.findOne(query);
    
    if (!notification) {
      console.error('Notification not found:', notificationId);
      return res.status(404).json({
        success: false,
        message: 'Notification not found'
      });
    }
    
    notification.isRead = true;
    await notification.save();
    
    console.log(`Notification ${notificationId} marked as read`);
    
    res.status(200).json({
      success: true,
      message: 'Notification marked as read',
      notification: {
        id: notification._id,
        isRead: notification.isRead
      }
    });
  } catch (err) {
    console.error('Error marking notification as read:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to mark notification as read'
    });
  }
});

// Mark notification as unread
app.put('/api/student/notifications/:notificationId/unread', dbMiddleware, async (req, res) => {
  const notificationId = req.params.notificationId;
  
  console.log(`Marking notification as unread: ${notificationId}`);
  
  try {
    let query = {};
    
    try {
      if (mongoose.Types.ObjectId.isValid(notificationId)) {
        // If valid ObjectId, search by ID directly
        query._id = new mongoose.Types.ObjectId(notificationId);
      } else {
        // Use string ID if not a valid ObjectId
        query._id = notificationId;
      }
    } catch (err) {
      console.error('Error converting notificationId to ObjectID:', err);
      query._id = notificationId; // Fallback to string ID
    }
    
    console.log('Finding notification with query:', query);
    const notification = await Notification.findOne(query);
    
    if (!notification) {
      console.error('Notification not found:', notificationId);
      return res.status(404).json({
        success: false,
        message: 'Notification not found'
      });
    }
    
    notification.isRead = false;
    await notification.save();
    
    console.log(`Notification ${notificationId} marked as unread`);
    
    res.status(200).json({
      success: true,
      message: 'Notification marked as unread',
      notification: {
        id: notification._id,
        isRead: notification.isRead
      }
    });
  } catch (err) {
    console.error('Error marking notification as unread:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to mark notification as unread'
    });
  }
});

// DELETE notification
app.delete('/api/student/notifications/:notificationId', dbMiddleware, async (req, res) => {
  const notificationId = req.params.notificationId;
  
  console.log(`Deleting notification: ${notificationId}`);
  
  try {
    let query = {};
    
    try {
      if (mongoose.Types.ObjectId.isValid(notificationId)) {
        // If valid ObjectId, search by ID directly
        query._id = new mongoose.Types.ObjectId(notificationId);
      } else {
        // Use string ID if not a valid ObjectId
        query._id = notificationId;
      }
    } catch (err) {
      console.error('Error converting notificationId to ObjectID:', err);
      query._id = notificationId; // Fallback to string ID
    }
    
    console.log('Finding notification to delete with query:', query);
    const deletionResult = await Notification.deleteOne(query);
    
    if (deletionResult.deletedCount === 0) {
      console.error('Notification not found for deletion:', notificationId);
      return res.status(404).json({
        success: false,
        message: 'Notification not found'
      });
    }
    
    console.log(`Notification ${notificationId} deleted successfully`);
    
    res.status(200).json({
      success: true,
      message: 'Notification deleted successfully'
    });
  } catch (err) {
    console.error('Error deleting notification:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to delete notification'
    });
  }
});

// Add helper functions for queue number management
async function isQueueNumberTaken(date, queueNumber) {
  const existingAppointment = await Appointment.findOne({
    dateTime: { $regex: `^${date}` },
    queueNumber: queueNumber
  });
  return !!existingAppointment;
}

async function findNextAvailableQueueNumber(date) {
  // Find all appointments for the given date
  const appointments = await Appointment.find({
    dateTime: { $regex: `^${date}` }
  }).sort({ queueNumber: 1 });
  
  // Get all taken queue numbers
  const takenNumbers = appointments.map(app => app.queueNumber);
  
  // Start from 1 and find the first unused number
  let nextNumber = 1;
  while (takenNumbers.includes(nextNumber)) {
    nextNumber++;
  }
  
  return nextNumber;
}

// Update the student appointments endpoint to ensure proper object formatting
// Upload profile image endpoint
app.post('/api/user/profile-image', upload.single('profileImage'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded'
      });
    }

    // Get user ID from form data
    const userId = req.body.userId;
    
    if (!userId) {
      // Delete the uploaded file since we can't associate it with a user
      fs.unlinkSync(req.file.path);
      
      return res.status(400).json({
        success: false,
        message: 'User ID is required'
      });
    }

    // Find the user
    const user = await Student.findById(userId);
    
    if (!user) {
      // Delete the uploaded file since the user doesn't exist
      fs.unlinkSync(req.file.path);
      
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Create the image URL (relative to the server)
    const imageUrl = `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;
    
    // If user had a previous profile image, delete it
    if (user.profileImageUrl) {
      const oldImagePath = user.profileImageUrl.split('/uploads/')[1];
      if (oldImagePath) {
        const fullPath = path.join(uploadsDir, oldImagePath);
        if (fs.existsSync(fullPath)) {
          fs.unlinkSync(fullPath);
        }
      }
    }
    
    // Update user's profile image URL
    user.profileImageUrl = imageUrl;
    await user.save();
    
    res.status(200).json({
      success: true,
      message: 'Profile image uploaded successfully',
      imageUrl: imageUrl
    });
    
  } catch (err) {
    console.error('Error uploading profile image:', err);
    
    // If there was an error and a file was uploaded, delete it
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    
    res.status(500).json({
      success: false,
      message: 'Failed to upload profile image',
      error: err.message
    });
  }
});

app.get('/api/student/appointments/:studentId', dbMiddleware, async (req, res) => {
  const studentId = req.params.studentId;
  
  console.log(`Fetching appointments for student ID: ${studentId}`);
  
  try {
    // Find all appointments for this student
    const appointments = await Appointment.find({ student: studentId });
    
    console.log(`Found ${appointments.length} raw appointments:`, JSON.stringify(appointments));
    
    // Get current date for filtering active/upcoming appointments
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    console.log(`Today is: ${today.toDateString()}, Month: ${months[today.getMonth()]}, Day: ${today.getDate()}`);
    
    // Format appointments and categorize them
    const formattedAppointments = appointments.map(appointment => {
      // Ensure queue number is always formatted with leading zeros
      const formattedQueueNumber = String(appointment.queueNumber).padStart(3, '0');
      
      // Make sure doctor is a string, not an object
      const doctorName = appointment.doctor && appointment.doctor.name ? 
        appointment.doctor.name : 'Unknown Doctor';
      
      const doctorSpecialty = appointment.doctor && appointment.doctor.specialty ? 
        appointment.doctor.specialty : '';
      
      console.log(`Processing appointment: ${appointment._id}, date: ${appointment.dateTime}, doctor: ${doctorName}`);
      
      return {
        id: appointment._id,
        doctor: doctorName,
        specialty: doctorSpecialty,
        type: appointment.type,
        dateTime: appointment.dateTime,
        status: appointment.status,
        queueNumber: appointment.queueNumber,
        formattedQueueNumber: formattedQueueNumber,
        notes: appointment.notes || ''
      };
    });

    // Active appointment finder logic
    const activeAppointment = formattedAppointments.find(app => {
      try {
        if (!app.dateTime) return false;
        
        // Parse date like "May 16 3:30 PM"
        const dateParts = app.dateTime.split(' ');
        if (dateParts.length < 3) return false;
        
        const month = dateParts[0]; // "May"
        const day = parseInt(dateParts[1], 10); // 16
        
        // Define currentDate variable
        const currentDate = new Date();
        
        // Define months array for comparison
        const months = ['January', 'February', 'March', 'April', 'May', 'June', 
                        'July', 'August', 'September', 'October', 'November', 'December'];
        
        // Get current date details
        const currentMonth = months[currentDate.getMonth()]; // "May"
        const currentDay = currentDate.getDate(); // Current day
        
        // Compare month and day
        const isSameMonth = month.toLowerCase() === currentMonth.toLowerCase();
        const isSameDay = day === currentDay;
        
        console.log(`Checking if appointment is active: "${app.dateTime}" vs today (${currentMonth} ${currentDay})`);
        console.log(`Same month: ${isSameMonth}, Same day: ${isSameDay}, Status: ${app.status}`);
        
        // Active if same day and status is not Cancelled or Completed
        return isSameMonth && isSameDay && 
               (app.status === 'Confirmed' || app.status === 'Pending');
      } catch (err) {
        console.error('Error checking active appointment:', err);
        return false;
      }
    });
    
    // Make a copy of all appointments, then we'll remove the active one
    let allNonCancelledAppointments = formattedAppointments.filter(app => 
      app.status !== 'Cancelled' && app.status !== 'Completed'
    );
    
    // Define upcoming appointments as all non-cancelled, non-completed appointments
    // INCLUDE the active appointment in upcoming - we'll show it in both places
    // This ensures the appointment always shows in the upcoming list
    let upcomingAppointments = [...allNonCancelledAppointments];
    
    // Log what we're sending
    console.log('Sending appointment data to client:', {
      active: activeAppointment ? {
        doctor: activeAppointment.doctor,
        dateTime: activeAppointment.dateTime
      } : null,
      upcomingCount: upcomingAppointments.length,
      upcomingFirst: upcomingAppointments.length > 0 ? {
        doctor: upcomingAppointments[0].doctor,
        dateTime: upcomingAppointments[0].dateTime
      } : null
    });

    // If we have an active appointment, don't show it in the upcoming list to avoid duplication
    if (activeAppointment) {
      // Comment out this line as it's causing appointments to not show in the dashboard
      // upcomingAppointments = upcomingAppointments.filter(app => app.id.toString() !== activeAppointment.id.toString());
    }
    
    // Make sure we have at least some appointments showing
    if (upcomingAppointments.length === 0 && !activeAppointment && formattedAppointments.length > 0) {
      // If no upcoming appointments, just show all non-completed/cancelled ones
      upcomingAppointments = formattedAppointments.filter(app => 
        app.status !== 'Cancelled' && app.status !== 'Completed'
      );
      
      console.log('No upcoming appointments found, showing all valid appointments as upcoming');
    }
    
    // Past appointments are those with Cancelled or Completed status
    const pastAppointments = formattedAppointments.filter(app => 
      app.status === 'Cancelled' || app.status === 'Completed'
    );

    // Make sure queue number is properly formatted for active appointment
    if (activeAppointment) {
      // Ensure queueNumber is a number
      const queueNum = typeof activeAppointment.queueNumber === 'number' 
        ? activeAppointment.queueNumber 
        : parseInt(activeAppointment.queueNumber || '1', 10);
      
      // Format queue number with leading zeros
      activeAppointment.formattedQueueNumber = String(queueNum).padStart(3, '0');
      
      // Calculate estimated wait time (15 mins per person in queue)
      activeAppointment.waitTime = (queueNum - 1) * 15;
      
      console.log('Active appointment details:', {
        doctor: activeAppointment.doctor,
        dateTime: activeAppointment.dateTime,
        queueNumber: activeAppointment.queueNumber,
        formattedQueueNumber: activeAppointment.formattedQueueNumber,
        waitTime: activeAppointment.waitTime
      });
    }

    console.log('Sending appointment data to client:', {
      active: activeAppointment ? true : false,
      upcoming: upcomingAppointments.length,
      past: pastAppointments.length,
      allAppointments: formattedAppointments.length
    });

          res.status(200).json({
        success: true,
        appointments: {
          active: activeAppointment || null,
          upcoming: upcomingAppointments,
          past: pastAppointments
        }
      });
    
  } catch (err) {
    console.error('Error fetching student appointments:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch appointments'
    });
  }
});

// Add a doctor login endpoint
app.post('/api/doctor/login', dbMiddleware, async (req, res) => {
  const { email, password } = req.body;
  
  console.log('Doctor login attempt with email/username:', email);
  console.log('Password provided:', password ? '[REDACTED]' : 'none');
  
  // Validate required fields
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required'
    });
  }
  
  try {
    // Find doctor by email OR username
    const doctor = await Doctor.findOne({
      $or: [
        { email: email },
        { username: email }
      ]
    });
    
    // No doctor found with that email/username
    if (!doctor) {
      console.log('No doctor found with email/username:', email);
      
      // Log available doctor accounts to help debugging
      const allDoctors = await Doctor.find({}).select('email username');
      console.log('Available doctor accounts:');
      console.log(JSON.stringify(allDoctors, null, 2));
      
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    console.log('Found doctor:', {
      id: doctor._id,
      name: `${doctor.firstName} ${doctor.lastName}`,
      email: doctor.email,
      username: doctor.username
    });
    
    // Check if password matches
    let passwordMatch = false;
    
    // Check if the password is already hashed
    if (doctor.password.startsWith('$2b$') || doctor.password.startsWith('$2a$')) {
      // If it's already hashed, use bcrypt.compare
      passwordMatch = await bcrypt.compare(password, doctor.password);
    } else {
      // For backward compatibility with non-hashed passwords
      passwordMatch = doctor.password === password;
    }
    
    if (!passwordMatch) {
      console.log('Password mismatch for doctor:', email);
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }
    
    console.log('Doctor login successful for:', doctor.email);
    
    // Login successful
    res.status(200).json({
      success: true,
      message: 'Login successful',
      doctor: {
        id: doctor._id,
        firstName: doctor.firstName,
        lastName: doctor.lastName,
        email: doctor.email,
        specialty: doctor.specialty,
        status: doctor.status,
        phoneNumber: doctor.phoneNumber,
        qualifications: doctor.qualifications
      }
    });
    
  } catch (err) {
    console.error('Doctor login error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Get doctor's appointments
app.get('/api/doctor/appointments/:doctorId', dbMiddleware, async (req, res) => {
  // API that fetches appointments for a doctor's dashboard
  const doctorId = req.params.doctorId;
  
  try {
    console.log('Fetching appointments for doctor ID:', doctorId);
    
    // First convert the doctor ID to proper format if needed
    let doctorIdObj;
    try {
      if (mongoose.Types.ObjectId.isValid(doctorId)) {
        doctorIdObj = new mongoose.Types.ObjectId(doctorId);
      } else {
        doctorIdObj = doctorId;
      }
    } catch (err) {
      console.error('Error converting doctorId:', err);
      doctorIdObj = doctorId;
    }
    
    console.log('Using doctorId for query:', doctorIdObj);
    
    // Find all non-archived appointments for this doctor
    const appointments = await Appointment.find({ 
      $and: [
        {
          $or: [
            { 'doctor.id': doctorId },
            { 'doctor.id': doctorIdObj },
            { 'doctor.id': doctorId.toString() }
          ]
        },
        { archived: { $ne: true } }
      ]
    })
    .populate('student', 'fname lname student_id')
    .sort({ dateTime: 1 });
    
    console.log(`Found ${appointments.length} raw appointments for doctor ${doctorId}`);
    
    // Log the first few appointments for debugging
    if (appointments.length > 0) {
      appointments.slice(0, 3).forEach((app, i) => {
        console.log(`Appointment ${i+1}:`, {
          id: app._id,
          doctorId: app.doctor.id,
          patient: app.student ? `${app.student.fname} ${app.student.lname}` : 'Unknown',
          dateTime: app.dateTime,
          status: app.status
        });
      });
    }
    
    // Get current date for filtering today's appointments
    const now = new Date();
    
    // IMPORTANT: For testing, consider ALL appointments as today's appointments
    // This ensures we show appointments regardless of date during development
    const todaysAppointments = appointments;
    
    console.log(`Using all ${todaysAppointments.length} appointments for today`);
    
    // Format for response
    const formattedAppointments = todaysAppointments.map((appointment, index) => {
      // Make sure student exists before trying to access properties
      const student = appointment.student || {};
      
      // Log each appointment datetime for debugging
      console.log(`Processing appointment for ${student.fname || ''} ${student.lname || ''}, dateTime: ${appointment.dateTime}`);
      
      // Calculate queue position based on time
      const formatted = {
        id: appointment._id,
        patientName: student.fname && student.lname ? 
          `${student.fname} ${student.lname}` : 'Unknown Patient',
        patientId: student.student_id || 'N/A',
        reason: appointment.type || 'Checkup',
        dateTime: appointment.dateTime,
        status: appointment.status,
        queueNumber: appointment.queueNumber || index + 1,
        formattedQueueNumber: appointment.formattedQueueNumber || 
          String(appointment.queueNumber || (index + 1)).padStart(3, '0'),
        queuePosition: index + 1,
        waitTime: index * 15, // Estimate 15 mins per patient
        type: appointment.type || 'General Checkup',
        notes: appointment.notes || ''
      };
      
      console.log(`Formatted appointment ${index+1}:`, formatted);
      return formatted;
    });
    
    // Count patients (excluding archived)
    const totalPatients = await Appointment.countDocuments({ 
      $and: [
        {
          $or: [
            { 'doctor.id': doctorId },
            { 'doctor.id': doctorIdObj },
            { 'doctor.id': doctorId.toString() }
          ]
        },
        { archived: { $ne: true } }
      ]
    });
    
    const thisWeekStart = new Date(now);
    thisWeekStart.setDate(now.getDate() - now.getDay()); // Start of week (Sunday)
    
    const newPatientsThisWeek = await Appointment.countDocuments({
      $or: [
        { 'doctor.id': doctorId },
        { 'doctor.id': doctorIdObj },
        { 'doctor.id': doctorId.toString() }
      ],
      created_at: { $gte: thisWeekStart }
    });
    
    // Get current queue status with proper time comparison
    // CRITICAL FIX: Exclude ALL appointments that should not appear in the queue
    console.log('Filtering queue, starting with', formattedAppointments.length, 'appointments');
    
    // Log all statuses for debugging
    formattedAppointments.forEach(app => {
      console.log(`Patient: ${app.patientName}, Status: ${app.status}`);
    });
    
    const currentQueue = formattedAppointments
      .filter(app => {
        // Include all appointments that aren't explicitly completed, called, or cancelled
        // This ensures we show all upcoming appointments in the queue
        const excludedStatuses = ['Completed', 'Cancelled', 'Called', 'No-Show'];
        const shouldInclude = !excludedStatuses.includes(app.status);
        
        // Log why we're including or excluding this appointment
        console.log(`Queue filter: ${app.patientName} (${app.status}) - ${shouldInclude ? 'INCLUDE' : 'EXCLUDE'}`);
        
        return shouldInclude;
      })
      .map((app, index) => {
        // Directly assign different wait times based on queue position
        // This ensures each appointment shows a different time
        let waitTimeDisplay;
        
        if (index === 0) {
          // First patient - current or coming soon
          if (app.status === 'Confirmed') {
            waitTimeDisplay = "Now";
          } else {
            waitTimeDisplay = "15m";
          }
        } else if (index === 1) {
          // Second patient
          waitTimeDisplay = "35m";
        } else if (index === 2) {
          // Third patient
          waitTimeDisplay = "1h 15m";
        } else if (index === 3) {
          // Fourth patient
          waitTimeDisplay = "2h 30m";
        } else if (index === 4) {
          // Fifth patient
          waitTimeDisplay = "3h 45m";
        } else {
          // Anyone else
          const hours = Math.floor(index / 2) + 2;
          const minuteOptions = [15, 30, 45];
          const minutes = minuteOptions[index % 3];
          waitTimeDisplay = `${hours}h ${minutes}m`;
        }
        
        console.log(`Assigned wait time for ${app.patientName} at position ${index+1}: ${waitTimeDisplay}`);
        
        return {
          position: app.queuePosition,
          patientName: app.patientName,
          patientId: app.patientId,
          appointmentId: app.id, // Include the appointment ID for actions
          reason: app.reason,
          dateTime: app.dateTime,
          waitTime: waitTimeDisplay,
          status: index === 0 ? 'Current' : 'Waiting'
        };
      });
    
    const responseData = {
      success: true,
      todaysAppointments: {
        total: todaysAppointments.length,
        completed: todaysAppointments.filter(app => app.status === 'Completed').length,
        list: formattedAppointments
      },
      currentQueue: currentQueue,
      stats: {
        totalPatients: totalPatients,
        newThisWeek: newPatientsThisWeek,
        prescriptions: 12 // Placeholder, you can add a prescriptions collection later
      }
    };
    
    console.log(`Sending response with ${formattedAppointments.length} appointments`);
    res.status(200).json(responseData);
    
  } catch (err) {
    console.error('Error fetching doctor appointments:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch appointments: ' + err.message
    });
  }
});

// Get doctor's patients
app.get('/api/doctor/patients/:doctorId', dbMiddleware, async (req, res) => {
  const doctorId = req.params.doctorId;
  
  try {
    console.log('Fetching patients for doctor ID:', doctorId);
    
    // First convert the doctor ID to proper format if needed
    let doctorIdObj;
    try {
      if (mongoose.Types.ObjectId.isValid(doctorId)) {
        doctorIdObj = new mongoose.Types.ObjectId(doctorId);
      } else {
        doctorIdObj = doctorId;
      }
    } catch (err) {
      console.error('Error converting doctorId:', err);
      doctorIdObj = doctorId;
    }
    
    console.log('Using doctorId for query:', doctorIdObj);
    
    // Find all appointments for this doctor using multiple query formats
    const appointments = await Appointment.find({ 
      $or: [
        { 'doctor.id': doctorId },
        { 'doctor.id': doctorIdObj },
        { 'doctor.id': doctorId.toString() }
      ]
    })
    .populate('student')
    .select('student');
    
    console.log(`Found ${appointments.length} appointments for doctor with patients data`);
    
    // Extract unique patient IDs
    const patientIds = [];
    appointments.forEach(app => {
      if (app.student && app.student._id && !patientIds.includes(app.student._id.toString())) {
        patientIds.push(app.student._id.toString());
      }
    });
    
    console.log(`Found ${patientIds.length} unique patient IDs`);
    
    // Find all these patients
    const patients = await Student.find({ 
      _id: { $in: patientIds.map(id => {
        try {
          return new mongoose.Types.ObjectId(id);
        } catch (err) {
          return id;
        }
      })} 
    });
    
    console.log(`Found ${patients.length} patients for doctor ID ${doctorId}`);
    
    // Format for response
    const formattedPatients = patients.map(patient => {
      return {
        id: patient._id,
        firstName: patient.fname,
        lastName: patient.lname,
        email: patient.university_email || patient.email,
        studentId: patient.student_id,
        medicalInfo: patient.medical_info || {}
      };
    });
    
    res.status(200).json({
      success: true,
      count: patients.length,
      patients: formattedPatients
    });
    
  } catch (err) {
    console.error('Error fetching doctor patients:', err);
    res.status(500).json({
      success: false,
      message: 'Server error'
    });
  }
});

// Update doctor profile endpoint
app.put('/api/doctors/:doctorId', dbMiddleware, async (req, res) => {
  const doctorId = req.params.doctorId;
  const { 
    firstName, 
    lastName, 
    email, 
    phoneNumber,
    specialty,
    licenseNumber,
    hospital,
    experience
  } = req.body;
  
  console.log('Received update doctor profile request for ID:', doctorId);
  console.log('Request body:', req.body);
  
  try {
    // First convert the doctor ID to proper format if needed
    let doctorIdObj;
    try {
      if (mongoose.Types.ObjectId.isValid(doctorId)) {
        doctorIdObj = new mongoose.Types.ObjectId(doctorId);
      } else {
        doctorIdObj = doctorId;
      }
    } catch (err) {
      console.error('Error converting doctorId:', err);
      doctorIdObj = doctorId;
    }
    
    // Find the doctor to update
    const doctor = await Doctor.findOne({
      $or: [
        { _id: doctorId },
        { _id: doctorIdObj },
        { _id: doctorId.toString() }
      ]
    });
    
    if (!doctor) {
      return res.status(404).json({
        success: false,
        message: 'Doctor not found'
      });
    }
    
    console.log(`Found doctor to update: ${doctor.firstName} ${doctor.lastName}`);
    
    // Create update object with only provided fields
    const updateData = {};
    
    // Only add fields that are provided and not undefined or empty
    if (firstName) updateData.firstName = firstName;
    if (lastName) updateData.lastName = lastName;
    if (email) updateData.email = email;
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (specialty) updateData.specialty = specialty;
    
    // Additional fields
    if (licenseNumber) updateData.qualifications = licenseNumber;
    if (hospital) updateData.biography = `Affiliated with ${hospital}`;
    if (experience) updateData.workingHours = `${experience} years of experience`;
    
    console.log('Update data:', updateData);
    
    // Update the doctor profile
    const updatedDoctor = await Doctor.findOneAndUpdate(
      { _id: doctor._id },
      updateData,
      { new: true }
    );
    
    if (!updatedDoctor) {
      return res.status(500).json({
        success: false,
        message: 'Failed to update doctor profile'
      });
    }
    
    console.log('Doctor profile updated successfully:', updatedDoctor.email);
    
    // Also update any appointment records with this doctor's information
    try {
      if (firstName || lastName || specialty) {
        // Update doctor info in appointments
        await Appointment.updateMany(
          { 'doctor.id': doctor._id },
          { 
            $set: { 
              'doctor.name': `${firstName || doctor.firstName} ${lastName || doctor.lastName}`,
              ...(specialty ? { 'doctor.specialty': specialty } : {})
            } 
          }
        );
        console.log('Updated doctor info in appointment records');
      }
    } catch (appointmentUpdateError) {
      console.error('Error updating appointments with doctor info:', appointmentUpdateError);
      // Continue with response even if appointment updates fail
    }
    
    res.status(200).json({
      success: true,
      message: 'Doctor profile updated successfully',
      doctor: {
        id: updatedDoctor._id,
        firstName: updatedDoctor.firstName,
        lastName: updatedDoctor.lastName,
        email: updatedDoctor.email,
        specialty: updatedDoctor.specialty,
        phoneNumber: updatedDoctor.phoneNumber
      }
    });
    
  } catch (err) {
    console.error('Error updating doctor profile:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to update doctor profile: ' + err.message
    });
  }
});

// Update doctor password endpoint
app.put('/api/doctors/:doctorId/password', dbMiddleware, async (req, res) => {
  const doctorId = req.params.doctorId;
  const { currentPassword, newPassword } = req.body;
  
  console.log('Received password change request for doctor ID:', doctorId);
  
  // Validate required fields
  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      message: 'Current password and new password are required'
    });
  }
  
  try {
    // First convert the doctor ID to proper format if needed
    let doctorIdObj;
    try {
      if (mongoose.Types.ObjectId.isValid(doctorId)) {
        doctorIdObj = new mongoose.Types.ObjectId(doctorId);
      } else {
        doctorIdObj = doctorId;
      }
    } catch (err) {
      console.error('Error converting doctorId:', err);
      doctorIdObj = doctorId;
    }
    
    // Find the doctor
    const doctor = await Doctor.findOne({
      $or: [
        { _id: doctorId },
        { _id: doctorIdObj },
        { _id: doctorId.toString() }
      ]
    });
    
    if (!doctor) {
      return res.status(404).json({
        success: false,
        message: 'Doctor not found'
      });
    }
    
    // Verify current password
    let passwordMatch = false;
    
    // Check if the current password is already hashed
    if (doctor.password.startsWith('$2b$') || doctor.password.startsWith('$2a$')) {
      // If it's already hashed, use bcrypt.compare
      passwordMatch = await bcrypt.compare(currentPassword, doctor.password);
    } else {
      // For backward compatibility with non-hashed passwords
      passwordMatch = doctor.password === currentPassword;
    }
    
    if (!passwordMatch) {
      console.log('Password mismatch during change attempt');
      return res.status(401).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }
    
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);
    
    // Update the password with the hashed version
    doctor.password = hashedPassword;
    await doctor.save();
    
    console.log('Password updated successfully for doctor:', doctor.email);
    
    res.status(200).json({
      success: true,
      message: 'Password updated successfully'
    });
    
  } catch (err) {
    console.error('Error updating doctor password:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to update password: ' + err.message
    });
  }
});

// Function to log existing doctors (for admin use only)
async function logExistingDoctors() {
  try {
    // Log only the number of doctors, not credentials
    const doctorCount = await Doctor.countDocuments();
    console.log(`System has ${doctorCount} registered doctors`);
  } catch (err) {
    console.error('Error checking doctor accounts:', err);
  }
}

// Call patient endpoint - sends a notification and removes from queue
app.post('/api/doctor/call-patient', dbMiddleware, async (req, res) => {
  const { patientId, doctorId, doctorName } = req.body;
  
  console.log('Call patient request:', { patientId, doctorId, doctorName });
  
  try {
    // Validate required fields
    if (!patientId || !doctorId || !doctorName) {
      return res.status(400).json({
        success: false,
        message: 'Patient ID, doctor ID, and doctor name are required'
      });
    }
    
    // First find the actual student to ensure we have the proper MongoDB ID
    const student = await Student.findOne({ student_id: patientId });
    if (!student) {
      console.log(`Could not find student with ID ${patientId}`);
      // Continue anyway, but log the issue
    }
    
    // Use the actual student ID from the database if found, otherwise use the provided ID
    const realStudentId = student ? student._id : patientId;
    console.log(`Using student ID for notification: ${realStudentId}`);
    
    // Create a notification for the patient to come in
    const notification = new Notification({
      studentId: realStudentId,
      title: 'Doctor is Ready',
      message: `${doctorName} is ready to see you. Please come to the clinic right away.`,
      type: 'queue',
      doctorName: doctorName,
      isRead: false,
      created_at: new Date()
    });
    
    await notification.save();
    console.log(`Created notification for patient ${patientId} to come to doctor's office`);
    console.log(`Notification ID: ${notification._id}`);
    
    // Create an entry in the CalledPatient collection
    try {
      // Get current date in YYYY-MM-DD format for filtering
      const today = new Date();
      const dateString = today.toISOString().split('T')[0];
      
      // Get the patient name if we found a student record
      const patientName = student ? `${student.fname} ${student.lname}` : patientId;
      
      // Create a new called patient record
      const calledPatient = new CalledPatient({
        patientId: patientId,
        doctorId: doctorId,
        patientName: patientName,
        doctorName: doctorName,
        date: dateString,
        status: 'Called'
      });
      
      await calledPatient.save();
      console.log(`Added patient ${patientId} to CalledPatient collection with ID: ${calledPatient._id}`);
    } catch (calledPatientError) {
      console.error('Error creating called patient record:', calledPatientError);
      // Continue with the process even if this fails
    }
    
    // DIRECT APPROACH: Update ALL appointments with this patient ID to remove them from queue
    console.log(`Updating all appointments for patient ${patientId} with doctorId ${doctorId}`);
    
    // First approach - direct update based on student ID field
    const updateResult1 = await Appointment.updateMany(
      { 
        'student.student_id': patientId,
        status: { $in: ['Confirmed', 'Pending'] }
      },
      { 
        $set: { status: 'Called' }
      }
    );
    
    console.log(`Direct update result: ${updateResult1.matchedCount} matched, ${updateResult1.modifiedCount} modified`);
    
    // Second approach - try with patientId field
    const updateResult2 = await Appointment.updateMany(
      { 
        patientId: patientId,
        status: { $in: ['Confirmed', 'Pending'] }
      },
      { 
        $set: { status: 'Called' }
      }
    );
    
    console.log(`Secondary update result: ${updateResult2.matchedCount} matched, ${updateResult2.modifiedCount} modified`);
    
    // Third approach - use raw MongoDB update to catch any structure
    // This is a last resort approach to match appointments regardless of structure
    const db = mongoose.connection.db;
    
    try {
      // Using the raw MongoDB driver for a broader query
      const result = await db.collection('appointments').updateMany(
        { 
          $or: [
            { "patient": patientId },
            { "patient.id": patientId },
            { "student": patientId },
            { "student.id": patientId },
            { "student.student_id": patientId },
            { "patientId": patientId }
          ],
          status: { $in: ['Confirmed', 'Pending'] }
        },
        { 
          $set: { status: 'Called' }
        }
      );
      
      console.log(`Raw MongoDB update result: ${result.matchedCount} matched, ${result.modifiedCount} modified`);
    } catch (rawDbError) {
      console.error('Error with raw MongoDB update:', rawDbError);
    }
    
    // Set one appointment to In Progress if available
    const firstAppointment = await Appointment.findOne({
      $or: [
        { 'student.student_id': patientId },
        { patientId: patientId }
      ],
      status: 'Called' // Find one that we just updated
    });
    
    if (firstAppointment) {
      firstAppointment.status = 'In Progress';
      await firstAppointment.save();
      console.log(`Set appointment ${firstAppointment._id} to In Progress`);
    }
    
    // Send success response
    res.status(200).json({
      success: true,
      message: 'Patient called successfully',
      notificationId: notification._id,
      appointmentsUpdated: updateResult1.modifiedCount + updateResult2.modifiedCount
    });
    
  } catch (error) {
    console.error('Error calling patient:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to call patient: ' + error.message
    });
  }
});

// Get called patients for a specific date
app.get('/api/doctor/called-patients/:doctorId', dbMiddleware, async (req, res) => {
  const doctorId = req.params.doctorId;
  const date = req.query.date || new Date().toISOString().split('T')[0]; // Default to today
  
  try {
    console.log(`Fetching called patients for doctor ${doctorId} on date ${date}`);
    
    // Query the CalledPatient collection
    const calledPatients = await CalledPatient.find({
      doctorId: doctorId,
      date: date
    }).sort({ calledTime: -1 }); // Most recent first
    
    console.log(`Found ${calledPatients.length} called patients`);
    
    // Send response
    res.status(200).json({
      success: true,
      count: calledPatients.length,
      calledPatients: calledPatients
    });
  } catch (err) {
    console.error('Error fetching called patients:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch called patients: ' + err.message
    });
  }
});

// Save patient vitals endpoint
app.post('/api/vitals', dbMiddleware, async (req, res) => {
  const { 
    patientId,
    doctorId,
    appointmentId,
    temperature,
    heartRate,
    bloodPressure,
    respiratoryRate,
    oxygenSaturation,
    weight,
    height,
    notes
  } = req.body;

  try {
    // Validate required fields
    if (!patientId || !doctorId) {
      return res.status(400).json({
        success: false,
        message: 'Patient ID and doctor ID are required'
      });
    }

    // Create new vitals record
    const vitals = new Vitals({
      patientId,
      doctorId,
      appointmentId,
      temperature,
      heartRate,
      bloodPressure,
      respiratoryRate,
      oxygenSaturation,
      weight,
      height,
      notes
    });

    // Save to database
    await vitals.save();

    res.status(201).json({
      success: true,
      message: 'Vitals saved successfully',
      vitals
    });

  } catch (err) {
    console.error('Error saving vitals:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to save vitals'
    });
  }
});

// Get patient vitals endpoint
app.get('/api/vitals/:patientId/:appointmentId', dbMiddleware, async (req, res) => {
  try {
    const { patientId, appointmentId } = req.params;
    
    // Find the most recent vitals for this patient and appointment
    const vitals = await Vitals.findOne({
      patientId,
      appointmentId
    }).sort({ date: -1 });
    
    if (!vitals) {
      return res.json({
        success: true,
        message: 'No vitals found',
        vitals: null
      });
    }
    
    res.json({
      success: true,
      message: 'Vitals retrieved successfully',
      vitals
    });
  } catch (err) {
    console.error('Error fetching vitals:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch vitals'
    });
  }
});

// Medicine endpoints
app.post('/api/medicines', dbMiddleware, async (req, res) => {
  try {
    const { name, strength, quantity, unit, manufacturer, expiryDate, status } = req.body;

    // Create new medicine
    const medicine = new Medicine({
      name,
      strength,
      quantity,
      unit,
      manufacturer,
      expiryDate,
      status
    });

    // Save to database
    await medicine.save();

    res.json({
      success: true,
      message: 'Medicine added successfully',
      medicine
    });
  } catch (err) {
    console.error('Error creating medicine:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to create medicine',
      error: err.message
    });
  }
});

app.get('/api/medicines', dbMiddleware, async (req, res) => {
  try {
    const medicines = await Medicine.find().sort({ created_at: -1 });
    res.json({
      success: true,
      medicines
    });
  } catch (err) {
    console.error('Error fetching medicines:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch medicines',
      error: err.message
    });
  }
});

app.get('/api/medicines/:id', dbMiddleware, async (req, res) => {
  try {
    const medicine = await Medicine.findById(req.params.id);
    if (!medicine) {
      return res.status(404).json({
        success: false,
        message: 'Medicine not found'
      });
    }
    res.json({
      success: true,
      medicine
    });
  } catch (err) {
    console.error('Error fetching medicine:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch medicine',
      error: err.message
    });
  }
});

app.put('/api/medicines/:id', dbMiddleware, async (req, res) => {
  try {
    const { name, strength, quantity, unit, manufacturer, expiryDate, status } = req.body;

    const medicine = await Medicine.findByIdAndUpdate(
      req.params.id,
      {
        name,
        strength,
        quantity,
        unit,
        manufacturer,
        expiryDate,
        status,
        updated_at: Date.now()
      },
      { new: true }
    );

    if (!medicine) {
      return res.status(404).json({
        success: false,
        message: 'Medicine not found'
      });
    }

    res.json({
      success: true,
      message: 'Medicine updated successfully',
      medicine
    });
  } catch (err) {
    console.error('Error updating medicine:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to update medicine',
      error: err.message
    });
  }
});

app.delete('/api/medicines/:id', dbMiddleware, async (req, res) => {
  try {
    const medicine = await Medicine.findByIdAndDelete(req.params.id);
    if (!medicine) {
      return res.status(404).json({
        success: false,
        message: 'Medicine not found'
      });
    }
    res.json({
      success: true,
      message: 'Medicine deleted successfully'
    });
  } catch (err) {
    console.error('Error deleting medicine:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to delete medicine',
      error: err.message
    });
  }
});

// Create prescription
app.post('/api/prescriptions', dbMiddleware, async (req, res) => {
  try {
    const {
      medication,
      dosage,
      quantity,
      frequency,
      instructions,
      patientId,
      doctorId,
      appointmentId,
      status,
      dateIssued
    } = req.body;

    // Create new prescription
    const prescription = new Prescription({
      medication,
      dosage,
      quantity,
      frequency,
      instructions,
      patientId,
      doctorId,
      appointmentId,
      status,
      dateIssued: dateIssued || new Date()
    });

    // Save to database
    await prescription.save();

    res.json({
      success: true,
      message: 'Prescription added successfully',
      prescription
    });
  } catch (err) {
    console.error('Error creating prescription:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to create prescription',
      error: err.message
    });
  }
});

// Get prescriptions for a patient
app.get('/api/prescriptions/:patientId', dbMiddleware, async (req, res) => {
  try {
    const prescriptions = await Prescription.find({ 
      patientId: req.params.patientId 
    }).sort({ dateIssued: -1 });

    res.json({
      success: true,
      prescriptions
    });
  } catch (err) {
    console.error('Error fetching prescriptions:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch prescriptions',
      error: err.message
    });
  }
});

// Delete prescription
app.delete('/api/prescriptions/:id', dbMiddleware, async (req, res) => {
  try {
    const prescription = await Prescription.findByIdAndDelete(req.params.id);
    if (!prescription) {
      return res.status(404).json({
        success: false,
        message: 'Prescription not found'
      });
    }
    res.json({
      success: true,
      message: 'Prescription deleted successfully'
    });
  } catch (err) {
    console.error('Error deleting prescription:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to delete prescription',
      error: err.message
    });
  }
});

// Update prescription
app.put('/api/prescriptions/:id', dbMiddleware, async (req, res) => {
  try {
    const {
      medication,
      dosage,
      quantity,
      frequency,
      instructions,
      status
    } = req.body;

    const prescription = await Prescription.findByIdAndUpdate(
      req.params.id,
      {
        medication,
        dosage,
        quantity,
        frequency,
        instructions,
        status,
        updated_at: Date.now()
      },
      { new: true }
    );

    if (!prescription) {
      return res.status(404).json({
        success: false,
        message: 'Prescription not found'
      });
    }

    res.json({
      success: true,
      message: 'Prescription updated successfully',
      prescription
    });
  } catch (err) {
    console.error('Error updating prescription:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to update prescription',
      error: err.message
    });
  }
});

// Create diagnosis
app.post('/api/diagnosis', dbMiddleware, async (req, res) => {
  try {
    const {
      appointmentId,
      patientId,
      doctorId,
      notes,
      diagnosis
    } = req.body;

    // Create new diagnosis
    const newDiagnosis = new Diagnosis({
      appointmentId,
      patientId,
      doctorId,
      notes,
      diagnosis
    });

    // Save to database
    await newDiagnosis.save();

    res.json({
      success: true,
      message: 'Diagnosis saved successfully',
      diagnosis: newDiagnosis
    });
  } catch (err) {
    console.error('Error saving diagnosis:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to save diagnosis',
      error: err.message
    });
  }
});

// Get diagnosis for an appointment
app.get('/api/diagnosis/:appointmentId', dbMiddleware, async (req, res) => {
  try {
    const diagnosis = await Diagnosis.findOne({ 
      appointmentId: req.params.appointmentId 
    }).sort({ date: -1 });

    if (!diagnosis) {
      return res.json({
        success: true,
        message: 'No diagnosis found',
        diagnosis: null
      });
    }

    res.json({
      success: true,
      diagnosis
    });
  } catch (err) {
    console.error('Error fetching diagnosis:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch diagnosis',
      error: err.message
    });
  }
});

// Update diagnosis
app.put('/api/diagnosis/:id', dbMiddleware, async (req, res) => {
  try {
    const {
      notes,
      diagnosis
    } = req.body;

    const updatedDiagnosis = await Diagnosis.findByIdAndUpdate(
      req.params.id,
      {
        notes,
        diagnosis,
        date: Date.now()
      },
      { new: true }
    );

    if (!updatedDiagnosis) {
      return res.status(404).json({
        success: false,
        message: 'Diagnosis not found'
      });
    }

    res.json({
      success: true,
      message: 'Diagnosis updated successfully',
      diagnosis: updatedDiagnosis
    });
  } catch (err) {
    console.error('Error updating diagnosis:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to update diagnosis',
      error: err.message
    });
  }
});

// Create patient history when appointment is completed
app.post('/api/patient-history', dbMiddleware, async (req, res) => {
  try {
    const {
      patientId,
      doctorId,
      appointmentId,
      appointmentDate,
      reason
    } = req.body;

    // Find related records
    const diagnosis = await Diagnosis.findOne({ appointmentId });
    const prescriptions = await Prescription.find({ appointmentId });
    const vitals = await Vitals.findOne({ appointmentId });

    // Create patient history record
    const patientHistory = new PatientHistory({
      patientId,
      doctorId,
      appointmentId,
      appointmentDate,
      reason,
      diagnosis: diagnosis?._id,
      prescription: prescriptions.map(p => p._id),
      vitals: vitals?._id
    });

    // Save to database
    await patientHistory.save();

    // Update appointment status to archived
    await Appointment.findByIdAndUpdate(appointmentId, {
      status: 'Archived',
      archived: true
    });

    res.json({
      success: true,
      message: 'Patient history created successfully',
      patientHistory
    });
  } catch (err) {
    console.error('Error creating patient history:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to create patient history',
      error: err.message
    });
  }
});

// Get patient history
app.get('/api/patient-history/:patientId', dbMiddleware, async (req, res) => {
  try {
    const history = await PatientHistory.find({ 
      patientId: req.params.patientId 
    })
    .populate('diagnosis')
    .populate('prescription')
    .populate('vitals')
    .sort({ completedAt: -1 });

    res.json({
      success: true,
      history
    });
  } catch (err) {
    console.error('Error fetching patient history:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch patient history',
      error: err.message
    });
  }
});

// Get patient records by doctorId
app.get('/api/patients/doctor/:doctorId', dbMiddleware, async (req, res) => {
  try {
    // Find all patients for this doctor
    const patients = await Patient.find({ doctorId: req.params.doctorId })
      .sort({ updated_at: -1 });
    
    // Get all student IDs from these patients
    const studentIds = patients.map(patient => patient.studentId);
    
    // Fetch all those students in one batch
    const students = await Student.find({ 
      $or: [
        { _id: { $in: studentIds } },
        { student_id: { $in: studentIds } }
      ]
    });
    
    console.log(`Found ${patients.length} patients and ${students.length} matching students`);
    
    // Create a lookup map for fast access
    const studentMap = {};
    students.forEach(student => {
      // Add by _id
      if (student._id) {
        studentMap[student._id.toString()] = student;
      }
      // Also add by student_id for flexibility
      if (student.student_id) {
        studentMap[student.student_id] = student;
      }
    });
    
    // Enhance patients with student information
    const enhancedPatients = patients.map(patient => {
      const patientObj = patient.toObject();
      const studentId = patient.studentId;
      const matchedStudent = studentMap[studentId];
      
      if (matchedStudent) {
        patientObj.studentData = {
          firstName: matchedStudent.fname,
          lastName: matchedStudent.lname,
          email: matchedStudent.university_email || matchedStudent.email,
          studentId: matchedStudent.student_id
        };
      }
      
      return patientObj;
    });
    
    res.json({
      success: true,
      count: enhancedPatients.length,
      patients: enhancedPatients
    });
  } catch (err) {
    console.error('Error fetching patients by doctor:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch patients',
      error: err.message
    });
  }
});

// Get patient records by studentId
app.get('/api/patients/student/:studentId', dbMiddleware, async (req, res) => {
  try {
    const patients = await Patient.find({ studentId: req.params.studentId })
      .sort({ updated_at: -1 });
    
    res.json({
      success: true,
      count: patients.length,
      patients
    });
  } catch (err) {
    console.error('Error fetching patient records by student:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch patient records',
      error: err.message
    });
  }
});

// GET settings
app.get('/api/admin/settings', dbMiddleware, async (req, res) => {
  try {
    // Find settings, or create default if none exists
    let settings = await Settings.findOne();
    
    if (!settings) {
      settings = await Settings.create({});
    }
    
    res.status(200).json({
      success: true,
      settings
    });
  } catch (err) {
    console.error('Error fetching settings:', err);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: err.message
    });
  }
});

// Update settings
app.put('/api/admin/settings', dbMiddleware, async (req, res) => {
  try {
    const { 
      clinicName, 
      address, 
      hours, 
      phoneNumber, 
      email 
    } = req.body;
    
    // Find settings, or create default if none exists
    let settings = await Settings.findOne();
    
    if (!settings) {
      settings = await Settings.create({
        clinicName: clinicName || 'Campus Health Center',
        address: address || '',
        hours: hours || 'Monday-Friday: 8:00 AM - 5:00 PM',
        phoneNumber: phoneNumber || '',
        email: email || '',
        updatedAt: new Date()
      });
    } else {
      // Update existing settings
      settings.clinicName = clinicName || settings.clinicName;
      settings.address = address || settings.address;
      settings.hours = hours || settings.hours;
      settings.phoneNumber = phoneNumber || settings.phoneNumber;
      settings.email = email || settings.email;
      settings.updatedAt = new Date();
      
      await settings.save();
    }
    
    res.status(200).json({
      success: true,
      settings
    });
  } catch (err) {
    console.error('Error updating settings:', err);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: err.message
    });
  }
});

// Upload settings logo
app.post('/api/admin/settings/logo', dbMiddleware, async (req, res) => {
  try {
    const { logoUrl } = req.body;
    
    if (!logoUrl) {
      return res.status(400).json({
        success: false,
        message: 'Logo URL is required'
      });
    }
    
    // Find settings, or create default if none exists
    let settings = await Settings.findOne();
    
    if (!settings) {
      settings = await Settings.create({
        logoUrl,
        updatedAt: new Date()
      });
    } else {
      // Update logo URL
      settings.logoUrl = logoUrl;
      settings.updatedAt = new Date();
      
      await settings.save();
    }
    
    res.status(200).json({
      success: true,
      settings
    });
  } catch (err) {
    console.error('Error updating settings logo:', err);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: err.message
    });
  }
});

// Update student status (activate/deactivate)
app.put('/api/admin/students/:studentId/status', dbMiddleware, async (req, res) => {
  try {
    const { studentId } = req.params;
    const { isActive } = req.body;
    
    console.log(`Attempting to update student status: ID=${studentId}, isActive=${isActive}`);
    
    if (isActive === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Active status is required'
      });
    }

    // Try different ways to find the student
    let student = null;
    
    // Try to find by MongoDB _id if it's a valid ObjectId
    if (mongoose.Types.ObjectId.isValid(studentId)) {
      console.log('Looking up student by valid ObjectId');
      student = await Student.findById(studentId);
    }
    
    // If not found, try to find by student_id field
    if (!student) {
      console.log('Looking up student by student_id field');
      student = await Student.findOne({ student_id: studentId });
    }
    
    // If still not found, try with string ID
    if (!student) {
      console.log('Trying to find student with string ID conversion');
      student = await Student.findOne({ _id: studentId.toString() });
    }
    
    if (!student) {
      console.log('Student not found with any ID format');
      return res.status(404).json({
        success: false,
        message: 'Student not found'
      });
    }
    
    console.log(`Found student: ${student.fname} ${student.lname}, updating isActive to ${isActive}`);
    
    // Add isActive field to the student schema if it doesn't exist
    student.isActive = isActive;
    await student.save();
    
    console.log('Student status updated successfully');
    
    res.status(200).json({
      success: true,
      message: `Student ${isActive ? 'activated' : 'deactivated'} successfully`,
      student: {
        id: student._id,
        firstName: student.fname,
        lastName: student.lname,
        email: student.university_email,
        studentId: student.student_id,
        isActive: student.isActive
      }
    });
    
  } catch (err) {
    console.error('Error updating student status:', err);
    console.error('Error stack:', err.stack);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: err.message
    });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
  console.log('Available routes:');
  console.log('GET /api/test');
  console.log('POST /api/register');
  console.log('POST /api/login');
  console.log('GET /api/user/:id');
  console.log('PUT /api/update-profile/:id');
  console.log('POST /api/admin/login');
  console.log('GET /api/admin/students');
  console.log('GET /api/admin/appointments');
  console.log('GET /api/admin/appointments/today');
  console.log('GET /api/admin/settings');
  console.log('PUT /api/admin/settings');
  console.log('POST /api/admin/settings/logo');
  console.log('POST /api/doctors');
  console.log('GET /api/doctors');
  console.log('POST /api/appointments');
  console.log('GET /api/appointments/queue-numbers/:date');
  console.log('GET /api/student/appointments/:studentId');
  console.log('POST /api/doctor/login');
  console.log('GET /api/doctor/appointments/:doctorId');
  console.log('GET /api/doctor/called-patients/:doctorId');
  console.log('POST /api/students');
  console.log('GET /api/student/notifications/:studentId');
  console.log('PUT /api/student/notifications/:notificationId/read');
  console.log('PUT /api/student/notifications/:notificationId/unread');
  console.log('DELETE /api/student/notifications/:notificationId');
  console.log('\nIMPORTANT: Make sure MongoDB is running before using database features');
}); 
// Required Modules
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
require('dotenv').config();

// Express App Initialization
const app = express();

// Middleware Setup
app.use(helmet()); // Secure HTTP headers
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true // Allow cookies and authentication headers
}));

// General Rate Limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use(limiter);

// Specific Limiter for Registration Endpoint
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: 'Too many registration attempts, please try again later.'
});

// Parsing Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/nagarBrahminDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ MongoDB connected successfully');
  console.log(`📊 Database: ${mongoose.connection.name}`);
})
.catch((err) => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Mongoose Member Schema
const memberSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Name is required'],
    trim: true,
    minlength: [2, 'Name must be at least 2 characters long'],
    maxlength: [50, 'Name cannot exceed 50 characters']
  },
  email: { 
    type: String, 
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    validate: [validator.isEmail, 'Please provide valid email']
  },
  phone: { 
    type: String, 
    required: [true, 'Phone number is required'],
    trim: true,
    validate: {
      validator: v => /^[+]?[\d\s\-\(\)]{10,15}$/.test(v),
      message: 'Please provide a valid phone number'
    }
  },
  status: {
    type: String,
    enum: ['active', 'inactive', 'pending'],
    default: 'active'
  },
  membershipType: {
    type: String,
    enum: ['regular', 'life', 'patron'],
    default: 'regular'
  },
  address: {
    street: String,
    city: String,
    state: String,
    pincode: String
  },
  dateOfBirth: Date,
  occupation: String,
}, {
  timestamps: true
});

// Indexes
memberSchema.index({ email: 1 });
memberSchema.index({ phone: 1 });
memberSchema.index({ createdAt: -1 });

const Member = mongoose.model('Member', memberSchema);

// Health Check Route
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

// Register Member Route
app.post('/api/members/register', registerLimiter, async (req, res) => {
  try {
    const { name, email, phone, address, dateOfBirth, occupation, membershipType } = req.body;

    if (!name || !email || !phone) {
      return res.status(400).json({ 
        error: 'Name, email, and phone are required fields.',
        code: 'MISSING_REQUIRED_FIELDS'
      });
    }

    const existingMember = await Member.findOne({
      $or: [
        { email: email.toLowerCase() },
        { phone: phone.trim() }
      ]
    });

    if (existingMember) {
      return res.status(409).json({ 
        error: 'Member with this email or phone already exists.',
        code: 'DUPLICATE_MEMBER'
      });
    }

    const newMember = new Member({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      phone: phone.trim(),
      membershipType: membershipType || 'regular',
      address,
      dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : undefined,
      occupation: occupation?.trim()
    });

    await newMember.save();

    res.status(201).json({ 
      message: 'Member registered successfully.',
      memberId: newMember._id,
      membershipType: newMember.membershipType
    });
  } catch (err) {
    console.error('Registration error:', err);

    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ 
        error: 'Validation failed',
        details: errors,
        code: 'VALIDATION_ERROR'
      });
    }

    res.status(500).json({ 
      error: 'Internal server error. Please try again later.',
      code: 'SERVER_ERROR'
    });
  }
});

// Fetch All Members (with pagination and filters)
app.get('/api/members', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;

    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.membershipType) filter.membershipType = req.query.membershipType;

    const members = await Member.find(filter)
      .select('-__v')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Member.countDocuments(filter);

    res.json({
      members,
      pagination: {
        current: page,
        pages: Math.ceil(total / limit),
        total,
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    });
  } catch (err) {
    console.error('Get members error:', err);
    res.status(500).json({ error: 'Failed to fetch members', code: 'FETCH_ERROR' });
  }
});

// Get Member By ID
app.get('/api/members/:id', async (req, res) => {
  try {
    const member = await Member.findById(req.params.id).select('-__v');

    if (!member) {
      return res.status(404).json({ error: 'Member not found', code: 'MEMBER_NOT_FOUND' });
    }

    res.json(member);
  } catch (err) {
    if (err.name === 'CastError') {
      return res.status(400).json({ error: 'Invalid member ID format', code: 'INVALID_ID' });
    }
    res.status(500).json({ error: 'Failed to fetch member', code: 'FETCH_ERROR' });
  }
});

// Update Member By ID
app.put('/api/members/:id', async (req, res) => {
  try {
    const updates = { ...req.body, updatedAt: new Date() };
    delete updates._id;

    const member = await Member.findByIdAndUpdate(req.params.id, updates, {
      new: true,
      runValidators: true
    }).select('-__v');

    if (!member) {
      return res.status(404).json({ error: 'Member not found', code: 'MEMBER_NOT_FOUND' });
    }

    res.json({ message: 'Member updated successfully', member });
  } catch (err) {
    if (err.name === 'ValidationError') {
      const errors = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ error: 'Validation failed', details: errors, code: 'VALIDATION_ERROR' });
    }
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Email or phone already exists', code: 'DUPLICATE_MEMBER' });
    }
    res.status(500).json({ error: 'Failed to update member', code: 'UPDATE_ERROR' });
  }
});

// Delete Member By ID
app.delete('/api/members/:id', async (req, res) => {
  try {
    const member = await Member.findByIdAndDelete(req.params.id);

    if (!member) {
      return res.status(404).json({ error: 'Member not found', code: 'MEMBER_NOT_FOUND' });
    }

    res.json({ message: 'Member deleted successfully', deletedMember: member });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete member', code: 'DELETE_ERROR' });
  }
});

// Membership Stats
app.get('/api/stats', async (req, res) => {
  try {
    const total = await Member.countDocuments();

    const byStatus = await Member.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);

    const byMembershipType = await Member.aggregate([
      { $group: { _id: '$membershipType', count: { $sum: 1 } } }
    ]);

    res.json({
      total,
      byStatus: Object.fromEntries(byStatus.map(i => [i._id, i.count])),
      byMembershipType: Object.fromEntries(byMembershipType.map(i => [i._id, i.count]))
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch statistics', code: 'STATS_ERROR' });
  }
});

// Fallback Route
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found', code: 'NOT_FOUND' });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  res.status(500).json({ error: 'Something went wrong!', code: 'INTERNAL_ERROR' });
});

// Graceful Shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});

// Server Listener
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📝 Health check at http://localhost:${PORT}/api/health`);
});

// server.js

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
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// General Rate Limiter
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.'
}));

// Specific Limiter for Registration Endpoint
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: 'Too many registration attempts, please try again later.'
});

// Parsing Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/nagarBrahminDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB connected'))
.catch(err => {
  console.error('❌ MongoDB error:', err);
  process.exit(1);
});

// Mongoose Schema and Model
const memberSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Name is required'],
    trim: true,
    minlength: 2,
    maxlength: 50
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    validate: [validator.isEmail, 'Invalid email']
  },
  phone: {
    type: String,
    required: true,
    trim: true,
    validate: {
      validator: v => /^[+]?\d{10,15}$/.test(v),
      message: 'Invalid phone number'
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
  occupation: String
}, { timestamps: true });

memberSchema.index({ email: 1 });
memberSchema.index({ phone: 1 });
memberSchema.index({ createdAt: -1 });

const Member = mongoose.model('Member', memberSchema);

// Routes

app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
  });
});

app.post('/api/members/register', registerLimiter, async (req, res) => {
  try {
    const { name, email, phone, address, dateOfBirth, occupation, membershipType } = req.body;

    if (!name || !email || !phone) {
      return res.status(400).json({ error: 'Name, email, and phone are required.', code: 'MISSING_FIELDS' });
    }

    const exists = await Member.findOne({ $or: [{ email }, { phone }] });
    if (exists) return res.status(409).json({ error: 'Email or phone exists.', code: 'DUPLICATE' });

    const member = new Member({
      name, email, phone, address, dateOfBirth, occupation, membershipType
    });

    await member.save();
    res.status(201).json({ message: 'Registered successfully', memberId: member._id });
  } catch (err) {
    console.error('Register error:', err);
    if (err.name === 'ValidationError') {
      const details = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ error: 'Validation failed', details });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/members', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.membershipType) filter.membershipType = req.query.membershipType;

    const [members, total] = await Promise.all([
      Member.find(filter).select('-__v').sort({ createdAt: -1 }).skip(skip).limit(limit),
      Member.countDocuments(filter)
    ]);

    res.json({
      members,
      pagination: {
        current: page,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page * limit < total,
        hasPrev: page > 1
      }
    });
  } catch (err) {
    console.error('Fetch members error:', err);
    res.status(500).json({ error: 'Failed to fetch members' });
  }
});

app.get('/api/members/:id', async (req, res) => {
  try {
    const member = await Member.findById(req.params.id).select('-__v');
    if (!member) return res.status(404).json({ error: 'Member not found' });
    res.json(member);
  } catch (err) {
    if (err.name === 'CastError') return res.status(400).json({ error: 'Invalid ID' });
    res.status(500).json({ error: 'Failed to fetch member' });
  }
});

app.put('/api/members/:id', async (req, res) => {
  try {
    const updates = req.body;
    delete updates._id;

    const member = await Member.findByIdAndUpdate(req.params.id, updates, {
      new: true,
      runValidators: true
    }).select('-__v');

    if (!member) return res.status(404).json({ error: 'Member not found' });
    res.json({ message: 'Updated successfully', member });
  } catch (err) {
    if (err.name === 'ValidationError') {
      const details = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ error: 'Validation error', details });
    }
    if (err.code === 11000) return res.status(409).json({ error: 'Duplicate entry' });
    res.status(500).json({ error: 'Update failed' });
  }
});

app.delete('/api/members/:id', async (req, res) => {
  try {
    const member = await Member.findByIdAndDelete(req.params.id);
    if (!member) return res.status(404).json({ error: 'Member not found' });
    res.json({ message: 'Deleted successfully', deletedMember: member });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const total = await Member.countDocuments();
    const byStatus = await Member.aggregate([{ $group: { _id: '$status', count: { $sum: 1 } } }]);
    const byMembershipType = await Member.aggregate([{ $group: { _id: '$membershipType', count: { $sum: 1 } } }]);

    res.json({
      total,
      byStatus: Object.fromEntries(byStatus.map(i => [i._id, i.count])),
      byMembershipType: Object.fromEntries(byMembershipType.map(i => [i._id, i.count]))
    });
  } catch (err) {
    res.status(500).json({ error: 'Stats fetch error' });
  }
});

// Fallback Route
app.use('*', (req, res) => res.status(404).json({ error: 'Route not found' }));

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Graceful Shutdown
process.on('SIGTERM', async () => {
  console.log('Shutting down...');
  await mongoose.connection.close();
  process.exit(0);
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});

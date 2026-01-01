require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const app = express();

app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ai_music_db');

// GridFS setup using mongoose
let bucket;
const conn = mongoose.connection;
conn.once('open', () => {
  bucket = new mongoose.mongo.GridFSBucket(conn.db, {
    bucketName: 'uploads'
  });
});

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow only image files
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// User Schema
const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 20
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 20
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    maxlength: 30
  },
  password: {
    type: String,
    required: true,
    minlength: 8,
    maxlength: 30
  },
  displayName: {
    type: String,
    trim: true,
    maxlength: 50
  },
  location: {
    type: String,
    trim: true,
    maxlength: 100
  },
  country: {
    type: String,
    trim: true,
    maxlength: 50
  },
  biography: {
    type: String,
    trim: true,
    maxlength: 500
  },
  profilePicture: {
    type: String,
    trim: true
  },
  socialLinks: {
    facebook: { type: String, trim: true },
    twitter: { type: String, trim: true },
    instagram: { type: String, trim: true },
    youtube: { type: String, trim: true },
    linkedin: { type: String, trim: true },
    website: { type: String, trim: true }
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

// Track Schema
const trackSchema = new mongoose.Schema({
  trackName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  trackId: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  bpm: {
    type: Number,
    min: 1,
    max: 300
  },
  trackKey: {
    type: String,
    trim: true
  },
  trackPrice: {
    type: Number,
    min: 0,
    default: 0
  },
  musician: {
    type: String,
    trim: true,
    maxlength: 100
  },
  musicianProfilePicture: {
    type: String,
    trim: true
  },
  trackType: {
    type: String,
    required: true,
    trim: true
  },
  moodType: {
    type: String,
    trim: true
  },
  energyType: {
    type: String,
    trim: true
  },
  instrument: {
    type: String,
    trim: true
  },
  generatedTrackPlatform: {
    type: String,
    trim: true
  },
  trackImage: {
    type: String,
    trim: true
  },
  trackFile: {
    type: String,
    trim: true
  },
  about: {
    type: String,
    trim: true,
    maxlength: 1000
  },
  publish: {
    type: String,
    default: 'Private',
    trim: true
  },
  genreCategory: {
    type: [String],
    default: []
  },
  beatCategory: {
    type: [String],
    default: []
  },
  trackTags: {
    type: [String],
    default: []
  },
  seoTitle: {
    type: String,
    trim: true,
    maxlength: 200
  },
  metaKeyword: {
    type: String,
    trim: true,
    maxlength: 500
  },
  metaDescription: {
    type: String,
    trim: true,
    maxlength: 500
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const Track = mongoose.model('Track', trackSchema);

// Genre Schema
const genreSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    unique: true,
    maxlength: 100
  },
  description: {
    type: String,
    trim: true,
    maxlength: 500
  },
  color: {
    type: String,
    trim: true,
    default: '#7ED7FF'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const Genre = mongoose.model('Genre', genreSchema);

// Beat Schema
const beatSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    unique: true,
    maxlength: 100
  },
  description: {
    type: String,
    trim: true,
    maxlength: 500
  },
  color: {
    type: String,
    trim: true,
    default: '#E100FF'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const Beat = mongoose.model('Beat', beatSchema);

// Tag Schema
const tagSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    unique: true,
    maxlength: 100
  },
  description: {
    type: String,
    trim: true,
    maxlength: 500
  },
  color: {
    type: String,
    trim: true,
    default: '#FF6B35'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const Tag = mongoose.model('Tag', tagSchema);

// Sound Kit Schema
const soundKitSchema = new mongoose.Schema({
  kitName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  kitId: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  description: {
    type: String,
    trim: true,
    maxlength: 1000
  },
  category: {
    type: String,
    trim: true
  },
  price: {
    type: Number,
    min: 0,
    default: 0
  },
  producer: {
    type: String,
    trim: true,
    maxlength: 100
  },
  musician: {
    type: String,
    trim: true,
    maxlength: 100
  },
  musicianProfilePicture: {
    type: String,
    trim: true
  },
  kitType: {
    type: String,
    trim: true
  },
  bpm: {
    type: Number,
    min: 1,
    max: 300
  },
  key: {
    type: String,
    trim: true
  },
  kitImage: {
    type: String,
    trim: true
  },
  kitFile: {
    type: String,
    trim: true
  },
  tags: [{
    type: String,
    trim: true
  }],
  publish: {
    type: String,
    enum: ['Private', 'Public'],
    default: 'Private'
  },
  seoTitle: {
    type: String,
    trim: true,
    maxlength: 200
  },
  metaKeyword: {
    type: String,
    trim: true,
    maxlength: 500
  },
  metaDescription: {
    type: String,
    trim: true,
    maxlength: 500
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const SoundKit = mongoose.model('SoundKit', soundKitSchema);

// Sound Kit Category Schema
const soundKitCategorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  description: {
    type: String,
    trim: true,
    maxlength: 500
  },
  color: {
    type: String,
    default: '#E100FF',
    trim: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const SoundKitCategory = mongoose.model('SoundKitCategory', soundKitCategorySchema);

// Sound Kit Tag Schema
const soundKitTagSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  description: {
    type: String,
    trim: true,
    maxlength: 500
  },
  color: {
    type: String,
    default: '#FF6B35',
    trim: true
  },
  isActive: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const SoundKitTag = mongoose.model('SoundKitTag', soundKitTagSchema);

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
})
.then(() => {
    console.log('Connected to MongoDB');
})
.catch((error) => {
    console.error('MongoDB connection error:', error);
});

app.post('/api/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;
        
        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                message: 'User with this email already exists' 
            });
        }
        
        // Create new user
        const user = new User({ 
            firstName, 
            lastName, 
            email, 
            password // Note: In production, you should hash the password
        });
        
        await user.save();
        
        res.status(201).json({ 
            success: true, 
            message: 'User created successfully',
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                displayName: user.displayName || '',
                location: user.location || '',
                country: user.country || '',
                biography: user.biography || '',
                socialLinks: user.socialLinks || {
                    facebook: '',
                    twitter: '',
                    instagram: '',
                    youtube: '',
                    linkedin: '',
                    website: ''
                }
            }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

app.post('/api/signin', async (req, res) => {
    try {
    const { email, password } = req.body;
        
        // Find user by email or displayName (username)
        const user = await User.findOne({
            $or: [
                { email: email },
                { displayName: email }
            ]
        });
        if (!user) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email/username or password' 
            });
        }
        
        // Check password (in production, you should compare hashed passwords)
        if (user.password !== password) {
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid email or password' 
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Login successful',
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                displayName: user.displayName || '',
                location: user.location || '',
                country: user.country || '',
                biography: user.biography || '',
                socialLinks: user.socialLinks || {
                    facebook: '',
                    twitter: '',
                    instagram: '',
                    youtube: '',
                    linkedin: '',
                    website: ''
                }
            }
        });
    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Get single user by ID endpoint
app.get('/api/users/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        console.log('Get user request for ID:', userId);
        
        const user = await User.findById(userId);
        if (!user) {
            console.log('User not found:', userId);
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        console.log('User found:', { id: user._id, firstName: user.firstName, profilePicture: user.profilePicture });
        
        res.json({ 
            success: true, 
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                displayName: user.displayName,
                location: user.location,
                country: user.country,
                biography: user.biography,
                profilePicture: user.profilePicture,
                socialLinks: user.socialLinks,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

app.put('/api/profile/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { firstName, lastName, displayName, location, country, biography, profilePicture, socialLinks } = req.body;
        
        console.log('Profile update request for user:', userId);
        console.log('Profile data received:', { firstName, lastName, displayName, location, country, biography, profilePicture, socialLinks });
        
        const user = await User.findById(userId);
        if (!user) {
            console.log('User not found:', userId);
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        // Update user profile
        user.firstName = firstName || user.firstName;
        user.lastName = lastName || user.lastName;
        user.displayName = displayName || user.displayName;
        user.location = location || user.location;
        user.country = country || user.country;
        user.biography = biography || user.biography;
        user.profilePicture = profilePicture || user.profilePicture;
        user.socialLinks = socialLinks || user.socialLinks;
        
        console.log('Updated user profile picture:', user.profilePicture);
        
        await user.save();
        console.log('User profile saved successfully');
        
        res.json({ 
            success: true, 
            message: 'Profile updated successfully',
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                displayName: user.displayName,
                location: user.location,
                country: user.country,
                biography: user.biography,
                profilePicture: user.profilePicture,
                socialLinks: user.socialLinks
            }
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Get all users endpoint
app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find({}).select('-password'); // Exclude password field
        
        console.log('Get all users request - found', users.length, 'users');
        users.forEach(user => {
            console.log('User:', { id: user._id, firstName: user.firstName, email: user.email, profilePicture: user.profilePicture });
        });
        
        res.status(200).json({
            success: true,
            users: users.map(user => ({
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                displayName: user.displayName || '',
                location: user.location || '',
                country: user.country || '',
                biography: user.biography || '',
                profilePicture: user.profilePicture || '',
                socialLinks: user.socialLinks || {},
                createdAt: user.createdAt
            }))
        });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Update user endpoint
app.put('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const {
            firstName,
            lastName,
            email,
            displayName,
            location,
            country,
            biography
        } = req.body;

        // Check if user exists
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if email is being changed and if it already exists
        if (email && email !== user.email) {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Email already exists'
                });
            }
        }

        // Update user fields
        user.firstName = firstName || user.firstName;
        user.lastName = lastName || user.lastName;
        user.email = email || user.email;
        user.displayName = displayName !== undefined ? displayName : user.displayName;
        user.location = location !== undefined ? location : user.location;
        user.country = country !== undefined ? country : user.country;
        user.biography = biography !== undefined ? biography : user.biography;

        await user.save();

        res.status(200).json({
            success: true,
            message: 'User updated successfully',
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                displayName: user.displayName,
                location: user.location,
                country: user.country,
                biography: user.biography,
                socialLinks: user.socialLinks,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Delete user endpoint
app.delete('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;

        // Check if user exists
        const user = await User.findById(id);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Delete user
        await User.findByIdAndDelete(id);

        res.status(200).json({
            success: true,
            message: 'User deleted successfully'
        });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Create user endpoint (admin)
app.post('/api/users', async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            email,
            username,
            password,
            phone
        } = req.body;

        // Validate required fields
        if (!firstName || !lastName || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'First name, last name, email, and password are required'
            });
        }

        // Check if user with email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User with this email already exists'
            });
        }

        // Create new user
        const user = new User({
            firstName,
            lastName,
            email,
            password, // Note: In production, this should be hashed
            displayName: username || `${firstName} ${lastName}`,
            location: '',
            country: '',
            biography: '',
            socialLinks: {
                facebook: '',
                twitter: '',
                instagram: '',
                youtube: '',
                linkedin: '',
                website: ''
            }
        });

        await user.save();

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            user: {
                id: user._id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                displayName: user.displayName,
                location: user.location,
                country: user.country,
                biography: user.biography,
                socialLinks: user.socialLinks,
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Track creation endpoint
app.post('/api/tracks', async (req, res) => {
    try {
        console.log('Received track data:', req.body);
        
        const {
            trackName,
            trackId,
            bpm,
            trackKey,
            trackPrice,
            musician,
            trackType,
            moodType,
            energyType,
            instrument,
            generatedTrackPlatform,
            trackImage,
            trackFile,
            about,
            publish,
            genreCategory,
            beatCategory,
            trackTags,
            seoTitle,
            metaKeyword,
            metaDescription
        } = req.body;

        // Check if track with same trackId already exists
        const existingTrack = await Track.findOne({ trackId });
        if (existingTrack) {
            return res.status(400).json({
                success: false,
                message: 'Track with this ID already exists'
            });
        }

        // Create new track with proper data validation
        const trackData = {
            trackName: trackName || '',
            trackId: trackId || '',
            trackType: trackType || '',
            bpm: bpm && !isNaN(parseInt(bpm)) ? parseInt(bpm) : undefined,
            trackKey: trackKey || '',
            trackPrice: trackPrice && !isNaN(parseFloat(trackPrice)) ? parseFloat(trackPrice) : 0,
            musician: musician || '',
            moodType: moodType || '',
            energyType: energyType || '',
            instrument: instrument || '',
            generatedTrackPlatform: generatedTrackPlatform || '',
            trackImage: trackImage || '',
            trackFile: trackFile || '',
            about: about || '',
            publish: publish || 'Private',
            genreCategory: Array.isArray(genreCategory) ? genreCategory : [],
            beatCategory: Array.isArray(beatCategory) ? beatCategory : [],
            trackTags: Array.isArray(trackTags) ? trackTags : [],
            seoTitle: seoTitle || '',
            metaKeyword: metaKeyword || '',
            metaDescription: metaDescription || ''
        };

        console.log('Creating track with data:', trackData);
        
        const track = new Track(trackData);

        await track.save();

        res.status(201).json({
            success: true,
            message: 'Track created successfully',
            track: {
                id: track._id,
                trackName: track.trackName,
                trackId: track.trackId,
                bpm: track.bpm,
                trackKey: track.trackKey,
                trackPrice: track.trackPrice,
                musician: track.musician,
                trackType: track.trackType,
                moodType: track.moodType,
                energyType: track.energyType,
                instrument: track.instrument,
                generatedTrackPlatform: track.generatedTrackPlatform,
                trackImage: track.trackImage,
                trackFile: track.trackFile,
                about: track.about,
                publish: track.publish,
                genreCategory: track.genreCategory,
                beatCategory: track.beatCategory,
                trackTags: track.trackTags,
                seoTitle: track.seoTitle,
                metaKeyword: track.metaKeyword,
                metaDescription: track.metaDescription,
                createdAt: track.createdAt
            }
        });
    } catch (error) {
        console.error('Track creation error:', error);
        console.error('Error details:', {
            name: error.name,
            message: error.message,
            code: error.code,
            errors: error.errors
        });
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Get all tracks endpoint
app.get('/api/tracks', async (req, res) => {
    try {
        const tracks = await Track.find().sort({ createdAt: -1 });
        res.json({
            success: true,
            tracks: tracks
        });
    } catch (error) {
        console.error('Get tracks error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update track endpoint
app.put('/api/tracks/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = req.body;

        const track = await Track.findById(id);
        if (!track) {
            return res.status(404).json({
                success: false,
                message: 'Track not found'
            });
        }

        // Check if trackId is being changed and if it conflicts with existing track
        if (updateData.trackId && updateData.trackId !== track.trackId) {
            const existingTrack = await Track.findOne({ trackId: updateData.trackId, _id: { $ne: id } });
            if (existingTrack) {
                return res.status(400).json({
                    success: false,
                    message: 'Track with this ID already exists'
                });
            }
        }

        // Update track fields
        Object.keys(updateData).forEach(key => {
            if (updateData[key] !== undefined) {
                track[key] = updateData[key];
            }
        });

        track.updatedAt = new Date();
        await track.save();

        res.json({
            success: true,
            message: 'Track updated successfully',
            track: {
                id: track._id,
                trackName: track.trackName,
                trackId: track.trackId,
                bpm: track.bpm,
                trackKey: track.trackKey,
                trackPrice: track.trackPrice,
                musician: track.musician,
                trackType: track.trackType,
                moodType: track.moodType,
                energyType: track.energyType,
                instrument: track.instrument,
                generatedTrackPlatform: track.generatedTrackPlatform,
                trackImage: track.trackImage,
                trackFile: track.trackFile,
                about: track.about,
                publish: track.publish,
                genreCategory: track.genreCategory,
                beatCategory: track.beatCategory,
                trackTags: track.trackTags,
                seoTitle: track.seoTitle,
                metaKeyword: track.metaKeyword,
                metaDescription: track.metaDescription,
                updatedAt: track.updatedAt
            }
        });
    } catch (error) {
        console.error('Track update error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Delete track endpoint
app.delete('/api/tracks/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const track = await Track.findByIdAndDelete(id);
        if (!track) {
            return res.status(404).json({
                success: false,
                message: 'Track not found'
            });
        }

        res.json({
            success: true,
            message: 'Track deleted successfully'
        });
    } catch (error) {
        console.error('Track delete error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Genre API endpoints
app.post('/api/genres', async (req, res) => {
    try {
        console.log('Received genre data:', req.body);
        
        const { name, description, color } = req.body;

        // Check if genre with same name already exists
        const existingGenre = await Genre.findOne({ name: name.trim() });
        if (existingGenre) {
            return res.status(400).json({
                success: false,
                message: 'Genre with this name already exists'
            });
        }

        // Create new genre
        const genre = new Genre({
            name: name.trim(),
            description: description || '',
            color: color || '#7ED7FF'
        });

        await genre.save();

        res.status(201).json({
            success: true,
            message: 'Genre created successfully',
            genre: {
                id: genre._id,
                name: genre.name,
                description: genre.description,
                color: genre.color,
                isActive: genre.isActive,
                createdAt: genre.createdAt
            }
        });
    } catch (error) {
        console.error('Genre creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Get all genres endpoint
app.get('/api/genres', async (req, res) => {
    try {
        const genres = await Genre.find().sort({ name: 1 });
        res.json({
            success: true,
            genres: genres
        });
    } catch (error) {
        console.error('Get genres error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update genre endpoint
app.put('/api/genres/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, color, isActive } = req.body;

        const genre = await Genre.findById(id);
        if (!genre) {
            return res.status(404).json({
                success: false,
                message: 'Genre not found'
            });
        }

        // Check if name is being changed and if it conflicts with existing genre
        if (name && name.trim() !== genre.name) {
            const existingGenre = await Genre.findOne({ name: name.trim(), _id: { $ne: id } });
            if (existingGenre) {
                return res.status(400).json({
                    success: false,
                    message: 'Genre with this name already exists'
                });
            }
        }

        // Update genre
        genre.name = name ? name.trim() : genre.name;
        genre.description = description !== undefined ? description : genre.description;
        genre.color = color || genre.color;
        genre.isActive = isActive !== undefined ? isActive : genre.isActive;
        genre.updatedAt = new Date();

        await genre.save();

        res.json({
            success: true,
            message: 'Genre updated successfully',
            genre: {
                id: genre._id,
                name: genre.name,
                description: genre.description,
                color: genre.color,
                isActive: genre.isActive,
                updatedAt: genre.updatedAt
            }
        });
    } catch (error) {
        console.error('Genre update error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Delete genre endpoint (hard delete)
app.delete('/api/genres/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const genre = await Genre.findByIdAndDelete(id);
        if (!genre) {
            return res.status(404).json({
                success: false,
                message: 'Genre not found'
            });
        }

        res.json({
            success: true,
            message: 'Genre deleted successfully'
        });
    } catch (error) {
        console.error('Genre delete error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Beat API endpoints
app.post('/api/beats', async (req, res) => {
    try {
        console.log('Received beat data:', req.body);
        
        const { name, description, color } = req.body;

        // Check if beat with same name already exists
        const existingBeat = await Beat.findOne({ name: name.trim() });
        if (existingBeat) {
            return res.status(400).json({
                success: false,
                message: 'Beat with this name already exists'
            });
        }

        // Create new beat
        const beat = new Beat({
            name: name.trim(),
            description: description || '',
            color: color || '#E100FF'
        });

        await beat.save();

        res.status(201).json({
            success: true,
            message: 'Beat created successfully',
            beat: {
                id: beat._id,
                name: beat.name,
                description: beat.description,
                color: beat.color,
                isActive: beat.isActive,
                createdAt: beat.createdAt
            }
        });
    } catch (error) {
        console.error('Beat creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Get all beats endpoint
app.get('/api/beats', async (req, res) => {
    try {
        const beats = await Beat.find().sort({ name: 1 });
        res.json({
            success: true,
            beats: beats
        });
    } catch (error) {
        console.error('Get beats error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update beat endpoint
app.put('/api/beats/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, color, isActive } = req.body;

        const beat = await Beat.findById(id);
        if (!beat) {
            return res.status(404).json({
                success: false,
                message: 'Beat not found'
            });
        }

        // Check if name is being changed and if it conflicts with existing beat
        if (name && name.trim() !== beat.name) {
            const existingBeat = await Beat.findOne({ name: name.trim(), _id: { $ne: id } });
            if (existingBeat) {
                return res.status(400).json({
                    success: false,
                    message: 'Beat with this name already exists'
                });
            }
        }

        // Update beat
        beat.name = name ? name.trim() : beat.name;
        beat.description = description !== undefined ? description : beat.description;
        beat.color = color || beat.color;
        beat.isActive = isActive !== undefined ? isActive : beat.isActive;
        beat.updatedAt = new Date();

        await beat.save();

        res.json({
            success: true,
            message: 'Beat updated successfully',
            beat: {
                id: beat._id,
                name: beat.name,
                description: beat.description,
                color: beat.color,
                isActive: beat.isActive,
                updatedAt: beat.updatedAt
            }
        });
    } catch (error) {
        console.error('Beat update error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Delete beat endpoint (hard delete)
app.delete('/api/beats/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const beat = await Beat.findByIdAndDelete(id);
        if (!beat) {
            return res.status(404).json({
                success: false,
                message: 'Beat not found'
            });
        }

        res.json({
            success: true,
            message: 'Beat deleted successfully'
        });
    } catch (error) {
        console.error('Beat delete error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Tag API endpoints
app.post('/api/tags', async (req, res) => {
    try {
        console.log('Received tag data:', req.body);
        
        const { name, description, color } = req.body;

        // Check if tag with same name already exists
        const existingTag = await Tag.findOne({ name: name.trim() });
        if (existingTag) {
            return res.status(400).json({
                success: false,
                message: 'Tag with this name already exists'
            });
        }

        // Create new tag
        const tag = new Tag({
            name: name.trim(),
            description: description || '',
            color: color || '#FF6B35'
        });

        await tag.save();

        res.status(201).json({
            success: true,
            message: 'Tag created successfully',
            tag: {
                id: tag._id,
                name: tag.name,
                description: tag.description,
                color: tag.color,
                isActive: tag.isActive,
                createdAt: tag.createdAt
            }
        });
    } catch (error) {
        console.error('Tag creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Get all tags endpoint
app.get('/api/tags', async (req, res) => {
    try {
        const tags = await Tag.find().sort({ name: 1 });
        res.json({
            success: true,
            tags: tags
        });
    } catch (error) {
        console.error('Get tags error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update tag endpoint
app.put('/api/tags/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, color, isActive } = req.body;

        const tag = await Tag.findById(id);
        if (!tag) {
            return res.status(404).json({
                success: false,
                message: 'Tag not found'
            });
        }

        // Check if name is being changed and if it conflicts with existing tag
        if (name && name.trim() !== tag.name) {
            const existingTag = await Tag.findOne({ name: name.trim(), _id: { $ne: id } });
            if (existingTag) {
                return res.status(400).json({
                    success: false,
                    message: 'Tag with this name already exists'
                });
            }
        }

        // Update tag
        tag.name = name ? name.trim() : tag.name;
        tag.description = description !== undefined ? description : tag.description;
        tag.color = color || tag.color;
        tag.isActive = isActive !== undefined ? isActive : tag.isActive;
        tag.updatedAt = new Date();

        await tag.save();

        res.json({
            success: true,
            message: 'Tag updated successfully',
            tag: {
                id: tag._id,
                name: tag.name,
                description: tag.description,
                color: tag.color,
                isActive: tag.isActive,
                updatedAt: tag.updatedAt
            }
        });
    } catch (error) {
        console.error('Tag update error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Delete tag endpoint (hard delete)
app.delete('/api/tags/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const tag = await Tag.findByIdAndDelete(id);
        if (!tag) {
            return res.status(404).json({
                success: false,
                message: 'Tag not found'
            });
        }

        res.json({
            success: true,
            message: 'Tag deleted successfully'
        });
    } catch (error) {
        console.error('Tag delete error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Sound Kit API endpoints
app.post('/api/sound-kits', async (req, res) => {
    try {
        console.log('Received sound kit data:', req.body);
        
        const {
            kitName,
            kitId,
            description,
            category,
            price,
            producer,
            kitType,
            bpm,
            key,
            kitImage,
            kitFile,
            tags,
            publish,
            seoTitle,
            metaKeyword,
            metaDescription
        } = req.body;

        // Check if sound kit with same kitId already exists
        const existingSoundKit = await SoundKit.findOne({ kitId });
        if (existingSoundKit) {
            return res.status(400).json({
                success: false,
                message: 'Sound kit with this ID already exists'
            });
        }

        // Create new sound kit with proper data validation
        const soundKitData = {
            kitName: kitName || '',
            kitId: kitId || '',
            description: description || '',
            category: category || '',
            price: price && !isNaN(parseFloat(price)) ? parseFloat(price) : 0,
            producer: producer || '',
            kitType: kitType || '',
            bpm: bpm && !isNaN(parseInt(bpm)) ? parseInt(bpm) : undefined,
            key: key || '',
            kitImage: kitImage || '',
            kitFile: kitFile || '',
            tags: tags || [],
            publish: publish || 'Private',
            seoTitle: seoTitle || '',
            metaKeyword: metaKeyword || '',
            metaDescription: metaDescription || ''
        };

        console.log('Kit image being stored:', kitImage);

        console.log('Creating sound kit with data:', soundKitData);
        
        const soundKit = new SoundKit(soundKitData);

        await soundKit.save();

        res.status(201).json({
            success: true,
            message: 'Sound kit created successfully',
            soundKit: {
                id: soundKit._id,
                kitName: soundKit.kitName,
                kitId: soundKit.kitId,
                description: soundKit.description,
                category: soundKit.category,
                price: soundKit.price,
                producer: soundKit.producer,
                kitType: soundKit.kitType,
                bpm: soundKit.bpm,
                key: soundKit.key,
                kitImage: soundKit.kitImage,
                kitFile: soundKit.kitFile,
                tags: soundKit.tags,
                publish: soundKit.publish,
                seoTitle: soundKit.seoTitle,
                metaKeyword: soundKit.metaKeyword,
                metaDescription: soundKit.metaDescription,
                createdAt: soundKit.createdAt
            }
        });
    } catch (error) {
        console.error('Sound kit creation error:', error);
        console.error('Error details:', {
            name: error.name,
            message: error.message,
            code: error.code,
            errors: error.errors
        });
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            details: error.message
        });
    }
});

// Get all sound kits endpoint
app.get('/api/sound-kits', async (req, res) => {
    try {
        const soundKits = await SoundKit.find({ isActive: true }).sort({ createdAt: -1 });
        res.json({
            success: true,
            soundKits: soundKits
        });
    } catch (error) {
        console.error('Get sound kits error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update sound kit endpoint
app.put('/api/sound-kits/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = req.body;

        const soundKit = await SoundKit.findById(id);
        if (!soundKit) {
            return res.status(404).json({
                success: false,
                message: 'Sound kit not found'
            });
        }

        // Update fields if provided
        Object.keys(updateData).forEach(key => {
            if (updateData[key] !== undefined) {
                soundKit[key] = updateData[key];
            }
        });
        
        soundKit.updatedAt = new Date();
        await soundKit.save();

        res.json({
            success: true,
            message: 'Sound kit updated successfully',
            soundKit: soundKit
        });
    } catch (error) {
        console.error('Update sound kit error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Delete sound kit endpoint
app.delete('/api/sound-kits/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const soundKit = await SoundKit.findById(id);
        if (!soundKit) {
            return res.status(404).json({
                success: false,
                message: 'Sound kit not found'
            });
        }

        await SoundKit.findByIdAndDelete(id);

        res.json({
            success: true,
            message: 'Sound kit deleted successfully'
        });
    } catch (error) {
        console.error('Delete sound kit error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Sound Kit Category API endpoints
app.post('/api/sound-kit-categories', async (req, res) => {
    try {
        const { name, description, color } = req.body;

        if (!name) {
            return res.status(400).json({
                success: false,
                message: 'Category name is required'
            });
        }

        const category = new SoundKitCategory({
            name: name.trim(),
            description: description || '',
            color: color || '#00D4FF'
        });

        await category.save();

        res.status(201).json({
            success: true,
            message: 'Sound kit category created successfully',
            category: {
                id: category._id,
                name: category.name,
                description: category.description,
                color: category.color,
                isActive: category.isActive,
                createdAt: category.createdAt
            }
        });
    } catch (error) {
        console.error('Create sound kit category error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.get('/api/sound-kit-categories', async (req, res) => {
    try {
        const categories = await SoundKitCategory.find().sort({ createdAt: -1 });
        res.json({
            success: true,
            categories: categories
        });
    } catch (error) {
        console.error('Get sound kit categories error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.put('/api/sound-kit-categories/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, color, isActive } = req.body;

        const category = await SoundKitCategory.findById(id);
        if (!category) {
            return res.status(404).json({
                success: false,
                message: 'Category not found'
            });
        }

        if (name) category.name = name.trim();
        if (description !== undefined) category.description = description;
        if (color) category.color = color;
        if (isActive !== undefined) category.isActive = isActive;
        category.updatedAt = new Date();

        await category.save();

        res.json({
            success: true,
            message: 'Sound kit category updated successfully',
            category: {
                id: category._id,
                name: category.name,
                description: category.description,
                color: category.color,
                isActive: category.isActive,
                updatedAt: category.updatedAt
            }
        });
    } catch (error) {
        console.error('Update sound kit category error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.delete('/api/sound-kit-categories/:id', async (req, res) => {
    try {
        const { id } = req.params;
        console.log('Backend: Received delete request for sound kit category ID:', id);

        const category = await SoundKitCategory.findById(id);
        console.log('Backend: Found category:', category);
        
        if (!category) {
            console.log('Backend: Category not found');
            return res.status(404).json({
                success: false,
                message: 'Category not found'
            });
        }

        // Hard delete - actually remove from MongoDB
        await SoundKitCategory.findByIdAndDelete(id);
        console.log('Backend: Category permanently deleted from MongoDB');

        res.json({
            success: true,
            message: 'Sound kit category deleted successfully'
        });
    } catch (error) {
        console.error('Delete sound kit category error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Sound Kit Tag API endpoints
app.post('/api/sound-kit-tags', async (req, res) => {
    try {
        const { name, description, color } = req.body;

        if (!name) {
            return res.status(400).json({
                success: false,
                message: 'Tag name is required'
            });
        }

        const tag = new SoundKitTag({
            name: name.trim(),
            description: description || '',
            color: color || '#FF6B35'
        });

        await tag.save();

        res.status(201).json({
            success: true,
            message: 'Sound kit tag created successfully',
            tag: {
                id: tag._id,
                name: tag.name,
                description: tag.description,
                color: tag.color,
                isActive: tag.isActive,
                createdAt: tag.createdAt
            }
        });
    } catch (error) {
        console.error('Create sound kit tag error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.get('/api/sound-kit-tags', async (req, res) => {
    try {
        const tags = await SoundKitTag.find().sort({ createdAt: -1 });
        res.json({
            success: true,
            tags: tags
        });
    } catch (error) {
        console.error('Get sound kit tags error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.put('/api/sound-kit-tags/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, color, isActive } = req.body;

        const tag = await SoundKitTag.findById(id);
        if (!tag) {
            return res.status(404).json({
                success: false,
                message: 'Tag not found'
            });
        }

        if (name) tag.name = name.trim();
        if (description !== undefined) tag.description = description;
        if (color) tag.color = color;
        if (isActive !== undefined) tag.isActive = isActive;
        tag.updatedAt = new Date();

        await tag.save();

        res.json({
            success: true,
            message: 'Sound kit tag updated successfully',
            tag: {
                id: tag._id,
                name: tag.name,
                description: tag.description,
                color: tag.color,
                isActive: tag.isActive,
                updatedAt: tag.updatedAt
            }
        });
    } catch (error) {
        console.error('Update sound kit tag error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.delete('/api/sound-kit-tags/:id', async (req, res) => {
    try {
        const { id } = req.params;
        console.log('Backend: Received delete request for sound kit tag ID:', id);

        const tag = await SoundKitTag.findById(id);
        console.log('Backend: Found tag:', tag);
        
        if (!tag) {
            console.log('Backend: Tag not found');
            return res.status(404).json({
                success: false,
                message: 'Tag not found'
            });
        }

        // Hard delete - actually remove from MongoDB
        await SoundKitTag.findByIdAndDelete(id);
        console.log('Backend: Tag permanently deleted from MongoDB');

        res.json({
            success: true,
            message: 'Sound kit tag deleted successfully'
        });
    } catch (error) {
        console.error('Delete sound kit tag error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// GridFS Image Upload Endpoint
app.post('/api/upload-image', upload.single('image'), async (req, res) => {
    try {
        console.log('Image upload request received');
        console.log('File info:', req.file ? { name: req.file.originalname, size: req.file.size, mimetype: req.file.mimetype } : 'No file');
        
        if (!req.file) {
            console.log('No image file provided');
            return res.status(400).json({
                success: false,
                message: 'No image file provided'
            });
        }

        // Create a readable stream from the buffer
        const readableStream = new require('stream').Readable();
        readableStream.push(req.file.buffer);
        readableStream.push(null);

        // Upload to GridFS
        const uploadStream = bucket.openUploadStream(req.file.originalname, {
            metadata: {
                contentType: req.file.mimetype,
                originalName: req.file.originalname,
                uploadedAt: new Date()
            }
        });

        // Pipe the file to GridFS
        readableStream.pipe(uploadStream);

        uploadStream.on('error', (error) => {
            console.error('GridFS upload error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to upload image'
            });
        });

        uploadStream.on('finish', () => {
            const imageUrl = `${req.protocol}://${req.get('host')}/api/image/${uploadStream.id}`;
            console.log('Image uploaded successfully to GridFS');
            console.log('File ID:', uploadStream.id);
            console.log('Image URL:', imageUrl);
            
            res.json({
                success: true,
                message: 'Image uploaded successfully',
                fileId: uploadStream.id,
                imageUrl: imageUrl,
                filename: req.file.originalname,
                contentType: req.file.mimetype
            });
        });

    } catch (error) {
        console.error('Upload image error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// GridFS Image Download Endpoint
app.get('/api/image/:fileId', async (req, res) => {
    try {
        const { fileId } = req.params;
        
        if (!mongoose.Types.ObjectId.isValid(fileId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid file ID'
            });
        }

        // Find the file in GridFS
        const files = bucket.find({ _id: new mongoose.Types.ObjectId(fileId) });
        const fileArray = await files.toArray();

        if (fileArray.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Image not found'
            });
        }

        const file = fileArray[0];
        
        // Set appropriate headers
        res.set({
            'Content-Type': file.metadata?.contentType || 'image/jpeg',
            'Content-Length': file.length,
            'Content-Disposition': `inline; filename="${file.metadata?.originalName || file.filename}"`
        });

        // Create download stream
        const downloadStream = bucket.openDownloadStream(new mongoose.Types.ObjectId(fileId));
        downloadStream.pipe(res);

    } catch (error) {
        console.error('Download image error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// GridFS Image Delete Endpoint
app.delete('/api/image/:fileId', async (req, res) => {
    try {
        const { fileId } = req.params;
        
        if (!mongoose.Types.ObjectId.isValid(fileId)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid file ID'
            });
        }

        // Delete from GridFS
        await bucket.delete(new mongoose.Types.ObjectId(fileId));

        res.json({
            success: true,
            message: 'Image deleted successfully'
        });

    } catch (error) {
        console.error('Delete image error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// GridFS List Images Endpoint
app.get('/api/images', async (req, res) => {
    try {
        const files = bucket.find({});
        const fileArray = await files.toArray();
        
        const images = fileArray.map(file => ({
            id: file._id,
            filename: file.filename,
            originalName: file.metadata?.originalName || file.filename,
            contentType: file.metadata?.contentType || 'image/jpeg',
            size: file.length,
            uploadedAt: file.metadata?.uploadedAt || file.uploadDate
        }));

        res.json({
            success: true,
            images: images
        });

    } catch (error) {
        console.error('List images error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get Musicians with Profile Pictures Endpoint
app.get('/api/musicians', async (req, res) => {
    try {
        // Aggregate tracks to get unique musicians with their profile pictures
        const musicians = await Track.aggregate([
            {
                $match: {
                    musician: { $exists: true, $ne: null, $ne: '' }
                }
            },
            {
                $group: {
                    _id: '$musician',
                    name: { $first: '$musician' },
                    profilePicture: { $first: '$musicianProfilePicture' },
                    trackCount: { $sum: 1 },
                    firstTrack: { $first: '$$ROOT' }
                }
            },
            {
                $sort: { name: 1 }
            }
        ]);

        res.json({
            success: true,
            musicians: musicians
        });

    } catch (error) {
        console.error('Get musicians error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get Specific Musician by ID Endpoint
app.get('/api/musicians/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Decode the URL parameter (musician name)
        const musicianName = decodeURIComponent(id);
        console.log('Looking for musician:', musicianName);
        
        // Find tracks by this musician name (exact match first, then case-insensitive)
        let tracks = await Track.find({ 
            musician: musicianName
        });
        
        // If no exact match, try case-insensitive search
        if (tracks.length === 0) {
            tracks = await Track.find({ 
                musician: { $regex: new RegExp(musicianName, 'i') }
            });
        }

        console.log('Found tracks:', tracks.length);

        if (tracks.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Musician not found'
            });
        }

        // Get musician details from first track
        const firstTrack = tracks[0];
        const musician = {
            _id: firstTrack.musician, // Use musician name as ID
            name: firstTrack.musician,
            profilePicture: firstTrack.musicianProfilePicture,
            bio: firstTrack.about || 'No bio available',
            country: firstTrack.country || 'Unknown',
            genre: firstTrack.genreCategory || 'Unknown',
            socialLinks: {
                website: firstTrack.website || '',
                instagram: firstTrack.instagram || '',
                twitter: firstTrack.twitter || '',
                youtube: firstTrack.youtube || ''
            },
            trackCount: tracks.length
        };

        console.log('Returning musician:', musician);

        res.json({
            success: true,
            musician: musician
        });

    } catch (error) {
        console.error('Get musician by ID error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', message: 'Server is running' });
});

// Test endpoint to check if tracks exist
app.get('/api/test-tracks', async (req, res) => {
    try {
        const tracks = await Track.find().limit(5);
        res.json({
            success: true,
            count: tracks.length,
            tracks: tracks.map(t => ({
                _id: t._id,
                trackName: t.trackName,
                musician: t.musician,
                musicianProfilePicture: t.musicianProfilePicture
            }))
        });
    } catch (error) {
        console.error('Test tracks error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.listen(3001, () => {
    console.log('Server is running on port 3001');
});
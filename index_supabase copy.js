require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const app = express();

app.use(cors());
app.use(express.json());

// Supabase client setup
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
    console.error('Missing Supabase configuration. Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your .env file');
    console.error('Example .env file:');
    console.error('SUPABASE_URL=https://yeoaploxakfvvcubyhaz.supabase.co');
    console.error('SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_here');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseServiceKey, {
    auth: {
        autoRefreshToken: false,
        persistSession: false
    }
});

// Email configuration
const emailTransporter = nodemailer.createTransport({
    service: 'gmail', // You can change this to other services like 'outlook', 'yahoo', etc.
    auth: {
        user: process.env.EMAIL_USER || 'your-email@gmail.com',
        pass: process.env.EMAIL_PASS || 'your-app-password' // Use App Password for Gmail
    }
});

// Helper function to send email
const sendEmail = async (to, subject, html) => {
    try {
        // Check if email credentials are configured
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS || 
            process.env.EMAIL_USER === 'your-email@gmail.com' || 
            process.env.EMAIL_PASS === 'your-app-password') {
            console.log('Email credentials not configured, skipping email send');
            return { success: false, error: 'Email credentials not configured' };
        }
        
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: to,
            subject: subject,
            html: html
        };
        
        const result = await emailTransporter.sendMail(mailOptions);
        console.log('Email sent successfully:', result.messageId);
        return { success: true, messageId: result.messageId };
    } catch (error) {
        console.error('Error sending email:', error);
        return { success: false, error: error.message };
    }
};

// S3-Compatible Storage Configuration
const STORAGE_BUCKET = 'uploads';
const STORAGE_ENDPOINT = 'https://yeoaploxakfvvcubyhaz.storage.supabase.co/storage/v1/s3';
const STORAGE_REGION = 'us-east-2';

console.log('Supabase Storage Configuration:');
console.log('- Bucket:', STORAGE_BUCKET);
console.log('- Endpoint:', STORAGE_ENDPOINT);
console.log('- Region:', STORAGE_REGION);

// Multer configuration for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit for audio/image files
  },
  fileFilter: (req, file, cb) => {
    // Allow image and audio files
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('audio/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image and audio files are allowed!'), false);
    }
  }
});

// Test Supabase connection and create storage bucket if needed
async function initializeStorage() {
    try {
        // Test database connection
        const { error: dbError } = await supabase.from('users').select('count', { count: 'exact', head: true });
        if (dbError) {
            console.error('Supabase database connection error:', dbError.message);
        } else {
            console.log('✅ Connected to Supabase database successfully');
        }

        // Test storage connection and create bucket if needed
        const { data: buckets, error: bucketsError } = await supabase.storage.listBuckets();
        if (bucketsError) {
            console.error('Supabase storage connection error:', bucketsError.message);
        } else {
            console.log('✅ Connected to Supabase storage successfully');
            
            // Check if uploads bucket exists
            const uploadsBucket = buckets.find(bucket => bucket.name === STORAGE_BUCKET);
            if (!uploadsBucket) {
                console.log(`Creating storage bucket: ${STORAGE_BUCKET}`);
                const { data: newBucket, error: createError } = await supabase.storage.createBucket(STORAGE_BUCKET, {
                    public: true,
                    allowedMimeTypes: ['image/*', 'audio/*'],
                    fileSizeLimit: 52428800 // 50MB
                });
                
                if (createError) {
                    console.error('Error creating storage bucket:', createError.message);
                } else {
                    console.log(`✅ Storage bucket '${STORAGE_BUCKET}' created successfully`);
                }
            } else {
                console.log(`✅ Storage bucket '${STORAGE_BUCKET}' already exists`);
            }
        }
    } catch (error) {
        console.error('Storage initialization error:', error);
    }
}

// Initialize storage on startup
initializeStorage();

// Helper function to handle database errors
const handleDatabaseError = (error, res, operation = 'operation') => {
    console.error(`Database ${operation} error:`, error);
    const statusCode = error.code === 'PGRST116' ? 404 : 500;
    res.status(statusCode).json({
        success: false,
        message: error.message || `Database ${operation} failed`
    });
};

// Helper function to convert snake_case to camelCase for response
const toCamelCase = (obj) => {
    if (!obj || typeof obj !== 'object') return obj;
    
    if (Array.isArray(obj)) {
        return obj.map(item => toCamelCase(item));
    }
    
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
        const camelKey = key.replace(/_([a-z])/g, (match, letter) => letter.toUpperCase());
        result[camelKey] = typeof value === 'object' ? toCamelCase(value) : value;
    }
    return result;
};

// Helper function to convert camelCase to snake_case for database
const toSnakeCase = (obj) => {
    if (!obj || typeof obj !== 'object') return obj;
    
    if (Array.isArray(obj)) {
        return obj.map(item => toSnakeCase(item));
    }
    
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
        const snakeKey = key.replace(/([A-Z])/g, (match, letter) => `_${letter.toLowerCase()}`);
        result[snakeKey] = typeof value === 'object' && !Array.isArray(value) ? toSnakeCase(value) : value;
    }
    return result;
};

// User Authentication APIs
app.post('/api/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;
        
        // Check if user already exists
        const { data: existingUser, error: checkError } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();
            
        if (existingUser) {
            return res.status(400).json({ 
                success: false, 
                message: 'User with this email already exists' 
            });
        }
        
        // Create new user
        const userData = {
            first_name: firstName,
            last_name: lastName,
            email,
            password, // Note: In production, you should hash the password
            social_links: {
                facebook: '',
                twitter: '',
                instagram: '',
                youtube: '',
                linkedin: '',
                website: ''
            }
        };
        
        const { data: user, error } = await supabase
            .from('users')
            .insert([userData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'signup');
        }
        
        res.status(201).json({ 
            success: true, 
            message: 'User created successfully',
            user: toCamelCase(user)
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
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .or(`email.eq.${email},display_name.eq.${email}`)
            .single();
            
        if (error || !user) {
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
            user: toCamelCase(user)
        });
    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Forgot Password API
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }
        
        // Check if user exists
        const { data: user, error } = await supabase
            .from('users')
            .select('id, email, first_name, last_name')
            .eq('email', email)
            .single();
            
        if (error || !user) {
            // For security, don't reveal if email exists or not
            return res.json({
                success: true,
                message: 'If an account with that email exists, password reset instructions have been sent.'
            });
        }
        
        // Generate a simple reset token (in production, use a more secure method)
        const resetToken = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
        const resetExpiry = new Date(Date.now() + 3600000); // 1 hour from now
        
        // Store reset token in database (with fallback if columns don't exist)
        const { error: updateError } = await supabase
            .from('users')
            .update({
                reset_token: resetToken,
                reset_token_expiry: resetExpiry.toISOString()
            })
            .eq('id', user.id);
            
        if (updateError) {
            console.error('Error storing reset token (columns may not exist):', updateError);
            // Store token in memory as fallback (for development)
            if (!global.resetTokens) {
                global.resetTokens = new Map();
            }
            global.resetTokens.set(resetToken, {
                userId: user.id,
                email: user.email,
                expiry: resetExpiry
            });
            console.log(`Reset token stored in memory for ${email}: ${resetToken}`);
        } else {
            console.log(`Reset token stored in database for ${email}: ${resetToken}`);
        }
        
        // Send password reset email
        const resetLink = `http://localhost:3000/user/pages/ResetPassword?token=${resetToken}`;
        
        const emailSubject = 'Reset Your Password - Museedle';
        const emailHtml = `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #4F46E5; margin: 0;">Museedle</h1>
                    <p style="color: #6B7280; margin: 5px 0;">Music Platform</p>
                </div>
                
                <div style="background: #F9FAFB; padding: 30px; border-radius: 8px; margin-bottom: 20px;">
                    <h2 style="color: #1F2937; margin: 0 0 20px 0;">Reset Your Password</h2>
                    <p style="color: #4B5563; line-height: 1.6; margin: 0 0 20px 0;">
                        Hello ${user.first_name || 'User'},
                    </p>
                    <p style="color: #4B5563; line-height: 1.6; margin: 0 0 20px 0;">
                        We received a request to reset your password for your Museedle account. Click the button below to reset your password:
                    </p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetLink}" 
                           style="background: #4F46E5; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: 600;">
                            Reset Password
                        </a>
                    </div>
                    
                    <p style="color: #6B7280; font-size: 14px; line-height: 1.6; margin: 20px 0 0 0;">
                        If the button doesn't work, you can copy and paste this link into your browser:
                    </p>
                    <p style="color: #4F46E5; font-size: 14px; word-break: break-all; margin: 5px 0 0 0;">
                        ${resetLink}
                    </p>
                </div>
                
                <div style="text-align: center; color: #6B7280; font-size: 12px;">
                    <p style="margin: 0 0 10px 0;">
                        This link will expire in 1 hour for security reasons.
                    </p>
                    <p style="margin: 0;">
                        If you didn't request this password reset, please ignore this email.
                    </p>
                </div>
            </div>
        `;
        
        // Send the email
        const emailResult = await sendEmail(email, emailSubject, emailHtml);
        
        if (emailResult.success) {
            console.log(`Password reset email sent successfully to ${email}`);
            res.json({
                success: true,
                message: 'Password reset instructions have been sent to your email address.'
            });
        } else {
            console.error('Failed to send password reset email:', emailResult.error);
            // For development, show the reset link in console and response
            console.log(`\n🔗 PASSWORD RESET LINK FOR ${email}:`);
            console.log(`   ${resetLink}`);
            console.log(`\n📧 Email not sent because credentials not configured.`);
            console.log(`   Add EMAIL_USER and EMAIL_PASS to .env file to enable email sending.\n`);
            
            res.json({
                success: true,
                message: 'Password reset link generated. Email not sent (credentials not configured). Check server console for the reset link.',
                resetLink: resetLink // Always include in development
            });
        }
        
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Reset Password API
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;
        
        if (!token || !password) {
            return res.status(400).json({
                success: false,
                message: 'Token and password are required'
            });
        }
        
        if (password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters long'
            });
        }
        
        // Find user by reset token (try database first, then memory fallback)
        let user = null;
        let tokenData = null;
        
        // Try database first
        const { data: dbUser, error: userError } = await supabase
            .from('users')
            .select('id, reset_token, reset_token_expiry')
            .eq('reset_token', token)
            .single();
            
        if (dbUser && !userError) {
            user = dbUser;
            tokenData = {
                userId: user.id,
                expiry: new Date(user.reset_token_expiry)
            };
        } else {
            // Fallback to memory storage
            if (global.resetTokens && global.resetTokens.has(token)) {
                tokenData = global.resetTokens.get(token);
                const { data: memoryUser } = await supabase
                    .from('users')
                    .select('id')
                    .eq('id', tokenData.userId)
                    .single();
                if (memoryUser) {
                    user = memoryUser;
                }
            }
        }
        
        if (!user || !tokenData) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset token'
            });
        }
        
        // Check if token is expired
        const now = new Date();
        const tokenExpiry = new Date(tokenData.expiry);
        
        if (now > tokenExpiry) {
            // Clean up expired token
            if (global.resetTokens) {
                global.resetTokens.delete(token);
            }
            return res.status(400).json({
                success: false,
                message: 'Reset token has expired. Please request a new password reset.'
            });
        }
        
        // Update the user's password
        const { error: updateError } = await supabase
            .from('users')
            .update({
                password: password // In production, hash this password
            })
            .eq('id', user.id);
            
        if (updateError) {
            console.error('Error updating password:', updateError);
            return res.status(500).json({
                success: false,
                message: 'Failed to reset password. Please try again.'
            });
        }
        
        // Clear the reset token (try database first, then memory)
        try {
            await supabase
                .from('users')
                .update({
                    reset_token: null,
                    reset_token_expiry: null
                })
                .eq('id', user.id);
        } catch (clearError) {
            // If database columns don't exist, clear from memory
            if (global.resetTokens) {
                global.resetTokens.delete(token);
            }
        }
        
        console.log(`Password reset successfully for user ID: ${user.id}`);
        
        res.json({
            success: true,
            message: 'Password has been reset successfully'
        });
        
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// User Management APIs
app.get('/api/users/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();
            
        if (error || !user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        res.json({ 
            success: true, 
            user: toCamelCase(user)
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
        const updateData = toSnakeCase(req.body);
        
        const { data: user, error } = await supabase
            .from('users')
            .update(updateData)
            .eq('id', userId)
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'profile update');
        }
        
        res.json({ 
            success: true, 
            message: 'Profile updated successfully',
            user: toCamelCase(user)
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

app.get('/api/users', async (req, res) => {
    try {
        const { data: users, error } = await supabase
            .from('users')
            .select('*')
            .order('created_at', { ascending: false });
            
        if (error) {
            return handleDatabaseError(error, res, 'get users');
        }
        
        res.status(200).json({
            success: true,
            users: toCamelCase(users)
        });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

app.put('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Check if email is being changed and if it already exists
        if (req.body.email) {
            const { data: existingUser } = await supabase
                .from('users')
                .select('id')
                .eq('email', req.body.email)
                .neq('id', id)
                .single();
                
            if (existingUser) {
                return res.status(400).json({
                    success: false,
                    message: 'Email already exists'
                });
            }
        }
        
        const updateData = toSnakeCase(req.body);
        const { data: user, error } = await supabase
            .from('users')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'user update');
        }

        res.status(200).json({
            success: true,
            message: 'User updated successfully',
            user: toCamelCase(user)
        });
    } catch (error) {
        console.error('Update user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

app.delete('/api/users/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const { error } = await supabase
            .from('users')
            .delete()
            .eq('id', id);
            
        if (error) {
            return handleDatabaseError(error, res, 'user delete');
        }

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

app.post('/api/users', async (req, res) => {
    try {
        const { firstName, lastName, email, username, password, phone, profilePicture } = req.body;

        // Validate required fields
        if (!firstName || !lastName || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'First name, last name, email, and password are required'
            });
        }

        // Check if user with email already exists
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();
            
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User with this email already exists'
            });
        }

        const userData = {
            first_name: firstName,
            last_name: lastName,
            email,
            password, // Note: In production, this should be hashed
            display_name: username || `${firstName} ${lastName}`,
            profile_picture: profilePicture || '',
            social_links: {
                facebook: '',
                twitter: '',
                instagram: '',
                youtube: '',
                linkedin: '',
                website: ''
            }
        };

        const { data: user, error } = await supabase
            .from('users')
            .insert([userData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'user creation');
        }

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            user: toCamelCase(user)
        });
    } catch (error) {
        console.error('Create user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Internal server error' 
        });
    }
});

// Track Management APIs
app.post('/api/tracks', async (req, res) => {
    try {
        const trackData = toSnakeCase(req.body);
        
        // Check if track with same trackId already exists
        if (trackData.track_id) {
            const { data: existingTrack } = await supabase
                .from('tracks')
                .select('id')
                .eq('track_id', trackData.track_id)
                .single();
                
            if (existingTrack) {
                return res.status(400).json({
                    success: false,
                    message: 'Track with this ID already exists'
                });
            }
        }

        const { data: track, error } = await supabase
            .from('tracks')
            .insert([trackData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'track creation');
        }

        res.status(201).json({
            success: true,
            message: 'Track created successfully',
            track: toCamelCase(track)
        });
    } catch (error) {
        console.error('Track creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update track with file uploads (image and audio)
app.put('/api/tracks/:id/upload', upload.fields([
    { name: 'audio', maxCount: 1 },
    { name: 'image', maxCount: 1 }
]), async (req, res) => {
    try {
        const { id } = req.params;
        console.log('Track with files update request received for ID:', id);
        console.log('Files:', req.files);
        console.log('Body:', req.body);

        const trackData = toSnakeCase(req.body);
        let audioUrl = '';
        let imageUrl = '';

        // Handle array fields that come as indexed properties from FormData
        const arrayFields = ['genre_category', 'beat_category', 'track_tags'];
        arrayFields.forEach(field => {
            const items = [];
            let index = 0;
            while (req.body[`${field}[${index}]`]) {
                items.push(req.body[`${field}[${index}]`]);
                index++;
            }
            if (items.length > 0) {
                trackData[field] = items;
            }
        });

        // Handle audio file upload
        if (req.files && req.files['audio'] && req.files['audio'][0]) {
            const audioFile = req.files['audio'][0];
            
            // Validate audio file type
            if (!audioFile.mimetype.startsWith('audio/')) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid audio file type. Please upload an audio file.'
                });
            }
            
            // Validate file size (50MB limit)
            if (audioFile.size > 50 * 1024 * 1024) {
                return res.status(400).json({
                    success: false,
                    message: 'Audio file too large. Maximum size is 50MB.'
                });
            }
            
            const audioExt = audioFile.originalname.split('.').pop();
            const audioFileName = `${uuidv4()}.${audioExt}`;
            const audioFilePath = `audio/${audioFileName}`;

            const { error: audioError } = await supabase.storage
                .from(STORAGE_BUCKET)
                .upload(audioFilePath, audioFile.buffer, {
                    contentType: audioFile.mimetype,
                    metadata: {
                        originalName: audioFile.originalname,
                        uploadedAt: new Date().toISOString(),
                        fileSize: audioFile.size
                    }
                });

            if (audioError) {
                console.error('Audio upload error:', audioError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to upload audio file: ' + audioError.message
                });
            }

            // Get public URL for audio
            const { data: { publicUrl: audioPublicUrl } } = supabase.storage
                .from(STORAGE_BUCKET)
                .getPublicUrl(audioFilePath);

            audioUrl = audioPublicUrl;
            trackData.track_file = audioUrl;
            console.log('Audio uploaded successfully:', audioUrl);
        }

        // Handle image file upload
        if (req.files && req.files['image'] && req.files['image'][0]) {
            const imageFile = req.files['image'][0];
            
            // Validate image file type
            if (!imageFile.mimetype.startsWith('image/')) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid image file type. Please upload an image file.'
                });
            }
            
            // Validate file size (10MB limit for images)
            if (imageFile.size > 10 * 1024 * 1024) {
                return res.status(400).json({
                    success: false,
                    message: 'Image file too large. Maximum size is 10MB.'
                });
            }
            
            const imageExt = imageFile.originalname.split('.').pop();
            const imageFileName = `${uuidv4()}.${imageExt}`;
            const imageFilePath = `images/${imageFileName}`;

            const { error: imageError } = await supabase.storage
                .from(STORAGE_BUCKET)
                .upload(imageFilePath, imageFile.buffer, {
                    contentType: imageFile.mimetype,
                    metadata: {
                        originalName: imageFile.originalname,
                        uploadedAt: new Date().toISOString(),
                        fileSize: imageFile.size
                    }
                });

            if (imageError) {
                console.error('Image upload error:', imageError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to upload image file: ' + imageError.message
                });
            }

            // Get public URL for image
            const { data: { publicUrl: imagePublicUrl } } = supabase.storage
                .from(STORAGE_BUCKET)
                .getPublicUrl(imageFilePath);

            imageUrl = imagePublicUrl;
            trackData.track_image = imageUrl;
            console.log('Image uploaded successfully:', imageUrl);
        }

        // Update the track in the database
        const { data: track, error } = await supabase
            .from('tracks')
            .update(trackData)
            .eq('id', id)
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'track update with files');
        }

        res.json({
            success: true,
            message: 'Track updated successfully with files uploaded',
            track: toCamelCase(track),
            audioUrl,
            imageUrl
        });
    } catch (error) {
        console.error('Track with files update error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Create track with file uploads (image and audio)
app.post('/api/tracks/upload', upload.fields([
    { name: 'audio', maxCount: 1 },
    { name: 'image', maxCount: 1 }
]), async (req, res) => {
    try {
        console.log('Track with files upload request received');
        console.log('Files:', req.files);
        console.log('Body:', req.body);

        const trackData = toSnakeCase(req.body);
        let audioUrl = '';
        let imageUrl = '';

        // Handle array fields that come as indexed properties from FormData
        const arrayFields = ['genre_category', 'beat_category', 'track_tags'];
        arrayFields.forEach(field => {
            const items = [];
            let index = 0;
            while (req.body[`${field}[${index}]`]) {
                items.push(req.body[`${field}[${index}]`]);
                index++;
            }
            if (items.length > 0) {
                trackData[field] = items;
            }
        });

        // Handle audio file upload
        if (req.files && req.files['audio'] && req.files['audio'][0]) {
            const audioFile = req.files['audio'][0];
            
            // Validate audio file type
            if (!audioFile.mimetype.startsWith('audio/')) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid audio file type. Please upload an audio file.'
                });
            }
            
            // Validate file size (50MB limit)
            if (audioFile.size > 50 * 1024 * 1024) {
                return res.status(400).json({
                    success: false,
                    message: 'Audio file too large. Maximum size is 50MB.'
                });
            }
            
            const audioExt = audioFile.originalname.split('.').pop();
            const audioFileName = `${uuidv4()}.${audioExt}`;
            const audioFilePath = `audio/${audioFileName}`;

            const { data: audioData, error: audioError } = await supabase.storage
                .from(STORAGE_BUCKET)
                .upload(audioFilePath, audioFile.buffer, {
                    contentType: audioFile.mimetype,
                    metadata: {
                        originalName: audioFile.originalname,
                        uploadedAt: new Date().toISOString(),
                        fileSize: audioFile.size
                    }
                });

            if (audioError) {
                console.error('Audio upload error:', audioError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to upload audio file: ' + audioError.message
                });
            }

            // Get public URL for audio
            const { data: { publicUrl: audioPublicUrl } } = supabase.storage
                .from(STORAGE_BUCKET)
                .getPublicUrl(audioFilePath);

            audioUrl = audioPublicUrl;
            trackData.track_file = audioUrl;
            console.log('Audio uploaded successfully:', audioUrl);
        }

        // Handle image file upload
        if (req.files && req.files['image'] && req.files['image'][0]) {
            const imageFile = req.files['image'][0];
            
            // Validate image file type
            if (!imageFile.mimetype.startsWith('image/')) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid image file type. Please upload an image file.'
                });
            }
            
            // Validate file size (10MB limit for images)
            if (imageFile.size > 10 * 1024 * 1024) {
                return res.status(400).json({
                    success: false,
                    message: 'Image file too large. Maximum size is 10MB.'
                });
            }
            
            const imageExt = imageFile.originalname.split('.').pop();
            const imageFileName = `${uuidv4()}.${imageExt}`;
            const imageFilePath = `images/${imageFileName}`;

            const { data: imageData, error: imageError } = await supabase.storage
                .from(STORAGE_BUCKET)
                .upload(imageFilePath, imageFile.buffer, {
                    contentType: imageFile.mimetype,
                    metadata: {
                        originalName: imageFile.originalname,
                        uploadedAt: new Date().toISOString(),
                        fileSize: imageFile.size
                    }
                });

            if (imageError) {
                console.error('Image upload error:', imageError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to upload image file: ' + imageError.message
                });
            }

            // Get public URL for image
            const { data: { publicUrl: imagePublicUrl } } = supabase.storage
                .from(STORAGE_BUCKET)
                .getPublicUrl(imageFilePath);

            imageUrl = imagePublicUrl;
            trackData.track_image = imageUrl;
            console.log('Image uploaded successfully:', imageUrl);
        }

        // Check if track with same trackId already exists
        if (trackData.track_id) {
            const { data: existingTrack } = await supabase
                .from('tracks')
                .select('id')
                .eq('track_id', trackData.track_id)
                .single();
                
            if (existingTrack) {
                return res.status(400).json({
                    success: false,
                    message: 'Track with this ID already exists'
                });
            }
        }

        // Insert track data into database
        const { data: track, error } = await supabase
            .from('tracks')
            .insert([trackData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'track creation');
        }

        res.status(201).json({
            success: true,
            message: 'Track created successfully with files uploaded',
            track: toCamelCase(track),
            audioUrl,
            imageUrl
        });
    } catch (error) {
        console.error('Track with files creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});


app.get('/api/tracks', async (req, res) => {
    try {
        const { data: tracks, error } = await supabase
            .from('tracks')
            .select('*')
            .order('created_at', { ascending: false });
            
        if (error) {
            return handleDatabaseError(error, res, 'get tracks');
        }
        
        res.json({
            success: true,
            tracks: toCamelCase(tracks)
        });
    } catch (error) {
        console.error('Get tracks error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.put('/api/tracks/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = toSnakeCase(req.body);

        // Check if trackId is being changed and if it conflicts with existing track
        if (updateData.track_id) {
            const { data: existingTrack } = await supabase
                .from('tracks')
                .select('id')
                .eq('track_id', updateData.track_id)
                .neq('id', id)
                .single();
                
            if (existingTrack) {
                return res.status(400).json({
                    success: false,
                    message: 'Track with this ID already exists'
                });
            }
        }

        const { data: track, error } = await supabase
            .from('tracks')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'track update');
        }

        res.json({
            success: true,
            message: 'Track updated successfully',
            track: toCamelCase(track)
        });
    } catch (error) {
        console.error('Track update error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.delete('/api/tracks/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        console.log('Delete track request - ID:', id);
        console.log('Delete track request - ID type:', typeof id);
        
        // Validate ID parameter
        if (!id || id === 'undefined' || id === 'null') {
            return res.status(400).json({
                success: false,
                message: 'Invalid track ID provided'
            });
        }

        const { error } = await supabase
            .from('tracks')
            .delete()
            .eq('id', id);
            
        if (error) {
            console.error('Database delete error:', error);
            return handleDatabaseError(error, res, 'track delete');
        }

        res.json({
            success: true,
            message: 'Track deleted successfully'
        });
    } catch (error) {
        console.error('Track delete error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Genre Management APIs
app.post('/api/genres', async (req, res) => {
    try {
        const { name, description, color } = req.body;

        // Check if genre with same name already exists
        const { data: existingGenre } = await supabase
            .from('genres')
            .select('id')
            .eq('name', name.trim())
            .single();
            
        if (existingGenre) {
            return res.status(400).json({
                success: false,
                message: 'Genre with this name already exists'
            });
        }

        const genreData = {
            name: name.trim(),
            description: description || '',
            color: color || '#7ED7FF'
        };

        const { data: genre, error } = await supabase
            .from('genres')
            .insert([genreData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'genre creation');
        }

        res.status(201).json({
            success: true,
            message: 'Genre created successfully',
            genre: toCamelCase(genre)
        });
    } catch (error) {
        console.error('Genre creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.get('/api/genres', async (req, res) => {
    try {
        const { data: genres, error } = await supabase
            .from('genres')
            .select('*')
            .order('name');
            
        if (error) {
            return handleDatabaseError(error, res, 'get genres');
        }
        
        res.json({
            success: true,
            genres: toCamelCase(genres)
        });
    } catch (error) {
        console.error('Get genres error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.put('/api/genres/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, color, isActive } = req.body;

        // Check if name is being changed and if it conflicts with existing genre
        if (name) {
            const { data: existingGenre } = await supabase
                .from('genres')
                .select('id')
                .eq('name', name.trim())
                .neq('id', id)
                .single();
                
            if (existingGenre) {
                return res.status(400).json({
                    success: false,
                    message: 'Genre with this name already exists'
                });
            }
        }

        const updateData = {};
        if (name) updateData.name = name.trim();
        if (description !== undefined) updateData.description = description;
        if (color) updateData.color = color;
        if (isActive !== undefined) updateData.is_active = isActive;

        const { data: genre, error } = await supabase
            .from('genres')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'genre update');
        }

        res.json({
            success: true,
            message: 'Genre updated successfully',
            genre: toCamelCase(genre)
        });
    } catch (error) {
        console.error('Genre update error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.delete('/api/genres/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const { error } = await supabase
            .from('genres')
            .delete()
            .eq('id', id);
            
        if (error) {
            return handleDatabaseError(error, res, 'genre delete');
        }

        res.json({
            success: true,
            message: 'Genre deleted successfully'
        });
    } catch (error) {
        console.error('Genre delete error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Beat Management APIs (similar pattern to genres)
app.post('/api/beats', async (req, res) => {
    try {
        const { name, description, color } = req.body;

        const { data: existingBeat } = await supabase
            .from('beats')
            .select('id')
            .eq('name', name.trim())
            .single();
            
        if (existingBeat) {
            return res.status(400).json({
                success: false,
                message: 'Beat with this name already exists'
            });
        }

        const beatData = {
            name: name.trim(),
            description: description || '',
            color: color || '#E100FF'
        };

        const { data: beat, error } = await supabase
            .from('beats')
            .insert([beatData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'beat creation');
        }

        res.status(201).json({
            success: true,
            message: 'Beat created successfully',
            beat: toCamelCase(beat)
        });
    } catch (error) {
        console.error('Beat creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.get('/api/beats', async (req, res) => {
    try {
        const { data: beats, error } = await supabase
            .from('beats')
            .select('*')
            .order('name');
            
        if (error) {
            return handleDatabaseError(error, res, 'get beats');
        }
        
        res.json({
            success: true,
            beats: toCamelCase(beats)
        });
    } catch (error) {
        console.error('Get beats error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.put('/api/beats/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, color, isActive } = req.body;

        if (name) {
            const { data: existingBeat } = await supabase
                .from('beats')
                .select('id')
                .eq('name', name.trim())
                .neq('id', id)
                .single();
                
            if (existingBeat) {
                return res.status(400).json({
                    success: false,
                    message: 'Beat with this name already exists'
                });
            }
        }

        const updateData = {};
        if (name) updateData.name = name.trim();
        if (description !== undefined) updateData.description = description;
        if (color) updateData.color = color;
        if (isActive !== undefined) updateData.is_active = isActive;

        const { data: beat, error } = await supabase
            .from('beats')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'beat update');
        }

        res.json({
            success: true,
            message: 'Beat updated successfully',
            beat: toCamelCase(beat)
        });
    } catch (error) {
        console.error('Beat update error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.delete('/api/beats/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const { error } = await supabase
            .from('beats')
            .delete()
            .eq('id', id);
            
        if (error) {
            return handleDatabaseError(error, res, 'beat delete');
        }

        res.json({
            success: true,
            message: 'Beat deleted successfully'
        });
    } catch (error) {
        console.error('Beat delete error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Tag Management APIs (similar pattern to genres and beats)
app.post('/api/tags', async (req, res) => {
    try {
        const { name, description, color } = req.body;

        const { data: existingTag } = await supabase
            .from('tags')
            .select('id')
            .eq('name', name.trim())
            .single();
            
        if (existingTag) {
            return res.status(400).json({
                success: false,
                message: 'Tag with this name already exists'
            });
        }

        const tagData = {
            name: name.trim(),
            description: description || '',
            color: color || '#FF6B35'
        };

        const { data: tag, error } = await supabase
            .from('tags')
            .insert([tagData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'tag creation');
        }

        res.status(201).json({
            success: true,
            message: 'Tag created successfully',
            tag: toCamelCase(tag)
        });
    } catch (error) {
        console.error('Tag creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.get('/api/tags', async (req, res) => {
    try {
        const { data: tags, error } = await supabase
            .from('tags')
            .select('*')
            .order('name');
            
        if (error) {
            return handleDatabaseError(error, res, 'get tags');
        }
        
        res.json({
            success: true,
            tags: toCamelCase(tags)
        });
    } catch (error) {
        console.error('Get tags error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.put('/api/tags/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, color, isActive } = req.body;

        if (name) {
            const { data: existingTag } = await supabase
                .from('tags')
                .select('id')
                .eq('name', name.trim())
                .neq('id', id)
                .single();
                
            if (existingTag) {
                return res.status(400).json({
                    success: false,
                    message: 'Tag with this name already exists'
                });
            }
        }

        const updateData = {};
        if (name) updateData.name = name.trim();
        if (description !== undefined) updateData.description = description;
        if (color) updateData.color = color;
        if (isActive !== undefined) updateData.is_active = isActive;

        const { data: tag, error } = await supabase
            .from('tags')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'tag update');
        }

        res.json({
            success: true,
            message: 'Tag updated successfully',
            tag: toCamelCase(tag)
        });
    } catch (error) {
        console.error('Tag update error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.delete('/api/tags/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const { error } = await supabase
            .from('tags')
            .delete()
            .eq('id', id);
            
        if (error) {
            return handleDatabaseError(error, res, 'tag delete');
        }

        res.json({
            success: true,
            message: 'Tag deleted successfully'
        });
    } catch (error) {
        console.error('Tag delete error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Create sound kit with file uploads (image and audio)
app.post('/api/sound-kits/upload', upload.fields([
    { name: 'kitFile', maxCount: 1 },
    { name: 'image', maxCount: 1 }
]), async (req, res) => {
    try {
        console.log('Sound kit with files upload request received');
        console.log('Files:', req.files);
        console.log('Body:', req.body);

        const soundKitData = toSnakeCase(req.body);
        let kitFileUrl = '';
        let imageUrl = '';

        // Handle array fields that come as indexed properties from FormData
        const arrayFields = ['tags', 'category'];
        arrayFields.forEach(field => {
            const items = [];
            let index = 0;
            while (req.body[`${field}[${index}]`]) {
                items.push(req.body[`${field}[${index}]`]);
                index++;
            }
            if (items.length > 0) {
                soundKitData[field] = items;
            }
        });

        // Handle kit file upload
        if (req.files && req.files['kitFile'] && req.files['kitFile'][0]) {
            const kitFile = req.files['kitFile'][0];
            
            // Validate audio file type
            if (!kitFile.mimetype.startsWith('audio/')) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid audio file type. Please upload an audio file.'
                });
            }
            
            // Validate file size (50MB limit)
            if (kitFile.size > 50 * 1024 * 1024) {
                return res.status(400).json({
                    success: false,
                    message: 'Audio file too large. Maximum size is 50MB.'
                });
            }
            
            const kitFileExt = kitFile.originalname.split('.').pop();
            const kitFileName = `${uuidv4()}.${kitFileExt}`;
            const kitFilePath = `audio/${kitFileName}`;

            const { data: kitFileData, error: kitFileError } = await supabase.storage
                .from(STORAGE_BUCKET)
                .upload(kitFilePath, kitFile.buffer, {
                    contentType: kitFile.mimetype,
                    metadata: {
                        originalName: kitFile.originalname,
                        uploadedAt: new Date().toISOString(),
                        fileSize: kitFile.size
                    }
                });

            if (kitFileError) {
                console.error('Kit file upload error:', kitFileError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to upload kit file: ' + kitFileError.message
                });
            }

            // Get public URL for kit file
            const { data: { publicUrl: kitFilePublicUrl } } = supabase.storage
                .from(STORAGE_BUCKET)
                .getPublicUrl(kitFilePath);

            kitFileUrl = kitFilePublicUrl;
            soundKitData.kit_file = kitFileUrl;
            console.log('Kit file uploaded successfully:', kitFileUrl);
        }

        // Handle image file upload
        if (req.files && req.files['image'] && req.files['image'][0]) {
            const imageFile = req.files['image'][0];
            
            // Validate image file type
            if (!imageFile.mimetype.startsWith('image/')) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid image file type. Please upload an image file.'
                });
            }
            
            // Validate file size (10MB limit for images)
            if (imageFile.size > 10 * 1024 * 1024) {
                return res.status(400).json({
                    success: false,
                    message: 'Image file too large. Maximum size is 10MB.'
                });
            }
            
            const imageExt = imageFile.originalname.split('.').pop();
            const imageFileName = `${uuidv4()}.${imageExt}`;
            const imageFilePath = `images/${imageFileName}`;

            const { data: imageData, error: imageError } = await supabase.storage
                .from(STORAGE_BUCKET)
                .upload(imageFilePath, imageFile.buffer, {
                    contentType: imageFile.mimetype,
                    metadata: {
                        originalName: imageFile.originalname,
                        uploadedAt: new Date().toISOString(),
                        fileSize: imageFile.size
                    }
                });

            if (imageError) {
                console.error('Image upload error:', imageError);
                return res.status(500).json({
                    success: false,
                    message: 'Failed to upload image file: ' + imageError.message
                });
            }

            // Get public URL for image
            const { data: { publicUrl: imagePublicUrl } } = supabase.storage
                .from(STORAGE_BUCKET)
                .getPublicUrl(imageFilePath);

            imageUrl = imagePublicUrl;
            soundKitData.kit_image = imageUrl;
            console.log('Image uploaded successfully:', imageUrl);
        }

        // Check if sound kit with same kitId already exists
        if (soundKitData.kit_id) {
            const { data: existingSoundKit } = await supabase
                .from('sound_kits')
                .select('id')
                .eq('kit_id', soundKitData.kit_id)
                .single();
                
            if (existingSoundKit) {
                return res.status(400).json({
                    success: false,
                    message: 'Sound kit with this ID already exists'
                });
            }
        }

        // Insert sound kit data into database
        const { data: soundKit, error } = await supabase
            .from('sound_kits')
            .insert([soundKitData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'sound kit creation');
        }

        res.status(201).json({
            success: true,
            message: 'Sound kit created successfully with files uploaded',
            soundKit: toCamelCase(soundKit),
            kitFileUrl,
            imageUrl
        });
    } catch (error) {
        console.error('Sound kit with files creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Sound Kit Management APIs
app.post('/api/sound-kits', async (req, res) => {
    try {
        const soundKitData = toSnakeCase(req.body);
        
        // Check if sound kit with same kitId already exists
        if (soundKitData.kit_id) {
            const { data: existingSoundKit } = await supabase
                .from('sound_kits')
                .select('id')
                .eq('kit_id', soundKitData.kit_id)
                .single();
                
            if (existingSoundKit) {
                return res.status(400).json({
                    success: false,
                    message: 'Sound kit with this ID already exists'
                });
            }
        }

        const { data: soundKit, error } = await supabase
            .from('sound_kits')
            .insert([soundKitData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'sound kit creation');
        }

        res.status(201).json({
            success: true,
            message: 'Sound kit created successfully',
            soundKit: toCamelCase(soundKit)
        });
    } catch (error) {
        console.error('Sound kit creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.get('/api/sound-kits', async (req, res) => {
    try {
        const { data: soundKits, error } = await supabase
            .from('sound_kits')
            .select('*')
            .eq('is_active', true)
            .order('created_at', { ascending: false });
            
        if (error) {
            return handleDatabaseError(error, res, 'get sound kits');
        }
        
        res.json({
            success: true,
            soundKits: toCamelCase(soundKits)
        });
    } catch (error) {
        console.error('Get sound kits error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.put('/api/sound-kits/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = toSnakeCase(req.body);

        const { data: soundKit, error } = await supabase
            .from('sound_kits')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'sound kit update');
        }

        res.json({
            success: true,
            message: 'Sound kit updated successfully',
            soundKit: toCamelCase(soundKit)
        });
    } catch (error) {
        console.error('Update sound kit error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.delete('/api/sound-kits/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        console.log('Delete sound kit request - ID:', id);
        console.log('Delete sound kit request - ID type:', typeof id);
        
        // Validate ID parameter
        if (!id || id === 'undefined' || id === 'null') {
            return res.status(400).json({
                success: false,
                message: 'Invalid sound kit ID provided'
            });
        }

        const { error } = await supabase
            .from('sound_kits')
            .delete()
            .eq('id', id);
            
        if (error) {
            console.error('Database delete error:', error);
            return handleDatabaseError(error, res, 'sound kit delete');
        }

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

// Sound Kit Categories APIs
app.post('/api/sound-kit-categories', async (req, res) => {
    try {
        const { name, description, color } = req.body;

        if (!name) {
            return res.status(400).json({
                success: false,
                message: 'Category name is required'
            });
        }

        const categoryData = {
            name: name.trim(),
            description: description || '',
            color: color || '#00D4FF'
        };

        const { data: category, error } = await supabase
            .from('sound_kit_categories')
            .insert([categoryData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'sound kit category creation');
        }

        res.status(201).json({
            success: true,
            message: 'Sound kit category created successfully',
            category: toCamelCase(category)
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
        const { data: categories, error } = await supabase
            .from('sound_kit_categories')
            .select('*')
            .order('created_at', { ascending: false });
            
        if (error) {
            return handleDatabaseError(error, res, 'get sound kit categories');
        }
        
        res.json({
            success: true,
            categories: toCamelCase(categories)
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

        const updateData = {};
        if (name) updateData.name = name.trim();
        if (description !== undefined) updateData.description = description;
        if (color) updateData.color = color;
        if (isActive !== undefined) updateData.is_active = isActive;

        const { data: category, error } = await supabase
            .from('sound_kit_categories')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'sound kit category update');
        }

        res.json({
            success: true,
            message: 'Sound kit category updated successfully',
            category: toCamelCase(category)
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

        const { error } = await supabase
            .from('sound_kit_categories')
            .delete()
            .eq('id', id);
            
        if (error) {
            return handleDatabaseError(error, res, 'sound kit category delete');
        }

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

// Sound Kit Tags APIs
app.post('/api/sound-kit-tags', async (req, res) => {
    try {
        const { name, description, color } = req.body;

        if (!name) {
            return res.status(400).json({
                success: false,
                message: 'Tag name is required'
            });
        }

        const tagData = {
            name: name.trim(),
            description: description || '',
            color: color || '#FF6B35'
        };

        const { data: tag, error } = await supabase
            .from('sound_kit_tags')
            .insert([tagData])
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'sound kit tag creation');
        }

        res.status(201).json({
            success: true,
            message: 'Sound kit tag created successfully',
            tag: toCamelCase(tag)
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
        const { data: tags, error } = await supabase
            .from('sound_kit_tags')
            .select('*')
            .order('created_at', { ascending: false });
            
        if (error) {
            return handleDatabaseError(error, res, 'get sound kit tags');
        }
        
        res.json({
            success: true,
            tags: toCamelCase(tags)
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

        const updateData = {};
        if (name) updateData.name = name.trim();
        if (description !== undefined) updateData.description = description;
        if (color) updateData.color = color;
        if (isActive !== undefined) updateData.is_active = isActive;

        const { data: tag, error } = await supabase
            .from('sound_kit_tags')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();
            
        if (error) {
            return handleDatabaseError(error, res, 'sound kit tag update');
        }

        res.json({
            success: true,
            message: 'Sound kit tag updated successfully',
            tag: toCamelCase(tag)
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

        const { error } = await supabase
            .from('sound_kit_tags')
            .delete()
            .eq('id', id);
            
        if (error) {
            return handleDatabaseError(error, res, 'sound kit tag delete');
        }

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

// File Upload APIs using Supabase Storage
app.post('/api/upload-image', upload.single('image'), async (req, res) => {
    try {
        console.log('Image upload request received');
        
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'No image file provided'
            });
        }

        const fileExt = req.file.originalname.split('.').pop();
        const fileName = `${uuidv4()}.${fileExt}`;
        const filePath = `images/${fileName}`;

        const { data, error } = await supabase.storage
            .from(STORAGE_BUCKET)
            .upload(filePath, req.file.buffer, {
                contentType: req.file.mimetype,
                metadata: {
                    originalName: req.file.originalname,
                    uploadedAt: new Date().toISOString()
                }
            });

        if (error) {
            console.error('Supabase storage upload error:', error);
            return res.status(500).json({
                success: false,
                message: 'Failed to upload image'
            });
        }

        // Get public URL
        const { data: { publicUrl } } = supabase.storage
            .from(STORAGE_BUCKET)
            .getPublicUrl(filePath);

        console.log('Image uploaded successfully to Supabase Storage');
        console.log('File path:', filePath);
        console.log('Public URL:', publicUrl);
        
        res.json({
            success: true,
            message: 'Image uploaded successfully',
            fileId: fileName,
            imageUrl: publicUrl,
            filePath: filePath,
            filename: req.file.originalname,
            contentType: req.file.mimetype
        });

    } catch (error) {
        console.error('Upload image error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Upload MP3/Audio files
app.post('/api/upload-audio', upload.single('audio'), async (req, res) => {
    try {
        console.log('Audio upload request received');
        
        if (!req.file) {
            return res.status(400).json({
                success: false,
                message: 'No audio file provided'
            });
        }

        const fileExt = req.file.originalname.split('.').pop();
        const fileName = `${uuidv4()}.${fileExt}`;
        const filePath = `audio/${fileName}`;

        const { data, error } = await supabase.storage
            .from(STORAGE_BUCKET)
            .upload(filePath, req.file.buffer, {
                contentType: req.file.mimetype,
                metadata: {
                    originalName: req.file.originalname,
                    uploadedAt: new Date().toISOString()
                }
            });

        if (error) {
            console.error('Supabase storage upload error:', error);
            return res.status(500).json({
                success: false,
                message: 'Failed to upload audio file'
            });
        }

        // Get public URL
        const { data: { publicUrl } } = supabase.storage
            .from(STORAGE_BUCKET)
            .getPublicUrl(filePath);

        console.log('Audio uploaded successfully to Supabase Storage');
        console.log('File path:', filePath);
        console.log('Public URL:', publicUrl);
        
        res.json({
            success: true,
            message: 'Audio uploaded successfully',
            fileId: fileName,
            audioUrl: publicUrl,
            filePath: filePath,
            filename: req.file.originalname,
            contentType: req.file.mimetype
        });

    } catch (error) {
        console.error('Upload audio error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get file info from Supabase Storage
app.get('/api/file/:filePath(*)', async (req, res) => {
    try {
        const filePath = req.params.filePath;
        
        // Get public URL for the file
        const { data: { publicUrl } } = supabase.storage
            .from(STORAGE_BUCKET)
            .getPublicUrl(filePath);

        // Redirect to the public URL
        res.redirect(publicUrl);
        
    } catch (error) {
        console.error('Get file error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Delete file from Supabase Storage
app.delete('/api/file/:filePath(*)', async (req, res) => {
    try {
        const filePath = req.params.filePath;
        
        const { error } = await supabase.storage
            .from(STORAGE_BUCKET)
            .remove([filePath]);

        if (error) {
            console.error('Supabase storage delete error:', error);
            return res.status(500).json({
                success: false,
                message: 'Failed to delete file'
            });
        }

        res.json({
            success: true, 
            message: 'File deleted successfully'
        });

    } catch (error) {
        console.error('Delete file error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// List files from Supabase Storage
app.get('/api/files', async (req, res) => {
    try {
        const { data: files, error } = await supabase.storage
            .from(STORAGE_BUCKET)
            .list('', {
                limit: 100,
                offset: 0
            });

        if (error) {
            console.error('List files error:', error);
            return res.status(500).json({
                success: false,
                message: 'Failed to list files'
            });
        }

        const fileList = files.map(file => ({
            name: file.name,
            size: file.metadata?.size,
            contentType: file.metadata?.mimetype,
            lastModified: file.updated_at,
            publicUrl: supabase.storage.from(STORAGE_BUCKET).getPublicUrl(file.name).data.publicUrl
        }));

        res.json({
            success: true,
            files: fileList
        });

    } catch (error) {
        console.error('List files error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Musicians API
app.get('/api/musicians', async (req, res) => {
    try {
        // Get unique musicians with their profile pictures and track count
        const { data: tracks, error } = await supabase
            .from('tracks')
            .select('musician, musician_profile_picture')
            .not('musician', 'is', null)
            .not('musician', 'eq', '');
            
        if (error) {
            return handleDatabaseError(error, res, 'get musicians');
        }

        // Group by musician name
        const musiciansMap = new Map();
        tracks.forEach(track => {
            if (!musiciansMap.has(track.musician)) {
                musiciansMap.set(track.musician, {
                    _id: track.musician,
                    name: track.musician,
                    profilePicture: track.musician_profile_picture,
                    trackCount: 0
                });
            }
            musiciansMap.get(track.musician).trackCount++;
        });

        const musicians = Array.from(musiciansMap.values()).sort((a, b) => a.name.localeCompare(b.name));

        res.json({
            success: true,
            musicians: toCamelCase(musicians)
        });

    } catch (error) {
        console.error('Get musicians error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

app.get('/api/musicians/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const musicianName = decodeURIComponent(id);
        
        const { data: tracks, error } = await supabase
            .from('tracks')
            .select('*')
            .ilike('musician', musicianName);
            
        if (error) {
            return handleDatabaseError(error, res, 'get musician tracks');
        }

        if (tracks.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Musician not found'
            });
        }

        const firstTrack = tracks[0];
        const musician = {
            _id: firstTrack.musician,
            name: firstTrack.musician,
            profilePicture: firstTrack.musician_profile_picture,
            bio: firstTrack.about || 'No bio available',
            trackCount: tracks.length
        };

        res.json({
            success: true,
            musician: toCamelCase(musician)
        });

    } catch (error) {
        console.error('Get musician by ID error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'Server is running with Supabase',
        storage: {
            bucket: STORAGE_BUCKET,
            endpoint: STORAGE_ENDPOINT,
            region: STORAGE_REGION
        }
    });
});

// Storage configuration endpoint
app.get('/api/storage/config', (req, res) => {
    res.json({
        success: true,
        config: {
            bucket: STORAGE_BUCKET,
            endpoint: STORAGE_ENDPOINT,
            region: STORAGE_REGION,
            maxFileSize: '50MB',
            allowedTypes: ['image/*', 'audio/*']
        }
    });
});

// Test storage connection endpoint
app.get('/api/storage/test', async (req, res) => {
    try {
        const { data: buckets, error } = await supabase.storage.listBuckets();
        
        if (error) {
            return res.status(500).json({
                success: false,
                message: 'Storage connection failed',
                error: error.message
            });
        }
        
        const uploadsBucket = buckets.find(bucket => bucket.name === STORAGE_BUCKET);
        
        res.json({
            success: true,
            message: 'Storage connection successful',
            bucket: {
                name: STORAGE_BUCKET,
                exists: !!uploadsBucket,
                public: uploadsBucket?.public || false
            },
            totalBuckets: buckets.length
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Storage test failed',
            error: error.message
        });
    }
});

// Test endpoint
app.get('/api/test-tracks', async (req, res) => {
    try {
        const { data: tracks, error } = await supabase
            .from('tracks')
            .select('id, track_name, musician, musician_profile_picture')
            .limit(5);
            
        if (error) {
            return handleDatabaseError(error, res, 'test tracks');
        }
        
        res.json({
            success: true,
            count: tracks.length,
            tracks: toCamelCase(tracks)
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
    console.log('Server is running on port 3001 with Supabase backend');
});

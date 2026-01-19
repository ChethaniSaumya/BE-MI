require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const app = express();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt = require('bcrypt');
const saltRounds = 10; // You can adjust this value (10-12 is good) 

app.use(cors());
app.use((req, res, next) => {
    if (req.originalUrl === '/api/webhook/stripe') {
        next();
    } else {
        express.json()(req, res, next);
    }
});


// Supabase client setup
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
    console.error('Missing Supabase configuration. Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your .env file');
    console.error('Example .env file:');
    console.error('SUPABASE_URL=https://eupdcffsqpjevpwcecys.supabase.co');
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
const STORAGE_ENDPOINT = 'https://eupdcffsqpjevpwcecys.storage.supabase.co/storage/v1/s3';
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

app.post('/api/signup', async (req, res) => {
    try {
        const { firstName, lastName, email, password, username, phone } = req.body;

        // Validate required fields
        if (!firstName || !lastName || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'First name, last name, email, and password are required'
            });
        }

        // Check if user already exists by email
        const { data: existingUserByEmail } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUserByEmail) {
            return res.status(400).json({
                success: false,
                message: 'User with this email already exists'
            });
        }

        // Check if username is provided and unique
        if (username) {
            const { data: existingUserByUsername } = await supabase
                .from('users')
                .select('id')
                .eq('username', username)
                .single();

            if (existingUserByUsername) {
                return res.status(400).json({
                    success: false,
                    message: 'Username already taken'
                });
            }
        }

        // Hash the password
        let hashedPassword;
        try {
            hashedPassword = await bcrypt.hash(password, saltRounds);
        } catch (hashError) {
            console.error('Password hashing error:', hashError);
            return res.status(500).json({
                success: false,
                message: 'Error processing password'
            });
        }

        // Create new user with default values
        const userData = {
            first_name: firstName,
            last_name: lastName,
            email: email,
            password: hashedPassword, // Store hashed password
            username: username || null,
            phone: phone || null,
            role: 'user', // Default role
            is_admin: false, // Default admin status
            is_creator: false, // Default creator status
            is_buyer: true, // Default buyer status
            profile_picture: '', // Default empty profile picture
            social_links: {
                facebook: '',
                twitter: '',
                instagram: '',
                youtube: '',
                linkedin: '',
                website: ''
            },
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };

        const { data: user, error } = await supabase
            .from('users')
            .insert([userData])
            .select()
            .single();

        if (error) {
            console.error('Supabase insert error:', error);
            return handleDatabaseError(error, res, 'signup');
        }

        // Return user without password
        const userResponse = {
            id: user.id,
            firstName: user.first_name,
            lastName: user.last_name,
            email: user.email,
            username: user.username,
            phone: user.phone,
            role: user.role || 'user',
            isAdmin: user.is_admin || false,
            isCreator: user.is_creator || false,
            isBuyer: user.is_buyer || true,
            profilePicture: user.profile_picture,
            createdAt: user.created_at
        };

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            user: userResponse
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

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Email/username and password are required'
            });
        }

        // Determine if login is by email or username
        let queryField = 'email';
        let queryValue = email;

        // Check if input is email or username
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            queryField = 'username';
            queryValue = email;
        }

        // Find user by email or username
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq(queryField, queryValue)
            .single();

        if (error || !user) {
            console.log(`User not found with ${queryField}: ${queryValue}`);
            return res.status(401).json({
                success: false,
                message: 'Invalid email/username or password'
            });
        }

        // Check if password is hashed (legacy check)
        let isPasswordValid;
        if (user.password.startsWith('$2b$') || user.password.startsWith('$2a$')) {
            // Password is bcrypt hashed
            isPasswordValid = await bcrypt.compare(password, user.password);
        } else {
            // Legacy plain text password (for migration)
            console.warn(`User ${user.id} has plain text password, migrating to bcrypt...`);
            isPasswordValid = user.password === password;
            
            // If password is valid, hash it and update in database
            if (isPasswordValid) {
                const hashedPassword = await bcrypt.hash(password, saltRounds);
                await supabase
                    .from('users')
                    .update({ 
                        password: hashedPassword,
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', user.id);
                console.log(`Migrated password for user ${user.id} to bcrypt`);
            }
        }

        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Return user with role information (without password)
        const userResponse = {
            id: user.id,
            firstName: user.first_name,
            lastName: user.last_name,
            email: user.email,
            username: user.username,
            phone: user.phone,
            role: user.role || 'user',
            isAdmin: user.is_admin || false,
            isCreator: user.is_creator || false,
            isBuyer: user.is_buyer || true,
            profilePicture: user.profile_picture,
            createdAt: user.created_at
        };

        res.json({
            success: true,
            message: 'Login successful',
            user: userResponse
        });
    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Add password migration endpoint for existing users
app.post('/api/migrate-passwords', async (req, res) => {
    try {
        // Get all users with plain text passwords
        const { data: users, error } = await supabase
            .from('users')
            .select('id, password')
            .not('password', 'like', '$2b$%')
            .not('password', 'like', '$2a$%');

        if (error) {
            console.error('Error fetching users:', error);
            return res.status(500).json({ success: false, message: 'Error fetching users' });
        }

        if (!users || users.length === 0) {
            return res.json({ 
                success: true, 
                message: 'No users need password migration',
                migrated: 0 
            });
        }

        let migratedCount = 0;
        let failedCount = 0;

        // Migrate each user's password
        for (const user of users) {
            try {
                const hashedPassword = await bcrypt.hash(user.password, saltRounds);
                
                const { error: updateError } = await supabase
                    .from('users')
                    .update({ 
                        password: hashedPassword,
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', user.id);

                if (updateError) {
                    console.error(`Failed to migrate user ${user.id}:`, updateError);
                    failedCount++;
                } else {
                    migratedCount++;
                    console.log(`Migrated password for user ${user.id}`);
                }
            } catch (hashError) {
                console.error(`Error hashing password for user ${user.id}:`, hashError);
                failedCount++;
            }
        }

        res.json({
            success: true,
            message: `Password migration completed: ${migratedCount} migrated, ${failedCount} failed`,
            migrated: migratedCount,
            failed: failedCount
        });

    } catch (error) {
        console.error('Password migration error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error during password migration'
        });
    }
});


// =====================================================
// ADMIN MANAGEMENT APIs
// =====================================================

// Get all admins (admin only)
app.get('/api/admin/admins', async (req, res) => {
    try {
        // Add authentication check here
        const { data: admins, error } = await supabase
            .from('users')
            .select('*')
            .eq('is_admin', true)
            .order('created_at', { ascending: false });

        if (error) {
            return handleDatabaseError(error, res, 'get admins');
        }

        res.json({
            success: true,
            admins: admins.map(admin => ({
                id: admin.id,
                firstName: admin.first_name,
                lastName: admin.last_name,
                email: admin.email,
                username: admin.username,
                role: admin.role,
                isAdmin: admin.is_admin,
                createdAt: admin.created_at
            }))
        });
    } catch (error) {
        console.error('Get admins error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Create new admin (admin only)
app.post('/api/admin/admins', async (req, res) => {
    try {
        const { firstName, lastName, email, username, password, role = 'admin' } = req.body;

        // Check if user already exists
        const { data: existingUser } = await supabase
            .from('users')
            .select('id')
            .or(`email.eq.${email},username.eq.${username}`)
            .single();

        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'User with this email or username already exists'
            });
        }

        // Create admin user
        const adminData = {
            first_name: firstName,
            last_name: lastName,
            email: email,
            username: username,
            password: password, // In production, hash this
            role: role,
            is_admin: true,
            is_creator: false,
            is_buyer: false
        };

        const { data: admin, error } = await supabase
            .from('users')
            .insert([adminData])
            .select()
            .single();

        if (error) {
            return handleDatabaseError(error, res, 'create admin');
        }

        res.status(201).json({
            success: true,
            message: 'Admin created successfully',
            admin: {
                id: admin.id,
                firstName: admin.first_name,
                lastName: admin.last_name,
                email: admin.email,
                username: admin.username,
                role: admin.role
            }
        });
    } catch (error) {
        console.error('Create admin error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update user role (admin only)
app.put('/api/admin/users/:id/role', async (req, res) => {
    try {
        const { id } = req.params;
        const { role, isAdmin, isCreator, isBuyer } = req.body;

        const updateData = {};
        if (role !== undefined) updateData.role = role;
        if (isAdmin !== undefined) updateData.is_admin = isAdmin;
        if (isCreator !== undefined) updateData.is_creator = isCreator;
        if (isBuyer !== undefined) updateData.is_buyer = isBuyer;

        const { data: user, error } = await supabase
            .from('users')
            .update(updateData)
            .eq('id', id)
            .select()
            .single();

        if (error) {
            return handleDatabaseError(error, res, 'update user role');
        }

        res.json({
            success: true,
            message: 'User role updated successfully',
            user: {
                id: user.id,
                firstName: user.first_name,
                lastName: user.last_name,
                email: user.email,
                role: user.role,
                isAdmin: user.is_admin,
                isCreator: user.is_creator,
                isBuyer: user.is_buyer
            }
        });
    } catch (error) {
        console.error('Update user role error:', error);
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

app.post('/api/users', async (req, res) => {
    try {
        const { firstName, lastName, email, username, password, phone, profilePicture, role, isAdmin, isCreator, isBuyer } = req.body;

        // Validate required fields
        if (!firstName || !lastName || !email || !password) {
            return res.status(400).json({
                success: false,
                message: 'First name, last name, email, and password are required'
            });
        }

        // Check if user with email already exists
        const { data: existingUserByEmail } = await supabase
            .from('users')
            .select('id')
            .eq('email', email)
            .single();

        if (existingUserByEmail) {
            return res.status(400).json({
                success: false,
                message: 'User with this email already exists'
            });
        }

        // Check if username is provided and unique
        if (username) {
            const { data: existingUserByUsername } = await supabase
                .from('users')
                .select('id')
                .eq('username', username)
                .single();

            if (existingUserByUsername) {
                return res.status(400).json({
                    success: false,
                    message: 'Username already taken'
                });
            }
        }

        // Hash the password
        let hashedPassword;
        try {
            hashedPassword = await bcrypt.hash(password, saltRounds);
        } catch (hashError) {
            console.error('Password hashing error:', hashError);
            return res.status(500).json({
                success: false,
                message: 'Error processing password'
            });
        }

        const userData = {
            first_name: firstName,
            last_name: lastName,
            email,
            username: username || null,
            password: hashedPassword, // Store hashed password
            phone: phone || null,
            profile_picture: profilePicture || '',
            role: role || 'user',
            is_admin: isAdmin || false,
            is_creator: isCreator || false,
            is_buyer: isBuyer !== undefined ? isBuyer : true,
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

        // Return user without password
        const userResponse = {
            id: user.id,
            firstName: user.first_name,
            lastName: user.last_name,
            email: user.email,
            username: user.username,
            phone: user.phone,
            role: user.role || 'user',
            isAdmin: user.is_admin || false,
            isCreator: user.is_creator || false,
            isBuyer: user.is_buyer || true,
            profilePicture: user.profile_picture,
            createdAt: user.created_at
        };

        res.status(201).json({
            success: true,
            message: 'User created successfully',
            user: userResponse
        });
    } catch (error) {
        console.error('Create user error:', error);
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
        console.log('Fetching sound kits from Supabase...');
        
        const { data: soundKits, error } = await supabase
            .from('sound_kits')
            .select('*')
            .eq('is_active', true)
            .order('created_at', { ascending: false });

        if (error) {
            console.error('Supabase error fetching sound kits:', error);
            return res.status(500).json({
                success: false,
                message: 'Database error',
                error: error.message
            });
        }

        console.log(`Found ${soundKits?.length || 0} sound kits`);

        res.json({
            success: true,
            soundKits: soundKits ? toCamelCase(soundKits) : []
        });
    } catch (error) {
        console.error('Get sound kits error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});


// Get dashboard data - FIXED
app.get('/api/dashboard-data', async (req, res) => {
    try {
        console.log('Fetching dashboard data...');

        // Get tracks count and top tracks
        const { data: tracks, error: tracksError } = await supabase
            .from('tracks')
            .select('id, track_name, musician, view_count, play_count, sales_count')
            .eq('is_active', true)
            .order('view_count', { ascending: false })
            .limit(5);

        if (tracksError) {
            console.error('Error fetching tracks:', tracksError);
        }

        // Get sound kits count and top sound kits
        const { data: soundKits, error: soundKitsError } = await supabase
            .from('sound_kits')
            .select('id, kit_name, musician, price, created_at')
            .eq('is_active', true)
            .order('created_at', { ascending: false })
            .limit(5);

        if (soundKitsError) {
            console.error('Error fetching sound kits:', soundKitsError);
        }

        // Get users count
        const { data: users, error: usersError } = await supabase
            .from('users')
            .select('id', { count: 'exact' });

        if (usersError) {
            console.error('Error fetching users:', usersError);
        }

        // Calculate totals
        const totalTracks = tracks?.length || 0;
        const totalSoundKits = soundKits?.length || 0;
        const totalUsers = users?.length || 0;
        const totalRevenue = 0; // Calculate from sales if you have that table

        res.json({
            success: true,
            data: {
                totalTracks,
                totalSoundKits,
                totalUsers,
                totalRevenue,
                topTracks: tracks ? toCamelCase(tracks) : [],
                topSoundKits: soundKits ? toCamelCase(soundKits) : []
            }
        });
    } catch (error) {
        console.error('Dashboard data error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch dashboard data',
            error: error.message
        });
    }
});

// Create sound kit with files - FIXED
app.post('/api/sound-kits-with-files', upload.fields([
    { name: 'kitImage', maxCount: 1 },
    { name: 'kitFile', maxCount: 1 },
    { name: 'musicianProfilePicture', maxCount: 1 }
]), async (req, res) => {
    try {
        console.log('Creating sound kit with files...');
        console.log('Request body:', req.body);
        console.log('Request files:', req.files);

        const {
            kitName, kitId, description, category, price, musician,
            kitType, bpm, key, tags, publish, seoTitle, metaKeyword, metaDescription
        } = req.body;

        // Handle file uploads
        let kitImageId = null;
        let kitFileId = null;
        let musicianProfilePictureId = null;

        if (req.files) {
            const files = req.files;
            
            if (files.kitImage && files.kitImage[0]) {
                kitImageId = files.kitImage[0].id;
            }
            if (files.kitFile && files.kitFile[0]) {
                kitFileId = files.kitFile[0].id;
            }
            if (files.musicianProfilePicture && files.musicianProfilePicture[0]) {
                musicianProfilePictureId = files.musicianProfilePicture[0].id;
            }
        }

        // Parse arrays
        let parsedCategory = [];
        try {
            parsedCategory = typeof category === 'string' ? JSON.parse(category) : category || [];
        } catch (e) {
            parsedCategory = [];
        }

        let parsedTags = [];
        try {
            parsedTags = typeof tags === 'string' ? JSON.parse(tags) : tags || [];
        } catch (e) {
            parsedTags = [];
        }

        const soundKitData = {
            kit_name: kitName || '',
            kit_id: kitId || '',
            description: description || '',
            category: parsedCategory,
            price: price && !isNaN(parseFloat(price)) ? parseFloat(price) : 0,
            musician: musician || '',
            kit_type: kitType || '',
            bpm: bpm && !isNaN(parseInt(bpm)) ? parseInt(bpm) : null,
            key: key || '',
            kit_image: kitImageId,
            kit_file: kitFileId,
            musician_profile_picture: musicianProfilePictureId,
            tags: parsedTags,
            publish: publish || 'Private',
            seo_title: seoTitle || '',
            meta_keyword: metaKeyword || '',
            meta_description: metaDescription || '',
            is_active: true
        };

        console.log('Inserting sound kit data:', soundKitData);

        const { data: soundKit, error } = await supabase
            .from('sound_kits')
            .insert([soundKitData])
            .select()
            .single();

        if (error) {
            console.error('Supabase insert error:', error);
            return handleDatabaseError(error, res, 'sound kit creation');
        }

        console.log('Sound kit created successfully:', soundKit);

        res.status(201).json({
            success: true,
            message: 'Sound kit created successfully',
            soundKit: toCamelCase(soundKit)
        });
    } catch (error) {
        console.error('Sound kit with files creation error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
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


// --------------- Newly added ---------------

// =====================================================
// CART APIS
// =====================================================

// Get user's cart
app.get('/api/cart/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        const { data: cartItems, error } = await supabase
            .from('cart_items')
            .select(`
                *,
                tracks (
                    id,
                    track_name,
                    track_image,
                    track_price,
                    musician,
                    musician_profile_picture,
                    track_file,
                    creator_id,
                    personal_price,
                    commercial_price,
                    exclusive_price
                )
            `)
            .eq('user_id', userId)
            .order('added_at', { ascending: false });

        if (error) {
            return handleDatabaseError(error, res, 'get cart');
        }

        // Calculate totals
        let subtotal = 0;
        const items = cartItems.map(item => {
            const track = item.tracks;
            let price = track.track_price || 0;

            // Apply license multiplier
            if (item.license_type === 'commercial') {
                price = track.commercial_price || price * 2.5;
            } else if (item.license_type === 'exclusive') {
                price = track.exclusive_price || price * 10;
            } else {
                price = track.personal_price || price;
            }

            subtotal += price;

            return {
                ...toCamelCase(item),
                track: toCamelCase(track),
                price: price
            };
        });

        const platformFee = Math.round(subtotal * 0.15 * 100); // 15% fee
        const total = subtotal;

        res.json({
            success: true,
            cart: {
                items,
                itemCount: items.length,
                subtotal,
                platformFee,
                total
            }
        });
    } catch (error) {
        console.error('Get cart error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Add item to cart
app.post('/api/cart', async (req, res) => {
    try {
        const { userId, trackId, licenseType = 'personal' } = req.body;

        if (!userId || !trackId) {
            return res.status(400).json({
                success: false,
                message: 'User ID and Track ID are required'
            });
        }

        // Check if item already in cart
        const { data: existingItem } = await supabase
            .from('cart_items')
            .select('id')
            .eq('user_id', userId)
            .eq('track_id', trackId)
            .single();

        if (existingItem) {
            // Update license type if already in cart
            const { data: updatedItem, error } = await supabase
                .from('cart_items')
                .update({ license_type: licenseType })
                .eq('id', existingItem.id)
                .select()
                .single();

            if (error) {
                return handleDatabaseError(error, res, 'update cart item');
            }

            return res.json({
                success: true,
                message: 'Cart item updated',
                cartItem: toCamelCase(updatedItem)
            });
        }

        // Check if user already owns this track
        const { data: existingPurchase } = await supabase
            .from('user_library')
            .select('id')
            .eq('user_id', userId)
            .eq('track_id', trackId)
            .single();

        if (existingPurchase) {
            return res.status(400).json({
                success: false,
                message: 'You already own this track'
            });
        }

        // Add to cart
        const { data: cartItem, error } = await supabase
            .from('cart_items')
            .insert([{
                user_id: userId,
                track_id: trackId,
                license_type: licenseType
            }])
            .select()
            .single();

        if (error) {
            return handleDatabaseError(error, res, 'add to cart');
        }

        res.status(201).json({
            success: true,
            message: 'Added to cart',
            cartItem: toCamelCase(cartItem)
        });
    } catch (error) {
        console.error('Add to cart error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Update cart item (change license type)
app.put('/api/cart/:itemId', async (req, res) => {
    try {
        const { itemId } = req.params;
        const { licenseType } = req.body;

        const { data: cartItem, error } = await supabase
            .from('cart_items')
            .update({ license_type: licenseType })
            .eq('id', itemId)
            .select()
            .single();

        if (error) {
            return handleDatabaseError(error, res, 'update cart item');
        }

        res.json({
            success: true,
            message: 'Cart item updated',
            cartItem: toCamelCase(cartItem)
        });
    } catch (error) {
        console.error('Update cart item error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Remove item from cart
app.delete('/api/cart/:itemId', async (req, res) => {
    try {
        const { itemId } = req.params;

        const { error } = await supabase
            .from('cart_items')
            .delete()
            .eq('id', itemId);

        if (error) {
            return handleDatabaseError(error, res, 'remove from cart');
        }

        res.json({
            success: true,
            message: 'Removed from cart'
        });
    } catch (error) {
        console.error('Remove from cart error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Clear user's cart
app.delete('/api/cart/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        const { error } = await supabase
            .from('cart_items')
            .delete()
            .eq('user_id', userId);

        if (error) {
            return handleDatabaseError(error, res, 'clear cart');
        }

        res.json({
            success: true,
            message: 'Cart cleared'
        });
    } catch (error) {
        console.error('Clear cart error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// =====================================================
// ORDER APIS
// =====================================================
/*
----------KAKAO, NEVER PAY + ETC K-Pay METHODS---------
app.post('/api/checkout', async (req, res) => {
    try {
        const { userId, items, currency = 'usd' } = req.body;  // Accept currency parameter
        
        if (!userId || !items || items.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'User ID and items are required'
            });
        }

        // Get buyer email
        const { data: buyer } = await supabase
            .from('users')
            .select('email')
            .eq('id', userId)
            .single();

        // Determine currency and payment methods
        const isKRW = currency.toLowerCase() === 'krw';
        const exchangeRate = parseFloat(process.env.USD_TO_KRW_RATE) || 1450;
        
        // Set payment methods based on currency
        let paymentMethodTypes;
        if (isKRW) {
            // KRW supports Kakao Pay, Naver Pay, Korean cards, and international cards
            paymentMethodTypes = ['card', 'kakao_pay', 'kr_card', 'naver_pay', 'samsung_pay', 'payco'];
        } else {
            // USD only supports card payments
            paymentMethodTypes = ['card'];
        }

        // Build line items and calculate transfers
        const lineItems = [];
        const orderData = [];

        for (const item of items) {
            // Get track with creator's Stripe account
            const { data: track } = await supabase
                .from('tracks')
                .select(`
                    *,
                    creator:users!tracks_creator_id_fkey (
                        id,
                        stripe_account_id,
                        stripe_payouts_enabled
                    )
                `)
                .eq('id', item.trackId)
                .single();

            if (!track) continue;

            // Check if creator has Stripe connected
            if (!track.creator?.stripe_account_id || !track.creator?.stripe_payouts_enabled) {
                return res.status(400).json({
                    success: false,
                    message: `Creator for track "${track.track_name}" has not set up payouts. Please contact the creator.`
                });
            }

            // Calculate price based on license (in USD)
            let priceUSD = track.track_price || 0;
            if (item.licenseType === 'commercial') {
                priceUSD = track.commercial_price || priceUSD * 2.5;
            } else if (item.licenseType === 'exclusive') {
                priceUSD = track.exclusive_price || priceUSD * 10;
            }

            // Convert to KRW if needed
            let price = priceUSD;
            let unitAmount;
            
            if (isKRW) {
                // Convert USD to KRW (no decimals for KRW)
                price = Math.round(priceUSD * exchangeRate);
                unitAmount = price; // KRW doesn't use cents
            } else {
                unitAmount = Math.round(price * 100); // USD uses cents
            }

            // Calculate fees
            const platformFeePercent = 0.15;
            const platformFee = Math.round(price * platformFeePercent * (isKRW ? 1 : 100));
            
            // Stripe fee: 2.9% + $0.30 (or equivalent in KRW)
            const stripeFeePercent = 0.029;
            const stripeFeeFixed = isKRW ? 435 : 30; // ~$0.30 in KRW
            const stripeFee = Math.round((price * stripeFeePercent * (isKRW ? 1 : 100)) + stripeFeeFixed);
            
            // Seller amount after fees
            const sellerAmount = unitAmount - platformFee - stripeFee;

            console.log('=== FEE CALCULATION ===');
            console.log('Currency:', isKRW ? 'KRW' : 'USD');
            console.log('Price:', price, isKRW ? 'KRW' : 'USD');
            console.log('Unit Amount:', unitAmount);
            console.log('Platform Fee:', platformFee);
            console.log('Stripe Fee:', stripeFee);
            console.log('Seller Amount:', sellerAmount);
            console.log('=======================');

            lineItems.push({
                price_data: {
                    currency: isKRW ? 'krw' : 'usd',
                    product_data: {
                        name: track.track_name,
                        description: `${item.licenseType.charAt(0).toUpperCase() + item.licenseType.slice(1)} License`,
                        images: track.track_image ? [track.track_image] : [],
                    },
                    unit_amount: unitAmount,
                },
                quantity: 1,
            });

            orderData.push({
                trackId: item.trackId,
                licenseType: item.licenseType,
                priceUSD: priceUSD,           // Original USD price
                price: isKRW ? price : priceUSD, // Price in transaction currency
                currency: isKRW ? 'krw' : 'usd',
                sellerId: track.creator_id,
                sellerStripeAccountId: track.creator.stripe_account_id,
                platformFee: platformFee / (isKRW ? 1 : 100),
                stripeFee: stripeFee / (isKRW ? 1 : 100),
                sellerEarnings: sellerAmount / (isKRW ? 1 : 100)
            });
        }

        // Create Stripe Checkout Session with appropriate payment methods
        const sessionConfig = {
            payment_method_types: paymentMethodTypes,
            line_items: lineItems,
            mode: 'payment',
            success_url: `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/payment/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.FRONTEND_URL}/user/pages/Cart`,
            customer_email: buyer?.email,
            metadata: {
                userId: userId,
                orderData: JSON.stringify(orderData),
                currency: isKRW ? 'krw' : 'usd'
            },
            payment_intent_data: {
                transfer_group: `ORDER-${Date.now()}`
            }
        };

        const session = await stripe.checkout.sessions.create(sessionConfig);

        console.log('Checkout session created with payment methods:', paymentMethodTypes);

        res.json({
            success: true,
            sessionId: session.id,
            url: session.url,
            currency: isKRW ? 'krw' : 'usd',
            paymentMethods: paymentMethodTypes
        });

    } catch (error) {
        console.error('Checkout error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});*/

app.post('/api/checkout', async (req, res) => {
    try {
        const { userId, items, currency = 'usd' } = req.body;
        
        if (!userId || !items || items.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'User ID and items are required'
            });
        }

        // Get buyer email
        const { data: buyer } = await supabase
            .from('users')
            .select('email')
            .eq('id', userId)
            .single();

        // Determine currency and payment methods
        const isKRW = currency.toLowerCase() === 'krw';
        const exchangeRate = parseFloat(process.env.USD_TO_KRW_RATE) || 1450;
        
        // Set payment methods based on currency
        // ONLY Card for USD, ONLY Kakao Pay + Card for KRW
        let paymentMethodTypes;
        if (isKRW) {
            paymentMethodTypes = ['kakao_pay', 'card'];
            // Commented out other Korean payment methods:
            // 'kr_card', 'naver_pay', 'samsung_pay', 'payco'
        } else {
            paymentMethodTypes = ['card'];
        }

        // Build line items and calculate transfers
        const lineItems = [];
        const orderData = [];

        for (const item of items) {
            // Get track with creator's Stripe account
            const { data: track } = await supabase
                .from('tracks')
                .select(`
                    *,
                    creator:users!tracks_creator_id_fkey (
                        id,
                        stripe_account_id,
                        stripe_payouts_enabled
                    )
                `)
                .eq('id', item.trackId)
                .single();

            if (!track) continue;

            // Check if creator has Stripe connected
            if (!track.creator?.stripe_account_id || !track.creator?.stripe_payouts_enabled) {
                return res.status(400).json({
                    success: false,
                    message: `Creator for track "${track.track_name}" has not set up payouts. Please contact the creator.`
                });
            }

            // Calculate price based on license (in USD)
            let priceUSD = track.track_price || 0;
            if (item.licenseType === 'commercial') {
                priceUSD = track.commercial_price || priceUSD * 2.5;
            } else if (item.licenseType === 'exclusive') {
                priceUSD = track.exclusive_price || priceUSD * 10;
            }

            // Convert to KRW if needed
            let price = priceUSD;
            let unitAmount;
            
            if (isKRW) {
                // Convert USD to KRW (no decimals for KRW)
                price = Math.round(priceUSD * exchangeRate);
                unitAmount = price; // KRW doesn't use cents
            } else {
                unitAmount = Math.round(price * 100); // USD uses cents
            }

            // Calculate fees
            const platformFeePercent = 0.15;
            const platformFee = Math.round(price * platformFeePercent * (isKRW ? 1 : 100));
            
            // Stripe fee: 2.9% + $0.30 (or equivalent in KRW)
            const stripeFeePercent = 0.029;
            const stripeFeeFixed = isKRW ? 435 : 30; // ~$0.30 in KRW
            const stripeFee = Math.round((price * stripeFeePercent * (isKRW ? 1 : 100)) + stripeFeeFixed);
            
            // Seller amount after fees
            const sellerAmount = unitAmount - platformFee - stripeFee;

            console.log('=== FEE CALCULATION ===');
            console.log('Currency:', isKRW ? 'KRW' : 'USD');
            console.log('Price:', price, isKRW ? 'KRW' : 'USD');
            console.log('Unit Amount:', unitAmount);
            console.log('Platform Fee:', platformFee);
            console.log('Stripe Fee:', stripeFee);
            console.log('Seller Amount:', sellerAmount);
            console.log('=======================');

            lineItems.push({
                price_data: {
                    currency: isKRW ? 'krw' : 'usd',
                    product_data: {
                        name: track.track_name,
                        description: `${item.licenseType.charAt(0).toUpperCase() + item.licenseType.slice(1)} License`,
                        images: track.track_image ? [track.track_image] : [],
                    },
                    unit_amount: unitAmount,
                },
                quantity: 1,
            });

            orderData.push({
                trackId: item.trackId,
                licenseType: item.licenseType,
                priceUSD: priceUSD,
                price: isKRW ? price : priceUSD,
                currency: isKRW ? 'krw' : 'usd',
                sellerId: track.creator_id,
                sellerStripeAccountId: track.creator.stripe_account_id,
                platformFee: platformFee / (isKRW ? 1 : 100),
                stripeFee: stripeFee / (isKRW ? 1 : 100),
                sellerEarnings: sellerAmount / (isKRW ? 1 : 100)
            });
        }

        // Create Stripe Checkout Session
        const sessionConfig = {
            payment_method_types: paymentMethodTypes,
            line_items: lineItems,
            mode: 'payment',
            success_url: `${process.env.BACKEND_URL || 'http://localhost:3001'}/api/payment/success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.FRONTEND_URL}/user/pages/Cart`,
            customer_email: buyer?.email,
            metadata: {
                userId: userId,
                orderData: JSON.stringify(orderData),
                currency: isKRW ? 'krw' : 'usd'
            },
            payment_intent_data: {
                transfer_group: `ORDER-${Date.now()}`
            }
        };

        const session = await stripe.checkout.sessions.create(sessionConfig);

        console.log('Checkout session created with payment methods:', paymentMethodTypes);

        res.json({
            success: true,
            sessionId: session.id,
            url: session.url,
            currency: isKRW ? 'krw' : 'usd',
            paymentMethods: paymentMethodTypes
        });

    } catch (error) {
        console.error('Checkout error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

app.get('/api/checkout/currency-options', async (req, res) => {
    try {
        // You can use IP geolocation or browser locale
        const acceptLanguage = req.headers['accept-language'] || '';
        const isKorean = acceptLanguage.includes('ko');
        
        res.json({
            success: true,
            suggestedCurrency: isKorean ? 'krw' : 'usd',
            availableCurrencies: [
                { code: 'usd', name: 'US Dollar', symbol: '$' },
                { code: 'krw', name: 'Korean Won', symbol: '₩' }
            ],
            paymentMethodsByCurrency: {
                usd: ['card'],
                krw: ['card', 'kakao_pay', 'naver_pay', 'samsung_pay', 'payco', 'kr_card']
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/payment/success', async (req, res) => {
    try {
        const { session_id } = req.query;
        console.log('=== PAYMENT SUCCESS ===');
        console.log('Session ID:', session_id);
        
        const session = await stripe.checkout.sessions.retrieve(session_id, {
            expand: ['payment_intent', 'payment_intent.latest_charge']
        });
        
        console.log('Payment status:', session.payment_status);
        console.log('Payment method types:', session.payment_method_types);
        
        if (session.payment_status === 'paid') {
            const { userId, orderData, currency } = session.metadata;
            const items = JSON.parse(orderData);
            const paymentIntentId = session.payment_intent?.id || session.payment_intent;
            const isKRW = currency === 'krw';
            
            console.log('Original currency:', currency);
            console.log('Payment Intent ID:', paymentIntentId);

            // Get charge and balance transaction details
            let chargeId = null;
            let actualAmountReceived = 0;
            let settlementCurrency = 'usd';
            
            try {
                // Get the payment intent with expanded charge
                const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId, {
                    expand: ['latest_charge.balance_transaction']
                });
                
                const charge = paymentIntent.latest_charge;
                chargeId = typeof charge === 'string' ? charge : charge?.id;
                
                console.log('Charge ID:', chargeId);
                console.log('Charge type:', typeof charge);
                
                if (charge && typeof charge === 'object') {
                    // If charge is expanded, get balance transaction directly
                    const balanceTransaction = charge.balance_transaction;
                    
                    if (balanceTransaction && typeof balanceTransaction === 'object') {
                        actualAmountReceived = balanceTransaction.net;
                        settlementCurrency = balanceTransaction.currency;
                        console.log('Balance transaction (expanded):', balanceTransaction.id);
                        console.log('Net amount:', actualAmountReceived, settlementCurrency);
                    } else if (balanceTransaction && typeof balanceTransaction === 'string') {
                        // Balance transaction is a string ID, need to retrieve it
                        const bt = await stripe.balanceTransactions.retrieve(balanceTransaction);
                        actualAmountReceived = bt.net;
                        settlementCurrency = bt.currency;
                        console.log('Balance transaction (retrieved):', bt.id);
                        console.log('Net amount:', actualAmountReceived, settlementCurrency);
                    } else {
                        console.log('⚠️ Balance transaction not yet available');
                    }
                }
                
                // If balance transaction is not available yet (can happen with some payment methods),
                // calculate from the session amount
                if (actualAmountReceived === 0 && isKRW) {
                    // Get the amount from the session and estimate USD conversion
                    const amountTotal = session.amount_total; // in KRW (smallest unit)
                    const exchangeRate = parseFloat(process.env.USD_TO_KRW_RATE) || 1450;
                    
                    // Convert KRW to USD cents
                    const estimatedUSDCents = Math.round((amountTotal / exchangeRate) * 100);
                    
                    // Estimate Stripe fee (approximately 3.4% + $0.30 for international)
                    const estimatedStripeFee = Math.round(estimatedUSDCents * 0.034) + 30;
                    actualAmountReceived = estimatedUSDCents - estimatedStripeFee;
                    
                    console.log('=== FALLBACK CALCULATION ===');
                    console.log('Session amount (KRW):', amountTotal);
                    console.log('Estimated USD cents:', estimatedUSDCents);
                    console.log('Estimated Stripe fee:', estimatedStripeFee);
                    console.log('Estimated net (cents):', actualAmountReceived);
                    console.log('============================');
                }
                
            } catch (piError) {
                console.error('Error retrieving payment details:', piError.message);
                
                // Fallback: Calculate from session amount
                if (isKRW && session.amount_total) {
                    const amountTotal = session.amount_total;
                    const exchangeRate = parseFloat(process.env.USD_TO_KRW_RATE) || 1450;
                    const estimatedUSDCents = Math.round((amountTotal / exchangeRate) * 100);
                    const estimatedStripeFee = Math.round(estimatedUSDCents * 0.034) + 30;
                    actualAmountReceived = estimatedUSDCents - estimatedStripeFee;
                    
                    console.log('=== ERROR FALLBACK CALCULATION ===');
                    console.log('Session amount (KRW):', amountTotal);
                    console.log('Estimated net (cents):', actualAmountReceived);
                    console.log('==================================');
                }
            }

            // If we still don't have chargeId, try to get it directly
            if (!chargeId) {
                try {
                    const pi = await stripe.paymentIntents.retrieve(paymentIntentId);
                    chargeId = pi.latest_charge;
                    console.log('Retrieved charge ID separately:', chargeId);
                } catch (e) {
                    console.error('Could not retrieve charge ID:', e.message);
                }
            }

            for (const item of items) {
                const orderNumber = 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6).toUpperCase();
                console.log('Processing order:', orderNumber);

                let transferAmount;
                let transferCurrency = settlementCurrency;
                
                if (isKRW) {
                    // For KRW payments, calculate based on what platform received
                    const platformFeeAmount = Math.round(actualAmountReceived * 0.15);
                    transferAmount = actualAmountReceived - platformFeeAmount;
                    
                    console.log('=== TRANSFER CALCULATION (KRW→USD) ===');
                    console.log('Buyer paid:', item.price, 'KRW');
                    console.log('Platform received (after Stripe fee):', actualAmountReceived, 'cents USD');
                    console.log('Platform keeps (15%):', platformFeeAmount, 'cents USD');
                    console.log('Seller receives:', transferAmount, 'cents USD');
                    console.log('=======================================');
                } else {
                    // For USD payments, use the pre-calculated amount
                    transferAmount = Math.round(item.sellerEarnings * 100);
                    
                    console.log('=== TRANSFER CALCULATION (USD) ===');
                    console.log('Buyer paid: $', item.price);
                    console.log('Platform Fee: $', item.platformFee);
                    console.log('Stripe Fee: $', item.stripeFee);
                    console.log('Seller Earnings: $', item.sellerEarnings);
                    console.log('Transfer Amount (cents):', transferAmount);
                    console.log('==================================');
                }
                
                // Create transfer to seller
                if (chargeId && item.sellerStripeAccountId && transferAmount > 0) {
                    try {
                        const transfer = await stripe.transfers.create({
                            amount: transferAmount,
                            currency: transferCurrency,
                            destination: item.sellerStripeAccountId,
                            source_transaction: chargeId,
                            metadata: {
                                orderId: orderNumber,
                                trackId: item.trackId,
                                sellerId: item.sellerId,
                                originalCurrency: currency,
                                originalAmount: item.price
                            }
                        });
                        console.log('✅ Transfer successful:', transfer.id, '- Amount:', transferAmount, transferCurrency.toUpperCase());
                    } catch (transferError) {
                        console.error('❌ Transfer error:', transferError.message);
                        
                        // If source_transaction fails, try without it (separate transfer)
                        if (transferError.message.includes('source_transaction')) {
                            try {
                                console.log('Attempting transfer without source_transaction...');
                                const transfer = await stripe.transfers.create({
                                    amount: transferAmount,
                                    currency: transferCurrency,
                                    destination: item.sellerStripeAccountId,
                                    metadata: {
                                        orderId: orderNumber,
                                        trackId: item.trackId,
                                        sellerId: item.sellerId,
                                        originalCurrency: currency,
                                        originalAmount: item.price,
                                        note: 'Transfer without source_transaction'
                                    }
                                });
                                console.log('✅ Transfer successful (without source):', transfer.id);
                            } catch (transferError2) {
                                console.error('❌ Transfer error (retry):', transferError2.message);
                            }
                        }
                    }
                } else {
                    console.log('⚠️ Skipping transfer - missing data or zero amount');
                    console.log('  chargeId:', chargeId);
                    console.log('  sellerStripeAccountId:', item.sellerStripeAccountId);
                    console.log('  transferAmount:', transferAmount);
                }

                // Calculate seller earnings in USD for database
                const sellerEarningsUSD = isKRW 
                    ? (transferAmount / 100)
                    : item.sellerEarnings;

                // Create order record
                const { data: order, error: orderError } = await supabase
                    .from('orders')
                    .insert([{
                        order_number: orderNumber,
                        buyer_id: userId,
                        seller_id: item.sellerId,
                        track_id: item.trackId,
                        license_type: item.licenseType,
                        base_price: item.priceUSD || (item.price / (parseFloat(process.env.USD_TO_KRW_RATE) || 1450)),
                        platform_fee: isKRW ? (actualAmountReceived * 0.15 / 100) : item.platformFee,
                        stripe_fee: item.stripeFee || 0,
                        seller_earnings: sellerEarningsUSD,
                        total_amount: item.priceUSD || (item.price / (parseFloat(process.env.USD_TO_KRW_RATE) || 1450)),
                        currency: currency,
                        status: 'completed',
                        payment_provider: 'stripe',
                        payment_method: isKRW ? 'kakao_pay' : 'card',
                        payment_reference: paymentIntentId
                    }])
                    .select()
                    .single();

                if (orderError) {
                    console.error('❌ Order creation error:', orderError);
                } else {
                    console.log('✅ Order created:', order.id);
                }

                // Record creator earnings
                if (order) {
                    await supabase
                        .from('creator_earnings')
                        .insert([{
                            user_id: item.sellerId,
                            order_id: order.id,
                            track_id: item.trackId,
                            amount: sellerEarningsUSD,
                            currency: 'usd',
                            status: transferAmount > 0 ? 'transferred' : 'pending'
                        }]);
                    console.log('✅ Creator earnings recorded: $' + sellerEarningsUSD.toFixed(2));
                }

                // Update track sales count
                const { error: rpcError } = await supabase.rpc('increment_sales_count', { 
                    track_id: item.trackId 
                });
                
                if (rpcError) {
                    console.error('❌ Sales count increment error:', rpcError);
                } else {
                    console.log('✅ Sales count incremented');
                }

                // Generate license key
                const licenseKey = 'MSL-' + 
                    Math.random().toString(36).substr(2, 4).toUpperCase() + '-' +
                    Math.random().toString(36).substr(2, 4).toUpperCase() + '-' +
                    Math.random().toString(36).substr(2, 4).toUpperCase() + '-' +
                    Math.random().toString(36).substr(2, 4).toUpperCase();

                // Add to user library
                if (order) {
                    await supabase
                        .from('user_library')
                        .insert([{
                            user_id: userId,
                            track_id: item.trackId,
                            order_id: order.id,
                            license_type: item.licenseType,
                            license_key: licenseKey
                        }]);
                    console.log('✅ Added to user library');
                }

                // Clear from cart
                await supabase
                    .from('cart_items')
                    .delete()
                    .eq('user_id', userId)
                    .eq('track_id', item.trackId);

                // If exclusive license, mark track as sold
                if (item.licenseType === 'exclusive') {
                    await supabase
                        .from('tracks')
                        .update({
                            is_sold_exclusive: true,
                            publish: 'Private'
                        })
                        .eq('id', item.trackId);
                }
            }
            
            console.log('=== PAYMENT SUCCESS COMPLETE ===');
            res.redirect(`${process.env.FRONTEND_URL}/user/pages/PaymentSuccess`);
        } else {
            console.log('Payment not completed, status:', session.payment_status);
            res.redirect(`${process.env.FRONTEND_URL}/user/pages/Cart?error=payment_failed`);
        }
    } catch (error) {
        console.error('Payment success error:', error);
        res.redirect(`${process.env.FRONTEND_URL}/user/pages/Cart?error=processing_failed`);
    }
});

// Stripe webhook to handle payment completion
app.post('/api/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const { userId, orderData } = session.metadata;
        const items = JSON.parse(orderData);

        // Create orders and add to library
        for (const item of items) {
            const orderNumber = 'ORD-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6).toUpperCase();
            const platformFee = Math.round(item.price * 0.15 * 100);
            const sellerEarnings = item.price - platformFee;

            // Create order
            const { data: order } = await supabase
                .from('orders')
                .insert([{
                    order_number: orderNumber,
                    buyer_id: userId,
                    seller_id: item.sellerId,
                    track_id: item.trackId,
                    license_type: item.licenseType,
                    base_price: item.price,
                    platform_fee: platformFee,
                    seller_earnings: sellerEarnings,
                    total_amount: item.price,
                    status: 'completed',
                    payment_provider: 'stripe',
                    payment_reference: session.payment_intent
                }])
                .select()
                .single();

            // INSERT creator earnings
            await supabase
                .from('creator_earnings')
                .insert([{
                    user_id: item.sellerId,
                    order_id: order.id,
                    track_id: item.trackId,
                    amount: sellerEarnings,
                    status: 'available'
                }]);

            // Update track sales count
            await supabase.rpc('increment_sales_count', { track_id: item.trackId });

            // Generate license key
            const licenseKey = 'MSL-' +
                Math.random().toString(36).substr(2, 4).toUpperCase() + '-' +
                Math.random().toString(36).substr(2, 4).toUpperCase() + '-' +
                Math.random().toString(36).substr(2, 4).toUpperCase() + '-' +
                Math.random().toString(36).substr(2, 4).toUpperCase();

            // Add to library
            await supabase
                .from('user_library')
                .insert([{
                    user_id: userId,
                    track_id: item.trackId,
                    order_id: order.id,
                    license_type: item.licenseType,
                    license_key: licenseKey
                }]);

            // Clear cart
            await supabase
                .from('cart_items')
                .delete()
                .eq('user_id', userId)
                .eq('track_id', item.trackId);

            // If exclusive license, mark track as sold
            if (item.licenseType === 'exclusive') {
                await supabase
                    .from('tracks')
                    .update({
                        is_sold_exclusive: true,
                        publish: 'Private'
                    })
                    .eq('id', item.trackId);
            }
        }
    }

    res.json({ received: true });
});

// Complete order (after payment success)
app.post('/api/orders/complete', async (req, res) => {
    try {
        const { orderIds, paymentReference } = req.body;

        if (!orderIds || orderIds.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Order IDs are required'
            });
        }

        const completedOrders = [];
        const libraryItems = [];

        for (const orderId of orderIds) {
            // Update order status
            const { data: order, error: orderError } = await supabase
                .from('orders')
                .update({
                    status: 'completed',
                    payment_reference: paymentReference
                })
                .eq('id', orderId)
                .select()
                .single();

            if (orderError) {
                console.error('Order completion error:', orderError);
                continue;
            }

            completedOrders.push(order);

            // Generate license key
            const licenseKey = 'MSL-' +
                Math.random().toString(36).substr(2, 4).toUpperCase() + '-' +
                Math.random().toString(36).substr(2, 4).toUpperCase() + '-' +
                Math.random().toString(36).substr(2, 4).toUpperCase() + '-' +
                Math.random().toString(36).substr(2, 4).toUpperCase();

            // Add to user library
            const { data: libraryItem, error: libraryError } = await supabase
                .from('user_library')
                .insert([{
                    user_id: order.buyer_id,
                    track_id: order.track_id,
                    order_id: order.id,
                    license_type: order.license_type,
                    license_key: licenseKey
                }])
                .select()
                .single();

            if (!libraryError) {
                libraryItems.push(libraryItem);
            }

            // Update creator earnings to available
            await supabase
                .from('creator_earnings')
                .update({ status: 'available' })
                .eq('order_id', orderId);

            // Update track sales count
            await supabase.rpc('increment_sales_count', { track_id: order.track_id });

            // If exclusive license, mark track as sold
            if (order.license_type === 'exclusive') {
                await supabase
                    .from('tracks')
                    .update({
                        is_sold_exclusive: true,
                        publish: 'Private'
                    })
                    .eq('id', order.track_id);
            }

            // Clear from cart
            await supabase
                .from('cart_items')
                .delete()
                .eq('user_id', order.buyer_id)
                .eq('track_id', order.track_id);
        }

        res.json({
            success: true,
            message: 'Orders completed',
            orders: completedOrders.map(o => toCamelCase(o)),
            libraryItems: libraryItems.map(l => toCamelCase(l))
        });
    } catch (error) {
        console.error('Complete order error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get user's orders (purchases)
app.get('/api/orders/user/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        const { type = 'purchases' } = req.query; // 'purchases' or 'sales'

        let query = supabase
            .from('orders')
            .select(`
                *,
                tracks (
                    id,
                    track_name,
                    track_image,
                    musician
                ),
                buyer:users!orders_buyer_id_fkey (
                    id,
                    first_name,
                    last_name,
                    email
                ),
                seller:users!orders_seller_id_fkey (
                    id,
                    first_name,
                    last_name
                )
            `)
            .order('created_at', { ascending: false });

        if (type === 'sales') {
            query = query.eq('seller_id', userId);
        } else {
            query = query.eq('buyer_id', userId);
        }

        const { data: orders, error } = await query;

        if (error) {
            return handleDatabaseError(error, res, 'get orders');
        }

        res.json({
            success: true,
            orders: toCamelCase(orders)
        });
    } catch (error) {
        console.error('Get orders error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get single order
app.get('/api/orders/:orderId', async (req, res) => {
    try {
        const { orderId } = req.params;

        const { data: order, error } = await supabase
            .from('orders')
            .select(`
                *,
                tracks (*),
                buyer:users!orders_buyer_id_fkey (*),
                seller:users!orders_seller_id_fkey (*)
            `)
            .eq('id', orderId)
            .single();

        if (error) {
            return handleDatabaseError(error, res, 'get order');
        }

        res.json({
            success: true,
            order: toCamelCase(order)
        });
    } catch (error) {
        console.error('Get order error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// =====================================================
// USER LIBRARY APIS
// =====================================================

// Get user's library (purchased tracks)
app.get('/api/library/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        const { data: library, error } = await supabase
            .from('user_library')
            .select(`
                id,
                track_id,
                license_type,
                license_key,
                download_count,
                purchased_at,
                tracks (
                    id,
                    track_name,
                    track_image,
                    track_file,
                    bpm,
                    track_key,
                    creator:users!tracks_creator_id_fkey (
                        id,
                        first_name,
                        last_name,
                        profile_picture
                    )
                ),
                orders (
                    id,
                    order_number,
                    total_amount,
                    base_price,
                    currency,
                    created_at
                )
            `)
            .eq('user_id', userId)
            .order('purchased_at', { ascending: false });

        if (error) {
            console.error('Library fetch error:', error);
            return res.status(500).json({ success: false, message: error.message });
        }

        // Transform the data
        const transformedLibrary = library.map(item => ({
            id: item.id,
            trackId: item.track_id,
            licenseType: item.license_type,
            licenseKey: item.license_key,
            downloadCount: item.download_count || 0,
            purchasedAt: item.purchased_at,
            tracks: item.tracks ? {
                id: item.tracks.id,
                trackName: item.tracks.track_name,
                trackImage: item.tracks.track_image,
                trackFile: item.tracks.track_file,
                bpm: item.tracks.bpm,
                trackKey: item.tracks.track_key,
                musician: item.tracks.creator 
                    ? `${item.tracks.creator.first_name} ${item.tracks.creator.last_name}` 
                    : 'Unknown Artist',
                musicianProfilePicture: item.tracks.creator?.profile_picture
            } : null,
            orders: item.orders ? {
                id: item.orders.id,
                orderNumber: item.orders.order_number,
                totalAmount: item.orders.total_amount,
                basePrice: item.orders.base_price,
                currency: item.orders.currency || 'usd',
                createdAt: item.orders.created_at
            } : null
        }));

        res.json({
            success: true,
            library: transformedLibrary
        });

    } catch (error) {
        console.error('Library error:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Download track from library
app.post('/api/library/download/:itemId', async (req, res) => {
    try {
        const { itemId } = req.params;
        const { userId } = req.body;

        // Get library item
        const { data: item, error } = await supabase
            .from('user_library')
            .select(`
                *,
                tracks (
                    id,
                    track_name,
                    track_file
                )
            `)
            .eq('id', itemId)
            .eq('user_id', userId)
            .single();

        if (error || !item) {
            return res.status(404).json({
                success: false,
                message: 'Library item not found'
            });
        }

        // Check download limits
        if (item.max_downloads > 0 && item.download_count >= item.max_downloads) {
            return res.status(403).json({
                success: false,
                message: 'Download limit reached'
            });
        }

        // Increment download count
        await supabase
            .from('user_library')
            .update({ download_count: item.download_count + 1 })
            .eq('id', itemId);

        res.json({
            success: true,
            downloadUrl: item.tracks.track_file,
            fileName: item.tracks.track_name + '.mp3'
        });
    } catch (error) {
        console.error('Download error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// =====================================================
// CREATOR/USER TRACK APIS
// =====================================================

// Get user's uploaded tracks
app.get('/api/user-tracks/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        const { data: tracks, error } = await supabase
            .from('tracks')
            .select('*')
            .eq('creator_id', userId)
            .order('created_at', { ascending: false });

        if (error) {
            return handleDatabaseError(error, res, 'get user tracks');
        }

        res.json({
            success: true,
            tracks: toCamelCase(tracks)
        });
    } catch (error) {
        console.error('Get user tracks error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Create track as user (not admin)
app.post('/api/user-tracks', upload.fields([
    { name: 'audio', maxCount: 1 },
    { name: 'image', maxCount: 1 }
]), async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
        }

        // Get user info
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('first_name, last_name, profile_picture')
            .eq('id', userId)
            .single();

        if (userError) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        let audioUrl = null;
        let imageUrl = null;

        // Handle audio upload
        const audioFile = req.files?.['audio']?.[0];
        if (audioFile) {
            const audioExt = audioFile.originalname.split('.').pop();
            const audioFileName = `${uuidv4()}.${audioExt}`;
            const audioFilePath = `audio/${audioFileName}`;

            const { error: audioError } = await supabase.storage
                .from(STORAGE_BUCKET)
                .upload(audioFilePath, audioFile.buffer, {
                    contentType: audioFile.mimetype
                });

            if (!audioError) {
                const { data: { publicUrl } } = supabase.storage
                    .from(STORAGE_BUCKET)
                    .getPublicUrl(audioFilePath);
                audioUrl = publicUrl;
            }
        }

        // Handle image upload
        const imageFile = req.files?.['image']?.[0];
        if (imageFile) {
            const imageExt = imageFile.originalname.split('.').pop();
            const imageFileName = `${uuidv4()}.${imageExt}`;
            const imageFilePath = `images/${imageFileName}`;

            const { error: imageError } = await supabase.storage
                .from(STORAGE_BUCKET)
                .upload(imageFilePath, imageFile.buffer, {
                    contentType: imageFile.mimetype
                });

            if (!imageError) {
                const { data: { publicUrl } } = supabase.storage
                    .from(STORAGE_BUCKET)
                    .getPublicUrl(imageFilePath);
                imageUrl = publicUrl;
            }
        }

        // Generate track ID
        const trackId = 'TRK-' + Date.now() + '-' + Math.random().toString(36).substr(2, 4).toUpperCase();

        // Parse prices
        const basePrice = parseFloat(req.body.trackPrice) || 0;

        // Create track data
        const trackData = {
            track_name: req.body.trackName,
            track_id: trackId,
            bpm: req.body.bpm ? parseInt(req.body.bpm) : null,
            track_key: req.body.trackKey || null,
            track_price: basePrice,
            personal_price: basePrice,
            commercial_price: Math.round(basePrice * 2.5 * 100) / 100,
            exclusive_price: Math.round(basePrice * 10 * 100) / 100,
            musician: `${user.first_name} ${user.last_name}`,
            musician_profile_picture: user.profile_picture || null,
            track_type: req.body.trackType || 'Beats',
            mood_type: req.body.moodType || null,
            energy_type: req.body.energyType || null,
            instrument: req.body.instrument || null,
            track_image: imageUrl,
            track_file: audioUrl,
            about: req.body.about || null,
            publish: req.body.publish || 'Private',
            genre_category: req.body.genreCategory ? JSON.parse(req.body.genreCategory) : [],
            beat_category: req.body.beatCategory ? JSON.parse(req.body.beatCategory) : [],
            track_tags: req.body.trackTags ? JSON.parse(req.body.trackTags) : [],
            creator_id: userId
        };

        const { data: track, error } = await supabase
            .from('tracks')
            .insert([trackData])
            .select()
            .single();

        if (error) {
            return handleDatabaseError(error, res, 'create user track');
        }

        // Update user to creator status
        await supabase
            .from('users')
            .update({ is_creator: true })
            .eq('id', userId);

        res.status(201).json({
            success: true,
            message: 'Track uploaded successfully',
            track: toCamelCase(track)
        });
    } catch (error) {
        console.error('Create user track error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// =====================================================
// CREATOR STATS APIS
// =====================================================

// Get creator dashboard stats
app.get('/api/creator/stats/:userId', async (req, res) => {
    try {
        const { userId } = req.params;
        console.log('Fetching creator stats for user:', userId);

        // Get total tracks count
        const { data: tracks, error: tracksError } = await supabase
            .from('tracks')
            .select('id, view_count, play_count, sales_count')
            .eq('creator_id', userId);

        if (tracksError) {
            console.error('Tracks fetch error:', tracksError);
        }

        const totalTracks = tracks?.length || 0;
        const totalViews = tracks?.reduce((sum, t) => sum + (t.view_count || 0), 0) || 0;
        const totalPlays = tracks?.reduce((sum, t) => sum + (t.play_count || 0), 0) || 0;
        const totalSalesFromTracks = tracks?.reduce((sum, t) => sum + (t.sales_count || 0), 0) || 0;

        // Get earnings from creator_earnings table
        const { data: earnings, error: earningsError } = await supabase
            .from('creator_earnings')
            .select('amount, status, currency, created_at')
            .eq('user_id', userId);

        if (earningsError) {
            console.error('Earnings fetch error:', earningsError);
        }

        // Calculate total earnings (convert KRW to USD if needed)
        const USD_TO_KRW_RATE = 1450;
        let totalEarnings = 0;
        let availableBalance = 0;
        let pendingBalance = 0;

        if (earnings && earnings.length > 0) {
            earnings.forEach(earning => {
                let amount = earning.amount || 0;
                
                // If amount seems to be in KRW (large number), convert to USD
                // This handles legacy data that might have been stored incorrectly
                if (amount > 1000 && earning.currency === 'krw') {
                    amount = amount / USD_TO_KRW_RATE;
                }
                
                totalEarnings += amount;

                // Check if earning is available (more than 7 days old) or pending
                const earningDate = new Date(earning.created_at);
                const sevenDaysAgo = new Date();
                sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

                if (earning.status === 'transferred' || earningDate < sevenDaysAgo) {
                    availableBalance += amount;
                } else {
                    pendingBalance += amount;
                }
            });
        }

        // Alternative: Get earnings from orders table if creator_earnings is empty
        if (totalEarnings === 0) {
            const { data: orders, error: ordersError } = await supabase
                .from('orders')
                .select('seller_earnings, base_price, currency, created_at, status')
                .eq('seller_id', userId)
                .eq('status', 'completed');

            if (ordersError) {
                console.error('Orders fetch error:', ordersError);
            }

            if (orders && orders.length > 0) {
                orders.forEach(order => {
                    let amount = order.seller_earnings || 0;
                    
                    // If seller_earnings is 0 but we have base_price, calculate it
                    if (amount === 0 && order.base_price) {
                        // Seller gets 85% minus Stripe fee
                        const basePrice = order.base_price;
                        const platformFee = basePrice * 0.15;
                        const stripeFee = (basePrice * 0.029) + 0.30;
                        amount = basePrice - platformFee - stripeFee;
                    }
                    
                    // Handle KRW amounts stored incorrectly
                    if (amount > 1000 && order.currency === 'krw') {
                        amount = amount / USD_TO_KRW_RATE;
                    }

                    totalEarnings += amount;

                    const orderDate = new Date(order.created_at);
                    const sevenDaysAgo = new Date();
                    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

                    if (orderDate < sevenDaysAgo) {
                        availableBalance += amount;
                    } else {
                        pendingBalance += amount;
                    }
                });
            }
        }

        // Get total sales count from orders
        const { count: salesCount, error: salesCountError } = await supabase
            .from('orders')
            .select('id', { count: 'exact', head: true })
            .eq('seller_id', userId)
            .eq('status', 'completed');

        if (salesCountError) {
            console.error('Sales count error:', salesCountError);
        }

        const totalSales = salesCount || totalSalesFromTracks;

        // Get recent sales with track and buyer info
        const { data: recentSales, error: recentSalesError } = await supabase
            .from('orders')
            .select(`
                id,
                order_number,
                license_type,
                seller_earnings,
                base_price,
                currency,
                created_at,
                tracks (
                    id,
                    track_name,
                    track_image
                ),
                buyer:users!orders_buyer_id_fkey (
                    id,
                    first_name,
                    last_name
                )
            `)
            .eq('seller_id', userId)
            .eq('status', 'completed')
            .order('created_at', { ascending: false })
            .limit(10);

        if (recentSalesError) {
            console.error('Recent sales error:', recentSalesError);
        }

        // Transform recent sales data
        const transformedRecentSales = (recentSales || []).map(sale => {
            let sellerEarnings = sale.seller_earnings || 0;
            
            // Calculate if not present
            if (sellerEarnings === 0 && sale.base_price) {
                const basePrice = sale.base_price;
                const platformFee = basePrice * 0.15;
                const stripeFee = (basePrice * 0.029) + 0.30;
                sellerEarnings = basePrice - platformFee - stripeFee;
            }
            
            // Convert KRW to USD if needed
            if (sellerEarnings > 1000 && sale.currency === 'krw') {
                sellerEarnings = sellerEarnings / USD_TO_KRW_RATE;
            }

            return {
                id: sale.id,
                orderNumber: sale.order_number,
                licenseType: sale.license_type,
                sellerEarnings: sellerEarnings,
                createdAt: sale.created_at,
                tracks: sale.tracks ? {
                    id: sale.tracks.id,
                    trackName: sale.tracks.track_name,
                    trackImage: sale.tracks.track_image
                } : null,
                buyer: sale.buyer ? {
                    id: sale.buyer.id,
                    firstName: sale.buyer.first_name,
                    lastName: sale.buyer.last_name
                } : null
            };
        });

        console.log('Creator stats calculated:', {
            totalTracks,
            totalSales,
            totalEarnings: totalEarnings.toFixed(2),
            availableBalance: availableBalance.toFixed(2),
            pendingBalance: pendingBalance.toFixed(2)
        });

        res.json({
            success: true,
            stats: {
                totalTracks,
                totalSales,
                totalViews,
                totalPlays,
                totalEarnings: Math.round(totalEarnings * 100) / 100,
                availableBalance: Math.round(availableBalance * 100) / 100,
                pendingBalance: Math.round(pendingBalance * 100) / 100,
                recentSales: transformedRecentSales
            }
        });

    } catch (error) {
        console.error('Creator stats error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// =====================================================
// MARKETPLACE APIS
// =====================================================

// Get marketplace tracks (public tracks for sale)
app.get('/api/marketplace', async (req, res) => {
    try {
        const {
            page = 1,
            limit = 20,
            genre,
            mood,
            minPrice,
            maxPrice,
            sortBy = 'newest',
            search
        } = req.query;

        let query = supabase
            .from('tracks')
            .select('*', { count: 'exact' })
            .eq('is_sold_exclusive', false);

        // FIX: Don't filter by publish status, or make it more inclusive
        // Only exclude explicitly private tracks
        query = query.or('publish.eq.Public,publish.is.null');

        // Apply filters
        if (genre) {
            query = query.contains('genre_category', [genre]);
        }
        if (mood) {
            query = query.eq('mood_type', mood);
        }
        if (minPrice) {
            query = query.gte('track_price', parseFloat(minPrice));
        }
        if (maxPrice) {
            query = query.lte('track_price', parseFloat(maxPrice));
        }
        if (search) {
            query = query.or(`track_name.ilike.%${search}%,musician.ilike.%${search}%`);
        }

        // Apply sorting
        switch (sortBy) {
            case 'popular':
                query = query.order('sales_count', { ascending: false });
                break;
            case 'price_low':
                query = query.order('track_price', { ascending: true });
                break;
            case 'price_high':
                query = query.order('track_price', { ascending: false });
                break;
            case 'newest':
            default:
                query = query.order('created_at', { ascending: false });
        }

        // Apply pagination
        const offset = (parseInt(page) - 1) * parseInt(limit);
        query = query.range(offset, offset + parseInt(limit) - 1);

        const { data: tracks, error, count } = await query;

        if (error) {
            return handleDatabaseError(error, res, 'get marketplace');
        }

        res.json({
            success: true,
            tracks: toCamelCase(tracks),
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total: count,
                totalPages: Math.ceil(count / parseInt(limit))
            }
        });
    } catch (error) {
        console.error('Get marketplace error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Get single track details (for track detail page)
app.get('/api/marketplace/track/:trackId', async (req, res) => {
    try {
        const { trackId } = req.params;

        const { data: track, error } = await supabase
            .from('tracks')
            .select(`
                *,
                creator:users!tracks_creator_id_fkey (
                    id,
                    first_name,
                    last_name,
                    profile_picture,
                    biography
                )
            `)
            .eq('id', trackId)
            .single();

        if (error) {
            return handleDatabaseError(error, res, 'get track details');
        }

        // Increment view count
        await supabase
            .from('tracks')
            .update({ view_count: (track.view_count || 0) + 1 })
            .eq('id', trackId);

        // Get license types
        const { data: licenseTypes } = await supabase
            .from('license_types')
            .select('*')
            .eq('is_active', true)
            .order('sort_order');

        res.json({
            success: true,
            track: toCamelCase(track),
            licenseTypes: toCamelCase(licenseTypes || [])
        });
    } catch (error) {
        console.error('Get track details error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// Increment play count
app.post('/api/tracks/:trackId/play', async (req, res) => {
    try {
        const { trackId } = req.params;

        const { data: track } = await supabase
            .from('tracks')
            .select('play_count')
            .eq('id', trackId)
            .single();

        await supabase
            .from('tracks')
            .update({ play_count: (track?.play_count || 0) + 1 })
            .eq('id', trackId);

        res.json({ success: true });
    } catch (error) {
        console.error('Increment play count error:', error);
        res.status(500).json({ success: false });
    }
});

// =====================================================
// LICENSE TYPES API
// =====================================================

app.get('/api/license-types', async (req, res) => {
    try {
        const { data: licenseTypes, error } = await supabase
            .from('license_types')
            .select('*')
            .eq('is_active', true)
            .order('sort_order');

        if (error) {
            return handleDatabaseError(error, res, 'get license types');
        }

        res.json({
            success: true,
            licenseTypes: toCamelCase(licenseTypes)
        });
    } catch (error) {
        console.error('Get license types error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

// --------------- Newly added ---------------

// =====================================================
// STRIPE CONNECT APIs
// =====================================================

// Create Stripe Connect account for creator
app.post('/api/stripe/connect/create', async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
        }

        // Get user details
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('*')
            .eq('id', userId)
            .single();

        if (userError || !user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Check if user already has a Stripe account
        if (user.stripe_account_id) {
            return res.json({
                success: true,
                message: 'Stripe account already exists',
                stripeAccountId: user.stripe_account_id
            });
        }

        // Create Stripe Connect Express account
        const account = await stripe.accounts.create({
            type: 'express',
            country: user.country || 'US',
            email: user.email,
            capabilities: {
                card_payments: { requested: true },
                transfers: { requested: true },
            },
            business_type: 'individual',
            metadata: {
                userId: userId
            }
        });

        // Save Stripe account ID to user
        await supabase
            .from('users')
            .update({ 
                stripe_account_id: account.id,
                stripe_onboarding_complete: false,
                stripe_payouts_enabled: false
            })
            .eq('id', userId);

        res.json({
            success: true,
            message: 'Stripe Connect account created',
            stripeAccountId: account.id
        });

    } catch (error) {
        console.error('Stripe Connect create error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Generate Stripe Connect onboarding link
app.post('/api/stripe/connect/onboarding', async (req, res) => {
    try {
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({
                success: false,
                message: 'User ID is required'
            });
        }

        // Get user's Stripe account ID
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('stripe_account_id')
            .eq('id', userId)
            .single();

        if (userError || !user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (!user.stripe_account_id) {
            return res.status(400).json({
                success: false,
                message: 'No Stripe account found. Please create one first.'
            });
        }

        // Create onboarding link
        const accountLink = await stripe.accountLinks.create({
            account: user.stripe_account_id,
            refresh_url: `${process.env.FRONTEND_URL}/user/pages/UserProfile?stripe=refresh`,
            return_url: `${process.env.FRONTEND_URL}/user/pages/UserProfile?stripe=success`,
            type: 'account_onboarding',
        });

        res.json({
            success: true,
            url: accountLink.url
        });

    } catch (error) {
        console.error('Stripe onboarding error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Check Stripe Connect account status
app.get('/api/stripe/connect/status/:userId', async (req, res) => {
    try {
        const { userId } = req.params;

        // Get user's Stripe account ID
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('stripe_account_id, stripe_onboarding_complete, stripe_payouts_enabled')
            .eq('id', userId)
            .single();

        if (userError || !user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        if (!user.stripe_account_id) {
            return res.json({
                success: true,
                connected: false,
                onboardingComplete: false,
                payoutsEnabled: false
            });
        }

        // Get account details from Stripe
        const account = await stripe.accounts.retrieve(user.stripe_account_id);

        // Update database with latest status
        const onboardingComplete = account.details_submitted;
        const payoutsEnabled = account.payouts_enabled;

        await supabase
            .from('users')
            .update({
                stripe_onboarding_complete: onboardingComplete,
                stripe_payouts_enabled: payoutsEnabled
            })
            .eq('id', userId);

        res.json({
            success: true,
            connected: true,
            stripeAccountId: user.stripe_account_id,
            onboardingComplete: onboardingComplete,
            payoutsEnabled: payoutsEnabled,
            chargesEnabled: account.charges_enabled
        });

    } catch (error) {
        console.error('Stripe status error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Generate Stripe Dashboard link for creator
app.post('/api/stripe/connect/dashboard', async (req, res) => {
    try {
        const { userId } = req.body;

        // Get user's Stripe account ID
        const { data: user, error: userError } = await supabase
            .from('users')
            .select('stripe_account_id')
            .eq('id', userId)
            .single();

        if (userError || !user || !user.stripe_account_id) {
            return res.status(400).json({
                success: false,
                message: 'No Stripe account connected'
            });
        }

        // Create login link to Stripe Express dashboard
        const loginLink = await stripe.accounts.createLoginLink(user.stripe_account_id);

        res.json({
            success: true,
            url: loginLink.url
        });

    } catch (error) {
        console.error('Stripe dashboard link error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

app.listen(3001, () => {
    console.log('Server is running on port 3001 with Supabase backend');
});

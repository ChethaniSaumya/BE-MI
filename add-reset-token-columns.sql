-- Add reset token columns to users table
-- Run this in your Supabase SQL editor

ALTER TABLE users 
ADD COLUMN IF NOT EXISTS reset_token TEXT,
ADD COLUMN IF NOT EXISTS reset_token_expiry TIMESTAMP WITH TIME ZONE;

-- Add index for better performance
CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(reset_token);

-- Add comment for documentation
COMMENT ON COLUMN users.reset_token IS 'Token for password reset functionality';
COMMENT ON COLUMN users.reset_token_expiry IS 'Expiry time for the reset token';

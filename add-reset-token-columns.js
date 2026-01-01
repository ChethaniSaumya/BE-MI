require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

// Supabase client setup
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
    console.error('Missing Supabase configuration. Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your .env file');
    process.exit(1);
}

const supabase = createClient(supabaseUrl, supabaseServiceKey, {
    auth: {
        autoRefreshToken: false,
        persistSession: false
    }
});

async function addResetTokenColumns() {
    try {
        console.log('Adding reset token columns to users table...');
        
        // Add reset_token column
        const { error: tokenError } = await supabase.rpc('exec_sql', {
            sql: 'ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token TEXT;'
        });
        
        if (tokenError) {
            console.log('Trying alternative method for reset_token column...');
            // Alternative: Try to add column by attempting to insert a test value
            const { error: testError } = await supabase
                .from('users')
                .select('reset_token')
                .limit(1);
                
            if (testError && testError.message.includes('column "reset_token" does not exist')) {
                console.log('reset_token column does not exist. Please add it manually in Supabase dashboard.');
                console.log('Column name: reset_token');
                console.log('Column type: text');
                console.log('Allow nullable: Yes');
            }
        } else {
            console.log('✅ reset_token column added successfully');
        }
        
        // Add reset_token_expiry column
        const { error: expiryError } = await supabase.rpc('exec_sql', {
            sql: 'ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expiry TIMESTAMP WITH TIME ZONE;'
        });
        
        if (expiryError) {
            console.log('Trying alternative method for reset_token_expiry column...');
            // Alternative: Try to add column by attempting to insert a test value
            const { error: testError } = await supabase
                .from('users')
                .select('reset_token_expiry')
                .limit(1);
                
            if (testError && testError.message.includes('column "reset_token_expiry" does not exist')) {
                console.log('reset_token_expiry column does not exist. Please add it manually in Supabase dashboard.');
                console.log('Column name: reset_token_expiry');
                console.log('Column type: timestamptz (timestamp with timezone)');
                console.log('Allow nullable: Yes');
            }
        } else {
            console.log('✅ reset_token_expiry column added successfully');
        }
        
        // Test if columns exist
        const { data, error } = await supabase
            .from('users')
            .select('id, reset_token, reset_token_expiry')
            .limit(1);
            
        if (error) {
            console.log('\n❌ Columns still missing. Please add them manually:');
            console.log('1. Go to your Supabase Dashboard');
            console.log('2. Navigate to Table Editor');
            console.log('3. Select the "users" table');
            console.log('4. Click "Add Column"');
            console.log('5. Add these columns:');
            console.log('   - Name: reset_token, Type: text, Nullable: Yes');
            console.log('   - Name: reset_token_expiry, Type: timestamptz, Nullable: Yes');
        } else {
            console.log('\n✅ Both columns exist and are accessible!');
            console.log('Password reset functionality should now work.');
        }
        
    } catch (error) {
        console.error('Error adding columns:', error);
        console.log('\nPlease add the columns manually in Supabase dashboard:');
        console.log('1. Go to Table Editor → users table');
        console.log('2. Add Column: reset_token (text, nullable)');
        console.log('3. Add Column: reset_token_expiry (timestamptz, nullable)');
    }
}

addResetTokenColumns();

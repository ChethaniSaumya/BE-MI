-- Supabase Database Schema for AI Music Backend
-- Run these commands in your Supabase SQL Editor

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    first_name VARCHAR(20) NOT NULL CHECK (length(first_name) >= 2),
    last_name VARCHAR(20) NOT NULL CHECK (length(last_name) >= 2),
    email VARCHAR(30) NOT NULL UNIQUE CHECK (length(email) > 0),
    password VARCHAR(30) NOT NULL CHECK (length(password) >= 8),
    display_name VARCHAR(50),
    location VARCHAR(100),
    country VARCHAR(50),
    biography VARCHAR(500),
    profile_picture TEXT,
    social_links JSONB DEFAULT '{
        "facebook": "",
        "twitter": "",
        "instagram": "",
        "youtube": "",
        "linkedin": "",
        "website": ""
    }',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create genres table
CREATE TABLE IF NOT EXISTS genres (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(500),
    color VARCHAR(7) DEFAULT '#7ED7FF',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create beats table
CREATE TABLE IF NOT EXISTS beats (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(500),
    color VARCHAR(7) DEFAULT '#E100FF',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create tags table
CREATE TABLE IF NOT EXISTS tags (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description VARCHAR(500),
    color VARCHAR(7) DEFAULT '#FF6B35',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create tracks table
CREATE TABLE IF NOT EXISTS tracks (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    track_name VARCHAR(100) NOT NULL,
    track_id VARCHAR(255) NOT NULL UNIQUE,
    bpm INTEGER CHECK (bpm >= 1 AND bpm <= 300),
    track_key VARCHAR(50),
    track_price DECIMAL(10,2) DEFAULT 0 CHECK (track_price >= 0),
    musician VARCHAR(100),
    musician_profile_picture TEXT,
    track_type VARCHAR(100) NOT NULL,
    mood_type VARCHAR(100),
    energy_type VARCHAR(100),
    instrument VARCHAR(100),
    generated_track_platform VARCHAR(100),
    track_image TEXT,
    track_file TEXT,
    about VARCHAR(1000),
    publish VARCHAR(20) DEFAULT 'Private',
    genre_category TEXT[] DEFAULT '{}',
    beat_category TEXT[] DEFAULT '{}',
    track_tags TEXT[] DEFAULT '{}',
    seo_title VARCHAR(200),
    meta_keyword VARCHAR(500),
    meta_description VARCHAR(500),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create sound_kit_categories table
CREATE TABLE IF NOT EXISTS sound_kit_categories (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(500),
    color VARCHAR(7) DEFAULT '#E100FF',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create sound_kit_tags table
CREATE TABLE IF NOT EXISTS sound_kit_tags (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description VARCHAR(500),
    color VARCHAR(7) DEFAULT '#FF6B35',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create sound_kits table
CREATE TABLE IF NOT EXISTS sound_kits (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    kit_name VARCHAR(100) NOT NULL,
    kit_id VARCHAR(255) NOT NULL UNIQUE,
    description VARCHAR(1000),
    category VARCHAR(100),
    price DECIMAL(10,2) DEFAULT 0 CHECK (price >= 0),
    producer VARCHAR(100),
    musician VARCHAR(100),
    musician_profile_picture TEXT,
    kit_type VARCHAR(100),
    bpm INTEGER CHECK (bpm >= 1 AND bpm <= 300),
    key VARCHAR(50),
    kit_image TEXT,
    kit_file TEXT,
    tags TEXT[] DEFAULT '{}',
    publish VARCHAR(20) DEFAULT 'Private' CHECK (publish IN ('Private', 'Public')),
    seo_title VARCHAR(200),
    meta_keyword VARCHAR(500),
    meta_description VARCHAR(500),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_tracks_track_id ON tracks(track_id);
CREATE INDEX IF NOT EXISTS idx_tracks_musician ON tracks(musician);
CREATE INDEX IF NOT EXISTS idx_tracks_publish ON tracks(publish);
CREATE INDEX IF NOT EXISTS idx_sound_kits_kit_id ON sound_kits(kit_id);
CREATE INDEX IF NOT EXISTS idx_sound_kits_publish ON sound_kits(publish);
CREATE INDEX IF NOT EXISTS idx_genres_active ON genres(is_active);
CREATE INDEX IF NOT EXISTS idx_beats_active ON beats(is_active);
CREATE INDEX IF NOT EXISTS idx_tags_active ON tags(is_active);

-- Create updated_at triggers for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tracks_updated_at BEFORE UPDATE ON tracks
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_genres_updated_at BEFORE UPDATE ON genres
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_beats_updated_at BEFORE UPDATE ON beats
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tags_updated_at BEFORE UPDATE ON tags
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sound_kits_updated_at BEFORE UPDATE ON sound_kits
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sound_kit_categories_updated_at BEFORE UPDATE ON sound_kit_categories
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_sound_kit_tags_updated_at BEFORE UPDATE ON sound_kit_tags
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create storage policies for file uploads
-- Note: These will be created in the Supabase dashboard under Storage > Policies

-- RLS (Row Level Security) policies
-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE tracks ENABLE ROW LEVEL SECURITY;
ALTER TABLE genres ENABLE ROW LEVEL SECURITY;
ALTER TABLE beats ENABLE ROW LEVEL SECURITY;
ALTER TABLE tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE sound_kits ENABLE ROW LEVEL SECURITY;
ALTER TABLE sound_kit_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE sound_kit_tags ENABLE ROW LEVEL SECURITY;

-- Create policies for public read access (adjust based on your needs)
CREATE POLICY "Enable read access for all users" ON genres FOR SELECT USING (true);
CREATE POLICY "Enable read access for all users" ON beats FOR SELECT USING (true);
CREATE POLICY "Enable read access for all users" ON tags FOR SELECT USING (true);
CREATE POLICY "Enable read access for all users" ON tracks FOR SELECT USING (publish = 'Public');
CREATE POLICY "Enable read access for all users" ON sound_kits FOR SELECT USING (publish = 'Public');
CREATE POLICY "Enable read access for all users" ON sound_kit_categories FOR SELECT USING (true);
CREATE POLICY "Enable read access for all users" ON sound_kit_tags FOR SELECT USING (true);

-- Create policies for authenticated users (you may need to adjust these based on your auth strategy)
CREATE POLICY "Enable all operations for service role" ON users FOR ALL USING (true);
CREATE POLICY "Enable all operations for service role" ON tracks FOR ALL USING (true);
CREATE POLICY "Enable all operations for service role" ON genres FOR ALL USING (true);
CREATE POLICY "Enable all operations for service role" ON beats FOR ALL USING (true);
CREATE POLICY "Enable all operations for service role" ON tags FOR ALL USING (true);
CREATE POLICY "Enable all operations for service role" ON sound_kits FOR ALL USING (true);
CREATE POLICY "Enable all operations for service role" ON sound_kit_categories FOR ALL USING (true);
CREATE POLICY "Enable all operations for service role" ON sound_kit_tags FOR ALL USING (true);

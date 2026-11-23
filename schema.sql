-- ============================================================================
-- SECTOR9 QR - NEON POSTGRESQL DATABASE SCHEMA
-- Timezone Aplikasi: Asia/Makassar (WITA / UTC+8)
-- Penyimpanan internal menggunakan TIMESTAMPTZ (UTC)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Fungsi trigger untuk memperbarui kolom updated_at secara otomatis
CREATE OR REPLACE FUNCTION trigger_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 1. TABEL ADMINS
-- Akun admin hanya dibuat melalui CLI terminal (npm run create-admin)
-- ============================================================================
CREATE TABLE IF NOT EXISTS admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER set_admins_updated_at
BEFORE UPDATE ON admins
FOR EACH ROW
EXECUTE FUNCTION trigger_set_updated_at();

-- ============================================================================
-- 2. TABEL ADMIN_SESSIONS
-- Mendukung JWT revocation saat logout & validasi CSRF token per sesi
-- ============================================================================
CREATE TABLE IF NOT EXISTS admin_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    jti UUID NOT NULL UNIQUE,
    csrf_token VARCHAR(128) NOT NULL,
    ip_address VARCHAR(64) NULL,
    user_agent TEXT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin_id ON admin_sessions(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_jti ON admin_sessions(jti);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at ON admin_sessions(expires_at);

-- ============================================================================
-- 3. TABEL QR_CODES
-- Menyimpan konfigurasi, batas akses, masa berlaku, PIN hash, dan style QR
-- ============================================================================
CREATE TABLE IF NOT EXISTS qr_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id UUID NULL REFERENCES admins(id) ON DELETE SET NULL,
    name VARCHAR(150) NOT NULL,
    slug VARCHAR(64) NOT NULL UNIQUE,
    destination_url TEXT NOT NULL,
    logo_url TEXT NULL,
    logo_file_id VARCHAR(128) NULL,
    style_type VARCHAR(20) NOT NULL DEFAULT 'original'
        CHECK (style_type IN ('original', 'card')),
    max_access INTEGER NOT NULL DEFAULT 100
        CHECK (max_access > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    pin_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    pin_hash TEXT NULL,
    is_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_qr_pin_consistency CHECK (
        (pin_enabled = FALSE AND pin_hash IS NULL) OR
        (pin_enabled = TRUE AND pin_hash IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_qr_codes_slug ON qr_codes(slug);
CREATE INDEX IF NOT EXISTS idx_qr_codes_expires_at ON qr_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_qr_codes_created_at ON qr_codes(created_at DESC);

CREATE TRIGGER set_qr_codes_updated_at
BEFORE UPDATE ON qr_codes
FOR EACH ROW
EXECUTE FUNCTION trigger_set_updated_at();

-- ============================================================================
-- 4. TABEL QR_SCAN_EVENTS
-- Menghitung unique visitor per QR Code agar refresh browser tidak menambah kuota
-- ============================================================================
CREATE TABLE IF NOT EXISTS qr_scan_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    qr_code_id UUID NOT NULL REFERENCES qr_codes(id) ON DELETE CASCADE,
    visitor_fingerprint VARCHAR(128) NOT NULL,
    ip_address VARCHAR(64) NULL,
    user_agent TEXT NULL,
    pin_verified BOOLEAN NOT NULL DEFAULT FALSE,
    hit_count INTEGER NOT NULL DEFAULT 1,
    first_scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_qr_unique_visitor UNIQUE (qr_code_id, visitor_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_qr_scan_events_qr_code_id ON qr_scan_events(qr_code_id);
CREATE INDEX IF NOT EXISTS idx_qr_scan_events_first_scanned_at ON qr_scan_events(first_scanned_at DESC);

-- ============================================================================
-- 5. TABEL QR_USERS
-- Menyimpan identitas user hasil scan beserta referensi file KTP privat ImageKit
-- ============================================================================
CREATE TABLE IF NOT EXISTS qr_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    qr_code_id UUID NOT NULL REFERENCES qr_codes(id) ON DELETE CASCADE,
    scan_event_id UUID NULL REFERENCES qr_scan_events(id) ON DELETE SET NULL,
    full_name VARCHAR(150) NOT NULL,
    whatsapp_number VARCHAR(20) NOT NULL,
    ktp_image_url TEXT NOT NULL,
    ktp_file_id VARCHAR(128) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'submitted'
        CHECK (status IN ('submitted', 'verified', 'rejected')),
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_qr_users_qr_code_id ON qr_users(qr_code_id);
CREATE INDEX IF NOT EXISTS idx_qr_users_submitted_at ON qr_users(submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_qr_users_whatsapp_number ON qr_users(whatsapp_number);
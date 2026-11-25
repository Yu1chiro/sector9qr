-- ============================================================================
-- SECTOR9 QR - MIGRASI FITUR USER QR PASS & ADMIN VERIFICATION CARD
-- ============================================================================

-- 1. Tambahkan kolom identitas pass & verifikasi pada tabel qr_users
ALTER TABLE qr_users
    ADD COLUMN IF NOT EXISTS pass_code VARCHAR(32) NULL,
    ADD COLUMN IF NOT EXISTS pass_token VARCHAR(128) NULL,
    ADD COLUMN IF NOT EXISTS visitor_fingerprint VARCHAR(128) NULL,
    ADD COLUMN IF NOT EXISTS verified_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS verified_by_admin_id UUID NULL REFERENCES admins(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS check_in_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_checked_in_at TIMESTAMPTZ NULL;

-- Backfill baris lama agar tidak gagal saat constraint NOT NULL diterapkan
UPDATE qr_users u
SET
    pass_code = COALESCE(
        u.pass_code,
        'S9-' || UPPER(SUBSTRING(REPLACE(u.id::TEXT, '-', '') FROM 1 FOR 8))
    ),
    pass_token = COALESCE(
        u.pass_token,
        ENCODE(DIGEST(u.id::TEXT || u.created_at::TEXT || RANDOM()::TEXT, 'sha256'), 'hex')
    ),
    visitor_fingerprint = COALESCE(
        u.visitor_fingerprint,
        (SELECT se.visitor_fingerprint FROM qr_scan_events se WHERE se.id = u.scan_event_id LIMIT 1),
        ENCODE(DIGEST(u.id::TEXT, 'sha256'), 'hex')
    )
WHERE u.pass_code IS NULL
   OR u.pass_token IS NULL
   OR u.visitor_fingerprint IS NULL;

-- Kunci kolom wajib & constraint unik
ALTER TABLE qr_users
    ALTER COLUMN pass_code SET NOT NULL,
    ALTER COLUMN pass_token SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_qr_users_pass_code'
    ) THEN
        ALTER TABLE qr_users ADD CONSTRAINT uq_qr_users_pass_code UNIQUE (pass_code);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_qr_users_pass_token'
    ) THEN
        ALTER TABLE qr_users ADD CONSTRAINT uq_qr_users_pass_token UNIQUE (pass_token);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_qr_users_pass_code ON qr_users(pass_code);
CREATE INDEX IF NOT EXISTS idx_qr_users_pass_token ON qr_users(pass_token);
CREATE INDEX IF NOT EXISTS idx_qr_users_status ON qr_users(status);

-- 2. Tabel audit log setiap kali admin memindai QR Pass milik user
CREATE TABLE IF NOT EXISTS qr_pass_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    qr_user_id UUID NOT NULL REFERENCES qr_users(id) ON DELETE CASCADE,
    qr_code_id UUID NOT NULL REFERENCES qr_codes(id) ON DELETE CASCADE,
    admin_id UUID NULL REFERENCES admins(id) ON DELETE SET NULL,
    action_type VARCHAR(24) NOT NULL DEFAULT 'verified'
        CHECK (action_type IN ('verified', 're_scanned')),
    scanner_ip VARCHAR(64) NULL,
    scanner_user_agent TEXT NULL,
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_qr_pass_verifications_user_id ON qr_pass_verifications(qr_user_id);
CREATE INDEX IF NOT EXISTS idx_qr_pass_verifications_scanned_at ON qr_pass_verifications(scanned_at DESC);
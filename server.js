'use strict';

require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const readline = require('readline');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const QRCode = require('qrcode');

// ============================================================================
// 1. VALIDASI & KONFIGURASI ENVIRONMENT (FOKUS LOCALHOST:3000)
// ============================================================================
const REQUIRED_ENV = [
  'DATABASE_URL',
  'JWT_SECRET',
  'IMAGEKIT_PUBLIC_KEY',
  'IMAGEKIT_PRIVATE_KEY',
  'IMAGEKIT_URL_ENDPOINT'
];

for (const key of REQUIRED_ENV) {
  if (!process.env[key] || !process.env[key].trim()) {
    console.error(`[FATAL] Environment variable ${key} belum dikonfigurasi di file .env`);
    process.exit(1);
  }
}

const SERVER_PORT = parseInt(process.env.PORT, 10) || 3000;

const CONFIG = {
  PORT: SERVER_PORT,
  LOCAL_ORIGIN: `http://localhost:${SERVER_PORT}`,
  NODE_ENV: process.env.NODE_ENV || 'development',
  IS_PROD: process.env.NODE_ENV === 'production',
  DATABASE_URL: process.env.DATABASE_URL,
  JWT_SECRET: process.env.JWT_SECRET,
  ADMIN_COOKIE_NAME: process.env.ADMIN_COOKIE_NAME || 'sector9_admin_token',
  ADMIN_SESSION_TTL: parseInt(process.env.ADMIN_SESSION_TTL, 10) || 86400,
  IMAGEKIT_PUBLIC_KEY: process.env.IMAGEKIT_PUBLIC_KEY,
  IMAGEKIT_PRIVATE_KEY: process.env.IMAGEKIT_PRIVATE_KEY,
  IMAGEKIT_URL_ENDPOINT: process.env.IMAGEKIT_URL_ENDPOINT.replace(/\/+$/, ''),
  UPLOAD_MAX_SIZE_MB: parseFloat(process.env.UPLOAD_MAX_SIZE_MB) || 5,
  TIMEZONE: 'Asia/Makassar'
};

// ============================================================================
// 2. KONEKSI NEON POSTGRESQL
// ============================================================================
const pool = new Pool({
  connectionString: CONFIG.DATABASE_URL,
  ssl: CONFIG.DATABASE_URL.includes('localhost') || CONFIG.DATABASE_URL.includes('127.0.0.1')
    ? false
    : { rejectUnauthorized: false },
  max: 15,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (err) => {
  console.error('[PostgreSQL Pool Error]', err.message);
});

// ============================================================================
// 3. CLI COMMAND: npm run create-admin
// ============================================================================
function promptLine(rl, question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => resolve(answer));
  });
}

function promptPassword(question) {
  return new Promise((resolve) => {
    if (!process.stdin.isTTY) {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      rl.question(question, (ans) => {
        rl.close();
        resolve(ans);
      });
      return;
    }

    process.stdout.write(question);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');

    let password = '';
    const onData = (ch) => {
      if (ch === '\n' || ch === '\r' || ch === '\u0004') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(password);
      } else if (ch === '\u0003') {
        stdin.setRawMode(false);
        process.stdout.write('\n');
        process.exit(1);
      } else if (ch === '\u007f' || ch === '\b') {
        if (password.length > 0) {
          password = password.slice(0, -1);
          process.stdout.write('\b \b');
        }
      } else {
        password += ch;
        process.stdout.write('*');
      }
    };

    stdin.on('data', onData);
  });
}

async function runCreateAdminCLI() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  console.log('\n=================================================');
  console.log(' SECTOR9 QR — CREATE ADMIN ACCOUNT (CLI)');
  console.log('=================================================\n');

  try {
    const rawUsername = await promptLine(rl, 'Username: ');
    rl.close();

    const username = (rawUsername || '').trim().toLowerCase();
    if (!/^[a-z0-9._-]{3,50}$/.test(username)) {
      console.error('\n[ERROR] Username harus 3-50 karakter (huruf kecil, angka, titik, underscore, atau strip).');
      process.exit(1);
    }

    const existing = await pool.query('SELECT id FROM admins WHERE username = $1 LIMIT 1', [username]);
    if (existing.rowCount > 0) {
      console.error(`\n[ERROR] Username "${username}" sudah terdaftar di database.`);
      process.exit(1);
    }

    const password = await promptPassword('Password: ');
    if (!password || password.length < 8) {
      console.error('\n[ERROR] Password minimal 8 karakter.');
      process.exit(1);
    }

    const confirmPassword = await promptPassword('Konfirmasi password: ');
    if (password !== confirmPassword) {
      console.error('\n[ERROR] Password dan konfirmasi password tidak cocok.');
      process.exit(1);
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO admins (username, password_hash, is_active)
       VALUES ($1, $2, TRUE)
       RETURNING id, username, created_at`,
      [username, passwordHash]
    );

    const admin = result.rows[0];
    console.log('\n[SUKSES] Akun admin berhasil dibuat:');
    console.log(`  ID       : ${admin.id}`);
    console.log(`  Username : ${admin.username}`);
    console.log(`  Dibuat   : ${formatWita(admin.created_at)} WITA\n`);
    await pool.end();
    process.exit(0);
  } catch (err) {
    console.error('\n[ERROR] Gagal membuat akun admin:', err.message);
    await pool.end().catch(() => {});
    process.exit(1);
  }
}

if (process.argv.includes('--create-admin')) {
  runCreateAdminCLI();
  return;
}

// ============================================================================
// 4. HELPER UTILITIES (TIMEZONE WITA, VALIDATION, VISITOR FINGERPRINT)
// ============================================================================
function formatWita(dateInput) {
  if (!dateInput) return null;
  const date = new Date(dateInput);
  if (Number.isNaN(date.getTime())) return null;
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone: CONFIG.TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).formatToParts(date);

  const map = {};
  for (const p of parts) {
    map[p.type] = p.value;
  }
  return `${map.year}-${map.month}-${map.day} ${map.hour}:${map.minute}:${map.second}`;
}

function parseWitaDateTimeToUtc(input) {
  if (!input || typeof input !== 'string') return null;
  const trimmed = input.trim();

  if (/(Z|[+-]\d{2}:\d{2})$/i.test(trimmed)) {
    const parsed = new Date(trimmed);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  const match = trimmed.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})(?::(\d{2}))?$/);
  if (!match) return null;

  const isoWithWitaOffset = `${match[1]}T${match[2]}:${match[3] || '00'}+08:00`;
  const parsed = new Date(isoWithWitaOffset);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function validateDestinationUrl(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return null;
  const trimmed = urlStr.trim();
  if (trimmed.length > 2048) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
}

function normalizeWhatsApp(rawPhone) {
  if (!rawPhone || typeof rawPhone !== 'string') return null;
  const digits = rawPhone.replace(/[\s\-().+]/g, '');
  if (!/^628[1-9][0-9]{7,11}$/.test(digits)) {
    return null;
  }
  return digits;
}

function generateSlug(length = 8) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = crypto.randomBytes(length);
  let slug = '';
  for (let i = 0; i < length; i++) {
    slug += alphabet[bytes[i] % alphabet.length];
  }
  return slug;
}

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim().slice(0, 64);
  }
  return (req.socket?.remoteAddress || '0.0.0.0').slice(0, 64);
}

function resolveVisitorIdentity(req, res) {
  const cookieName = 's9_vid';
  let vid = req.cookies?.[cookieName];

  if (!vid || !/^[a-f0-9]{32}$/.test(vid)) {
    vid = crypto.randomBytes(16).toString('hex');
    res.cookie(cookieName, vid, {
      httpOnly: true,
      sameSite: 'lax',
      secure: CONFIG.IS_PROD,
      path: '/',
      maxAge: 365 * 24 * 60 * 60 * 1000
    });
  }

  const ip = getClientIp(req);
  const ua = (req.headers['user-agent'] || '').slice(0, 256);
  const fingerprint = crypto
    .createHmac('sha256', CONFIG.JWT_SECRET)
    .update(`${vid}|${ip}|${ua}`)
    .digest('hex');

  return { vid, fingerprint, ip, ua };
}

function computeQrStatus(qrRow) {
  if (qrRow.is_disabled) return 'Disabled';
  const now = Date.now();
  const expiresAt = new Date(qrRow.expires_at).getTime();
  if (expiresAt <= now) return 'Expired';
  const uniqueAccess = parseInt(qrRow.unique_access, 10) || 0;
  const maxAccess = parseInt(qrRow.max_access, 10) || 0;
  if (uniqueAccess >= maxAccess) return 'Limit Reached';
  return 'Active';
}

function enrichQrMetrics(row) {
  const maxAccess = parseInt(row.max_access, 10) || 0;
  const uniqueAccess = parseInt(row.unique_access, 10) || 0;
  const remainingAccess = Math.max(0, maxAccess - uniqueAccess);
  const totalScans = parseInt(row.total_scans, 10) || 0;
  const submittedUsers = parseInt(row.submitted_users, 10) || 0;
  const status = computeQrStatus({
    is_disabled: row.is_disabled,
    expires_at: row.expires_at,
    unique_access: uniqueAccess,
    max_access: maxAccess
  });

  return {
    ...row,
    max_access: maxAccess,
    unique_access: uniqueAccess,
    remaining_access: remainingAccess,
    total_scans: totalScans,
    submitted_users: submittedUsers,
    status,
    qr_url: `${CONFIG.LOCAL_ORIGIN}/r/${row.slug}`,
    expires_at_wita: formatWita(row.expires_at),
    created_at_wita: formatWita(row.created_at)
  };
}

function signPinCookieValue(slug, fingerprint) {
  const exp = Math.floor(Date.now() / 1000) + 1800; // berlaku 30 menit
  const payload = `${slug}.${fingerprint}.${exp}`;
  const sig = crypto.createHmac('sha256', CONFIG.JWT_SECRET).update(payload).digest('hex');
  return `${exp}.${sig}`;
}

function verifyPinCookieValue(cookieVal, slug, fingerprint) {
  if (!cookieVal || typeof cookieVal !== 'string') return false;
  const parts = cookieVal.split('.');
  if (parts.length !== 2) return false;
  const exp = parseInt(parts[0], 10);
  if (!exp || exp < Math.floor(Date.now() / 1000)) return false;

  const expectedSig = crypto
    .createHmac('sha256', CONFIG.JWT_SECRET)
    .update(`${slug}.${fingerprint}.${exp}`)
    .digest('hex');

  try {
    return crypto.timingSafeEqual(Buffer.from(parts[1], 'hex'), Buffer.from(expectedSig, 'hex'));
  } catch {
    return false;
  }
}

// ============================================================================
// 5. IMAGEKIT.IO INTEGRATION (UPLOAD, SIGNED URL, DELETE)
// ============================================================================
const ALLOWED_IMAGE_MIME = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp'
};

function validateAndParseBase64Image(base64Input) {
  if (!base64Input || typeof base64Input !== 'string') {
    throw new Error('Data gambar Base64 tidak valid.');
  }

  let mimeType = null;
  let rawBase64 = base64Input.trim();

  const dataUriMatch = rawBase64.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/);
  if (dataUriMatch) {
    mimeType = dataUriMatch[1].toLowerCase();
    rawBase64 = dataUriMatch[2];
  }

  if (mimeType === 'image/svg+xml') {
    throw new Error('Format SVG tidak diizinkan.');
  }

  const buffer = Buffer.from(rawBase64, 'base64');
  if (!buffer || buffer.length === 0) {
    throw new Error('File gambar kosong atau rusak.');
  }

  const maxBytes = CONFIG.UPLOAD_MAX_SIZE_MB * 1024 * 1024;
  if (buffer.length > maxBytes) {
    throw new Error(`Ukuran file melebihi batas maksimal ${CONFIG.UPLOAD_MAX_SIZE_MB} MB.`);
  }

  let detectedMime = null;
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    detectedMime = 'image/jpeg';
  } else if (
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    detectedMime = 'image/png';
  } else if (
    buffer.length >= 12 &&
    buffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buffer.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    detectedMime = 'image/webp';
  }

  if (!detectedMime || !ALLOWED_IMAGE_MIME[detectedMime]) {
    throw new Error('Format gambar hanya mendukung JPG, PNG, atau WEBP.');
  }

  if (mimeType && mimeType !== detectedMime) {
    throw new Error('Header MIME gambar tidak sesuai dengan isi file.');
  }

  return {
    buffer,
    mimeType: detectedMime,
    ext: ALLOWED_IMAGE_MIME[detectedMime],
    dataUri: `data:${detectedMime};base64,${buffer.toString('base64')}`
  };
}

async function uploadToImageKit({ base64Data, folder, prefix, isPrivateFile = false }) {
  const parsed = validateAndParseBase64Image(base64Data);
  const uniqueFileName = `${prefix}_${Date.now()}_${crypto.randomBytes(6).toString('hex')}.${parsed.ext}`;

  const formData = new FormData();
  formData.append('file', parsed.dataUri);
  formData.append('fileName', uniqueFileName);
  formData.append('folder', folder);
  formData.append('useUniqueFileName', 'false');
  formData.append('isPrivateFile', isPrivateFile ? 'true' : 'false');

  const basicAuth = Buffer.from(`${CONFIG.IMAGEKIT_PRIVATE_KEY}:`).toString('base64');

  const response = await fetch('https://upload.imagekit.io/api/v1/files/upload', {
    method: 'POST',
    headers: {
      Authorization: `Basic ${basicAuth}`
    },
    body: formData
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.url || !data.fileId) {
    console.error('[ImageKit Upload Error]', response.status, data);
    throw new Error(data.message || 'Gagal mengunggah gambar ke ImageKit.');
  }

  return {
    url: data.url,
    fileId: data.fileId,
    name: data.name
  };
}

async function deleteFromImageKit(fileId) {
  if (!fileId) return;
  const basicAuth = Buffer.from(`${CONFIG.IMAGEKIT_PRIVATE_KEY}:`).toString('base64');
  try {
    const response = await fetch(`https://api.imagekit.io/v1/files/${encodeURIComponent(fileId)}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Basic ${basicAuth}`
      }
    });
    if (!response.ok && response.status !== 404) {
      const errText = await response.text().catch(() => '');
      console.warn('[ImageKit Delete Warning]', response.status, errText);
    }
  } catch (err) {
    console.warn('[ImageKit Delete Exception]', err.message);
  }
}

function generateSignedImageKitUrl(fileUrl, expireSeconds = 60) {
  const urlObj = new URL(fileUrl);
  const endpointObj = new URL(CONFIG.IMAGEKIT_URL_ENDPOINT);

  let relativePath = urlObj.pathname;
  if (relativePath.startsWith(endpointObj.pathname)) {
    relativePath = relativePath.slice(endpointObj.pathname.length);
  }
  relativePath = relativePath.replace(/^\/+/, '');

  const expiryTimestamp = Math.floor(Date.now() / 1000) + expireSeconds;
  const signature = crypto
    .createHmac('sha1', CONFIG.IMAGEKIT_PRIVATE_KEY)
    .update(`${relativePath}${expiryTimestamp}`)
    .digest('hex');

  // Parameter resmi ImageKit: ik-s = signature, ik-t = expiry timestamp
  urlObj.searchParams.set('ik-s', signature);
  urlObj.searchParams.set('ik-t', String(expiryTimestamp));
  return urlObj.toString();
}

// ============================================================================
// 6. IN-MEMORY RATE LIMITER
// ============================================================================
const rateLimitBuckets = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitBuckets.entries()) {
    if (entry.resetAt <= now) {
      rateLimitBuckets.delete(key);
    }
  }
}, 5 * 60 * 1000).unref();

function createRateLimiter({ namespace, windowMs, maxAttempts, keyGenerator, message }) {
  return (req, res, next) => {
    const rawKey = keyGenerator ? keyGenerator(req) : getClientIp(req);
    const bucketKey = `${namespace}:${rawKey}`;
    const now = Date.now();

    let entry = rateLimitBuckets.get(bucketKey);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs };
    }

    entry.count += 1;
    rateLimitBuckets.set(bucketKey, entry);

    if (entry.count > maxAttempts) {
      const retryAfterSec = Math.ceil((entry.resetAt - now) / 1000);
      res.setHeader('Retry-After', String(retryAfterSec));
      return res.status(429).json({
        success: false,
        message: message || `Terlalu banyak percobaan. Silakan coba lagi dalam ${retryAfterSec} detik.`
      });
    }

    return next();
  };
}

const loginRateLimiter = createRateLimiter({
  namespace: 'admin_login',
  windowMs: 15 * 60 * 1000,
  maxAttempts: 5,
  keyGenerator: (req) => `${getClientIp(req)}:${String(req.body?.username || '').toLowerCase()}`,
  message: 'Terlalu banyak percobaan login gagal. Coba lagi dalam 15 menit.'
});

const pinVerifyRateLimiter = createRateLimiter({
  namespace: 'public_pin',
  windowMs: 15 * 60 * 1000,
  maxAttempts: 8,
  keyGenerator: (req) => `${getClientIp(req)}:${String(req.body?.slug || '')}`,
  message: 'Terlalu banyak percobaan PIN. Silakan tunggu beberapa saat.'
});

const publicSubmitRateLimiter = createRateLimiter({
  namespace: 'public_submit',
  windowMs: 15 * 60 * 1000,
  maxAttempts: 10,
  keyGenerator: (req) => getClientIp(req),
  message: 'Batas pengiriman formulir tercapai. Silakan coba lagi nanti.'
});

// ============================================================================
// 7. INISIALISASI EXPRESS & SECURITY HEADERS (TANPA HELMET & TANPA CORS)
// ============================================================================
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const bodyLimit = `${Math.ceil(CONFIG.UPLOAD_MAX_SIZE_MB * 1.5) + 2}mb`;
app.use(express.json({ limit: bodyLimit }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(cookieParser());

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(), geolocation=()');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com data:",
      `img-src 'self' data: blob: ${CONFIG.IMAGEKIT_URL_ENDPOINT} https://ik.imagekit.io`,
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; ')
  );

  if (CONFIG.IS_PROD) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// ============================================================================
// 8. ADMIN AUTHENTICATION & CSRF MIDDLEWARE
// ============================================================================
async function authenticateAdminSession(req) {
  const token = req.cookies?.[CONFIG.ADMIN_COOKIE_NAME];
  if (!token || typeof token !== 'string') return null;

  let decoded;
  try {
    decoded = jwt.verify(token, CONFIG.JWT_SECRET);
  } catch {
    return null;
  }

  if (!decoded || !decoded.sub || !decoded.jti) return null;

  const result = await pool.query(
    `SELECT
       s.id AS session_id,
       s.jti,
       s.csrf_token,
       s.expires_at,
       s.revoked_at,
       a.id AS admin_id,
       a.username,
       a.is_active,
       a.last_login_at
     FROM admin_sessions s
     INNER JOIN admins a ON a.id = s.admin_id
     WHERE s.jti = $1 AND a.id = $2
     LIMIT 1`,
    [decoded.jti, decoded.sub]
  );

  if (result.rowCount === 0) return null;
  const session = result.rows[0];

  if (!session.is_active || session.revoked_at !== null) return null;
  if (new Date(session.expires_at).getTime() <= Date.now()) return null;

  return session;
}

function clearAdminCookie(res) {
  res.clearCookie(CONFIG.ADMIN_COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'lax',
    secure: CONFIG.IS_PROD,
    path: '/'
  });
}

async function requireAdminPage(req, res, next) {
  try {
    const session = await authenticateAdminSession(req);
    if (!session) {
      clearAdminCookie(res);
      return res.redirect(302, '/');
    }
    req.admin = session;
    return next();
  } catch (err) {
    return next(err);
  }
}

async function requireAdminApi(req, res, next) {
  try {
    const session = await authenticateAdminSession(req);
    if (!session) {
      clearAdminCookie(res);
      return res.status(401).json({
        success: false,
        message: 'Sesi tidak valid atau telah berakhir. Silakan login kembali.'
      });
    }
    req.admin = session;
    return next();
  } catch (err) {
    return next(err);
  }
}

function verifyCsrf(req, res, next) {
  const headerToken = req.headers['x-csrf-token'];
  const expectedToken = req.admin?.csrf_token;

  if (!headerToken || !expectedToken || typeof headerToken !== 'string') {
    return res.status(403).json({
      success: false,
      message: 'Token keamanan CSRF tidak valid.'
    });
  }

  try {
    const a = Buffer.from(headerToken, 'utf8');
    const b = Buffer.from(expectedToken, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(403).json({
        success: false,
        message: 'Token keamanan CSRF tidak cocok.'
      });
    }
  } catch {
    return res.status(403).json({
      success: false,
      message: 'Validasi CSRF gagal.'
    });
  }

  return next();
}

// ============================================================================
// 9. ROUTER: AUTHENTICATION (/api/auth)
// ============================================================================
const authRouter = express.Router();

authRouter.post('/login', loginRateLimiter, async (req, res, next) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');

    if (!username || !password || username.length > 64 || password.length > 256) {
      return res.status(400).json({
        success: false,
        message: 'Username dan password wajib diisi.'
      });
    }

    const adminResult = await pool.query(
      'SELECT id, username, password_hash, is_active FROM admins WHERE username = $1 LIMIT 1',
      [username]
    );

    const dummyHash = '$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234';
    const admin = adminResult.rows[0];
    const hashToCompare = admin ? admin.password_hash : dummyHash;

    const isMatch = await bcrypt.compare(password, hashToCompare);
    if (!admin || !admin.is_active || !isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Username atau password salah.'
      });
    }

    const jti = crypto.randomUUID();
    const csrfToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + CONFIG.ADMIN_SESSION_TTL * 1000);

    await pool.query(
      `INSERT INTO admin_sessions (admin_id, jti, csrf_token, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [
        admin.id,
        jti,
        csrfToken,
        getClientIp(req),
        (req.headers['user-agent'] || '').slice(0, 500),
        expiresAt
      ]
    );

    await pool.query('UPDATE admins SET last_login_at = NOW() WHERE id = $1', [admin.id]);

    const token = jwt.sign(
      { sub: admin.id, username: admin.username, jti },
      CONFIG.JWT_SECRET,
      { expiresIn: CONFIG.ADMIN_SESSION_TTL }
    );

    res.cookie(CONFIG.ADMIN_COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: CONFIG.IS_PROD,
      path: '/',
      maxAge: CONFIG.ADMIN_SESSION_TTL * 1000
    });

    return res.json({
      success: true,
      message: 'Login berhasil.',
      redirect: '/dashboard'
    });
  } catch (err) {
    return next(err);
  }
});

authRouter.post('/logout', requireAdminApi, verifyCsrf, async (req, res, next) => {
  try {
    await pool.query(
      'UPDATE admin_sessions SET revoked_at = NOW() WHERE jti = $1',
      [req.admin.jti]
    );
    clearAdminCookie(res);
    return res.json({
      success: true,
      message: 'Logout berhasil.',
      redirect: '/'
    });
  } catch (err) {
    return next(err);
  }
});

authRouter.get('/me', requireAdminApi, (req, res) => {
  return res.json({
    success: true,
    admin: {
      id: req.admin.admin_id,
      username: req.admin.username,
      last_login_at: formatWita(req.admin.last_login_at)
    },
    csrfToken: req.admin.csrf_token,
    config: {
      localOrigin: CONFIG.LOCAL_ORIGIN,
      timezone: CONFIG.TIMEZONE,
      uploadMaxSizeMb: CONFIG.UPLOAD_MAX_SIZE_MB
    }
  });
});

app.use('/api/auth', authRouter);

// ============================================================================
// 10. ROUTER: ADMIN API (/api/admin)
// ============================================================================
const adminRouter = express.Router();
adminRouter.use(requireAdminApi);

// 10A. Dashboard Analytics
adminRouter.get('/dashboard', async (req, res, next) => {
  try {
    const qrStatsQuery = await pool.query(`
      SELECT
        q.id,
        q.name,
        q.slug,
        q.destination_url,
        q.max_access,
        q.expires_at,
        q.is_disabled,
        q.style_type,
        q.pin_enabled,
        q.created_at,
        COUNT(DISTINCT se.id)::INT AS unique_access,
        COALESCE(SUM(se.hit_count), 0)::INT AS total_scans,
        COUNT(DISTINCT u.id)::INT AS submitted_users
      FROM qr_codes q
      LEFT JOIN qr_scan_events se ON se.qr_code_id = q.id
      LEFT JOIN qr_users u ON u.qr_code_id = q.id
      GROUP BY q.id
      ORDER BY q.created_at DESC
    `);

    const allQrs = qrStatsQuery.rows.map(enrichQrMetrics);

    let activeQr = 0;
    let expiredQr = 0;
    let limitReachedQr = 0;
    let disabledQr = 0;
    let totalUniqueAccess = 0;
    let totalRawScans = 0;
    let totalSubmittedUsers = 0;

    for (const q of allQrs) {
      if (q.status === 'Active') activeQr += 1;
      else if (q.status === 'Expired') expiredQr += 1;
      else if (q.status === 'Limit Reached') limitReachedQr += 1;
      else if (q.status === 'Disabled') disabledQr += 1;

      totalUniqueAccess += q.unique_access;
      totalRawScans += q.total_scans;
      totalSubmittedUsers += q.submitted_users;
    }

    const dailyScansResult = await pool.query(`
      SELECT
        TO_CHAR(first_scanned_at AT TIME ZONE 'Asia/Makassar', 'YYYY-MM-DD') AS day,
        COUNT(*)::INT AS count
      FROM qr_scan_events
      WHERE first_scanned_at >= NOW() - INTERVAL '14 days'
      GROUP BY day
      ORDER BY day ASC
    `);

    const dailyUsersResult = await pool.query(`
      SELECT
        TO_CHAR(submitted_at AT TIME ZONE 'Asia/Makassar', 'YYYY-MM-DD') AS day,
        COUNT(*)::INT AS count
      FROM qr_users
      WHERE submitted_at >= NOW() - INTERVAL '14 days'
      GROUP BY day
      ORDER BY day ASC
    `);

    const scansMap = new Map(dailyScansResult.rows.map((r) => [r.day, r.count]));
    const usersMap = new Map(dailyUsersResult.rows.map((r) => [r.day, r.count]));

    const timelineDates = [];
    const timelineScans = [];
    const timelineUsers = [];

    for (let i = 13; i >= 0; i--) {
      const d = new Date(Date.now() - i * 24 * 60 * 60 * 1000);
      const dayKey = new Intl.DateTimeFormat('en-CA', {
        timeZone: CONFIG.TIMEZONE,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
      }).format(d);

      timelineDates.push(dayKey);
      timelineScans.push(scansMap.get(dayKey) || 0);
      timelineUsers.push(usersMap.get(dayKey) || 0);
    }

    const topByAccess = [...allQrs]
      .sort((a, b) => b.unique_access - a.unique_access)
      .slice(0, 7);

    const topByUsers = [...allQrs]
      .sort((a, b) => b.submitted_users - a.submitted_users)
      .slice(0, 7);

    return res.json({
      success: true,
      summary: {
        total_qr: allQrs.length,
        active_qr: activeQr,
        expired_qr: expiredQr,
        limit_reached_qr: limitReachedQr,
        disabled_qr: disabledQr,
        total_unique_scans: totalUniqueAccess,
        total_raw_scans: totalRawScans,
        total_submitted_users: totalSubmittedUsers
      },
      charts: {
        scans_over_time: {
          dates: timelineDates,
          scans: timelineScans,
          submissions: timelineUsers
        },
        top_qr_codes: {
          names: topByAccess.map((q) => q.name),
          unique_scans: topByAccess.map((q) => q.unique_access),
          max_access: topByAccess.map((q) => q.max_access)
        },
        users_by_qr: {
          names: topByUsers.map((q) => q.name),
          submitted_users: topByUsers.map((q) => q.submitted_users),
          unique_scans: topByUsers.map((q) => q.unique_access)
        }
      },
      recent_qr_codes: allQrs.slice(0, 10)
    });
  } catch (err) {
    return next(err);
  }
});

// 10B. QR Code Management CRUD
adminRouter.get('/qr-codes', async (req, res, next) => {
  try {
    const search = String(req.query.search || '').trim().toLowerCase();
    const statusFilter = String(req.query.status || 'all').trim().toLowerCase();
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 12));

    const result = await pool.query(`
      SELECT
        q.id,
        q.name,
        q.slug,
        q.destination_url,
        q.logo_url,
        q.style_type,
        q.max_access,
        q.expires_at,
        q.pin_enabled,
        q.is_disabled,
        q.created_at,
        q.updated_at,
        COUNT(DISTINCT se.id)::INT AS unique_access,
        COALESCE(SUM(se.hit_count), 0)::INT AS total_scans,
        COUNT(DISTINCT u.id)::INT AS submitted_users
      FROM qr_codes q
      LEFT JOIN qr_scan_events se ON se.qr_code_id = q.id
      LEFT JOIN qr_users u ON u.qr_code_id = q.id
      GROUP BY q.id
      ORDER BY q.created_at DESC
    `);

    let items = result.rows.map(enrichQrMetrics);

    if (search) {
      items = items.filter(
        (item) =>
          item.name.toLowerCase().includes(search) ||
          item.slug.toLowerCase().includes(search) ||
          item.destination_url.toLowerCase().includes(search)
      );
    }

    if (statusFilter !== 'all') {
      const normalizedFilter = statusFilter.replace(/[\s_-]+/g, '').toLowerCase();
      items = items.filter(
        (item) => item.status.replace(/[\s_-]+/g, '').toLowerCase() === normalizedFilter
      );
    }

    const total = items.length;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    const safePage = Math.min(page, totalPages);
    const offset = (safePage - 1) * limit;
    const paginated = items.slice(offset, offset + limit);

    return res.json({
      success: true,
      data: paginated,
      pagination: {
        page: safePage,
        limit,
        total,
        totalPages
      }
    });
  } catch (err) {
    return next(err);
  }
});

adminRouter.get('/qr-codes/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, message: 'ID QR Code tidak valid.' });
    }

    const qrRes = await pool.query(
      `SELECT
        q.id,
        q.name,
        q.slug,
        q.destination_url,
        q.logo_url,
        q.style_type,
        q.max_access,
        q.expires_at,
        q.pin_enabled,
        q.is_disabled,
        q.created_at,
        q.updated_at,
        COUNT(DISTINCT se.id)::INT AS unique_access,
        COALESCE(SUM(se.hit_count), 0)::INT AS total_scans,
        COUNT(DISTINCT u.id)::INT AS submitted_users
       FROM qr_codes q
       LEFT JOIN qr_scan_events se ON se.qr_code_id = q.id
       LEFT JOIN qr_users u ON u.qr_code_id = q.id
       WHERE q.id = $1
       GROUP BY q.id`,
      [id]
    );

    if (qrRes.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'QR Code tidak ditemukan.' });
    }

    const enriched = enrichQrMetrics(qrRes.rows[0]);
    const dailyScans = await pool.query(
      `SELECT
        TO_CHAR(first_scanned_at AT TIME ZONE 'Asia/Makassar', 'YYYY-MM-DD') AS day,
        COUNT(*)::INT AS unique_access,
        COALESCE(SUM(hit_count), 0)::INT AS total_scans
       FROM qr_scan_events
       WHERE qr_code_id = $1 AND first_scanned_at >= NOW() - INTERVAL '14 days'
       GROUP BY day
       ORDER BY day ASC`,
      [id]
    );

    return res.json({
      success: true,
      data: {
        ...enriched,
        daily_scans: dailyScans.rows
      }
    });
  } catch (err) {
    return next(err);
  }
});

adminRouter.get('/qr-codes/:id/image', async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, message: 'ID QR Code tidak valid.' });
    }

    const qrRes = await pool.query('SELECT slug, logo_url FROM qr_codes WHERE id = $1 LIMIT 1', [id]);
    if (qrRes.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'QR Code tidak ditemukan.' });
    }

    const qr = qrRes.rows[0];
    const targetUrl = `${CONFIG.LOCAL_ORIGIN}/r/${qr.slug}`;

    const pngDataUrl = await QRCode.toDataURL(targetUrl, {
      errorCorrectionLevel: qr.logo_url ? 'H' : 'M',
      margin: 3,
      width: 600,
      color: {
        dark: '#000000',
        light: '#FFFFFF'
      }
    });

    return res.json({
      success: true,
      qr_url: targetUrl,
      data_url: pngDataUrl
    });
  } catch (err) {
    return next(err);
  }
});

adminRouter.post('/qr-codes', verifyCsrf, async (req, res, next) => {
  let uploadedLogo = null;
  try {
    const name = String(req.body?.name || '').trim();
    const destinationUrl = validateDestinationUrl(req.body?.destination_url);
    const maxAccess = parseInt(req.body?.max_access, 10);
    const expiresAt = parseWitaDateTimeToUtc(req.body?.expires_at);
    const styleType = req.body?.style_type === 'card' ? 'card' : 'original';
    const pinEnabled = Boolean(req.body?.pin_enabled);
    const rawPin = String(req.body?.pin || '').trim();
    const logoBase64 = req.body?.logo_base64 ? String(req.body.logo_base64) : null;

    if (name.length < 2 || name.length > 150) {
      return res.status(400).json({
        success: false,
        message: 'Nama QR Code harus antara 2 hingga 150 karakter.'
      });
    }

    if (!destinationUrl) {
      return res.status(400).json({
        success: false,
        message: 'Link tujuan tidak valid. Gunakan URL dengan protokol http:// atau https://.'
      });
    }

    if (!Number.isInteger(maxAccess) || maxAccess < 1 || maxAccess > 1000000) {
      return res.status(400).json({
        success: false,
        message: 'Maximal User Access harus berupa angka antara 1 hingga 1.000.000.'
      });
    }

    if (!expiresAt || expiresAt.getTime() <= Date.now()) {
      return res.status(400).json({
        success: false,
        message: 'Expired date harus valid dan berada di masa depan (waktu WITA).'
      });
    }

    let pinHash = null;
    if (pinEnabled) {
      if (!/^\d{4,8}$/.test(rawPin)) {
        return res.status(400).json({
          success: false,
          message: 'PIN harus terdiri dari 4 hingga 8 digit angka.'
        });
      }
      pinHash = await bcrypt.hash(rawPin, 10);
    }

    if (logoBase64) {
      uploadedLogo = await uploadToImageKit({
        base64Data: logoBase64,
        folder: '/sector9-qr/logos',
        prefix: 'logo',
        isPrivateFile: false
      });
    }

    let slug = null;
    for (let attempt = 0; attempt < 6; attempt++) {
      const candidate = generateSlug(8);
      const dup = await pool.query('SELECT 1 FROM qr_codes WHERE slug = $1 LIMIT 1', [candidate]);
      if (dup.rowCount === 0) {
        slug = candidate;
        break;
      }
    }
    if (!slug) {
      throw new Error('Gagal menghasilkan slug unik. Silakan coba lagi.');
    }

    const insertRes = await pool.query(
      `INSERT INTO qr_codes (
        admin_id, name, slug, destination_url, logo_url, logo_file_id,
        style_type, max_access, expires_at, pin_enabled, pin_hash
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
      RETURNING id, name, slug, destination_url, logo_url, style_type,
                max_access, expires_at, pin_enabled, is_disabled, created_at`,
      [
        req.admin.admin_id,
        name,
        slug,
        destinationUrl,
        uploadedLogo ? uploadedLogo.url : null,
        uploadedLogo ? uploadedLogo.fileId : null,
        styleType,
        maxAccess,
        expiresAt,
        pinEnabled,
        pinHash
      ]
    );

    const created = enrichQrMetrics({
      ...insertRes.rows[0],
      unique_access: 0,
      total_scans: 0,
      submitted_users: 0
    });

    return res.status(201).json({
      success: true,
      message: 'QR Code berhasil dibuat.',
      data: created
    });
  } catch (err) {
    if (uploadedLogo?.fileId) {
      await deleteFromImageKit(uploadedLogo.fileId);
    }
    if (err.message && (err.message.includes('Format') || err.message.includes('Ukuran') || err.message.includes('gambar'))) {
      return res.status(400).json({ success: false, message: err.message });
    }
    return next(err);
  }
});

adminRouter.put('/qr-codes/:id', verifyCsrf, async (req, res, next) => {
  let newlyUploadedLogo = null;
  try {
    const { id } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, message: 'ID QR Code tidak valid.' });
    }

    const existingRes = await pool.query('SELECT * FROM qr_codes WHERE id = $1 LIMIT 1', [id]);
    if (existingRes.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'QR Code tidak ditemukan.' });
    }
    const existing = existingRes.rows[0];

    const name = String(req.body?.name ?? existing.name).trim();
    const destinationUrl = validateDestinationUrl(req.body?.destination_url ?? existing.destination_url);
    const maxAccess = parseInt(req.body?.max_access ?? existing.max_access, 10);
    const expiresAt = req.body?.expires_at
      ? parseWitaDateTimeToUtc(req.body.expires_at)
      : new Date(existing.expires_at);
    const styleType = req.body?.style_type
      ? (req.body.style_type === 'card' ? 'card' : 'original')
      : existing.style_type;
    const isDisabled = typeof req.body?.is_disabled === 'boolean'
      ? req.body.is_disabled
      : existing.is_disabled;

    const pinEnabled = typeof req.body?.pin_enabled === 'boolean'
      ? req.body.pin_enabled
      : existing.pin_enabled;
    const rawPin = String(req.body?.pin || '').trim();
    const logoBase64 = req.body?.logo_base64 ? String(req.body.logo_base64) : null;
    const removeLogo = Boolean(req.body?.remove_logo);

    if (name.length < 2 || name.length > 150) {
      return res.status(400).json({
        success: false,
        message: 'Nama QR Code harus antara 2 hingga 150 karakter.'
      });
    }

    if (!destinationUrl) {
      return res.status(400).json({
        success: false,
        message: 'Link tujuan tidak valid. Gunakan URL dengan protokol http:// atau https://.'
      });
    }

    if (!Number.isInteger(maxAccess) || maxAccess < 1 || maxAccess > 1000000) {
      return res.status(400).json({
        success: false,
        message: 'Maximal User Access harus berupa angka antara 1 hingga 1.000.000.'
      });
    }

    if (!expiresAt) {
      return res.status(400).json({
        success: false,
        message: 'Format expired date tidak valid.'
      });
    }

    let pinHash = existing.pin_hash;
    if (!pinEnabled) {
      pinHash = null;
    } else if (rawPin.length > 0) {
      if (!/^\d{4,8}$/.test(rawPin)) {
        return res.status(400).json({
          success: false,
          message: 'PIN baru harus terdiri dari 4 hingga 8 digit angka.'
        });
      }
      pinHash = await bcrypt.hash(rawPin, 10);
    } else if (!existing.pin_hash) {
      return res.status(400).json({
        success: false,
        message: 'PIN wajib diisi (4-8 digit angka) saat mengaktifkan proteksi PIN.'
      });
    }

    let logoUrl = existing.logo_url;
    let logoFileId = existing.logo_file_id;
    let oldLogoToDelete = null;

    if (logoBase64) {
      newlyUploadedLogo = await uploadToImageKit({
        base64Data: logoBase64,
        folder: '/sector9-qr/logos',
        prefix: 'logo',
        isPrivateFile: false
      });
      oldLogoToDelete = existing.logo_file_id;
      logoUrl = newlyUploadedLogo.url;
      logoFileId = newlyUploadedLogo.fileId;
    } else if (removeLogo) {
      oldLogoToDelete = existing.logo_file_id;
      logoUrl = null;
      logoFileId = null;
    }

    await pool.query(
      `UPDATE qr_codes
       SET name = $1,
           destination_url = $2,
           logo_url = $3,
           logo_file_id = $4,
           style_type = $5,
           max_access = $6,
           expires_at = $7,
           pin_enabled = $8,
           pin_hash = $9,
           is_disabled = $10
       WHERE id = $11`,
      [
        name,
        destinationUrl,
        logoUrl,
        logoFileId,
        styleType,
        maxAccess,
        expiresAt,
        pinEnabled,
        pinHash,
        isDisabled,
        id
      ]
    );

    if (oldLogoToDelete) {
      await deleteFromImageKit(oldLogoToDelete);
    }

    const refreshedRes = await pool.query(
      `SELECT
        q.id, q.name, q.slug, q.destination_url, q.logo_url, q.style_type,
        q.max_access, q.expires_at, q.pin_enabled, q.is_disabled, q.created_at, q.updated_at,
        COUNT(DISTINCT se.id)::INT AS unique_access,
        COALESCE(SUM(se.hit_count), 0)::INT AS total_scans,
        COUNT(DISTINCT u.id)::INT AS submitted_users
       FROM qr_codes q
       LEFT JOIN qr_scan_events se ON se.qr_code_id = q.id
       LEFT JOIN qr_users u ON u.qr_code_id = q.id
       WHERE q.id = $1
       GROUP BY q.id`,
      [id]
    );

    return res.json({
      success: true,
      message: 'Konfigurasi QR Code berhasil diperbarui.',
      data: enrichQrMetrics(refreshedRes.rows[0])
    });
  } catch (err) {
    if (newlyUploadedLogo?.fileId) {
      await deleteFromImageKit(newlyUploadedLogo.fileId);
    }
    if (err.message && (err.message.includes('Format') || err.message.includes('Ukuran') || err.message.includes('gambar'))) {
      return res.status(400).json({ success: false, message: err.message });
    }
    return next(err);
  }
});

adminRouter.delete('/qr-codes/:id', verifyCsrf, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, message: 'ID QR Code tidak valid.' });
    }

    const qrRes = await pool.query('SELECT id, logo_file_id FROM qr_codes WHERE id = $1 LIMIT 1', [id]);
    if (qrRes.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'QR Code tidak ditemukan.' });
    }

    const usersRes = await pool.query(
      'SELECT ktp_file_id FROM qr_users WHERE qr_code_id = $1',
      [id]
    );

    await pool.query('DELETE FROM qr_codes WHERE id = $1', [id]);

    if (qrRes.rows[0].logo_file_id) {
      await deleteFromImageKit(qrRes.rows[0].logo_file_id);
    }
    for (const u of usersRes.rows) {
      if (u.ktp_file_id) {
        await deleteFromImageKit(u.ktp_file_id);
      }
    }

    return res.json({
      success: true,
      message: 'QR Code beserta data terkait berhasil dihapus.'
    });
  } catch (err) {
    return next(err);
  }
});

// 10C. User List Management & Private KTP Proxy
adminRouter.get('/users', async (req, res, next) => {
  try {
    const search = String(req.query.search || '').trim();
    const qrId = String(req.query.qr_id || '').trim();
    const dateFrom = String(req.query.date_from || '').trim();
    const dateTo = String(req.query.date_to || '').trim();
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 15));

    const conditions = [];
    const params = [];

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(u.full_name ILIKE $${params.length} OR u.whatsapp_number ILIKE $${params.length})`);
    }

    if (qrId && /^[0-9a-f-]{36}$/i.test(qrId)) {
      params.push(qrId);
      conditions.push(`u.qr_code_id = $${params.length}`);
    }

    if (/^\d{4}-\d{2}-\d{2}$/.test(dateFrom)) {
      params.push(dateFrom);
      conditions.push(`DATE(u.submitted_at AT TIME ZONE 'Asia/Makassar') >= $${params.length}::DATE`);
    }

    if (/^\d{4}-\d{2}-\d{2}$/.test(dateTo)) {
      params.push(dateTo);
      conditions.push(`DATE(u.submitted_at AT TIME ZONE 'Asia/Makassar') <= $${params.length}::DATE`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    const countRes = await pool.query(
      `SELECT COUNT(*)::INT AS total FROM qr_users u ${whereClause}`,
      params
    );
    const total = countRes.rows[0].total;
    const totalPages = Math.max(1, Math.ceil(total / limit));
    const safePage = Math.min(page, totalPages);
    const offset = (safePage - 1) * limit;

    const listParams = [...params, limit, offset];
    const usersRes = await pool.query(
      `SELECT
        u.id,
        u.qr_code_id,
        u.full_name,
        u.whatsapp_number,
        u.status,
        u.scanned_at,
        u.submitted_at,
        q.name AS qr_name,
        q.slug AS qr_slug
       FROM qr_users u
       INNER JOIN qr_codes q ON q.id = u.qr_code_id
       ${whereClause}
       ORDER BY u.submitted_at DESC
       LIMIT $${listParams.length - 1} OFFSET $${listParams.length}`,
      listParams
    );

    const data = usersRes.rows.map((row) => ({
      id: row.id,
      qr_code_id: row.qr_code_id,
      qr_name: row.qr_name,
      qr_slug: row.qr_slug,
      full_name: row.full_name,
      whatsapp_number: row.whatsapp_number,
      wa_url: `https://wa.me/${row.whatsapp_number}`,
      status: row.status,
      scanned_at_wita: formatWita(row.scanned_at),
      submitted_at_wita: formatWita(row.submitted_at)
    }));

    return res.json({
      success: true,
      data,
      pagination: {
        page: safePage,
        limit,
        total,
        totalPages
      }
    });
  } catch (err) {
    return next(err);
  }
});

adminRouter.get('/users/:id', async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, message: 'ID user tidak valid.' });
    }

    const userRes = await pool.query(
      `SELECT
        u.id,
        u.qr_code_id,
        u.full_name,
        u.whatsapp_number,
        u.status,
        u.scanned_at,
        u.submitted_at,
        q.name AS qr_name,
        q.slug AS qr_slug,
        q.destination_url
       FROM qr_users u
       INNER JOIN qr_codes q ON q.id = u.qr_code_id
       WHERE u.id = $1
       LIMIT 1`,
      [id]
    );

    if (userRes.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Data user tidak ditemukan.' });
    }

    const row = userRes.rows[0];
    return res.json({
      success: true,
      data: {
        id: row.id,
        qr_code_id: row.qr_code_id,
        qr_name: row.qr_name,
        qr_slug: row.qr_slug,
        destination_url: row.destination_url,
        full_name: row.full_name,
        whatsapp_number: row.whatsapp_number,
        wa_url: `https://wa.me/${row.whatsapp_number}`,
        status: row.status,
        scanned_at_wita: formatWita(row.scanned_at),
        submitted_at_wita: formatWita(row.submitted_at),
        ktp_image_endpoint: `/api/admin/users/${row.id}/ktp`
      }
    });
  } catch (err) {
    return next(err);
  }
});

adminRouter.get('/users/:id/ktp', async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, message: 'ID user tidak valid.' });
    }

    const userRes = await pool.query(
      'SELECT ktp_image_url FROM qr_users WHERE id = $1 LIMIT 1',
      [id]
    );

    if (userRes.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Data user tidak ditemukan.' });
    }

    const signedUrl = generateSignedImageKitUrl(userRes.rows[0].ktp_image_url, 60);
    const ikResponse = await fetch(signedUrl);

    if (!ikResponse.ok) {
      const ikErrText = await ikResponse.text().catch(() => '');
      console.error('[ImageKit Private Fetch Error]', ikResponse.status, ikErrText.slice(0, 300));
      return res.status(502).json({
        success: false,
        message: 'Gagal memuat dokumen KTP dari penyimpanan privat.'
      });
    }

    const contentType = ikResponse.headers.get('content-type') || 'image/jpeg';
    const arrayBuffer = await ikResponse.arrayBuffer();

    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Content-Disposition', 'inline');
    return res.send(Buffer.from(arrayBuffer));
  } catch (err) {
    return next(err);
  }
});

adminRouter.delete('/users/:id', verifyCsrf, async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!/^[0-9a-f-]{36}$/i.test(id)) {
      return res.status(400).json({ success: false, message: 'ID user tidak valid.' });
    }

    const userRes = await pool.query(
      'SELECT id, ktp_file_id FROM qr_users WHERE id = $1 LIMIT 1',
      [id]
    );

    if (userRes.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Data user tidak ditemukan.' });
    }

    const { ktp_file_id } = userRes.rows[0];
    await pool.query('DELETE FROM qr_users WHERE id = $1', [id]);

    if (ktp_file_id) {
      await deleteFromImageKit(ktp_file_id);
    }

    return res.json({
      success: true,
      message: 'Data user dan dokumen KTP berhasil dihapus.'
    });
  } catch (err) {
    return next(err);
  }
});

app.use('/api/admin', adminRouter);

// ============================================================================
// 11. ATOMIC UNIQUE ACCESS ENGINE & PUBLIC SCANNER ROUTES (/r/:slug & /api/public)
// ============================================================================
/**
 * Mengunci baris qr_codes dengan FOR UPDATE di dalam transaksi PostgreSQL agar:
 * 1. Pengunjung baru hanya diterima jika unique_access < max_access.
 * 2. Dua pengunjung bersamaan tidak bisa melampaui max_access (atomic concurrency).
 * 3. Refresh halaman / scan ulang dari visitor_fingerprint yang sama tidak mengurangi sisa kuota.
 * 4. Kuota dihitung saat QR diakses, BUKAN saat form identitas disubmit.
 */
async function claimOrRefreshQrAccess(slug, visitor) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Lock row QR Code untuk menjamin pengecekan dan pencatatan kuota bersifat atomic
    const qrRes = await client.query(
      `SELECT
        id, name, slug, destination_url, logo_url, style_type,
        max_access, expires_at, pin_enabled, pin_hash, is_disabled
       FROM qr_codes
       WHERE slug = $1
       FOR UPDATE`,
      [slug]
    );

    if (qrRes.rowCount === 0) {
      await client.query('ROLLBACK');
      return { status: 'not_found', qr: null, scanEvent: null };
    }

    const qr = qrRes.rows[0];

    if (qr.is_disabled) {
      await client.query('ROLLBACK');
      return { status: 'disabled', qr, scanEvent: null };
    }

    if (new Date(qr.expires_at).getTime() <= Date.now()) {
      await client.query('ROLLBACK');
      return { status: 'expired', qr, scanEvent: null };
    }

    // Cek apakah pengunjung ini sudah pernah memiliki akses unik pada QR ini
    const existingRes = await client.query(
      `SELECT id, pin_verified, first_scanned_at, hit_count
       FROM qr_scan_events
       WHERE qr_code_id = $1 AND visitor_fingerprint = $2
       LIMIT 1`,
      [qr.id, visitor.fingerprint]
    );

    if (existingRes.rowCount > 0) {
      // Pengunjung yang sama (refresh atau scan berulang): tidak menggunakan kuota baru
      const updatedEventRes = await client.query(
        `UPDATE qr_scan_events
         SET hit_count = hit_count + 1,
             last_scanned_at = NOW(),
             ip_address = $2
         WHERE id = $1
         RETURNING id, pin_verified, first_scanned_at, hit_count`,
        [existingRes.rows[0].id, visitor.ip]
      );

      const statsRes = await client.query(
        `SELECT
          COUNT(*)::INT AS unique_access,
          COALESCE(SUM(hit_count), 0)::INT AS total_scans
         FROM qr_scan_events
         WHERE qr_code_id = $1`,
        [qr.id]
      );

      await client.query('COMMIT');
      const uniqueAccess = statsRes.rows[0].unique_access;
      return {
        status: 'valid',
        qr,
        scanEvent: updatedEventRes.rows[0],
        unique_access: uniqueAccess,
        remaining_access: Math.max(0, qr.max_access - uniqueAccess),
        total_scans: statsRes.rows[0].total_scans
      };
    }

    // Pengunjung baru: hitung jumlah unique_access saat ini
    const countRes = await client.query(
      `SELECT
        COUNT(*)::INT AS unique_access,
        COALESCE(SUM(hit_count), 0)::INT AS total_scans
       FROM qr_scan_events
       WHERE qr_code_id = $1`,
      [qr.id]
    );

    const currentUniqueAccess = countRes.rows[0].unique_access;
    const currentTotalScans = countRes.rows[0].total_scans;

    if (currentUniqueAccess >= qr.max_access) {
      await client.query('ROLLBACK');
      return {
        status: 'limit_reached',
        qr,
        scanEvent: null,
        unique_access: currentUniqueAccess,
        remaining_access: 0,
        total_scans: currentTotalScans
      };
    }

    // Kuota tersedia -> klaim 1 kuota unique access untuk pengunjung baru ini
    const insertEventRes = await client.query(
      `INSERT INTO qr_scan_events (
        qr_code_id, visitor_fingerprint, ip_address, user_agent, pin_verified, hit_count
      )
      VALUES ($1, $2, $3, $4, FALSE, 1)
      RETURNING id, pin_verified, first_scanned_at, hit_count`,
      [qr.id, visitor.fingerprint, visitor.ip, visitor.ua]
    );

    await client.query('COMMIT');
    const newUniqueAccess = currentUniqueAccess + 1;

    return {
      status: 'valid',
      qr,
      scanEvent: insertEventRes.rows[0],
      unique_access: newUniqueAccess,
      remaining_access: Math.max(0, qr.max_access - newUniqueAccess),
      total_scans: currentTotalScans + 1
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// Endpoint redirect internal saat QR Code dipindai kamera
app.get('/r/:slug', async (req, res, next) => {
  try {
    const slug = String(req.params.slug || '').trim();
    if (!/^[a-zA-Z0-9_-]{4,64}$/.test(slug)) {
      return res.redirect(302, '/scan-qr?status=not_found');
    }

    const visitor = resolveVisitorIdentity(req, res);
    const result = await claimOrRefreshQrAccess(slug, visitor);

    if (result.status !== 'valid') {
      return res.redirect(
        302,
        `/scan-qr?qr=${encodeURIComponent(slug)}&status=${encodeURIComponent(result.status)}`
      );
    }

    return res.redirect(302, `/scan-qr?qr=${encodeURIComponent(slug)}`);
  } catch (err) {
    return next(err);
  }
});

const publicRouter = express.Router();

// Memproses scan dan mengevaluasi status QR Code secara atomic
publicRouter.post('/scan', async (req, res, next) => {
  try {
    const slug = String(req.body?.slug || '').trim();
    if (!/^[a-zA-Z0-9_-]{4,64}$/.test(slug)) {
      return res.status(404).json({
        success: false,
        status: 'not_found',
        message: 'QR Code tidak ditemukan.'
      });
    }

    const visitor = resolveVisitorIdentity(req, res);
    const result = await claimOrRefreshQrAccess(slug, visitor);

    if (result.status === 'not_found') {
      return res.status(404).json({
        success: false,
        status: 'not_found',
        message: 'QR Code tidak ditemukan atau sudah dihapus.'
      });
    }

    const { qr, scanEvent } = result;

    if (result.status !== 'valid') {
      return res.json({
        success: true,
        status: result.status,
        message:
          result.status === 'limit_reached'
            ? 'Maaf, kuota akses untuk QR Code ini telah mencapai batas maksimal.'
            : result.status === 'expired'
              ? 'QR Code ini telah melewati batas masa berlaku.'
              : 'QR Code ini sedang dinonaktifkan oleh administrator.',
        qr: {
          name: qr.name,
          slug: qr.slug,
          logo_url: qr.logo_url,
          style_type: qr.style_type,
          max_access: qr.max_access,
          unique_access: result.unique_access ?? qr.max_access,
          remaining_access: result.remaining_access ?? 0,
          expires_at_wita: formatWita(qr.expires_at)
        }
      });
    }

    const pinCookieName = `s9_pin_${qr.slug}`;
    const hasValidPinCookie = verifyPinCookieValue(
      req.cookies?.[pinCookieName],
      qr.slug,
      visitor.fingerprint
    );
    const isPinVerified = !qr.pin_enabled || (scanEvent.pin_verified && hasValidPinCookie);

    return res.json({
      success: true,
      status: isPinVerified ? 'valid' : 'pin_required',
      qr: {
        name: qr.name,
        slug: qr.slug,
        logo_url: qr.logo_url,
        style_type: qr.style_type,
        pin_enabled: qr.pin_enabled,
        pin_verified: isPinVerified,
        max_access: qr.max_access,
        unique_access: result.unique_access,
        remaining_access: result.remaining_access,
        expires_at_wita: formatWita(qr.expires_at)
      }
    });
  } catch (err) {
    return next(err);
  }
});

// Verifikasi PIN QR Code di sisi server
publicRouter.post('/verify-pin', pinVerifyRateLimiter, async (req, res, next) => {
  try {
    const slug = String(req.body?.slug || '').trim();
    const pin = String(req.body?.pin || '').trim();

    if (!/^[a-zA-Z0-9_-]{4,64}$/.test(slug) || !/^\d{4,8}$/.test(pin)) {
      return res.status(400).json({
        success: false,
        message: 'Format PIN tidak valid (4-8 digit angka).'
      });
    }

    const visitor = resolveVisitorIdentity(req, res);
    const result = await claimOrRefreshQrAccess(slug, visitor);

    if (result.status !== 'valid') {
      return res.status(403).json({
        success: false,
        status: result.status,
        message:
          result.status === 'limit_reached'
            ? 'Maaf, kuota akses untuk QR Code ini telah mencapai batas maksimal.'
            : 'QR Code ini tidak lagi dapat diakses.'
      });
    }

    const { qr, scanEvent } = result;
    if (!qr.pin_enabled || !qr.pin_hash) {
      return res.json({ success: true, message: 'QR Code tidak memerlukan PIN.' });
    }

    const isPinMatch = await bcrypt.compare(pin, qr.pin_hash);
    if (!isPinMatch) {
      return res.status(401).json({
        success: false,
        message: 'PIN yang Anda masukkan salah.'
      });
    }

    await pool.query(
      'UPDATE qr_scan_events SET pin_verified = TRUE, last_scanned_at = NOW() WHERE id = $1',
      [scanEvent.id]
    );

    res.cookie(`s9_pin_${qr.slug}`, signPinCookieValue(qr.slug, visitor.fingerprint), {
      httpOnly: true,
      sameSite: 'lax',
      secure: CONFIG.IS_PROD,
      path: '/',
      maxAge: 30 * 60 * 1000
    });

    return res.json({
      success: true,
      message: 'PIN berhasil diverifikasi.'
    });
  } catch (err) {
    return next(err);
  }
});

// Pengiriman formulir identitas user + upload KTP privat ke ImageKit
publicRouter.post('/submit', publicSubmitRateLimiter, async (req, res, next) => {
  let uploadedKtp = null;
  try {
    const slug = String(req.body?.slug || '').trim();
    const fullName = String(req.body?.full_name || '').trim();
    const whatsappNumber = normalizeWhatsApp(req.body?.whatsapp_number);
    const ktpBase64 = req.body?.ktp_base64 ? String(req.body.ktp_base64) : '';

    if (!/^[a-zA-Z0-9_-]{4,64}$/.test(slug)) {
      return res.status(400).json({ success: false, message: 'Parameter QR Code tidak valid.' });
    }

    if (fullName.length < 2 || fullName.length > 150) {
      return res.status(400).json({
        success: false,
        message: 'Nama lengkap wajib diisi (2 hingga 150 karakter).'
      });
    }

    if (!whatsappNumber) {
      return res.status(400).json({
        success: false,
        message: 'Nomor WhatsApp wajib menggunakan format 628xxxxxxxxxx.'
      });
    }

    if (!ktpBase64) {
      return res.status(400).json({
        success: false,
        message: 'Foto KTP wajib diunggah.'
      });
    }

    const visitor = resolveVisitorIdentity(req, res);
    const result = await claimOrRefreshQrAccess(slug, visitor);

    if (result.status !== 'valid') {
      return res.status(403).json({
        success: false,
        status: result.status,
        message:
          result.status === 'limit_reached'
            ? 'Maaf, kuota akses untuk QR Code ini telah mencapai batas maksimal.'
            : 'QR Code sudah tidak aktif atau kedaluwarsa.'
      });
    }

    const { qr, scanEvent } = result;

    if (qr.pin_enabled) {
      const hasValidPinCookie = verifyPinCookieValue(
        req.cookies?.[`s9_pin_${qr.slug}`],
        qr.slug,
        visitor.fingerprint
      );
      if (!scanEvent?.pin_verified || !hasValidPinCookie) {
        return res.status(403).json({
          success: false,
          status: 'pin_required',
          message: 'Silakan verifikasi PIN terlebih dahulu sebelum mengirim data.'
        });
      }
    }

    uploadedKtp = await uploadToImageKit({
      base64Data: ktpBase64,
      folder: '/sector9-qr/ktp',
      prefix: `ktp_${qr.slug}`,
      isPrivateFile: true
    });

    const userInsert = await pool.query(
      `INSERT INTO qr_users (
        qr_code_id, scan_event_id, full_name, whatsapp_number,
        ktp_image_url, ktp_file_id, status, scanned_at, submitted_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, 'submitted', $7, NOW())
      RETURNING id, submitted_at`,
      [
        qr.id,
        scanEvent.id,
        fullName,
        whatsappNumber,
        uploadedKtp.url,
        uploadedKtp.fileId,
        scanEvent.first_scanned_at
      ]
    );

    const savedUser = userInsert.rows[0];

    return res.status(201).json({
      success: true,
      message: 'Data identitas berhasil diverifikasi dan disimpan.',
      data: {
        id: savedUser.id,
        qr_name: qr.name,
        destination_url: qr.destination_url,
        submitted_at_wita: formatWita(savedUser.submitted_at)
      }
    });
  } catch (err) {
    if (uploadedKtp?.fileId) {
      await deleteFromImageKit(uploadedKtp.fileId);
    }
    if (err.message && (err.message.includes('Format') || err.message.includes('Ukuran') || err.message.includes('gambar'))) {
      return res.status(400).json({ success: false, message: err.message });
    }
    return next(err);
  }
});

app.use('/api/public', publicRouter);

// ============================================================================
// 12. HTML PAGE ROUTES & ROUTE PROTECTION
// ============================================================================
const PUBLIC_DIR = path.join(__dirname, 'public');

function sendHtmlPage(res, filename) {
  const filePath = path.join(PUBLIC_DIR, filename);
  if (!fs.existsSync(filePath)) {
    return res.status(503).send(
      `<!doctype html><html lang="id"><head><meta charset="utf-8"><title>Sector9 QR</title></head>` +
      `<body style="font-family:monospace;padding:2rem;">Halaman <b>${filename}</b> belum dibuat pada tahap ini.</body></html>`
    );
  }
  res.setHeader('Cache-Control', 'no-store');
  return res.sendFile(filePath);
}

app.get(['/dashboard.html', '/qr-manage.html', '/user-list.html'], (req, res) => {
  return res.redirect(302, '/');
});

app.get('/', async (req, res, next) => {
  try {
    const session = await authenticateAdminSession(req);
    if (session) {
      return res.redirect(302, '/dashboard');
    }
    return sendHtmlPage(res, 'index.html');
  } catch (err) {
    return next(err);
  }
});

app.get('/scan-qr', (req, res) => {
  return sendHtmlPage(res, 'scan-qr.html');
});

app.get('/dashboard', requireAdminPage, (req, res) => {
  return sendHtmlPage(res, 'dashboard.html');
});

app.get('/manage-qr', requireAdminPage, (req, res) => {
  return sendHtmlPage(res, 'qr-manage.html');
});

app.get('/user-list', requireAdminPage, (req, res) => {
  return sendHtmlPage(res, 'user-list.html');
});

// ============================================================================
// 13. 404 & GLOBAL ERROR HANDLER
// ============================================================================
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      success: false,
      message: 'Endpoint API tidak ditemukan.'
    });
  }
  return res.status(404).send(
    '<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>404 — Sector9 QR</title></head>' +
    '<body style="margin:0;background:#fff;color:#000;font-family:ui-sans-serif,system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;">' +
    '<div style="border:1px solid #000;padding:2.5rem;max-width:420px;width:90%;">' +
    '<div style="font-size:12px;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:0.5rem;">ERROR 404</div>' +
    '<h1 style="margin:0 0 0.75rem;font-size:1.5rem;font-weight:700;">Halaman Tidak Ditemukan</h1>' +
    '<p style="margin:0 0 1.5rem;font-size:0.875rem;color:#333;line-height:1.5;">Alamat URL yang Anda akses tidak tersedia di sistem Sector9 QR.</p>' +
    '<a href="/" style="display:inline-block;background:#000;color:#fff;text-decoration:none;padding:0.65rem 1.25rem;font-size:0.75rem;letter-spacing:0.1em;text-transform:uppercase;">Kembali ke Beranda</a>' +
    '</div></body></html>'
  );
});

app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      success: false,
      message: `Ukuran payload melebihi batas maksimal ${CONFIG.UPLOAD_MAX_SIZE_MB} MB.`
    });
  }

  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      success: false,
      message: 'Format JSON tidak valid.'
    });
  }

  console.error('[Server Error]', err);

  const statusCode = err.statusCode || 500;
  const safeMessage = CONFIG.IS_PROD
    ? 'Terjadi kesalahan internal pada server.'
    : (err.message || 'Terjadi kesalahan internal pada server.');

  if (req.path.startsWith('/api/')) {
    return res.status(statusCode).json({
      success: false,
      message: safeMessage
    });
  }

  return res.status(statusCode).send(safeMessage);
});

// ============================================================================
// 14. START HTTP SERVER
// ============================================================================
app.listen(CONFIG.PORT, () => {
  console.log(`[Sector9 QR] Server berjalan pada ${CONFIG.LOCAL_ORIGIN}`);
  console.log(`[Sector9 QR] Environment: ${CONFIG.NODE_ENV} | Timezone: ${CONFIG.TIMEZONE}`);
});
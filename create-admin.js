require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const readline = require('readline');

function askQuestion(rl, query) {
  return new Promise((resolve) => rl.question(query, resolve));
}

async function main() {
  if (!process.env.DATABASE_URL) {
    console.error('[ERROR] DATABASE_URL tidak ditemukan di file .env');
    process.exit(1);
  }

  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  try {
    let username = (process.argv[2] || '').trim();
    let password = (process.argv[3] || '').trim();

    if (!username) {
      username = (await askQuestion(rl, 'Masukkan Username Admin (3-50 karakter): ')).trim();
    }

    if (!password) {
      password = (await askQuestion(rl, 'Masukkan Password Admin (minimal 8 karakter): ')).trim();
    }

    if (!/^[a-zA-Z0-9._-]{3,50}$/.test(username)) {
      console.error('[ERROR] Username hanya boleh huruf, angka, titik, underscore, atau tanda hubung (3-50 karakter).');
      process.exitCode = 1;
      return;
    }

    if (password.length < 8) {
      console.error('[ERROR] Password minimal harus 8 karakter.');
      process.exitCode = 1;
      return;
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const query = `
      INSERT INTO admins (username, password_hash)
      VALUES ($1, $2)
      ON CONFLICT (username)
      DO UPDATE SET password_hash = EXCLUDED.password_hash
      RETURNING id, username;
    `;

    const { rows } = await pool.query(query, [username, passwordHash]);
    const admin = rows[0];

    console.log('\n[OK] Akun admin berhasil disimpan ke database Neon PostgreSQL:');
    console.log(`- ID       : ${admin.id}`);
    console.log(`- Username : ${admin.username}`);
    console.log('- Login    : http://localhost:3000/\n');
  } catch (err) {
    console.error('[ERROR] Gagal membuat akun admin:', err.message);
    process.exitCode = 1;
  } finally {
    rl.close();
    await pool.end();
  }
}

main();
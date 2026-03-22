const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS questions (
      id SERIAL PRIMARY KEY,
      text TEXT NOT NULL,
      type TEXT NOT NULL,
      options TEXT,
      points INTEGER DEFAULT 1,
      correct_answer TEXT,
      category TEXT,
      sort_order INTEGER DEFAULT 0,
      day INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Migration: add day column if missing
  await pool.query(`ALTER TABLE questions ADD COLUMN IF NOT EXISTS day INTEGER DEFAULT 0`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS answers (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      question_id INTEGER NOT NULL REFERENCES questions(id),
      answer TEXT NOT NULL,
      submitted_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(user_id, question_id)
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS leaderboard_snapshots (
      id SERIAL PRIMARY KEY,
      data JSONB NOT NULL,
      label TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  // Default settings
  await pool.query(`
    INSERT INTO settings (key, value) VALUES
      ('pool_name', 'Mastersbet 2026'),
      ('deadline', '2026-04-10T12:00:00'),
      ('locked', '0')
    ON CONFLICT (key) DO NOTHING
  `);
  console.log('Database initialized');
}

async function run(sql, params = []) {
  // Convert ? placeholders to $1, $2...
  let i = 0;
  const pgSql = sql.replace(/\?/g, () => `$${++i}`);
  await pool.query(pgSql, params);
}

async function all(sql, params = []) {
  let i = 0;
  const pgSql = sql.replace(/\?/g, () => `$${++i}`);
  const res = await pool.query(pgSql, params);
  return res.rows;
}

async function get(sql, params = []) {
  const rows = await all(sql, params);
  return rows.length > 0 ? rows[0] : null;
}

module.exports = { initDb, run, all, get };

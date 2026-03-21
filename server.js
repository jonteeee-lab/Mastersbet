const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { initDb, run, all, get } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'masters-pool-secret-2026-change-me';

app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ──
function auth(req, res, next) {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Ej inloggad' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Ogiltig session' }); }
}
function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: 'Endast admin' });
    next();
  });
}

// ── Auth ──
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Alla fält krävs' });
    const existing = await get('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) return res.status(400).json({ error: 'E-postadressen är redan registrerad' });
    const hash = bcrypt.hashSync(password, 10);
    const isFirst = !(await get('SELECT id FROM users LIMIT 1'));
    await run('INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
      [name, email, hash, isFirst ? 1 : 0]);
    const user = await get('SELECT id, name, email, is_admin FROM users WHERE email = ?', [email]);
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7*24*60*60*1000 });
    res.json({ user, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user || !bcrypt.compareSync(password, user.password_hash))
      return res.status(401).json({ error: 'Fel e-post eller lösenord' });
    const payload = { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7*24*60*60*1000 });
    res.json({ user: payload, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });

app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

// ── Settings ──
app.get('/api/settings', async (req, res) => {
  try {
    const rows = await all('SELECT key, value FROM settings');
    const s = {}; rows.forEach(r => { s[r.key] = r.value; });
    res.json(s);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Questions ──
app.get('/api/questions', auth, async (req, res) => {
  try {
    const qs = await all('SELECT id, text, type, options, points, category, sort_order FROM questions ORDER BY sort_order, id');
    qs.forEach(q => { if (q.options) q.options = JSON.parse(q.options); });
    res.json(qs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Answers ──
app.get('/api/answers', auth, async (req, res) => {
  try {
    res.json(await all('SELECT question_id, answer FROM answers WHERE user_id = ?', [req.user.id]));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/answers', auth, async (req, res) => {
  try {
    const rows = await all('SELECT key, value FROM settings');
    const s = {}; rows.forEach(r => { s[r.key] = r.value; });
    if (s.locked === '1') return res.status(403).json({ error: 'Poolen är låst' });
    if (new Date(s.deadline) < new Date()) return res.status(403).json({ error: 'Deadline har passerat' });
    const { answers } = req.body;
    for (const a of answers) {
      const existing = await get('SELECT id FROM answers WHERE user_id = ? AND question_id = ?', [req.user.id, a.question_id]);
      if (existing) {
        await run('UPDATE answers SET answer = ?, submitted_at = NOW() WHERE user_id = ? AND question_id = ?',
          [a.answer, req.user.id, a.question_id]);
      } else {
        await run('INSERT INTO answers (user_id, question_id, answer) VALUES (?, ?, ?)',
          [req.user.id, a.question_id, a.answer]);
      }
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Results ──
app.get('/api/results', auth, async (req, res) => {
  try {
    const rows = await all(`
      SELECT q.id, q.text, q.type, q.options, q.points, q.correct_answer, q.category, a.answer as my_answer
      FROM questions q
      LEFT JOIN answers a ON a.question_id = q.id AND a.user_id = ?
      ORDER BY q.sort_order, q.id
    `, [req.user.id]);
    let total = 0, earned = 0;
    const results = rows.map(r => {
      if (r.options) r.options = JSON.parse(r.options);
      total += r.points;
      let correct = null;
      if (r.correct_answer !== null) {
        correct = r.my_answer === r.correct_answer;
        if (correct) earned += r.points;
      }
      return { ...r, correct };
    });
    res.json({ results, totalPoints: total, earnedPoints: earned });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Leaderboard ──
async function calcLeaderboard() {
  const users = await all('SELECT id, name FROM users ORDER BY created_at');
  const questions = await all('SELECT id, points, correct_answer FROM questions');
  const board = await Promise.all(users.map(async u => {
    const answers = await all('SELECT question_id, answer FROM answers WHERE user_id = ?', [u.id]);
    let earned = 0, correctCount = 0;
    answers.forEach(a => {
      const q = questions.find(q => q.id == a.question_id);
      if (q && q.correct_answer !== null && a.answer === q.correct_answer) { earned += q.points; correctCount++; }
    });
    return { name: u.name, points: earned, answered: answers.length, correctCount };
  }));
  board.sort((a, b) => b.points - a.points);
  return board;
}

app.get('/api/leaderboard', async (req, res) => {
  try {
    const board = await calcLeaderboard();
    const snap = await get('SELECT data FROM leaderboard_snapshots ORDER BY created_at DESC LIMIT 1');
    res.json({ board, prevSnapshot: snap ? snap.data : null });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/leaderboard/snapshot', adminAuth, async (req, res) => {
  try {
    const board = await calcLeaderboard();
    const { label } = req.body;
    await run('INSERT INTO leaderboard_snapshots (data, label) VALUES (?, ?)', [JSON.stringify(board), label || null]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/leaderboard/snapshot', adminAuth, async (req, res) => {
  try {
    await run('DELETE FROM leaderboard_snapshots');
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══ ADMIN ══

app.get('/api/admin/questions', adminAuth, async (req, res) => {
  try {
    const qs = await all('SELECT * FROM questions ORDER BY sort_order, id');
    qs.forEach(q => { if (q.options) q.options = JSON.parse(q.options); });
    res.json(qs);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/questions', adminAuth, async (req, res) => {
  try {
    const { text, type, options, points, category, sort_order } = req.body;
    if (!text || !type) return res.status(400).json({ error: 'Text och typ krävs' });
    await run('INSERT INTO questions (text, type, options, points, category, sort_order) VALUES (?, ?, ?, ?, ?, ?)',
      [text, type, options ? JSON.stringify(options) : null, points||1, category||null, sort_order||0]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/questions/:id', adminAuth, async (req, res) => {
  try {
    const { text, type, options, points, correct_answer, category, sort_order } = req.body;
    await run('UPDATE questions SET text=?, type=?, options=?, points=?, correct_answer=?, category=?, sort_order=? WHERE id=?',
      [text, type, options ? JSON.stringify(options) : null, points||1, correct_answer||null, category||null, sort_order||0, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/questions/:id', adminAuth, async (req, res) => {
  try {
    await run('DELETE FROM answers WHERE question_id = ?', [req.params.id]);
    await run('DELETE FROM questions WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/settings', adminAuth, async (req, res) => {
  try {
    const { pool_name, deadline, locked } = req.body;
    if (pool_name !== undefined) await run("INSERT INTO settings (key,value) VALUES ('pool_name',?) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", [pool_name]);
    if (deadline !== undefined) await run("INSERT INTO settings (key,value) VALUES ('deadline',?) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", [deadline]);
    if (locked !== undefined) await run("INSERT INTO settings (key,value) VALUES ('locked',?) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value", [locked ? '1' : '0']);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/users', adminAuth, async (req, res) => {
  try { res.json(await all('SELECT id, name, email, is_admin, created_at FROM users ORDER BY created_at')); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const { name, email, password, is_admin } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Namn, e-post och lösenord krävs' });
    const existing = await get('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) return res.status(400).json({ error: 'E-postadressen är redan registrerad' });
    const hash = bcrypt.hashSync(password, 10);
    await run('INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, ?)', [name, email, hash, is_admin ? 1 : 0]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/users/:id/toggle-admin', adminAuth, async (req, res) => {
  try {
    const user = await get('SELECT id, is_admin FROM users WHERE id = ?', [req.params.id]);
    if (!user) return res.status(404).json({ error: 'Användare hittades inte' });
    await run('UPDATE users SET is_admin = ? WHERE id = ?', [user.is_admin ? 0 : 1, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    if (req.params.id == req.user.id) return res.status(400).json({ error: 'Du kan inte ta bort dig själv' });
    await run('DELETE FROM answers WHERE user_id = ?', [req.params.id]);
    await run('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/users/:id/answers', adminAuth, async (req, res) => {
  try {
    const rows = await all(`
      SELECT q.id as question_id, q.text, q.type, q.options, q.points, q.correct_answer, q.category, a.answer
      FROM questions q
      LEFT JOIN answers a ON a.question_id = q.id AND a.user_id = ?
      ORDER BY q.sort_order, q.id
    `, [req.params.id]);
    rows.forEach(r => { if (r.options) r.options = JSON.parse(r.options); });
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/users/:userId/answers/:questionId', adminAuth, async (req, res) => {
  try {
    const { answer } = req.body;
    const existing = await get('SELECT id FROM answers WHERE user_id = ? AND question_id = ?', [req.params.userId, req.params.questionId]);
    if (existing) {
      await run('UPDATE answers SET answer = ? WHERE user_id = ? AND question_id = ?', [answer, req.params.userId, req.params.questionId]);
    } else {
      await run('INSERT INTO answers (user_id, question_id, answer) VALUES (?, ?, ?)', [req.params.userId, req.params.questionId, answer]);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:userId/answers/:questionId', adminAuth, async (req, res) => {
  try {
    await run('DELETE FROM answers WHERE user_id = ? AND question_id = ?', [req.params.userId, req.params.questionId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

(async () => {
  await initDb();
  app.listen(PORT, () => console.log(`Mastersbet running on http://localhost:${PORT}`));
})();

const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { initDb, run, all, get } = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'vm-bettet-2026-secret-change-me';

app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ══════════════════════════════════════════════════════════════════════════════
// TOURNAMENT DATA
// ══════════════════════════════════════════════════════════════════════════════

const GROUPS = {
  A: ['Mexiko', 'Sydafrika', 'Sydkorea', 'Tjeckien'],
  B: ['Kanada', 'Bosnien', 'Qatar', 'Schweiz'],
  C: ['Brasilien', 'Marocko', 'Haiti', 'Skottland'],
  D: ['USA', 'Paraguay', 'Australien', 'Turkiet'],
  E: ['Tyskland', 'Curaçao', 'Elfenbenskusten', 'Ecuador'],
  F: ['Nederländerna', 'Japan', 'Sverige', 'Tunisien'],
  G: ['Belgien', 'Egypten', 'Iran', 'Nya Zeeland'],
  H: ['Spanien', 'Kap Verde', 'Saudiarabien', 'Uruguay'],
  I: ['Frankrike', 'Senegal', 'Norge', 'Irak'],
  J: ['Argentina', 'Algeriet', 'Österrike', 'Jordanien'],
  K: ['Portugal', 'DR Kongo', 'Uzbekistan', 'Colombia'],
  L: ['England', 'Kroatien', 'Ghana', 'Panama']
};

const ALL_TEAMS = Object.values(GROUPS).flat();

// Group matches: [matchNum, date, timeET, homeTeam, awayTeam, group, broadcaster]
const GROUP_MATCHES = [
  [1,'2026-06-11','15:00','Mexiko','Sydafrika','A','TV4'],
  [2,'2026-06-11','22:00','Sydkorea','Tjeckien','A','TV4'],
  [3,'2026-06-12','15:00','Kanada','Bosnien','B','SVT'],
  [4,'2026-06-12','21:00','USA','Paraguay','D','TV4'],
  [5,'2026-06-13','00:00','Australien','Turkiet','D','TV4'],
  [6,'2026-06-13','15:00','Qatar','Schweiz','B','TV4'],
  [7,'2026-06-13','18:00','Brasilien','Marocko','C','SVT'],
  [8,'2026-06-13','21:00','Haiti','Skottland','C','SVT'],
  [9,'2026-06-14','13:00','Tyskland','Curaçao','E','TV4'],
  [10,'2026-06-14','16:00','Nederländerna','Japan','F','TV4'],
  [11,'2026-06-14','19:00','Elfenbenskusten','Ecuador','E','TV4'],
  [12,'2026-06-14','22:00','Sverige','Tunisien','F','SVT'],
  [13,'2026-06-15','12:00','Spanien','Kap Verde','H','SVT'],
  [14,'2026-06-15','15:00','Belgien','Egypten','G','SVT'],
  [15,'2026-06-15','18:00','Saudiarabien','Uruguay','H','TV4'],
  [16,'2026-06-15','21:00','Iran','Nya Zeeland','G','TV4'],
  [17,'2026-06-16','15:00','Frankrike','Senegal','I','SVT'],
  [18,'2026-06-16','18:00','Irak','Norge','I','TV4'],
  [19,'2026-06-16','21:00','Argentina','Algeriet','J','TV4'],
  [20,'2026-06-17','00:00','Österrike','Jordanien','J','TV4'],
  [21,'2026-06-17','13:00','Portugal','DR Kongo','K','TV4'],
  [22,'2026-06-17','16:00','England','Kroatien','L','TV4'],
  [23,'2026-06-17','19:00','Ghana','Panama','L','TV4'],
  [24,'2026-06-17','22:00','Uzbekistan','Colombia','K','TV4'],
  [25,'2026-06-18','12:00','Tjeckien','Sydafrika','A','TV4'],
  [26,'2026-06-18','15:00','Schweiz','Bosnien','B','TV4'],
  [27,'2026-06-18','18:00','Kanada','Qatar','B','TV4'],
  [28,'2026-06-18','21:00','Mexiko','Sydkorea','A','TV4'],
  [29,'2026-06-19','00:00','Turkiet','Paraguay','D','TV4'],
  [30,'2026-06-19','15:00','USA','Australien','D','SVT'],
  [31,'2026-06-19','18:00','Skottland','Marocko','C','SVT'],
  [32,'2026-06-19','21:00','Brasilien','Haiti','C','TV4'],
  [33,'2026-06-20','00:00','Tunisien','Japan','F','SVT'],
  [34,'2026-06-20','13:00','Nederländerna','Sverige','F','TV4'],
  [35,'2026-06-20','16:00','Tyskland','Elfenbenskusten','E','TV4'],
  [36,'2026-06-20','20:00','Ecuador','Curaçao','E','TV4'],
  [37,'2026-06-21','12:00','Spanien','Saudiarabien','H','TV4'],
  [38,'2026-06-21','15:00','Belgien','Iran','G','TV4'],
  [39,'2026-06-21','18:00','Uruguay','Kap Verde','H','TV4'],
  [40,'2026-06-21','21:00','Nya Zeeland','Egypten','G','TV4'],
  [41,'2026-06-22','13:00','Argentina','Österrike','J','SVT'],
  [42,'2026-06-22','17:00','Frankrike','Irak','I','TV4'],
  [43,'2026-06-22','20:00','Norge','Senegal','I','SVT'],
  [44,'2026-06-22','23:00','Jordanien','Algeriet','J','TV4'],
  [45,'2026-06-23','13:00','Portugal','Uzbekistan','K','SVT'],
  [46,'2026-06-23','16:00','England','Ghana','L','SVT'],
  [47,'2026-06-23','19:00','Panama','Kroatien','L','TV4'],
  [48,'2026-06-23','22:00','Colombia','DR Kongo','K','SVT'],
  [49,'2026-06-24','15:00','Schweiz','Kanada','B','TV4'],
  [50,'2026-06-24','15:00','Bosnien','Qatar','B','TV4'],
  [51,'2026-06-24','18:00','Skottland','Brasilien','C','TV4'],
  [52,'2026-06-24','18:00','Marocko','Haiti','C','TV4'],
  [53,'2026-06-24','21:00','Tjeckien','Mexiko','A','SVT'],
  [54,'2026-06-24','21:00','Sydafrika','Sydkorea','A','SVT'],
  [55,'2026-06-25','16:00','Curaçao','Elfenbenskusten','E','SVT'],
  [56,'2026-06-25','16:00','Ecuador','Tyskland','E','SVT'],
  [57,'2026-06-25','19:00','Japan','Sverige','F','SVT'],
  [58,'2026-06-25','19:00','Tunisien','Nederländerna','F','SVT'],
  [59,'2026-06-25','22:00','Turkiet','USA','D','TV4'],
  [60,'2026-06-25','22:00','Paraguay','Australien','D','TV4'],
  [61,'2026-06-26','15:00','Norge','Frankrike','I','TV4'],
  [62,'2026-06-26','15:00','Senegal','Irak','I','TV4'],
  [63,'2026-06-26','20:00','Kap Verde','Saudiarabien','H','TV4'],
  [64,'2026-06-26','20:00','Uruguay','Spanien','H','TV4'],
  [65,'2026-06-26','23:00','Egypten','Iran','G','TV4'],
  [66,'2026-06-26','23:00','Nya Zeeland','Belgien','G','TV4'],
  [67,'2026-06-27','17:00','Panama','England','L','SVT'],
  [68,'2026-06-27','17:00','Kroatien','Ghana','L','SVT'],
  [69,'2026-06-27','19:30','Colombia','Portugal','K','TV4'],
  [70,'2026-06-27','19:30','DR Kongo','Uzbekistan','K','TV4'],
  [71,'2026-06-27','22:00','Algeriet','Österrike','J','TV4'],
  [72,'2026-06-27','22:00','Jordanien','Argentina','J','TV4']
];

// R32 bracket: [matchNum, date, timeET, homeSlot, awaySlot]
// Slots: "1A"=winner group A, "2B"=runner-up group B, "3ABCDF"=best 3rd from those groups
const R32_MATCHES = [
  [73,'2026-06-28','15:00','2A','2B'],
  [74,'2026-06-29','13:00','1C','2F'],
  [75,'2026-06-29','16:30','1E','3ABCDF'],
  [76,'2026-06-29','21:00','1F','2C'],
  [77,'2026-06-30','17:00','1I','3CDFGH'],
  [78,'2026-06-30','13:00','2E','2I'],
  [79,'2026-06-30','21:00','1A','3CEFHI'],
  [80,'2026-07-01','12:00','1L','3EHIJK'],
  [81,'2026-07-01','20:00','1D','3BEFIJ'],
  [82,'2026-07-01','16:00','1G','3AEHIJ'],
  [83,'2026-07-02','19:00','2K','2L'],
  [84,'2026-07-02','15:00','1H','2J'],
  [85,'2026-07-02','23:00','1B','3EFGIJ'],
  [86,'2026-07-03','18:00','1J','2H'],
  [87,'2026-07-03','21:30','1K','3DEIJL'],
  [88,'2026-07-03','14:00','2D','2G']
];

// R16 onwards: [matchNum, date, timeET, homeSource, awaySource]
const R16_MATCHES = [
  [89,'2026-07-04','17:00','W74','W77'],
  [90,'2026-07-04','13:00','W73','W75'],
  [91,'2026-07-05','16:00','W76','W78'],
  [92,'2026-07-05','20:00','W79','W80'],
  [93,'2026-07-06','15:00','W83','W84'],
  [94,'2026-07-06','20:00','W81','W82'],
  [95,'2026-07-07','12:00','W86','W88'],
  [96,'2026-07-07','16:00','W85','W87']
];

const QF_MATCHES = [
  [97,'2026-07-09','16:00','W89','W90'],
  [98,'2026-07-10','15:00','W93','W94'],
  [99,'2026-07-11','17:00','W91','W92'],
  [100,'2026-07-11','21:00','W95','W96']
];

const SF_MATCHES = [
  [101,'2026-07-14','15:00','W97','W98'],
  [102,'2026-07-15','15:00','W99','W100']
];

const BRONZE_MATCH = [103,'2026-07-18','17:00','L101','L102'];
const FINAL_MATCH = [104,'2026-07-19','15:00','W101','W102'];

// ══════════════════════════════════════════════════════════════════════════════
// SCORING ENGINE
// ══════════════════════════════════════════════════════════════════════════════

const SCORING = {
  matchSign: 3,         // correct 1X2 (× consensus multiplier)
  matchMargin: 2,       // correct goal-margin — 1/2 only, flat (no multiplier)
  // Group placement per group: points for 0/1/2/3/4 correct positions
  // (3 correct is impossible in a 4-team permutation, so index 3 is never reached)
  placementTier: [0, 5, 10, 0, 20],
  r32Team: 1,  r32AllBonus: 15,
  r16Team: 3,  r16AllBonus: 15,
  qfTeam:  6,  qfAllBonus:  15,
  sfTeam:  12, sfAllBonus:  15,
  finalistAdvance: 8,  // per team correctly placed in final (order-independent)
  winnerBonus: 12,     // additional for exact 1st place
  runnerUpBonus: 8,    // additional for exact 2nd place
  thirdPlace: 8,       // exact 3rd place
  fourthPlace: 8,      // exact 4th place
  question: 4,         // per correct answer (10 questions total)
};

function calcSign(h, a) {
  if (h > a) return '1';
  if (h === a) return 'X';
  return '2';
}

function consensusMult(pct) {
  if (pct > 0.50) return 1.0;
  if (pct > 0.25) return 1.5;
  if (pct > 0.10) return 2.0;
  return 3.0;
}

// Build a per-match sign-distribution map from all stored prediction objects.
// Returns: { [matchNum]: { '1': fraction, 'X': fraction, '2': fraction } }
function buildConsensusMap(allPredData) {
  const map = {};
  const total = allPredData.length;
  if (total === 0) return map;
  for (const m of GROUP_MATCHES) {
    const mn = String(m[0]);
    const counts = { '1': 0, 'X': 0, '2': 0 };
    for (const pred of allPredData) {
      const p = pred.matches?.[mn];
      if (p && p[0] != null && p[1] != null) {
        counts[calcSign(Number(p[0]), Number(p[1]))]++;
      }
    }
    const validCount = counts['1'] + counts['X'] + counts['2'];
    map[mn] = validCount > 0
      ? { '1': counts['1'] / validCount, 'X': counts['X'] / validCount, '2': counts['2'] / validCount }
      : { '1': 0, 'X': 0, '2': 0 };
  }
  return map;
}

function computeScore(pred, actual, consensusMap = {}) {
  if (!pred || !actual) return { total: 0, breakdown: {} };
  const bd = {};
  let total = 0;

  // ── A. Group matches (72 matches) ──
  let signPts = 0, marginPts = 0, boostPts = 0;
  for (const m of GROUP_MATCHES) {
    const mn = String(m[0]);
    const p = pred.matches?.[mn];
    const a = actual.matches?.[mn];
    if (!p || !a || a[0] == null || a[1] == null) continue;
    const pSign = calcSign(Number(p[0]), Number(p[1]));
    const aSign = calcSign(Number(a[0]), Number(a[1]));
    const pct   = consensusMap[mn]?.[aSign] ?? null;
    const mult  = pct !== null ? consensusMult(pct) : 1;
    if (pSign === aSign) {
      signPts += SCORING.matchSign * mult;
      if (mult > 1) boostPts += SCORING.matchSign * (mult - 1);
      if (pSign !== 'X') {
        const pMargin = Math.abs(Number(p[0]) - Number(p[1]));
        const aMargin = Math.abs(Number(a[0]) - Number(a[1]));
        if (pMargin === aMargin) marginPts += SCORING.matchMargin; // flat, no mult
      }
    }
  }
  bd.matchSign      = Math.round(signPts);
  bd.matchMargin    = Math.round(marginPts);
  bd.consensusBoost = Math.round(boostPts);
  total += bd.matchSign + bd.matchMargin;

  // ── B. Group placements (12 groups, tier scoring per group) ──
  let placePts = 0;
  for (const g of Object.keys(GROUPS)) {
    const pArr = pred.placements?.[g];
    const aArr = actual.placements?.[g];
    if (!pArr || !aArr || aArr.length < 4) continue;
    let correct = 0;
    for (let i = 0; i < 4; i++) {
      if (pArr[i] && aArr[i] && pArr[i] === aArr[i]) correct++;
    }
    placePts += SCORING.placementTier[correct] || 0;
  }
  bd.placements = placePts;
  total += placePts;

  // ── C-F. Knockout teams ──
  function scoreRound(predKey, actualKey, perTeam, allBonus, expectedCount) {
    const pTeams = pred[predKey] || [];
    const aTeams = actual[actualKey] || [];
    if (aTeams.length === 0) return 0;
    let correct = 0;
    for (const t of pTeams) { if (t && aTeams.includes(t)) correct++; }
    return correct * perTeam + (correct === expectedCount && expectedCount === aTeams.length ? allBonus : 0);
  }
  bd.r32 = scoreRound('r32Teams', 'r32Teams', SCORING.r32Team, SCORING.r32AllBonus, 32); total += bd.r32;
  bd.r16 = scoreRound('r16Teams', 'r16Teams', SCORING.r16Team, SCORING.r16AllBonus, 16); total += bd.r16;
  bd.qf  = scoreRound('qfTeams',  'qfTeams',  SCORING.qfTeam,  SCORING.qfAllBonus,  8);  total += bd.qf;
  bd.sf  = scoreRound('sfTeams',  'sfTeams',  SCORING.sfTeam,  SCORING.sfAllBonus,  4);  total += bd.sf;

  // ── G. Final & bronze placements ──
  let finalPts = 0;
  const pFinal = pred.finalPlacements || {};
  const aFinal = actual.finalPlacements || {};
  if (aFinal['1']) {
    const aFinalists = [aFinal['1'], aFinal['2']].filter(Boolean);
    // 8p per finalist correctly identified (order-independent)
    for (const pos of ['1', '2']) {
      if (pFinal[pos] && aFinalists.includes(pFinal[pos])) finalPts += SCORING.finalistAdvance;
    }
    // Position bonuses (on top of advance points)
    if (pFinal['1'] && aFinal['1'] && pFinal['1'] === aFinal['1']) finalPts += SCORING.winnerBonus;
    if (pFinal['2'] && aFinal['2'] && pFinal['2'] === aFinal['2']) finalPts += SCORING.runnerUpBonus;
  }
  if (pFinal['3'] && aFinal['3'] && pFinal['3'] === aFinal['3']) finalPts += SCORING.thirdPlace;
  if (pFinal['4'] && aFinal['4'] && pFinal['4'] === aFinal['4']) finalPts += SCORING.fourthPlace;
  bd.finalPlacements = finalPts;
  total += finalPts;

  // ── H. Questions ──
  let questionPts = 0;
  const pQ = pred.questions || {};
  const aQ = actual.questions || {};

  // Q1-Q3: skytteliga topp 3 — pool-based, order irrelevant
  const actualPool = ['q1','q2','q3']
    .map(k => String(aQ[k] || '').toLowerCase().trim())
    .filter(Boolean);
  const usedActual = new Set();
  for (const key of ['q1','q2','q3']) {
    const pVal = String(pQ[key] || '').toLowerCase().trim();
    if (pVal && actualPool.includes(pVal) && !usedActual.has(pVal)) {
      usedActual.add(pVal);
      questionPts += SCORING.question;
    }
  }

  // Q4-Q6: comma-separated multi-correct answers
  for (const key of ['q4','q5','q6']) {
    const pVal = String(pQ[key] || '').toLowerCase().trim();
    const accepted = String(aQ[key] || '').split(',')
      .map(s => s.toLowerCase().trim()).filter(Boolean);
    if (pVal && accepted.includes(pVal)) questionPts += SCORING.question;
  }

  // Q7-Q10: exact string match
  for (const key of ['q7','q8','q9','q10']) {
    const pVal = String(pQ[key] || '').toLowerCase().trim();
    const aVal = String(aQ[key] || '').toLowerCase().trim();
    if (pVal && aVal && pVal === aVal) questionPts += SCORING.question;
  }

  bd.questions = questionPts;
  total += questionPts;

  return { total, breakdown: bd };
}

// Build a scoreable prediction from stored data.
// r32Teams is derived from group placements (24 auto) + thirdPlaceQualifiers (8 manual).
function buildScoreablePrediction(predData) {
  const r32Teams = [];
  for (const g of Object.keys(GROUPS)) {
    const pl = predData.placements?.[g];
    if (pl) {
      if (pl[0]) r32Teams.push(pl[0]); // group winner
      if (pl[1]) r32Teams.push(pl[1]); // runner-up
    }
  }
  for (const t of (predData.thirdPlaceQualifiers || [])) {
    if (t) r32Teams.push(t);
  }
  return {
    matches:         predData.matches         || {},
    placements:      predData.placements      || {},
    r32Teams:        [...new Set(r32Teams)],
    r16Teams:        predData.r16Teams        || [],
    qfTeams:         predData.qfTeams         || [],
    sfTeams:         predData.sfTeams         || [],
    finalPlacements: predData.finalPlacements || {},
    questions:       predData.questions       || {}
  };
}

function buildScoreableResults(resData) {
  return {
    matches:         resData.matches         || {},
    placements:      resData.placements      || {},
    r32Teams:        resData.r32Teams        || [],
    r16Teams:        resData.r16Teams        || [],
    qfTeams:         resData.qfTeams         || [],
    sfTeams:         resData.sfTeams         || [],
    finalPlacements: resData.finalPlacements || {},
    questions:       resData.questions       || {}
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// AUTH
// ══════════════════════════════════════════════════════════════════════════════

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

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Alla fält krävs' });
    const existing = await get('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) return res.status(400).json({ error: 'E-postadressen är redan registrerad' });
    const hash = bcrypt.hashSync(password, 10);
    const isFirst = !(await get('SELECT id FROM users LIMIT 1'));
    await run('INSERT INTO users (name, email, password_hash, is_admin, approved) VALUES (?, ?, ?, ?, ?)',
      [name, email, hash, isFirst ? 1 : 0, isFirst ? 1 : 0]);
    const user = await get('SELECT id, name, email, is_admin, approved, avatar FROM users WHERE email = ?', [email]);
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 30*24*60*60*1000 });
    res.json({ user: { ...user, submitted: false }, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user || !bcrypt.compareSync(password, user.password_hash))
      return res.status(401).json({ error: 'Fel e-post eller lösenord' });
    const pred = await get('SELECT submitted_at FROM predictions WHERE user_id = ?', [user.id]);
    const payload = { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 30*24*60*60*1000 });
    res.json({ user: { ...payload, avatar: user.avatar, approved: user.approved, submitted: !!pred?.submitted_at }, token });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('token'); res.json({ ok: true }); });
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const u = await get('SELECT id, name, email, is_admin, approved, avatar FROM users WHERE id = ?', [req.user.id]);
    if (!u) return res.status(401).json({ error: 'Användare borttagen' });
    const pred = await get('SELECT submitted_at FROM predictions WHERE user_id = ?', [req.user.id]);
    res.json({ user: { ...u, submitted: !!pred?.submitted_at } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Avatar upload/delete ──
const MAX_AVATAR_LEN = 200000; // ~150 kB JPEG base64
app.put('/api/users/me/avatar', auth, async (req, res) => {
  try {
    const { avatar } = req.body;
    if (!avatar || typeof avatar !== 'string') return res.status(400).json({ error: 'Bild saknas' });
    if (!/^data:image\/(jpeg|png|webp);base64,/.test(avatar)) return res.status(400).json({ error: 'Ogiltigt format' });
    if (avatar.length > MAX_AVATAR_LEN) return res.status(400).json({ error: 'Bilden är för stor' });
    await run('UPDATE users SET avatar = ? WHERE id = ?', [avatar, req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/users/me/avatar', auth, async (req, res) => {
  try {
    await run('UPDATE users SET avatar = NULL WHERE id = ?', [req.user.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// TOURNAMENT DATA ENDPOINT
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/tournament', (req, res) => {
  res.json({
    groups: GROUPS,
    allTeams: ALL_TEAMS,
    groupMatches: GROUP_MATCHES,
    r32Matches: R32_MATCHES,
    r16Matches: R16_MATCHES,
    qfMatches: QF_MATCHES,
    sfMatches: SF_MATCHES,
    bronzeMatch: BRONZE_MATCH,
    finalMatch: FINAL_MATCH,
    scoring: SCORING
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// SETTINGS
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/settings', async (req, res) => {
  try {
    const rows = await all('SELECT key, value FROM settings');
    const s = {}; rows.forEach(r => { s[r.key] = r.value; });
    res.json(s);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// PREDICTIONS
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/predictions', auth, async (req, res) => {
  try {
    const row = await get('SELECT data FROM predictions WHERE user_id = ?', [req.user.id]);
    res.json(row ? row.data : {});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/predictions', auth, async (req, res) => {
  try {
    const settings = {};
    (await all('SELECT key, value FROM settings')).forEach(r => { settings[r.key] = r.value; });
    if (settings.locked === '1') return res.status(403).json({ error: 'Tipset är låst' });
    if (new Date(settings.deadline) < new Date()) return res.status(403).json({ error: 'Deadline har passerat' });
    const { data, submit } = req.body;
    const existing = await get('SELECT id, submitted_at FROM predictions WHERE user_id = ?', [req.user.id]);
    if (existing) {
      if (submit && !existing.submitted_at) {
        await run('UPDATE predictions SET data = ?, updated_at = NOW(), submitted_at = NOW() WHERE user_id = ?',
          [JSON.stringify(data), req.user.id]);
      } else {
        await run('UPDATE predictions SET data = ?, updated_at = NOW() WHERE user_id = ?',
          [JSON.stringify(data), req.user.id]);
      }
    } else {
      await run(`INSERT INTO predictions (user_id, data, submitted_at) VALUES (?, ?, ${submit ? 'NOW()' : 'NULL'})`,
        [req.user.id, JSON.stringify(data)]);
    }
    res.json({ ok: true, submitted: submit ? true : undefined });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// RESULTS & SCORING
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/results', auth, async (req, res) => {
  try {
    const resRow = await get('SELECT data FROM results ORDER BY id LIMIT 1');
    const actualData = resRow ? resRow.data : {};
    const predRow = await get('SELECT data FROM predictions WHERE user_id = ?', [req.user.id]);
    const predData = predRow ? predRow.data : {};
    const allPreds = await all('SELECT data FROM predictions');
    const consensusMap = buildConsensusMap(allPreds.map(p => p.data));
    const scoreable = buildScoreablePrediction(predData);
    const scoreableActual = buildScoreableResults(actualData);
    const score = computeScore(scoreable, scoreableActual, consensusMap);
    res.json({ actual: actualData, prediction: predData, score, consensusMap });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// LEADERBOARD
// ══════════════════════════════════════════════════════════════════════════════

async function calcLeaderboard() {
  const users = await all('SELECT id, name, avatar FROM users WHERE approved = 1 ORDER BY created_at');
  const preds = await all('SELECT user_id, data FROM predictions');
  const resRow = await get('SELECT data FROM results ORDER BY id LIMIT 1');
  const actualData = resRow ? resRow.data : {};
  const scoreableActual = buildScoreableResults(actualData);

  const predMap = {};
  preds.forEach(p => { predMap[p.user_id] = p.data; });

  const consensusMap = buildConsensusMap(preds.map(p => p.data));

  const board = users.map(u => {
    const predData = predMap[u.id] || {};
    const scoreable = buildScoreablePrediction(predData);
    const score = computeScore(scoreable, scoreableActual, consensusMap);
    return { name: u.name, avatar: u.avatar, points: score.total, breakdown: score.breakdown };
  });
  board.sort((a, b) => b.points - a.points);
  return board;
}

app.get('/api/leaderboard', async (req, res) => {
  try {
    const board = await calcLeaderboard();
    const snap = await get('SELECT data FROM leaderboard_snapshots ORDER BY created_at DESC LIMIT 1');
    const prevSnapshot = snap ? (typeof snap.data === 'string' ? JSON.parse(snap.data) : snap.data) : null;
    res.json({ board, prevSnapshot });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ALL PREDICTIONS (visible after lock)
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/allPredictions', auth, async (req, res) => {
  try {
    const locked = await get("SELECT value FROM settings WHERE key='locked'");
    const deadline = await get("SELECT value FROM settings WHERE key='deadline'");
    const isLocked = locked?.value === '1' || new Date(deadline?.value) < new Date();
    if (!isLocked) return res.status(403).json({ error: 'Inte låst ännu' });
    const users = await all('SELECT id, name, avatar FROM users ORDER BY name');
    const preds = await all('SELECT user_id, data FROM predictions');
    const predMap = {};
    preds.forEach(p => { predMap[p.user_id] = p.data; });
    const participants = users.map(u => ({ name: u.name, avatar: u.avatar, data: predMap[u.id] || {} }));
    res.json({ participants });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// PROJECTION
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/projection', auth, async (req, res) => {
  try {
    const locked = await get("SELECT value FROM settings WHERE key='locked'");
    const deadline = await get("SELECT value FROM settings WHERE key='deadline'");
    const isLocked = locked?.value === '1' || new Date(deadline?.value) < new Date();
    if (!isLocked) return res.status(403).json({ error: 'Inte låst ännu' });
    const resRow = await get('SELECT data FROM results ORDER BY id LIMIT 1');
    const users = await all('SELECT id, name FROM users ORDER BY name');
    const preds = await all('SELECT user_id, data FROM predictions');
    const predMap = {};
    preds.forEach(p => { predMap[p.user_id] = p.data; });
    const participants = users.map(u => ({
      name: u.name,
      data: predMap[u.id] || {}
    }));
    res.json({ actual: resRow ? resRow.data : {}, participants, scoring: SCORING });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// SIDEBETS
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/sidebets', auth, async (req, res) => {
  try {
    await run("DELETE FROM sidebets WHERE status = 'open' AND expires_at IS NOT NULL AND expires_at < NOW()");
    const rows = await all(`
      SELECT s.id, s.title, s.stake, s.status, s.created_at, s.expires_at,
        s.creator_id, uc.name AS creator_name, uc.avatar AS creator_avatar,
        s.acceptor_id, ua.name AS acceptor_name, ua.avatar AS acceptor_avatar,
        s.winner_id, uw.name AS winner_name, uw.avatar AS winner_avatar,
        s.comment
      FROM sidebets s
      JOIN users uc ON uc.id = s.creator_id
      LEFT JOIN users ua ON ua.id = s.acceptor_id
      LEFT JOIN users uw ON uw.id = s.winner_id
      ORDER BY s.created_at DESC
    `);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sidebets', auth, async (req, res) => {
  try {
    const { title, stake, expires_at } = req.body;
    if (!title || !stake || stake < 1) return res.status(400).json({ error: 'Titel och insats krävs' });
    await run('INSERT INTO sidebets (title, stake, creator_id, expires_at) VALUES (?, ?, ?, ?)',
      [title.trim(), parseInt(stake), req.user.id, expires_at || null]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sidebets/:id/accept', auth, async (req, res) => {
  try {
    const bet = await get('SELECT * FROM sidebets WHERE id = ?', [req.params.id]);
    if (!bet) return res.status(404).json({ error: 'Bet ej hittat' });
    if (bet.status !== 'open') return res.status(400).json({ error: 'Inte öppet' });
    if (bet.creator_id === req.user.id) return res.status(400).json({ error: 'Kan inte acceptera eget bet' });
    await run("UPDATE sidebets SET acceptor_id = ?, status = 'matched' WHERE id = ?", [req.user.id, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sidebets/:id/withdraw', auth, async (req, res) => {
  try {
    const bet = await get('SELECT * FROM sidebets WHERE id = ?', [req.params.id]);
    if (!bet) return res.status(404).json({ error: 'Bet ej hittat' });
    if (bet.creator_id !== req.user.id) return res.status(403).json({ error: 'Inte ditt bet' });
    if (bet.status !== 'open') return res.status(400).json({ error: 'Kan bara ta tillbaka öppna' });
    await run('DELETE FROM sidebets WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/sidebets/:id/settle', auth, async (req, res) => {
  try {
    const { winner_id, comment } = req.body;
    const bet = await get('SELECT * FROM sidebets WHERE id = ?', [req.params.id]);
    if (!bet) return res.status(404).json({ error: 'Bet ej hittat' });
    if (bet.creator_id !== req.user.id) return res.status(403).json({ error: 'Bara skaparen kan rätta' });
    if (bet.status !== 'matched') return res.status(400).json({ error: 'Inte matchat' });
    await run("UPDATE sidebets SET winner_id = ?, comment = ?, status = 'settled' WHERE id = ?",
      [winner_id, comment || null, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/results', adminAuth, async (req, res) => {
  try {
    const row = await get('SELECT data FROM results ORDER BY id LIMIT 1');
    res.json(row ? row.data : {});
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/results', adminAuth, async (req, res) => {
  try {
    const { data } = req.body;
    await run('UPDATE results SET data = ?, updated_at = NOW() WHERE id = (SELECT id FROM results ORDER BY id LIMIT 1)',
      [JSON.stringify(data)]);
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
  try {
    const users = await all('SELECT u.id, u.name, u.email, u.is_admin, u.approved, u.created_at, p.submitted_at FROM users u LEFT JOIN predictions p ON p.user_id = u.id ORDER BY u.created_at');
    res.json(users);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/pending', adminAuth, async (req, res) => {
  try {
    const users = await all(`SELECT u.id, u.name, u.email, u.created_at, p.submitted_at FROM users u JOIN predictions p ON p.user_id = u.id WHERE u.approved = 0 AND p.submitted_at IS NOT NULL ORDER BY p.submitted_at`);
    res.json(users);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/users/:id/approve', adminAuth, async (req, res) => {
  try {
    await run('UPDATE users SET approved = 1 WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const { name, email, password, is_admin } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Alla fält krävs' });
    const existing = await get('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) return res.status(400).json({ error: 'E-post redan registrerad' });
    const hash = bcrypt.hashSync(password, 10);
    await run('INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, ?)', [name, email, hash, is_admin ? 1 : 0]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/admin/users/:id/toggle-admin', adminAuth, async (req, res) => {
  try {
    const user = await get('SELECT id, is_admin FROM users WHERE id = ?', [req.params.id]);
    if (!user) return res.status(404).json({ error: 'Ej hittad' });
    await run('UPDATE users SET is_admin = ? WHERE id = ?', [user.is_admin ? 0 : 1, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    if (req.params.id == req.user.id) return res.status(400).json({ error: 'Kan inte ta bort dig själv' });
    await run('DELETE FROM predictions WHERE user_id = ?', [req.params.id]);
    await run('DELETE FROM users WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
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

app.post('/api/admin/sidebets/:id/winner', adminAuth, async (req, res) => {
  try {
    const { winner_id, comment } = req.body;
    const bet = await get('SELECT * FROM sidebets WHERE id = ?', [req.params.id]);
    if (!bet) return res.status(404).json({ error: 'Ej hittat' });
    if (bet.status !== 'matched') return res.status(400).json({ error: 'Inte matchat' });
    await run("UPDATE sidebets SET winner_id = ?, comment = ?, status = 'settled' WHERE id = ?",
      [winner_id, comment || null, req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// ADMIN EXPORT (full backup of users, predictions, results, settings)
// Read-only. Returns a JSON snapshot sufficient to recompute the leaderboard
// manually if the app or database is lost.
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/export', adminAuth, async (req, res) => {
  try {
    const settingsRows = await all('SELECT key, value FROM settings');
    const settings = {};
    settingsRows.forEach(r => { settings[r.key] = r.value; });

    const resultsRow = await get('SELECT data, updated_at FROM results ORDER BY id LIMIT 1');
    const actualResults = resultsRow ? resultsRow.data : {};

    const users = await all(`
      SELECT u.id, u.name, u.email, u.is_admin, u.approved, u.created_at,
             p.data AS prediction, p.submitted_at, p.updated_at AS prediction_updated_at
      FROM users u
      LEFT JOIN predictions p ON p.user_id = u.id
      WHERE u.approved = 1
      ORDER BY u.created_at
    `);

    const payload = {
      exported_at: new Date().toISOString(),
      exported_by: req.user.name,
      note: 'Komplett backup av godkända användare, deras tips, faktiska resultat, inställningar och poängregler. Kan användas för att rättna manuellt om appen kraschar.',
      scoring_rules: SCORING,
      settings,
      actual_results: actualResults,
      users: users.map(u => ({
        id: u.id,
        name: u.name,
        email: u.email,
        is_admin: !!u.is_admin,
        approved: !!u.approved,
        created_at: u.created_at,
        submitted_at: u.submitted_at,
        prediction_updated_at: u.prediction_updated_at,
        prediction: u.prediction || null
      }))
    };

    const filename = `vm-bettet-export-${new Date().toISOString().slice(0,10)}.json`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.send(JSON.stringify(payload, null, 2));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════════
// CONSENSUS (match tip distribution -- requires login)
// ══════════════════════════════════════════════════════════════════════════════

app.get('/api/consensus', auth, async (req, res) => {
  try {
    const locked = await get("SELECT value FROM settings WHERE key='locked'");
    const deadline = await get("SELECT value FROM settings WHERE key='deadline'");
    const isLocked = locked?.value === '1' || new Date(deadline?.value) < new Date();
    if (!isLocked) return res.status(403).json({ error: 'Inte låst ännu' });
    const preds = await all('SELECT data FROM predictions');
    const total = preds.length;
    const consensusMap = buildConsensusMap(preds.map(p => p.data));
    res.json({ consensusMap, total });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// SPA fallback
app.get('/{*splat}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

(async () => {
  await initDb();
  app.listen(PORT, () => console.log(`VM-Bettet running on http://localhost:${PORT}`));
})();

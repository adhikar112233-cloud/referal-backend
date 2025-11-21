// index.js
require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(bodyParser.json());

// init firebase-admin with service account (JSON string in env)
if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON || !process.env.FIREBASE_DATABASE_URL) {
  console.error("Missing FIREBASE_SERVICE_ACCOUNT_JSON or FIREBASE_DATABASE_URL");
  process.exit(1);
}

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.database();

// simple admin UIDs list (comma separated) or use custom claims
const ADMIN_UIDS = (process.env.ADMIN_UIDS || "").split(',').filter(Boolean);

// helper: verify firebase id token middleware
async function verifyToken(req, res, next) {
  const auth = req.headers.authorization || '';
  const match = auth.match(/^Bearer (.+)$/);
  if (!match) return res.status(401).json({ error: 'Missing Authorization header' });
  const idToken = match[1];
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verify error', err);
    res.status(401).json({ error: 'Invalid ID token' });
  }
}

// helper: admin check
function requireAdmin(req, res, next) {
  const uid = req.user?.uid;
  if (!uid) return res.status(403).json({ error: 'Not authenticated' });
  if (ADMIN_UIDS.includes(uid) || req.user.admin === true || req.user.isAdmin === true) {
    return next();
  }
  // fallback: check custom claim
  if (req.user.admin === true) return next();
  return res.status(403).json({ error: 'Admin only' });
}

// generate human-friendly referral code
function makeReferralCode(uid) {
  const hash = crypto.createHash('sha1').update(uid + Date.now().toString()).digest('hex').slice(0,6).toUpperCase();
  return `${uid.slice(0,3).toUpperCase()}-${hash}`;
}

// PUBLIC: generate a referral code for currently authenticated user (idempotent)
app.post('/generateReferral', verifyToken, async (req, res) => {
  const uid = req.user.uid;
  const userRef = db.ref(`/users/${uid}`);

  const snapshot = await userRef.once('value');
  if (snapshot.exists()) {
    const data = snapshot.val();
    if (data.referralCode) return res.json({ referralCode: data.referralCode });
  }

  const newCode = makeReferralCode(uid);
  await userRef.update({
    referralCode: newCode,
    updatedAt: Date.now()
  });
  res.json({ referralCode: newCode });
});

// PUBLIC: get referral info by code (for client to preview)
app.get('/referral/:code', async (req, res) => {
  const code = req.params.code;
  // find user with this referral code
  const usersSnap = await db.ref('/users').orderByChild('referralCode').equalTo(code).limitToFirst(1).once('value');
  if (!usersSnap.exists()) return res.status(404).json({ error: 'Referral code not found' });
  const users = usersSnap.val();
  const uid = Object.keys(users)[0];
  const user = users[uid];
  res.json({ uid, displayName: user.displayName || null });
});

// This endpoint is called by your registration flow when a new user completes registration.
// Body: { newUid, usedReferralCode }   <-- server will verify and award
app.post('/applyReferral', verifyToken, async (req, res) => {
  // Ensure newUid matches token uid (security)
  const newUid = req.body.newUid;
  const usedCode = req.body.usedReferralCode;
  const tokenUid = req.user.uid;
  if (!newUid || newUid !== tokenUid) return res.status(400).json({ error: 'Bad newUid' });
  if (!usedCode) return res.status(400).json({ error: 'Missing usedReferralCode' });

  const newUserRef = db.ref(`/users/${newUid}`);
  const newUserSnap = await newUserRef.once('value');
  const newUserData = newUserSnap.exists() ? newUserSnap.val() : {};

  // already applied? avoid double award
  if (newUserData.referralAppliedAt) {
    return res.status(409).json({ error: 'Referral already applied' });
  }

  // find referrer
  const refSnap = await db.ref('/users').orderByChild('referralCode').equalTo(usedCode).limitToFirst(1).once('value');
  if (!refSnap.exists()) return res.status(404).json({ error: 'Referral code not found' });

  const refObj = refSnap.val();
  const referrerUid = Object.keys(refObj)[0];
  if (referrerUid === newUid) {
    return res.status(400).json({ error: 'Cannot use your own code' });
  }

  // load admin settings for coins
  const settingsSnap = await db.ref('/admin/settings/referral').once('value');
  const settings = settingsSnap.exists() ? settingsSnap.val() : {};
  const referrerCoins = Number(settings.referrerCoins || process.env.DEFAULT_REFERRER_COINS || 50);
  const referredCoins = Number(settings.referredCoins || process.env.DEFAULT_REFERRED_COINS || 20);

  const now = Date.now();

  // transactionally update both users and write referral audit record
  // Use transactions to be safe from race conditions
  const updates = {};
  // update new user
  updates[`/users/${newUid}/referredBy`] = usedCode;
  updates[`/users/${newUid}/referralAppliedAt`] = now;
  updates[`/users/${newUid}/coins`] = (newUserData.coins || 0) + referredCoins;
  updates[`/users/${newUid}/updatedAt`] = now;

  // update referrer coins (read existing)
  const referrerUser = refObj[referrerUid];
  const currentReferrerCoins = Number(referrerUser.coins || 0);
  updates[`/users/${referrerUid}/coins`] = currentReferrerCoins + referrerCoins;
  updates[`/users/${referrerUid}/updatedAt`] = now;

  // add audit record
  const referralId = uuidv4();
  updates[`/referrals/${referralId}`] = {
    id: referralId,
    referrerUid,
    referredUid: newUid,
    referrerCode: usedCode,
    referredCode: newUserData.referralCode || null,
    awarded: true,
    referrerCoins,
    referredCoins,
    createdAt: now
  };

  await db.ref().update(updates);

  return res.json({
    success: true,
    awarded: { referrerUid, referrerCoins, referredCoins }
  });
});

// ADMIN: list referrals (with pagination-ish basic)
app.get('/admin/referrals', verifyToken, requireAdmin, async (req, res) => {
  // optional ?limit=50
  const limit = Math.min(200, Number(req.query.limit || 100));
  const snap = await db.ref('/referrals').orderByChild('createdAt').limitToLast(limit).once('value');
  const data = snap.exists() ? snap.val() : {};
  res.json({ data });
});

// ADMIN: edit referral audit (rare) or edit user coins
// patch body: { type: 'user'|'referral', id: '<uid or referralId>', changes: {...} }
app.patch('/admin/edit', verifyToken, requireAdmin, async (req, res) => {
  const { type, id, changes } = req.body;
  if (!type || !id || !changes) return res.status(400).json({ error: 'Bad request' });

  if (type === 'user') {
    await db.ref(`/users/${id}`).update({ ...changes, updatedAt: Date.now() });
    return res.json({ success: true });
  } else if (type === 'referral') {
    await db.ref(`/referrals/${id}`).update({ ...changes, updatedAt: Date.now() });
    return res.json({ success: true });
  } else {
    return res.status(400).json({ error: 'unknown type' });
  }
});

// ADMIN: update referral settings
app.post('/admin/settings/referral', verifyToken, requireAdmin, async (req, res) => {
  const { referrerCoins, referredCoins, requireCompleteProfile } = req.body;
  const updates = {};
  if (typeof referrerCoins !== 'undefined') updates.referrerCoins = Number(referrerCoins);
  if (typeof referredCoins !== 'undefined') updates.referredCoins = Number(referredCoins);
  if (typeof requireCompleteProfile !== 'undefined') updates.requireCompleteProfile = !!requireCompleteProfile;
  await db.ref('/admin/settings/referral').update(updates);
  res.json({ success: true, saved: updates });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Referral backend listening on ${PORT}`);
});

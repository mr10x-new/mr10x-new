import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { randomUUID, randomInt, randomBytes, createHash, pbkdf2Sync, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import db from './db.js';
import { pollAll } from './poller.js';
import { encryptPassword, decryptPassword } from './crypto-utils.js';
import { extractCode } from './extract.js';
import {
  gmailEnabled, makeOAuthState, parseOAuthState,
  getAuthUrl, exchangeCode, getGmailAddress,
  pollGmailMailboxes
} from './gmail.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORS_ORIGIN = process.env.CORS_ORIGIN;
const app = express();
app.set('trust proxy', 1);
if (CORS_ORIGIN) { app.use(cors({ origin: CORS_ORIGIN })); }
app.use(express.json({ limit: '64kb' }));
app.use('/api/inbound', express.text({ limit: '64kb' }));
app.use('/api/inbound', express.urlencoded({ extended: false, limit: '64kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'");
  next();
});

// ─── Helpers ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

// In-memory rate limiter — resets on restart (acceptable for Railway)
const rateLimitMap = new Map();
function rateLimit(key, maxRequests, windowMs) {
  const now = Date.now();
  const entry = rateLimitMap.get(key) || { count: 0, resetAt: now + windowMs };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + windowMs; }
  entry.count++;
  rateLimitMap.set(key, entry);
  return entry.count <= maxRequests;
}

function generateSalt() { return randomBytes(16).toString('hex'); }

function hashPw(password, salt) {
  const SECRET = process.env.SECRET || '';
  return pbkdf2Sync(`${password}${SECRET}`, salt, 100_000, 32, 'sha256').toString('hex');
}

function pwMatch(plain, hash, salt) {
  const candidate = Buffer.from(hashPw(plain, salt), 'hex');
  const stored    = Buffer.from(hash, 'hex');
  if (candidate.length !== stored.length) return false;
  return timingSafeEqual(candidate, stored);
}

// ─── Auth middleware ───────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = header.slice(7);
  const session = db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?')
    .get(token, Math.floor(Date.now() / 1000));
  if (!session) return res.status(401).json({ error: 'Session expired or invalid' });
  const seller = db.prepare('SELECT * FROM sellers WHERE id = ?').get(session.seller_id);
  if (!seller || seller.status !== 'active') return res.status(403).json({ error: 'Account not active' });
  req.seller = seller;
  next();
}

function adminMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = header.slice(7);
  const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
  if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ─── Health check ─────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true }));

// ─── Admin Login ──────────────────────────────────────────────────────────────
app.post('/api/admin/login', (req, res) => {
  const ip = req.ip;
  if (!rateLimit(`admin-login:${ip}`, 5, 15 * 60_000)) {
    return res.status(429).json({ error: 'Too many attempts, try again later' });
  }
  const { token } = req.body || {};
  const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
  if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) {
    return res.status(403).json({ error: 'Invalid admin token' });
  }
  res.json({ ok: true, token: ADMIN_TOKEN });
});

// ─── Register ─────────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const ip = req.ip;
  if (!rateLimit(`register:${ip}`, 10, 15 * 60_000)) {
    return res.status(429).json({ error: 'Too many attempts, try again later' });
  }
  const { name, email, phone, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email, password required' });
  if (password.length < 8) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل' });

  const normalizedEmail = email.toLowerCase().trim();
  const existing = db.prepare('SELECT id FROM sellers WHERE email = ?').get(normalizedEmail);
  if (existing) return res.status(409).json({ error: 'البريد الإلكتروني مسجّل مسبقاً' });

  const salt = generateSalt();
  const hash = hashPw(password, salt);
  const id   = randomUUID();
  const verifyToken = randomBytes(32).toString('hex');
  const verifyExpiry = Math.floor(Date.now() / 1000) + 24 * 3600;

  db.prepare(`INSERT INTO sellers (id, name, email, phone, password, salt, status, verify_token, verify_token_expires_at)
    VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`)
    .run(id, name, normalizedEmail, phone || '', hash, salt, verifyToken, verifyExpiry);

  // Send verification email
  const BASE_URL = process.env.BASE_URL || 'https://mr10x.co';
  const verifyUrl = `${BASE_URL}/verify-email.html?token=${verifyToken}`;
  try {
    await sendEmail({
      to: normalizedEmail,
      subject: 'تأكيد بريدك الإلكتروني — Mr10x',
      html: `
        <div dir="rtl" style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
          <h2 style="color:#6C63FF">مرحباً ${name}!</h2>
          <p>شكراً لتسجيلك في Mr10x. لتفعيل حسابك، يرجى الضغط على الرابط أدناه:</p>
          <a href="${verifyUrl}" style="display:inline-block;padding:12px 24px;background:#6C63FF;color:#fff;text-decoration:none;border-radius:8px;margin:16px 0">
            تأكيد البريد الإلكتروني
          </a>
          <p style="color:#666;font-size:14px">الرابط صالح لمدة 24 ساعة.</p>
          <p style="color:#666;font-size:12px">إذا لم تقم بالتسجيل، يمكنك تجاهل هذا الإيميل.</p>
        </div>`
    });
  } catch (err) {
    console.error('[Register] Email send failed:', err.message);
  }

  res.json({ ok: true, message: 'تم التسجيل بنجاح. تحقق من بريدك الإلكتروني لتأكيد الحساب.' });
});

// ─── Verify Email ─────────────────────────────────────────────────────────────
app.post('/api/verify-email', (req, res) => {
  const ip = req.ip;
  if (!rateLimit(`verify-email:${ip}`, 10, 15 * 60_000)) {
    return res.status(429).json({ error: 'Too many attempts, try again later' });
  }
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token required' });

  const seller = db.prepare('SELECT * FROM sellers WHERE verify_token = ? AND verify_token_expires_at > ?')
    .get(token, Math.floor(Date.now() / 1000));

  if (!seller) return res.status(400).json({ error: 'الرابط غير صالح أو منتهي الصلاحية' });

  db.prepare('UPDATE sellers SET status = ?, verify_token = NULL, verify_token_expires_at = NULL WHERE id = ?')
    .run('pending_approval', seller.id);

  res.json({ ok: true, message: 'تم تأكيد بريدك الإلكتروني. سيتم مراجعة حسابك من قِبل الإدارة.' });
});

// ─── Login ────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (!rateLimit(`login:${ip}`, 10, 15 * 60_000)) {
    return res.status(429).json({ error: 'Too many attempts, try again later' });
  }
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const seller = db.prepare('SELECT * FROM sellers WHERE email = ?').get(email.toLowerCase().trim());
  if (!seller) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  if (!pwMatch(password, seller.password, seller.salt)) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });

  if (seller.status === 'pending') return res.status(403).json({ error: 'pending_verification', message: 'يرجى تأكيد بريدك الإلكتروني أولاً' });
  if (seller.status === 'pending_approval') return res.status(403).json({ error: 'pending_approval', message: 'حسابك قيد المراجعة من قِبل الإدارة' });
  if (seller.status === 'rejected') return res.status(403).json({ error: 'rejected', message: 'تم رفض طلب حسابك' });
  if (seller.status !== 'active') return res.status(403).json({ error: 'Account not active' });

  // Check subscription expiry
  const now = Math.floor(Date.now() / 1000);
  if (seller.subscription_expires_at && seller.subscription_expires_at < now) {
    return res.status(403).json({ error: 'subscription_expired', message: 'انتهت صلاحية اشتراكك. يرجى التواصل مع الدعم لتجديد الاشتراك.' });
  }

  const token = randomBytes(32).toString('hex');
  const expiresAt = now + 30 * 24 * 3600; // 30 days
  db.prepare('INSERT INTO sessions (token, seller_id, expires_at) VALUES (?, ?, ?)').run(token, seller.id, expiresAt);

  res.json({ ok: true, token, name: seller.name, email: seller.email });
});

// ─── Forgot Password ──────────────────────────────────────────────────────────
app.post('/api/forgot-password', async (req, res) => {
  const ip = req.ip;
  if (!rateLimit(`forgot-password:${ip}`, 5, 10 * 60_000)) {
    return res.status(429).json({ error: 'Too many attempts, try again later' });
  }
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email required' });

  const seller = db.prepare('SELECT * FROM sellers WHERE email = ?').get(email.toLowerCase().trim());
  // Always return success to prevent email enumeration
  if (!seller) return res.json({ ok: true, message: 'إذا كان البريد مسجّلاً، ستصل رسالة استعادة كلمة المرور' });

  const rawToken   = randomBytes(32).toString('hex');
  const tokenHash  = createHash('sha256').update(rawToken).digest('hex');
  const expiresAt  = Math.floor(Date.now() / 1000) + 3600; // 1 hour

  db.prepare('DELETE FROM password_resets WHERE email = ?').run(seller.email);
  db.prepare('INSERT INTO password_resets (token, email, expires_at, used) VALUES (?, ?, ?, 0)')
    .run(tokenHash, seller.email, expiresAt);

  const BASE_URL  = process.env.BASE_URL || 'https://mr10x.co';
  const resetUrl  = `${BASE_URL}/reset-password.html?token=${rawToken}`;
  try {
    await sendEmail({
      to: seller.email,
      subject: 'استعادة كلمة المرور — Mr10x',
      html: `
        <div dir="rtl" style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
          <h2 style="color:#6C63FF">استعادة كلمة المرور</h2>
          <p>تلقّينا طلباً لإعادة تعيين كلمة مرور حسابك.</p>
          <a href="${resetUrl}" style="display:inline-block;padding:12px 24px;background:#6C63FF;color:#fff;text-decoration:none;border-radius:8px;margin:16px 0">
            إعادة تعيين كلمة المرور
          </a>
          <p style="color:#666;font-size:14px">الرابط صالح لمدة ساعة واحدة فقط.</p>
          <p style="color:#666;font-size:12px">إذا لم تطلب ذلك، يمكنك تجاهل هذا الإيميل.</p>
        </div>`
    });
  } catch (err) {
    console.error('[ForgotPw] Email send failed:', err.message);
  }

  res.json({ ok: true, message: 'إذا كان البريد مسجّلاً، ستصل رسالة استعادة كلمة المرور' });
});

// ─── Reset Password ───────────────────────────────────────────────────────────
app.post('/api/reset-password', (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'token and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل' });

  // F-06: hash the incoming raw token before comparing against stored hash
  const tokenHash = createHash('sha256').update(token).digest('hex');
  const record = db.prepare('SELECT * FROM password_resets WHERE token = ? AND used = 0 AND expires_at > ?')
    .get(tokenHash, Math.floor(Date.now() / 1000));

  if (!record) return res.status(400).json({ error: 'الرابط غير صالح أو منتهي الصلاحية' });

  const newSalt = generateSalt();
  const newHash = hashPw(password, newSalt);
  db.prepare('UPDATE sellers SET password = ?, salt = ? WHERE email = ?')
    .run(newHash, newSalt, record.email);
  db.prepare('UPDATE password_resets SET used = 1 WHERE token = ?')
    .run(tokenHash);

  res.json({ ok: true });
});

// GET /api/me — بيانات الحساب الحالي
app.get('/api/me', authMiddleware, (req, res) => {
  const seller = db.prepare('SELECT id, name, email, phone, status, subscription_expires_at, plan_type FROM sellers WHERE id = ?').get(req.seller.id);
  const now = Math.floor(Date.now() / 1000);
  let subscription_days_left;
  if (!seller.subscription_expires_at) {
    subscription_days_left = null;
  } else if (seller.subscription_expires_at > now) {
    subscription_days_left = Math.ceil((seller.subscription_expires_at - now) / 86400);
  } else {
    subscription_days_left = 0;
  }
  const planNames = { plan1: 'أساسية', plan2: 'احترافية', plan3: 'متقدمة' };
  res.json({ ...seller, subscription_days_left, plan: seller.plan_type });
});

// ─── Admin API ────────────────────────────────────────────────────────────────
app.get('/api/admin/sellers', adminMiddleware, (req, res) => {
  const sellers = db.prepare('SELECT id, name, email, phone, status, created_at, subscription_expires_at, plan_type FROM sellers ORDER BY created_at DESC').all();
  res.json(sellers);
});

app.patch('/api/admin/sellers/:id/approve', adminMiddleware, (req, res) => {
  db.prepare('UPDATE sellers SET status = ? WHERE id = ?').run('active', req.params.id);
  res.json({ ok: true });
});

app.patch('/api/admin/sellers/:id/reject', adminMiddleware, (req, res) => {
  db.prepare('UPDATE sellers SET status = ? WHERE id = ?').run('rejected', req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/sellers/:id', adminMiddleware, (req, res) => {
  db.prepare('DELETE FROM sellers WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.patch('/api/admin/sellers/:id/subscription', adminMiddleware, (req, res) => {
  const { expires_at } = req.body || {};
  let ts = null;
  if (expires_at) {
    const parsed = new Date(expires_at).getTime();
    if (isNaN(parsed)) return res.status(400).json({ error: 'expires_at تاريخ غير صالح' });
    ts = Math.floor(parsed / 1000);
  }
  db.prepare('UPDATE sellers SET subscription_expires_at = ? WHERE id = ?').run(ts, req.params.id);
  res.json({ ok: true });
});

app.patch('/api/admin/sellers/:id/plan', adminMiddleware, (req, res) => {
  const { plan_type } = req.body || {};
  if (!['plan1', 'plan2', 'plan3'].includes(plan_type))
    return res.status(400).json({ error: 'plan_type يجب أن يكون plan1 أو plan2 أو plan3' });
  db.prepare('UPDATE sellers SET plan_type = ? WHERE id = ?').run(plan_type, req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/stats', adminMiddleware, (req, res) => {
  const totalSellers     = db.prepare("SELECT COUNT(*) as n FROM sellers").get().n;
  const activeSellers    = db.prepare("SELECT COUNT(*) as n FROM sellers WHERE status = 'active'").get().n;
  const pendingSellers   = db.prepare("SELECT COUNT(*) as n FROM sellers WHERE status = 'pending'").get().n;
  const totalMailboxes   = db.prepare("SELECT COUNT(*) as n FROM mailboxes").get().n;
  const totalSlots       = db.prepare("SELECT COUNT(*) as n FROM slots").get().n;
  const totalCodes       = db.prepare("SELECT COUNT(*) as n FROM codes").get().n;
  const codesViewed      = db.prepare("SELECT COUNT(*) as n FROM codes WHERE viewed = 1").get().n;
  const now              = Math.floor(Date.now() / 1000);
  const activeSubs       = db.prepare("SELECT COUNT(*) as n FROM sellers WHERE subscription_expires_at IS NOT NULL AND subscription_expires_at > ?").get(now).n;
  res.json({ totalSellers, activeSellers, pendingSellers, totalMailboxes, totalSlots, totalCodes, codesViewed, activeSubs });
});

// ─── Mailboxes ─────────────────────────────────────────────────────────────────
// ─── Gmail OAuth Routes ────────────────────────────────────────────────────────

app.get('/api/auth/gmail/start', authMiddleware, (req, res) => {
  if (!gmailEnabled()) return res.status(503).json({ error: 'Gmail OAuth not configured' });
  const { mailbox_id } = req.query;
  if (!mailbox_id) return res.status(400).json({ error: 'mailbox_id required' });

  const mailbox = db.prepare('SELECT id FROM mailboxes WHERE id = ? AND seller_id = ?')
    .get(mailbox_id, req.seller.id);
  if (!mailbox) return res.status(404).json({ error: 'Mailbox not found' });

  const state = makeOAuthState(mailbox_id, req.seller.id);
  res.json({ url: getAuthUrl(state) });
});

app.get('/api/auth/gmail/callback', async (req, res) => {
  if (!gmailEnabled()) return res.status(503).send('Gmail OAuth not configured');
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(`/index.html?gmail_error=${encodeURIComponent(error)}`);
  }
  if (!code || !state) {
    return res.redirect('/index.html?gmail_error=missing_params');
  }

  const parsed = parseOAuthState(state);
  if (!parsed) {
    return res.redirect('/index.html?gmail_error=invalid_state');
  }

  const { mailboxId, sellerId } = parsed;

  const mailbox = db.prepare('SELECT id, email FROM mailboxes WHERE id = ? AND seller_id = ?')
    .get(mailboxId, sellerId);
  if (!mailbox) {
    return res.redirect('/?gmail_error=mailbox_not_found');
  }

  try {
    const tokens = await exchangeCode(code);
    const now = Math.floor(Date.now() / 1000);
    const expiry = now + (tokens.expires_in || 3600);

    let gmailEmail = null;
    try { gmailEmail = await getGmailAddress(tokens.access_token); } catch {}

    db.prepare(`
      UPDATE mailboxes
      SET gmail_refresh_token = ?, gmail_access_token = ?, gmail_token_expiry = ?,
          gmail_email = ?, gmail_last_sync_ts = ?, status = 'active', last_error = NULL
      WHERE id = ?
    `).run(
      tokens.refresh_token,
      tokens.access_token,
      expiry,
      gmailEmail || mailbox.email,
      now,
      mailboxId
    );

    res.redirect('/index.html?gmail_connected=1');
  } catch (err) {
    console.error('[Gmail OAuth] callback error:', err.message);
    res.redirect(`/index.html?gmail_error=${encodeURIComponent('فشل الاتصال بـ Gmail')}`);
  }
});

app.post('/api/mailboxes/:id/gmail-disconnect', authMiddleware, (req, res) => {
  const mailbox = db.prepare('SELECT id FROM mailboxes WHERE id = ? AND seller_id = ?')
    .get(req.params.id, req.seller.id);
  if (!mailbox) return res.status(404).json({ error: 'Mailbox not found' });

  db.prepare(`
    UPDATE mailboxes
    SET gmail_refresh_token = NULL, gmail_access_token = NULL,
        gmail_token_expiry = NULL, gmail_email = NULL, gmail_last_sync_ts = NULL,
        status = 'active'
    WHERE id = ?
  `).run(req.params.id);

  res.json({ ok: true });
});

// ─── Mailboxes ─────────────────────────────────────────────────────────────────

app.get('/api/mailboxes', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT id, email, label, status, last_sync, last_error, webhook_token,
           gmail_email,
           CASE WHEN gmail_refresh_token IS NOT NULL THEN 1 ELSE 0 END as gmail_connected
    FROM mailboxes WHERE seller_id = ?
  `).all(req.seller.id);
  res.json(rows);
});

app.post('/api/mailboxes', authMiddleware, (req, res) => {
  const { email, label } = req.body || {};
  if (!email) return res.status(400).json({ error: 'البريد الإلكتروني مطلوب' });
  const mailboxCount = db.prepare('SELECT COUNT(*) as cnt FROM mailboxes WHERE seller_id = ?').get(req.seller.id);
  if (mailboxCount.cnt >= 500) return res.status(400).json({ error: 'تعذّر إضافة صندوق البريد، يرجى التواصل مع الدعم.' });
  const id = randomUUID();
  const webhookToken = randomUUID();
  db.prepare(`INSERT INTO mailboxes (id, seller_id, email, imap_host, imap_port, password, label, status, webhook_token)
    VALUES (?, ?, ?, '', 993, '', ?, 'active', ?)`)
    .run(id, req.seller.id, email.toLowerCase().trim(), label || '', webhookToken);
  res.json({ id, email, label: label || '', status: 'active', webhook_token: webhookToken });
});

app.delete('/api/mailboxes/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM mailboxes WHERE id = ? AND seller_id = ?').run(req.params.id, req.seller.id);
  res.json({ ok: true });
});

// ─── Inbound Webhook ───────────────────────────────────────────────────────────
app.post('/api/inbound/:token', (req, res) => {
  if (!rateLimit(`inbound:${req.params.token}`, 60, 60_000)) {
    return res.status(429).json({ error: 'Too many requests' });
  }
  const mailbox = db.prepare('SELECT * FROM mailboxes WHERE webhook_token = ?').get(req.params.token);
  if (!mailbox) return res.status(404).json({ error: 'Invalid token' });

  let subject = '';
  let body = '';

  const ct = (req.headers['content-type'] || '').toLowerCase();

  if (ct.includes('application/json')) {
    const p = req.body || {};
    subject = String(p.subject || p.Subject || '');
    body = String(p.text || p.plain || p.body || p.html || '');
  } else {
    body = String(req.body?.text || req.body?.body || '');
    subject = String(req.body?.subject || '');
  }

  if (!body && typeof req.body === 'string') {
    body = req.body;
  }

  const code = extractCode(subject, body);

  if (!code) {
    console.log(`[Webhook] لا كود في إيميل لصندوق ${mailbox.email}`);
    return res.json({ ok: true, extracted: false });
  }

  const slots = db.prepare('SELECT * FROM slots WHERE mailbox_id = ?').all(mailbox.id);
  const receivedTs = Math.floor(Date.now() / 1000);

  for (const slot of slots) {
    const exists = db.prepare(
      'SELECT id FROM codes WHERE slot_id = ? AND code = ? AND received_at > ?'
    ).get(slot.id, code, receivedTs - 60);
    if (exists) continue;

    db.prepare(`
      INSERT INTO codes (id, slot_id, code, email_from, email_subj, received_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      randomUUID(), slot.id, code,
      String(req.body?.from || req.body?.sender || '').toLowerCase().slice(0, 200),
      subject.slice(0, 200),
      receivedTs,
      receivedTs + 10 * 60
    );

    console.log(`[Webhook] 🔑 كود جديد ${code} → slot ${slot.id}`);
  }

  db.prepare("UPDATE mailboxes SET last_sync = ?, status = 'active', last_error = NULL WHERE id = ?")
    .run(receivedTs, mailbox.id);

  res.json({ ok: true, extracted: true, code });
});

// ─── Slots ────────────────────────────────────────────────────────────────────
app.get('/api/slots', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT s.id, s.label, s.token, s.mailbox_id, s.created_at,
           s.account_email,
           m.email as mailbox_email,
           (SELECT code FROM codes WHERE slot_id = s.id ORDER BY received_at DESC LIMIT 1) as latest_code
    FROM slots s JOIN mailboxes m ON m.id = s.mailbox_id
    WHERE s.seller_id = ? ORDER BY s.created_at DESC`)
    .all(req.seller.id);
  res.json(rows);
});

app.post('/api/slots', authMiddleware, (req, res) => {
  const { mailbox_id, label, count = 1, account_email = '', account_password = '' } = req.body || {};
  if (!mailbox_id || !label) return res.status(400).json({ error: 'mailbox_id and label required' });
  const mailbox = db.prepare('SELECT id FROM mailboxes WHERE id = ? AND seller_id = ?').get(mailbox_id, req.seller.id);
  if (!mailbox) return res.status(404).json({ error: 'Mailbox not found' });

  const seller = db.prepare('SELECT plan_type FROM sellers WHERE id = ?').get(req.seller.id);
  const planType = seller?.plan_type || 'plan2';
  if (planType === 'plan1') {
    const existingCount = db.prepare('SELECT COUNT(*) as n FROM slots WHERE seller_id = ?').get(req.seller.id).n;
    if (existingCount >= 1)
      return res.status(403).json({ error: 'plan_limit', message: 'باقتك تسمح بتطبيق واحد فقط. يرجى الترقية للباقة الثانية أو الثالثة.' });
  }

  const created = [];
  const n = Math.min(Number(count) || 1, 10);
  const encryptedAccountPassword = account_password ? encryptPassword(account_password) : '';
  for (let i = 0; i < n; i++) {
    const id = randomUUID();
    const token = randomBytes(16).toString('hex');
    db.prepare('INSERT INTO slots (id, seller_id, mailbox_id, label, token, account_email, account_password, account_password_encrypted) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, req.seller.id, mailbox_id, label, token, account_email, encryptedAccountPassword, encryptedAccountPassword ? 1 : 0);
    created.push({ id, token, label, account_email });
  }
  res.json(created);
});

app.patch('/api/slots/:id', authMiddleware, (req, res) => {
  const { account_email, account_password, label } = req.body || {};
  const slot = db.prepare('SELECT id FROM slots WHERE id = ? AND seller_id = ?').get(req.params.id, req.seller.id);
  if (!slot) return res.status(404).json({ error: 'Slot not found' });
  if (account_email !== undefined)
    db.prepare('UPDATE slots SET account_email = ? WHERE id = ?').run(account_email, req.params.id);
  if (account_password !== undefined) {
    const enc = account_password ? encryptPassword(account_password) : '';
    db.prepare('UPDATE slots SET account_password = ?, account_password_encrypted = ? WHERE id = ?')
      .run(enc, enc ? 1 : 0, req.params.id);
  }
  if (label !== undefined)
    db.prepare('UPDATE slots SET label = ? WHERE id = ?').run(label, req.params.id);
  res.json({ ok: true });
});

app.patch('/api/slots/:id/reset', authMiddleware, (req, res) => {
  const slot = db.prepare('SELECT id FROM slots WHERE id = ? AND seller_id = ?').get(req.params.id, req.seller.id);
  if (!slot) return res.status(404).json({ error: 'Slot not found' });
  db.prepare('UPDATE slots SET code_attempts = 0 WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/slots/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM slots WHERE id = ? AND seller_id = ?').run(req.params.id, req.seller.id);
  res.json({ ok: true });
});

// ─── Customer endpoint (public) ───────────────────────────────────────────────
app.get('/api/slot/:token', (req, res) => {
  const ip = req.ip;
  if (!rateLimit(`slot:${ip}`, 10, 60_000)) {
    return res.status(429).json({ error: 'Too many requests.' });
  }
  const slot = db.prepare('SELECT * FROM slots WHERE token = ?').get(req.params.token);
  if (!slot) return res.status(404).json({ error: 'Invalid link' });
  const rawPass = slot.account_password
    ? (slot.account_password_encrypted ? decryptPassword(slot.account_password) : slot.account_password)
    : '';
  res.json({
    label: slot.label,
    account_email: slot.account_email || '',
    account_password: rawPass,
    attempts_left: Math.max(0, 2 - (slot.code_attempts || 0))
  });
});

app.get('/api/code/:token', (req, res) => {
  const ip = req.ip;
  if (!rateLimit(`code:${ip}`, 20, 60_000)) {
    return res.status(429).json({ error: 'Too many requests.' });
  }

  const slot = db.prepare('SELECT * FROM slots WHERE token = ?').get(req.params.token);
  if (!slot) return res.status(404).json({ error: 'Invalid link' });

  const rawPass = slot.account_password
    ? (slot.account_password_encrypted ? decryptPassword(slot.account_password) : slot.account_password)
    : '';
  const attempts = slot.code_attempts || 0;
  if (attempts >= 2) {
    return res.json({
      status: 'exhausted',
      label: slot.label,
      account_email: slot.account_email || '',
      account_password: rawPass
    });
  }

  const code = db.prepare(`
    SELECT code, received_at, expires_at FROM codes
    WHERE slot_id = ? AND expires_at > ?
    ORDER BY received_at DESC LIMIT 1`)
    .get(slot.id, Math.floor(Date.now() / 1000));

  if (!code) return res.json({ status: 'waiting', label: slot.label, account_email: slot.account_email || '', account_password: rawPass });

  db.prepare('UPDATE slots SET code_attempts = code_attempts + 1 WHERE id = ?').run(slot.id);
  db.prepare('UPDATE codes SET viewed = 1 WHERE slot_id = ? AND code = ?').run(slot.id, code.code);

  res.json({
    status: 'ready',
    code: code.code,
    label: slot.label,
    expires_in: code.expires_at - Math.floor(Date.now() / 1000),
    attempts_left: Math.max(0, 2 - (attempts + 1)),
    account_email: slot.account_email || '',
    account_password: rawPass
  });
});

// ─── Polling ──────────────────────────────────────────────────────────────────
pollAll();

// Gmail polling — كل 60 ثانية
if (gmailEnabled()) {
  setTimeout(() => pollGmailMailboxes(db), 10_000);
  setInterval(() => pollGmailMailboxes(db), 60_000);
  console.log('[Gmail] Polling enabled — every 60s');
} else {
  console.log('[Gmail] OAuth not configured (GOOGLE_CLIENT_ID/SECRET/REDIRECT_URI missing)');
}

app.listen(PORT, () => {
  console.log(`Mr10x OTP Backend running on port ${PORT}`);
});

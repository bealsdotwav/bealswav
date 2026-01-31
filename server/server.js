// server.js

// ─── IMPORTS & CONFIG ─────────────────────────────────────────────────────────
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { body, validationResult } = require('express-validator');
const Stripe = require('stripe');

const app = express();
const PORT = process.env.PORT || 4242;

// ─── FEATURE FLAGS (OPTION 2: DON'T DIE IF MISSING) ───────────────────────────
const HAS_DB = !!process.env.MONGODB_URI;
const HAS_EMAIL = !!process.env.SENDER_EMAIL;
const HAS_STRIPE = !!process.env.STRIPE_SECRET_KEY;

if (!HAS_DB) console.warn('⚠️  MONGODB_URI not set: auth/session routes will return 503.');
if (!HAS_EMAIL) console.warn('⚠️  SENDER_EMAIL not set: email routes will return 503.');
if (!HAS_STRIPE) console.warn('⚠️  STRIPE_SECRET_KEY not set: checkout route will return 503.');

// ─── SECURITY, CORS & RATE-LIMIT ──────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdn.jsdelivr.net",
          "https://www.googletagmanager.com",
        ],
        "script-src-attr": ["'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:"],
        connectSrc: [
          "'self'",
          "https://api.emailjs.com",
          "https://www.google-analytics.com",
          "https://www.googletagmanager.com",
        ],
        frameSrc: [
          "'self'",
          "https://www.youtube.com",
          "https://www.youtube-nocookie.com",
          "https://open.spotify.com",
          "https://player.beatstars.com",
        ],
      },
    },
    frameguard: { action: 'sameorigin' },
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);

// trust proxy if behind Render/Heroku/etc.
app.enable('trust proxy');

// only allow your front-end origins
const allowedOrigins =
  process.env.NODE_ENV === 'production'
    ? ['https://bealswav.com', 'https://www.bealswav.com']
    : ['http://localhost:4242'];

app.use(cors({ origin: allowedOrigins }));

// redirect HTTP → HTTPS in prod (Render-safe)
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production') {
    const proto = req.get('x-forwarded-proto');
    if (proto && proto !== 'https') {
      return res.redirect(`https://${req.headers.host}${req.url}`);
    }
  }
  next();
});

// rate-limit on register & contact to prevent spam
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP, please try again later.',
});
app.use('/register', apiLimiter);
app.use('/contact', apiLimiter);

// ─── BODY PARSING & STATIC ────────────────────────────────────────────────────
app.use(bodyParser.json());

// Serve files from ../public at the site root
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
app.use(express.static(PUBLIC_DIR, { extensions: ['html'] }));

const fs = require('fs');

app.get('/__debug/logo', (_req, res) => {
  const p = path.join(PUBLIC_DIR, 'assets', 'images', 'logo.jpeg');
  fs.access(p, fs.constants.R_OK, (err) => {
    if (err) {
      return res.status(404).json({ ok: false, path: p });
    }
    res.json({ ok: true, path: p });
  });
});

// ─── DATABASE (ONLY CONNECT IF CONFIGURED) ────────────────────────────────────
if (HAS_DB) {
  mongoose
    .connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .then(() => console.log('✅  MongoDB connected'))
    .catch((err) => {
      console.error('❌  MongoDB connection error:', err);
      process.exit(1); // configured but broken = fair to exit
    });
} else {
  console.warn('⚠️  Skipping MongoDB connection.');
}

// ─── USER MODEL (ONLY DEFINE IF DB ENABLED) ───────────────────────────────────
let User = null;

if (HAS_DB) {
  const userSchema = new mongoose.Schema(
    {
      email: { type: String, required: true, unique: true },
      password: { type: String, required: true },
      emailVerified: { type: Boolean, default: false },
      verifyToken: String,
      verifyTokenExpiry: Date,
      resetToken: String,
      resetTokenExpiry: Date,
      sessions: [
        {
          serviceType: String,
          dateBooked: String,
          status: String,
          details: String,
        },
      ],
    },
    { timestamps: true }
  );

  User = mongoose.model('User', userSchema);
}

// ─── STRIPE (LAZY INIT) ───────────────────────────────────────────────────────
function getStripe() {
  if (!HAS_STRIPE) {
    const err = new Error('Stripe not configured');
    err.status = 503;
    throw err;
  }
  return Stripe(process.env.STRIPE_SECRET_KEY);
}

// ─── EMAIL TRANSPORTER (ONLY IF EMAIL ENABLED) ────────────────────────────────
let transporterPromise = null;

if (HAS_EMAIL) {
  transporterPromise = (async () => {
    if (process.env.ZOHO_SMTP_USER && process.env.ZOHO_SMTP_PASS) {
      return nodemailer.createTransport({
        host: 'smtp.zoho.com',
        port: 465,
        secure: true,
        auth: {
          user: process.env.ZOHO_SMTP_USER,
          pass: process.env.ZOHO_SMTP_PASS,
        },
      });
    }

    // Dev fallback: Ethereal
    const testAcct = await nodemailer.createTestAccount();
    console.log('ℹ️  Ethereal SMTP account:', testAcct.user);
    return nodemailer.createTransport({
      host: testAcct.smtp.host,
      port: testAcct.smtp.port,
      secure: testAcct.smtp.secure,
      auth: { user: testAcct.user, pass: testAcct.pass },
    });
  })();

  transporterPromise.then((transporter) => {
    transporter.verify((err) => {
      if (err) console.error('❌ SMTP connect error:', err);
      else console.log('✅ SMTP ready to send');
    });
  });
}

// ─── EMAIL SENDER HELPER ──────────────────────────────────────────────────────
async function sendEmail(options) {
  if (!HAS_EMAIL || !transporterPromise) {
    const err = new Error('Email not configured');
    err.status = 503;
    throw err;
  }

  const transporter = await transporterPromise;
  const info = await transporter.sendMail({
    from: process.env.SENDER_EMAIL,
    ...options,
  });

  console.log('✉️  Sent:', info.messageId);
  return info;
}

// ─── GUARDS (RETURN 503 INSTEAD OF CRASHING) ──────────────────────────────────
function requireDb(_req, res, next) {
  if (!HAS_DB || !User) return res.status(503).json({ message: 'Service unavailable (DB not configured).' });
  next();
}

function requireEmail(_req, res, next) {
  if (!HAS_EMAIL) return res.status(503).json({ message: 'Service unavailable (Email not configured).' });
  next();
}

function requireStripe(_req, res, next) {
  if (!HAS_STRIPE) return res.status(503).json({ message: 'Service unavailable (Payments not configured).' });
  next();
}

// ─── ROUTES ───────────────────────────────────────────────────────────────────

// Home page
app.get('/', (_req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

// — REGISTER —
app.post(
  '/register',
  requireDb,
  requireEmail,
  [body('email').isEmail().normalizeEmail(), body('password').isLength({ min: 8 })],
  async (req, res, next) => {
    try {
      const errs = validationResult(req);
      if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });

      const { email, password } = req.body;

      if (await User.findOne({ email })) {
        return res.status(400).json({ message: 'Email already registered.' });
      }

      const hashed = await bcrypt.hash(password, 12);
      const token = crypto.randomBytes(32).toString('hex');

      await new User({
        email,
        password: hashed,
        verifyToken: token,
        verifyTokenExpiry: Date.now() + 24 * 60 * 60 * 1000,
      }).save();

      const verifyUrl = `${req.protocol}://${req.get('host')}/verify-email?token=${token}`;
      await sendEmail({
        to: email,
        subject: 'Verify your Beals.wav account',
        html: `<p>Click to verify your account: <a href="${verifyUrl}">${verifyUrl}</a></p>`,
      });

      res.json({ message: 'Registered—check your email to verify.' });
    } catch (err) {
      next(err);
    }
  }
);

// — VERIFY EMAIL —
app.get('/verify-email', requireDb, async (req, res, next) => {
  try {
    const { token } = req.query;
    const u = await User.findOne({
      verifyToken: token,
      verifyTokenExpiry: { $gt: Date.now() },
    });

    if (!u) return res.status(400).send('Invalid or expired verification link.');

    u.emailVerified = true;
    u.verifyToken = undefined;
    u.verifyTokenExpiry = undefined;
    await u.save();

    res.sendFile(path.join(PUBLIC_DIR, 'verify-email.html'));
  } catch (err) {
    next(err);
  }
});

// — LOGIN —
app.post(
  '/login',
  requireDb,
  [body('email').isEmail().normalizeEmail(), body('password').notEmpty()],
  async (req, res, next) => {
    try {
      const errs = validationResult(req);
      if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });

      const { email, password } = req.body;

      const u = await User.findOne({ email });
      if (!u || !(await bcrypt.compare(password, u.password))) {
        return res.status(401).json({ message: 'Invalid email or password.' });
      }

      if (!u.emailVerified) {
        if (!HAS_EMAIL) return res.status(403).json({ message: 'Email not verified (email service not configured).' });

        const token = crypto.randomBytes(32).toString('hex');
        u.verifyToken = token;
        u.verifyTokenExpiry = Date.now() + 24 * 60 * 60 * 1000;
        await u.save();

        const verifyUrl = `${req.protocol}://${req.get('host')}/verify-email?token=${token}`;
        await sendEmail({
          to: email,
          subject: 'Please verify your Beals.wav account',
          html: `<p>Click to verify: <a href="${verifyUrl}">${verifyUrl}</a></p>`,
        });

        return res.status(403).json({ message: 'Email not verified. New link sent.' });
      }

      res.json({ success: true, message: 'Login successful!' });
    } catch (err) {
      next(err);
    }
  }
);

// — PASSWORD RESET REQUEST —
app.post(
  '/request-reset',
  requireDb,
  requireEmail,
  [body('email').isEmail().normalizeEmail()],
  async (req, res, next) => {
    try {
      const { email } = req.body;
      const u = await User.findOne({ email });

      if (u) {
        const token = crypto.randomBytes(32).toString('hex');
        u.resetToken = token;
        u.resetTokenExpiry = Date.now() + 60 * 60 * 1000;
        await u.save();

        const resetUrl = `${req.protocol}://${req.get('host')}/reset-password.html?token=${token}`;
        await sendEmail({
          to: email,
          subject: 'Beals.wav password reset',
          html: `<p>Reset your password: <a href="${resetUrl}">${resetUrl}</a></p>`,
        });
      }

      res.json({ message: 'If that email exists, a reset link has been sent.' });
    } catch (err) {
      next(err);
    }
  }
);

// — PASSWORD RESET SUBMISSION —
app.post(
  '/reset-password',
  requireDb,
  [body('token').notEmpty(), body('newPassword').isLength({ min: 8 })],
  async (req, res, next) => {
    try {
      const errs = validationResult(req);
      if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });

      const { token, newPassword } = req.body;

      const u = await User.findOne({
        resetToken: token,
        resetTokenExpiry: { $gt: Date.now() },
      });

      if (!u) return res.status(400).json({ message: 'Invalid or expired reset token.' });

      u.password = await bcrypt.hash(newPassword, 12);
      u.resetToken = undefined;
      u.resetTokenExpiry = undefined;
      await u.save();

      res.json({ message: 'Password has been reset. You can now log in.' });
    } catch (err) {
      next(err);
    }
  }
);


// — SAVE SESSION —
app.post(
  '/save-session',
  requireDb,
  [body('email').isEmail().normalizeEmail(), body('serviceType').notEmpty(), body('dateBooked').notEmpty()],
  async (req, res, next) => {
    try {
      const errs = validationResult(req);
      if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });

      const { email, serviceType, dateBooked, details } = req.body;

      const u = await User.findOne({ email });
      if (!u) return res.status(404).json({ message: 'User not found.' });

      u.sessions.push({ serviceType, dateBooked, details: details || '', status: 'Confirmed' });
      await u.save();

      res.json({ success: true });
    } catch (err) {
      next(err);
    }
  }
);

// — SESSION HISTORY —
app.post('/session-history', requireDb, [body('email').isEmail().normalizeEmail()], async (req, res, next) => {
  try {
    const { email } = req.body;

    const u = await User.findOne({ email });
    if (!u) return res.status(404).json({ message: 'User not found.' });

    res.json({ sessions: u.sessions });
  } catch (err) {
    next(err);
  }
});

// ─── CONTACT FORM —
app.post(
  '/contact',
  requireEmail,
  [body('name').notEmpty().trim(), body('email').isEmail().normalizeEmail(), body('message').notEmpty().trim()],
  async (req, res, next) => {
    try {
      const errs = validationResult(req);
      if (!errs.isEmpty()) return res.status(400).json({ errors: errs.array() });

      const { name, email, message } = req.body;

      await sendEmail({
        to: process.env.SENDER_EMAIL,
        cc: 'beals.wav@gmail.com',
        replyTo: email,
        subject: `📬 New contact from ${name}`,
        text: `Name: ${name}\nEmail: ${email}\n\n${message}`,
        html: `<p><strong>Name:</strong> ${name}</p>
               <p><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
               <p>${message}</p>`,
      });

      console.log(`✉️  Contact from ${name} <${email}>`);
      res.json({ message: 'Message sent! We’ll be in touch shortly.' });
    } catch (err) {
      next(err);
    }
  }
);

// ─── GLOBAL ERROR HANDLER ─────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  const status = err.status || 500;
  console.error('🔥 Server error:', err);
  res.status(status).json({ message: err.message || 'Internal Server Error' });
});

// ─── START SERVER ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🎵 Server listening on port ${PORT}`);
});

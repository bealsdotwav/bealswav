// server.js

// ─── IMPORTS & CONFIG ─────────────────────────────────────────────────────────
const express             = require('express');
const helmet              = require('helmet');
const rateLimit           = require('express-rate-limit');
const cors                = require('cors');
const mongoose            = require('mongoose');
const path                = require('path');
require('dotenv').config();  // load .env
const bodyParser          = require('body-parser');
const bcrypt              = require('bcrypt');
const stripe              = require('stripe')(process.env.STRIPE_SECRET_KEY);
const crypto              = require('crypto');
const nodemailer          = require('nodemailer');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 4242;

// ─── ENV CHECK ────────────────────────────────────────────────────────────────
if (!process.env.MONGODB_URI) {
  console.error('❌  MONGODB_URI not set in .env');
  process.exit(1);
}
if (!process.env.SENDER_EMAIL) {
  console.error('❌  SENDER_EMAIL not set in .env');
  process.exit(1);
}

// ─── SECURITY, CORS & RATE‑LIMIT ──────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc:    ["'self'"],
        scriptSrc:     ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        "script-src-attr": ["'unsafe-inline'"],    // allow inline onclick handlers
        styleSrc:      ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc:       ["'self'", "https://fonts.gstatic.com"],
        imgSrc:        ["'self'", "data:"],
        connectSrc:    ["'self'", "https://api.emailjs.com"],   // EmailJS XHR
        frameSrc:      [
          "'self'",
          "https://www.youtube.com",
          "https://www.youtube-nocookie.com",
          "https://open.spotify.com",       // Spotify embeds
          "https://player.beatstars.com"    // BeatStars embeds
        ]
      }
    },
    frameguard:                { action: 'sameorigin' },
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  })
);

// trust proxy if you’re behind one (Render, Heroku, etc.)
app.enable('trust proxy');

// only allow your front‑end origins
const allowedOrigins = process.env.NODE_ENV === 'production'
  ? ['https://bealswav.com']
  : ['http://localhost:4242'];
app.use(cors({ origin: allowedOrigins }));

// redirect HTTP → HTTPS in prod
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure) {
    return res.redirect(`https://${req.headers.host}${req.url}`);
  }
  next();
});

// rate‑limit on register & contact to prevent spam
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,    // 15 minutes
  max:      100,               // limit each IP to 100 requests per windowMs
  message:  'Too many requests from this IP, please try again later.'
});
app.use('/register', apiLimiter);
app.use('/contact',  apiLimiter);

// ─── BODY PARSING & STATIC ────────────────────────────────────────────────────
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../public')));

// ─── MONGOOSE SETUP ───────────────────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser:    true,
  useUnifiedTopology: true
})
.then(() => console.log('✅  MongoDB connected'))
.catch(err => {
  console.error('❌  MongoDB connection error:', err);
  process.exit(1);
});

// ─── USER MODEL ────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email:             { type: String, required: true, unique: true },
  password:          { type: String, required: true },
  emailVerified:     { type: Boolean, default: false },
  verifyToken:       String,
  verifyTokenExpiry: Date,
  resetToken:        String,
  resetTokenExpiry:  Date,
  sessions: [{
    serviceType: String,
    dateBooked:  String,
    status:      String,
    details:     String
  }]
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// ─── EMAIL TRANSPORTER ────────────────────────────────────────────────────────
let transporterPromise = (async () => {
  if (process.env.ZOHO_SMTP_USER && process.env.ZOHO_SMTP_PASS) {
    // → Zoho SMTP relay for production
    return nodemailer.createTransport({
      host:   'smtp.zoho.com',
      port:   465,
      secure: true,
      auth: {
        user: process.env.ZOHO_SMTP_USER,
        pass: process.env.ZOHO_SMTP_PASS
      }
    });
  }
  // → Dev fallback: Ethereal
  const testAcct = await nodemailer.createTestAccount();
  console.log('ℹ️  Ethereal SMTP account:', testAcct);
  return nodemailer.createTransport({
    host:     testAcct.smtp.host,
    port:     testAcct.smtp.port,
    secure:   testAcct.smtp.secure,
    auth:     { user: testAcct.user, pass: testAcct.pass }
  });
})();

// verify once ready
transporterPromise.then(transporter => {
  transporter.verify(err => {
    if (err) console.error('❌ SMTP connect error:', err);
    else    console.log('✅ SMTP ready to send');
  });
});

// ─── EMAIL SENDER HELPER ───────────────────────────────────────────────────────
async function sendEmail(options) {
  const transporter = await transporterPromise;
  const info = await transporter.sendMail({
    from: process.env.SENDER_EMAIL,
    ...options
  });
  console.log('✉️  Sent:', info.messageId);
  console.log('   accepted:', info.accepted);
  console.log('   rejected:', info.rejected);
  return info;
}

// ─── ROUTES ────────────────────────────────────────────────────────────────────

// Health check
app.get('/', (_req, res) => {
  res.send('🎵 Beals.wav server up and running!');
});

// — REGISTER — validate input, hash password, save user, send verification email
app.post('/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8 })
], async (req, res, next) => {
  try {
    const errs = validationResult(req);
    if (!errs.isEmpty()) {
      return res.status(400).json({ errors: errs.array() });
    }

    const { email, password } = req.body;
    if (await User.findOne({ email })) {
      return res.status(400).json({ message: 'Email already registered.' });
    }

    const hashed = await bcrypt.hash(password, 12);
    const token  = crypto.randomBytes(32).toString('hex');
    await new User({
      email,
      password:          hashed,
      verifyToken:       token,
      verifyTokenExpiry: Date.now() + 24*60*60*1000
    }).save();

    const verifyUrl = `${req.protocol}://${req.get('host')}/verify-email?token=${token}`;
    await sendEmail({
      to:      email,
      subject: 'Verify your Beals.wav account',
      html:    `<p>Click to verify your account: <a href="${verifyUrl}">${verifyUrl}</a></p>`
    });

    res.json({ message: 'Registered—check your email to verify.' });
  } catch (err) {
    next(err);
  }
});

// — VERIFY EMAIL — mark a user as verified
app.get('/verify-email', async (req, res, next) => {
  try {
    const { token } = req.query;
    const u = await User.findOne({
      verifyToken:       token,
      verifyTokenExpiry: { $gt: Date.now() }
    });
    if (!u) {
      return res.status(400).send('Invalid or expired verification link.');
    }

    u.emailVerified       = true;
    u.verifyToken         = undefined;
    u.verifyTokenExpiry   = undefined;
    await u.save();

    res.sendFile(path.join(__dirname, '../public/verify-email.html'));
  } catch (err) {
    next(err);
  }
});

// — LOGIN — check credentials, optionally resend verification link
app.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res, next) => {
  try {
    const errs = validationResult(req);
    if (!errs.isEmpty()) {
      return res.status(400).json({ errors: errs.array() });
    }

    const { email, password } = req.body;
    const u = await User.findOne({ email });
    if (!u || !(await bcrypt.compare(password, u.password))) {
      return res.status(401).json({ message: 'Invalid email or password.' });
    }
    if (!u.emailVerified) {
      // resend verification
      const token = crypto.randomBytes(32).toString('hex');
      u.verifyToken       = token;
      u.verifyTokenExpiry = Date.now() + 24*60*60*1000;
      await u.save();

      const verifyUrl = `${req.protocol}://${req.get('host')}/verify-email?token=${token}`;
      await sendEmail({
        to:      email,
        subject: 'Please verify your Beals.wav account',
        html:    `<p>Click to verify: <a href="${verifyUrl}">${verifyUrl}</a></p>`
      });
      return res.status(403).json({ message: 'Email not verified. New link sent.' });
    }

    res.json({ success: true, message: 'Login successful!' });
  } catch (err) {
    next(err);
  }
});

// — PASSWORD RESET REQUEST — generate & email reset link
app.post('/request-reset', [
  body('email').isEmail().normalizeEmail()
], async (req, res, next) => {
  try {
    const { email } = req.body;
    const u = await User.findOne({ email });
    if (u) {
      const token = crypto.randomBytes(32).toString('hex');
      u.resetToken       = token;
      u.resetTokenExpiry = Date.now() + 60*60*1000;
      await u.save();

      const resetUrl = `${req.protocol}://${req.get('host')}/reset-password.html?token=${token}`;
      await sendEmail({
        to:      email,
        subject: 'Beals.wav password reset',
        html:    `<p>Reset your password: <a href="${resetUrl}">${resetUrl}</a></p>`
      });
    }
    // Always respond 200 to avoid email enumeration
    res.json({ message: 'If that email exists, a reset link has been sent.' });
  } catch (err) {
    next(err);
  }
});

// — PASSWORD RESET SUBMISSION — verify & update password
app.post('/reset-password', [
  body('token').notEmpty(),
  body('newPassword').isLength({ min: 8 })
], async (req, res, next) => {
  try {
    const errs = validationResult(req);
    if (!errs.isEmpty()) {
      return res.status(400).json({ errors: errs.array() });
    }

    const { token, newPassword } = req.body;
    const u = await User.findOne({
      resetToken:        token,
      resetTokenExpiry: { $gt: Date.now() }
    });
    if (!u) {
      return res.status(400).json({ message: 'Invalid or expired reset token.' });
    }

    u.password         = await bcrypt.hash(newPassword, 12);
    u.resetToken       = undefined;
    u.resetTokenExpiry = undefined;
    await u.save();

    res.json({ message: 'Password has been reset. You can now log in.' });
  } catch (err) {
    next(err);
  }
});

// — STRIPE CHECKOUT SESSION — your existing checkout logic
app.post('/create-checkout-session', async (req, res, next) => {
  try {
    const { cartItems, customerEmail } = req.body;
    const line_items = cartItems.map(item => ({
      price_data: {
        currency:     'usd',
        product_data: { name: `${item.title} - ${item.license}` },
        unit_amount:  Math.round(item.price * 100)
      },
      quantity: 1
    }));
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode:                 'payment',
      customer_email:       customerEmail,
      line_items,
      success_url:          `${req.protocol}://${req.get('host')}/account.html?status=success`,
      cancel_url:           `${req.protocol}://${req.get('host')}/beatstore.html?status=cancel`
    });
    res.json({ url: session.url });
  } catch (err) {
    next(err);
  }
});

// — SAVE & RETRIEVE SESSIONS — unchanged
app.post('/save-session', [
  body('email').isEmail().normalizeEmail(),
  body('serviceType').notEmpty(),
  body('dateBooked').notEmpty()
], async (req, res, next) => {
  try {
    const errs = validationResult(req);
    if (!errs.isEmpty()) {
      return res.status(400).json({ errors: errs.array() });
    }

    const { email, serviceType, dateBooked, details } = req.body;
    const u = await User.findOne({ email });
    if (!u) {
      return res.status(404).json({ message: 'User not found.' });
    }

    u.sessions.push({ serviceType, dateBooked, details: details || '', status: 'Confirmed' });
    await u.save();
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

app.post('/session-history', [
  body('email').isEmail().normalizeEmail()
], async (req, res, next) => {
  try {
    const { email } = req.body;
    const u = await User.findOne({ email });
    if (!u) {
      return res.status(404).json({ message: 'User not found.' });
    }
    res.json({ sessions: u.sessions });
  } catch (err) {
    next(err);
  }
});

// ─── CONTACT FORM — send contact email to Zoho + Gmail
app.post('/contact', [
  body('name').notEmpty().trim(),
  body('email').isEmail().normalizeEmail(),
  body('message').notEmpty().trim()
], async (req, res, next) => {
  try {
    const errs = validationResult(req);
    if (!errs.isEmpty()) {
      return res.status(400).json({ errors: errs.array() });
    }

    const { name, email, message } = req.body;
    await sendEmail({
      to:      process.env.SENDER_EMAIL,      // Zoho inbox
      cc:      'beals.wav@gmail.com',         // personal Gmail
      replyTo: email,
      subject: `📬 New contact from ${name}`,
      text:    `Name: ${name}\nEmail: ${email}\n\n${message}`,
      html:    `<p><strong>Name:</strong> ${name}</p>
                <p><strong>Email:</strong> <a href="mailto:${email}">${email}</a></p>
                <p>${message}</p>`
    });

    console.log(`✉️  Contact from ${name} <${email}>`);
    res.json({ message: 'Message sent! We’ll be in touch shortly.' });
  } catch (err) {
    next(err);
  }
});

// ─── GLOBAL ERROR HANDLER ─────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error('🔥 Server error:', err);
  res.status(500).json({ message: 'Internal Server Error' });
});

// ─── START SERVER ─────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🎵 Server listening at http://localhost:${PORT}`);
});

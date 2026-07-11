const express = require('express');
const crypto  = require('crypto');
const https   = require('https');
const mongoose = require('mongoose');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const multer  = require('multer');

const userModel    = require('../../models/userModel');
const dbConnection = require('../../connections/xmsPr');
const verify       = require('./verifyToken');
const crashLogger  = require('../../utils/crashLogger');

const router = express.Router();

// ── Rate limit constants ──────────────────────────────────────────────────────
const COOLDOWN_MS       = 60  * 1000;        // 60s between sends (per phone)
const PHONE_WINDOW_MS   = 30  * 60 * 1000;   // 30-min rolling window (per phone)
const PHONE_MAX_SENDS   = 5;                  // max sends per window (per phone)
const IP_WINDOW_MS      = 30  * 60 * 1000;   // 30-min rolling window (per IP)
const IP_MAX_SENDS      = 5;                  // max sends per window (per IP)
const LOCKOUT_DURATION  = 2   * 60 * 60 * 1000;  // 2h lockout after 5 failed verifies
const MAX_VERIFY_FAILS  = 5;

// ── Per-IP in-memory send throttle ───────────────────────────────────────────
// Resets on server restart — acceptable since IP windows are 30 min.
// Format: Map<ip, { count: Number, windowStart: Number (ms timestamp) }>
const ipRateMap = new Map();

function checkAndRecordIp(ip) {
  const now = Date.now();
  const entry = ipRateMap.get(ip);

  if (!entry || now - entry.windowStart > IP_WINDOW_MS) {
    ipRateMap.set(ip, { count: 1, windowStart: now });
    return null;
  }
  if (entry.count >= IP_MAX_SENDS) {
    const remainingMs  = IP_WINDOW_MS - (now - entry.windowStart);
    const remainingMin = Math.ceil(remainingMs / 60000);
    return remainingMin;  // non-null = blocked
  }
  entry.count++;
  return null;
}

// ── File upload (kept for /register profile image) ────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads'),
  filename: (req, file, cb) =>
    cb(null, file.fieldname + '-' + Date.now() + file.originalname.match(/\..*$/)[0]),
});
const upload = multer({ storage, limits: { fileSize: 1 * 1000 * 1000 } });

const userM = dbConnection.model('user', userModel);

// ── Token payload factory ─────────────────────────────────────────────────────
const tokenPayload = (user) => ({
  id: user._id,
  firstName: user.firstName,
  profileImage: user.profileImage,
  lastName: user.lastName,
  access: user.access,
  filterMemory: user.filterMemory,
});

const issueTokens = (user, res) => {
  const payload = tokenPayload(user);
  const accessToken  = jwt.sign(payload, process.env.TOKEN_SECRET,     { expiresIn: '3m'   });
  const refreshToken = jwt.sign(payload, process.env.TOKEN_SECRET_REF, { expiresIn: '180d' });

  return res.status(200).cookie('refreshToken', refreshToken, {
    sameSite: 'strict',
    path: '/',
    secure: true,
    expires: new Date(Date.now() + 4320 * 60 * 60 * 1000),
    httpOnly: true,
  }).json({ accessToken });
};

// ── sms.ir OTP delivery ───────────────────────────────────────────────────────
async function sendOtpViaSmsIr(mobile, otp) {
  const body = JSON.stringify({
    mobile,
    templateId: Number(process.env.SMSIR_OTP_TEMPLATE_ID),
    parameters: [{
      name:  process.env.SMSIR_OTP_PARAM_NAME || 'Code',
      value: String(otp),
    }],
  });

  const verifyUrl = new URL(
    process.env.SMSIR_VERIFY_URL || 'https://api.sms.ir/v1/send/verify'
  );

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: verifyUrl.hostname,
        path:     verifyUrl.pathname,
        method:   'POST',
        headers: {
          'x-api-key':      process.env.SMSIR_API_KEY,
          'Content-Type':   'application/json',
          'Accept':         'text/plain',
          'Content-Length': Buffer.byteLength(body),
        },
      },
      (resp) => {
        let data = '';
        resp.on('data', (chunk) => { data += chunk; });
        resp.on('end', () => {
          try {
            const parsed = JSON.parse(data);
            if (parsed.status !== 1) {
              reject(new Error(`sms.ir: ${parsed.message}`));
            } else {
              resolve(parsed);
            }
          } catch {
            reject(new Error('sms.ir: invalid response'));
          }
        });
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ── POST /auth/requestOtp ─────────────────────────────────────────────────────
router.post('/requestOtp', async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) {
    return res.status(400).json({ message: 'Enter your phone number' });
  }

  // ① Per-IP throttle (checked before DB hit)
  const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
  const ipBlockedMin = checkAndRecordIp(clientIp);
  if (ipBlockedMin !== null) {
    return res.status(429).json({
      message: `Too many requests. Try again in ${ipBlockedMin} minutes`,
    });
  }

  try {
    const user = await userM.findOne({ phoneNumber, deleteDate: null });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    if (user.validation !== true) {
      return res.status(403).json({ message: 'Account is not active' });
    }

    const now  = new Date();
    const auth = user.auth || {};

    // ② Account lockout check
    if (auth.lockedUntil && auth.lockedUntil > now) {
      const remainingMin = Math.ceil((auth.lockedUntil - now) / 60000);
      return res.status(423).json({
        message: `Account is locked. Try again in ${remainingMin} minutes`,
        lockedUntil: auth.lockedUntil,
      });
    }

    // ③ Per-phone 60s cooldown
    if (auth.otpLastSentAt) {
      const msSinceLast = now - new Date(auth.otpLastSentAt);
      if (msSinceLast < COOLDOWN_MS) {
        const remainingS = Math.ceil((COOLDOWN_MS - msSinceLast) / 1000);
        return res.status(429).json({
          message: `Try again in ${remainingS} seconds`,
          cooldownSeconds: remainingS,
        });
      }
    }

    // ④ Per-phone max-sends-per-window check
    const inWindow = auth.otpWindowStart &&
      (now - new Date(auth.otpWindowStart)) < PHONE_WINDOW_MS;
    if (inWindow && (auth.otpSendCount || 0) >= PHONE_MAX_SENDS) {
      const remainingMin = Math.ceil(
        (PHONE_WINDOW_MS - (now - new Date(auth.otpWindowStart))) / 60000
      );
      return res.status(429).json({
        message: `Send limit reached for this period. Try again in ${remainingMin} minutes`,
      });
    }

    // ⑤ Generate OTP, hash it, update user
    const otp          = String(crypto.randomInt(100000, 999999));
    const salt         = await bcrypt.genSalt(10);
    const otpHash      = await bcrypt.hash(otp, salt);
    const otpExpiresAt = new Date(now.getTime() + 3 * 60 * 1000);  // 3 min

    await userM.updateOne(
      { _id: user._id },
      {
        $set: {
          'auth.otpHash':        otpHash,
          'auth.otpExpiresAt':   otpExpiresAt,
          'auth.otpLastSentAt':  now,
          'auth.otpSendCount':   inWindow ? (auth.otpSendCount || 0) + 1 : 1,
          'auth.otpWindowStart': inWindow ? auth.otpWindowStart : now,
        },
      }
    );

    // ⑥ Deliver via sms.ir (DEV: OTP also printed to console for testing)
    console.log(`[DEV] OTP for ${phoneNumber}: ${otp}`);
    try {
      await sendOtpViaSmsIr(phoneNumber, otp);
    } catch (smsErr) {
      crashLogger.logError(smsErr, { type: 'smsIrError', phoneNumber });
      // DEV: don't block login if SMS fails — OTP is in the console above
      // TODO: restore the 502 return below when sms.ir is confirmed working
      // return res.status(502).json({ message: 'Failed to send the code — please try again' });
    }

    return res.status(200).json({ message: 'Verification code sent' });

  } catch (err) {
    return res.status(500).json({ message: 'Server error' });
  }
});

// ── POST /auth/verifyOtp ──────────────────────────────────────────────────────
router.post('/verifyOtp', async (req, res) => {
  const { phoneNumber, otp } = req.body;
  if (!phoneNumber || !otp) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    const user = await userM.findOne({ phoneNumber, deleteDate: null });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const now  = new Date();
    const auth = user.auth || {};

    // ① Lockout check
    if (auth.lockedUntil && auth.lockedUntil > now) {
      const remainingMin = Math.ceil((auth.lockedUntil - now) / 60000);
      return res.status(423).json({
        message: `Account is locked. Try again in ${remainingMin} minutes`,
        lockedUntil: auth.lockedUntil,
      });
    }

    // ② OTP must exist and not be expired
    if (!auth.otpHash || !auth.otpExpiresAt) {
      return res.status(400).json({ message: 'Request a code first' });
    }
    if (new Date(auth.otpExpiresAt) < now) {
      return res.status(400).json({ message: 'Code expired — request a new one' });
    }

    // ③ Compare OTP
    const valid = await bcrypt.compare(String(otp), auth.otpHash);

    if (!valid) {
      const newFailCount = (auth.failedOtpAttempts || 0) + 1;

      if (newFailCount >= MAX_VERIFY_FAILS) {
        // Lock the account for 2 hours
        const lockedUntil = new Date(now.getTime() + LOCKOUT_DURATION);
        await userM.updateOne(
          { _id: user._id },
          {
            $set: {
              'auth.failedOtpAttempts': 0,
              'auth.lockedUntil':       lockedUntil,
            },
          }
        );
        return res.status(423).json({
          message: 'Too many failed attempts. Account locked for 2 hours',
          lockedUntil,
        });
      }

      await userM.updateOne(
        { _id: user._id },
        { $set: { 'auth.failedOtpAttempts': newFailCount } }
      );
      const attemptsLeft = MAX_VERIFY_FAILS - newFailCount;
      return res.status(400).json({ message: 'Incorrect code', attemptsLeft });
    }

    // ④ SUCCESS — clear all OTP + lockout state
    await userM.updateOne(
      { _id: user._id },
      {
        $set: {
          'auth.otpHash':           null,
          'auth.otpExpiresAt':      null,
          'auth.failedOtpAttempts': 0,
          'auth.lockedUntil':       null,
        },
      }
    );

    return issueTokens(user, res);

  } catch (err) {
    return res.status(500).json({ message: 'Server error' });
  }
});

// ── POST /auth/register ───────────────────────────────────────────────────────
router.post('/register', upload.single('images'), verify, async (req, res) => {
  try {
    const existing = await userM.findOne({ phoneNumber: req.body.phoneNumber });
    if (existing) {
      return res.status(400).json({ message: 'Phone number already exists' });
    }
    const newUser = new userM({
      firstName:    req.body.firstName,
      lastName:     req.body.lastName,
      phoneNumber:  req.body.phoneNumber,
      profileImage: req.file,
      validation:   false,
      access:       req.body.access || [],
    });
    const saved = await newUser.save();
    return res.status(200).json(saved);
  } catch (err) {
    return res.status(400).json({ message: err.message });
  }
});

// ── POST /auth/login — DEPRECATED (password login replaced by OTP) ────────────
// router.post('/login', async (req, res) => { ... bcrypt.compare ... });

// ── POST /auth/refreshToken — UNCHANGED ───────────────────────────────────────
router.post('/refreshToken', (req, res) => {
  if (!req.cookies.refreshToken) {
    return res.status(401).json({ message: 'Not available' });
  }
  jwt.verify(req.cookies.refreshToken, process.env.TOKEN_SECRET_REF, (error, user) => {
    if (error) {
      return res.status(401).json({ message: 'Not available' });
    }
    const accessToken = jwt.sign(
      {
        id:           user.id,
        firstName:    user.firstName,
        profileImage: user.profileImage,
        lastName:     user.lastName,
        access:       user.access,
        filterMemory: user.filterMemory,
      },
      process.env.TOKEN_SECRET,
      { expiresIn: '3m' }
    );
    return res.status(200).json({ accessToken });
  });
});

// ── POST /auth/deleteRefreshToken — UNCHANGED (logout) ───────────────────────
router.post('/deleteRefreshToken', (req, res) => {
  res.status(200).clearCookie('refreshToken').json({ message: 'logged out' });
});

// ── POST /auth/updateUser — kept until Session 23 user-management routes ship ─
router.post('/updateUser', upload.single('images'), verify, async (req, res) => {
  try {
    const update = {
      firstName: req.body.firstName,
      lastName:  req.body.lastName,
      access:    req.body.access || [],
    };
    if (req.file) update.profileImage = req.file;
    await userM.findOneAndUpdate({ _id: req.body.userId }, { $set: update });
    return res.status(200).json({ message: 'user updated' });
  } catch (err) {
    return res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;

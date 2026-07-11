const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  // ── Identity ───────────────────────────────────────────────────────────────
  firstName:   { type: String, required: true, min: 1, max: 50 },
  lastName:    { type: String, required: true, min: 1, max: 50 },
  phoneNumber: { type: String, required: true, unique: true },

  // ── Deprecated auth fields (kept for migration, no longer read on login) ──
  password:     { type: String, min: 8, max: 1024 },  // deprecated — OTP replaces this
  oldPasswords: { type: Array },                        // deprecated
  passwordReset:{ type: Array },                        // deprecated

  // ── OTP / login security (Phase 4) ────────────────────────────────────────
  auth: {
    otpHash:           { type: String, default: null },  // bcrypt(otp)
    otpExpiresAt:      { type: Date,   default: null },  // now + 3 min
    otpLastSentAt:     { type: Date,   default: null },  // last SMS send time
    otpSendCount:      { type: Number, default: 0    },  // sends in current window
    otpWindowStart:    { type: Date,   default: null },  // start of send-throttle window
    failedOtpAttempts: { type: Number, default: 0    },  // wrong-code counter
    // Password fallback (reinstated 2026-07-11) — its own counter, 10-attempt
    // limit; shares lockedUntil with OTP so a locked account is locked for both.
    failedPasswordAttempts: { type: Number, default: 0 },
    lockedUntil:       { type: Date,   default: null },  // OTP: 5 fails / password: 10 fails → now + 2h
  },

  // ── Presence (Phase 4 — updated by Socket.io) ─────────────────────────────
  isOnline: { type: Boolean, default: false },
  lastSeen: { type: Date,    default: null  },

  // ── Access (deprecated — replaced by xmsApi userAccess RBAC) ─────────────
  access: [],  // migrate via script in Session 23, then retire

  // ── Profile ───────────────────────────────────────────────────────────────
  validation:   { type: Boolean, required: true },
  profileImage: { type: Object  },
  city:         { type: String  },
  State:        { type: String  },
  postalCode:   { type: String  },
  address:      { type: String  },

  // ── Misc ──────────────────────────────────────────────────────────────────
  recivedRequests: [{
    from:       { type: mongoose.Schema.Types.ObjectId },
    deleteDate: { type: Date, default: null },
    date:       { type: Date },
    document:   { type: mongoose.Schema.Types.ObjectId },
  }],
  products:  { type: Array },
  savedPost: { type: Array },
  filterMemory: {
    crm: {
      sort:   { type: String, default: null },
      filter: {
        country:        { type: String,  default: null },
        attractedBy:    { type: String,  default: null },
        whatsApp:       { type: Boolean, default: null },
        havingAdderss:  { type: Boolean, default: null },
      },
    },
    mis: {
      sort:   { type: String, default: null },
      filter: {
        requestType: { type: String, default: null },
        sentTo:      { type: Array,  default: null },
        sentBy:      { type: Array,  default: null },
      },
    },
  },

  insertDate: { type: Date, default: Date.now },
  updateDate: { type: Date, default: null },
  deleteDate: { type: Date, default: null },
});

module.exports = userSchema;

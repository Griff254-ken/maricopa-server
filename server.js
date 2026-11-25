'use strict';
/* =====================================================================
   MARICOPA CONCRETE & ALLIED — BACKEND
   Express + MongoDB Atlas + Safaricom Daraja (M-Pesa STK Push)

   Serves both frontends:
     • index.html  (storefront)  → public endpoints
     • admin.html  (admin panel) → /api/admin/* (HTTP Basic auth)

   Payment flow
     1. Storefront POST /api/orders           → server re-prices, creates order
     2. Storefront POST /api/mpesa/stkpush    → Daraja prompt sent to phone
     3. Safaricom   POST /api/payments/callback/:secret
                                              → order.paymentStatus = "paid"
     4. Admin       POST /api/admin/orders/:id/confirm
                                              → order.adminConfirmed = true
     5. Storefront polls GET /api/orders/:id/status and only shows
        "Order confirmed" when paid AND adminConfirmed are both true.
   ===================================================================== */

require('dotenv').config();

const crypto = require('node:crypto');
const path = require('node:path');
const fs = require('node:fs');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { MongoClient, ServerApiVersion, Binary } = require('mongodb');

/* =====================================================================
   CONFIG
   ===================================================================== */
const env = process.env;
const IS_PROD = env.NODE_ENV === 'production';
const flag = (v, d = false) => (v === undefined || v === '' ? d : /^(1|true|yes|on)$/i.test(v));
const list = v => (v || '').split(',').map(s => s.trim()).filter(Boolean);

const parseTrustProxy = v => {
  if (v === undefined || v === '') return 1;
  if (/^\d+$/.test(v)) return Number(v);
  if (/^(true|false)$/i.test(v)) return /^true$/i.test(v);
  return v;
};

const CFG = {
  port: Number(env.PORT) || 3000,
  mongoUri: env.MONGODB_URI,
  dbName: env.MONGODB_DB || 'maricopa',
  publicUrl: (env.PUBLIC_URL || '').replace(/\/+$/, ''),
  allowedOrigins: list(env.ALLOWED_ORIGINS).map(o => o.replace(/\/+$/, '')),
  trustProxy: parseTrustProxy(env.TRUST_PROXY),
  seedDemo: flag(env.SEED_DEMO_PRODUCTS, false),
  admin: { user: env.ADMIN_USERNAME || '', pass: env.ADMIN_PASSWORD || '' },
  mpesa: {
    env: env.MPESA_ENV === 'production' ? 'production' : 'sandbox',
    key: env.MPESA_CONSUMER_KEY || '',
    secret: env.MPESA_CONSUMER_SECRET || '',
    shortcode: env.MPESA_SHORTCODE || '',
    passkey: env.MPESA_PASSKEY || '',
    partyB: env.MPESA_PARTY_B || env.MPESA_SHORTCODE || '',
    txType: env.MPESA_TRANSACTION_TYPE === 'CustomerBuyGoodsOnline' ? 'CustomerBuyGoodsOnline' : 'CustomerPayBillOnline',
    callbackSecret: env.MPESA_CALLBACK_SECRET || '',
    callbackIps: list(env.MPESA_CALLBACK_IPS),
    reconcile: flag(env.MPESA_RECONCILE, true),
    maxAttempts: 8,
    minRetryMs: 25_000
  }
};
CFG.mpesa.base = CFG.mpesa.env === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';

function assertConfig() {
  const errors = [];
  if (!CFG.mongoUri) errors.push('MONGODB_URI is required.');
  if (!CFG.admin.user || !CFG.admin.pass) errors.push('ADMIN_USERNAME and ADMIN_PASSWORD are required.');
  if (IS_PROD && CFG.admin.pass.length < 10) errors.push('ADMIN_PASSWORD must be at least 10 characters in production.');
  if (errors.length) {
    console.error('\nConfiguration error:\n - ' + errors.join('\n - ') + '\n');
    process.exit(1);
  }
  if (!mpesaConfigured()) {
    console.warn('⚠️  M-Pesa is not fully configured (need MPESA_CONSUMER_KEY/SECRET, MPESA_SHORTCODE, MPESA_PASSKEY, MPESA_CALLBACK_SECRET and PUBLIC_URL). STK push will return 503.');
  }
  if (IS_PROD && !CFG.allowedOrigins.length) {
    console.warn('⚠️  ALLOWED_ORIGINS is empty: any website can call this API. Set it to your storefront/admin origins.');
  }
  if (IS_PROD && CFG.publicUrl && !CFG.publicUrl.startsWith('https://')) {
    console.warn('⚠️  PUBLIC_URL should be https:// (Daraja only calls back to HTTPS URLs).');
  }
}

/* =====================================================================
   SMALL UTILITIES
   ===================================================================== */
class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
    this.expose = true;
  }
}
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const sha256 = s => crypto.createHash('sha256').update(s).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha256(String(a)), sha256(String(b)));
const round2 = n => Math.round(n * 100) / 100;
const isObj = v => v && typeof v === 'object' && !Array.isArray(v);

function str(v, { min = 0, max = 255, required = false, field = 'Field' } = {}) {
  if (v === undefined || v === null || v === '') {
    if (required) throw new HttpError(400, `${field} is required.`);
    return '';
  }
  if (typeof v !== 'string') throw new HttpError(400, `${field} must be text.`);
  const s = v.replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim();
  if (required && !s) throw new HttpError(400, `${field} is required.`);
  if (s && s.length < min) throw new HttpError(400, `${field} is too short.`);
  if (s.length > max) throw new HttpError(400, `${field} is too long (max ${max} characters).`);
  return s;
}

function num(v, { min = -Infinity, max = Infinity, field = 'Value' } = {}) {
  const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
  if (typeof n !== 'number' || !Number.isFinite(n) || n < min || n > max) {
    throw new HttpError(400, `${field} is invalid.`);
  }
  return n;
}

function normPhone(v) {
  if (typeof v !== 'string') return null;
  v = v.replace(/[\s\-+()]/g, '');
  if (/^0[17]\d{8}$/.test(v)) return '254' + v.slice(1);
  if (/^254[17]\d{8}$/.test(v)) return v;
  if (/^[17]\d{8}$/.test(v)) return '254' + v;
  return null;
}

const REF_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 chars, no I/O/0/1
const makeReference = () => 'MCA-' + Array.from(crypto.randomBytes(6), b => REF_ALPHABET[b % 32]).join(''); // ≤12 chars (Daraja AccountReference limit)

const baseUrl = req => CFG.publicUrl || `${req.protocol}://${req.get('host')}`;

/* =====================================================================
   DATABASE
   ===================================================================== */
let client;
let db;
const col = {};

async function connectDb() {
  client = new MongoClient(CFG.mongoUri, {
    serverApi: { version: ServerApiVersion.v1, deprecationErrors: true },
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 10_000,
    retryWrites: true
  });
  await client.connect();
  db = client.db(CFG.dbName);
  col.products = db.collection('products');
  col.images = db.collection('product_images');
  col.orders = db.collection('orders');
  col.callbacks = db.collection('payment_callbacks');

  await Promise.all([
    col.products.createIndex({ category: 1, name: 1 }),
    col.orders.createIndex({ reference: 1 }, { unique: true }),
    col.orders.createIndex({ createdAt: -1 }),
    col.orders.createIndex({ paymentStatus: 1, adminConfirmed: 1, createdAt: -1 }),
    col.orders.createIndex({ checkoutRequestIds: 1 }),
    col.orders.createIndex({ idempotencyKey: 1 }, { unique: true, partialFilterExpression: { idempotencyKey: { $type: 'string' } } }),
    col.orders.createIndex({ mpesaReceipt: 1 }, { unique: true, partialFilterExpression: { mpesaReceipt: { $type: 'string' } } }),
    col.callbacks.createIndex({ receivedAt: 1 }, { expireAfterSeconds: 90 * 24 * 3600 })
  ]);

  if (CFG.seedDemo && (await col.products.estimatedDocumentCount()) === 0) {
    const now = new Date();
    await col.products.insertMany(SEED.map(p => ({ _id: crypto.randomUUID(), image: null, inStock: true, createdAt: now, updatedAt: now, ...p })));
    console.log(`Seeded ${SEED.length} demo products (replace prices from the admin panel).`);
  }
}

const SEED = [
  {
    name: 'Ready-Mix Concrete C25', category: 'Concrete', unit: 'per m³', price: 14500, emoji: '🏗️',
    description: 'Batched, tested C25/30 ready-mix concrete delivered to site.',
    gradient: ['#64748b', '#334155'],
    specs: [['Grade', 'C25/30'], ['Max aggregate', '20 mm']],
    options: [{ key: 'Slump', choices: [{ value: '75–100 mm', priceAdjust: 0 }, { value: '100–150 mm', priceAdjust: 300 }] }]
  },
  {
    name: 'Portland Cement 50kg', category: 'Cement', unit: 'per bag', price: 800, emoji: '🧱',
    description: 'General-purpose Portland cement, 50 kg bag.',
    gradient: ['#94a3b8', '#475569'],
    specs: [['Weight', '50 kg'], ['Class', '42.5N']], options: []
  },
  {
    name: 'Ballast 3/4"', category: 'Aggregates', unit: 'per tonne', price: 2200, emoji: '⛰️',
    description: 'Crushed stone ballast for concrete and bases.',
    gradient: ['#78716c', '#44403c'], specs: [['Size', '3/4 inch']], options: []
  },
  {
    name: 'Hollow Block 6"', category: 'Blocks', unit: 'per block', price: 75, emoji: '🧱',
    description: 'Machine-cut hollow concrete block for walling.',
    gradient: ['#a8a29e', '#57534e'], specs: [['Size', '6 inch']], options: []
  }
];

/* =====================================================================
   PRODUCTS — validation & mapping
   ===================================================================== */
const HEX = /^#[0-9a-f]{3,8}$/i;

function sanitizeProduct(b) {
  if (!isObj(b)) throw new HttpError(400, 'Invalid product data.');

  const gradient = Array.isArray(b.gradient) && b.gradient.length === 2 && b.gradient.every(c => typeof c === 'string' && HEX.test(c.trim()))
    ? b.gradient.map(c => c.trim())
    : ['#64748b', '#334155'];

  const specs = (Array.isArray(b.specs) ? b.specs.slice(0, 30) : [])
    .map(s => (Array.isArray(s) ? [str(s[0], { max: 60, field: 'Spec label' }), str(s[1], { max: 120, field: 'Spec value' })] : null))
    .filter(s => s && s[0] && s[1]);

  const rawOpts = Array.isArray(b.options) ? b.options : [];
  if (rawOpts.length > 10) throw new HttpError(400, 'Too many option groups (max 10).');
  const options = [];
  const seenKeys = new Set();
  for (const g of rawOpts) {
    if (!isObj(g)) continue;
    const key = str(g.key, { max: 60, field: 'Option name' });
    if (!key) continue;
    if (seenKeys.has(key)) throw new HttpError(400, `Duplicate option group "${key}".`);
    seenKeys.add(key);
    const seen = new Set();
    const choices = [];
    for (const c of (Array.isArray(g.choices) ? g.choices.slice(0, 30) : [])) {
      if (!isObj(c)) continue;
      const value = str(c.value, { max: 80, field: 'Option value' });
      if (!value) continue;
      if (seen.has(value)) throw new HttpError(400, `Duplicate choice "${value}" in "${key}".`);
      seen.add(value);
      const priceAdjust = c.priceAdjust === undefined || c.priceAdjust === '' ? 0 : num(c.priceAdjust, { min: -10_000_000, max: 10_000_000, field: 'Price adjustment' });
      choices.push({ value, priceAdjust });
    }
    if (choices.length) options.push({ key, choices });
  }

  return {
    name: str(b.name, { max: 120, required: true, field: 'Product name' }),
    category: str(b.category, { max: 60, field: 'Category' }) || 'Other',
    unit: str(b.unit, { max: 40, required: true, field: 'Unit' }),
    price: num(b.price, { min: 0, max: 100_000_000, field: 'Price' }),
    description: str(b.description, { max: 1000, field: 'Description' }),
    emoji: str(b.emoji, { max: 8, field: 'Emoji' }) || '📦',
    inStock: b.inStock === undefined ? true : b.inStock === true || b.inStock === 'true',
    gradient,
    specs,
    options
  };
}

const MAX_IMAGE_BYTES = 2.5 * 1024 * 1024;

function detectImageType(buf) {
  if (buf.length < 12) return null;
  if (buf[0] === 0x89 && buf.toString('ascii', 1, 4) === 'PNG') return 'image/png';
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.toString('ascii', 0, 4) === 'GIF8') return 'image/gif';
  if (buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';
  return null;
}

/** Interprets the `image` field sent by admin.html. */
function parseImageInput(input, productId) {
  if (input === undefined) return { action: 'keep' };
  if (input === null || input === '') return { action: 'clear' };
  if (typeof input !== 'string') throw new HttpError(400, 'Invalid image.');

  if (input.startsWith('data:')) {
    const comma = input.indexOf(',');
    const header = comma > 0 ? input.slice(0, comma) : '';
    if (!/^data:image\/(png|jpe?g|webp|gif);base64$/i.test(header)) {
      throw new HttpError(400, 'Image must be a PNG, JPG, WebP or GIF.');
    }
    const buf = Buffer.from(input.slice(comma + 1), 'base64');
    if (buf.length > MAX_IMAGE_BYTES) throw new HttpError(413, 'Image is too large (max 2 MB).');
    const contentType = detectImageType(buf);
    if (!contentType) throw new HttpError(400, 'Image file is not valid.');
    return { action: 'upload', buf, contentType };
  }

  let u;
  try { u = new URL(input); } catch { throw new HttpError(400, 'Invalid image URL.'); }
  if (!/^https?:$/.test(u.protocol) || input.length > 2000) throw new HttpError(400, 'Invalid image URL.');
  const own = /\/api\/products\/([^/]+)\/image\/?$/.exec(u.pathname);
  if (own) {
    if (decodeURIComponent(own[1]) === productId) return { action: 'keep' }; // admin re-sent our own URL
    throw new HttpError(400, 'Invalid image URL.');
  }
  return { action: 'url', url: input };
}

async function applyImage(productId, img) {
  if (img.action === 'upload') {
    const hash = crypto.createHash('sha1').update(img.buf).digest('hex').slice(0, 16);
    await col.images.updateOne(
      { _id: productId },
      { $set: { contentType: img.contentType, data: new Binary(img.buf), hash, size: img.buf.length, updatedAt: new Date() } },
      { upsert: true }
    );
    return { kind: 'upload', hash };
  }
  await col.images.deleteOne({ _id: productId });
  if (img.action === 'url') return { kind: 'url', url: img.url };
  return null; // clear
}

function publicProduct(req, p) {
  let image = '';
  if (p.image?.kind === 'url') image = p.image.url;
  else if (p.image?.kind === 'upload') image = `${baseUrl(req)}/api/products/${encodeURIComponent(p._id)}/image?v=${p.image.hash}`;
  return {
    id: p._id,
    name: p.name,
    category: p.category,
    unit: p.unit,
    price: p.price,
    description: p.description,
    image,
    inStock: p.inStock !== false,
    emoji: p.emoji,
    gradient: p.gradient,
    specs: p.specs || [],
    options: p.options || []
  };
}

/* =====================================================================
   ORDERS — pricing & mapping
   ===================================================================== */
const stepOf = unit => (/m³/.test(unit) ? 0.5 : 1); // must match the storefront

async function priceOrder(body) {
  if (!isObj(body)) throw new HttpError(400, 'Invalid order.');
  const c = body.customer;
  if (!isObj(c)) throw new HttpError(400, 'Customer details are required.');
  const phone = normPhone(c.phone);
  if (!phone) throw new HttpError(400, 'Enter a valid Safaricom number, e.g. 0712 345 678.');
  const customer = {
    name: str(c.name, { min: 2, max: 80, required: true, field: 'Name' }),
    phone,
    location: str(c.location, { min: 2, max: 200, required: true, field: 'Delivery location' })
  };

  if (!Array.isArray(body.items) || !body.items.length) throw new HttpError(400, 'Your cart is empty.');
  if (body.items.length > 50) throw new HttpError(400, 'Too many items in one order (max 50).');

  const ids = [...new Set(body.items.map(i => (isObj(i) && typeof i.productId === 'string' ? i.productId : null)))];
  if (ids.includes(null) || ids.some(id => id.length > 64)) throw new HttpError(400, 'Invalid item in cart.');
  const found = await col.products.find({ _id: { $in: ids } }).toArray();
  const byId = new Map(found.map(p => [p._id, p]));

  const items = body.items.map(it => {
    const p = byId.get(it.productId);
    if (!p) throw new HttpError(409, 'An item in your cart is no longer available. Please refresh the page.');
    if (p.inStock === false) throw new HttpError(409, `${p.name} is out of stock.`);

    const quantity = num(it.quantity, { min: 0.5, max: 100_000, field: `Quantity for ${p.name}` });
    const step = stepOf(p.unit);
    if (Math.abs(quantity / step - Math.round(quantity / step)) > 1e-9) {
      throw new HttpError(400, `Quantity for ${p.name} must be in steps of ${step}.`);
    }

    const chosen = isObj(it.options) ? it.options : {};
    const options = {};
    let unitPrice = p.price;
    for (const g of p.options || []) {
      const want = chosen[g.key];
      const choice = want === undefined ? g.choices[0] : g.choices.find(x => typeof want === 'string' && x.value === want);
      if (!choice) throw new HttpError(409, `The "${g.key}" option for ${p.name} has changed. Please refresh the page.`);
      options[g.key] = choice.value;
      unitPrice += choice.priceAdjust || 0;
    }
    if (unitPrice < 0) throw new HttpError(409, `${p.name} has an invalid price. Please contact us.`);

    return {
      productId: p._id,
      name: p.name,
      unit: p.unit,
      quantity,
      options,
      note: str(it.note, { max: 200, field: 'Note' }),
      unitPrice: round2(unitPrice),
      lineTotal: round2(unitPrice * quantity)
    };
  });

  const total = Math.round(items.reduce((s, i) => s + i.lineTotal, 0)); // whole shillings (M-Pesa requirement)
  if (total < 1) throw new HttpError(400, 'Order total must be at least KSh 1.');
  return { customer, items, total };
}

function adminOrder(o) {
  return {
    id: o._id,
    reference: o.reference,
    customer: o.customer,
    items: o.items,
    total: o.total,
    paymentStatus: o.paymentStatus,
    adminConfirmed: !!o.adminConfirmed,
    mpesaReceipt: o.mpesaReceipt || null,
    createdAt: o.createdAt,
    confirmedAt: o.confirmedAt || null
  };
}

/* =====================================================================
   DARAJA (M-PESA)
   ===================================================================== */
function mpesaConfigured() {
  const m = CFG.mpesa;
  return !!(m.key && m.secret && m.shortcode && m.passkey && m.callbackSecret && CFG.publicUrl);
}

const darajaTimestamp = () => new Date(Date.now() + 3 * 3600 * 1000).toISOString().replace(/[-:T]/g, '').slice(0, 14); // EAT
const darajaPassword = ts => Buffer.from(CFG.mpesa.shortcode + CFG.mpesa.passkey + ts).toString('base64');

let tokenCache = { value: null, exp: 0, pending: null };

async function getToken(force = false) {
  if (!force && tokenCache.value && Date.now() < tokenCache.exp) return tokenCache.value;
  if (tokenCache.pending) return tokenCache.pending;
  tokenCache.pending = (async () => {
    try {
      const basic = Buffer.from(`${CFG.mpesa.key}:${CFG.mpesa.secret}`).toString('base64');
      const res = await fetch(`${CFG.mpesa.base}/oauth/v1/generate?grant_type=client_credentials`, {
        headers: { Authorization: `Basic ${basic}` },
        signal: AbortSignal.timeout(15_000)
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.access_token) throw new Error(`Daraja auth failed (${res.status})`);
      tokenCache.value = data.access_token;
      tokenCache.exp = Date.now() + Math.max(60, (Number(data.expires_in) || 3599) - 60) * 1000;
      return tokenCache.value;
    } finally {
      tokenCache.pending = null;
    }
  })();
  return tokenCache.pending;
}

async function darajaPost(pathname, body, retried = false) {
  const token = await getToken(retried);
  const res = await fetch(CFG.mpesa.base + pathname, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20_000)
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !retried) { tokenCache.value = null; return darajaPost(pathname, body, true); }
  return { ok: res.ok, status: res.status, data };
}

async function sendStkPush(order, phone) {
  const ts = darajaTimestamp();
  let r;
  try {
    r = await darajaPost('/mpesa/stkpush/v1/processrequest', {
      BusinessShortCode: CFG.mpesa.shortcode,
      Password: darajaPassword(ts),
      Timestamp: ts,
      TransactionType: CFG.mpesa.txType,
      Amount: order.total,
      PartyA: phone,
      PartyB: CFG.mpesa.partyB,
      PhoneNumber: phone,
      CallBackURL: `${CFG.publicUrl}/api/payments/callback/${CFG.mpesa.callbackSecret}`,
      AccountReference: order.reference,
      TransactionDesc: 'Maricopa'
    });
  } catch (e) {
    console.error('Daraja STK request failed:', e.message);
    throw new HttpError(502, 'Could not reach M-Pesa. Please try again in a moment.');
  }
  const d = r.data || {};
  if (!r.ok || String(d.ResponseCode) !== '0') {
    console.error('Daraja STK rejected:', r.status, JSON.stringify(d));
    throw new HttpError(502, d.CustomerMessage || d.errorMessage || d.ResponseDescription || 'M-Pesa could not send the payment prompt.');
  }
  return { checkoutRequestId: d.CheckoutRequestID, merchantRequestId: d.MerchantRequestID };
}

const FAIL_MESSAGES = {
  1: 'Insufficient M-Pesa balance.',
  1001: 'Another M-Pesa transaction is in progress on your phone. Try again shortly.',
  1019: 'The M-Pesa request expired. Please try again.',
  1025: 'M-Pesa could not show the prompt on your phone. Please try again.',
  1032: 'You cancelled the M-Pesa request.',
  1037: 'The M-Pesa prompt timed out. Please try again.',
  2001: 'Wrong M-Pesa PIN entered.'
};
const failMessage = (code, desc) => FAIL_MESSAGES[code] || (typeof desc === 'string' && desc.slice(0, 200)) || 'The payment was not completed.';

/** Marks an order paid. Safe to call repeatedly (callback + reconciliation). */
async function markPaid(order, { receipt, amount, phone, via }) {
  const now = new Date();
  const set = { paymentStatus: 'paid', paidAt: now, paidVia: via, failureReason: null, updatedAt: now };
  if (receipt) set.mpesaReceipt = receipt;
  if (amount !== undefined) set.paidAmount = amount;
  if (phone) set.paidPhone = phone;

  try {
    const r = await col.orders.updateOne({ _id: order._id, paymentStatus: { $in: ['pending', 'failed'] } }, { $set: set });
    if (r.matchedCount) return;

    const cur = await col.orders.findOne({ _id: order._id });
    if (!cur) return;
    if (cur.paymentStatus === 'paid' && receipt && !cur.mpesaReceipt) {
      // Paid earlier via status query (no receipt) → attach the receipt now.
      await col.orders.updateOne({ _id: cur._id }, { $set: { mpesaReceipt: receipt, paidAmount: amount, paidPhone: phone, updatedAt: now } });
    } else if (cur.paymentStatus === 'cancelled') {
      await col.orders.updateOne({ _id: cur._id }, { $set: { lateReceipt: receipt || null, lateReceiptAmount: amount ?? null, updatedAt: now } });
      console.error(`⚠️  Payment ${receipt} arrived for CANCELLED order ${cur.reference}. Refund required.`);
    }
  } catch (e) {
    if (e.code === 11000) { console.warn('Duplicate M-Pesa receipt ignored:', receipt); return; }
    throw e;
  }
}

async function markFailed(order, checkoutRequestId, reason) {
  await col.orders.updateOne(
    { _id: order._id, paymentStatus: 'pending', checkoutRequestId },
    { $set: { paymentStatus: 'failed', failureReason: reason, updatedAt: new Date() } }
  );
}

async function handleStkCallback(body) {
  const cb = body?.Body?.stkCallback;
  if (!cb || typeof cb.CheckoutRequestID !== 'string') return;

  await col.callbacks.insertOne({
    receivedAt: new Date(),
    checkoutRequestId: cb.CheckoutRequestID,
    resultCode: cb.ResultCode,
    resultDesc: cb.ResultDesc,
    payload: body
  });

  const order = await col.orders.findOne({ checkoutRequestIds: cb.CheckoutRequestID });
  if (!order) { console.warn('Callback for unknown CheckoutRequestID', cb.CheckoutRequestID); return; }

  const code = Number(cb.ResultCode);
  if (code === 0) {
    const meta = Array.isArray(cb.CallbackMetadata?.Item) ? cb.CallbackMetadata.Item : [];
    const get = n => meta.find(i => i.Name === n)?.Value;
    const receipt = String(get('MpesaReceiptNumber') || '');
    const amount = Number(get('Amount'));
    const phone = String(get('PhoneNumber') || '');
    if (!receipt) { console.error('Success callback without receipt', cb.CheckoutRequestID); return; }
    if (!(amount >= order.total)) {
      console.error(`Underpayment on ${order.reference}: expected ${order.total}, got ${amount} (${receipt})`);
      await col.orders.updateOne({ _id: order._id }, { $set: { paymentStatus: 'failed', failureReason: 'Payment amount did not match the order total. Please contact us.', mpesaReceipt: receipt, paidAmount: amount, updatedAt: new Date() } });
      return;
    }
    await markPaid(order, { receipt, amount, phone, via: 'callback' });
  } else {
    await markFailed(order, cb.CheckoutRequestID, failMessage(code, cb.ResultDesc));
  }
}

/** If the callback never arrived, ask Daraja directly (throttled). */
async function reconcileOrder(o) {
  const cutoff = new Date(Date.now() - 12_000);
  const claimed = await col.orders.findOneAndUpdate(
    { _id: o._id, paymentStatus: 'pending', $or: [{ lastQueryAt: null }, { lastQueryAt: { $lt: cutoff } }] },
    { $set: { lastQueryAt: new Date() } },
    { returnDocument: 'after' }
  );
  if (!claimed) return o;

  const ts = darajaTimestamp();
  const r = await darajaPost('/mpesa/stkpushquery/v1/query', {
    BusinessShortCode: CFG.mpesa.shortcode,
    Password: darajaPassword(ts),
    Timestamp: ts,
    CheckoutRequestID: claimed.checkoutRequestId
  });
  const d = r.data || {};
  if (d.ResultCode === undefined) return claimed; // still processing, or transient Daraja error

  const code = Number(d.ResultCode);
  if (code === 0) await markPaid(claimed, { via: 'query' });
  else await markFailed(claimed, claimed.checkoutRequestId, failMessage(code, d.ResultDesc));
  return (await col.orders.findOne({ _id: o._id })) || claimed;
}

/* =====================================================================
   EXPRESS APP
   ===================================================================== */
const app = express();
app.set('trust proxy', CFG.trustProxy);
app.disable('x-powered-by');

app.use(helmet({
  contentSecurityPolicy: false,                         // the frontends use inline scripts/styles
  crossOriginResourcePolicy: { policy: 'cross-origin' } // product images are loaded from another origin
}));
app.use(compression());

app.use((req, res, next) => {
  const t = process.hrtime.bigint();
  res.on('finish', () => {
    if (req.path === '/health') return;
    const ms = Number(process.hrtime.bigint() - t) / 1e6;
    const p = req.path.replace(/\/callback\/.*/, '/callback/***');
    console.log(`${new Date().toISOString()} ${req.method} ${p} ${res.statusCode} ${ms.toFixed(0)}ms`);
  });
  next();
});

app.use(cors({
  origin(origin, cb) {
    if (!origin || !CFG.allowedOrigins.length) return cb(null, true);
    cb(null, CFG.allowedOrigins.includes(origin.replace(/\/+$/, '')));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key'],
  maxAge: 86_400
}));

const smallJson = express.json({ limit: '50kb' });
app.use((req, res, next) => (req.path.startsWith('/api/admin/') ? next() : smallJson(req, res, next)));

const limiter = (windowMs, limit, message, extra = {}) => rateLimit({
  windowMs, limit, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: message }, ...extra
});
app.use('/api/', limiter(60_000, 300, 'Too many requests. Please slow down.'));
const ordersLimiter = limiter(10 * 60_000, 30, 'Too many orders from this connection. Please wait a few minutes.');
const stkLimiter = limiter(10 * 60_000, 20, 'Too many payment attempts. Please wait a few minutes.');
const statusLimiter = limiter(60_000, 200, 'Too many status checks. Please slow down.');
const adminAuthLimiter = limiter(15 * 60_000, 20, 'Too many failed sign-in attempts. Try again in 15 minutes.', {
  requestWasSuccessful: (req, res) => res.statusCode !== 401 // only failed logins count
});

/* ---------------- Health ---------------- */
app.get('/health', wrap(async (req, res) => {
  await db.command({ ping: 1 });
  res.json({ ok: true, mpesa: mpesaConfigured() ? CFG.mpesa.env : 'not-configured' });
}));

/* =====================================================================
   PUBLIC API (storefront)
   ===================================================================== */
app.get('/api/products', wrap(async (req, res) => {
  const products = await col.products.find({}).sort({ category: 1, name: 1 }).toArray();
  res.set('Cache-Control', 'no-cache').json({ products: products.map(p => publicProduct(req, p)) });
}));

app.get('/api/products/:id/image', wrap(async (req, res) => {
  const doc = await col.images.findOne({ _id: req.params.id.slice(0, 64) });
  if (!doc) throw new HttpError(404, 'Image not found.');
  const etag = `"${doc.hash}"`;
  res.set({
    'Content-Type': doc.contentType,
    'Cache-Control': 'public, max-age=31536000, immutable', // URL carries ?v=<hash>
    ETag: etag,
    'X-Content-Type-Options': 'nosniff'
  });
  if (req.get('If-None-Match') === etag) return res.status(304).end();
  res.end(Buffer.from(doc.data.buffer.subarray(0, doc.data.position)));
}));

app.post('/api/orders', ordersLimiter, wrap(async (req, res) => {
  const key = req.get('Idempotency-Key');
  if (!key || !/^[\w\-:.]{8,100}$/.test(key)) throw new HttpError(400, 'Missing or invalid Idempotency-Key header.');
  const requestHash = sha256(JSON.stringify(req.body)).toString('hex');

  const reply = (o, status = 200) => res.status(status).json({ orderId: o._id, reference: o.reference, total: o.total });

  const existing = await col.orders.findOne({ idempotencyKey: key });
  if (existing) {
    if (existing.requestHash !== requestHash) throw new HttpError(422, 'This request key was already used for a different order.');
    return reply(existing);
  }

  const priced = await priceOrder(req.body);
  const now = new Date();

  for (let attempt = 0; attempt < 5; attempt++) {
    const doc = {
      _id: crypto.randomUUID(),
      reference: makeReference(),
      idempotencyKey: key,
      requestHash,
      customer: priced.customer,
      items: priced.items,
      total: priced.total,
      currency: 'KES',
      paymentStatus: 'pending',
      adminConfirmed: false,
      mpesaReceipt: null,
      checkoutRequestId: null,
      checkoutRequestIds: [],
      stkAttempts: 0,
      lastStkAt: null,
      lastQueryAt: null,
      failureReason: null,
      ip: req.ip,
      createdAt: now,
      updatedAt: now
    };
    try {
      await col.orders.insertOne(doc);
      return reply(doc, 201);
    } catch (e) {
      if (e.code !== 11000) throw e;
      if (e.keyPattern?.idempotencyKey) {
        const again = await col.orders.findOne({ idempotencyKey: key });
        if (again) return reply(again); // concurrent duplicate request
      }
      // reference collision → loop and generate a new one
    }
  }
  throw new HttpError(500, 'Could not create the order. Please try again.');
}));

app.post('/api/mpesa/stkpush', stkLimiter, wrap(async (req, res) => {
  const orderId = str(req.body?.orderId, { required: true, max: 64, field: 'orderId' });
  const phone = normPhone(req.body?.phone);
  if (!phone) throw new HttpError(400, 'Enter a valid Safaricom number, e.g. 0712 345 678.');
  if (!mpesaConfigured()) throw new HttpError(503, 'Payments are not available right now. Please contact us.');

  const order = await col.orders.findOne({ _id: orderId });
  if (!order) throw new HttpError(404, 'Order not found.');
  if (order.paymentStatus === 'paid') return res.json({ alreadyPaid: true, checkoutRequestId: order.checkoutRequestId });
  if (order.paymentStatus === 'cancelled') throw new HttpError(409, 'This order was cancelled.');
  if (order.stkAttempts >= CFG.mpesa.maxAttempts) throw new HttpError(429, 'Too many payment attempts for this order. Please contact us.');

  // Atomically claim the right to send a prompt (prevents double prompts).
  const now = new Date();
  const claimed = await col.orders.findOneAndUpdate(
    {
      _id: orderId,
      paymentStatus: { $in: ['pending', 'failed'] },
      $or: [{ lastStkAt: null }, { lastStkAt: { $lt: new Date(Date.now() - CFG.mpesa.minRetryMs) } }]
    },
    { $set: { paymentStatus: 'pending', failureReason: null, lastStkAt: now, updatedAt: now }, $inc: { stkAttempts: 1 } },
    { returnDocument: 'after' }
  );
  if (!claimed) {
    const cur = await col.orders.findOne({ _id: orderId });
    if (cur?.paymentStatus === 'paid') return res.json({ alreadyPaid: true, checkoutRequestId: cur.checkoutRequestId });
    return res.json({ checkoutRequestId: cur?.checkoutRequestId || null, reused: true }); // a prompt was just sent
  }

  let sent;
  try {
    sent = await sendStkPush(claimed, phone);
  } catch (e) {
    await col.orders.updateOne({ _id: orderId }, { $set: { lastStkAt: null } }); // allow immediate retry
    throw e;
  }

  await col.orders.updateOne({ _id: orderId }, {
    $set: { checkoutRequestId: sent.checkoutRequestId, merchantRequestId: sent.merchantRequestId, payerPhone: phone, updatedAt: new Date() },
    $addToSet: { checkoutRequestIds: sent.checkoutRequestId }
  });
  res.json({ checkoutRequestId: sent.checkoutRequestId });
}));

/* Safaricom → us. Path secret + optional IP allow-list (Daraja callbacks are unsigned). */
app.post('/api/payments/callback/:secret', wrap(async (req, res) => {
  if (!CFG.mpesa.callbackSecret || !safeEqual(req.params.secret, CFG.mpesa.callbackSecret)) {
    return res.status(403).json({ ResultCode: 1, ResultDesc: 'Forbidden' });
  }
  if (CFG.mpesa.callbackIps.length && !CFG.mpesa.callbackIps.includes(req.ip)) {
    console.warn('Callback rejected from IP', req.ip);
    return res.status(403).json({ ResultCode: 1, ResultDesc: 'Forbidden' });
  }
  try { await handleStkCallback(req.body); } catch (e) { console.error('Callback processing error:', e); }
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
}));

app.get('/api/orders/:id/status', statusLimiter, wrap(async (req, res) => {
  let o = await col.orders.findOne({ _id: req.params.id.slice(0, 64) });
  if (!o) throw new HttpError(404, 'Order not found.');

  if (o.paymentStatus === 'pending' && o.checkoutRequestId && CFG.mpesa.reconcile && mpesaConfigured()
      && o.lastStkAt && Date.now() - o.lastStkAt.getTime() > 25_000) {
    try { o = await reconcileOrder(o); } catch (e) { console.warn('Reconcile skipped:', e.message); }
  }

  res.set('Cache-Control', 'no-store').json({
    paymentStatus: o.paymentStatus,
    adminConfirmed: !!o.adminConfirmed,
    mpesaReceipt: o.mpesaReceipt || null,
    reference: o.reference,
    message: o.failureReason || null
  });
}));

/* =====================================================================
   ADMIN API (HTTP Basic auth)
   ===================================================================== */
function requireAdmin(req, res, next) {
  const header = req.get('Authorization') || '';
  let user = '';
  let pass = '';
  if (header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const i = decoded.indexOf(':');
    if (i >= 0) { user = decoded.slice(0, i); pass = decoded.slice(i + 1); }
  }
  // Evaluate both (no short-circuit) so timing doesn't reveal which was wrong.
  const okUser = safeEqual(user, CFG.admin.user);
  const okPass = safeEqual(pass, CFG.admin.pass);
  if (okUser && okPass) { req.admin = { user }; return next(); }
  // No WWW-Authenticate header on purpose: it would trigger the browser's native login popup.
  res.status(401).json({ error: 'Invalid username or password.' });
}

const admin = express.Router();
admin.use(adminAuthLimiter, requireAdmin, express.json({ limit: '4mb' })); // 4 MB: base64 product images
admin.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

/* ---- Orders ---- */
const ORDER_FILTERS = {
  all: () => ({}),
  paid: () => ({ paymentStatus: 'paid', adminConfirmed: false }), // awaiting confirmation
  confirmed: () => ({ adminConfirmed: true }),
  pending: () => ({ paymentStatus: 'pending' }),
  failed: () => ({ paymentStatus: 'failed' }),
  cancelled: () => ({ paymentStatus: 'cancelled' })
};

admin.get('/orders', wrap(async (req, res) => {
  const status = typeof req.query.status === 'string' ? req.query.status : 'all';
  if (!ORDER_FILTERS[status]) throw new HttpError(400, 'Unknown status filter.');
  const orders = await col.orders.find(ORDER_FILTERS[status]()).sort({ createdAt: -1 }).limit(500).toArray();
  res.json({ orders: orders.map(adminOrder) });
}));

admin.post('/orders/:id/confirm', wrap(async (req, res) => {
  const now = new Date();
  const o = await col.orders.findOneAndUpdate(
    { _id: req.params.id, paymentStatus: 'paid', adminConfirmed: false },
    { $set: { adminConfirmed: true, confirmedAt: now, confirmedBy: req.admin.user, updatedAt: now } },
    { returnDocument: 'after' }
  );
  if (o) return res.json({ ok: true, order: adminOrder(o) });

  const cur = await col.orders.findOne({ _id: req.params.id });
  if (!cur) throw new HttpError(404, 'Order not found.');
  if (cur.adminConfirmed) return res.json({ ok: true, order: adminOrder(cur) }); // already confirmed (idempotent)
  throw new HttpError(409, cur.paymentStatus === 'cancelled' ? 'This order was cancelled.' : 'Payment has not been received for this order yet.');
}));

admin.post('/orders/:id/reject', wrap(async (req, res) => {
  const now = new Date();
  const o = await col.orders.findOneAndUpdate(
    { _id: req.params.id, adminConfirmed: false, paymentStatus: { $ne: 'cancelled' } },
    {
      $set: {
        paymentStatus: 'cancelled',
        failureReason: 'This order was cancelled by the store. If money was deducted, contact us with your order reference.',
        cancelledAt: now, cancelledBy: req.admin.user, updatedAt: now
      }
    },
    { returnDocument: 'after' }
  );
  if (o) return res.json({ ok: true, order: adminOrder(o) }); // NB: refunds for paid orders are handled manually in M-Pesa

  const cur = await col.orders.findOne({ _id: req.params.id });
  if (!cur) throw new HttpError(404, 'Order not found.');
  throw new HttpError(409, cur.adminConfirmed ? 'This order was already released and cannot be cancelled.' : 'This order is already cancelled.');
}));

/* ---- Products ---- */
admin.get('/products', wrap(async (req, res) => {
  const products = await col.products.find({}).sort({ category: 1, name: 1 }).toArray();
  res.json({ products: products.map(p => publicProduct(req, p)) });
}));

admin.post('/products', wrap(async (req, res) => {
  const id = crypto.randomUUID();
  const data = sanitizeProduct(req.body);
  const img = parseImageInput(req.body.image, id);
  const now = new Date();
  const doc = { _id: id, ...data, image: img.action === 'keep' ? null : await applyImage(id, img), createdAt: now, updatedAt: now };
  await col.products.insertOne(doc);
  res.status(201).json({ product: publicProduct(req, doc) });
}));

admin.put('/products/:id', wrap(async (req, res) => {
  const id = req.params.id.slice(0, 64);
  const existing = await col.products.findOne({ _id: id });
  if (!existing) throw new HttpError(404, 'Product not found.');
  const data = sanitizeProduct(req.body);
  const img = parseImageInput(req.body.image, id);
  const set = { ...data, updatedAt: new Date() };
  if (img.action !== 'keep') set.image = await applyImage(id, img);
  const updated = await col.products.findOneAndUpdate({ _id: id }, { $set: set }, { returnDocument: 'after' });
  res.json({ product: publicProduct(req, updated) });
}));

admin.delete('/products/:id', wrap(async (req, res) => {
  const id = req.params.id.slice(0, 64);
  const r = await col.products.deleteOne({ _id: id });
  if (!r.deletedCount) throw new HttpError(404, 'Product not found.');
  await col.images.deleteOne({ _id: id });
  res.json({ ok: true });
}));

app.use('/api/admin', admin);

/* =====================================================================
   STATIC FRONTENDS (optional): drop index.html + admin.html in ./public
   ===================================================================== */
const PUBLIC_DIR = path.join(__dirname, 'public');
if (fs.existsSync(PUBLIC_DIR)) {
  app.use(express.static(PUBLIC_DIR, { extensions: ['html'], maxAge: '5m' }));
}
app.get('/', (req, res) => res.json({ name: 'Maricopa Concrete & Allied API', status: 'ok' }));

/* ---------------- 404 + errors ---------------- */
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON.' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request is too large.' });
  const status = Number.isInteger(err.status) && err.status >= 400 && err.status < 600 ? err.status : 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: err.expose || status < 500 ? err.message : 'Something went wrong on our side. Please try again.' });
});

/* =====================================================================
   START / SHUTDOWN
   ===================================================================== */
let server;

async function start() {
  assertConfig();
  await connectDb();
  server = app.listen(CFG.port, () => {
    console.log(`✅ Maricopa API listening on :${CFG.port}  (db: ${CFG.dbName}, M-Pesa: ${mpesaConfigured() ? CFG.mpesa.env : 'not configured'})`);
  });
  server.keepAliveTimeout = 65_000; // above typical proxy idle timeouts
}

async function shutdown(signal) {
  console.log(`\n${signal} received — shutting down…`);
  const force = setTimeout(() => process.exit(1), 10_000);
  force.unref();
  try {
    if (server) await new Promise(r => server.close(r));
    if (client) await client.close();
  } finally {
    process.exit(0);
  }
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', e => console.error('Unhandled rejection:', e));

start().catch(e => {
  console.error('Failed to start:', e.message);
  process.exit(1);
});

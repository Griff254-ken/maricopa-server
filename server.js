'use strict';
/* =====================================================================
   Maricopa Concrete & Allied — backend
   Express + MongoDB Atlas (mongoose) + IntaSend (M-Pesa STK Push)

   ENVIRONMENT VARIABLES (Render → Environment, enter values WITHOUT quotes)
     MONGODB_URI                  required
     ADMIN_USERNAME / ADMIN_PASSWORD   required for admin login
     ALLOWED_ORIGINS              comma-separated site URLs (your frontend)
     PUBLIC_URL                   this server's public URL, e.g. https://xxx.onrender.com
     INTASEND_ENV                 sandbox | production
     INTASEND_PUBLISHABLE_KEY
     INTASEND_SECRET_KEY
     INTASEND_WEBHOOK_CHALLENGE   same value you typed in the IntaSend dashboard
     INTASEND_BASE_URL            optional override of the IntaSend API host
     COLLECTION_PREFIX            optional
     SEED_SAMPLE_PRODUCTS         "true" to seed sample products on an empty DB

   IntaSend webhook URL (set in the IntaSend dashboard):
     https://YOUR-SERVER/api/intasend/webhook
   (https://YOUR-SERVER/api/intasend/webhook/<challenge> also works)

   PUBLIC
     GET  /health
     GET  /api/products
     POST /api/orders                      (needs Idempotency-Key header)
     POST /api/intasend/stkpush
     GET  /api/orders/:id/status
   INTASEND (called by IntaSend)
     POST /api/intasend/webhook
   ADMIN (HTTP Basic auth)
     GET    /api/admin/products
     POST   /api/admin/products
     PUT    /api/admin/products/:id
     DELETE /api/admin/products/:id
     GET    /api/admin/orders?status=all|paid|pending|cancelled|released|review
     POST   /api/admin/orders/:id/confirm
     POST   /api/admin/orders/:id/reject
     DELETE /api/admin/orders/:id            (unreleased orders only)
   ===================================================================== */
require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const env = process.env;
const PORT = Number(env.PORT) || 3000;

/* ---------------- Config ---------------- */
const clean = v => String(v || '').trim().replace(/^["']|["']$/g, '').trim();

const INTASEND = {
  env: clean(env.INTASEND_ENV).toLowerCase() === 'production' ? 'production' : 'sandbox',
  pubKey: clean(env.INTASEND_PUBLISHABLE_KEY),
  secretKey: clean(env.INTASEND_SECRET_KEY),
  webhookChallenge: clean(env.INTASEND_WEBHOOK_CHALLENGE),
  publicUrl: clean(env.PUBLIC_URL).replace(/\/+$/, '')
};
INTASEND.base = clean(env.INTASEND_BASE_URL).replace(/\/+$/, '') ||
  (INTASEND.env === 'production' ? 'https://payment.intasend.com' : 'https://sandbox.intasend.com');
const intasendReady = () =>
  !!(INTASEND.pubKey && INTASEND.secretKey && INTASEND.publicUrl && INTASEND.webhookChallenge);

/* ---------------- Helpers ---------------- */
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const ah = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const sha256 = s => crypto.createHash('sha256').update(s).digest();
const safeEq = (a, b) => crypto.timingSafeEqual(sha256(String(a)), sha256(String(b)));
const str = (v, max) => String(v ?? '').trim().slice(0, max);
const isObjectId = v => typeof v === 'string' && /^[a-f\d]{24}$/i.test(v);

function normPhone(v) {
  v = String(v || '').replace(/[\s\-+()]/g, '');
  if (/^0[17]\d{8}$/.test(v)) return '254' + v.slice(1);
  if (/^254[17]\d{8}$/.test(v)) return v;
  if (/^[17]\d{8}$/.test(v)) return '254' + v;
  return null;
}

const REF_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function newReference() {
  let r = 'MCA-';
  for (let i = 0; i < 8; i++) r += REF_CHARS[crypto.randomInt(REF_CHARS.length)];
  return r;
}

/* ---------------- Models ---------------- */
const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 120 },
  category: { type: String, default: 'Other', trim: true, maxlength: 60 },
  emoji: { type: String, default: '📦', maxlength: 8 },
  unit: { type: String, required: true, trim: true, maxlength: 40 },
  price: { type: Number, required: true, min: 0 },
  description: { type: String, default: '', maxlength: 1000 },
  gradient: { type: [String], default: ['#64748b', '#334155'] },
  image: { type: String, default: '' },
  inStock: { type: Boolean, default: true },
  specs: { type: [[String]], default: [] },
  options: {
    type: [{
      _id: false,
      key: { type: String, required: true },
      choices: [{ _id: false, value: { type: String, required: true }, priceAdjust: { type: Number, default: 0 } }]
    }],
    default: []
  }
}, { timestamps: true });

const OrderSchema = new mongoose.Schema({
  id: { type: String, default: () => crypto.randomUUID(), unique: true, index: true },
  reference: { type: String, unique: true, index: true },
  idempotencyKey: { type: String },
  requestHash: String,
  customer: { name: String, phone: String, location: String },
  items: [{
    _id: false,
    productId: String,
    name: String,
    quantity: Number,
    unitPrice: Number,
    lineTotal: Number,
    options: [{ _id: false, key: String, value: String }],
    note: { type: String, default: '' }
  }],
  total: { type: Number, required: true },
  paymentStatus: { type: String, enum: ['pending', 'paid', 'failed', 'cancelled'], default: 'pending', index: true },
  paymentMessage: { type: String, default: '' },
  failedCode: { type: Number, default: null },
  adminConfirmed: { type: Boolean, default: false },
  confirmedAt: Date,
  confirmedBy: String,
  cancelledAt: Date,
  paidAt: Date,
  paidVia: String,
  mpesaReceipt: { type: String, default: '' },
  intasendReceipt: { type: String, default: '' },
  providerRef: { type: String, default: '' },
  intasendTrackingId: { type: String, default: '' },
  payerPhone: String,
  stkRequestedAt: { type: Date, default: null },
  stkAttempts: { type: Number, default: 0 },
  lastQueryAt: { type: Date, default: null },
  checkoutRequestId: String,
  checkoutRequestIds: { type: [String], index: true },
  invoiceId: String,
  needsReview: { type: Boolean, default: false },
  reviewNote: String
}, { timestamps: true });
OrderSchema.index({ idempotencyKey: 1 }, { unique: true, partialFilterExpression: { idempotencyKey: { $type: 'string' } } });
OrderSchema.index({ createdAt: -1 });

const PREFIX = clean(env.COLLECTION_PREFIX);
const Product = mongoose.model('Product', ProductSchema, PREFIX + 'products');
const Order = mongoose.model('Order', OrderSchema, PREFIX + 'orders');

/* ---------------- Mappers ---------------- */
const receiptOf = o => o.intasendReceipt || o.providerRef || o.mpesaReceipt || '';

const productOut = p => ({
  id: String(p._id),
  name: p.name,
  category: p.category,
  emoji: p.emoji,
  unit: p.unit,
  price: p.price,
  description: p.description,
  gradient: p.gradient,
  image: p.image,
  inStock: p.inStock,
  specs: p.specs || [],
  options: (p.options || []).map(o => ({
    key: o.key,
    choices: (o.choices || []).map(c => ({ value: c.value, priceAdjust: c.priceAdjust || 0 }))
  }))
});

const orderOut = o => ({
  id: o.id,
  reference: o.reference,
  customer: o.customer,
  items: (o.items || []).map(i => ({
    productId: i.productId,
    name: i.name,
    quantity: i.quantity,
    unitPrice: i.unitPrice,
    lineTotal: i.lineTotal,
    options: Object.fromEntries((i.options || []).map(x => [x.key, x.value])),
    note: i.note || ''
  })),
  total: o.total,
  paymentStatus: o.paymentStatus,
  paymentMessage: o.paymentMessage || '',
  failedCode: o.failedCode ?? null,
  adminConfirmed: !!o.adminConfirmed,
  mpesaReceipt: receiptOf(o),
  intasendReceipt: o.intasendReceipt || o.providerRef || '',
  providerRef: o.providerRef || '',
  needsReview: !!o.needsReview,
  reviewNote: o.reviewNote || '',
  createdAt: o.createdAt,
  paidAt: o.paidAt || null,
  confirmedAt: o.confirmedAt || null
});

/* ---------------- Product validation ---------------- */
function cleanProduct(b) {
  if (!b || typeof b !== 'object') throw new HttpError(400, 'Invalid product data.');
  const name = str(b.name, 120);
  if (!name) throw new HttpError(400, 'Product name is required.');
  const unit = str(b.unit, 40);
  if (!unit) throw new HttpError(400, 'Unit is required.');
  const price = Number(b.price);
  if (b.price === '' || b.price === null || !Number.isFinite(price) || price < 0 || price > 1e9)
    throw new HttpError(400, 'Price must be a number of 0 or more.');

  const image = typeof b.image === 'string' ? b.image.trim() : '';
  if (image) {
    const okData = /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(image);
    const okUrl = /^https:\/\/\S+$/i.test(image);
    if (!okData && !okUrl) throw new HttpError(400, 'Image must be an uploaded photo or an https link.');
    if (image.length > 2_000_000) throw new HttpError(413, 'That photo is too large. Try a smaller one.');
  }

  const gradient = Array.isArray(b.gradient) && b.gradient.length === 2 &&
    b.gradient.every(c => typeof c === 'string' && /^#[0-9a-f]{3,8}$/i.test(c))
    ? b.gradient : ['#64748b', '#334155'];

  const specs = (Array.isArray(b.specs) ? b.specs : [])
    .filter(Array.isArray)
    .map(s => [str(s[0], 60), str(s[1], 120)])
    .filter(s => s[0] && s[1])
    .slice(0, 30);

  const options = (Array.isArray(b.options) ? b.options : []).slice(0, 10).map(g => ({
    key: str(g && g.key, 60),
    choices: (Array.isArray(g && g.choices) ? g.choices : []).slice(0, 20).map(c => ({
      value: str(c && c.value, 80),
      priceAdjust: Number.isFinite(Number(c && c.priceAdjust)) ? Number(c.priceAdjust) : 0
    })).filter(c => c.value)
  })).filter(g => g.key && g.choices.length);

  return {
    name, unit, price,
    category: str(b.category, 60) || 'Other',
    description: str(b.description, 1000),
    emoji: str(b.emoji, 8) || '📦',
    inStock: b.inStock !== false && b.inStock !== 'false',
    image, gradient, specs, options
  };
}

/* ---------------- IntaSend client ---------------- */
async function intasendPost(path, payload) {
  const r = await fetch(INTASEND.base + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      Authorization: `Bearer ${INTASEND.secretKey}`
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(25000)
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data };
}

/* IntaSend state strings: PENDING, PROCESSING, COMPLETE, FAILED */
function mapState(s) {
  s = String(s || '').toUpperCase();
  if (['SUCCESS', 'COMPLETE', 'COMPLETED', 'PAID'].includes(s)) return 'paid';
  if (['FAILED', 'CANCELLED', 'CANCELED', 'REVERSED'].includes(s)) return 'failed';
  return 'pending';
}

/* M-Pesa code can arrive under several names depending on the endpoint */
const pickReceipt = b =>
  String(b.mpesa_reference || b.provider_reference || b.providerReference || b.mpesa_receipt || '');

async function intasendStkPush(order, phone) {
  const r = await intasendPost('/api/v1/payment/mpesa-stk-push/', {
    public_key: INTASEND.pubKey,
    phone_number: phone,
    amount: Math.ceil(order.total),
    api_ref: order.reference,
    currency: 'KES'
  });
  if (!r.ok) {
    const d = r.data || {};
    const msg = d.error || d.message || d.detail ||
      (Array.isArray(d.errors) && d.errors[0] && (d.errors[0].detail || d.errors[0].message)) ||
      'IntaSend rejected the request.';
    const err = new Error(String(msg));
    err.data = d;
    err.status = r.status;
    throw err;
  }
  return r.data;
}

async function intasendQuery(order) {
  const id = order.checkoutRequestId;
  if (!id) return null;
  const r = await intasendPost('/api/v1/payment/status/', { invoice_id: id });
  if (!r.ok) {
    console.warn('[intasend status]', r.status, JSON.stringify(r.data));
    return null;
  }
  return r.data;
}

/* ---------------- Payment state changes (single source of truth) ---------------- */
/* Called by the webhook, the status-check fallback and the STK response. */
async function applyPaid(order, { providerRef = '', trackingId = '', value = 0, via }) {
  const receipt = providerRef
    ? { intasendReceipt: providerRef, providerRef, mpesaReceipt: providerRef }
    : {};

  if (order.paymentStatus === 'paid') {
    if (providerRef && !order.intasendReceipt) await Order.updateOne({ id: order.id }, { $set: receipt });
    return 'already-paid';
  }

  if (order.paymentStatus === 'cancelled') {
    await Order.updateOne({ id: order.id }, { $set: {
      ...receipt, paidAt: new Date(), needsReview: true,
      reviewNote: 'Customer paid after the order was cancelled. Refund required.'
    } });
    console.warn('[payment] paid on cancelled order', order.reference, providerRef);
    return 'cancelled-order-paid';
  }

  if (value > 0 && value + 0.001 < order.total) {
    await Order.updateOne({ id: order.id }, { $set: {
      ...receipt, needsReview: true,
      reviewNote: `Underpayment: received KSh ${value}, expected KSh ${order.total}.`
    } });
    console.warn('[payment] underpaid', order.reference, value, order.total);
    return 'underpaid';
  }

  const res = await Order.updateOne(
    { id: order.id, paymentStatus: { $in: ['pending', 'failed'] } },
    { $set: {
      ...receipt,
      paymentStatus: 'paid',
      paidAt: new Date(),
      paidVia: via,
      intasendTrackingId: trackingId || order.intasendTrackingId || '',
      paymentMessage: '',
      failedCode: null
    } }
  );
  if (res.modifiedCount) console.log(`[payment] ${order.reference} marked PAID via ${via} ${providerRef}`);
  return 'paid';
}

async function applyFailed(order, { message, code }) {
  await Order.updateOne(
    { id: order.id, paymentStatus: 'pending' },
    { $set: {
      paymentStatus: 'failed',
      paymentMessage: String(message || 'The payment was not completed.'),
      failedCode: Number.isFinite(code) ? code : null
    } }
  );
}

/* Webhook body: { invoice_id, state, api_ref, mpesa_reference, value, failed_reason, failed_code, challenge, ... } */
async function processWebhook(body) {
  if (!body || typeof body !== 'object') return 'ignored';
  const invoiceId = String(body.invoice_id || body.invoice || '');
  const trackingId = String(body.tracking_id || body.intasend_tracking_id || '');
  const apiRef = String(body.api_ref || '');
  const state = String(body.state || '');
  const value = Number(body.value || body.amount || 0);
  const failedCode = Number(body.failed_code ?? body.failedCode ?? NaN);
  const failedReason = body.failed_reason || body.failedReason || body.message || '';

  console.log('[intasend webhook]', JSON.stringify({ invoiceId, trackingId, apiRef, state, value }));
  if (!invoiceId && !trackingId && !apiRef) return 'ignored';

  /* Find the order by invoice, tracking id, then our own reference (api_ref).
     The api_ref fallback covers a webhook that beats the STK response to the DB. */
  let order = null;
  if (invoiceId) order = await Order.findOne({ checkoutRequestIds: invoiceId });
  if (!order && trackingId) order = await Order.findOne({ checkoutRequestIds: trackingId });
  if (!order && apiRef) order = await Order.findOne({ reference: apiRef });
  if (!order) { console.warn('[intasend webhook] no order for', invoiceId, trackingId, apiRef); return 'no-order'; }

  /* Remember these ids so later lookups and status checks work */
  const ids = [invoiceId, trackingId].filter(Boolean);
  if (ids.length) {
    await Order.updateOne({ id: order.id }, {
      $addToSet: { checkoutRequestIds: { $each: ids } },
      ...(order.checkoutRequestId ? {} : { $set: { checkoutRequestId: invoiceId || trackingId, invoiceId } })
    });
  }

  const mapped = mapState(state);
  if (mapped === 'paid') {
    return applyPaid(order, { providerRef: pickReceipt(body), trackingId, value, via: 'intasend-webhook' });
  }
  if (mapped === 'failed') {
    await applyFailed(order, { message: failedReason, code: failedCode });
    return 'failed';
  }
  return 'pending';
}

/* Fallback for a missed webhook: ask IntaSend directly. Throttled per order. */
async function reconcile(order) {
  if (!intasendReady() || order.paymentStatus !== 'pending' || !order.checkoutRequestId) return;
  if (order.stkRequestedAt && Date.now() - order.stkRequestedAt.getTime() < 12000) return;

  const claimed = await Order.findOneAndUpdate(
    {
      id: order.id, paymentStatus: 'pending',
      $or: [{ lastQueryAt: null }, { lastQueryAt: { $lt: new Date(Date.now() - 8000) } }]
    },
    { $set: { lastQueryAt: new Date() } }, { new: true }
  );
  if (!claimed) return;

  try {
    const data = await intasendQuery(order);
    if (!data) return;
    const inv = data.invoice || data;
    const mapped = mapState(inv.state);
    if (mapped === 'paid') {
      await applyPaid(claimed, { providerRef: pickReceipt(inv), value: Number(inv.value || 0), via: 'intasend-query' });
    } else if (mapped === 'failed') {
      await applyFailed(claimed, {
        message: inv.failed_reason || inv.message,
        code: Number(inv.failed_code ?? NaN)
      });
    }
  } catch (e) { console.warn('[reconcile]', e.message); }
}

/* Background safety net: re-check recent pending payments even if nobody is polling */
async function sweepPending() {
  if (!intasendReady() || mongoose.connection.readyState !== 1) return;
  try {
    const since = new Date(Date.now() - 3 * 3600e3);
    const list = await Order.find({
      paymentStatus: 'pending',
      checkoutRequestId: { $exists: true, $ne: '' },
      stkRequestedAt: { $gte: since }
    }).sort({ stkRequestedAt: -1 }).limit(25);
    for (const o of list) await reconcile(o);
  } catch (e) { console.warn('[sweep]', e.message); }
}

/* ---------------- App ---------------- */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));

const toOrigin = v => {
  v = clean(v);
  if (!v) return '';
  if (v === '*' || v === 'null') return v;
  try { return new URL(/^https?:\/\//i.test(v) ? v : 'https://' + v).origin; } catch { return ''; }
};
const allowed = [...new Set((env.ALLOWED_ORIGINS || '').split(',').map(toOrigin).filter(Boolean))];
const allowAll = !allowed.length || allowed.includes('*');
const originAllowed = origin => !origin || allowAll || allowed.includes(toOrigin(origin));

app.get('/health', cors({ origin: true }), (req, res) => res.json({
  status: 'ok',
  db: mongoose.connection.readyState === 1,
  intasend: intasendReady() ? INTASEND.env : 'not configured',
  yourOrigin: req.get('Origin') || null,
  originAllowed: originAllowed(req.get('Origin'))
}));

app.use(cors({
  origin: (origin, cb) => {
    if (originAllowed(origin)) return cb(null, true);
    console.warn(`[cors] blocked origin "${origin}". Add it to ALLOWED_ORIGINS (current: ${allowed.join(', ')})`);
    cb(new HttpError(403, `This website (${origin}) is not allowed to use the server. Add it to ALLOWED_ORIGINS.`));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key'],
  maxAge: 86400
}));

/* Keep the raw body so optional HMAC signatures can be verified */
app.use(express.json({
  limit: '3mb',
  verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); }
}));

const limiter = (windowMs, limit, message) =>
  rateLimit({ windowMs, limit, standardHeaders: true, legacyHeaders: false, message: { error: message } });
const orderLimiter = limiter(60e3, 20, 'Too many orders. Please wait a minute.');
const stkLimiter = limiter(60e3, 10, 'Too many payment requests. Please wait a minute.');
const statusLimiter = limiter(60e3, 120, 'Too many status checks. Please slow down.');
const adminLimiter = rateLimit({
  windowMs: 15 * 60e3, limit: 60, skipSuccessfulRequests: true, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many failed attempts. Try again in 15 minutes.' }
});

app.get('/', (req, res) => res.json({ name: 'Maricopa server', ok: true }));

/* ---- Public: products ---- */
app.get('/api/products', ah(async (req, res) => {
  const list = await Product.find().sort({ category: 1, name: 1 }).lean();
  res.json({ products: list.map(productOut) });
}));

/* ---- Public: create order ---- */
app.post('/api/orders', orderLimiter, ah(async (req, res) => {
  const key = req.get('Idempotency-Key') || '';
  if (key.length < 8 || key.length > 100) throw new HttpError(400, 'Missing or invalid Idempotency-Key header.');
  const body = req.body || {};
  const requestHash = sha256(JSON.stringify(body)).toString('hex');

  const summary = o => ({ orderId: o.id, reference: o.reference, total: o.total, paymentStatus: o.paymentStatus });
  const prior = await Order.findOne({ idempotencyKey: key });
  if (prior) {
    if (prior.requestHash !== requestHash) throw new HttpError(422, 'This Idempotency-Key was already used with different data.');
    return res.json(summary(prior));
  }

  const c = body.customer || {};
  const name = str(c.name, 100), location = str(c.location, 200), phone = normPhone(c.phone);
  if (name.length < 2) throw new HttpError(400, 'Please enter your name.');
  if (!phone) throw new HttpError(400, 'Enter a valid Safaricom number, e.g. 0712 345 678.');
  if (location.length < 2) throw new HttpError(400, 'Please enter a delivery location.');

  const rawItems = Array.isArray(body.items) ? body.items : [];
  if (!rawItems.length) throw new HttpError(400, 'Your cart is empty.');
  if (rawItems.length > 50) throw new HttpError(400, 'Too many items in one order.');
  const ids = [...new Set(rawItems.map(i => i && i.productId))];
  if (!ids.every(isObjectId)) throw new HttpError(400, 'One of the products in your cart is no longer available.');
  const prods = await Product.find({ _id: { $in: ids } }).lean();
  const byId = new Map(prods.map(p => [String(p._id), p]));

  const items = [];
  let sum = 0;
  for (const it of rawItems) {
    const p = byId.get(String(it.productId));
    if (!p) throw new HttpError(400, 'One of the products in your cart is no longer available.');
    if (!p.inStock) throw new HttpError(400, `${p.name} is currently out of stock.`);

    const step = /m³/.test(p.unit) ? 0.5 : 1;
    const q = Number(it.quantity);
    const ratio = q / step;
    if (!Number.isFinite(q) || q < step || q > 100000 || Math.abs(ratio - Math.round(ratio)) > 1e-9)
      throw new HttpError(400, `Invalid quantity for ${p.name}.`);

    const given = it.options && typeof it.options === 'object' && !Array.isArray(it.options) ? it.options : {};
    const chosen = [];
    let adj = 0;
    for (const g of p.options || []) {
      if (!g.choices || !g.choices.length) continue;
      const want = typeof given[g.key] === 'string' ? given[g.key] : g.choices[0].value;
      const ch = g.choices.find(x => x.value === want);
      if (!ch) throw new HttpError(400, `"${want}" is not available for ${g.key} on ${p.name}. Please refresh the page.`);
      chosen.push({ key: g.key, value: ch.value });
      adj += ch.priceAdjust || 0;
    }
    const unitPrice = Math.max(0, p.price + adj);
    const lineTotal = Math.round(unitPrice * q * 100) / 100;
    sum += lineTotal;
    items.push({
      productId: String(p._id), name: p.name, quantity: q, unitPrice, lineTotal,
      options: chosen, note: str(it.note, 200)
    });
  }
  const total = Math.round(sum);
  if (total <= 0) throw new HttpError(400, 'Order total must be greater than zero.');

  let order;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      order = await Order.create({
        reference: newReference(), idempotencyKey: key, requestHash,
        customer: { name, phone, location }, items, total
      });
      break;
    } catch (e) {
      if (e && e.code === 11000) {
        const dup = await Order.findOne({ idempotencyKey: key });
        if (dup) return res.json(summary(dup));
        continue; // reference collision: try a new one
      }
      throw e;
    }
  }
  if (!order) throw new HttpError(500, 'Could not create the order. Please try again.');
  res.status(201).json(summary(order));
}));

/* ---- Public: IntaSend STK push ---- */
app.post('/api/intasend/stkpush', stkLimiter, ah(async (req, res) => {
  if (!intasendReady()) throw new HttpError(503, 'IntaSend is not configured on the server yet.');
  const { orderId, phone } = req.body || {};
  if (typeof orderId !== 'string' || orderId.length > 64) throw new HttpError(400, 'Missing order.');

  const existing = await Order.findOne({ id: orderId });
  if (!existing) throw new HttpError(404, 'Order not found.');
  let ph = existing.customer.phone;
  if (phone) {
    ph = normPhone(phone);
    if (!ph) throw new HttpError(400, 'Enter a valid Safaricom number, e.g. 0712 345 678.');
  }

  /* Atomic claim: blocks double-taps and paid/cancelled orders */
  const cutoff = new Date(Date.now() - 45000);
  const order = await Order.findOneAndUpdate(
    {
      id: orderId, adminConfirmed: false, paymentStatus: { $in: ['pending', 'failed'] },
      $or: [{ stkRequestedAt: null }, { stkRequestedAt: { $lt: cutoff } }]
    },
    { $set: { paymentStatus: 'pending', paymentMessage: '', failedCode: null, stkRequestedAt: new Date(), payerPhone: ph } },
    { new: true }
  );
  if (!order) {
    const o = await Order.findOne({ id: orderId });
    if (!o) throw new HttpError(404, 'Order not found.');
    if (o.adminConfirmed || o.paymentStatus === 'paid') throw new HttpError(409, 'This order has already been paid.');
    if (o.paymentStatus === 'cancelled') throw new HttpError(409, 'This order was cancelled.');
    throw new HttpError(429, 'A payment prompt was just sent. Please wait a moment before trying again.');
  }

  const release = () => Order.updateOne({ id: orderId }, { $set: { stkRequestedAt: null } }).catch(() => {});
  let r;
  try {
    r = await intasendStkPush(order, ph);
  } catch (e) {
    await release();
    console.error('[intasend stkpush]', e.message, JSON.stringify(e.data || ''));
    throw new HttpError(502, e.message || 'Could not reach IntaSend. Please try again.');
  }

  const invoiceId = String((r.invoice && r.invoice.invoice_id) || r.invoice_id || r.id || '');
  const trackingId = String(r.tracking_id || r.intasend_tracking_id || '');
  const state = String((r.invoice && r.invoice.state) || r.state || '');
  const newIds = [invoiceId, trackingId].filter(Boolean);

  await Order.updateOne({ id: orderId }, {
    $set: { checkoutRequestId: invoiceId || trackingId, invoiceId, intasendTrackingId: trackingId },
    ...(newIds.length ? { $addToSet: { checkoutRequestIds: { $each: newIds } } } : {}),
    $inc: { stkAttempts: 1 }
  });

  if (mapState(state) === 'paid') {
    const fresh = await Order.findOne({ id: orderId });
    if (fresh) await applyPaid(fresh, { providerRef: pickReceipt(r.invoice || r), trackingId, via: 'intasend-stk' });
  }

  res.json({
    ok: true,
    message: 'Prompt sent. Enter your M-Pesa PIN on your phone.',
    checkoutRequestId: invoiceId || trackingId
  });
}));

/* ---- IntaSend webhook ---- */
function verifyIntasendWebhook(req) {
  /* 1. challenge in the URL path */
  if (req.params.secret && INTASEND.webhookChallenge && safeEq(req.params.secret, INTASEND.webhookChallenge)) return true;
  /* 2. challenge in the body (what IntaSend normally sends) */
  const bodyChallenge = req.body && (req.body.challenge || req.body.secret);
  if (bodyChallenge && INTASEND.webhookChallenge && safeEq(clean(bodyChallenge), INTASEND.webhookChallenge)) return true;
  /* 3. optional HMAC signature header */
  const sig = req.get('X-IntaSend-Signature');
  if (sig && INTASEND.secretKey) {
    const raw = req.rawBody || JSON.stringify(req.body || {});
    const expected = crypto.createHmac('sha256', INTASEND.secretKey).update(raw).digest('hex');
    try { return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex')); }
    catch { return false; }
  }
  return false;
}

const webhookHandler = ah(async (req, res) => {
  if (!verifyIntasendWebhook(req)) {
    console.warn('[intasend webhook] challenge/signature mismatch. Check INTASEND_WEBHOOK_CHALLENGE matches the dashboard exactly.');
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  try {
    await processWebhook(req.body);
  } catch (e) {
    /* Reply 500 so IntaSend retries instead of the payment being lost */
    console.error('[intasend webhook] processing failed', e);
    return res.status(500).json({ error: 'Temporary error, please retry.' });
  }
  res.json({ ok: true });
});
app.post('/api/intasend/webhook', webhookHandler);
app.post('/api/intasend/webhook/:secret', webhookHandler);

/* ---- Public: order status (polled by the storefront) ---- */
app.get('/api/orders/:id/status', statusLimiter, ah(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const id = req.params.id;
  if (typeof id !== 'string' || id.length > 64) throw new HttpError(404, 'Order not found.');
  let o = await Order.findOne({ id });
  if (!o) throw new HttpError(404, 'Order not found.');
  if (o.paymentStatus === 'pending') {
    await reconcile(o);
    o = await Order.findOne({ id });
  }
  const paid = o.paymentStatus === 'paid';
  res.json({
    orderId: o.id,
    reference: o.reference,
    paymentStatus: o.paymentStatus,
    adminConfirmed: !!o.adminConfirmed,
    mpesaReceipt: paid ? receiptOf(o) : '',
    intasendReceipt: paid ? (o.intasendReceipt || o.providerRef || '') : '',
    message: o.paymentMessage || '',
    failed_code: o.failedCode ?? null
  });
}));

/* ---- Admin auth ---- */
function adminAuth(req, res, next) {
  const user = clean(env.ADMIN_USERNAME), pass = clean(env.ADMIN_PASSWORD);
  if (!user || !pass) return next(new HttpError(503, 'Admin login is not configured on the server.'));
  const h = req.get('Authorization') || '';
  if (!h.startsWith('Basic ')) return next(new HttpError(401, 'Authentication required.'));
  let decoded = '';
  try { decoded = Buffer.from(h.slice(6), 'base64').toString('utf8'); } catch { /* ignore */ }
  const i = decoded.indexOf(':');
  const u = i < 0 ? '' : decoded.slice(0, i), p = i < 0 ? '' : decoded.slice(i + 1);
  const okU = safeEq(u, user), okP = safeEq(p, pass);
  if (!(okU && okP)) return next(new HttpError(401, 'Wrong username or password.'));
  req.admin = u;
  next();
}
app.use('/api/admin', adminLimiter, adminAuth);

/* ---- Admin: products ---- */
app.get('/api/admin/products', ah(async (req, res) => {
  const list = await Product.find().sort({ category: 1, name: 1 }).lean();
  res.json({ products: list.map(productOut) });
}));
app.post('/api/admin/products', ah(async (req, res) => {
  const p = await Product.create(cleanProduct(req.body));
  res.status(201).json({ product: productOut(p.toObject()) });
}));
app.put('/api/admin/products/:id', ah(async (req, res) => {
  if (!isObjectId(req.params.id)) throw new HttpError(404, 'Product not found.');
  const p = await Product.findByIdAndUpdate(req.params.id, { $set: cleanProduct(req.body) }, { new: true, runValidators: true }).lean();
  if (!p) throw new HttpError(404, 'Product not found.');
  res.json({ product: productOut(p) });
}));
app.delete('/api/admin/products/:id', ah(async (req, res) => {
  if (!isObjectId(req.params.id)) throw new HttpError(404, 'Product not found.');
  const r = await Product.deleteOne({ _id: req.params.id });
  if (!r.deletedCount) throw new HttpError(404, 'Product not found.');
  res.json({ ok: true });
}));

/* ---- Admin: orders ---- */
const ORDER_FILTERS = {
  all: {},
  paid: { paymentStatus: 'paid', adminConfirmed: false },
  pending: { paymentStatus: { $in: ['pending', 'failed'] } },
  cancelled: { paymentStatus: 'cancelled' },
  released: { adminConfirmed: true },
  review: { needsReview: true }
};
app.get('/api/admin/orders', ah(async (req, res) => {
  res.set('Cache-Control', 'no-store');
  const f = ORDER_FILTERS[String(req.query.status || 'all')] || ORDER_FILTERS.all;
  const list = await Order.find(f).sort({ createdAt: -1 }).limit(500).lean();
  res.json({ orders: list.map(orderOut) });
}));
app.post('/api/admin/orders/:id/confirm', ah(async (req, res) => {
  const o = await Order.findOneAndUpdate(
    { id: req.params.id, paymentStatus: 'paid', adminConfirmed: false },
    { $set: { adminConfirmed: true, confirmedAt: new Date(), confirmedBy: req.admin } },
    { new: true }
  ).lean();
  if (o) return res.json({ order: orderOut(o) });
  const cur = await Order.findOne({ id: req.params.id }).lean();
  if (!cur) throw new HttpError(404, 'Order not found.');
  if (cur.adminConfirmed) throw new HttpError(409, 'This order has already been released.');
  if (cur.paymentStatus === 'cancelled') throw new HttpError(409, 'This order was cancelled.');
  throw new HttpError(409, 'The customer has not paid yet.');
}));
app.post('/api/admin/orders/:id/reject', ah(async (req, res) => {
  const o = await Order.findOneAndUpdate(
    { id: req.params.id, adminConfirmed: false, paymentStatus: { $ne: 'cancelled' } },
    { $set: { paymentStatus: 'cancelled', cancelledAt: new Date(), paymentMessage: 'This order was cancelled by the store.' } },
    { new: true }
  ).lean();
  if (o) return res.json({ order: orderOut(o) });
  const cur = await Order.findOne({ id: req.params.id }).lean();
  if (!cur) throw new HttpError(404, 'Order not found.');
  if (cur.adminConfirmed) throw new HttpError(409, 'This order has already been released and cannot be cancelled.');
  throw new HttpError(409, 'This order is already cancelled.');
}));
/* Delete an unreleased order (released orders are kept as a record) */
app.delete('/api/admin/orders/:id', ah(async (req, res) => {
  const cur = await Order.findOne({ id: req.params.id }).lean();
  if (!cur) throw new HttpError(404, 'Order not found.');
  if (cur.adminConfirmed) throw new HttpError(409, 'Released orders cannot be deleted. They are kept as a record.');
  await Order.deleteOne({ id: req.params.id });
  res.json({ ok: true });
}));

/* ---- 404 + errors ---- */
app.use((req, res) => res.status(404).json({ error: 'Not found.' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON.' });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'The request is too large.' });
  if (err && err.name === 'ValidationError') return res.status(400).json({ error: err.message });
  console.error('[error]', err);
  res.status(500).json({ error: 'Something went wrong on the server.' });
});

/* ---------------- Start ---------------- */
const SAMPLE = [
  { name: 'Ready-mix concrete C25', category: 'Concrete', emoji: '🚛', unit: 'per m³', price: 14500,
    description: 'Ready-mix concrete for slabs, beams and columns, delivered to site.',
    specs: [['Grade', 'C25'], ['Aggregate', '20 mm']],
    options: [{ key: 'Slump', choices: [{ value: '75–100 mm', priceAdjust: 0 }, { value: '100–150 mm', priceAdjust: 300 }] }] },
  { name: 'Portland cement 50 kg', category: 'Cement', emoji: '🧱', unit: 'per bag', price: 850,
    description: 'General-purpose Portland cement, 50 kg bag.', specs: [['Weight', '50 kg'], ['Class', '42.5N']], options: [] },
  { name: 'Building sand', category: 'Aggregates', emoji: '⛰️', unit: 'per m³', price: 3200,
    description: 'Clean river sand for plaster and mortar.', specs: [], options: [] },
  { name: 'Hollow block 6"', category: 'Blocks', emoji: '🧱', unit: 'per block', price: 75,
    description: 'Machine-cut hollow concrete block.', specs: [['Size', '6 inch']], options: [] }
];

async function main() {
  if (!env.MONGODB_URI) { console.error('MONGODB_URI is required.'); process.exit(1); }
  if (!env.ADMIN_USERNAME || !env.ADMIN_PASSWORD) console.warn('⚠️  ADMIN_USERNAME / ADMIN_PASSWORD not set: admin login is disabled.');
  else if (clean(env.ADMIN_PASSWORD).length < 10) console.warn('⚠️  ADMIN_PASSWORD is short. Use at least 12 characters.');
  if (!intasendReady()) console.warn('⚠️  IntaSend is not fully configured (need INTASEND_PUBLISHABLE_KEY, INTASEND_SECRET_KEY, INTASEND_WEBHOOK_CHALLENGE, PUBLIC_URL). Payments disabled.');
  console.log('🌐 Allowed origins:', allowAll ? 'ANY' : allowed.join(', '));
  console.log('💳 IntaSend API:', INTASEND.base);
  if (!allowed.length) console.warn('⚠️  ALLOWED_ORIGINS is empty: any website can call this API. Set it in production.');

  await mongoose.connect(env.MONGODB_URI, { serverSelectionTimeoutMS: 20000 });
  await Promise.all([Product.init(), Order.init()]);
  console.log('✅ MongoDB connected');

  if (env.SEED_SAMPLE_PRODUCTS === 'true' && (await Product.countDocuments()) === 0) {
    await Product.insertMany(SAMPLE);
    console.log('🌱 Seeded sample products');
  }

  const server = app.listen(PORT, '0.0.0.0', () =>
    console.log(`🚀 Server listening on :${PORT} (IntaSend: ${intasendReady() ? INTASEND.env : 'off'})`));

  const sweeper = setInterval(sweepPending, 60e3);
  sweeper.unref();

  const stop = () => {
    clearInterval(sweeper);
    server.close(() => mongoose.connection.close(false).then(() => process.exit(0)));
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));
main().catch(e => { console.error('Failed to start:', e.message); process.exit(1); });

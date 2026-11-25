'use strict';

require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const env = process.env;
const PORT = Number(env.PORT) || 3000;

const DARAJA = {
  env: (env.DARAJA_ENV || 'sandbox').toLowerCase() === 'production' ? 'production' : 'sandbox',
  key: env.DARAJA_CONSUMER_KEY || '',
  secret: env.DARAJA_CONSUMER_SECRET || '',
  shortcode: env.DARAJA_SHORTCODE || '',
  passkey: env.DARAJA_PASSKEY || '',
  txType: env.DARAJA_TRANSACTION_TYPE || 'CustomerPayBillOnline', // or CustomerBuyGoodsOnline
  partyB: env.DARAJA_PARTYB || env.DARAJA_SHORTCODE || '',        // till number for Buy Goods
  publicUrl: (env.PUBLIC_URL || '').replace(/\/+$/, ''),
  cbSecret: env.CALLBACK_SECRET || ''
};
DARAJA.base = DARAJA.env === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';
const darajaReady = () =>
  !!(DARAJA.key && DARAJA.secret && DARAJA.shortcode && DARAJA.passkey && DARAJA.publicUrl && DARAJA.cbSecret);

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
function newReference() { // "MCA-" + 8 chars = 12 chars (fits Daraja AccountReference limit)
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
  adminConfirmed: { type: Boolean, default: false },
  confirmedAt: Date,
  confirmedBy: String,
  cancelledAt: Date,
  paidAt: Date,
  paidVia: String,
  mpesaReceipt: { type: String, default: '' },
  payerPhone: String,
  // Daraja bookkeeping
  stkRequestedAt: { type: Date, default: null },
  lastQueryAt: { type: Date, default: null },
  stkAttempts: { type: Number, default: 0 },
  merchantRequestId: String,
  checkoutRequestId: String,
  checkoutRequestIds: { type: [String], index: true },
  needsReview: { type: Boolean, default: false },
  reviewNote: String
}, { timestamps: true });
OrderSchema.index({ idempotencyKey: 1 }, { unique: true, partialFilterExpression: { idempotencyKey: { $type: 'string' } } });
OrderSchema.index({ createdAt: -1 });

const Product = mongoose.model('Product', ProductSchema);
const Order = mongoose.model('Order', OrderSchema);

/* ---------------- Mappers ---------------- */
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
  adminConfirmed: !!o.adminConfirmed,
  mpesaReceipt: o.mpesaReceipt || '',
  needsReview: !!o.needsReview,
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

  let image = typeof b.image === 'string' ? b.image.trim() : '';
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

/* ---------------- Daraja ---------------- */
let tokenCache = { token: null, exp: 0 };
async function darajaToken(force) {
  if (!force && tokenCache.token && Date.now() < tokenCache.exp) return tokenCache.token;
  const basic = Buffer.from(`${DARAJA.key}:${DARAJA.secret}`).toString('base64');
  const r = await fetch(`${DARAJA.base}/oauth/v1/generate?grant_type=client_credentials`, {
    headers: { Authorization: `Basic ${basic}` },
    signal: AbortSignal.timeout(20000)
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.access_token) throw new Error('Daraja auth failed (' + r.status + ')');
  tokenCache = { token: d.access_token, exp: Date.now() + (Number(d.expires_in) || 3599) * 1000 - 60000 };
  return tokenCache.token;
}
async function darajaPost(path, payload, retried) {
  const token = await darajaToken(!!retried);
  const r = await fetch(DARAJA.base + path, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(25000)
  });
  if (r.status === 401 && !retried) return darajaPost(path, payload, true);
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data };
}
const darajaTimestamp = () => new Date(Date.now() + 3 * 3600e3).toISOString().replace(/\D/g, '').slice(0, 14); // EAT
const darajaPassword = ts => Buffer.from(DARAJA.shortcode + DARAJA.passkey + ts).toString('base64');

function friendlyFailure(code, desc) {
  switch (Number(code)) {
    case 1032: return 'You cancelled the M-Pesa request.';
    case 1: return 'Insufficient M-Pesa balance.';
    case 2001: return 'Wrong M-Pesa PIN entered.';
    case 1037: return 'The M-Pesa prompt timed out. Please try again.';
    case 1025: case 1019: return 'M-Pesa could not send the prompt. Please try again.';
    default: return desc || 'The M-Pesa payment was not completed.';
  }
}

/* Handles Safaricom's callback body */
async function processCallback(body) {
  const cb = body && body.Body && body.Body.stkCallback;
  if (!cb || !cb.CheckoutRequestID) return;
  const checkoutId = String(cb.CheckoutRequestID);
  const code = Number(cb.ResultCode);
  const order = await Order.findOne({ checkoutRequestIds: checkoutId });
  if (!order) { console.warn('[callback] no order for', checkoutId); return; }

  if (code === 0) {
    const items = (cb.CallbackMetadata && cb.CallbackMetadata.Item) || [];
    const get = n => (items.find(i => i.Name === n) || {}).Value;
    const receipt = String(get('MpesaReceiptNumber') || '');
    const amount = Number(get('Amount'));
    const phone = get('PhoneNumber') != null ? String(get('PhoneNumber')) : undefined;

    if (order.paymentStatus === 'paid') {
      if (!order.mpesaReceipt && receipt) await Order.updateOne({ id: order.id }, { $set: { mpesaReceipt: receipt } });
      return;
    }
    if (order.paymentStatus === 'cancelled') {
      await Order.updateOne({ id: order.id }, { $set: {
        mpesaReceipt: receipt, paidAt: new Date(), needsReview: true,
        reviewNote: 'Customer paid after the order was cancelled. Refund required.'
      } });
      console.warn('[callback] payment on cancelled order', order.reference, receipt);
      return;
    }
    if (Number.isFinite(amount) && amount + 0.001 < order.total) {
      await Order.updateOne({ id: order.id }, { $set: {
        mpesaReceipt: receipt, needsReview: true,
        reviewNote: `Underpayment: received KSh ${amount}, expected KSh ${order.total}.`
      } });
      console.warn('[callback] amount mismatch', order.reference, amount, order.total);
      return;
    }
    await Order.updateOne(
      { id: order.id, paymentStatus: { $in: ['pending', 'failed'] } },
      { $set: { paymentStatus: 'paid', paidAt: new Date(), paidVia: 'callback', mpesaReceipt: receipt, payerPhone: phone || order.payerPhone, paymentMessage: '' } }
    );
  } else {
    // only fail the order if this was the latest attempt
    await Order.updateOne(
      { id: order.id, paymentStatus: 'pending', checkoutRequestId: checkoutId },
      { $set: { paymentStatus: 'failed', paymentMessage: friendlyFailure(code, cb.ResultDesc) } }
    );
  }
}

/* If the callback never arrives, ask Daraja directly */
async function reconcile(order) {
  if (!darajaReady() || order.paymentStatus !== 'pending' || !order.checkoutRequestId) return;
  const now = Date.now();
  if (!order.stkRequestedAt || now - order.stkRequestedAt.getTime() < 25000) return;
  const claimed = await Order.findOneAndUpdate(
    { id: order.id, paymentStatus: 'pending', $or: [{ lastQueryAt: null }, { lastQueryAt: { $lt: new Date(now - 15000) } }] },
    { $set: { lastQueryAt: new Date() } }, { new: true }
  );
  if (!claimed) return;
  try {
    const ts = darajaTimestamp();
    const r = await darajaPost('/mpesa/stkpushquery/v1/query', {
      BusinessShortCode: DARAJA.shortcode,
      Password: darajaPassword(ts),
      Timestamp: ts,
      CheckoutRequestID: order.checkoutRequestId
    });
    const code = r.data && r.data.ResultCode;
    if (code === undefined || code === null || code === '') return; // still processing
    if (String(code) === '0') {
      await Order.updateOne(
        { id: order.id, paymentStatus: 'pending', checkoutRequestId: order.checkoutRequestId },
        { $set: { paymentStatus: 'paid', paidAt: new Date(), paidVia: 'query' } }
      );
    } else {
      await Order.updateOne(
        { id: order.id, paymentStatus: 'pending', checkoutRequestId: order.checkoutRequestId },
        { $set: { paymentStatus: 'failed', paymentMessage: friendlyFailure(code, r.data.ResultDesc) } }
      );
    }
  } catch (e) { console.warn('[reconcile]', e.message); }
}

/* ---------------- App ---------------- */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet());

const allowed = (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || !allowed.length || allowed.includes(origin)) return cb(null, true);
    cb(new HttpError(403, 'This website is not allowed to use the server (add it to ALLOWED_ORIGINS).'));
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key'],
  maxAge: 86400
}));
app.use(express.json({ limit: '3mb' }));

const limiter = (windowMs, limit, message) =>
  rateLimit({ windowMs, limit, standardHeaders: true, legacyHeaders: false, message: { error: message } });
const orderLimiter = limiter(60e3, 20, 'Too many orders. Please wait a minute.');
const stkLimiter = limiter(60e3, 10, 'Too many payment requests. Please wait a minute.');
const statusLimiter = limiter(60e3, 60, 'Too many status checks. Please slow down.');
const adminLimiter = rateLimit({
  windowMs: 15 * 60e3, limit: 60, skipSuccessfulRequests: true, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many failed attempts. Try again in 15 minutes.' }
});

/* ---- Health ---- */
app.get('/', (req, res) => res.json({ name: 'Maricopa server', ok: true }));
app.get('/health', (req, res) => res.json({
  status: 'ok',
  db: mongoose.connection.readyState === 1,
  mpesa: darajaReady() ? DARAJA.env : 'not configured'
}));

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

  // customer
  const c = body.customer || {};
  const name = str(c.name, 100), location = str(c.location, 200), phone = normPhone(c.phone);
  if (name.length < 2) throw new HttpError(400, 'Please enter your name.');
  if (!phone) throw new HttpError(400, 'Enter a valid Safaricom number, e.g. 0712 345 678.');
  if (location.length < 2) throw new HttpError(400, 'Please enter a delivery location.');

  // items
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
        if (dup) return res.json(summary(dup));      // concurrent duplicate request
        continue;                                     // reference collision, retry
      }
      throw e;
    }
  }
  if (!order) throw new HttpError(500, 'Could not create the order. Please try again.');
  res.status(201).json(summary(order));
}));

/* ---- Public: STK push ---- */
app.post('/api/mpesa/stkpush', stkLimiter, ah(async (req, res) => {
  if (!darajaReady()) throw new HttpError(503, 'M-Pesa is not configured on the server yet.');
  const { orderId, phone } = req.body || {};
  if (typeof orderId !== 'string' || orderId.length > 64) throw new HttpError(400, 'Missing order.');

  const existing = await Order.findOne({ id: orderId });
  if (!existing) throw new HttpError(404, 'Order not found.');
  let ph = existing.customer.phone;
  if (phone) {
    ph = normPhone(phone);
    if (!ph) throw new HttpError(400, 'Enter a valid Safaricom number, e.g. 0712 345 678.');
  }

  // atomically claim the right to send a prompt (stops double-taps / double prompts)
  const cutoff = new Date(Date.now() - 45000);
  const order = await Order.findOneAndUpdate(
    {
      id: orderId, adminConfirmed: false, paymentStatus: { $in: ['pending', 'failed'] },
      $or: [{ stkRequestedAt: null }, { stkRequestedAt: { $lt: cutoff } }]
    },
    { $set: { paymentStatus: 'pending', paymentMessage: '', stkRequestedAt: new Date(), stkAmount: undefined, payerPhone: ph } },
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
  const ts = darajaTimestamp();
  let r;
  try {
    r = await darajaPost('/mpesa/stkpush/v1/processrequest', {
      BusinessShortCode: DARAJA.shortcode,
      Password: darajaPassword(ts),
      Timestamp: ts,
      TransactionType: DARAJA.txType,
      Amount: Math.ceil(order.total),
      PartyA: ph,
      PartyB: DARAJA.partyB,
      PhoneNumber: ph,
      CallBackURL: `${DARAJA.publicUrl}/api/pay/callback/${DARAJA.cbSecret}`,
      AccountReference: order.reference.slice(0, 12),
      TransactionDesc: 'Materials'
    });
  } catch (e) {
    await release();
    console.error('[stkpush]', e.message);
    throw new HttpError(502, 'Could not reach M-Pesa. Please try again.');
  }
  if (!r.ok || String(r.data.ResponseCode) !== '0') {
    await release();
    console.error('[stkpush] rejected', r.status, JSON.stringify(r.data));
    throw new HttpError(502, r.data.errorMessage || r.data.CustomerMessage || r.data.ResponseDescription || 'M-Pesa rejected the request.');
  }
  await Order.updateOne({ id: orderId }, {
    $set: { merchantRequestId: r.data.MerchantRequestID, checkoutRequestId: r.data.CheckoutRequestID },
    $addToSet: { checkoutRequestIds: r.data.CheckoutRequestID },
    $inc: { stkAttempts: 1 }
  });
  res.json({ ok: true, message: r.data.CustomerMessage || 'Prompt sent.', checkoutRequestId: r.data.CheckoutRequestID });
}));

/* ---- Daraja callback ---- */
app.post('/api/pay/callback/:secret', ah(async (req, res) => {
  if (!DARAJA.cbSecret || !safeEq(req.params.secret, DARAJA.cbSecret)) return res.status(404).json({ error: 'Not found.' });
  try { await processCallback(req.body); }
  catch (e) { console.error('[callback]', e); }
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
}));

/* ---- Public: order status (polled by the storefront) ---- */
app.get('/api/orders/:id/status', statusLimiter, ah(async (req, res) => {
  const id = req.params.id;
  if (typeof id !== 'string' || id.length > 64) throw new HttpError(404, 'Order not found.');
  let o = await Order.findOne({ id });
  if (!o) throw new HttpError(404, 'Order not found.');
  if (o.paymentStatus === 'pending') {
    await reconcile(o);
    o = await Order.findOne({ id });
  }
  res.json({
    orderId: o.id,
    reference: o.reference,
    paymentStatus: o.paymentStatus,
    adminConfirmed: !!o.adminConfirmed,
    mpesaReceipt: o.paymentStatus === 'paid' ? (o.mpesaReceipt || '') : '',
    message: o.paymentMessage || ''
  });
}));

/* ---- Admin auth ---- */
function adminAuth(req, res, next) {
  const user = env.ADMIN_USERNAME, pass = env.ADMIN_PASSWORD;
  if (!user || !pass) return next(new HttpError(503, 'Admin login is not configured on the server.'));
  const h = req.get('Authorization') || '';
  if (!h.startsWith('Basic ')) return next(new HttpError(401, 'Authentication required.'));
  let decoded = '';
  try { decoded = Buffer.from(h.slice(6), 'base64').toString('utf8'); } catch { /* ignore */ }
  const i = decoded.indexOf(':');
  const u = i < 0 ? '' : decoded.slice(0, i), p = i < 0 ? '' : decoded.slice(i + 1);
  const okU = safeEq(u, user), okP = safeEq(p, pass); // evaluate both
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
  released: { adminConfirmed: true }
};
app.get('/api/admin/orders', ah(async (req, res) => {
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
  else if (env.ADMIN_PASSWORD.length < 10) console.warn('⚠️  ADMIN_PASSWORD is short. Use at least 12 characters.');
  if (!darajaReady()) console.warn('⚠️  Daraja is not fully configured (need DARAJA_CONSUMER_KEY/SECRET/SHORTCODE/PASSKEY, PUBLIC_URL, CALLBACK_SECRET). Payments disabled.');
  if (!allowed.length) console.warn('⚠️  ALLOWED_ORIGINS is empty: any website can call this API. Set it in production.');

  await mongoose.connect(env.MONGODB_URI, { serverSelectionTimeoutMS: 20000 });
  await Promise.all([Product.init(), Order.init()]);
  console.log('✅ MongoDB connected');

  if (env.SEED_SAMPLE_PRODUCTS === 'true' && (await Product.countDocuments()) === 0) {
    await Product.insertMany(SAMPLE);
    console.log('🌱 Seeded sample products');
  }

  const server = app.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server listening on :${PORT} (M-Pesa: ${darajaReady() ? DARAJA.env : 'off'})`));
  const stop = () => server.close(() => mongoose.connection.close(false).then(() => process.exit(0)));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
process.on('unhandledRejection', e => console.error('[unhandledRejection]', e));
main().catch(e => { console.error('Failed to start:', e.message); process.exit(1); });

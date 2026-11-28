const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const admin = require("firebase-admin");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

const PORT = process.env.PORT || 10000;
const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || "sudip-industry";
const CASHFREE_ENV = String(process.env.CASHFREE_ENV || "PRODUCTION").toUpperCase();
const CASHFREE_BASE = CASHFREE_ENV === "SANDBOX" ? "https://sandbox.cashfree.com/pg" : "https://api.cashfree.com/pg";
const CASHFREE_API_VERSION = process.env.CASHFREE_API_VERSION || "2025-01-01";
const SITE_URL = process.env.SITE_URL || "https://sudip-industry.onrender.com";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://sudip-industry.onrender.com";
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "sudippramanick66@gmail.com").toLowerCase();

// ===============================
// FIREBASE INITIALIZATION
// ===============================
function initFirebase() {
  if (admin.apps.length) return;
  const secretPath = process.env.GOOGLE_APPLICATION_CREDENTIALS ||
    (fs.existsSync("/etc/secrets/firebase-service-account.json") ? "/etc/secrets/firebase-service-account.json" : "");
  if (secretPath) {
    const serviceAccount = JSON.parse(fs.readFileSync(secretPath, "utf8"));
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount), projectId: PROJECT_ID });
  } else {
    admin.initializeApp({ credential: admin.credential.applicationDefault(), projectId: PROJECT_ID });
  }
}
initFirebase();
const db = admin.firestore();

// ===============================
// CORS
// ===============================
const allowedOrigins = new Set([
  FRONTEND_ORIGIN,
  SITE_URL,
  "https://sudip-industry.github.io"
].filter(Boolean));
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && !allowedOrigins.has(origin)) return res.status(403).json({ error: "Origin not allowed" });
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ===============================
// CASHFREE WEBHOOK (RAW BODY)
// ===============================
app.post("/api/payments/webhook", express.raw({ type: "application/json", limit: "1mb" }), async (req, res) => {
  try {
    const signature = req.get("x-webhook-signature") || "";
    const timestamp = req.get("x-webhook-timestamp") || "";
    const secret = process.env.CASHFREE_SECRET_KEY;
    if (!secret || !signature || !timestamp || !Buffer.isBuffer(req.body)) return res.status(400).send("Invalid webhook");
    const expected = crypto.createHmac("sha256", secret).update(timestamp + req.body.toString("utf8")).digest("base64");
    const a = Buffer.from(signature), b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401).send("Invalid signature");
    const event = JSON.parse(req.body.toString("utf8"));
    const orderId = event?.data?.order?.order_id;
    const paymentStatus = event?.data?.payment?.cf_payment_status;
    if (orderId && paymentStatus === "SUCCESS") await confirmPaidOrder(orderId);
    return res.status(200).json({ received: true });
  } catch (err) {
    console.error("Webhook error:", err.message);
    return res.status(500).send("Webhook processing failed");
  }
});

app.use(express.json({ limit: "250kb" }));

// ===============================
// AUTHENTICATION
// ===============================
async function requireUser(req, res, next) {
  try {
    const match = (req.get("authorization") || "").match(/^Bearer (.+)$/i);
    if (!match) return res.status(401).json({ error: "Please sign in first." });
    req.user = await admin.auth().verifyIdToken(match[1]);
    next();
  } catch (_) {
    return res.status(401).json({ error: "Your sign-in session expired. Please sign in again." });
  }
}
async function requireAdmin(req, res, next) {
  try {
    if (!req.user || String(req.user.email || "").toLowerCase() !== ADMIN_EMAIL) {
      return res.status(403).json({ error: "Admin access required." });
    }
    const snap = await db.collection("admins").doc(req.user.uid).get();
    if (!snap.exists || snap.data()?.active !== true) return res.status(403).json({ error: "Admin access is not active." });
    next();
  } catch (e) {
    console.error("Admin verification failed:", e.message);
    return res.status(403).json({ error: "Could not verify Admin access." });
  }
}

// ===============================
// CASHFREE HELPERS
// ===============================
function cashfreeHeaders() {
  const appId = process.env.CASHFREE_APP_ID, secret = process.env.CASHFREE_SECRET_KEY;
  if (!appId || !secret) throw new Error("Cashfree credentials are not configured on the server.");
  return { "Content-Type": "application/json", "x-client-id": appId, "x-client-secret": secret, "x-api-version": CASHFREE_API_VERSION };
}
async function cashfreeRequest(pathname, options = {}) {
  const response = await fetch(CASHFREE_BASE + pathname, { ...options, headers: { ...cashfreeHeaders(), ...(options.headers || {}) } });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error("Cashfree API error:", response.status, JSON.stringify(body).slice(0, 1200));
    throw new Error("Cashfree could not process the payment request.");
  }
  return body;
}
function cleanText(v, max) { return typeof v === "string" ? v.trim().slice(0, max) : ""; }
function validPhone(v) { return /^[6-9][0-9]{9}$/.test(v); }
function makeOrderId() { return "SI" + crypto.randomBytes(16).toString("hex").toUpperCase(); }

// ===============================
// MEMBER MANAGEMENT SECURITY
// Aadhaar/PAN are encrypted and stored only in memberPrivate.
// Set MEMBER_ENCRYPTION_KEY to exactly 64 hexadecimal characters (32 bytes).
// ===============================
function memberEncryptionKey() {
  const raw = String(process.env.MEMBER_ENCRYPTION_KEY || "").trim();
  if (!/^[a-fA-F0-9]{64}$/.test(raw)) throw new Error("MEMBER_ENCRYPTION_KEY is not configured correctly (use 64 hex characters). ");
  return Buffer.from(raw, "hex");
}
function encryptMemberValue(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", memberEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(value), "utf8"), cipher.final()]);
  return { iv: iv.toString("base64"), data: encrypted.toString("base64"), tag: cipher.getAuthTag().toString("base64") };
}
function decryptMemberValue(value) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", memberEncryptionKey(), Buffer.from(value.iv, "base64"));
  decipher.setAuthTag(Buffer.from(value.tag, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(value.data, "base64")), decipher.final()]).toString("utf8");
}
function maskAadhaar(value) { return "XXXX-XXXX-" + String(value).slice(-4); }
function maskPan(value) { return String(value).slice(0, 2) + "*****" + String(value).slice(-2); }
function validMemberPhoto(photo) {
  return typeof photo === "string" && photo.length <= 140000 && /^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(photo);
}
function memberPublicData(x) {
  return {
    id: x.id, fullName: x.fullName, role: x.role, dob: x.dob,
    email: x.email, mobile: x.mobile, address: x.address, photo: x.photo || "",
    status: x.status, siin: x.siin || "", createdAt: x.createdAt || null,
    approvedAt: x.approvedAt || null, rejectionReason: x.rejectionReason || ""
  };
}

// Admin creates a member. Sensitive values never enter the public member document.
app.post("/api/members", requireUser, requireAdmin, async (req, res) => {
  try {
    const b = req.body || {};
    const fullName = cleanText(b.fullName, 100);
    const role = cleanText(b.role, 20);
    const dob = cleanText(b.dob, 10);
    const aadhaar = cleanText(b.aadhaar, 12);
    const pan = cleanText(b.pan, 10).toUpperCase();
    const email = cleanText(b.email, 254).toLowerCase();
    const mobile = cleanText(b.mobile, 10);
    const address = cleanText(b.address, 500);
    const photo = b.photo || "";
    if (fullName.length < 2 || !["Manager", "Employee"].includes(role) || !/^\d{4}-\d{2}-\d{2}$/.test(dob) ||
        !/^\d{12}$/.test(aadhaar) || !/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(pan) ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !validPhone(mobile) || address.length < 5 || address.length > 500 || !validMemberPhoto(photo)) {
      return res.status(400).json({ error: "Check all fields. Aadhaar must be 12 digits, PAN must be valid, mobile must be a 10-digit Indian number and photo must be a compressed JPEG." });
    }
    const existing = await db.collection("members").where("email", "==", email).limit(1).get();
    if (!existing.empty) return res.status(409).json({ error: "A member record already exists for this email." });
    // Validate encryption configuration before writing any member data.
    const privateData = { aadhaar: encryptMemberValue(aadhaar), pan: encryptMemberValue(pan), createdAt: admin.firestore.FieldValue.serverTimestamp() };
    const id = crypto.randomUUID();
    const publicData = { fullName, role, dob, email, mobile, address, photo, status: "Pending", siin: "", rejectionReason: "", createdBy: req.user.uid, createdAt: admin.firestore.FieldValue.serverTimestamp() };
    const batch = db.batch();
    batch.create(db.collection("members").doc(id), publicData);
    batch.create(db.collection("memberPrivate").doc(id), privateData);
    await batch.commit();
    return res.status(201).json({ id, status: "Pending", message: "Member added successfully." });
  } catch (e) {
    console.error("Create member error:", e.message);
    return res.status(500).json({ error: e.message.includes("MEMBER_ENCRYPTION_KEY") ? e.message : "Could not create member. Please try again." });
  }
});

// Admin list: only masked Aadhaar/PAN are returned.
app.get("/api/members", requireUser, requireAdmin, async (_req, res) => {
  try {
    const [snap, counterSnap] = await Promise.all([
      db.collection("members").orderBy("createdAt", "desc").limit(300).get(),
      db.collection("memberCounters").doc("siin").get()
    ]);
    const rows = await Promise.all(snap.docs.map(async d => {
      const x = { id: d.id, ...d.data() };
      let aadhaarMasked = "Not available", panMasked = "Not available";
      try {
        const p = await db.collection("memberPrivate").doc(d.id).get();
        if (p.exists) { const v = p.data(); aadhaarMasked = maskAadhaar(decryptMemberValue(v.aadhaar)); panMasked = maskPan(decryptMemberValue(v.pan)); }
      } catch (e) { console.error("Private member data mask failed:", e.message); }
      const publicRow = memberPublicData(x);
      delete publicRow.photo; // photos are fetched only when an approved card is requested
      return { ...publicRow, aadhaarMasked, panMasked };
    }));
    const lastAssigned = counterSnap.exists ? Number(counterSnap.data().lastAssigned || 100000) : 100000;
    return res.json({ members: rows, nextSiin: String(lastAssigned + 1).padStart(6, "0") });
  } catch (e) {
    console.error("List members error:", e.message);
    return res.status(500).json({ error: "Could not load member records." });
  }
});

// Admin approves and assigns the SIIN manually. Registry + member update are atomic.
app.post("/api/members/:id/approve", requireUser, requireAdmin, async (req, res) => {
  try {
    const id = cleanText(req.params.id, 80);
    const siin = cleanText(req.body?.siin, 6);
    if (!/^[0-9]{6}$/.test(siin) || Number(siin) < 100001) return res.status(400).json({ error: "SIIN must be a 6-digit number starting from 100001." });
    const memberRef = db.collection("members").doc(id);
    const registryRef = db.collection("siinRegistry").doc(siin);
    const counterRef = db.collection("memberCounters").doc("siin");
    await db.runTransaction(async tx => {
      const [memberSnap, registrySnap, counterSnap] = await Promise.all([tx.get(memberRef), tx.get(registryRef), tx.get(counterRef)]);
      if (!memberSnap.exists) throw new Error("MEMBER_NOT_FOUND");
      const m = memberSnap.data();
      if (m.status !== "Pending") throw new Error("MEMBER_ALREADY_REVIEWED");
      if (registrySnap.exists) throw new Error("SIIN_ALREADY_USED");
      const lastAssigned = counterSnap.exists ? Number(counterSnap.data().lastAssigned || 100000) : 100000;
      const expectedSiin = String(lastAssigned + 1).padStart(6, "0");
      if (siin !== expectedSiin) throw new Error("SIIN_NOT_NEXT:" + expectedSiin);
      const staffRef = m.role === "Manager" ? db.collection("managers").doc(m.email) : db.collection("employeesByEmail").doc(m.email);
      const staffSnap = await tx.get(staffRef);
      const old = staffSnap.exists ? staffSnap.data() : {};
      tx.create(registryRef, { memberId: id, email: m.email, role: m.role, assignedAt: admin.firestore.FieldValue.serverTimestamp(), assignedBy: req.user.uid });
      tx.set(counterRef, { lastAssigned: Number(siin), updatedAt: admin.firestore.FieldValue.serverTimestamp() });
      tx.update(memberRef, { status: "Approved", siin, rejectionReason: "", approvedAt: admin.firestore.FieldValue.serverTimestamp(), approvedBy: req.user.uid });
      if (m.role === "Manager") {
        tx.set(staffRef, { ...old, email: m.email, name: m.fullName, active: true, linkedUid: old.linkedUid || "", memberId: id, createdAt: old.createdAt || new Date().toISOString() });
      } else {
        tx.set(staffRef, { ...old, email: m.email, name: m.fullName, phone: m.mobile, status: "Active", linkedUid: old.linkedUid || "", memberId: id, createdAt: old.createdAt || new Date().toISOString() });
      }
    });
    return res.json({ ok: true, siin, message: "Member approved and SIIN assigned." });
  } catch (e) {
    const nextMatch = String(e.message || "").match(/^SIIN_NOT_NEXT:(\d{6})$/);
    const msg = e.message === "SIIN_ALREADY_USED" ? "This SIIN is already assigned. Enter another unique number." : nextMatch ? "The next sequential SIIN must be " + nextMatch[1] + "." : e.message === "MEMBER_NOT_FOUND" ? "Member not found." : e.message === "MEMBER_ALREADY_REVIEWED" ? "This member has already been reviewed." : "Could not approve this member.";
    if (!["SIIN_ALREADY_USED", "MEMBER_NOT_FOUND", "MEMBER_ALREADY_REVIEWED"].includes(e.message) && !nextMatch) console.error("Approve member error:", e.message);
    return res.status(e.message === "SIIN_ALREADY_USED" || nextMatch ? 409 : e.message === "MEMBER_NOT_FOUND" ? 404 : 400).json({ error: msg });
  }
});

app.post("/api/members/:id/reject", requireUser, requireAdmin, async (req, res) => {
  try {
    const id = cleanText(req.params.id, 80), reason = cleanText(req.body?.reason, 500);
    const ref = db.collection("members").doc(id);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: "Member not found." });
    if (snap.data().status !== "Pending") return res.status(400).json({ error: "This member has already been reviewed." });
    await ref.update({ status: "Rejected", rejectionReason: reason, rejectedAt: admin.firestore.FieldValue.serverTimestamp(), rejectedBy: req.user.uid });
    return res.json({ ok: true, message: "Member rejected." });
  } catch (e) {
    console.error("Reject member error:", e.message);
    return res.status(500).json({ error: "Could not reject member." });
  }
});

// Approved staff can fetch only their own public ID-card fields.
app.get("/api/members/me/card", requireUser, async (req, res) => {
  try {
    if (!req.user.email_verified) return res.status(403).json({ error: "Please verify your email first. Sign in with Google using the same email." });
    const email = String(req.user.email || "").toLowerCase();
    if (!email) return res.status(404).json({ error: "No approved member ID card was found." });
    const snap = await db.collection("members").where("email", "==", email).where("status", "==", "Approved").limit(1).get();
    if (snap.empty) return res.status(404).json({ error: "No approved member ID card was found for this account." });
    const doc = snap.docs[0], ref = doc.ref;
    await db.runTransaction(async tx => {
      const fresh = await tx.get(ref);
      const linkedUid = fresh.data()?.linkedUid || "";
      if (linkedUid && linkedUid !== req.user.uid) throw new Error("MEMBER_LINKED_TO_OTHER_ACCOUNT");
      if (!linkedUid) tx.update(ref, { linkedUid: req.user.uid, linkedAt: admin.firestore.FieldValue.serverTimestamp() });
    });
    const x = { id: doc.id, ...doc.data() };
    return res.json({ member: memberPublicData(x) });
  } catch (e) {
    if (e.message === "MEMBER_LINKED_TO_OTHER_ACCOUNT") return res.status(403).json({ error: "This member record is linked to another account." });
    console.error("Member card fetch error:", e.message);
    return res.status(500).json({ error: "Could not load your ID card." });
  }
});

app.get("/api/members/:id/card", requireUser, requireAdmin, async (req, res) => {
  try {
    const snap = await db.collection("members").doc(cleanText(req.params.id, 80)).get();
    if (!snap.exists || snap.data().status !== "Approved") return res.status(404).json({ error: "Approved member card not found." });
    return res.json({ member: memberPublicData({ id: snap.id, ...snap.data() }) });
  } catch (e) {
    console.error("Admin card fetch error:", e.message);
    return res.status(500).json({ error: "Could not load this ID card." });
  }
});

// ===============================
// VERIFY PAID ORDER
// ===============================
async function confirmPaidOrder(orderId) {
  if (typeof orderId !== "string" || !/^SI[0-9A-F]{32}$/.test(orderId)) return false;
  const ref = db.collection("orders").doc(orderId), snap = await ref.get();
  if (!snap.exists) return false;
  const order = snap.data();
  if (order.payment !== "Cashfree" || order.paymentStatus === "Verified") return false;
  const [cfOrder, payments] = await Promise.all([
    cashfreeRequest("/orders/" + encodeURIComponent(orderId)),
    cashfreeRequest("/orders/" + encodeURIComponent(orderId) + "/payments")
  ]);
  const successful = Array.isArray(payments) && payments.some(p => p && p.cf_payment_status === "SUCCESS" && Number(p.order_amount) === Number(order.total) && p.payment_currency === "INR");
  if (cfOrder.order_status !== "PAID" || !successful || Number(cfOrder.order_amount) !== Number(order.total) || cfOrder.order_currency !== "INR") return false;
  await ref.update({ paymentStatus: "Verified", cashfreeStatus: "PAID", paidAt: admin.firestore.FieldValue.serverTimestamp() });
  return true;
}

// ===============================
// HEALTH + HOMEPAGE
// ===============================
app.get("/health", (_req, res) => res.json({ ok: true, service: "sudip-industry-payments" }));
const INDEX_FILE = path.join(__dirname, "index.html");
app.get("/", (_req, res) => {
  if (!fs.existsSync(INDEX_FILE)) return res.status(404).send("index.html not found. Please check your GitHub repository.");
  res.sendFile(INDEX_FILE);
});
app.get("/index.html", (_req, res) => res.sendFile(INDEX_FILE));

// ===============================
// CREATE CASHFREE ORDER
// ===============================
app.post("/api/payments/create-order", requireUser, async (req, res) => {
  try {
    const { customer = {}, items = [] } = req.body || {};
    const name = cleanText(customer.name, 80), phone = cleanText(customer.phone, 10), address = cleanText(customer.address, 300), pin = cleanText(customer.pin, 6);
    if (name.length < 2 || !validPhone(phone) || address.length < 5 || !/^\d{6}$/.test(pin)) return res.status(400).json({ error: "Please check your name, phone, address and PIN code." });
    if (!Array.isArray(items) || items.length < 1 || items.length > 50) return res.status(400).json({ error: "Your cart is empty or invalid." });
    const cleanItems = []; let total = 0;
    for (const item of items) {
      const productId = cleanText(item?.id, 100), qty = Number(item?.qty);
      if (!productId || !Number.isInteger(qty) || qty < 1 || qty > 100) return res.status(400).json({ error: "An item in your cart is invalid." });
      const productSnap = await db.collection("products").doc(productId).get();
      if (!productSnap.exists) return res.status(400).json({ error: "A product in your cart is no longer available." });
      const product = productSnap.data(), price = Number(product.price), stock = Number(product.stock);
      if (product.sample || !Number.isFinite(price) || price < 0 || (Number.isFinite(stock) && stock < qty)) return res.status(400).json({ error: "A product is unavailable or has insufficient stock." });
      const line = { id: productId, name: cleanText(product.name, 120), price, qty };
      if (item.size !== undefined && item.size !== null && item.size !== "") { const size = cleanText(item.size, 30); if (!size) return res.status(400).json({ error: "Invalid product size." }); line.size = size; }
      cleanItems.push(line); total += price * qty;
    }
    total = Math.round((total + Number.EPSILON) * 100) / 100;
    if (!Number.isFinite(total) || total <= 0 || total > 1000000) return res.status(400).json({ error: "Invalid order total." });
    const orderId = makeOrderId();
    const order = { ownerId: req.user.uid, email: cleanText(req.user.email || "", 254), name, phone, address, pin, items: cleanItems, total, payment: "Cashfree", paymentStatus: "Pending", status: "New", cashfreeOrderId: orderId, createdAt: admin.firestore.FieldValue.serverTimestamp() };
    await db.collection("orders").doc(orderId).create(order);
    try {
      const cfOrder = await cashfreeRequest("/orders", { method: "POST", headers: { "x-idempotency-key": crypto.randomUUID() }, body: JSON.stringify({
        order_id: orderId, order_amount: total, order_currency: "INR",
        customer_details: { customer_id: req.user.uid.slice(0, 50), customer_name: name, customer_email: cleanText(req.user.email || "customer@sudip-industry.invalid", 254), customer_phone: phone },
        order_meta: { return_url: SITE_URL + "/?payment=return&order_id=" + encodeURIComponent(orderId), notify_url: process.env.CASHFREE_WEBHOOK_URL || undefined },
        order_note: "SUDIP INDUSTRY order " + orderId
      }) });
      if (!cfOrder.payment_session_id) throw new Error("Cashfree did not return a payment session.");
      await db.collection("orders").doc(orderId).update({ cashfreePaymentSessionId: cfOrder.payment_session_id });
      return res.json({ orderId, paymentSessionId: cfOrder.payment_session_id });
    } catch (err) {
      await db.collection("orders").doc(orderId).update({ paymentStatus: "Failed", cashfreeError: cleanText(err.message, 200) }).catch(() => {});
      throw err;
    }
  } catch (err) {
    console.error("Create order error:", err.message);
    return res.status(400).json({ error: err.message || "Unable to start payment. Please try again." });
  }
});

// ===============================
// VERIFY CASHFREE PAYMENT
// ===============================
app.post("/api/payments/verify", requireUser, async (req, res) => {
  try {
    const orderId = cleanText(req.body?.orderId, 40);
    if (!/^SI[0-9A-F]{32}$/.test(orderId)) return res.status(400).json({ error: "Invalid order ID." });
    const ref = db.collection("orders").doc(orderId), snap = await ref.get();
    if (!snap.exists || snap.data().ownerId !== req.user.uid) return res.status(404).json({ error: "Order not found." });
    await confirmPaidOrder(orderId);
    const fresh = await ref.get(), data = fresh.data();
    return res.json({ orderId, paymentStatus: data.paymentStatus, orderStatus: data.status });
  } catch (err) {
    console.error("Verify payment error:", err.message);
    return res.status(502).json({ error: "Payment confirmation is still pending. Please refresh My Orders shortly." });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log("SUDIP INDUSTRY server listening on port", PORT);
  console.log("Website URL:", SITE_URL);
});

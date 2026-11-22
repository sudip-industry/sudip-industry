const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const admin = require("firebase-admin");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

const PORT = process.env.PORT || 10000;
const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || "sudip-industry";
const CASHFREE_ENV = String(process.env.CASHFREE_ENV || "PRODUCTION").toUpperCase();
const CASHFREE_BASE = CASHFREE_ENV === "SANDBOX"
  ? "https://sandbox.cashfree.com/pg"
  : "https://api.cashfree.com/pg";
const CASHFREE_API_VERSION = process.env.CASHFREE_API_VERSION || "2025-01-01";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://sudip-industry.github.io";
const SITE_URL = process.env.SITE_URL || "https://sudip-industry.github.io/sudip-industry";

function initFirebase() {
  if (admin.apps.length) return;
  const secretPath = process.env.GOOGLE_APPLICATION_CREDENTIALS ||
    (fs.existsSync("/etc/secrets/firebase-service-account.json")
      ? "/etc/secrets/firebase-service-account.json" : "");
  if (secretPath) {
    const serviceAccount = JSON.parse(fs.readFileSync(secretPath, "utf8"));
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount), projectId: PROJECT_ID });
  } else {
    admin.initializeApp({ credential: admin.credential.applicationDefault(), projectId: PROJECT_ID });
  }
}
initFirebase();
const db = admin.firestore();

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && origin !== FRONTEND_ORIGIN) return res.status(403).json({ error: "Origin not allowed" });
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Cashfree signatures are calculated over timestamp + the exact raw body.
app.post("/api/payments/webhook", express.raw({ type: "application/json", limit: "1mb" }), async (req, res) => {
  try {
    const signature = req.get("x-webhook-signature") || "";
    const timestamp = req.get("x-webhook-timestamp") || "";
    const secret = process.env.CASHFREE_SECRET_KEY;
    if (!secret || !signature || !timestamp || !Buffer.isBuffer(req.body)) {
      return res.status(400).send("Invalid webhook");
    }
    const expected = crypto.createHmac("sha256", secret)
      .update(timestamp + req.body.toString("utf8"))
      .digest("base64");
    const a = Buffer.from(signature);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(401).send("Invalid signature");
    }

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

app.use(express.json({ limit: "100kb" }));

async function requireUser(req, res, next) {
  try {
    const header = req.get("authorization") || "";
    const match = header.match(/^Bearer (.+)$/i);
    if (!match) return res.status(401).json({ error: "Please sign in first." });
    req.user = await admin.auth().verifyIdToken(match[1]);
    next();
  } catch (_) {
    return res.status(401).json({ error: "Your sign-in session expired. Please sign in again." });
  }
}

function cashfreeHeaders() {
  const appId = process.env.CASHFREE_APP_ID;
  const secret = process.env.CASHFREE_SECRET_KEY;
  if (!appId || !secret) throw new Error("Cashfree credentials are not configured on the server.");
  return {
    "Content-Type": "application/json",
    "x-client-id": appId,
    "x-client-secret": secret,
    "x-api-version": CASHFREE_API_VERSION
  };
}

async function cashfreeRequest(path, options = {}) {
  const response = await fetch(CASHFREE_BASE + path, {
    ...options,
    headers: { ...cashfreeHeaders(), ...(options.headers || {}) }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    console.error("Cashfree API error:", response.status, JSON.stringify(body).slice(0, 1200));
    throw new Error("Cashfree could not process the payment request.");
  }
  return body;
}

function cleanText(v, max) {
  return typeof v === "string" ? v.trim().slice(0, max) : "";
}
function validPhone(v) { return /^[6-9][0-9]{9}$/.test(v); }
function makeOrderId() { return "SI" + crypto.randomBytes(16).toString("hex").toUpperCase(); }

async function confirmPaidOrder(orderId) {
  if (typeof orderId !== "string" || !/^SI[0-9A-F]{32}$/.test(orderId)) return false;
  const ref = db.collection("orders").doc(orderId);
  const snap = await ref.get();
  if (!snap.exists) return false;
  const order = snap.data();
  if (order.payment !== "Cashfree" || order.paymentStatus === "Verified") return false;

  // Do not trust the browser redirect or webhook payload as proof of payment.
  const [cfOrder, payments] = await Promise.all([
    cashfreeRequest("/orders/" + encodeURIComponent(orderId)),
    cashfreeRequest("/orders/" + encodeURIComponent(orderId) + "/payments")
  ]);
  const successful = Array.isArray(payments) && payments.some(p =>
    p && p.cf_payment_status === "SUCCESS" &&
    Number(p.order_amount) === Number(order.total) &&
    p.payment_currency === "INR"
  );
  if (cfOrder.order_status !== "PAID" || !successful ||
      Number(cfOrder.order_amount) !== Number(order.total) ||
      cfOrder.order_currency !== "INR") return false;

  await ref.update({
    paymentStatus: "Verified",
    cashfreeStatus: "PAID",
    paidAt: admin.firestore.FieldValue.serverTimestamp()
  });
  return true;
}

app.get("/health", (_req, res) => res.json({ ok: true, service: "sudip-industry-payments" }));

app.post("/api/payments/create-order", requireUser, async (req, res) => {
  try {
    const { customer = {}, items = [] } = req.body || {};
    const name = cleanText(customer.name, 80);
    const phone = cleanText(customer.phone, 10);
    const address = cleanText(customer.address, 300);
    const pin = cleanText(customer.pin, 6);
    if (name.length < 2 || !validPhone(phone) || address.length < 5 || !/^\d{6}$/.test(pin)) {
      return res.status(400).json({ error: "Please check your name, phone, address and PIN code." });
    }
    if (!Array.isArray(items) || items.length < 1 || items.length > 50) {
      return res.status(400).json({ error: "Your cart is empty or invalid." });
    }

    const cleanItems = [];
    let total = 0;
    for (const item of items) {
      const productId = cleanText(item?.id, 100);
      const qty = Number(item?.qty);
      if (!productId || !Number.isInteger(qty) || qty < 1 || qty > 100) {
        return res.status(400).json({ error: "An item in your cart is invalid." });
      }
      const productSnap = await db.collection("products").doc(productId).get();
      if (!productSnap.exists) return res.status(400).json({ error: "A product in your cart is no longer available." });
      const product = productSnap.data();
      const price = Number(product.price);
      const stock = Number(product.stock);
      if (product.sample || !Number.isFinite(price) || price < 0 ||
          (Number.isFinite(stock) && stock < qty)) {
        return res.status(400).json({ error: "A product is unavailable or has insufficient stock." });
      }
      const line = { id: productId, name: cleanText(product.name, 120), price, qty };
      if (item.size !== undefined && item.size !== null && item.size !== "") {
        const size = cleanText(item.size, 30);
        if (!size) return res.status(400).json({ error: "Invalid product size." });
        line.size = size;
      }
      cleanItems.push(line);
      total += price * qty;
    }
    total = Math.round((total + Number.EPSILON) * 100) / 100;
    if (!Number.isFinite(total) || total <= 0 || total > 1000000) {
      return res.status(400).json({ error: "Invalid order total." });
    }

    const orderId = makeOrderId();
    const order = {
      ownerId: req.user.uid,
      email: cleanText(req.user.email || "", 254),
      name, phone, address, pin,
      items: cleanItems,
      total,
      payment: "Cashfree",
      paymentStatus: "Pending",
      status: "New",
      cashfreeOrderId: orderId,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    };
    await db.collection("orders").doc(orderId).create(order);

    try {
      const cfOrder = await cashfreeRequest("/orders", {
        method: "POST",
        headers: { "x-idempotency-key": crypto.randomUUID() },
        body: JSON.stringify({
          order_id: orderId,
          order_amount: total,
          order_currency: "INR",
          customer_details: {
            customer_id: req.user.uid.slice(0, 50),
            customer_name: name,
            customer_email: cleanText(req.user.email || "customer@sudip-industry.invalid", 254),
            customer_phone: phone
          },
          order_meta: {
            return_url: SITE_URL + "/?payment=return&order_id=" + encodeURIComponent(orderId),
            notify_url: process.env.CASHFREE_WEBHOOK_URL || undefined
          },
          order_note: "SUDIP INDUSTRY order " + orderId
        })
      });
      if (!cfOrder.payment_session_id) throw new Error("Cashfree did not return a payment session.");
      await db.collection("orders").doc(orderId).update({
        cashfreePaymentSessionId: cfOrder.payment_session_id
      });
      return res.json({ orderId, paymentSessionId: cfOrder.payment_session_id });
    } catch (err) {
      await db.collection("orders").doc(orderId).update({
        paymentStatus: "Failed",
        cashfreeError: cleanText(err.message, 200)
      }).catch(() => {});
      throw err;
    }
  } catch (err) {
    console.error("Create order error:", err.message);
    return res.status(400).json({ error: err.message || "Unable to start payment. Please try again." });
  }
});

app.post("/api/payments/verify", requireUser, async (req, res) => {
  try {
    const orderId = cleanText(req.body?.orderId, 40);
    if (!/^SI[0-9A-F]{32}$/.test(orderId)) return res.status(400).json({ error: "Invalid order ID." });
    const ref = db.collection("orders").doc(orderId);
    const snap = await ref.get();
    if (!snap.exists || snap.data().ownerId !== req.user.uid) {
      return res.status(404).json({ error: "Order not found." });
    }
    await confirmPaidOrder(orderId);
    const fresh = await ref.get();
    const data = fresh.data();
    return res.json({ orderId, paymentStatus: data.paymentStatus, orderStatus: data.status });
  } catch (err) {
    console.error("Verify payment error:", err.message);
    return res.status(502).json({ error: "Payment confirmation is still pending. Please refresh My Orders shortly." });
  }
});

app.listen(PORT, () => console.log("SUDIP INDUSTRY payment backend listening on", PORT));

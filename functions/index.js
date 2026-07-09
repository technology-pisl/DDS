/**
 * DDS backend — every write to Firestore happens here, under the Admin SDK,
 * never directly from the browser. firestore.rules denies all client writes,
 * so this file is the single, auditable choke point for data mutation.
 */

const { initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const bcrypt = require("bcryptjs");
const { randomUUID } = require("crypto");

initializeApp();
const auth = getAuth();
const db = getFirestore();

const SALT_ROUNDS = 10;
const LOCK_THRESHOLD = 5;
const LOCK_DURATION_MS = 15 * 60 * 1000;
const ROLES = ["admin", "user", "si", "sadmin"];

// All callables require App Check by default; the client attaches a token
// obtained via reCAPTCHA v3, so scripted callers without a real browser
// session are rejected before the function body even runs.
const CALL_OPTS = { enforceAppCheck: true };

function requireAuth(request) {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Sign in required.");
  }
  return request.auth;
}

function requireRole(request, roles) {
  const a = requireAuth(request);
  const role = a.token.role;
  if (!roles.includes(role)) {
    throw new HttpsError("permission-denied", "Not authorized for this action.");
  }
  return a;
}

function assertPin(pin) {
  if (typeof pin !== "string" || !/^\d{4,6}$/.test(pin)) {
    throw new HttpsError("invalid-argument", "PIN must be 4-6 digits.");
  }
}

function assertNonEmptyString(v, field, maxLen = 200) {
  if (typeof v !== "string" || !v.trim() || v.length > maxLen) {
    throw new HttpsError("invalid-argument", `${field} is invalid.`);
  }
  return v.trim();
}

// ── AUTH ─────────────────────────────────────────────────────────────────

/**
 * Public, no-auth-required list of active users for the login dropdown.
 * Deliberately returns only {uid, name} — never role, site, or anything
 * else — so the pre-login screen doesn't need Firestore read access at all
 * (firestore.rules requires signedIn() for every collection).
 */
exports.listLoginUsers = onCall(CALL_OPTS, async () => {
  const snap = await db.collection("users").where("active", "==", true).get();
  return {
    users: snap.docs.map((d) => ({ uid: d.id, name: d.data().name || "" })),
  };
});

/**
 * One-time bootstrap: only works while the `users` collection is empty.
 * Lets you create the very first admin account without already having one.
 * After the first user exists, this always rejects.
 */
exports.bootstrapAdmin = onCall(CALL_OPTS, async (request) => {
  const name = assertNonEmptyString(request.data.name, "name", 100);
  const pin = String(request.data.pin || "");
  assertPin(pin);

  const existing = await db.collection("users").limit(1).get();
  if (!existing.empty) {
    throw new HttpsError("failed-precondition", "Setup already completed.");
  }

  const userRecord = await auth.createUser({ displayName: name });
  const uid = userRecord.uid;
  await auth.setCustomUserClaims(uid, { role: "admin", site: "", siId: "" });

  const pinHash = await bcrypt.hash(pin, SALT_ROUNDS);
  await db.collection("users").doc(uid).set({
    name,
    role: "admin",
    site: "",
    empCode: "",
    siId: "",
    active: true,
    createdAt: FieldValue.serverTimestamp(),
  });
  await db.collection("credentials").doc(uid).set({
    pinHash,
    failedAttempts: 0,
    lockedUntil: null,
    mustChangePin: false,
    updatedAt: FieldValue.serverTimestamp(),
  });

  return { uid };
});

/**
 * PIN login, enforced entirely server-side. Verifies the hash, applies
 * lockout after repeated failures, and mints a Firebase custom token —
 * the browser never sees or checks the PIN itself.
 */
exports.login = onCall(CALL_OPTS, async (request) => {
  const userId = assertNonEmptyString(request.data.userId, "userId", 128);
  const pin = String(request.data.pin || "");
  assertPin(pin);

  const genericError = () => new HttpsError("permission-denied", "Invalid user or PIN.");

  const [userSnap, credSnap] = await Promise.all([
    db.collection("users").doc(userId).get(),
    db.collection("credentials").doc(userId).get(),
  ]);
  if (!userSnap.exists || !credSnap.exists) throw genericError();

  const user = userSnap.data();
  const cred = credSnap.data();
  if (user.active === false) throw genericError();

  const now = Date.now();
  if (cred.lockedUntil && cred.lockedUntil.toMillis && cred.lockedUntil.toMillis() > now) {
    throw new HttpsError(
      "resource-exhausted",
      "Too many failed attempts. Try again in a few minutes.",
    );
  }

  const ok = await bcrypt.compare(pin, cred.pinHash || "");
  if (!ok) {
    const failedAttempts = (cred.failedAttempts || 0) + 1;
    const patch = { failedAttempts, updatedAt: FieldValue.serverTimestamp() };
    if (failedAttempts >= LOCK_THRESHOLD) {
      patch.failedAttempts = 0;
      patch.lockedUntil = new Date(now + LOCK_DURATION_MS);
    }
    await credSnap.ref.set(patch, { merge: true });
    throw genericError();
  }

  await credSnap.ref.set(
    { failedAttempts: 0, lockedUntil: null, updatedAt: FieldValue.serverTimestamp() },
    { merge: true },
  );

  const token = await auth.createCustomToken(userId);
  return {
    token,
    mustChangePin: !!cred.mustChangePin,
    profile: {
      uid: userId,
      name: user.name,
      role: user.role,
      site: user.site,
      siId: user.siId || "",
      empCode: user.empCode || "",
    },
  };
});

exports.changePin = onCall(CALL_OPTS, async (request) => {
  const a = requireAuth(request);
  const oldPin = String(request.data.oldPin || "");
  const newPin = String(request.data.newPin || "");
  assertPin(oldPin);
  assertPin(newPin);

  const credRef = db.collection("credentials").doc(a.uid);
  const credSnap = await credRef.get();
  if (!credSnap.exists) throw new HttpsError("not-found", "No credentials on file.");

  const ok = await bcrypt.compare(oldPin, credSnap.data().pinHash || "");
  if (!ok) throw new HttpsError("permission-denied", "Current PIN is incorrect.");

  const pinHash = await bcrypt.hash(newPin, SALT_ROUNDS);
  await credRef.set(
    { pinHash, mustChangePin: false, updatedAt: FieldValue.serverTimestamp() },
    { merge: true },
  );
  return { ok: true };
});

exports.adminSetPin = onCall(CALL_OPTS, async (request) => {
  requireRole(request, ["admin"]);
  const targetUserId = assertNonEmptyString(request.data.targetUserId, "targetUserId", 128);
  const newPin = String(request.data.newPin || "");
  assertPin(newPin);

  const userSnap = await db.collection("users").doc(targetUserId).get();
  if (!userSnap.exists) throw new HttpsError("not-found", "User not found.");

  const pinHash = await bcrypt.hash(newPin, SALT_ROUNDS);
  await db.collection("credentials").doc(targetUserId).set(
    {
      pinHash,
      failedAttempts: 0,
      lockedUntil: null,
      mustChangePin: true,
      updatedAt: FieldValue.serverTimestamp(),
    },
    { merge: true },
  );
  return { ok: true };
});

// ── USER MANAGEMENT (admin only) ────────────────────────────────────────

exports.adminCreateUser = onCall(CALL_OPTS, async (request) => {
  requireRole(request, ["admin"]);
  const name = assertNonEmptyString(request.data.name, "name", 100);
  const role = request.data.role;
  if (!ROLES.includes(role)) throw new HttpsError("invalid-argument", "Invalid role.");
  const site = String(request.data.site || "").slice(0, 300);
  const empCode = String(request.data.empCode || "").slice(0, 50);
  const siId = String(request.data.siId || "").slice(0, 128);
  const pin = String(request.data.pin || "0000");
  assertPin(pin);

  const userRecord = await auth.createUser({ displayName: name });
  const uid = userRecord.uid;
  await auth.setCustomUserClaims(uid, { role, site, siId });

  await db.collection("users").doc(uid).set({
    name,
    role,
    site,
    empCode,
    siId,
    active: true,
    createdAt: FieldValue.serverTimestamp(),
  });
  const pinHash = await bcrypt.hash(pin, SALT_ROUNDS);
  await db.collection("credentials").doc(uid).set({
    pinHash,
    failedAttempts: 0,
    lockedUntil: null,
    mustChangePin: true,
    updatedAt: FieldValue.serverTimestamp(),
  });

  return { uid };
});

exports.adminUpdateUser = onCall(CALL_OPTS, async (request) => {
  requireRole(request, ["admin"]);
  const uid = assertNonEmptyString(request.data.uid, "uid", 128);
  const userRef = db.collection("users").doc(uid);
  const snap = await userRef.get();
  if (!snap.exists) throw new HttpsError("not-found", "User not found.");

  const patch = {};
  if (request.data.name !== undefined) patch.name = assertNonEmptyString(request.data.name, "name", 100);
  if (request.data.site !== undefined) patch.site = String(request.data.site).slice(0, 300);
  if (request.data.empCode !== undefined) patch.empCode = String(request.data.empCode).slice(0, 50);
  if (request.data.siId !== undefined) patch.siId = String(request.data.siId).slice(0, 128);
  if (request.data.role !== undefined) {
    if (!ROLES.includes(request.data.role)) throw new HttpsError("invalid-argument", "Invalid role.");
    patch.role = request.data.role;
  }

  await userRef.set(patch, { merge: true });

  if (patch.role !== undefined || patch.site !== undefined || patch.siId !== undefined) {
    const merged = { ...snap.data(), ...patch };
    await auth.setCustomUserClaims(uid, {
      role: merged.role,
      site: merged.site || "",
      siId: merged.siId || "",
    });
  }
  return { ok: true };
});

exports.adminSetUserActive = onCall(CALL_OPTS, async (request) => {
  requireRole(request, ["admin"]);
  const uid = assertNonEmptyString(request.data.uid, "uid", 128);
  const active = !!request.data.active;
  await db.collection("users").doc(uid).set(
    { active, updatedAt: FieldValue.serverTimestamp() },
    { merge: true },
  );
  if (!active) {
    await auth.updateUser(uid, { disabled: true }).catch(() => {});
  } else {
    await auth.updateUser(uid, { disabled: false }).catch(() => {});
  }
  return { ok: true };
});

// ── ENTRIES ──────────────────────────────────────────────────────────────

const ENTRY_FIELDS = [
  "site", "str", "act", "elem", "loc", "cat", "remark", "uom", "qty", "rate",
  "bench", "vendor", "pm", "supply", "skDay", "skOT", "uskDay", "uskOT",
  "todayPct", "qtyToday", "date",
];

function pickEntryFields(data) {
  const out = {};
  for (const f of ENTRY_FIELDS) {
    if (data[f] !== undefined) out[f] = data[f];
  }
  return out;
}

exports.submitEntry = onCall(CALL_OPTS, async (request) => {
  const a = requireRole(request, ["user", "admin"]);
  const site = assertNonEmptyString(request.data.site, "site", 100);
  const payload = pickEntryFields(request.data);

  const userSnap = await db.collection("users").doc(a.uid).get();
  const user = userSnap.exists ? userSnap.data() : {};

  const counterRef = db.collection("counters").doc(`site_${site}`);
  const entryRef = db.collection("entries").doc();

  const ddsNo = await db.runTransaction(async (tx) => {
    const counterSnap = await tx.get(counterRef);
    const next = (counterSnap.exists ? counterSnap.data().value || 0 : 0) + 1;
    tx.set(counterRef, { value: next }, { merge: true });
    tx.set(entryRef, {
      ...payload,
      site,
      userId: a.uid,
      eng: user.name || "",
      empCode: user.empCode || "",
      si: user.siId || "",
      ddsNo: next,
      status: a.token.role === "admin" ? "approved" : "pending",
      createdAt: FieldValue.serverTimestamp(),
    });
    return next;
  });

  return { id: entryRef.id, ddsNo };
});

exports.updateEntry = onCall(CALL_OPTS, async (request) => {
  const a = requireAuth(request);
  const id = assertNonEmptyString(request.data.id, "id", 128);
  const ref = db.collection("entries").doc(id);
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError("not-found", "Entry not found.");
  const entry = snap.data();

  const isOwner = entry.userId === a.uid;
  const isAdmin = a.token.role === "admin";
  if (!isOwner && !isAdmin) throw new HttpsError("permission-denied", "Not your entry.");
  if (isOwner && !isAdmin && entry.status !== "pending") {
    throw new HttpsError("failed-precondition", "Approved/rejected entries can only be edited by an admin.");
  }

  const patch = pickEntryFields(request.data);
  patch.updatedAt = FieldValue.serverTimestamp();
  patch.updatedBy = a.uid;
  if (!isAdmin) patch.status = "pending";
  await ref.set(patch, { merge: true });
  return { ok: true };
});

exports.reviewEntry = onCall(CALL_OPTS, async (request) => {
  const a = requireRole(request, ["si", "admin"]);
  const id = assertNonEmptyString(request.data.id, "id", 128);
  const decision = request.data.decision;
  if (!["approved", "rejected"].includes(decision)) {
    throw new HttpsError("invalid-argument", "decision must be approved or rejected.");
  }
  const siRemark = String(request.data.siRemark || "").slice(0, 500);

  const ref = db.collection("entries").doc(id);
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError("not-found", "Entry not found.");
  const entry = snap.data();

  if (a.token.role === "si" && entry.si !== a.uid) {
    throw new HttpsError("permission-denied", "This entry is not assigned to you.");
  }

  await ref.set(
    {
      status: decision,
      siRemark,
      reviewedBy: a.uid,
      reviewedAt: FieldValue.serverTimestamp(),
    },
    { merge: true },
  );
  return { ok: true };
});

exports.deleteEntry = onCall(CALL_OPTS, async (request) => {
  const a = requireRole(request, ["admin"]);
  const id = assertNonEmptyString(request.data.id, "id", 128);
  const reason = String(request.data.reason || "").slice(0, 300);

  const ref = db.collection("entries").doc(id);
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError("not-found", "Entry not found.");

  const batch = db.batch();
  batch.set(db.collection("delete_log").doc(), {
    entry: snap.data(),
    entryId: id,
    deletedBy: a.uid,
    deletedAt: FieldValue.serverTimestamp(),
    reason,
  });
  batch.delete(ref);
  await batch.commit();
  return { ok: true };
});

// ── VENDORS (admin only) ─────────────────────────────────────────────────

exports.adminUpsertVendor = onCall(CALL_OPTS, async (request) => {
  requireRole(request, ["admin"]);
  const name = assertNonEmptyString(request.data.name, "name", 150);
  const site = String(request.data.site || "").slice(0, 100);
  const mode = request.data.mode === "Supply" ? "Supply" : "Measurement";
  const id = request.data.id ? assertNonEmptyString(request.data.id, "id", 128) : db.collection("vendors").doc().id;

  await db.collection("vendors").doc(id).set(
    { name, site, mode, updatedAt: FieldValue.serverTimestamp() },
    { merge: true },
  );
  return { id };
});

exports.adminDeleteVendor = onCall(CALL_OPTS, async (request) => {
  requireRole(request, ["admin"]);
  const id = assertNonEmptyString(request.data.id, "id", 128);
  await db.collection("vendors").doc(id).delete();
  return { ok: true };
});

// ── MASTER DATA (admin only) — server fetches the CSV, client never trusts a raw URL ──

exports.syncMasterData = onCall(CALL_OPTS, async (request) => {
  const a = requireRole(request, ["admin"]);
  const csvUrl = assertNonEmptyString(request.data.csvUrl, "csvUrl", 2000);
  let parsed;
  try {
    parsed = new URL(csvUrl);
  } catch {
    throw new HttpsError("invalid-argument", "Not a valid URL.");
  }
  if (parsed.protocol !== "https:") {
    throw new HttpsError("invalid-argument", "URL must use https.");
  }

  const res = await fetch(csvUrl, { redirect: "follow" });
  if (!res.ok) throw new HttpsError("failed-precondition", `Fetch failed: HTTP ${res.status}`);
  const text = await res.text();
  if (text.length > 5_000_000) {
    throw new HttpsError("resource-exhausted", "CSV too large.");
  }

  const rows = parseCsv(text);
  if (!rows.length) throw new HttpsError("failed-precondition", "No rows parsed from CSV.");

  await db.collection("config").doc("masterData").set({
    rows,
    csvUrl,
    syncedAt: FieldValue.serverTimestamp(),
    syncedBy: a.uid,
  });
  return { count: rows.length };
});

function parseCsv(text) {
  const lines = text.split(/\r\n|\n/).filter((l) => l.trim().length);
  if (!lines.length) return [];
  const splitLine = (line) => {
    const out = [];
    let cur = "";
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (inQuotes) {
        if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
        else if (c === '"') inQuotes = false;
        else cur += c;
      } else if (c === '"') inQuotes = true;
      else if (c === ",") { out.push(cur); cur = ""; }
      else cur += c;
    }
    out.push(cur);
    return out;
  };
  const header = splitLine(lines[0]).map((h) => h.trim().toLowerCase());
  return lines.slice(1).map((line) => {
    const cells = splitLine(line);
    const row = {};
    header.forEach((h, i) => { row[h] = (cells[i] || "").trim(); });
    return row;
  });
}

// ── DATE UNLOCKS (admin only) ────────────────────────────────────────────

exports.adminGrantUnlock = onCall(CALL_OPTS, async (request) => {
  const a = requireRole(request, ["admin"]);
  const uid = assertNonEmptyString(request.data.uid, "uid", 128);
  const from = assertNonEmptyString(request.data.from, "from", 20);
  const to = assertNonEmptyString(request.data.to, "to", 20);

  const ref = db.collection("config").doc("unlocks");
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const list = snap.exists ? snap.data().list || [] : [];
    list.push({ id: randomUUID(), uid, from, to, on: new Date().toISOString(), grantedBy: a.uid });
    tx.set(ref, { list }, { merge: true });
  });
  return { ok: true };
});

exports.adminRevokeUnlock = onCall(CALL_OPTS, async (request) => {
  requireRole(request, ["admin"]);
  const id = assertNonEmptyString(request.data.id, "id", 128);
  const ref = db.collection("config").doc("unlocks");
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const list = snap.exists ? snap.data().list || [] : [];
    tx.set(ref, { list: list.filter((u) => u.id !== id) }, { merge: true });
  });
  return { ok: true };
});

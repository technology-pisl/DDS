/**
 * Optional one-time migration template: copies entries/vendors/master data
 * from the OLD Firebase project into this NEW one, and recreates users with
 * forced PIN resets (the old PINs were stored in plaintext, so they must
 * not be carried over as-is).
 *
 * This is a starting point, not a turnkey script — read it, adjust the
 * field mapping to match your old data if it drifted, and dry-run against
 * a copy of your data or the Firestore emulator before pointing it at
 * production.
 *
 * Usage:
 *   OLD_SERVICE_ACCOUNT=./old-key.json NEW_SERVICE_ACCOUNT=./new-key.json \
 *     node scripts/migrate.js
 */

const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");

if (!process.env.OLD_SERVICE_ACCOUNT || !process.env.NEW_SERVICE_ACCOUNT) {
  console.error("Set OLD_SERVICE_ACCOUNT and NEW_SERVICE_ACCOUNT to service-account JSON paths.");
  process.exit(1);
}

const oldApp = admin.initializeApp(
  { credential: admin.credential.cert(require(process.env.OLD_SERVICE_ACCOUNT)) },
  "old",
);
const newApp = admin.initializeApp(
  { credential: admin.credential.cert(require(process.env.NEW_SERVICE_ACCOUNT)) },
  "new",
);

const oldDb = oldApp.firestore();
const newDb = newApp.firestore();
const newAuth = newApp.auth();

async function migrateUsers() {
  const snap = await oldDb.collection("users").get();
  const idMap = {}; // old doc id -> new uid
  for (const doc of snap.docs) {
    const u = doc.data();
    const userRecord = await newAuth.createUser({ displayName: u.name || "Unnamed" });
    const uid = userRecord.uid;
    idMap[doc.id] = uid;
    const role = ["admin", "user", "si", "sadmin"].includes(u.role) ? u.role : "user";
    await newAuth.setCustomUserClaims(uid, { role, site: u.site || "", siId: "" });
    await newDb.collection("users").doc(uid).set({
      name: u.name || "",
      role,
      site: u.site || "",
      empCode: u.empCode || "",
      siId: "", // re-link SI relationships manually after migration; old ids won't match
      active: true,
      migratedFrom: doc.id,
    });
    const tempPin = String(Math.floor(1000 + Math.random() * 9000));
    const pinHash = await bcrypt.hash(tempPin, 10);
    await newDb.collection("credentials").doc(uid).set({
      pinHash,
      failedAttempts: 0,
      lockedUntil: null,
      mustChangePin: true,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log(`user ${u.name}: old id ${doc.id} -> new uid ${uid}, temp PIN ${tempPin} (tell them privately, force-changed on first login)`);
  }
  return idMap;
}

async function migrateCollection(name, idMap) {
  const snap = await oldDb.collection(name).get();
  const batchSize = 400;
  let batch = newDb.batch();
  let count = 0;
  for (const doc of snap.docs) {
    const data = doc.data();
    if (data.userId && idMap[data.userId]) data.userId = idMap[data.userId];
    if (data.si && idMap[data.si]) data.si = idMap[data.si];
    batch.set(newDb.collection(name).doc(), data);
    count++;
    if (count % batchSize === 0) {
      await batch.commit();
      batch = newDb.batch();
    }
  }
  await batch.commit();
  console.log(`${name}: migrated ${count} documents`);
}

async function migrateMasterData() {
  const doc = await oldDb.collection("config").doc("masterData").get();
  if (doc.exists) {
    await newDb.collection("config").doc("masterData").set(doc.data());
    console.log("config/masterData migrated");
  }
}

(async () => {
  const idMap = await migrateUsers();
  await migrateCollection("vendors", idMap);
  await migrateCollection("entries", idMap);
  await migrateMasterData();
  console.log("Done. Give each user their temp PIN privately — they'll be forced to set a new one on first login.");
  process.exit(0);
})();

# DDS — Daily Workdone Status (secure rebuild)

This is a from-scratch, security-hardened rebuild of the original single-file
DDS app. The UI/workflow (engineers log daily work-done entries, Section
Incharges approve them, admins manage master data/users/vendors) is the
same; everything about *who can change or delete data* has been rebuilt.

## What changed vs. the original app, and why

| Original | Here | Why |
|---|---|---|
| PIN checked in browser JS (`u.pin !== pin`) | PIN checked in `functions/index.js`, server-side, against a bcrypt hash | Client-side checks can be bypassed by anyone reading the page source or the console — the server never trusted the browser to begin with |
| PINs stored in plaintext in Firestore | PINs stored as bcrypt hashes in a `credentials` collection the client can never read | A leaked database no longer means leaked PINs |
| No login rate limiting | 5 failed attempts locks the account for 15 minutes | Blocks brute-forcing a 4-digit PIN |
| All Firestore writes came directly from the browser | **Every** write goes through a Cloud Function; `firestore.rules` denies all client writes outright | Even someone who extracts your public Firebase API key and opens the browser console cannot create, edit, or delete a single document — only signed-in users hitting a role-checked Cloud Function can |
| No authentication at all (no Firebase Auth) | Firebase Auth + custom claims (`role`, `site`, `siId`) attached server-side at account creation | Firestore rules can now check `request.auth`, which the client cannot forge |
| Unescaped data rendered into `innerHTML` in the Master Data table | All rendering goes through an `esc()` helper | Closes a stored-XSS path where anything in the synced Google Sheet could execute as script |
| Master data synced by the browser fetching an arbitrary pasted URL | Synced by the `syncMasterData` Cloud Function (HTTPS-only, size-capped) | Removes a client-side SSRF/trust boundary |
| No security headers | CSP, `X-Frame-Options: DENY`, HSTS, `Referrer-Policy`, `Permissions-Policy` on every response | Reduces damage from any future markup injection and blocks clickjacking |
| Anyone with repo write access could push straight to the live site | GitHub Actions deploys only from `main`, which should be branch-protected (see below) | Changing the live app requires a reviewed, merged PR |

One known remaining trade-off: the CSP allows `'unsafe-inline'` for scripts
because the UI still uses inline `onclick="..."` handlers throughout (a
carryover from the original app's structure). This is safe as long as the
XSS-escaping discipline above is maintained, but a stronger CSP (nonces,
no inline handlers) is a good follow-up hardening step — see "Further
hardening" at the end.

## Architecture

```
Browser (public/index.html)
  → Firebase Auth (signInWithCustomToken)      — identity
  → Firebase App Check (reCAPTCHA v3)          — proves it's a real browser session
  → Cloud Functions (functions/index.js)       — the only thing allowed to write
  → Firestore                                  — read-only from the browser, rules-enforced
```

- `login`, `changePin`, `adminSetPin`, `bootstrapAdmin` — authentication
- `adminCreateUser`, `adminUpdateUser`, `adminSetUserActive` — user/role management
- `submitEntry`, `updateEntry`, `reviewEntry`, `deleteEntry` — the DDS entry workflow
- `adminUpsertVendor`, `adminDeleteVendor` — vendor list
- `syncMasterData` — pulls the published Google Sheet CSV server-side
- `adminGrantUnlock`, `adminRevokeUnlock` — date-unlock grants

## Where to host this (recommendation)

**Firebase (Hosting + Auth + Functions + Firestore), on the Blaze
(pay-as-you-go) plan, in its own new Firebase project separate from the old
app.** Reasons:

- Your data is already in Firestore, so this is the least migration work.
- Hosting, Auth, Functions, and Firestore are one product with one set of
  IAM/security boundaries to reason about, instead of stitching together
  multiple vendors.
- Firebase Hosting gives you free managed TLS, a global CDN, and the header
  config above out of the box.
- Blaze is still effectively free at 20-100 users — Cloud Functions and
  Firestore have generous no-cost quotas; set a budget alert (see below) so
  you'd know immediately if usage ever spiked unexpectedly.

You do **not** need a VPS, a separate web server, or a container host for
this. Adding one would only add attack surface (an OS to patch, TLS to
manage yourself) for no benefit over Firebase Hosting.

### One-time setup

1. **Create a new, separate Firebase project** (do not reuse the old app's
   project — start clean): https://console.firebase.google.com/
2. Upgrade it to the **Blaze plan** (required for Cloud Functions) and set a
   budget alert: Console → *Usage and billing* → *Details & settings* →
   *Budgets & alerts*. Start with something like $10/month as a tripwire.
3. Enable products in the console:
   - **Authentication** → Sign-in method → enable "Custom" (this is
     automatic once you call `signInWithCustomToken`, no toggle needed) —
     just confirm Authentication is turned on.
   - **Firestore Database** → create in production mode, pick a region
     close to your users.
   - **App Check** → register your web app → provider **reCAPTCHA v3** →
     copy the site key. Enforce App Check for **Firestore** and for
     **Cloud Functions** (toggle in the App Check console page once your
     app has registered a few real requests, so you don't lock yourself out
     first).
4. Install the Firebase CLI locally (`npm install -g firebase-tools`),
   `firebase login`, then `firebase use --add` and pick your new project —
   this writes a local `.firebaserc` (gitignored; copy from
   `.firebaserc.example` and fill in your real project ID).
5. Fill in `public/index.html`'s Firebase config block (apiKey, projectId,
   appId — copy from Console → Project settings → General → "Your apps")
   and the reCAPTCHA v3 site key from step 3.
6. Deploy once by hand to confirm it all works:
   ```
   cd functions && npm install && cd ..
   firebase deploy --only firestore:rules,functions,hosting
   ```
7. Open the deployed URL and use the **first-run "Set up admin account"**
   screen (calls `bootstrapAdmin`, which only works while no users exist
   yet) to create your own admin login. From then on, all other accounts
   are created by that admin from inside the app.

### Locking down deploys (GitHub)

1. Make the GitHub repo **private**.
2. Settings → Branches → add a protection rule on `main`:
   - Require a pull request before merging (require at least 1 approval).
   - Require status checks to pass (once you have CI checks beyond deploy).
   - Do not allow force pushes; do not allow deletions.
   - Restrict who can push directly to `main` — ideally nobody; everything
     goes through a PR.
3. Create a **service account** scoped to this Firebase project only
   (Console → Project settings → Service accounts → Generate new private
   key), and add its JSON as a GitHub Actions secret named
   `FIREBASE_SERVICE_ACCOUNT`, plus a `FIREBASE_PROJECT_ID` secret with your
   project ID. `.github/workflows/deploy.yml` uses these to deploy only when
   something is merged into `main` — nobody can make the live site change
   without going through a reviewed PR merge.
4. Consider requiring 2FA for all collaborators (GitHub org setting) and
   turning on secret scanning / push protection for the repo.

## Testing locally with the Firebase Emulator Suite

The app can run entirely against local emulators — no real Firebase project,
no network access, no cost — which is how this rebuild was verified end to
end (full login/PIN-lockout/entry-approval/admin-override/security-boundary
testing) before being committed.

1. `npm install -g firebase-tools`, then `cd functions && npm install`.
2. Start the emulators: `firebase emulators:start --project demo-dds-test --only auth,firestore,functions`
   (any `demo-` prefixed project id works offline, no real GCP project needed).
3. Serve `public/` with any static file server, e.g. `cd public && python3 -m http.server 8765`.
4. Open `http://localhost:8765/index.html` (or `127.0.0.1`) — the app
   detects it's running on localhost and automatically points Auth/
   Firestore/Functions at the emulators instead of production (see
   `USE_EMULATORS` near the top of `public/index.html`). App Check is
   skipped under the emulator, since it needs real network access to
   Google's servers even in debug mode.
5. The Firebase compat SDKs are normally loaded from `gstatic.com`; if your
   network can't reach it, set `window.DDS_LOCAL_SDK_TEST_ONLY = true` before
   the app loads and drop matching copies of the `firebase-*-compat.js`
   files (from the `firebase` npm package) into `public/vendor-test-only/`
   (gitignored — this is a local-only fallback, never used in production).
6. Reset emulator state between runs with:
   `curl -X DELETE http://localhost:8080/emulator/v1/projects/demo-dds-test/databases/\(default\)/documents`
   and `curl -X DELETE http://localhost:9099/emulator/v1/projects/demo-dds-test/accounts`.

None of this touches production: `USE_EMULATORS` only triggers on
`localhost`/`127.0.0.1`, and App Check enforcement in `functions/index.js`
only relaxes if you set `DDS_TEST_DISABLE_APPCHECK=true` in a
`functions/.env.local` file — a filename Firebase only ever loads for the
emulator, never for a deployed function.

## Migrating data from the old app (optional)

The old project stored PINs in plaintext, so treat every existing PIN as
already compromised — don't carry them over as-is. `scripts/migrate.js` is a
template: point it at a service-account key for the *old* project and the
*new* project, and it copies `entries`, `vendors`, and `config/masterData`
across, recreates each user with `adminCreateUser`-equivalent logic, and
force-sets `mustChangePin` so every user must pick a new PIN the first time
they sign in. Read the script before running it — it's a starting point, not
a turnkey tool, and you should dry-run it against a Firestore emulator or a
copy of your data first.

## Further hardening (optional next steps)

- Replace inline `onclick="..."` handlers with `addEventListener`, then
  tighten the CSP to drop `'unsafe-inline'` for scripts.
- Add Cloud Functions request logging/alerting (e.g. alert on repeated
  `permission-denied` from the same UID — a sign of a compromised or
  probing account).
- Turn on Firestore backups (Console → Firestore → Backups) for point-in-
  time recovery in case of accidental bulk deletion.
- Rotate the reCAPTCHA/App Check keys periodically and if you ever suspect
  the repo or config leaked.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

REST API backend for the **iStar Class Management System** — a studio/class booking system (students, families, courses, class schedules, prepaid course packages, reservations). Express.js + MySQL. The companion frontend lives at `c:\iStarApp\istarapp_dev`.

## Commands

There is **no build, lint, or test setup** (`npm test` is a placeholder that just errors).

```bash
npm install          # install deps
node server.js       # run the server (listens on port 3000, hardcoded)
```

Requires a populated `.env` (gitignored). Required keys: `DB_HOST DB_PORT DB_USER DB_PASSWORD DB_NAME SECRET_KEY TWILIO_ACCOUNT_SID TWILIO_AUTH_TOKEN TWILIO_SERVICE_SID GOOGLE_SERVICE_ACCOUNT_KEY DO_SPACES_KEY DO_SPACES_SECRET SERVER_TYPE` plus the seven `DISCORD_*_WEBHOOK_URL` keys consumed by `logToDiscord.js`.

There is no local test DB or fixture; verifying behavior requires a live MySQL instance with the schema described in `SYSTEM_DOCUMENTATION.md`.

## Architecture

**Effectively a single-file app.** All ~120 endpoints, all middleware, all helpers, and all cron jobs live in `server.js` (~3800 lines). The `database/` and `middleware/` directories exist but are **empty placeholders** — do not assume code is there. The only other source file is `logToDiscord.js`.

When adding an endpoint, follow the existing in-file pattern: `app.post('/name', verifyToken, async (req, res) => { try {...} catch {...} })`, define inline SQL strings, call `queryPromise`, and `res.json({ success: bool, message, ... })`.

### Auth (in-memory, non-persistent)
- `verifyToken` middleware (server.js:311) verifies the JWT (`SECRET_KEY`, 24h expiry) and sets `req.user`.
- `activeSessions` (Map) and `blacklistSessions` (Set) are **in-memory globals** — they reset on every restart. There is no shared session store.
- **Authorization is done inline inside each handler**, not via a middleware — e.g. `if (req.user.adminflag !== 1 && req.user.usertype !== 0) return res.status(403)...`. There is no `verifyAdmin` helper; match the existing inline checks. `usertype`: `0`=manager, `1`=admin, `2`=coach, `10`=student (set from `registercode` at `/register`).

### Database access
- `queryPromise(query, params, showlog)` (server.js:169) — the standard helper: grabs a pooled connection, runs a **parameterized** query, releases. Use this for everything except multi-step transactions.
- `queryPromiseWithConn(connection, ...)` (server.js:204) — same but reuses a caller-held connection, for transactions (`connection.beginTransaction()` / `commit` / `rollback`).
- Pool: mysql2, `connectionLimit: 30`, `timezone: '+07:00'`. Always use `?` placeholders (SQL is built as inline strings — never interpolate user input).

### Dates
Always use the **`momentTH(input)`** helper (server.js:165), which forces `Asia/Bangkok`. The whole system assumes Bangkok time; don't introduce raw `moment()`/`new Date()` formatting for business logic.

### "Journal" table pattern
Pending records live in `j*` tables and approved/live records in `t*` tables: `jstudent` → `tstudent` on admin approval, `jreservation` → `treservation`. Deletes are usually **soft** (`delflag = 1`), not row removal.

### Course-package quota logic (subtle — read the comments)
`tcustomer_course.remaining` is decremented per **paid** booking and restored on cancel; there is no stored "total" column — total is reconstructed as `remaining + COUNT(paid reservations)`. Free bookings (`freeflag`) and `owner = 'trial'` packages do **not** deduct. `coursetype = 'Monthly'` is unlimited (total = NULL). See the long comment at server.js:508 and the `getFamilyMember` query before changing any booking/cancel/quota math.

### Reference-code generation
`generateRefer(refertype)` (server.js:3252) issues human-readable IDs (e.g. `courserefer`) as `TYPE-YYYYMMDD-NNNN` using a daily counter in the `trunning` table.

### Logging (note the global override)
- `console.log` and `console.error` are **reassigned at the bottom of server.js** to pipe into the Winston logger (and `console.error` also fires a Discord error notification). So existing `console.log(...)` calls are intentional logging, not debug leftovers.
- Request/response bodies are logged via Morgan + a custom middleware that **masks** any key containing `image`, `password`, or `token`. `maskSensitiveData` does the same for query params/results. Preserve this masking when touching logging.
- `logToDiscord.js` exposes channel-specific senders (`logSystemToDiscord`, `logLoginToDiscord`, `logBookingToDiscord`, `logCourseToDiscord`, `logStudentToDiscord`, and `logToQueue`). Each Discord channel has its own queue to avoid 429 rate-limits — send through these, don't POST webhooks directly.
- User-facing `message` strings are frequently in **Thai**; match the surrounding endpoint's language.

### File storage
Uploads go to **DigitalOcean Spaces** (S3-compatible, `@aws-sdk/client-s3`, bucket `istar`, region `sgp1`), not local disk. Multer writes a temp file to `uploads/` (5MB limit, images only), which is then streamed to Spaces and deleted. Profile images → `profile_images/`, payment slips → `slip_customer_course/`, logs → `logs/`.

### Scheduled tasks (node-cron, in-process)
- Daily auto-restart at **01:30** (`scheduleRestartAtSpecificTime`) to mitigate memory leaks.
- Log file upload to Spaces **every 55 minutes**; old logs auto-pruned.

## Deployment

This repo is the **production** source.

- **Vercel** — `vercel.json` routes all requests to `server.js`. (istarserver only)
- **DigitalOcean App Platform** — production app `istar-app`
  (https://istar-gymnastics.com) auto-deploys from branch `main` via DO's native
  GitHub auto-deploy. **No GitHub Actions and no `DIGITALOCEAN_ACCESS_TOKEN`
  secret are needed here.** Prod runs continuously (always on) — there is no
  wake/start step.
- The `do-test-window.yml` wake/archive workflow is intentionally **NOT** in this
  repo. It belongs only to the dev fork (`thana-devtest/istarserver_dev` /
  `istarapp_dev`), which manages a separate dev app. Do not add it here — its
  auto-archive step would shut production down every hour.
  
## Further reference

`SYSTEM_DOCUMENTATION.md` and `SYSTEM_REQUIREMENTS.md` (both Thai) contain the full endpoint catalogue, DB schema, table relationships, and feature flows. Consult them for table columns and the full API list rather than re-deriving from SQL strings — but treat `server.js` as the source of truth when they disagree.

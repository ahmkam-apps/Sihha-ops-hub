# SIHAA Food Charity — Operations Hub Memory

_**2026-08-16 secure portal onboarding completion (v1.2.1):** family and volunteer
accounts now use invitation-only onboarding across direct creation, approval/reactivation,
and legacy bulk account creation. Portal onboarding no longer returns, displays, or emails
temporary passwords. Linked email/name/active state is synchronized before access delivery;
the same hashed, one-time 60-minute invitation serves both `/family` and `/portal` users.
Verified with 234 passing tests, 1 intentional skip, and Python/inline-JavaScript syntax
checks._

_**2026-08-15 secure account invitations (v1.2.0):** branch
`agent/secure-account-invitations` adds a 60-minute, single-use, hashed-token account
activation flow and removes password disclosure from the admin reset workflow. The admin
now sends a secure link; the recipient creates the password at `/activate`; consumption
revokes prior sessions and writes an append-only security event. The old reset URL aliases
the new behavior. Verified locally with 227 passing tests, 1 intentional skip, and Python/
inline-JavaScript syntax checks._

_**2026-08-06 current hardening status:** non-paid security/workflow batch `94cbfbf` is live on staging and production. Commit `2b79457` on staging adds DB-backed readiness/throttling, transactional family deletion with financial-history preservation, fail-closed order validation, expiring single-use legacy confirmation tokens, and verified/quota-controlled uploads with orphan cleanup. Signed-in staging acceptance found and locally fixed a cross-portal bundle-quantity mismatch plus a UTC/Central reminder-date edge case. Current verification: 209 passed, 1 intentional live-smoke skip. Paid receipt/payment invariants remain deliberately deferred. Treat `CLAUDE.md` as the current schema/route reference._

_Last updated: 2026-06-11 — **AUDIT REMEDIATION COMPLETE.** Phases 0–3 fully done + Phase 4 high-value items, all deployed to prod (final commit `2201810`). Sequence: `252d986` (backup job + Phase 1) → `c8db8d2` (Phase 2 hardening) → `937097d` (43 finance tests + 4 bug fixes) → `4fcc631`/`20725e4` (Phase 3: dead code, sessions, transactions, N+1, empty-DB dashboard fix) → `2201810` (Phase 4 lite: shared base.css/shared.js, secrets tokens, tmp_ temp-token scoping, receipts gate, Procfile removed). Test suite: 157 passed / 2 skipped. Staging-first deploy protocol in effect and exercised. Off-site backup verified to info@sihha.org; heartbeat 11:00 UTC. Phase 4 remainder (versioned migrations, status constants, exception logging, error envelope, family↔my-order merge) in backlog below — low priority. Manual items: CI 3.10→3.11 via GitHub UI (PAT lacks workflow scope); consider removing SENDGRID_API_KEY from staging._

_**2026-06-15 reconciliation (verified against code):** ops.sihha.org is now **LIVE**; Twilio/SMS **fully removed** — all notifications go via SendGrid email (prod sender `info@sihha.org` via `NOTIFY_FROM_EMAIL` env; code default `ops@sihha.org`); APScheduler runs **8 jobs** (7 daily + a new **hourly Wix donation sync**: `/api/donations/sync-wix` + `_sync_wix_donations_job`, deployed commit `eef0d62`); all GitHub PATs were **revoked** — auth is via macOS Keychain, never embed a token in a URL. The Infrastructure / Tech-Stack / Scheduler-Jobs tables below are corrected to match. ⚠️ Some deep sections still date from 2026-05-02; treat CLAUDE.md as the authoritative current reference._

---

## Project Summary

Building a **cloud-based Operations Hub** for **SIHAA Food Charity (Rochester, NY)** to digitize and replace their current Google Forms + Google Spreadsheet workflow.

Manages: family intake, volunteer coordination, food shopping/delivery cycles, bundle assignments, receipt submission, reimbursement processing, donation tracking, and financial reconciliation.

**Philosophy:** Simple, scalable, no cutting corners. Build it right once. Current system is working — we are building the new system in parallel and migrating. Always recommend the logical, appropriate, cost-effective solution. **Minimum clicks** — every action should take as few clicks as possible.

**Terminology:** "Coordinator" and "Admin" are the same person/role throughout the system. No distinction.

---

## Live Deployment

| Item | Value |
|------|-------|
| Live URL (prod) | **https://ops.sihha.org** (+ https://sihha-ops-hub-production.up.railway.app) |
| Staging URL | https://dev-staging-sihha-production.up.railway.app (deploys from `staging` branch) |
| GitHub Repo | https://github.com/ahmkam-apps/Sihha-ops-hub.git |
| Hosting | Railway (auto-deploys: `master` → prod, `staging` → staging) |
| Admin Login | admin / (set via ADMIN_PASSWORD env var in Railway) |
| Public Intake | /intake |
| Public Volunteer Signup | /volunteer |
| Public Volunteer Portal | /portal |
| Family Order Portal | /family (was /my-order — 301 redirect kept) |
| Family Bundle Opt-In | /confirm/<token> |
| Public Donate Stats Widget | /donate-stats |
| order.html | ⚠️ RETIRED — shows WA flow explanation + link to /intake |

---

## Infrastructure

| Item | Status | Notes |
|------|--------|-------|
| Railway Volume | ✅ LIVE | Mounted at `/app/data` |
| DB_PATH env var | ✅ Set | `/app/data/sihaa.db` |
| ADMIN_PASSWORD env var | ✅ Set | Synced to DB on every deploy |
| APP_URL env var | ⚠️ Should be set | Used for confirmation links: `https://ops.sihha.org` (SMS removed — links now emailed) |
| GitHub auth | macOS Keychain (`credential.helper osxkeychain`) | ✅ All PATs revoked 2026-06-15 — never embed a token in the remote URL |
| Custom subdomain | ✅ LIVE | ops.sihha.org → Railway |
| Wix buttons | 🔲 Pending | "Get Help" → /intake, "Volunteer" → /volunteer |
| Stripe MCP plugin | 🔲 Pending | Phase 4D reconciliation |
| Rashid treasurer account | 🔲 Pending | Add email address for treasurer notifications |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask 3.0.3 |
| Database | SQLite (WAL mode), Railway Volume |
| WSGI | Gunicorn 2 workers |
| Frontend | Vanilla JS, single-file HTML SPAs |
| Auth | Bearer token, DB-persisted sessions |
| SMS | ❌ Removed — Twilio fully stripped; `/api/otp/*` + `/api/portal/login` return **410**; `otp_tokens` + `portal_sessions` tables dead |
| Scheduling | APScheduler — 8 jobs (7 daily + hourly Wix donation sync) |
| Charts | Chart.js 4.4.1 (CDN) |
| Email | SendGrid (SENDGRID_API_KEY env var) — ALL notifications; prod sender `info@sihha.org` (via `NOTIFY_FROM_EMAIL` env; **code default is `ops@sihha.org`**) |

---

## Repository Structure

```
sihaa-ops-hub/
├── server.py              # Flask backend, all API routes (~5000+ lines)
├── public/
│   ├── index.html         # Admin SPA (all admin modules)
│   ├── intake.html        # Public family registration
│   ├── volunteer.html     # Public volunteer signup
│   ├── portal.html        # Volunteer portal (Sign Up / My Tasks / History + receipts)
│   ├── family.html        # Family self-service portal (view order, cancel, request change) — was my-order.html
│   ├── my-order.html      # RETIRED — 301 redirect to /family (keep for old SMS links)
│   ├── confirm.html       # Family bundle opt-in (token-based) ✅
│   ├── order.html         # RETIRED — informational redirect page
│   └── donate-stats.html  # Donation stats widget (iframe embed for Wix)
├── import_data.py         # Historical data import script
└── tests/
```

---

## Full Data Model

```
users (system users — roles: admin | volunteer | finance | treasurer | viewer | family)
  NOTE: "coordinator" and "admin" are the same role — no distinction
  NOTE: family + volunteer PORTAL users are rows here too (role='family' / 'volunteer'),
        linked to their family/volunteer record via linked_id + linked_type.
        Auth = username/password → Bearer token in `sessions` (NOT phone-based anymore)

sessions (admin bearer tokens)
portal_sessions (volunteer portal tokens — phone-based login, 48hr expiry)

families
  ├── wa_phone, wa_apikey   ← CallMeBot (still in DB schema, but removed from all admin UI — WA stripped)
  ├── family_code           ← unique: last 6 phone digits + bundle letter (e.g. "398540-M")
  ├── bundle_size, pending_bundle_size  ← S/M/L; pending_* drives request/approve-bundle-change routes
  ├── email                 ← login credentials + notifications
  ├── city, family_size, children_count, income_range, frequency  ← all editable in admin
  └── status: pending | active | inactive   (⚠️ 'paused' was migrated → inactive and removed from the CHECK)

volunteers
  ├── wa_phone, wa_apikey   ← CallMeBot (still in DB schema, removed from all admin UI — WA stripped)
  └── status: pending | active | inactive

delivery_cycles
  ├── status: upcoming | open | shopping | delivered
  │   upcoming = created, not yet open for orders
  │   open = "Accepting Orders" — families can submit (T-7 to T-5 window)
  │   shopping = orders locked, volunteers shopping
  │   delivered = cycle complete
  ├── delivery_date_start, delivery_date_end (Sat–Sun)
  └── request_open_at, request_close_at (legacy fields — not used in current flow)

food_requests  ← ONE per family per cycle
  ├── status: pending_confirmation | confirmed | auto_confirmed | skipped | submitted | delivered | cancelled
  │   ⚠️ 'submitted' = created by legacy order.html flow (different from opt-in flow)
  │   ⚠️ Shopping list filters to status='confirmed' ONLY — 'submitted' orders are EXCLUDED
  ├── bundle_size: S | M | L  (computed from family_size, never shown to family)
  ├── confirmation_token   ← UUID used in /confirm/<token> link
  ├── confirmation_sent_at ← prevents double-send
  ├── confirmed_at
  └── updated_at           ← added via ALTER TABLE migration (safety net in bootstrap_db)

food_request_items  ← one row per food_item per food_request
  └── selected: 0 | 1

food_request_events  ← append-only audit log per order
  ├── event_type: confirmed | items_edited | admin_edit_items | cancelled | auto_skipped | admin_override
  │              | change_requested | change_approved | change_rejected | change_retracted
  │              (⚠️ 'order_reset' is NOT emitted anywhere — removed; code uses 'admin_edit_items')
  └── actor: family | admin | scheduler | system

order_change_requests  ← family-submitted item change requests, one active per order at a time
  ├── status: pending | approved | rejected | retracted
  ├── family_notes  ← family's free-text reason
  ├── payload JSON  ← {selected_item_ids: [...]}
  ├── admin_notes   ← admin's response message (sent via WA on approve/reject)
  └── reviewed_by → users.id

food_categories    (Grains, Protein, Produce — display_order sorted)
food_items         (Rice, Pasta, Bread, Eggs, Canned Beans, Whole Chicken, Brown Lentils, Potatoes, Oranges, Bananas)
bundle_quantities  (quantity per item per bundle size S/M/L)
bundle_size_rules  (S: 1–2, M: 3–5, L: 6+)

volunteer_slots  ← ONE row per family per task per cycle (open slot model)
  ├── task_type: any slug from volunteer_task_types
  ├── claimed_by → volunteers.id  (NULL when open)
  ├── prev_claimed_by → volunteers.id  ← tracks last holder before release (for portal history)
  ├── status: open | claimed | confirmed | complete | cancelled
  │   open      = slot exists, no volunteer signed up
  │   claimed   = volunteer signed up, family has NOT yet placed order
  │   confirmed = volunteer signed up + family has placed order (← NEW)
  │   complete  = delivery/shopping done
  │   cancelled = slot cancelled (not re-used)
  ├── PRE-CREATION MODEL (NEW):
  │   _pre_create_slots_for_cycle(db, cycle_id) — called on cycle creation/seeding
  │   _pre_create_slots_for_family(db, family_id) — called when family activated
  │   Creates open slots for ALL is_family_slot=1 task types, ALL future cycles (12 months)
  │   Volunteers can sign up as soon as slots are created (before family orders)
  ├── LIFECYCLE: open → claimed (volunteer signs up) → confirmed (family orders) → complete
  ├── 3-day auto-release: if claimed slot and no family order 3 days before delivery → flip to open + WA volunteer
  ├── portal_signup() CLAIMs the open slot via UPDATE (not INSERT) — one volunteer per slot
  │   portal_cancel_slot() RELEASEs back to open (sets prev_claimed_by = claimed_by, claimed_by = NULL)
  └── Conflict detection: if slot already claimed by another, returns 409 with their name

volunteer_task_types  (admin-configurable: Shop, Delivery, Stock + custom)
  └── is_family_slot: 0|1 — if 1, pre-create one slot per family per cycle (Shopping + Delivery default to 1)
receipts        ← volunteer shopping receipts; slot_id → volunteer_slots.id
reimbursements  ← treasurer approves payment
donations       ← manual + imported
bank_transactions, stripe_transactions, wix_donations  (Phase 4D)
reminder_log    ← idempotency guard for WA volunteer reminders
```

---

## Scheduler Jobs (APScheduler — runs in each gunicorn worker; idempotent)

| Job ID | Schedule (UTC) | What it does |
|--------|-----------|--------------|
| `session_purge` | daily 06:45 | Purge expired `sessions` + `portal_sessions` |
| `daily_db_backup` | daily 07:30 (+ on deploy) | SQLite online-backup → `data/backups/`, keep 14; off-site copy emailed (`BACKUP_EMAIL`) |
| `daily_reminders` | daily 08:00 | Email reminder to volunteers with delivery slots 2 days out |
| `family_opt_in_notifications` | daily 09:00 | T-7 before delivery: creates food_requests + emails opt-in link to each active family |
| `family_cutoff_skip` | daily 09:30 | T-5 before delivery: marks all `pending_confirmation` requests as `skipped` |
| `auto_release_unconfirmed_slots` | daily 10:00 | 3 days before delivery: releases `claimed` slots with no family order; emails volunteer; idempotent via reminder_log |
| `daily_heartbeat` | daily 11:00 | Emails active admins: backup freshness, active cycle/orders/open slots, 24h notification count, pending queues |
| `wix_donation_sync` | **hourly (:00)** | Pulls PAID Wix donation orders into `donations` (dedup by Wix order id); no-op if `WIX_API_KEY` unset — added 2026-06-15 |

---

## Family Self-Service Portal (`/family` → `family.html`) — Current State ✅

- Login: **username/password via `/login`** — a `role='family'` user (linked to the family via `linked_id`) gets a Bearer token stored as `familyToken`; family.html sends it on `/api/food-order/check`. **Verified working end-to-end** (login.html routes by role → stores familyToken → /family consumes it). Old phone/OTP routes return 410; family.html still contains the OTP functions but they are **dead stubs** (labeled "no longer used" — redirect to /login before firing). Harmless; optional cleanup only.
- **Two tabs: "My Deliveries" | "History"**

### My Deliveries tab
- Shows ALL delivery cycles within next 12 months (was 30 days) (+ any active order outside that window)
- Each cycle = one card with state-aware content:
  - **Open, no order**: "Order for this delivery" button → inline item checklist + notes → [Confirm Order]
  - **Confirmed order**: shows items as chips, cancel/request-change actions, pending CR banner, event timeline toggle
  - **Shopping, no order**: locked note ("Shopping in progress")
  - **Upcoming, no order**: "Coming soon" note
- Notes field on initial order (optional, stored in `food_requests.family_notes`)
- Cancel: direct (must be **≥1 day before the delivery date** — calendar-day, Central time), releases volunteer slots, emails coordinators + volunteers
- Request Change: approval-gated, one pending at a time, retractable
- After any action: refreshes full state from API
- Shows **volunteer assignment strip** at bottom: shopper + deliverer names with ✓ confirmed / ⏳ pending status
- Admin-cancelled orders: amber box "order was cancelled by our team, you can place a new order" (family can re-order)

### History tab
- All past orders with status delivered/cancelled/skipped
- Shows cycle title, date range, status pill

### API
- `GET /api/food-order/check?phone=` now returns `{cycles: [], history: []}` multi-cycle format
- `POST /api/food-order` updated: accepts optional `notes` field, logs event, notifies coordinators
- Bilingual UI (English + Arabic), PWA-enabled

---

## Family Opt-In Delivery Flow (LIVE ✅)

1. Cycle created → no food_requests created
2. T-7 days: scheduler creates `food_requests` (status=`pending_confirmation`) + sends WA opt-in link
3. Family taps link → `/confirm/<token>` → selects/deselects items → confirms or declines
4. T-5 days cutoff: any still `pending_confirmation` → marked `skipped`
5. Shopping list = **only `confirmed`** families
6. Families without WA credentials: food_request still created, admin sees "No Response", manually overrides

---

## Admin SPA Modules (index.html) — Current State

### Navigation
Dashboard → Deliveries → Families → Volunteers → Finance → 📋 Change Requests

### Dashboard
- Active delivery banner: status, family count, slot progress
- **Active cycle priority: `open` → `shopping` → `upcoming`** — banner and Orders/Slots/Remind buttons show for `open` cycles (was missing `open` before)
- Status colours: open = amber (#e07b00), shopping = blue, upcoming = green
- **Needs Attention alerts**: pending families, pending volunteers, pending payments, **pending change requests** (links to Requests inbox)
- Chart.js donation chart (bar + projection line)
- Projection calculator with sliders
- "Seed 2026 Deliveries" button

### Deliveries
- Table: all cycles, clickable rows → detail view
- Status advance: upcoming → open → shopping → delivered (manual)
- Detail view: confirmation response board — Confirmed / Declined / No Response stats + per-family override buttons
- **Volunteer Coverage table** (NEW): below Family Responses — shows each confirmed family's Shopper + Deliverer slot status. Red = open (no volunteer), amber = claimed, green = confirmed. Summary: "X need a shopper · Y need a deliverer"

### Families
- Table: all families, clickable rows → full-page family profile
- **Current cycle strip**: status badge + override buttons (Confirm / Skip / Mark Confirmed)
  - **✕ Cancel button** (NEW): admin-initiated cancel — prompts for reason, hard-deletes order row, releases volunteer slots, family can re-order. Tooltip: "Cancels the order and frees the delivery slot — family can place a fresh order."
  - **↺ Reset button**: silently wipes confirmed order back to pending (items cleared); for already-cancelled orders, deletes the record. Tooltip explains the difference.
- Edit grid: all fields editable, auto-save
- Delivery history table with inline event callout showing most recent edit/cancel
- Inline event log (collapsible)

### Volunteers
- Table: all volunteers, clickable rows → profile
- Profile: role switcher, task history
- Task Types manager: `is_family_slot` checkbox ("Per family" — creates a slot per family per cycle for this task type). Shopping + Delivery default to 1.
- **📊 Activity Report** (NEW): per-volunteer lifetime stats — tasks done, shopping/delivery breakdown, cycles, families served, last active. CSV export. Accessed via button in Volunteers topbar. API: `GET /api/reports/volunteer-activity`

### Finance
- Donations, Receipts, Reimbursements, Users

### 📋 Change Requests
- Centralized inbox: all pending requests across all families/cycles
- Each card shows: family name, cycle, family's notes, requested item list
- Approve (auto-applies item changes + WA to family) or Reject (WA to family with admin note)
- Recent resolved requests shown below

---

## Volunteer Portal (`/portal` → `portal.html`) — Current State ✅

- Login: **username/password** — a `role='volunteer'` user linked to the volunteer → Bearer token in `sessions`. ⚠️ Phone-only login + OTP **removed** (`/api/portal/login`, `/api/otp/*` → 410); `portal_sessions` + `otp_tokens` tables are now dead.
- **Two tabs: "Deliveries" (default) | "History"**

### Deliveries tab — two sections on one page
**My Sign-Ups** (top):
- Lists every family the volunteer has committed to: task type badge, family code, delivery date, status
- Status: green border = confirmed (family ordered), amber border = pending (waiting for family order)
- Shows shopping item list for confirmed shopping tasks, delivery address for confirmed delivery tasks
- Receipt submit/update button for shopping tasks
- Mark Done button for delivery tasks
- If no sign-ups: "You haven't signed up yet"

**Available Families** (below):
- All `open`/`shopping` cycles loaded in parallel — no cycle selector needed
- Each family shows order badge: "✓ Order placed" (confirmed/submitted/delivered only) or "⏳ No order yet"
- Four slot states: Mine-confirmed (green), Mine-pending (amber), Taken (grey + name), Open (signup button)
- Multiple volunteers allowed on same order in different task types (by design)
- Cycle header shown when multiple active cycles exist

**Real-time updates:**
- `silentRefreshTasks()` runs every 60 seconds while Deliveries tab is open
- Re-fetches My Sign-Ups silently — shopping list updates automatically if family changes items
- Pauses when browser tab hidden, catches up on return
- Polling stops on logout or switching to History tab

### History tab
- Lifetime stats: tasks done, shopping, deliveries, cycles, families served
- Completed task list

### Key business rules
- One slot per task type per family per cycle (one shopper + one deliverer)
- Same volunteer can claim both tasks on same family (by design)
- `portal_get_families` LEFT JOIN only matches `confirmed`/`submitted`/`delivered` orders — cancelled/pending never show as "Order placed"
- Receipt modal: submit photo + amount + store

---

## Key API Routes

### Family (`require_family_auth` — username/password Bearer token)
- `GET /api/food-order/check?phone=` — eligibility check, returns full order state + `can_request_change` + `pending_change_request` (still takes a phone param)
- `POST /api/food-order` — confirm order (initial submission)
- `PUT /api/food-order/items` — family edits items on an existing order
- `POST /api/food-order/cancel` — direct cancel (no approval; must be **≥1 day before the delivery date**, Central time)
- `POST /api/family-request` — submit item change request with notes
- `POST /api/family-request/<id>/retract` — retract pending request (method is **POST**, not DELETE)
- `POST /api/families/<fid>/request-bundle-change` + `/approve-bundle-change` — bundle-size change flow (uses `pending_bundle_size`)

### Admin (require_auth)
- `GET /api/admin/change-requests?status=pending|all` — request inbox
- `POST /api/admin/change-requests/<id>/approve` — apply items + WA family
- `POST /api/admin/change-requests/<id>/reject` — reject + WA family with note
- `POST /api/families/<fid>/reset-order` — silent order reset (confirmed→pending_confirmation, items cleared), releases volunteer slots. For already-cancelled orders: deletes record. Tooltip: "Rolls confirmed order back to pending. For cancelled orders, deletes the record."
- `POST /api/families/<fid>/cancel-order` — **admin cancel** (NEW): releases claimed/confirmed slots, logs cancelled event with actor='admin', hard-deletes order row so family can re-order, WA to coordinators. Takes optional `cycle_id` + `reason` in body.
- `POST /api/families/<fid>/manual-confirm` — add family to current cycle

---

## ⚠️ AUDIT FINDINGS — Bugs & Inconsistencies

### ALL CRITICAL BUGS FIXED ✅

| # | Fix | Commit |
|---|-----|--------|
| A | order.html retired | 2026-04-28 |
| B | intake.html status→pending | 2026-04-28 |
| C | intake.html success page updated | 2026-04-28 |
| D | portal_get_families confirmed filter | 2026-04-28 |
| E | Confirm button updated_at column fix | 2026-04-29 |
| F | Volunteer double-booking fix | 2026-04-29 |
| G | "No upcoming delivery" false negative | 2026-04-29 |
| H | Confirmed order shows no items | 2026-04-29 |
| — | cancel_food_order 500 → JSON error + try/except | 2026-04-29 |
| — | bootstrap_db crash (missing row_factory) | 2026-04-29 |

### MINOR (low priority)
- **L**: Volunteer portal sign-up tab empty until T-7 — acceptable
- **M**: Volunteer role not enforced in portal — intentional flexibility
- **N**: confirm.html header says "SIHAA Food Charity" vs "Sihha" elsewhere — brand inconsistency

---

## 2026 Delivery Cycle Schedule

Seeded via "Seed 2026 Deliveries" button. All Sat–Sun, bi-weekly.

May 9-10, May 23-24, Jun 6-7, Jun 20-21, Jul 4-5, Jul 18-19, Aug 1-2, Aug 15-16, Aug 29-30, Sep 12-13, Sep 26-27, Oct 10-11, Oct 24-25, Nov 7-8, Nov 21-22, Dec 5-6, Dec 19-20

---

## Active Backlog

### 🚨 Phase 0 — Operational robustness (jumps the queue — bigger risk than any code bug)

| # | Item | Notes | Status |
|---|------|-------|--------|
| 0.1 | **Daily DB backup job** | ✅ DONE 2026-06-09 — `_daily_backup_job()` in server.py: SQLite online-backup API → `data/backups/sihaa-YYYYMMDD.db`, keeps 14, runs 07:30 UTC + once on deploy, idempotent across workers. Uploads folder NOT yet included (covered by 0.2) | ✅ |
| 0.2 | **Off-site backup copy** | ✅ DONE & VERIFIED 2026-06-11 — `BACKUP_EMAIL=info@sihha.org` set in Railway prod; first snapshot email received (79 KB gz). Arrives daily ~07:30 UTC. Auto-warns if DB outgrows the 10MB email cap → then move to S3/B2 | ✅ |
| 0.3 | **Staging environment** | ✅ DONE & VERIFIED 2026-06-11 — Railway staging service deploys from `staging` branch: https://dev-staging-sihha-production.up.railway.app — own DB (`sihaa_staging.db`, fresh), ADMIN_PASSWORD set. **Deploy protocol: push to `staging` → verify → fast-forward same commit to `master`.** ⚠️ staging has a live SENDGRID_API_KEY — keep staging data synthetic or remove the key | ✅ |
| 0.4 | **Heartbeat / monitoring** | ✅ DONE 2026-06-10 — `_daily_heartbeat_job()` 11:00 UTC: emails active admins backup status/freshness, active cycle + orders + open slots, 24h notification count, pending queues. Requires admin users to have email addresses set | ✅ |

### 🔴 Phase 1 — Critical fixes from code audit (2026-06-09) — ~2h total

| # | Item | Where | Status |
|---|------|-------|--------|
| 1.1 | Startup guard: refuse to boot in prod if `ADMIN_PASSWORD` env var unset | ✅ DONE 2026-06-09 — raises RuntimeError when RAILWAY_* env detected and var missing; local dev still falls back | ✅ |
| 1.2 | Atomic slot claim | ✅ DONE 2026-06-09 — `AND status='open'` + rowcount check in portal_signup, 409 with holder name on race; preserves all-or-nothing semantics (no commit before return) | ✅ |
| 1.3 | Upload size limit | ✅ DONE 2026-06-09 — `MAX_CONTENT_LENGTH` = 16 MB | ✅ |
| 1.4 | Duplicate test class | ✅ DONE 2026-06-09 — second class renamed `TestFoodItemPricing`; all 5 shadowed tests recovered and passing (suite: 114 passed, 2 skipped) | ✅ |
| 1.5 | Python version pin | ✅ DONE 2026-06-09 — `.python-version` (3.11) un-gitignored (nixpacks reads it natively); CI bumped 3.10→3.11; nixpacks.toml stays ignored (previously broke Railway builds) | ✅ |

### 🟠 Phase 2 — High priority — ~1 day

| # | Item | Where | Status |
|---|------|-------|--------|
| 2.1 | Stored XSS | ✅ DONE 2026-06-10 — `esc()` + `escJs()` helpers added; 229 interpolation sites wrapped (index.html 204, portal.html 25); ad-hoc partial escapes normalized; node --check passed | ✅ |
| 2.2 | Login rate limiting | ✅ DONE 2026-06-10 — in-memory throttle on `/api/auth/login`: 5 fails per (IP, username) per 15 min → 429; functionally verified | ✅ |
| 2.3 | CORS | ✅ DONE 2026-06-10 — restricted to railway URL + sihha.org domains; override via `CORS_ORIGINS` env var | ✅ |
| 2.4 | `_recreate_users_table` data loss | ✅ DONE 2026-06-10 — copies PRAGMA table_info column intersection; late-added columns survive rebuilds | ✅ |
| 2.5 | `make_conn()` factory | ✅ DONE 2026-06-10 — all 4 scheduler jobs + get_db share one factory (WAL, FK ON, busy_timeout 5s); bootstrap conn got busy_timeout | ✅ |
| 2.6 | Guard-before-send in reminder jobs | ✅ DONE 2026-06-10 — opt-in job reserves reminder_log row first (rowcount-gated, guard released on send failure); auto-release job email gated on guard rowcount | ✅ |

### 🟡 Phase 3 — Medium — week 2–3

| # | Item | Notes | Status |
|---|------|-------|--------|
| 3.1 | Tests for finance domain | ✅ DONE 2026-06-11 — 43 tests added (receipts, approval→reimbursement auto-create, payments, donations + export, finance summary math, portal receipt flow). Suite: 157 passed. Found + fixed 4 prod bugs: payment-sent email never fired (SELECT phone vs vol['email']), receipt submit never auto-completed slot (stale 'claimed' guard), negative amounts accepted, invalid payment_method → 500. Remaining oddity (documented, not fixed): GET /api/receipts readable by any authenticated role | ✅ |
| 3.2 | Add ~6 missing indexes | ✅ DONE 2026-06-10 — 8 added: `families(phone)`, `volunteer_slots(family_id)`, `receipts(slot_id/volunteer_id/cycle_id)`, `sessions(expires_at)`, `donations(cycle_id)`, `reminder_log(slot_id,sent_to)` | ✅ |
| 3.3 | Batch N+1 queries | ✅ DONE 2026-06-11 — `get_orders` items batched into one IN-query; `list_families` 4 correlated subqueries/row replaced with single slot scan. Eligibility-check loop left as-is (family-facing critical path, defer until measured) | ✅ |
| 3.4 | Delete dead code | ✅ DONE 2026-06-11 — `/api/assignments` (3) + `/api/cycle-assignments` (3) routes deleted, `auto_update_cycle_statuses` no-op removed, volunteer.html + order.html dropped from git tree (redirects remain). Tables (`assignments`, `cycle_assignments`, `stripe_transactions`, `wix_donations`) retained — drop in a future migration | ✅ |
| 3.5 | gunicorn `--preload` | ✅ DONE 2026-06-10 — Procfile + railway.json. bootstrap_db + APScheduler now run ONCE in the gunicorn master (verified: single "APScheduler started" log line). Migration races and double-job execution eliminated; reminder_log guards remain as defense | ✅ |
| 3.6 | Session hygiene | ✅ DONE 2026-06-11 — nightly purge job (06:45 UTC, sessions + portal_sessions); expiry slide throttled to at most hourly per session (was a write per request) | ✅ |
| 3.7 | Transaction discipline | ✅ DONE 2026-06-11 (key flows) — family cancel + admin cancel now single-transaction (event log + deletes atomic). Remaining multi-commit functions are benign (branch-exclusive or idempotent follow-ons). Bonus fix: dashboard RangeError on empty donations table (Array(-1) in projection chart) | ✅ |

### ⚪ Phase 4 — Ongoing / structural

| Item | Notes | Status |
|------|-------|--------|
| Split bootstrap_db (1,300 lines) into schema / versioned migrations / seeds + `schema_version` table | | 🔲 |
| Extract shared `public/js/api.js` + `base.css` | ✅ DONE 2026-06-11 — `public/css/base.css` (fonts + reset, 7 pages) and `public/js/shared.js` (`esc`, `escJs`, `makeApi` factory; index + portal wired). `/css/` + `/js/` routes added; sw.js cache → v6. family↔my-order page merge NOT done (escHtml semantics differ — deferred) | ✅ |
| Status string constants (`'confirmed'` ×62 inline; inconsistent `status IN (...)` lists are latent bugs) | | 🔲 |
| Log every silent `except: pass` (25 sites); standardize error envelope on `{'error': ...}`; stop echoing exception text (cancel route) | | 🔲 |
| Remove/strip `/api/admin/db-debug` traceback leak; `secrets.token_urlsafe` for session tokens; reject temp_tokens in require_auth | ✅ DONE 2026-06-11 — all three + `GET /api/receipts` tightened to admin/finance/treasurer. Temp tokens now `tmp_`-prefixed, rejected by require_auth, accepted only by set-password | ✅ |
| Consolidate start command; delete repo cruft | ✅ DONE 2026-06-11 — Procfile + 0-byte `master` dropped from git tree (railway.json is the single start-command source); pytest caches gitignored | ✅ |
| Update stale docs: CLAUDE.md (writable_schema hack removed; portal login is 410; volunteer.html/order.html are dead redirects) | | 🔲 |

### 🟡 Pre-existing backlog (carried forward)

| Item | Notes | Status |
|------|-------|--------|
| Phase 4D: Financial reconciliation | **Wix donation sync ✅ DONE 2026-06-15** (hourly job + `/api/donations/sync-wix`). Stripe + bank CSV import + matching still pending | ◑ |
| Revoke old GitHub token | ✅ DONE 2026-06-15 — all PATs revoked; auth via macOS Keychain, no token in URL | ✅ |
| ops.sihha.org DNS → Railway | ✅ DONE — custom subdomain LIVE | ✅ |
| Wix buttons | "Get Help" → /intake, "Volunteer" → /volunteer | 🔲 |
| Donate-stats widget on Wix | iframe embed (`/donate-stats` + widget-progress fundraising bar) | 🔲 |
| Notification triggers (now via SendGrid email — Twilio/SMS fully removed) | Intake received, family activated, volunteer approved, T-5 skipped, delivery on its way | 🔲 |

---

## Completed Work (this session + prior)

| Item |
|------|
| Volunteer slot model redesign: pre-created slots (12 months), open→claimed→confirmed→complete lifecycle ✅ |
| volunteer_task_types.is_family_slot flag: controls which task types get pre-created per family per cycle ✅ |
| volunteer_slots.status 'confirmed' added: migration removes CHECK constraint, rebuilds table ✅ |
| _pre_create_slots_for_cycle() + _pre_create_slots_for_family() helpers ✅ |
| Order confirm hook: flips claimed→confirmed slots + WA to volunteers with item list / address ✅ |
| 3-day auto-release scheduler job: releases unconfirmed claimed slots, WA to volunteers ✅ |
| Admin cancel order (POST /api/families/<fid>/cancel-order): hard-deletes order, frees slot, family can re-order ✅ |
| Admin cancel vs family cancel distinction: actor='admin' on event, amber box on my-order.html ✅ |
| Hover tooltips on Cancel and Reset buttons in admin family profile ✅ |
| portal_get_families() returns ALL active families (not just confirmed orders) + order_status + my_status ✅ |
| Volunteer portal Sign Up tab: order status badge per family, pending/confirmed slot states ✅ |
| Volunteer portal My Tasks tab: split into Confirmed / Waiting for Family Order / Done sections ✅ |
| Shopping item list in My Tasks for confirmed shopping slots ✅ |
| Family portal 12-month window: check_food_order_eligibility + portal_list_cycles extended to 365 days ✅ |
| my-order.html volunteer assignment strip: shows shopper + deliverer names with confirmed/pending state ✅ |
| Food catalog quantity fields (S/M/L) in add/edit item drawer ✅ |
| Admin catalog table: Small/Medium/Large columns now display values (data-bq attributes) ✅ |
| my-order.html redesigned: multi-cycle hub (12 months), inline order form, History tab, notes field ✅ |
| Family change request workflow: submit/retract, admin inbox, approve/reject, auto-apply, reset order ✅ |
| WA notification to volunteer when admin reassigns their slot ✅ |
| Volunteer portal: "Removed Assignments" section for released slots ✅ |
| Volunteer portal: two-tab layout (Deliveries + History), Deliveries = My Sign-Ups + Available Families ✅ |
| Volunteer portal: Available Families loads ALL open/shopping cycles in parallel — no cycle selector needed ✅ |
| OTP SMS login: Twilio integration, otp_tokens table, two-step login on both portals ✅ |
| OTP dev mode fix: always return code in JSON when OTP_DEV_MODE=true (Twilio accepts but carrier silently drops) ✅ |
| Volunteer coverage table in cycle detail: confirmed families × shopper/deliverer slot status, red/amber/green ✅ |
| Volunteer activity report: lifetime stats per volunteer, CSV export, GET /api/reports/volunteer-activity ✅ |
| Renamed /my-order → /family (family.html); /my-order kept as 301 redirect; SW bumped to v4 ✅ |
| WhatsApp fully stripped from admin UI (index.html): WA columns, filter tabs, setup page, banners, profile fields, form fields all removed ✅ |
| Service worker cache bumped to v3: forces fresh page loads for all users ✅ |
| nixpacks.toml deleted: was causing `No module named pip` build errors; nixpacks now auto-detects correctly ✅ |
| railway.json: forced NIXPACKS builder to prevent railpack build-secret false positive on TWILIO_ACCOUNT_SID ✅ |
| twilio + sendgrid added to requirements.txt: were missing, caused build failures ✅ |
| Family portal: phone stored in localStorage — session survives page refresh ✅ |
| Volunteer portal: accordion upcoming deliveries for all 2026 cycles, lazy-load + cache ✅ |
| Volunteer portal: real-time shopping list — silentRefreshTasks() polls every 60s, updates items if family changes them ✅ |
| Volunteer portal: order placed badge only shows for confirmed/submitted/delivered — cancelled/pending excluded ✅ |
| Admin dashboard: active cycle banner now recognises `open` status (was only shopping/upcoming) ✅ |
| Admin Food Orders: default cycle selection prefers open → shopping → upcoming ✅ |
| Admin family profile: "Food Orders" section shows all non-terminal orders across all cycles ✅ |
| manual-confirm: now flips existing claimed slots to confirmed + sends WA to volunteers ✅ |
| WA credentials workflow: WA column in tables, profile banners, confirmation board split, dashboard alert, WA Setup page ✅ |
| Admin family history: inline callout showing most recent edit/cancel without expanding ✅ |
| cancel_food_order: wrapped in try/except, always returns JSON, logs actual error ✅ |
| bootstrap_db crash fix: added row_factory to bootstrap connection ✅ |
| Order audit trail: food_request_events table + _log_order_event() + _notify_coordinators() ✅ |
| Family item change request (now approval-gated): replaced direct Edit Order ✅ |
| Cancel order: direct (no approval), 24h window, releases volunteer slots, WA notifications ✅ |
| Order Activity timeline in family portal ✅ |
| Admin family history: event log per cycle row ✅ |
| Auto-create volunteer slots on order confirmation (_ensure_volunteer_slots) ✅ |
| Volunteer portal: conflict-safe claiming, taken/mine/open slot states ✅ |
| Family order-first lookup: always shows confirmed order regardless of cycle status ✅ |
| Admin manual-confirm + reset order buttons in family profile ✅ |
| Rebuild family profile: full-page, all fields editable, delivery history ✅ |
| Rebuild scheduler: T-7 opt-in WA + T-5 skip cutoff ✅ |
| Confirmation response board in delivery detail ✅ |
| Configurable volunteer task types ✅ |
| Seed 2026 bi-weekly delivery cycles ✅ |

---

## GitHub Push / Deploy Process

Canonical local clone: `~/Documents/Claude/Projects/RAILWAY_Sihha-Ops-Hub/Sihha-ops-hub` (real git, on `master`).

- Claude edits files there directly (the Cowork mount blocks git plumbing, but file edits work). Claude **never pushes** — it hands over a patch when a change spans many files.
- The **user runs all git from their own Terminal** (where git works), authenticated via macOS Keychain — **no token in the URL**.
- **Deploy protocol (staging-first):** push to `staging` → verify → fast-forward the same commit to `master`. Railway auto-deploys `master` to prod (Wait-for-CI gate ≈ 1 min, then build ~1–2 min).

```bash
cd ~/Documents/Claude/Projects/RAILWAY_Sihha-Ops-Hub/Sihha-ops-hub
git add <files> && git commit -m "message"
git push origin staging      # deploys to dev-staging-sihha — verify first
git checkout master && git merge staging && git push origin master
```

---

## Design System

- Black/white, zero border radius, Area font (AreaExtrabold + AreaNormal from Wixstatic CDN)
- Sihha brand: #111111 black, #ffffff white, grayscale
- Minimum clicks philosophy
- confirm.html uses #1a3a2a dark green (family-facing pages have softer brand feel)
- Admin UI: auto-save indicators in green (#1a8754), 2.5s fade-out
- Amber (#fff8e6 / #f0c040) for warnings and pending states
- Red (#fdecea / #c00) for cancelled/rejected states

---

## How SIHAA Operates

- Bi-weekly deliveries (every 2 weeks, Sat–Sun)
- Bundle sizes: S (1–2 people), M (3–5), L (6+) — **never shown to families as letters** (shown as Small/Medium/Large)
- Shopping volunteers buy groceries, drop at Abu Baqr mosque, submit receipt via portal
- Delivery volunteers pick up from Abu Baqr, deliver to family home
- Stock volunteers: new role (TBD exact duties)
- Privacy: family addresses shared ONLY with delivery volunteers who claimed that family's slot
- Volunteer portal login: phone number only → 48hr session
- Family opt-in: WA link → /confirm/<token> → select/deselect items → confirm or decline
- Family opt-in notifications: currently manual (WA stripped, SMS notifications not yet wired — pending 10DLC approval)
- Families without SMS: admin manually contacts and overrides status in admin panel

### Key Contacts
| Role | Name | Phone |
|------|------|-------|
| Coordinator/Admin | Rayaan Kamal | 507-513-4990 |
| Coordinator/Admin | Dania Ali | 507-261-7190 |
| Coordinator/Admin | Fatimah Sunez | 404-660-5746 |
| Treasurer | Rashid Fehmi | 507-512-9909 |

---

## Business Rules

- Bundle size never shown to families as S/M/L
- Family addresses: delivery volunteers only, revealed only after slot is claimed
- One food request per family per cycle
- Portal login: username/password (volunteer/family-role user linked to the record); phone-only login + OTP removed
- No reimbursement without admin approval
- Families opt-in per cycle — no auto-inclusion
- Shopping list = confirmed families only (status='confirmed')
- ADMIN_PASSWORD env var always synced to DB on deploy
- Families without phone on file: admin manually contacts → overrides status in admin panel
- Cycles are manually advanced by admin (upcoming → open → shopping → delivered)
- `order.html` / `status='open'` cycle path is DEAD — do not use
- Direct order edit removed — families submit change requests, admin approves/rejects
- Cancel is direct (no approval) — admin can reset order silently if needed
- Change requests blocked once cycle moves to shopping status
- Change requests only allowed within 30 days of delivery date

# SIHAA Food Charity — Operations Hub Memory

_Last updated: 2026-05-02 (latest commit: 991bf3c — fix OTP dev mode: always return code when OTP_DEV_MODE=true)_

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
| Live URL | https://sihha-ops-hub-production.up.railway.app |
| GitHub Repo | https://github.com/ahmkam-apps/Sihha-ops-hub.git |
| Hosting | Railway (auto-deploys from GitHub master) |
| Admin Login | admin / (set via ADMIN_PASSWORD env var in Railway) |
| Public Intake | /intake |
| Public Volunteer Signup | /volunteer |
| Public Volunteer Portal | /portal |
| Family Order Portal | /my-order |
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
| APP_URL env var | ⚠️ Should be set | Used for SMS confirmation links: `https://sihha-ops-hub-production.up.railway.app` |
| GitHub token | stored in Railway env — do not commit | Active |
| Old token | stored separately — revoke when convenient | 🔲 Revoke |
| Custom subdomain | 🔲 Pending | ops.sihaa.org → Railway |
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
| SMS | Twilio — all family + volunteer notifications |
| Scheduling | APScheduler (3 daily jobs) |
| Charts | Chart.js 4.4.1 (CDN) |
| Email | SendGrid (SENDGRID_API_KEY env var) — treasurer notifications |

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
│   ├── my-order.html      # Family self-service portal (view order, cancel, request change)
│   ├── confirm.html       # Family bundle opt-in (token-based) ✅
│   ├── order.html         # RETIRED — informational redirect page
│   └── donate-stats.html  # Donation stats widget (iframe embed for Wix)
├── import_data.py         # Historical data import script
└── tests/
```

---

## Full Data Model

```
users (admin system users — roles: admin | volunteer | finance | treasurer | viewer)
  NOTE: "coordinator" and "admin" are the same role — no distinction

sessions (admin bearer tokens)
portal_sessions (volunteer portal tokens — phone-based login, 48hr expiry)

families
  ├── wa_phone, wa_apikey   ← CallMeBot (still in DB schema, but removed from all admin UI — WA stripped)
  ├── family_code           ← unique: last 6 phone digits + bundle letter (e.g. "398540-M")
  ├── city, family_size, children_count, income_range, frequency  ← all editable in admin
  └── status: pending | active | inactive | paused

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
  ├── event_type: confirmed | items_edited | cancelled | auto_skipped | admin_override
  │              | change_requested | change_approved | change_rejected | change_retracted | order_reset
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

## Scheduler Jobs (APScheduler — daily, idempotent)

| Job ID | Time (UTC) | What it does |
|--------|-----------|--------------|
| `daily_reminders` | 08:00 | WA reminder to volunteers with delivery slots 2 days out |
| `family_opt_in_notifications` | 09:00 | T-7 before delivery: creates food_requests + sends WA opt-in link to each active family |
| `family_cutoff_skip` | 09:30 | T-5 before delivery: marks all `pending_confirmation` requests as `skipped` |
| `auto_release_unconfirmed_slots` | 10:00 | 3 days before delivery: releases `claimed` slots where family has NOT placed order; WA to volunteer; idempotent via reminder_log |

---

## Family Self-Service Portal (`/my-order` → `my-order.html`) — Current State ✅

- Phone-based login (fuzzy phone number lookup)
- **Two tabs: "My Deliveries" | "History"**

### My Deliveries tab
- Shows ALL delivery cycles within next 12 months (was 30 days) (+ any active order outside that window)
- Each cycle = one card with state-aware content:
  - **Open, no order**: "Order for this delivery" button → inline item checklist + notes → [Confirm Order]
  - **Confirmed order**: shows items as chips, cancel/request-change actions, pending CR banner, event timeline toggle
  - **Shopping, no order**: locked note ("Shopping in progress")
  - **Upcoming, no order**: "Coming soon" note
- Notes field on initial order (optional, stored in `food_requests.family_notes`)
- Cancel: direct (≥24h before delivery), releases volunteer slots, WA to coordinators + volunteers
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
- Detail view: confirmation response board — Confirmed / No WA / No Response stats + per-family override buttons

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

### Finance
- Donations, Receipts, Reimbursements, Users

### 📋 Change Requests
- Centralized inbox: all pending requests across all families/cycles
- Each card shows: family name, cycle, family's notes, requested item list
- Approve (auto-applies item changes + WA to family) or Reject (WA to family with admin note)
- Recent resolved requests shown below

---

## Volunteer Portal (`/portal` → `portal.html`) — Current State ✅

- Login: phone number → 48hr session token
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

### Family (no auth — phone or family_id based)
- `GET /api/food-order/check?phone=` — eligibility check, returns full order state + `can_request_change` + `pending_change_request`
- `POST /api/food-order` — confirm order (initial submission)
- `POST /api/food-order/cancel` — direct cancel (no approval, ≥24h before delivery)
- `POST /api/family-request` — submit item change request with notes
- `DELETE /api/family-request/<id>/retract` — retract pending request

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

### 🟡 Important

| Item | Notes |
|------|-------|
| Shopping list / coverage view | Show which confirmed families have no volunteer signed up yet — admin can see at a glance who needs outreach |
| Volunteer activity report | Per-volunteer lifetime stats, exportable |
| Phase 4D: Financial reconciliation | Stripe + bank CSV import, donation matching — needs Stripe MCP plugin |

### 🔐 Auth — SMS OTP (LIVE ✅)

SMS OTP login is live on both portals. Phone number → 6-digit PIN via Twilio → 48hr session.

**Current status:**
- `OTP_DEV_MODE=true` set in Railway — server always returns PIN in JSON response so it auto-fills on screen (bypasses Twilio delivery)
- Twilio accepts SMS but US carriers silently block it — **10DLC registration required** for real SMS delivery
- Once 10DLC is approved: remove `OTP_DEV_MODE=true` from Railway variables

**Railway env vars (all set):**
- TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM, OTP_DEV_MODE

| Item | Notes |
|------|-------|
| SMS OTP login — families + volunteers | ✅ LIVE — dev mode auto-fill active |
| 10DLC A2P registration | 🔲 Pending — complete in Twilio console, then remove OTP_DEV_MODE |
| Rename /my-order → /family | 🔲 Backlog — "Family Portal" more accurate |

### 📲 SMS Notifications (backlog — grouped)

WA is fully stripped from the system. All notifications will go via Twilio SMS once 10DLC is approved.

| Trigger | Who gets it | Message |
|---------|------------|---------|
| Family submits intake form | Family | "We received your application, we'll be in touch within 48 hrs" |
| Admin activates family | Family | "You're registered with SIHAA. Visit [link] to manage your deliveries" |
| Admin activates volunteer | Volunteer | "You're approved! Visit /portal to log in and sign up for deliveries" |
| Volunteer signs up (registration form) | Volunteer | "Thanks for signing up, we'll review and be in touch soon" |
| T-5 cutoff — family skipped | Family | "Sorry, the ordering window for [cycle] has closed. We'll reach out next cycle" |
| Volunteer marks delivery complete | Family | "Your delivery from SIHAA is on its way — JazakAllah Khair" |

### Back Burner

| Item | Notes |
|------|-------|
| ops.sihaa.org DNS → Railway | Custom subdomain |
| Wix buttons | "Get Help" → /intake, "Volunteer" → /volunteer |
| Donate-stats widget on Wix | iframe embed |
| Revoke old GitHub token | (stored separately — do not commit token strings) |

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

## GitHub Push Process

Use the clean-clone workaround (avoids lock file issues in sandbox):

```bash
cd /tmp && rm -rf sihaa-push && \
git clone https://ghp_<TOKEN>@github.com/ahmkam-apps/Sihha-ops-hub.git sihaa-push && \
cp "/sessions/.../mnt/Ops Hub -App/sihaa-ops-hub/public/portal.html" /tmp/sihaa-push/public/portal.html && \
cd /tmp/sihaa-push && \
git config user.email "ahmerkam@icloud.com" && git config user.name "AK" && \
git add <files> && git commit -m "message" && git push origin master
```

Token is embedded in the remote URL. Railway auto-deploys from master (~2 min).

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
- Portal login: phone must match active volunteer record
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

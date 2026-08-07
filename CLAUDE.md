# CLAUDE.md — Sihha Ops Hub

**Read this file at the start of every dev session before touching server.py or any DB/route code.**

> **Code audit 2026-06-09:** full security/architecture audit completed. Prioritized remediation backlog (Phase 0 operational → Phase 4 structural) lives in `MEMORY.md → Active Backlog`. Check it before starting work.
>
> **Remediation status (2026-06-11): COMPLETE through Phase 3 + Phase 4 high-value items** (final commit `2201810`). Everything from the 2026-06-10 note, plus: off-site backup email (`BACKUP_EMAIL` env, verified), heartbeat digest 11:00 UTC, staging-first deploys, finance test suite (157 total tests), dead legacy routes removed, session purge 06:45 UTC + hourly expiry slide, atomic cancel flows, N+1 batching in get_orders/list_families, shared `public/js/shared.js` (`esc`/`escJs`/`makeApi`) + `public/css/base.css` — **use these for all new pages/interpolations**, `secrets.token_urlsafe` sessions, `tmp_`-prefixed temp tokens (rejected by require_auth; only set-password accepts), receipts list gated to admin/finance/treasurer, Procfile gone (railway.json owns the start command). Remaining low-priority Phase 4 items in `MEMORY.md → Active Backlog`.
>
> **2026-06-15 session:** Shipped **hourly Wix donation sync** (`_sync_wix_donations_core` / `_sync_wix_donations_job` + `POST /api/donations/sync-wix`; runs at minute 0 each hour; no-op without `WIX_API_KEY`; commit `eef0d62`) — scheduler now runs **8 jobs**. Reconciled `MEMORY.md` against the code (auth model, schema, routes, cancel rule; commit `70c766a`, pushed). **Verified family login works end-to-end** (username/password via `/login` → Bearer `familyToken`; OTP/phone login are dead 410 stubs in family.html — harmless). Canonical domain is **https://ops.sihha.org** (live). **Open items:** Wix-site buttons (Get Help→/intake, Volunteer→/volunteer), donate-stats widget embed on Wix, Phase 4D bank/Stripe reconciliation. Auth/notification facts below were corrected this session.
>
> **2026-07-10:** All three portals (family/volunteer/intake) are now complete installable **PWAs** — fixed `family.html` (added the missing `<link rel="manifest" href="/manifest-family.json">` + `serviceWorker.register('/sw.js')`) and corrected `manifest-family.json` `start_url` `/order`→`/family`; live on prod (commits `aee43fb`, `af29e1e`). New deploy helper **`deploy-sihha.command`** in the parent `RAILWAY_Sihha-Ops-Hub/` folder — double-click to commit + push (staging-first via `git push origin HEAD:staging`, or straight to prod). Still open: Wix-site buttons + donate-stats widget embed on Wix; Phase 4D bank/Stripe reconciliation.
>
> **2026-07-11 — full code audit + P0 remediation.** Report: `../AUDIT_2026-07-11.md` (P0 done; P1/P2 backlog remains). P0 fixes applied this session: (1) **NameError bug** in `edit_food_order_items` — `family['id']`→`family_id` (families got a 500 on every item edit; edit saved but shopper emails never sent); (2) **IDOR closed** — 18 staff read endpoints (families/<id>, histories, volunteers, orders, delivery-cycles, dashboard/stats, reports, volunteer-slots, food catalog GETs) upgraded from bare `@require_auth()` to `roles=['admin','finance','treasurer','viewer']`; `/api/auth/change-password` deliberately left role-open (family/volunteer need it); (3) **stored XSS fixed** in `public/confirm.html` — added inline `esc`/`escJs`, all server values escaped; (4) **dependency CVEs cleared** — flask 3.1.3, werkzeug 3.1.6, flask-cors 6.0.0, gunicorn 23.0.0 (pip-audit clean). Tests: **159 pass** (2 new regression tests: `test_edit_order_items`, `test_family_session_cannot_read_staff_endpoints`). Next up from the audit (P1): ProxyFix for the XFF login throttle, async request-path email, Wix sync early-exit + `donations.reference_id` index, `misfire_grace_time=3600`, partial-unique index on active volunteer_slots.
>
> **2026-08-06 — portal/security hardening.** Unified session/domain enforcement and upload ownership shipped in `94cbfbf`. Commit `2b79457` on staging adds DB-backed readiness and login/public-form throttles, transactional family deletion that preserves financial records, fail-closed family-order validation, expiring single-use legacy confirmation tokens, verified/quota-controlled uploads with orphan cleanup, and 11 focused regressions. Signed-in staging acceptance then caught a quantity mismatch between the family confirmation and volunteer shopping list; the follow-up uses one effective-quantity rule across family, volunteer, aggregate-shopping, and admin views and makes volunteer reminder dates Central-time calendar based. Tests: **209 passed, 1 intentional live-smoke skip**. Paid/reimbursement state-machine changes remain explicitly deferred.

---

## 1. App Overview

**Sihha Ops Hub** is the operations backend for Sihha Food Charity — a Muslim community food-aid organization in Rochester, NY that runs bi-weekly grocery delivery cycles for enrolled families, using a volunteer shopper/delivery model.

### What it does
- Manages families, volunteers, delivery cycles, food requests, and reimbursements
- Provides a public family intake form, a volunteer sign-up form, and username/password-authenticated family + volunteer portals (phone/OTP login removed — those routes return 410)
- Manages a food catalog (items + bundle sizes S/M/L) and generates shopping lists per cycle
- Families receive email opt-in links 7 days before delivery; they confirm/skip/customize bundles (WhatsApp/SMS fully removed)
- Tracks receipts submitted by volunteers and handles reimbursement approval + payment notifications
- Syncs donation data from Wix eCommerce API; exposes a donation-stats widget for embedding in Wix

### Tech stack
- **Backend:** Python 3, Flask 3.0.3, Flask-CORS 4.0.1
- **Database:** SQLite with WAL mode; production uses `DB_PATH=/app/data/sihaa.db` on a Railway Volume
- **Server:** gunicorn 22.0.0, 2 workers, port from `$PORT` env var
- **Notifications:** SendGrid email — sole notification channel (`_email_send(to, subject, body)`); Twilio/WhatsApp fully removed
- **Scheduler:** APScheduler 3.10.4 (background, runs inside each gunicorn worker)
- **Excel export:** openpyxl 3.1.5
- **Hosting:** Railway (production), GitHub remote: `ahmkam-apps/Sihha-ops-hub`

### Public URLs
**PROD:** `https://ops.sihha.org` (live canonical custom domain) + `https://sihha-ops-hub-production.up.railway.app` (both deploy from `master`)
**STAGING:** `https://dev-staging-sihha-production.up.railway.app` (deploys from `staging` branch; own DB `sihaa_staging.db`; synthetic data only — it has a live SendGrid key)

**Deploy protocol (since 2026-06-11):** push to `staging` → verify there → fast-forward the SAME commit to `master`. Never push untested changes straight to master.

### Environment variables (set in Railway dashboard)
| Variable | Purpose |
|---|---|
| `DB_PATH` | Default: `data/sihaa.db` |
| `UPLOAD_FOLDER` | Default: `data/uploads` |
| `PORT` | Injected by Railway |
| `SESSION_EXPIRY_HOURS` | Default: 24 |
| `ADMIN_PASSWORD` | Admin account password — if set, synced on every deploy |
| `SENDGRID_API_KEY` | For email notifications |
| `NOTIFY_FROM_EMAIL` | Default: `ops@sihha.org` |
| `WIX_API_KEY` | Wix eCommerce API key for donation sync |
| `WIX_SITE_ID` | Default: `038c9d97-1ce8-4495-982b-37591dce50ee` |
| `APP_URL` | Base URL for confirmation links, default: `https://sihha-ops-hub-production.up.railway.app` |
| `REQUIRE_EXISTING_DB` | Set to `1` on production only; startup fails instead of creating an empty DB when the volume is missing |
| `MAX_UPLOAD_BYTES` | Per-file validated upload limit; default 12 MB |
| `MAX_IMAGE_PIXELS` | Decoded image pixel ceiling; default 40 million |
| `UPLOAD_FILES_PER_DAY` | Volunteer upload count quota per 24 hours; default 20 |
| `UPLOAD_BYTES_PER_DAY` | Volunteer upload byte quota per 24 hours; default 64 MB |
| `UPLOAD_TOTAL_BYTES` | Upload-storage safety ceiling; default 2 GB |
| `CONFIRMATION_TOKEN_HOURS` | Maximum legacy confirmation-token lifetime; default 168 hours |

---

## 2. Database Schema

**CRITICAL:** The live Railway DB was created in an early version of the app. Many columns were added later via ALTER TABLE migrations in `bootstrap_db()`. When reasoning about what columns exist on the live DB, always check the migration inventory below — never assume a column exists just because it appears in the CREATE TABLE statement in the current code.

### Table: `users`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `username` | TEXT UNIQUE NOT NULL | CREATE TABLE (original) |
| `password_hash` | TEXT NOT NULL | CREATE TABLE (original) |
| `name` | TEXT | CREATE TABLE (original) |
| `role` | TEXT DEFAULT 'viewer' CHECK IN ('admin','volunteer','finance','treasurer','viewer') | CREATE TABLE — but the `treasurer` value was **not** in original CHECK; added via table-recreation migration |
| `active` | INTEGER DEFAULT 1 | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `email` | TEXT | **ALTER TABLE migration** (Phase 4A) |
| `wa_phone` | TEXT | **ALTER TABLE migration** (Phase 4A) |
| `wa_apikey` | TEXT | **ALTER TABLE migration** (Phase 4A) |
| `linked_id` | TEXT | **ALTER TABLE migration** — FK to families.id or volunteers.id |
| `linked_type` | TEXT | **ALTER TABLE migration** — 'family' or 'volunteer' |
| `must_change_password` | INTEGER DEFAULT 1 | **ALTER TABLE migration** — 1 = force password set on next login |
| `password_changed_at` | TEXT | **ALTER TABLE migration** — ISO timestamp; drives 60-day expiry check |
| `last_login_at` | TEXT | **ALTER TABLE migration** — updated on every successful login |

**Note:** The `treasurer` CHECK value required a full table recreation via `executescript` in `bootstrap_db()` and a fallback `_ensure_treasurer_role()` / `_recreate_users_table()` helper. There is also `/api/admin/fix-schema` to trigger the repair manually.

---

### Table: `sessions`
| Column | Type | Source |
|---|---|---|
| `token` | TEXT PK | CREATE TABLE (original) |
| `user_id` | TEXT NOT NULL → FK users | CREATE TABLE (original) |
| `expires_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |

No migrations. Fully original.

---

### Table: `families`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `name` | TEXT NOT NULL | CREATE TABLE (original) |
| `phone` | TEXT | CREATE TABLE (original) — **normalized to digits-only** via Phase 6 migration |
| `address` | TEXT | CREATE TABLE (original) |
| `city` | TEXT | CREATE TABLE (original) |
| `family_size` | INTEGER | CREATE TABLE (original) |
| `children_count` | INTEGER | CREATE TABLE (original) |
| `dietary_notes` | TEXT | CREATE TABLE (original) |
| `frequency` | TEXT | CREATE TABLE (original) |
| `income_range` | TEXT | CREATE TABLE (original) |
| `status` | TEXT CHECK IN ('pending','active','inactive','paused') | CREATE TABLE (original) |
| `notes` | TEXT | CREATE TABLE (original) |
| `source` | TEXT DEFAULT 'admin' | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `updated_at` | TEXT | CREATE TABLE (original) — but may be absent on very early DBs; also added via ALTER |
| `family_code` | TEXT | **ALTER TABLE migration** — added, then back-filled on all existing rows |
| `bundle_size` | TEXT | **ALTER TABLE migration** (listed in "columns missing from live DBs" batch) |
| `pending_bundle_size` | TEXT | **ALTER TABLE migration** (Phase 6, also in batch) |
| `wa_phone` | TEXT | **ALTER TABLE migration** (Phase 5, also in batch) |
| `wa_apikey` | TEXT | **ALTER TABLE migration** (Phase 5, also in batch) |

**Note:** `bundle_size` is the coordinator-approved active size. `pending_bundle_size` is a family-requested change awaiting approval. These are separate from the auto-calculated size from `bundle_size_rules`.

---

### Table: `volunteers`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `name` | TEXT NOT NULL | CREATE TABLE (original) |
| `phone` | TEXT | CREATE TABLE (original) — **normalized to digits-only** via Phase 6 migration |
| `email` | TEXT | CREATE TABLE (original) |
| `role` | TEXT CHECK IN ('shopper','delivery','both','general') | CREATE TABLE (original) |
| `availability` | TEXT | CREATE TABLE (original) |
| `service_area` | TEXT | CREATE TABLE (original) |
| `contact_preference` | TEXT | CREATE TABLE (original) |
| `volunteer_areas` | TEXT | CREATE TABLE (original) |
| `comfort_level` | INTEGER | CREATE TABLE (original) |
| `skills` | TEXT | CREATE TABLE (original) |
| `other_info` | TEXT | CREATE TABLE (original) |
| `status` | TEXT CHECK IN ('pending','active','inactive') | CREATE TABLE (original) |
| `notes` | TEXT | CREATE TABLE (original) |
| `source` | TEXT DEFAULT 'admin' | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `updated_at` | TEXT | CREATE TABLE (original) |
| `wa_phone` | TEXT | **ALTER TABLE migration** (first batch, before Phase 4A) |
| `wa_apikey` | TEXT | **ALTER TABLE migration** (first batch, before Phase 4A) |

---

### Table: `assignments`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `family_id` | TEXT NOT NULL → FK families | CREATE TABLE (original) |
| `volunteer_id` | TEXT → FK volunteers | CREATE TABLE (original) |
| `task_type` | TEXT CHECK IN ('shopping','delivery','both') | CREATE TABLE (original) |
| `due_date` | TEXT | CREATE TABLE (original) |
| `status` | TEXT CHECK IN ('pending','assigned','in_progress','completed','cancelled') | CREATE TABLE (original) |
| `notes` | TEXT | CREATE TABLE (original) |
| `created_by` | TEXT | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `updated_at` | TEXT | CREATE TABLE (original) |

No migrations. Legacy table — mostly superseded by `volunteer_slots` in Phase 3C.

---

### Table: `receipts`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `assignment_id` | TEXT → FK assignments | CREATE TABLE (original) |
| `volunteer_id` | TEXT → FK volunteers | CREATE TABLE (original) |
| `family_id` | TEXT → FK families | CREATE TABLE (original) |
| `store` | TEXT | CREATE TABLE (original) |
| `purchase_date` | TEXT | CREATE TABLE (original) |
| `amount` | REAL | CREATE TABLE (original) |
| `file_url` | TEXT | CREATE TABLE (original) |
| `status` | TEXT CHECK IN ('pending','approved','rejected') | CREATE TABLE (original) |
| `notes` | TEXT | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `updated_at` | TEXT | CREATE TABLE (original) |
| `slot_id` | TEXT | **ALTER TABLE migration** (Phase 4A) — links receipt to a volunteer_slot |
| `cycle_id` | TEXT | **ALTER TABLE migration** (2026-06-09) — direct cycle association for admin-entered historical receipts; nullable; takes precedence over slot→cycle derivation in `list_receipts` |

---

### Table: `reimbursements`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `receipt_id` | TEXT NOT NULL → FK receipts | CREATE TABLE (original) |
| `volunteer_id` | TEXT | CREATE TABLE (original) |
| `amount` | REAL | CREATE TABLE (original) |
| `status` | TEXT CHECK IN ('pending','approved','paid','rejected') | CREATE TABLE (original) |
| `payment_method` | TEXT CHECK IN ('venmo','zelle','check','cash','bank_transfer','cheque','other') | **Table recreation migration** — original only had subset of payment methods |
| `payment_ref` | TEXT | **Table recreation migration** (Phase 4A) — was not in original |
| `paid_date` | TEXT | CREATE TABLE (original) |
| `approved_by` | TEXT | CREATE TABLE (original) |
| `notes` | TEXT | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `updated_at` | TEXT | CREATE TABLE (original) |

**Note:** The `payment_method` CHECK constraint was expanded (added venmo/zelle) and `payment_ref` was added via a full table recreation migration in Phase 4A (`bootstrap_db()`).

---

### Table: `donations`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `donor_name` | TEXT | CREATE TABLE (original) |
| `donor_email` | TEXT | CREATE TABLE (original) — but also redundantly added via ALTER in bootstrap AND in `create_donation` route handler |
| `amount` | REAL | CREATE TABLE (original) |
| `type` | TEXT CHECK IN ('online','cash','check','bank') | CREATE TABLE (original) — but also redundantly added via ALTER |
| `date` | TEXT | CREATE TABLE (original) |
| `source` | TEXT DEFAULT 'manual' | CREATE TABLE (original) — but also added via ALTER in batch |
| `reference_id` | TEXT | CREATE TABLE (original) — but also redundantly added via ALTER |
| `cycle_id` | TEXT | CREATE TABLE (original) — but also added via ALTER in batch |
| `notes` | TEXT | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `frequency` | TEXT | **ALTER TABLE migration** only — was NOT in original CREATE TABLE; added in batch + in sync-wix route |

**CRITICAL:** `frequency` is NOT in the original donations CREATE TABLE. It is only present on live DBs that have been through the batch migration in `bootstrap_db()`. If a live DB predates that migration, queries filtering on `frequency` will fail or return null. The column is idempotently added in bootstrap, so it should exist post-deploy.

---

### Table: `food_categories`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `name` | TEXT NOT NULL | CREATE TABLE (original) |
| `display_order` | INTEGER DEFAULT 0 | CREATE TABLE (original) |
| `is_active` | INTEGER DEFAULT 1 | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |

No migrations.

---

### Table: `food_items`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `category_id` | TEXT NOT NULL → FK food_categories | CREATE TABLE (original) |
| `name` | TEXT NOT NULL | CREATE TABLE (original) |
| `unit` | TEXT DEFAULT 'each' | CREATE TABLE (original) |
| `is_active` | INTEGER DEFAULT 1 | CREATE TABLE (original) |
| `display_order` | INTEGER DEFAULT 0 | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `price` | REAL DEFAULT 0 | **ALTER TABLE migration** (priced bundle selection) |
| `allow_qty` | INTEGER DEFAULT 0 | **ALTER TABLE migration** (priced bundle selection) — 1 = show +/- stepper |
| `is_default` | INTEGER DEFAULT 0 | **ALTER TABLE migration** (2026-05-15) — pre-checked on order form open |
| `group_id` | TEXT | **ALTER TABLE migration** (2026-05-15) — mutual-exclusion group key (bread_pasta / beans / fruit) |
| `group_max` | INTEGER DEFAULT 1 | **ALTER TABLE migration** (2026-05-15) — max items selectable from group |
| `is_free_text` | INTEGER DEFAULT 0 | **ALTER TABLE migration** (2026-05-15) — show text input alongside checkbox |

Active catalog (2026-05-15): Rice, Pasta, Bread (default, bread_pasta), Eggs, Red Kidney Beans (beans), Red Beans Cans (beans), Whole Chicken (default, allow_qty), Red Potato (default), Bananas (default), Red Onion (default), Italian Dressing, Apples (fruit), Grapes (fruit), Other Fruit (fruit, is_free_text), Brown Lentils.

Defaults pre-checked: Chicken, Eggs, Rice, Bread, Bananas, Red Potato, Red Onion.

---

### Table: `bundle_quantities`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `food_item_id` | TEXT NOT NULL → FK food_items | CREATE TABLE (original) |
| `bundle_size` | TEXT CHECK IN ('S','M','L') | CREATE TABLE (original) |
| `quantity` | TEXT NOT NULL | CREATE TABLE (original) |
| UNIQUE(food_item_id, bundle_size) | constraint | CREATE TABLE (original) |

No migrations.

---

### Table: `bundle_size_rules`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `bundle_size` | TEXT UNIQUE CHECK IN ('S','M','L') | CREATE TABLE (original) |
| `label` | TEXT NOT NULL | CREATE TABLE (original) |
| `min_household` | INTEGER NOT NULL | CREATE TABLE (original) |
| `max_household` | INTEGER | CREATE TABLE (original) — NULL means no upper limit |

Seeded with S(1-2), M(3-5), L(6+) if table is empty.

---

### Table: `delivery_cycles`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `title` | TEXT NOT NULL | CREATE TABLE (original) |
| `delivery_date_start` | TEXT NOT NULL | CREATE TABLE (original) |
| `delivery_date_end` | TEXT NOT NULL | CREATE TABLE (original) |
| `request_open_at` | TEXT NOT NULL DEFAULT '' | CREATE TABLE (original) — added DEFAULT '' in Phase 5 table recreation |
| `request_close_at` | TEXT NOT NULL DEFAULT '' | CREATE TABLE (original) — added DEFAULT '' in Phase 5 table recreation |
| `status` | TEXT CHECK IN ('draft','open','closed','upcoming','shopping','delivered') | **Table recreation migration** (Phase 5) — original only had draft/open/closed/shopping/delivered; `upcoming` was added |
| `notes` | TEXT | CREATE TABLE (original) |
| `created_by` | TEXT | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `updated_at` | TEXT | CREATE TABLE (original) |

**Note:** The `upcoming` status was added via a full table recreation in Phase 5. The helper `_fix_delivery_cycles_schema(db)` is called at the start of `create_delivery_cycle` and `seed_cycles_2026` to ensure the schema is correct on any live DB that may have missed the migration.

---

### Table: `food_requests`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `cycle_id` | TEXT NOT NULL → FK delivery_cycles | CREATE TABLE (original) |
| `family_id` | TEXT NOT NULL → FK families | CREATE TABLE (original) |
| `bundle_size` | TEXT CHECK IN ('S','M','L') | CREATE TABLE (original) |
| `submitted_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `status` | TEXT CHECK IN ('submitted','assigned','delivered','cancelled','pending_confirmation','confirmed','skipped','auto_confirmed') | **Table recreation migration** (Phase 5) — original only had submitted/assigned/delivered/cancelled |
| `assigned_volunteer_id` | TEXT | CREATE TABLE (original) |
| `delivered_at` | TEXT | CREATE TABLE (original) |
| `notes` | TEXT | CREATE TABLE (original) |
| UNIQUE(cycle_id, family_id) | constraint | CREATE TABLE (original) |
| `confirmation_token` | TEXT | **ALTER TABLE migration** (Phase 5) |
| `confirmation_expires_at` | TEXT | **ALTER TABLE migration** (2026-08 hardening); pending legacy rows receive a one-time 24-hour grace period |
| `confirmed_at` | TEXT | **ALTER TABLE migration** (Phase 5) |
| `confirmation_sent_at` | TEXT | **ALTER TABLE migration** (Phase 5) |
| `updated_at` | TEXT | **ALTER TABLE migration** (safety-net batch in `init_db()`, 2026-04-29) |
| `family_notes` | TEXT | **ALTER TABLE migration** — optional notes submitted by family with order |

---

### Table: `food_request_items`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `request_id` | TEXT NOT NULL → FK food_requests | CREATE TABLE (original) |
| `food_item_id` | TEXT NOT NULL → FK food_items | CREATE TABLE (original) |
| `selected` | INTEGER DEFAULT 0 | CREATE TABLE (original) |
| UNIQUE(request_id, food_item_id) | constraint | CREATE TABLE (original) |
| `quantity` | INTEGER DEFAULT 1 | **ALTER TABLE migration** (priced bundle selection) |
| `custom_value` | TEXT | **ALTER TABLE migration** (2026-05-15) — free-text value for is_free_text items (e.g. "Other Fruit" → "Mangoes") |

---

### Table: `cycle_assignments`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `cycle_id` | TEXT NOT NULL → FK delivery_cycles | CREATE TABLE (original) |
| `volunteer_id` | TEXT NOT NULL → FK volunteers | CREATE TABLE (original) |
| `family_id` | TEXT → FK families | CREATE TABLE (original) |
| `task_type` | TEXT CHECK IN ('shopping','delivery') | CREATE TABLE (original) |
| `task_date` | TEXT | CREATE TABLE (original) |
| `task_time` | TEXT | CREATE TABLE (original) |
| `status` | TEXT CHECK IN ('pending','confirmed','completed','cancelled') | CREATE TABLE (original) |
| `notes` | TEXT | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |
| `updated_at` | TEXT | CREATE TABLE (original) |

Legacy table from early cycle assignment model — mostly superseded by `volunteer_slots`.

---

### Table: `bank_transactions`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `transaction_date` | TEXT NOT NULL | CREATE TABLE (original) |
| `description` | TEXT | CREATE TABLE (original) |
| `amount` | REAL NOT NULL | CREATE TABLE (original) |
| `matched_donation_id` | TEXT → FK donations | CREATE TABLE (original) |
| `reconcile_status` | TEXT CHECK IN ('matched','unmatched','ignored') | CREATE TABLE (original) |
| `imported_at` | TEXT NOT NULL | CREATE TABLE (original) |

No migrations. Reconciliation feature not yet fully built.

---

### Table: `reconciliation_runs`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `run_date` | TEXT NOT NULL | CREATE TABLE (original) |
| `period_start` | TEXT | CREATE TABLE (original) |
| `period_end` | TEXT | CREATE TABLE (original) |
| `total_online_donations` | REAL DEFAULT 0 | CREATE TABLE (original) |
| `total_bank_deposits` | REAL DEFAULT 0 | CREATE TABLE (original) |
| `variance` | REAL DEFAULT 0 | CREATE TABLE (original) |
| `notes` | TEXT | CREATE TABLE (original) |
| `run_by` | TEXT | CREATE TABLE (original) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (original) |

No migrations.

---

### Table: `stripe_transactions`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `stripe_charge_id` | TEXT UNIQUE | CREATE TABLE (original) |
| `stripe_payout_id` | TEXT | CREATE TABLE (original) |
| `donor_name` | TEXT | CREATE TABLE (original) |
| `donor_email` | TEXT | CREATE TABLE (original) |
| `amount` | REAL | CREATE TABLE (original) |
| `fee` | REAL | CREATE TABLE (original) |
| `net` | REAL | CREATE TABLE (original) |
| `charge_date` | TEXT | CREATE TABLE (original) |
| `payout_date` | TEXT | CREATE TABLE (original) |
| `description` | TEXT | CREATE TABLE (original) |
| `synced_at` | TEXT NOT NULL | CREATE TABLE (original) |

No migrations. Table is provisioned but no sync route exists yet.

---

### Table: `wix_donations`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (original) |
| `wix_order_id` | TEXT UNIQUE | CREATE TABLE (original) |
| `donor_name` | TEXT | CREATE TABLE (original) |
| `donor_email` | TEXT | CREATE TABLE (original) |
| `amount` | REAL | CREATE TABLE (original) |
| `donation_date` | TEXT | CREATE TABLE (original) |
| `description` | TEXT | CREATE TABLE (original) |
| `synced_at` | TEXT NOT NULL | CREATE TABLE (original) |

No migrations. Table is provisioned but sync goes directly into `donations` table, not here.

---

### Table: `volunteer_slots` (Phase 3C)
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (Phase 3C) |
| `cycle_id` | TEXT NOT NULL → FK delivery_cycles | CREATE TABLE (Phase 3C) |
| `family_id` | TEXT NOT NULL → FK families | CREATE TABLE (Phase 3C) |
| `task_type` | TEXT NOT NULL | CREATE TABLE (Phase 3C) — no CHECK constraint (removed via migration) |
| `task_date` | TEXT | CREATE TABLE (Phase 3C) |
| `claimed_by` | TEXT → FK volunteers | CREATE TABLE (Phase 3C) |
| `claimed_at` | TEXT | CREATE TABLE (Phase 3C) |
| `completed_at` | TEXT | **ALTER TABLE migration** (added before Phase 3C was written, via separate migration) |
| `status` | TEXT CHECK IN ('open','claimed','confirmed','complete','cancelled') | **Table recreation migration** (2026-05) — 'confirmed' added; open slot model redesigned to pre-create slots; claimed→confirmed when family places order |
| `notes` | TEXT | CREATE TABLE (Phase 3C) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (Phase 3C) |
| `updated_at` | TEXT | CREATE TABLE (Phase 3C) |

**Note:** An earlier version of this table had `UNIQUE(cycle_id, family_id, task_type)` and a `CHECK(task_type IN ...)` constraint. Both were removed via a table-rebuild migration to allow multiple volunteers per task. The migration detects the old schema by checking for those strings in `sqlite_master`.

**Current slot model (updated 2026-06-09):** Pre-created open slots exist for all families + task types. Volunteers claim a slot by UPDATEing that row to `status='confirmed'` directly — **no intermediate `claimed` state** (auto-confirm, no coordinator approval step). Cancelling a slot UPDATEs back to `status='open'`, so another volunteer can claim it. Attempting to claim a slot already confirmed by someone else returns HTTP 409 with their name. Confirmation email fires immediately on claim.

---

### Table: `volunteer_task_types` (Phase 3C)
| Column | Type | Source |
|---|---|---|
| `slug` | TEXT PK | CREATE TABLE (Phase 3C) |
| `label` | TEXT NOT NULL | CREATE TABLE (Phase 3C) |
| `display_order` | INTEGER DEFAULT 0 | CREATE TABLE (Phase 3C) |
| `is_active` | INTEGER DEFAULT 1 | CREATE TABLE (Phase 3C) |

| `is_family_slot` | INTEGER DEFAULT 0 | **ALTER TABLE migration** — if 1, pre-create one slot per family per cycle (shopping + delivery = 1) |

Seeded with: shopping (is_family_slot=1), delivery (is_family_slot=1), stock (is_family_slot=0). No schema migrations beyond is_family_slot.

---

### Table: `portal_sessions` (Phase 3C)
| Column | Type | Source |
|---|---|---|
| `token` | TEXT PK | CREATE TABLE (Phase 3C) |
| `volunteer_id` | TEXT NOT NULL → FK volunteers | CREATE TABLE (Phase 3C) |
| `expires_at` | TEXT NOT NULL | CREATE TABLE (Phase 3C) |
| `created_at` | TEXT NOT NULL | CREATE TABLE (Phase 3C) |

No migrations. Portal sessions expire in 48 hours (different from admin sessions which use `SESSION_HOURS`, default 24).

---

### Table: `food_request_events` (2026-04-29)
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (Phase order-audit) |
| `request_id` | TEXT NOT NULL → FK food_requests | CREATE TABLE (Phase order-audit) |
| `event_type` | TEXT NOT NULL | `confirmed` \| `items_edited` \| `cancelled` \| `admin_override` \| `auto_skipped` |
| `actor` | TEXT NOT NULL DEFAULT 'system' | `family` \| `admin` \| `scheduler` \| `system` |
| `payload` | TEXT NOT NULL DEFAULT '{}' | JSON string — e.g. `{"added":["Rice"],"removed":["Chicken"]}` |
| `created_at` | TEXT NOT NULL | CREATE TABLE (Phase order-audit) |

**Note:** Created in Phase order-audit (2026-04-29). Migration #19 in `bootstrap_db()` includes a one-time backfill of synthetic events for all existing orders using `confirmed_at`/`updated_at` timestamps. Backfilled rows have `payload={"note":"backfilled"}` and are filtered out of UI display. Item names (not IDs) are stored in payload so history remains readable after catalog changes.

---

### Table: `order_change_requests`
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE |
| `request_id` | TEXT NOT NULL → FK food_requests | CREATE TABLE |
| `family_id` | TEXT NOT NULL → FK families | CREATE TABLE |
| `cycle_id` | TEXT NOT NULL → FK delivery_cycles | CREATE TABLE |
| `status` | TEXT CHECK IN ('pending','approved','rejected','retracted') | CREATE TABLE |
| `family_notes` | TEXT | CREATE TABLE — family's free-text reason |
| `payload` | TEXT NOT NULL DEFAULT '{}' | CREATE TABLE — JSON: `{selected_item_ids: [...]}` |
| `admin_notes` | TEXT | CREATE TABLE — admin's response message |
| `reviewed_by` | TEXT → FK users | CREATE TABLE |
| `created_at` | TEXT NOT NULL | CREATE TABLE |
| `updated_at` | TEXT | CREATE TABLE |

One active pending CR per order at a time (enforced server-side). Change requests blocked once cycle moves to `shopping`.

---

### Table: `reminder_log` (Phase 3C)
| Column | Type | Source |
|---|---|---|
| `id` | TEXT PK | CREATE TABLE (Phase 3C) |
| `slot_id` | TEXT NOT NULL | CREATE TABLE (Phase 3C) |
| `sent_to` | TEXT NOT NULL | CREATE TABLE (Phase 3C) |
| `sent_at` | TEXT NOT NULL | CREATE TABLE (Phase 3C) |
| UNIQUE(slot_id, sent_to) | constraint | CREATE TABLE (Phase 3C) — idempotency guard |

No migrations.

### Table: `rate_limit_events` (2026-08 hardening)

Persistent, cross-worker throttle events. `bucket_key` stores a SHA-256 digest rather than raw usernames, phone numbers, or IP addresses. Indexed by `(scope, bucket_key, created_at)` and purged after 48 hours.

### Table: `uploaded_files` (2026-08 hardening)

Registry of new receipt uploads: filename, uploader user/volunteer identity, size, creation time, and claim time. It enforces per-uploader quotas, one-receipt claims, and cleanup of registered files older than 24 hours that no receipt references.

---

## 3. Migration Inventory

Complete ordered list of every ALTER TABLE / table-recreation migration in `bootstrap_db()`. Migrations are idempotent — each is wrapped in try/except to skip if the column/change already exists.

| # | Migration | Type | Target Table | Column(s) Added |
|---|---|---|---|---|
| 1 | First batch | ALTER TABLE | `volunteers` | `wa_phone TEXT`, `wa_apikey TEXT` |
| 2 | `completed_at` | ALTER TABLE | `volunteer_slots` | `completed_at TEXT` |
| 3 | `family_code` | ALTER TABLE | `families` | `family_code TEXT` |
| 4 | Live DB column backfill | ALTER TABLE | `families` | `bundle_size TEXT`, `updated_at TEXT`, `pending_bundle_size TEXT`, `wa_phone TEXT`, `wa_apikey TEXT` |
| 5 | Donations column backfill | ALTER TABLE | `donations` | `donor_email TEXT`, `type TEXT`, `reference_id TEXT`, `cycle_id TEXT`, `frequency TEXT`, `source TEXT` |
| 6 | Phase 4A: slot_id on receipts | ALTER TABLE | `receipts` | `slot_id TEXT` |
| 7 | Phase 4A: user notification columns | ALTER TABLE | `users` | `email TEXT`, `wa_phone TEXT`, `wa_apikey TEXT` |
| 8 | Phase 4A: treasurer role | TABLE RECREATION | `users` | Expands role CHECK to include `treasurer` |
| 9 | Phase 4A: payment method expansion | TABLE RECREATION | `reimbursements` | Expands `payment_method` CHECK (venmo/zelle), adds `payment_ref TEXT` |
| 10 | Phase 6: `pending_bundle_size` | ALTER TABLE | `families` | `pending_bundle_size TEXT` (duplicate of #4, harmless) |
| 11 | Phase 6: phone normalisation | DATA migration | `families`, `volunteers` | Strips hyphens/spaces from all existing phone numbers |
| 12 | Phase 5: family WA credentials | ALTER TABLE | `families` | `wa_phone TEXT`, `wa_apikey TEXT` (duplicate of #4, harmless) |
| 13 | Phase 5: food_request confirmation fields | ALTER TABLE | `food_requests` | `confirmation_token TEXT`, `confirmation_expires_at TEXT`, `confirmed_at TEXT`, `confirmation_sent_at TEXT` |
| 14 | Phase 5: delivery_cycles `upcoming` | TABLE RECREATION | `delivery_cycles` | Expands status CHECK to include `upcoming`, sets DEFAULT `''` on request_open/close_at |
| 15 | Phase 5: food_requests confirmation statuses | TABLE RECREATION | `food_requests` | Expands status CHECK to include `pending_confirmation`, `confirmed`, `skipped`, `auto_confirmed` |
| 16 | Phase 3C CREATE (idempotent) | CREATE TABLE IF NOT EXISTS | `volunteer_slots`, `volunteer_task_types`, `portal_sessions`, `reminder_log` | New tables |
| 17 | Phase 3C: remove UNIQUE+CHECK on slots | TABLE RECREATION | `volunteer_slots` | Removes UNIQUE(cycle_id,family_id,task_type) and CHECK(task_type IN...) |
| 18 | 2026-04-29 safety-net batch | ALTER TABLE | `food_requests` | `confirmation_token TEXT`, `confirmation_expires_at TEXT`, `confirmed_at TEXT`, `confirmation_sent_at TEXT`, `updated_at TEXT` (idempotent, all in try/except) |
| 19 | 2026-04-29 order audit trail | CREATE TABLE IF NOT EXISTS + backfill | `food_request_events` | New table + one-time backfill of existing orders |
| 20 | 2026-05 priced bundle selection | ALTER TABLE | `food_items` | `price REAL DEFAULT 0`, `allow_qty INTEGER DEFAULT 0` |
| 21 | 2026-05 priced bundle selection | ALTER TABLE | `bundle_size_rules` | `budget REAL DEFAULT 0` |
| 22 | 2026-05 priced bundle selection | ALTER TABLE | `food_request_items` | `quantity INTEGER DEFAULT 1` |
| 23 | 2026-05 family email | ALTER TABLE | `families` | `email TEXT` (for sending login credentials) |
| 24 | 2026-05 users role CHECK | TABLE RECREATION | `users` | Regex-patches CHECK to include all roles: admin, volunteer, finance, treasurer, viewer, family |
| 25 | Sprint 2 (2026-05-15) paused status removal | TABLE RECREATION | `families` | Removes 'paused' from status CHECK — detected via sqlite_master inspection; existing paused rows migrated to 'inactive' |
| 26 | 2026-06-09 cycle_id on receipts | ALTER TABLE | `receipts` | `cycle_id TEXT` — direct cycle association for admin-entered historical receipts (nullable) |
| 27 | 2026-08 confirmation expiry | ALTER TABLE + data grace migration | `food_requests` | `confirmation_expires_at TEXT`; pending legacy tokens receive 24 hours, processed tokens remain invalid |
| 28 | 2026-08 abuse/upload controls | CREATE TABLE IF NOT EXISTS | `rate_limit_events`, `uploaded_files` | Persistent rate limits and upload registry/quota/orphan tracking |

**Columns used in route queries that had NO explicit migration (were in CREATE TABLE from the start):**
- All original columns. These are safe.

**Columns added by route handlers directly (not in bootstrap migrations) — DANGER ZONE:**
- `donations.donor_email`, `donations.type`, `donations.reference_id` — also added inline in `create_donation` route via try/except ALTER TABLE. This is a code smell but harmless since bootstrap_db also adds them.
- `donations.frequency` — added in `sync_wix_donations` route via try/except ALTER TABLE. Also added in bootstrap batch migration #5. Bootstrap wins on deploy, so this is safe.

---

## 4. All Routes

### Authentication
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/login` | None | Username + password login; returns `must_change_password+temp_token` on first login, else full `token` |
| POST | `/api/auth/set-password` | temp_token | Complete first-login or forced-reset; issues full session token |
| POST | `/api/auth/change-password` | Bearer (any) | Change own password |
| POST | `/api/auth/logout` | Bearer token (any) | Deletes session |
| GET | `/api/auth/me` | Bearer token (any) | Returns current user info |

### System
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/health` | None | Railway readiness: opens the existing DB read/write without creating it, verifies core schema, runs SQLite `quick_check`; returns 503 on failure |
| GET | `/api/donate-stats` | None | Public aggregate donation stats for Wix embed |

### Users (Admin only)
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/users` | admin | List all users | users |
| POST | `/api/users` | admin | Create user (all roles) | users |
| PUT | `/api/users/<uid>` | admin | Update user (role, password, WA creds, active) | users |
| POST | `/api/admin/fix-schema` | admin | Manual trigger for users table CHECK repair | users (sqlite_master) |

### Families
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/families` | any auth | List families (filter: status, search). Joins volunteer_slots for last delivery info | families, volunteer_slots, volunteers, delivery_cycles |
| POST | `/api/families` | admin/finance/treasurer | Create family + auto-create linked user account; returns login_username, login_temp_password, email_sent | families, users |
| GET | `/api/families/<fid>` | any auth | Get single family | families |
| PUT | `/api/families/<fid>` | admin/finance/treasurer | Update family (all fields incl. bundle_size, wa creds) | families |
| DELETE | `/api/families/<fid>` | admin | Transactionally deletes non-financial family data and linked sessions; returns 409 when receipts/financial history exist (deactivate instead) | families + related non-financial tables |
| POST | `/api/families/<fid>/request-bundle-change` | None (public) | Family requests bundle size change | families, users (WA notify admin) |
| POST | `/api/families/<fid>/approve-bundle-change` | admin | Approve or deny pending bundle change | families |
| GET | `/api/families/<fid>/history` | any auth | Full order history with items and slots | families, food_requests, delivery_cycles, food_request_items, food_items, food_categories, volunteer_slots, volunteers |
| POST | `/api/families/<fid>/preview-token` | admin | Mint 2h family session token for admin to open /family as that family | sessions, users |

### Volunteers (Admin portal)
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/volunteers` | any auth | List volunteers (filter: status, search) | volunteers |
| POST | `/api/volunteers` | admin | Create volunteer | volunteers |
| GET | `/api/volunteers/<vid>` | any auth | Get single volunteer | volunteers |
| PUT | `/api/volunteers/<vid>` | admin | Update volunteer | volunteers |
| GET | `/api/volunteers/<vid>/history` | any auth | Lifetime task stats and task log | volunteers, volunteer_slots, delivery_cycles, families |

### Assignments (Legacy)
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/assignments` | any auth | List assignments (volunteers see own only) | assignments, families, volunteers |
| POST | `/api/assignments` | admin | Create assignment | assignments |
| PUT | `/api/assignments/<aid>` | admin/volunteer | Update assignment | assignments |

### Receipts
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/receipts` | any auth | List receipts (with family/volunteer names, cycle_title via JOIN) | receipts, families, volunteers, volunteer_slots, delivery_cycles |
| POST | `/api/receipts` | admin/volunteer | Create receipt (accepts cycle_id) + notify treasurers | receipts, volunteers, users |
| PUT | `/api/receipts/<rid>` | admin/finance/treasurer | Update receipt status; auto-creates reimbursement on approval | receipts, reimbursements |
| POST | `/api/receipts/upload` | admin/finance/treasurer | Signature/decode/dimension-verified, registered and quota-controlled receipt upload | filesystem, uploaded_files |
| GET | `/api/finance/summary` | admin/finance/treasurer | Overall totals (donations/reimbursed/balance/pending/submitted) + per-cycle breakdown | delivery_cycles, receipts, reimbursements, donations |

### Reimbursements
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/reimbursements` | admin/finance/treasurer | List reimbursements with volunteer name and receipt info | reimbursements, volunteers, receipts |
| PUT | `/api/reimbursements/<rid>` | admin/finance/treasurer | Update status/payment; notifies volunteer via WA when paid | reimbursements, receipts, volunteers |

### Donations
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/donations` | admin/finance/treasurer | List all donations | donations |
| GET | `/api/donations/export` | admin/finance/treasurer | Download donations as Excel (.xlsx) | donations |
| POST | `/api/donations` | admin/finance/treasurer | Create manual donation | donations |
| POST | `/api/donations/sync-wix` | admin/treasurer | Sync PAID orders from Wix eCommerce API into donations table (anonymizes donor names/emails) | donations |

### Dashboard
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/dashboard/stats` | any auth | Stats aggregate: families, volunteers, receipts, reimbursements, donations, active cycle info | all major tables |

### Food Catalog
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/food-categories` | any auth | List categories | food_categories |
| POST | `/api/food-categories` | admin | Create category | food_categories |
| PUT | `/api/food-categories/<cid>` | admin | Update category | food_categories |
| DELETE | `/api/food-categories/<cid>` | admin | Soft-delete category (only if no active items) | food_categories, food_items |
| GET | `/api/food-items` | any auth | List items (filter: active, category_id) | food_items, food_categories |
| POST | `/api/food-items` | admin | Create item + seed empty bundle quantities | food_items, bundle_quantities |
| PUT | `/api/food-items/<iid>` | admin | Update item | food_items |
| GET | `/api/bundle-quantities` | any auth | List bundle quantities (all or by item_id) | bundle_quantities, food_items, food_categories |
| PUT | `/api/bundle-quantities` | admin | Bulk upsert bundle quantities | bundle_quantities |
| GET | `/api/bundle-size-rules` | any auth | List S/M/L rules | bundle_size_rules |
| PUT | `/api/bundle-size-rules` | admin | Bulk update S/M/L household ranges | bundle_size_rules |

### Delivery Cycles
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/delivery-cycles` | any auth | List cycles (filter: status) | delivery_cycles |
| POST | `/api/delivery-cycles` | admin | Create cycle (calls `_fix_delivery_cycles_schema` first) | delivery_cycles |
| PUT | `/api/delivery-cycles/<cid>` | admin | Update cycle | delivery_cycles |
| GET | `/api/delivery-cycles/<cid>/orders` | any auth | Orders for a cycle with selected items | food_requests, families, food_request_items, food_items, food_categories |
| GET | `/api/delivery-cycles/<cid>/shopping-list` | any auth | Aggregated shopping list (confirmed orders only) | food_requests, food_request_items, food_items, food_categories, bundle_quantities |
| POST | `/api/delivery-cycles/<cid>/generate-slots` | admin | Auto-generate one shopping + one delivery slot per food_request | volunteer_slots, food_requests |
| PUT | `/api/food-requests/<rid>` | admin | Override food_request status (confirmed/skipped/pending_confirmation) | food_requests |

### Print Reports (HTML → browser PDF)
| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/reports/shopping-list/<cid>` | any auth | Returns HTML page with printable shopping list |
| GET | `/api/reports/cycle-summary/<cid>` | any auth | Returns HTML page with cycle family + volunteer summary |

### Cycle Assignments (Legacy)
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/cycle-assignments` | any auth | List (filter: cycle_id) | cycle_assignments, volunteers, families |
| POST | `/api/cycle-assignments` | admin | Create cycle assignment | cycle_assignments |
| PUT | `/api/cycle-assignments/<aid>` | admin | Update cycle assignment | cycle_assignments |

### Volunteer Slots (Admin management)
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/volunteer-slots` | any auth | List slots (filter: cycle_id) with family/volunteer names | volunteer_slots, families, volunteers |
| POST | `/api/volunteer-slots` | admin | Create slot with claimed volunteer | volunteer_slots, delivery_cycles |
| PUT | `/api/volunteer-slots/<sid>` | admin | Update slot (status, notes, task_date, claimed_by) | volunteer_slots, volunteers |
| DELETE | `/api/volunteer-slots/<sid>` | admin | Hard delete slot | volunteer_slots |

### Task Types
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| GET | `/api/task-types` | None (no auth!) | List task types | volunteer_task_types |
| POST | `/api/task-types` | admin | Create task type | volunteer_task_types |
| PUT | `/api/task-types/<slug>` | admin | Update task type | volunteer_task_types |

### Public Family Portal (session-based auth)
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| POST | `/api/intake` | None | Rate-limited/honeypot-protected intake; duplicate and new submissions return the same public response | families, rate_limit_events |
| GET | `/api/food-order/check` | Bearer (family session) | Returns family info + all cycles (12mo); legacy ?phone= param removed | families, delivery_cycles, food_requests, food_items, bundle_size_rules, food_categories |
| POST | `/api/food-order` | family Bearer session | Validates active family, open window, future delivery, active items, bounded quantities/custom text, budget, and duplicate race before atomic creation | food_requests, food_request_items, delivery_cycles, families, bundle_size_rules |
| POST | `/api/food-order/cancel` | family Bearer session | Cancel confirmed order if ≥1 day before delivery (Central time); malformed dates fail closed; releases slots and notifies affected users | food_requests, volunteer_slots, food_request_events, delivery_cycles, users, volunteers |
| PUT | `/api/food-order/items` | family Bearer session | Validates item/budget input and edit window; malformed dates fail closed; logs diff and notifies shopping volunteers | food_requests, food_request_items, food_request_events, delivery_cycles, users, volunteers |
| PUT | `/api/food-requests/<rid>/items` | admin | Admin edits item selections for a family's order; logs `admin_override` event | food_requests, food_request_items, food_request_events |
| GET | `/api/family/confirm/<token>` | None (token capability) | Reads only active, unexpired pending confirmation links; rate-limited and privacy-minimized response | food_requests, families, delivery_cycles, food items, rate_limit_events |
| POST | `/api/family/confirm/<token>` | None (token capability) | Atomically consumes a single-use token to confirm/skip; validates cycle deadline, active items and bounded notes | food_requests, food_request_items, food_items |
| POST | `/api/families/<fid>/request-bundle-change` | None | Request bundle size change | families, users (WA) |
| POST | `/api/families/<fid>/manual-confirm` | admin | Manually confirm a family for the active cycle; creates confirmed food_request + items + open volunteer slots | food_requests, food_request_items, families, delivery_cycles, volunteer_slots |

### Volunteer Portal (username/password via unified `/login` page)
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| POST | `/api/portal/login` | None | **410 GONE** — legacy phone-only login removed; use main login. (`/api/otp/request` + `/api/otp/verify` also 410) | — |
| GET | `/api/portal/cycles` | portal token | Upcoming/shopping cycles in next 6 months | delivery_cycles |
| GET | `/api/portal/slots/<cycle_id>` | portal token | Slots for a cycle (volunteer sees all; addresses only for own claimed delivery slots) | volunteer_slots, families, volunteers, delivery_cycles |
| POST | `/api/portal/claim` | portal token | **REMOVED** — superseded by `/api/portal/signup` | — |
| GET | `/api/portal/my-tasks` | portal token | Volunteer's claimed/complete tasks | volunteer_slots, families, delivery_cycles |
| POST | `/api/portal/complete/<slot_id>` | portal token | Mark slot complete; auto-marks food_request delivered if delivery type | volunteer_slots, food_requests |
| GET | `/api/portal/families/<cycle_id>` | portal token | Families enrolled in cycle + volunteer signup status | food_requests, families, volunteer_slots, volunteer_task_types |
| POST | `/api/portal/signup` | portal token | Claim an open slot for a family+task (UPDATE existing open row; 409 if already taken by another); emails confirmation to volunteer | volunteer_slots, families, delivery_cycles, volunteers |
| DELETE | `/api/portal/cancel/<slot_id>` | portal token | Release own claimed slot back to open (UPDATE status→open, NULL claimed_by) | volunteer_slots |
| POST | `/api/portal/receipts/upload` | portal token | Verified, per-volunteer quota-controlled upload registered for one-receipt claiming | filesystem, uploaded_files |
| POST | `/api/portal/receipts` | portal token | Submit receipt + auto-create reimbursement + mark slot complete + notify treasurers | receipts, reimbursements, volunteer_slots, volunteers, users |
| GET | `/api/portal/receipts` | portal token | List own receipts with reimbursement status | receipts, reimbursements |
| GET | `/api/portal/history` | portal token | Own completed task history (privacy-safe: no names/addresses) | volunteer_slots, delivery_cycles, families |

### Admin Utilities
| Method | Path | Auth | Description | Tables |
|---|---|---|---|---|
| POST | `/api/admin/wipe-test-data` | admin | Wipe all operational data (keeps users, catalog, donations) | all operational tables |
| POST | `/api/admin/import-historical` | admin | Bulk import families, volunteers, historical cycles | families, volunteers, delivery_cycles, food_requests, food_request_items |
| POST | `/api/admin/seed-cycles-2026` | admin | Create all bi-weekly 2026 cycles (May–Dec), deletes then reseeds | delivery_cycles |
| GET | `/api/admin/db-debug` | admin | Show delivery_cycles schema + rows + run insert test | delivery_cycles |
| POST | `/api/admin/fix-schema` | admin | Manual trigger for users table CHECK repair | users |
| POST | `/api/reminders/trigger` | admin | Manual trigger for volunteer WA reminders | volunteer_slots, volunteers, families, reminder_log |

### Static file routes
| Path | Serves |
|---|---|
| `GET /` | `public/index.html` (admin SPA) |
| `GET /intake` | `public/intake.html` |
| `GET /order` | 301 redirect → `/intake` (order.html is dead, file still in repo) |
| `GET /confirm/<token>` | `public/confirm.html` |
| `GET /portal` | `public/portal.html` |
| `GET /volunteer` | 301 redirect → `/portal` (volunteer.html is dead, file still in repo) |
| `GET /volunteer-signup` | `public/volunteer-signup.html` |
| `GET /donate-stats` | `public/donate-stats.html` |
| `GET /my-order` | `public/my-order.html` |
| `GET /uploads/<filename>` | Uploaded files (UUID-named, not guessable) |
| `GET /sw.js` | PWA service worker |
| `GET /manifest-family.json` | PWA manifest for family app |
| `GET /manifest-volunteer.json` | PWA manifest for volunteer app |
| `GET /icons/<filename>` | PWA icons |

---

## 5. Public-Facing Pages

All HTML files live in `/public/`. They are single-page apps with inline JS making fetch() calls to the API.

### `index.html` — Admin Dashboard SPA
- Served at `/`
- Requires admin login (`/api/auth/login`)
- Multi-section SPA: Dashboard, Families, Volunteers, Cycles, Food Catalog, Receipts, Reimbursements, Donations, Settings (users)
- Design: black/white minimal, "AreaExtrabold"/"AreaNormal" custom fonts from Wix CDN
- Calls nearly every admin API endpoint

### `intake.html` — Family Intake Form
- Served at `/intake`
- Public (no auth)
- Collects: name, phone, address, city, family size, children count, dietary notes
- Submits to `POST /api/intake`
- PWA-enabled (manifest-family.json, ios/android meta tags)

### `order.html` — RETIRED (dead file)
- `/order` is a 301 redirect to `/intake`; the file is never served
- Safe to delete from repo (backlog Phase 3.4)

### `confirm.html` — Bundle Confirmation (WhatsApp link)
- Served at `/confirm/<token>`
- Public (token-based, no phone needed)
- Token comes from WhatsApp link sent 7 days before delivery
- Calls `GET /api/family/confirm/<token>` to load bundle details
- Calls `POST /api/family/confirm/<token>` to confirm/skip

### `portal.html` — Volunteer Portal SPA
- Served at `/portal`
- Username/password authenticated (POST `/api/portal/login` → unified `/login` page)
- PWA-enabled (manifest-volunteer.json)
- **3-tab layout (rebuilt 2026-06-09):** My Work (assignments + receipt button) | Sign Up (claim board) | History (stats)
- My Work: full-width task cards, prominent green "Submit Receipt" button for shopping slots, "Mark as Done" for delivery
- Sign Up: family rows with order badge + task claim buttons; upcoming cycles accordion
- Auto-confirm on claim — no intermediate pending state
- Delivery volunteers see family address only for their own confirmed delivery slots (enforced server-side)

### `volunteer.html` — RETIRED (dead file)
- `/volunteer` is a 301 redirect to `/portal`; the file is never served
- Safe to delete from repo (backlog Phase 3.4)

### `volunteer-signup.html` — Volunteer Sign-Up Form
- Served at `/volunteer-signup`
- Public (no auth)
- Collects: name, phone, email, role (shopper/delivery/both/general), availability, notes
- Submits to `POST /api/volunteer-signup`

### `my-order.html` — Family Order Status Page
- Served at `/my-order`
- Public, phone-based lookup (same fuzzy phone matching as order.html)
- Calls `GET /api/food-order/check?phone=...`
- Shows current cycle delivery date + order status
- **Confirmed state**: renders "What's in your bundle" item list — first from `selected_categories`, falls back to `bundle_categories` (full catalog for their bundle size)
- **Cancel button**: shown when `can_cancel=true` (>2 days before delivery); calls `POST /api/food-order/cancel`
- **Any-cycle fallback**: works correctly for all cycle statuses (upcoming/open/shopping/delivered) — family always sees their confirmed order if one exists
- Bilingual: English + Arabic (Cairo font for Arabic)
- PWA-enabled (manifest-family.json)

### `donate-stats.html` — Donation Statistics Widget
- Served at `/donate-stats`
- Public (no auth) — designed to be embedded as iframe in Wix website
- Background transparent (no body background)
- Calls `GET /api/donate-stats`
- Renders: total raised, month raised, chart (Chart.js via CDN), projection stats, lives impacted counter

---

## 6. Git Workflow Warning

### index.lock Issue
The `.git/index.lock` file gets created when git operations are interrupted or when multiple processes attempt to write simultaneously. On this machine, the lock persists and blocks all subsequent git operations (add, commit, push).

### The Problem with a Fresh Index
**NEVER** create a fresh temp index file and stage files directly without first seeding it from the current master tree. If you do, git will create a commit that contains ONLY the files you staged — effectively deleting every other file from the tree. This has caused deploys that wipe `server.py`, all HTML files, or other critical files from Railway.

### Safe Git Workflow
When normal `git add` / `git commit` fails due to index.lock:

1. **Remove the lock file first:**
   ```
   rm /path/to/sihaa-ops-hub/.git/index.lock
   ```

2. **If the index is corrupt or missing, seed it from the current HEAD tree before staging:**
   ```bash
   GIT_INDEX_FILE=/tmp/my_index git read-tree master
   GIT_INDEX_FILE=/tmp/my_index git add -A
   GIT_INDEX_FILE=/tmp/my_index git commit -m "your message"
   ```
   The `git read-tree master` step is **mandatory** — it loads the entire current commit tree into the index. Without it, the commit will only contain the files you staged, and all other files will be deleted from git history.

3. **Verify the commit tree before pushing:**
   ```bash
   git ls-tree --name-only HEAD
   ```
   Confirm all expected files appear: `server.py`, `Procfile`, `requirements.txt`, `railway.json`, all `public/*.html` files, etc.

4. **If Claude Code is performing git operations, always use the Python `subprocess` approach with explicit error handling** and always verify the tree before `git push`.

### Files That Must Always Be in the Commit Tree
Every push to `origin/master` (which triggers Railway deploy) must include:
- `server.py`
- `Procfile`
- `requirements.txt`
- `railway.json`
- `public/index.html`
- `public/intake.html`
- `public/confirm.html`
- `public/portal.html`
- `public/family.html`
- `public/volunteer-signup.html`
- `public/donate-stats.html`
- `public/my-order.html`

(`order.html` and `volunteer.html` are retired dead files — their routes are 301 redirects; they need not be in the tree once deleted from the repo.)

---

## 7. Known Issues and Architectural Decisions

### DB Migration Strategy
- SQLite does not support `ALTER COLUMN` or modifying CHECK constraints
- All constraint expansions require full table recreation via `CREATE TABLE ... AS`, copy, DROP, RENAME
- This is done in-process at startup, with try/except to handle concurrent gunicorn workers
- **Risk:** If two gunicorn workers run `bootstrap_db()` simultaneously (both detect the migration is needed and race), the second worker's table-recreation may fail with "table already exists" — this is caught and logged, not re-raised

### `_ensure_treasurer_role()` — safe table recreation (writable_schema hack REMOVED)
- Now uses safe table recreation only (see docstring at server.py ~1526: "no PRAGMA writable_schema")
- ✅ Fixed 2026-06-10 (audit 2.4): `_recreate_users_table` now copies the PRAGMA table_info column INTERSECTION — late-added columns (`linked_id`, `must_change_password`, `password_changed_at`, `last_login_at`) survive rebuilds

### Volunteer Portal Auth vs Admin Auth
- Admin auth: UUID session tokens stored in `sessions` table, `Authorization: Bearer <token>` header
- Volunteer portal auth: Separate UUID tokens in `portal_sessions` table, same header format
- Routes decorated with `@require_auth()` only accept admin session tokens
- Routes decorated with `@require_portal_auth()` only accept portal session tokens
- These are completely separate — a volunteer cannot call admin routes with a portal token

### `/api/food-order/check` — Family-Order-First Logic (updated 2026-04-29, commit cfd1211)
The `check_food_order_eligibility()` function uses a **family-order-first** approach:
1. **Priority 1 — Family has an active order:** Searches `food_requests` for the family's most recent non-skipped/non-cancelled order in any cycle with status `upcoming`, `open`, or `shopping`. If found, returns that cycle + order regardless of cycle status. This ensures families always see their confirmed delivery in My Order.
2. **Priority 2 — Open cycle for fresh submission:** If no active family order exists, falls back to any `open` cycle so a new order can be submitted.
3. **No cycle found:** Returns `open_cycle: False` → UI shows "No upcoming deliveries" message.
4. The `already_submitted` response always includes both `selected_categories` (family's chosen items) AND `bundle_categories` (full catalog fallback) — so my-order.html always has something to display even if `food_request_items` is empty.
5. Returns `can_cancel=True` (≥1 day before delivery, Central time) and `can_edit=True` (≥2 days before delivery, Central time, cycle not shopping/delivered).
6. Returns `order_events` list for the current order (used by My Order Order Activity timeline).
7. If `food_request_items` is empty for an existing order (created before catalog was populated), backfills all active catalog items as `selected=1`.

### Phone-Based Family Lookup (`/api/food-order/check`)
- Normalizes input phone to digits only, then does exact match
- Falls back to fuzzy scan of all families matching last 10 digits if exact match fails
- This exists because early data had phones stored with hyphens/formatting
- The Phase 6 migration normalizes all stored phones, so the fuzzy fallback should rarely be needed on a migrated DB

### Food Request Status Flow
```
pending_confirmation → confirmed     (family confirmed via WA link or admin override)
pending_confirmation → skipped       (family did not respond by cutoff, auto-skipped)
pending_confirmation → skipped       (family opted out via confirm.html)
confirmed → [hard-deleted]           (family cancelled via My Order — row deleted, family CAN re-order)
confirmed → [hard-deleted]           (admin cancelled — row deleted, family CAN re-order)
confirmed → delivered                (volunteer marks delivery slot complete)
```
- `auto_confirmed` status exists in the CHECK but is not currently set anywhere in code
- `submitted` status (legacy) is set when family submits via `/api/food-order` (the self-serve order form), not the WA confirmation flow
- `cancelled` rows no longer persist — both family cancel and admin cancel hard-delete the row (Sprint 3)
- `skipped`: no response / family opted out — these rows ARE kept (not deleted)

### Order Edit/Cancel Business Rules (updated Sprint 3 — 2026-05-15)
- **Edit window**: ≥2 days (48h) before delivery date, Central time (`America/Chicago`). Blocked if cycle status is `shopping` or `delivered`.
- **Cancel window**: ≥1 day (24h) before delivery date, Central time.
- **Cancel hard-deletes**: Both family cancel and admin cancel hard-delete the food_request row (log event → commit → delete child rows → delete food_request → commit). Family CAN re-order after cancelling.
- **All cutoffs use Central time** via `_today_central()` helper (zoneinfo, Python 3.9+).
- **Notifications on cancel**: `_notify_coordinators()` + claimed volunteers for that family/cycle (slots released to open before deletion).
- **Notifications on edit**: `_notify_coordinators()` + claimed shopping volunteers (shopping list may have changed).
- **Event logging**: Cancel event is logged to `food_request_events` BEFORE hard-delete, then that table is also cleaned up in the second delete pass. Net result: no event rows remain after cancel (both actor='family' and actor='admin').
- **Payload stores item names** (not IDs) so history remains readable after catalog changes.

### APScheduler in Multi-Worker gunicorn
- Both workers run the scheduler — both will try to send reminders at 8am, 9am, 9:30am UTC
- `reminder_log` has `UNIQUE(slot_id, sent_to)` — second worker's INSERT fails with IntegrityError (caught), so no double-sends
- Family confirmation job is also idempotent via `INSERT OR IGNORE` and `confirmation_sent_at IS NULL` check

### Wix Donation Sync Privacy
- Full donor names and emails are **never stored** — they are abbreviated/masked at sync time
- Names: first 3 chars of first name + first char of last name, e.g. "Ahm. K."
- Emails: masked to `***@domain.com`
- One-time cleanup pass also anonymizes any previously synced full-name records

### `delivery_cycles.status` Lifecycle
Cycles are manually advanced by admin — there is no auto-advancement (`auto_update_cycle_statuses` is a no-op). Typical progression:
```
upcoming → open → shopping → delivered
```
- `upcoming` — created, T-7 scheduler sends WA opt-in links
- `open` — "Accepting Orders" — families can still submit; T-5 auto-skip fires
- `shopping` — order window closed, volunteers are shopping
- `delivered` — cycle complete

The portal shows cycles with status `upcoming` or `shopping`. Dashboard shows the first `upcoming` or `shopping` cycle as the "active cycle".

### Bundle Size Logic
Two separate bundle size concepts:
1. **Auto-calculated** from `bundle_size_rules` based on `family_size` — used when no override exists
2. **Override** stored in `families.bundle_size` — set by admin, takes precedence

`families.pending_bundle_size` is a family-requested change that requires admin approval before becoming the active override.

### `volunteer_slots` vs `cycle_assignments`
- `cycle_assignments` is the original (Phase 2) assignment model — one volunteer per family per cycle
- `volunteer_slots` (Phase 3C) is the current model — multiple volunteers can claim tasks, open/claimed/complete/cancelled lifecycle, portal-claimable
- Both tables still exist; `cycle_assignments` routes remain functional but the UI uses `volunteer_slots`

### Hard-coded Production URL
The production URL `https://sihha-ops-hub-production.up.railway.app` is hard-coded in:
- `create_receipt` (treasurer notification message)
- `_send_family_confirmation_reminders` uses `APP_URL` env var with that URL as fallback

Set `APP_URL` env var if the URL changes.

### No Authentication on `/api/task-types` GET
The `GET /api/task-types` route has no `@require_auth` decorator — it is publicly accessible. This is intentional (volunteer portal may call it before login) but worth noting.

---

### Architectural Issues — Resolution Status (2026-05-15)

Full details in `SIHAA_Ops_Hub_Architecture_Plan.docx` at workspace root.

| # | Issue | Status | Sprint |
|---|-------|--------|--------|
| 1 | Dual order creation paths — scheduler created food_request rows, diverging from portal path | ✅ Fixed | Sprint 2 — scheduler now sends SMS only; all rows created via `/api/food-order` |
| 2 | `pending_confirmation` semantic overload — set by both scheduler and CR retract | ✅ Fixed | Sprint 2 — scheduler no longer sets this status via row creation |
| 3 | CR retract bug — FALSE POSITIVE | ✅ N/A | Sprint 1 — retract handler never touched food_requests.status; no fix needed |
| 4 | Intake families get no login account on approval | ✅ Fixed | Sprint 1 — `update_family()` pending→active auto-creates users row + emails credentials |
| 5 | Family cancel is permanent (UNIQUE constraint blocks re-order) | ✅ Fixed | Sprint 3 — family cancel now hard-deletes (log → commit → delete) |
| 6 | Two volunteer claim endpoints | ✅ Fixed | Sprint 2 — `/api/portal/claim` removed; only `/api/portal/signup` remains |
| 7 | `paused` family status dead weight | ✅ Fixed | Sprint 2 — removed from CHECK constraint via bootstrap migration; index.html updated |
| 8 | Deliveries module does 3 jobs | ✅ Fixed | commit 1f5e1b7 — "Active Cycle" nav added; auto-loads current open/shopping cycle with advance/revert controls in topbar; Deliveries stays as history list |

### Proposed Target Architecture (approved for planning, not yet implemented)

- **Order statuses**: 7 → 3 (`placed`, `skipped`, `cancelled`; `delivered` stays as lifecycle milestone)
- **Scheduler role**: notification only — never creates food_request rows
- **CR workflow**: removed — families edit directly while cycle open; admin edits directly after lock
- **Volunteer slots**: lazy creation on first claim (not pre-created)
- **Family portal**: next 2–3 cycles only (not 12-month window)
- **Admin nav**: Dashboard → Active Cycle → Deliveries → Families → Volunteers → Finance
- **Active Cycle command center**: 3 panels (Orders / Coverage / Attention), one admin action ("Lock for Shopping")
- **Auto-triggers**: cycle opens at T-7 (scheduler); cycle delivers when all slots complete

---

## 8. Session Start Checklist

At the start of every dev session involving this codebase:

1. **Read this file (CLAUDE.md) in full** before making any changes.

2. **If making DB changes (new table, new column, new migration):**
   - Read the full `bootstrap_db()` function in `server.py` (lines ~91–882)
   - Add the migration to `bootstrap_db()` as an idempotent ALTER TABLE or table-recreation
   - Never add a column only inside a route handler — always add it in `bootstrap_db()` first
   - Update Section 2 (DB Schema) and Section 3 (Migration Inventory) in this file

3. **If adding or modifying routes:**
   - Check for auth decorator requirements
   - Verify all DB columns referenced already exist (see Section 2)
   - Update Section 4 (All Routes) in this file

4. **Before any git commit:**
   - Check for `.git/index.lock` and remove it if present
   - If the git index seems wrong or was rebuilt, run `git ls-tree --name-only HEAD` to verify all expected files are in the tree
   - NEVER push a commit without verifying the tree — Railway deploys immediately on push to master
   - See Section 6 (Git Workflow Warning) for the safe procedure

5. **After deploying to Railway:**
   - Check Railway logs for `bootstrap_db` output: it logs every migration step and the final DB size
   - Look for `DB EXISTS (X KB)` — if you see `DB NOT FOUND — creating fresh database`, the Railway Volume is not mounted correctly
   - Confirm no `Migration: ... failed` log lines (warnings are OK, errors are not)

6. **If a migration was supposed to run but didn't (live DB is missing a column):**
   - The idempotent migrations in `bootstrap_db()` run on every deploy
   - Trigger a redeploy (push any change) to run them on the live DB
   - Use `GET /api/admin/db-debug` to inspect live schema for `delivery_cycles`
   - Use `POST /api/admin/fix-schema` to repair the `users` CHECK constraint specifically

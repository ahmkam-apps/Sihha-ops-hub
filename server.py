import os
import sqlite3
import uuid
import logging
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException

# ── Config ────────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder='public')
CORS(app)

DB_PATH         = os.environ.get('DB_PATH', 'data/sihaa.db')
UPLOAD_FOLDER   = os.environ.get('UPLOAD_FOLDER', 'data/uploads')
SESSION_HOURS   = int(os.environ.get('SESSION_EXPIRY_HOURS', 24))
PORT            = int(os.environ.get('PORT', 5000))
ALLOWED_EXT     = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'heic'}
SENDGRID_API_KEY  = os.environ.get('SENDGRID_API_KEY', '')
NOTIFY_FROM_EMAIL = os.environ.get('NOTIFY_FROM_EMAIL', 'ops@sihha.org')
# Set WA_ENABLED=0 in Railway env to bypass all WhatsApp sends globally (useful during dev/testing)
WA_ENABLED = os.environ.get('WA_ENABLED', '1').strip() not in ('0', 'false', 'no', 'off')

# ── Twilio (SMS OTP) ──────────────────────────────────────────────────────────
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN  = os.environ.get('TWILIO_AUTH_TOKEN', '')
TWILIO_FROM        = os.environ.get('TWILIO_FROM', '')  # E.164 e.g. +15551234567
SMS_ENABLED        = bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM)

os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else '.', exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

# ── DB Helpers ────────────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
        g.db.execute('PRAGMA foreign_keys=ON')
        g.db.execute('PRAGMA busy_timeout=5000')  # wait up to 5s on lock before erroring
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def now():
    return datetime.utcnow().isoformat()

def _bundle_letter(family_size):
    """Return S / M / L based on household size."""
    size = int(family_size or 1)
    if size <= 2:   return 'S'
    elif size <= 5: return 'M'
    else:           return 'L'

def _normalize_phone(phone):
    """Strip all non-digit characters. '555-123-4567' → '5551234567'."""
    return ''.join(c for c in (phone or '') if c.isdigit())

def _make_family_code(phone, family_size, db_conn=None, exclude_id=None):
    """Generate unique human-readable family reference.
    Format: last 6 digits of phone + '-' + bundle size letter.
    Example: phone=5855551234, family_size=4 → '551234-M'
    If a collision exists, appends -2, -3, … until unique.
    Pass db_conn to enforce uniqueness against the families table.
    """
    digits = ''.join(c for c in (phone or '') if c.isdigit())
    phone_part = digits[-6:].zfill(6) if digits else '000000'
    bundle = _bundle_letter(family_size)
    base = f'{phone_part}-{bundle}'

    if db_conn is None:
        return base

    # Enforce uniqueness
    candidate = base
    suffix = 2
    while True:
        row = db_conn.execute(
            "SELECT id FROM families WHERE family_code=?" +
            (" AND id!=?" if exclude_id else ""),
            (candidate, exclude_id) if exclude_id else (candidate,)
        ).fetchone()
        if not row:
            return candidate
        candidate = f'{base}-{suffix}'
        suffix += 1

def bootstrap_db():
    # ── Diagnostics: log exactly where the DB lives and whether it's fresh ────
    abs_db = os.path.abspath(DB_PATH)
    db_dir = os.path.dirname(abs_db)
    log.info(f'DB_PATH={DB_PATH}  →  absolute={abs_db}')
    log.info(f'Working directory: {os.getcwd()}')

    if os.path.exists(abs_db):
        size_kb = os.path.getsize(abs_db) / 1024
        log.info(f'DB EXISTS ({size_kb:.1f} KB) — data will be preserved ✓')
    else:
        log.warning(f'DB NOT FOUND — creating fresh database. '
                    f'If this happens every deploy, the Railway Volume is not mounted at: {db_dir}')

    os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(abs_db)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id            TEXT PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name          TEXT,
            role          TEXT NOT NULL DEFAULT 'viewer'
                          CHECK(role IN ('admin','volunteer','finance','treasurer','viewer')),
            email         TEXT,
            wa_phone      TEXT,
            wa_apikey     TEXT,
            active        INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            expires_at  TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS families (
            id              TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            phone           TEXT,
            address         TEXT,
            city            TEXT,
            family_size     INTEGER,
            children_count  INTEGER,
            dietary_notes   TEXT,
            frequency       TEXT,
            income_range    TEXT,
            status          TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending','active','inactive','paused')),
            notes           TEXT,
            source          TEXT DEFAULT 'admin',
            created_at      TEXT NOT NULL,
            updated_at      TEXT
        );

        CREATE TABLE IF NOT EXISTS volunteers (
            id                  TEXT PRIMARY KEY,
            name                TEXT NOT NULL,
            phone               TEXT,
            email               TEXT,
            role                TEXT DEFAULT 'shopper'
                                CHECK(role IN ('shopper','delivery','both','general')),
            availability        TEXT,
            service_area        TEXT,
            contact_preference  TEXT,
            volunteer_areas     TEXT,
            comfort_level       INTEGER,
            skills              TEXT,
            other_info          TEXT,
            status              TEXT NOT NULL DEFAULT 'pending'
                                CHECK(status IN ('pending','active','inactive')),
            notes               TEXT,
            source              TEXT DEFAULT 'admin',
            created_at          TEXT NOT NULL,
            updated_at          TEXT
        );

        CREATE TABLE IF NOT EXISTS assignments (
            id              TEXT PRIMARY KEY,
            family_id       TEXT NOT NULL,
            volunteer_id    TEXT,
            task_type       TEXT CHECK(task_type IN ('shopping','delivery','both')),
            due_date        TEXT,
            status          TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending','assigned','in_progress','completed','cancelled')),
            notes           TEXT,
            created_by      TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT,
            FOREIGN KEY (family_id) REFERENCES families(id),
            FOREIGN KEY (volunteer_id) REFERENCES volunteers(id)
        );

        CREATE TABLE IF NOT EXISTS receipts (
            id              TEXT PRIMARY KEY,
            assignment_id   TEXT,
            volunteer_id    TEXT,
            family_id       TEXT,
            store           TEXT,
            purchase_date   TEXT,
            amount          REAL,
            file_url        TEXT,
            status          TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending','approved','rejected')),
            notes           TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT,
            FOREIGN KEY (assignment_id) REFERENCES assignments(id),
            FOREIGN KEY (volunteer_id) REFERENCES volunteers(id),
            FOREIGN KEY (family_id) REFERENCES families(id)
        );

        CREATE TABLE IF NOT EXISTS reimbursements (
            id              TEXT PRIMARY KEY,
            receipt_id      TEXT NOT NULL,
            volunteer_id    TEXT,
            amount          REAL,
            status          TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending','approved','paid','rejected')),
            payment_method  TEXT CHECK(payment_method IN ('venmo','zelle','check','cash','bank_transfer','cheque','other')),
            payment_ref     TEXT,
            paid_date       TEXT,
            approved_by     TEXT,
            notes           TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT,
            FOREIGN KEY (receipt_id) REFERENCES receipts(id)
        );

        CREATE TABLE IF NOT EXISTS donations (
            id          TEXT PRIMARY KEY,
            donor_name  TEXT,
            donor_email TEXT,
            amount      REAL,
            type        TEXT DEFAULT 'online'
                        CHECK(type IN ('online','cash','check','bank')),
            date        TEXT,
            source      TEXT DEFAULT 'manual',
            reference_id TEXT,
            cycle_id    TEXT,
            notes       TEXT,
            created_at  TEXT NOT NULL
        );

        -- ── Food Catalog ──────────────────────────────────────────────────────

        CREATE TABLE IF NOT EXISTS food_categories (
            id            TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            display_order INTEGER NOT NULL DEFAULT 0,
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS food_items (
            id            TEXT PRIMARY KEY,
            category_id   TEXT NOT NULL,
            name          TEXT NOT NULL,
            unit          TEXT NOT NULL DEFAULT 'each',
            is_active     INTEGER NOT NULL DEFAULT 1,
            display_order INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL,
            FOREIGN KEY (category_id) REFERENCES food_categories(id)
        );

        CREATE TABLE IF NOT EXISTS bundle_quantities (
            id           TEXT PRIMARY KEY,
            food_item_id TEXT NOT NULL,
            bundle_size  TEXT NOT NULL CHECK(bundle_size IN ('S','M','L')),
            quantity     TEXT NOT NULL,
            UNIQUE(food_item_id, bundle_size),
            FOREIGN KEY (food_item_id) REFERENCES food_items(id)
        );

        CREATE TABLE IF NOT EXISTS bundle_size_rules (
            id            TEXT PRIMARY KEY,
            bundle_size   TEXT NOT NULL UNIQUE CHECK(bundle_size IN ('S','M','L')),
            label         TEXT NOT NULL,
            min_household INTEGER NOT NULL,
            max_household INTEGER
        );

        -- ── Delivery Cycles ───────────────────────────────────────────────────

        CREATE TABLE IF NOT EXISTS delivery_cycles (
            id                  TEXT PRIMARY KEY,
            title               TEXT NOT NULL,
            delivery_date_start TEXT NOT NULL,
            delivery_date_end   TEXT NOT NULL,
            request_open_at     TEXT NOT NULL,
            request_close_at    TEXT NOT NULL,
            status              TEXT NOT NULL DEFAULT 'draft'
                                CHECK(status IN ('draft','open','closed','shopping','delivered')),
            notes               TEXT,
            created_by          TEXT,
            created_at          TEXT NOT NULL,
            updated_at          TEXT
        );

        -- ── Food Orders ───────────────────────────────────────────────────────

        CREATE TABLE IF NOT EXISTS food_requests (
            id                  TEXT PRIMARY KEY,
            cycle_id            TEXT NOT NULL,
            family_id           TEXT NOT NULL,
            bundle_size         TEXT NOT NULL CHECK(bundle_size IN ('S','M','L')),
            submitted_at        TEXT NOT NULL,
            status              TEXT NOT NULL DEFAULT 'submitted'
                                CHECK(status IN ('submitted','assigned','delivered','cancelled')),
            assigned_volunteer_id TEXT,
            delivered_at        TEXT,
            notes               TEXT,
            UNIQUE(cycle_id, family_id),
            FOREIGN KEY (cycle_id) REFERENCES delivery_cycles(id),
            FOREIGN KEY (family_id) REFERENCES families(id)
        );

        CREATE TABLE IF NOT EXISTS food_request_items (
            id           TEXT PRIMARY KEY,
            request_id   TEXT NOT NULL,
            food_item_id TEXT NOT NULL,
            selected     INTEGER NOT NULL DEFAULT 0,
            UNIQUE(request_id, food_item_id),
            FOREIGN KEY (request_id) REFERENCES food_requests(id),
            FOREIGN KEY (food_item_id) REFERENCES food_items(id)
        );

        -- ── Volunteer Cycle Assignments ────────────────────────────────────────

        CREATE TABLE IF NOT EXISTS cycle_assignments (
            id           TEXT PRIMARY KEY,
            cycle_id     TEXT NOT NULL,
            volunteer_id TEXT NOT NULL,
            family_id    TEXT,
            task_type    TEXT NOT NULL CHECK(task_type IN ('shopping','delivery')),
            task_date    TEXT,
            task_time    TEXT,
            status       TEXT NOT NULL DEFAULT 'pending'
                         CHECK(status IN ('pending','confirmed','completed','cancelled')),
            notes        TEXT,
            created_at   TEXT NOT NULL,
            updated_at   TEXT,
            FOREIGN KEY (cycle_id) REFERENCES delivery_cycles(id),
            FOREIGN KEY (volunteer_id) REFERENCES volunteers(id),
            FOREIGN KEY (family_id) REFERENCES families(id)
        );

        -- ── Financial Reconciliation ──────────────────────────────────────────

        CREATE TABLE IF NOT EXISTS bank_transactions (
            id                  TEXT PRIMARY KEY,
            transaction_date    TEXT NOT NULL,
            description         TEXT,
            amount              REAL NOT NULL,
            matched_donation_id TEXT,
            reconcile_status    TEXT NOT NULL DEFAULT 'unmatched'
                                CHECK(reconcile_status IN ('matched','unmatched','ignored')),
            imported_at         TEXT NOT NULL,
            FOREIGN KEY (matched_donation_id) REFERENCES donations(id)
        );

        CREATE TABLE IF NOT EXISTS reconciliation_runs (
            id                      TEXT PRIMARY KEY,
            run_date                TEXT NOT NULL,
            period_start            TEXT,
            period_end              TEXT,
            total_online_donations  REAL DEFAULT 0,
            total_bank_deposits     REAL DEFAULT 0,
            variance                REAL DEFAULT 0,
            notes                   TEXT,
            run_by                  TEXT,
            created_at              TEXT NOT NULL
        );

        -- ── Phase 4D: Stripe / Wix / Bank reconciliation ─────────────────────

        CREATE TABLE IF NOT EXISTS stripe_transactions (
            id               TEXT PRIMARY KEY,
            stripe_charge_id TEXT UNIQUE,
            stripe_payout_id TEXT,
            donor_name       TEXT,
            donor_email      TEXT,
            amount           REAL,
            fee              REAL,
            net              REAL,
            charge_date      TEXT,
            payout_date      TEXT,
            description      TEXT,
            synced_at        TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS wix_donations (
            id              TEXT PRIMARY KEY,
            wix_order_id    TEXT UNIQUE,
            donor_name      TEXT,
            donor_email     TEXT,
            amount          REAL,
            donation_date   TEXT,
            description     TEXT,
            synced_at       TEXT NOT NULL
        );
    ''')

    # Seed default admin — INSERT OR IGNORE is atomic, safe under concurrent gunicorn workers.
    # Password is read from ADMIN_PASSWORD env var (set in Railway dashboard).
    # Falls back to 'admin123' only if env var is not set (dev/local only).
    admin_pw = os.environ.get('ADMIN_PASSWORD', 'admin123')
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password_hash, name, role, created_at) VALUES (?,?,?,?,?,?)",
        (str(uuid.uuid4()), 'admin', generate_password_hash(admin_pw),
         'Administrator', 'admin', now())
    )
    # If ADMIN_PASSWORD env var is explicitly set, always sync it to the DB.
    # This means changing ADMIN_PASSWORD in Railway takes effect on the next deploy
    # even if the admin user already existed with a different password.
    if os.environ.get('ADMIN_PASSWORD'):
        conn.execute(
            "UPDATE users SET password_hash=? WHERE username='admin'",
            (generate_password_hash(admin_pw),)
        )
        log.info('Admin password synced from ADMIN_PASSWORD env var.')
    else:
        log.warning('Admin password is default admin123 — set ADMIN_PASSWORD env var in Railway!')

    # Seed bundle size rules if not present
    if not conn.execute("SELECT id FROM bundle_size_rules LIMIT 1").fetchone():
        rules = [
            (str(uuid.uuid4()), 'S', 'Small',  1, 2),
            (str(uuid.uuid4()), 'M', 'Medium', 3, 5),
            (str(uuid.uuid4()), 'L', 'Large',  6, None),
        ]
        conn.executemany(
            "INSERT INTO bundle_size_rules (id, bundle_size, label, min_household, max_household) VALUES (?,?,?,?,?)",
            rules
        )
        log.info('Bundle size rules seeded.')

    # Seed food catalog if not present
    if not conn.execute("SELECT id FROM food_categories LIMIT 1").fetchone():
        ts = now()
        # Categories
        cats = [
            (str(uuid.uuid4()), 'Grains',  1, ts),
            (str(uuid.uuid4()), 'Protein', 2, ts),
            (str(uuid.uuid4()), 'Produce', 3, ts),
        ]
        conn.executemany(
            "INSERT INTO food_categories (id, name, display_order, is_active, created_at) VALUES (?,?,?,1,?)",
            cats
        )
        grains_id, protein_id, produce_id = cats[0][0], cats[1][0], cats[2][0]

        # Items: (id, category_id, name, unit, display_order)
        items_data = [
            (str(uuid.uuid4()), grains_id,  'Rice',          'lb',     1),
            (str(uuid.uuid4()), grains_id,  'Pasta',         'packet', 2),
            (str(uuid.uuid4()), grains_id,  'Bread',         'loaf',   3),
            (str(uuid.uuid4()), protein_id, 'Eggs',          'dozen',  1),
            (str(uuid.uuid4()), protein_id, 'Canned Beans',  'can',    2),
            (str(uuid.uuid4()), protein_id, 'Whole Chicken', 'each',   3),
            (str(uuid.uuid4()), protein_id, 'Brown Lentils', 'lb',     4),
            (str(uuid.uuid4()), produce_id, 'Potatoes',      'lb',     1),
            (str(uuid.uuid4()), produce_id, 'Oranges',       'bag',    2),
            (str(uuid.uuid4()), produce_id, 'Bananas',       'bunch',  3),
        ]
        conn.executemany(
            "INSERT INTO food_items (id, category_id, name, unit, is_active, display_order, created_at) VALUES (?,?,?,?,1,?,?)",
            [(i[0],i[1],i[2],i[3],i[4],ts) for i in items_data]
        )

        # Bundle quantities per item (S, M, L)
        qty_map = {
            'Rice':          [('S','2 lb'),  ('M','5 lb'),  ('L','10 lb')],
            'Pasta':         [('S','2'),     ('M','3'),     ('L','4')],
            'Bread':         [('S','1'),     ('M','2'),     ('L','3')],
            'Eggs':          [('S','2'),     ('M','3'),     ('L','4')],
            'Canned Beans':  [('S','4'),     ('M','6'),     ('L','8')],
            'Whole Chicken': [('S','1'),     ('M','2'),     ('L','3')],
            'Brown Lentils': [('S','1 lb'),  ('M','2 lb'),  ('L','3 lb')],
            'Potatoes':      [('S','5 lb'),  ('M','8 lb'),  ('L','10 lb')],
            'Oranges':       [('S','1'),     ('M','2'),     ('L','3')],
            'Bananas':       [('S','1'),     ('M','2'),     ('L','2')],
        }
        item_name_to_id = {i[2]: i[0] for i in items_data}
        bq_rows = []
        for name, qtys in qty_map.items():
            iid = item_name_to_id[name]
            for size, qty in qtys:
                bq_rows.append((str(uuid.uuid4()), iid, size, qty))
        conn.executemany(
            "INSERT INTO bundle_quantities (id, food_item_id, bundle_size, quantity) VALUES (?,?,?,?)",
            bq_rows
        )
        log.info('Food catalog seeded with default items and bundle quantities.')

    # ── Idempotent column migrations (alter existing tables safely) ───────────
    for _col, _def in [('wa_phone', 'TEXT'), ('wa_apikey', 'TEXT')]:
        try:
            conn.execute(f'ALTER TABLE volunteers ADD COLUMN {_col} {_def}')
        except sqlite3.OperationalError:
            pass  # Column already exists

    # Add completed_at to volunteer_slots (tracks when a task was marked done)
    try:
        conn.execute('ALTER TABLE volunteer_slots ADD COLUMN completed_at TEXT')
        log.info('Migration: added completed_at to volunteer_slots')
    except sqlite3.OperationalError:
        pass  # Already exists

    # Add family_code — human-readable reference (last 4 digits of phone + bundle size)
    try:
        conn.execute('ALTER TABLE families ADD COLUMN family_code TEXT')
        log.info('Migration: added family_code to families')
    except sqlite3.OperationalError:
        pass  # Already exists

    # Add columns that exist in CREATE TABLE but were missing from live DBs
    for _col, _def in [
        ('bundle_size',         'TEXT'),
        ('updated_at',          'TEXT'),
        ('pending_bundle_size', 'TEXT'),
        ('wa_phone',            'TEXT'),
        ('wa_apikey',           'TEXT'),
    ]:
        try:
            conn.execute(f'ALTER TABLE families ADD COLUMN {_col} {_def}')
            log.info(f'Migration: added families.{_col}')
        except sqlite3.OperationalError:
            pass  # Already exists

    # Ensure all donations columns exist (some only added inside route handlers, not here)
    for _col, _def in [
        ('donor_email',  'TEXT'),
        ('type',         'TEXT'),
        ('reference_id', 'TEXT'),
        ('cycle_id',     'TEXT'),
        ('frequency',    'TEXT'),
        ('source',       'TEXT'),
    ]:
        try:
            conn.execute(f'ALTER TABLE donations ADD COLUMN {_col} {_def}')
            log.info(f'Migration: added donations.{_col}')
        except sqlite3.OperationalError:
            pass

    # ── Phase 4A migrations ───────────────────────────────────────────────────

    # Ensure food_requests has all expected columns (safety net in case table recreation failed)
    for _col, _def in [
        ('confirmation_token',    'TEXT'),
        ('confirmed_at',          'TEXT'),
        ('confirmation_sent_at',  'TEXT'),
        ('updated_at',            'TEXT'),
        ('family_notes',          'TEXT'),
    ]:
        try:
            conn.execute(f'ALTER TABLE food_requests ADD COLUMN {_col} {_def}')
            log.info(f'Migration: added food_requests.{_col}')
        except sqlite3.OperationalError:
            pass  # Already exists

    # Add slot_id to receipts (links a portal-submitted receipt to a volunteer slot)
    try:
        conn.execute('ALTER TABLE receipts ADD COLUMN slot_id TEXT')
        log.info('Migration: added slot_id to receipts')
    except sqlite3.OperationalError:
        pass

    # Add email/wa_phone/wa_apikey to users (treasurer notification channels)
    for _col, _def in [('email', 'TEXT'), ('wa_phone', 'TEXT'), ('wa_apikey', 'TEXT')]:
        try:
            conn.execute(f'ALTER TABLE users ADD COLUMN {_col} {_def}')
            log.info(f'Migration: added {_col} to users')
        except sqlite3.OperationalError:
            pass

    # Migrate users table: add treasurer role + new notification columns
    # (SQLite CHECK constraints require table recreation to modify)
    users_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()
    if users_sql and 'treasurer' not in users_sql[0]:
        log.info('Migration: upgrading users table for treasurer role')
        try:
            conn.execute('PRAGMA foreign_keys=OFF')
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS users_new (
                    id            TEXT PRIMARY KEY,
                    username      TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name          TEXT,
                    role          TEXT NOT NULL DEFAULT 'viewer'
                                  CHECK(role IN ('admin','volunteer','finance','treasurer','viewer')),
                    email         TEXT,
                    wa_phone      TEXT,
                    wa_apikey     TEXT,
                    active        INTEGER NOT NULL DEFAULT 1,
                    created_at    TEXT NOT NULL
                );
                INSERT OR IGNORE INTO users_new
                    (id, username, password_hash, name, role, email, wa_phone, wa_apikey, active, created_at)
                SELECT id, username, password_hash, name, role, email, wa_phone, wa_apikey, active, created_at
                FROM users;
                DROP TABLE IF EXISTS users;
                ALTER TABLE users_new RENAME TO users;
            ''')
            conn.execute('PRAGMA foreign_keys=ON')
            log.info('Migration: users table upgraded — treasurer role now supported')
        except Exception as _e:
            # Another worker already ran this migration — safe to skip
            log.info(f'Migration: users table already upgraded or in progress — skipping ({_e})')
            conn.execute('PRAGMA foreign_keys=ON')

    # Migrate reimbursements table: add venmo/zelle payment methods + payment_ref column
    reimb_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='reimbursements'"
    ).fetchone()
    if reimb_sql and 'venmo' not in reimb_sql[0]:
        log.info('Migration: upgrading reimbursements table for new payment methods')
        try:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS reimbursements_new (
                    id              TEXT PRIMARY KEY,
                    receipt_id      TEXT NOT NULL,
                    volunteer_id    TEXT,
                    amount          REAL,
                    status          TEXT NOT NULL DEFAULT 'pending'
                                    CHECK(status IN ('pending','approved','paid','rejected')),
                    payment_method  TEXT CHECK(payment_method IN ('venmo','zelle','check','cash','bank_transfer','cheque','other')),
                    payment_ref     TEXT,
                    paid_date       TEXT,
                    approved_by     TEXT,
                    notes           TEXT,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT,
                    FOREIGN KEY (receipt_id) REFERENCES receipts(id)
                );
                INSERT OR IGNORE INTO reimbursements_new
                    (id, receipt_id, volunteer_id, amount, status, payment_method,
                     payment_ref, paid_date, approved_by, notes, created_at, updated_at)
                SELECT id, receipt_id, volunteer_id, amount, status, payment_method,
                       NULL, paid_date, approved_by, notes, created_at, updated_at
                FROM reimbursements;
                DROP TABLE IF EXISTS reimbursements;
                ALTER TABLE reimbursements_new RENAME TO reimbursements;
            ''')
            log.info('Migration: reimbursements table upgraded — venmo/zelle/payment_ref added')
        except Exception as _e:
            # Another worker already ran this migration — safe to skip
            log.info(f'Migration: reimbursements table already upgraded or in progress — skipping ({_e})')

    # ── Phase 6 migrations: phone normalisation + bundle size request ─────────────

    # Add pending_bundle_size to families (coordinator must approve before it takes effect)
    try:
        conn.execute('ALTER TABLE families ADD COLUMN pending_bundle_size TEXT')
        log.info('Migration: added pending_bundle_size to families')
    except sqlite3.OperationalError:
        pass

    # Normalise all existing phone numbers — strip hyphens/spaces/parens to digits only
    rows = conn.execute("SELECT id, phone FROM families WHERE phone IS NOT NULL").fetchall()
    updated = 0
    for row in rows:
        normalized = ''.join(c for c in row[1] if c.isdigit())
        if normalized != row[1]:
            conn.execute("UPDATE families SET phone=? WHERE id=?", (normalized, row[0]))
            updated += 1
    if updated:
        conn.commit()
        log.info(f'Migration: normalised {updated} family phone numbers')

    # Same for volunteers
    vrows = conn.execute("SELECT id, phone FROM volunteers WHERE phone IS NOT NULL").fetchall()
    vupdated = 0
    for row in vrows:
        normalized = ''.join(c for c in row[1] if c.isdigit())
        if normalized != row[1]:
            conn.execute("UPDATE volunteers SET phone=? WHERE id=?", (normalized, row[0]))
            vupdated += 1
    if vupdated:
        conn.commit()
        log.info(f'Migration: normalised {vupdated} volunteer phone numbers')

    # ── Phase 5 migrations: family WhatsApp + food_request confirmation ──────────

    # Add wa_phone / wa_apikey to families (for confirmation messages)
    for _col in ['wa_phone', 'wa_apikey']:
        try:
            conn.execute(f'ALTER TABLE families ADD COLUMN {_col} TEXT')
            log.info(f'Migration: added {_col} to families')
        except sqlite3.OperationalError:
            pass

    # Add confirmation fields to food_requests
    for _col, _def in [('confirmation_token', 'TEXT'), ('confirmed_at', 'TEXT'), ('confirmation_sent_at', 'TEXT')]:
        try:
            conn.execute(f'ALTER TABLE food_requests ADD COLUMN {_col} {_def}')
            log.info(f'Migration: added {_col} to food_requests')
        except sqlite3.OperationalError:
            pass

    # Upgrade delivery_cycles status CHECK to include 'upcoming'
    cycles_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='delivery_cycles'"
    ).fetchone()
    if cycles_sql and 'upcoming' not in cycles_sql[0]:
        log.info('Migration: upgrading delivery_cycles CHECK to include upcoming status')
        try:
            conn.execute('PRAGMA foreign_keys=OFF')
            # Clean up any leftover _new table from a previous failed attempt
            conn.execute('DROP TABLE IF EXISTS delivery_cycles_new')
            conn.execute('''
                CREATE TABLE delivery_cycles_new (
                    id                  TEXT PRIMARY KEY,
                    title               TEXT NOT NULL,
                    delivery_date_start TEXT NOT NULL,
                    delivery_date_end   TEXT NOT NULL,
                    request_open_at     TEXT NOT NULL DEFAULT '',
                    request_close_at    TEXT NOT NULL DEFAULT '',
                    status              TEXT NOT NULL DEFAULT 'upcoming'
                                        CHECK(status IN ('draft','open','closed','upcoming','shopping','delivered')),
                    notes               TEXT,
                    created_by          TEXT,
                    created_at          TEXT NOT NULL,
                    updated_at          TEXT
                )''')
            # Explicit column list so old rows (without updated_at) copy correctly
            conn.execute('''
                INSERT INTO delivery_cycles_new
                    (id, title, delivery_date_start, delivery_date_end,
                     request_open_at, request_close_at, status, notes, created_by, created_at)
                SELECT id, title, delivery_date_start, delivery_date_end,
                       COALESCE(request_open_at,''), COALESCE(request_close_at,''),
                       status, notes, created_by, created_at
                FROM delivery_cycles''')
            conn.execute('DROP TABLE delivery_cycles')
            conn.execute('ALTER TABLE delivery_cycles_new RENAME TO delivery_cycles')
            conn.execute("UPDATE delivery_cycles SET status='upcoming' WHERE status IN ('draft','open','closed')")
            conn.commit()
            conn.execute('PRAGMA foreign_keys=ON')
            log.info('Migration: delivery_cycles upgraded — upcoming status added')
        except Exception as _e:
            conn.execute('PRAGMA foreign_keys=ON')
            log.info(f'Migration: delivery_cycles upgrade failed — {_e}')

    # Upgrade food_requests status CHECK to include confirmation statuses
    freq_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='food_requests'"
    ).fetchone()
    if freq_sql and 'pending_confirmation' not in freq_sql[0]:
        log.info('Migration: upgrading food_requests for confirmation statuses')
        try:
            conn.execute('PRAGMA foreign_keys=OFF')
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS food_requests_new (
                    id                   TEXT PRIMARY KEY,
                    cycle_id             TEXT NOT NULL,
                    family_id            TEXT NOT NULL,
                    bundle_size          TEXT NOT NULL CHECK(bundle_size IN ('S','M','L')),
                    submitted_at         TEXT NOT NULL,
                    status               TEXT NOT NULL DEFAULT 'pending_confirmation'
                                         CHECK(status IN ('submitted','assigned','delivered','cancelled',
                                                          'pending_confirmation','confirmed','skipped','auto_confirmed')),
                    assigned_volunteer_id TEXT,
                    delivered_at         TEXT,
                    notes                TEXT,
                    confirmation_token   TEXT,
                    confirmed_at         TEXT,
                    confirmation_sent_at TEXT,
                    UNIQUE(cycle_id, family_id),
                    FOREIGN KEY (cycle_id)  REFERENCES delivery_cycles(id),
                    FOREIGN KEY (family_id) REFERENCES families(id)
                );
                INSERT OR IGNORE INTO food_requests_new
                    (id, cycle_id, family_id, bundle_size, submitted_at, status,
                     assigned_volunteer_id, delivered_at, notes,
                     confirmation_token, confirmed_at, confirmation_sent_at)
                SELECT id, cycle_id, family_id, bundle_size, submitted_at, status,
                       assigned_volunteer_id, delivered_at, notes,
                       confirmation_token, confirmed_at, confirmation_sent_at
                FROM food_requests;
                DROP TABLE IF EXISTS food_requests;
                ALTER TABLE food_requests_new RENAME TO food_requests;
            ''')
            conn.execute('PRAGMA foreign_keys=ON')
            log.info('Migration: food_requests upgraded — confirmation statuses added')
        except Exception as _e:
            conn.execute('PRAGMA foreign_keys=ON')
            log.info(f'Migration: food_requests already upgraded — skipping ({_e})')

    conn.commit()

    # Back-fill family_code for existing families that don't have one
    existing = conn.execute(
        "SELECT id, phone, family_size FROM families WHERE family_code IS NULL OR family_code=''"
    ).fetchall()
    for row in existing:
        code = _make_family_code(row[1], row[2], db_conn=conn, exclude_id=row[0])
        conn.execute("UPDATE families SET family_code=? WHERE id=?", (code, row[0]))
    if existing:
        log.info(f'Back-filled family_code for {len(existing)} existing families')

    # ── Phase 3C tables ───────────────────────────────────────────────────────
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS volunteer_slots (
            id           TEXT PRIMARY KEY,
            cycle_id     TEXT NOT NULL,
            family_id    TEXT NOT NULL,
            task_type    TEXT NOT NULL,
            task_date    TEXT,
            claimed_by   TEXT,
            claimed_at   TEXT,
            completed_at TEXT,
            status       TEXT NOT NULL DEFAULT 'claimed'
                         CHECK(status IN ('open','claimed','complete','cancelled')),
            notes        TEXT,
            created_at   TEXT NOT NULL,
            updated_at   TEXT,
            FOREIGN KEY (cycle_id)   REFERENCES delivery_cycles(id),
            FOREIGN KEY (family_id)  REFERENCES families(id),
            FOREIGN KEY (claimed_by) REFERENCES volunteers(id)
        );

        CREATE TABLE IF NOT EXISTS volunteer_task_types (
            slug          TEXT PRIMARY KEY,
            label         TEXT NOT NULL,
            display_order INTEGER NOT NULL DEFAULT 0,
            is_active     INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS portal_sessions (
            token        TEXT PRIMARY KEY,
            volunteer_id TEXT NOT NULL,
            expires_at   TEXT NOT NULL,
            created_at   TEXT NOT NULL,
            FOREIGN KEY (volunteer_id) REFERENCES volunteers(id)
        );

        CREATE TABLE IF NOT EXISTS otp_tokens (
            id         TEXT PRIMARY KEY,
            phone      TEXT NOT NULL,
            code       TEXT NOT NULL,
            type       TEXT NOT NULL DEFAULT 'volunteer',
            expires_at TEXT NOT NULL,
            used       INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reminder_log (
            id       TEXT PRIMARY KEY,
            slot_id  TEXT NOT NULL,
            sent_to  TEXT NOT NULL,
            sent_at  TEXT NOT NULL,
            UNIQUE(slot_id, sent_to)
        );

        CREATE TABLE IF NOT EXISTS food_request_events (
            id          TEXT PRIMARY KEY,
            request_id  TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            actor       TEXT NOT NULL DEFAULT 'system',
            payload     TEXT NOT NULL DEFAULT '{}',
            created_at  TEXT NOT NULL,
            FOREIGN KEY (request_id) REFERENCES food_requests(id)
        );
    ''')

    # ── Migration #19: backfill synthetic events for existing orders ──────────
    existing_events = conn.execute("SELECT COUNT(*) FROM food_request_events").fetchone()[0]
    if existing_events == 0:
        log.info('Migration #19: backfilling food_request_events for existing orders...')
        import json as _json
        backfill_rows = conn.execute(
            '''SELECT id, status, confirmed_at, updated_at, submitted_at FROM food_requests'''
        ).fetchall()
        _bf_count = 0
        for _r in backfill_rows:
            _etype = None
            _ts    = None
            if _r['status'] in ('confirmed', 'auto_confirmed'):
                _etype = 'confirmed'
                _ts    = _r['confirmed_at'] or _r['submitted_at'] or datetime.utcnow().isoformat()
            elif _r['status'] == 'submitted':
                _etype = 'confirmed'
                _ts    = _r['submitted_at'] or datetime.utcnow().isoformat()
            elif _r['status'] == 'skipped':
                _etype = 'auto_skipped'
                _ts    = _r['updated_at'] or _r['submitted_at'] or datetime.utcnow().isoformat()
            elif _r['status'] == 'cancelled':
                _etype = 'cancelled'
                _ts    = _r['updated_at'] or _r['submitted_at'] or datetime.utcnow().isoformat()
            elif _r['status'] == 'delivered':
                _etype = 'confirmed'
                _ts    = _r['confirmed_at'] or _r['submitted_at'] or datetime.utcnow().isoformat()
            if _etype:
                conn.execute(
                    "INSERT OR IGNORE INTO food_request_events (id, request_id, event_type, actor, payload, created_at) VALUES (?,?,?,?,?,?)",
                    (str(uuid.uuid4()), _r['id'], _etype, 'system',
                     _json.dumps({'note': 'backfilled'}), _ts)
                )
                _bf_count += 1
        conn.commit()
        log.info(f'Migration #19: backfilled {_bf_count} events for existing orders')

    # ── Seed default task types (idempotent) ─────────────────────────────────
    for _slug, _label, _order in [('shopping', 'Shop', 1), ('delivery', 'Delivery', 2), ('stock', 'Stock', 3)]:
        conn.execute(
            "INSERT OR IGNORE INTO volunteer_task_types (slug, label, display_order, is_active) VALUES (?,?,?,1)",
            (_slug, _label, _order)
        )

    # ── Migration: add is_family_slot to volunteer_task_types ─────────────────
    try:
        conn.execute('ALTER TABLE volunteer_task_types ADD COLUMN is_family_slot INTEGER NOT NULL DEFAULT 0')
        log.info('Migration: added volunteer_task_types.is_family_slot')
    except Exception:
        pass
    # Backfill: shopping + delivery are family-specific; stock is not
    conn.execute("UPDATE volunteer_task_types SET is_family_slot=1 WHERE slug IN ('shopping','delivery')")
    conn.execute("UPDATE volunteer_task_types SET is_family_slot=0 WHERE slug='stock'")

    # ── Migration: rebuild volunteer_slots — remove UNIQUE + CHECK constraints ─
    _vs_ddl = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='volunteer_slots'"
    ).fetchone()
    if _vs_ddl and (
        "UNIQUE(cycle_id, family_id, task_type)" in (_vs_ddl[0] or "") or
        "CHECK(task_type IN" in (_vs_ddl[0] or "")
    ):
        log.info('Migration: rebuilding volunteer_slots — removing UNIQUE + CHECK constraints')
        try:
            conn.execute('PRAGMA foreign_keys=OFF')
            conn.executescript('''
                ALTER TABLE volunteer_slots RENAME TO _vs_backup;
                CREATE TABLE volunteer_slots (
                    id           TEXT PRIMARY KEY,
                    cycle_id     TEXT NOT NULL,
                    family_id    TEXT NOT NULL,
                    task_type    TEXT NOT NULL,
                    task_date    TEXT,
                    claimed_by   TEXT,
                    claimed_at   TEXT,
                    completed_at TEXT,
                    status       TEXT NOT NULL DEFAULT 'claimed'
                                 CHECK(status IN ('open','claimed','complete','cancelled')),
                    notes        TEXT,
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT,
                    FOREIGN KEY (cycle_id)   REFERENCES delivery_cycles(id),
                    FOREIGN KEY (family_id)  REFERENCES families(id),
                    FOREIGN KEY (claimed_by) REFERENCES volunteers(id)
                );
                INSERT INTO volunteer_slots SELECT * FROM _vs_backup;
                DROP TABLE _vs_backup;
            ''')
            conn.execute('PRAGMA foreign_keys=ON')
            log.info('Migration: volunteer_slots rebuilt — multi-volunteer per task now supported')
        except Exception as _e:
            conn.execute('PRAGMA foreign_keys=ON')
            log.info(f'Migration: volunteer_slots rebuild skipped ({_e})')

    # ── Migration: add prev_claimed_by to volunteer_slots ────────────────────────
    try:
        conn.execute('ALTER TABLE volunteer_slots ADD COLUMN prev_claimed_by TEXT')
        log.info('Migration: added volunteer_slots.prev_claimed_by')
    except Exception:
        pass

    # ── Migration: volunteer_slots — expand status CHECK to include 'confirmed' ─
    _vs_ddl2 = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='volunteer_slots'"
    ).fetchone()
    if _vs_ddl2 and "CHECK(status IN ('open','claimed','complete','cancelled'))" in (_vs_ddl2[0] or ''):
        log.info("Migration: rebuilding volunteer_slots — adding 'confirmed' status")
        try:
            conn.execute('PRAGMA foreign_keys=OFF')
            conn.executescript('''
                ALTER TABLE volunteer_slots RENAME TO _vs_backup2;
                CREATE TABLE volunteer_slots (
                    id              TEXT PRIMARY KEY,
                    cycle_id        TEXT NOT NULL,
                    family_id       TEXT NOT NULL,
                    task_type       TEXT NOT NULL,
                    task_date       TEXT,
                    claimed_by      TEXT,
                    claimed_at      TEXT,
                    completed_at    TEXT,
                    status          TEXT NOT NULL DEFAULT 'open',
                    notes           TEXT,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT,
                    prev_claimed_by TEXT,
                    FOREIGN KEY (cycle_id)   REFERENCES delivery_cycles(id),
                    FOREIGN KEY (family_id)  REFERENCES families(id),
                    FOREIGN KEY (claimed_by) REFERENCES volunteers(id)
                );
                INSERT INTO volunteer_slots
                    SELECT id, cycle_id, family_id, task_type, task_date,
                           claimed_by, claimed_at, completed_at, status, notes,
                           created_at, updated_at, prev_claimed_by
                    FROM _vs_backup2;
                DROP TABLE _vs_backup2;
            ''')
            conn.execute('PRAGMA foreign_keys=ON')
            log.info("Migration: volunteer_slots rebuilt — 'confirmed' status now supported")
        except Exception as _e:
            conn.execute('PRAGMA foreign_keys=ON')
            log.info(f'Migration: volunteer_slots confirm-rebuild skipped ({_e})')

    # ── order_change_requests table ──────────────────────────────────────────────
    conn.execute('''
        CREATE TABLE IF NOT EXISTS order_change_requests (
            id           TEXT PRIMARY KEY,
            family_id    TEXT NOT NULL,
            cycle_id     TEXT NOT NULL,
            request_id   TEXT,
            status       TEXT NOT NULL DEFAULT 'pending'
                         CHECK(status IN ('pending','approved','rejected','retracted')),
            family_notes TEXT,
            payload      TEXT NOT NULL DEFAULT '{}',
            admin_notes  TEXT,
            reviewed_by  TEXT,
            created_at   TEXT NOT NULL,
            reviewed_at  TEXT,
            FOREIGN KEY (family_id) REFERENCES families(id),
            FOREIGN KEY (cycle_id)  REFERENCES delivery_cycles(id)
        )
    ''')

    conn.commit()
    conn.close()
    final_size_kb = os.path.getsize(abs_db) / 1024
    log.info(f'Database bootstrapped. Size: {final_size_kb:.1f} KB  Path: {abs_db}')

# ── Auth Helpers ──────────────────────────────────────────────────────────────

def get_session(token):
    return get_db().execute(
        '''SELECT s.token, s.expires_at, u.id as user_id, u.username,
                  u.name, u.role, u.active
           FROM sessions s JOIN users u ON s.user_id = u.id
           WHERE s.token=? AND s.expires_at > ?''',
        (token, now())
    ).fetchone()

def require_auth(roles=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            # Also accept ?token= query param (used for direct PDF/file links)
            if not auth.startswith('Bearer ') and request.args.get('token'):
                auth = 'Bearer ' + request.args.get('token')
            if not auth.startswith('Bearer '):
                return jsonify({'error': 'Unauthorized'}), 401
            token = auth[7:]
            session = get_session(token)
            if not session:
                return jsonify({'error': 'Session expired or invalid'}), 401
            if not session['active']:
                return jsonify({'error': 'Account inactive'}), 401
            if roles and session['role'] not in roles:
                return jsonify({'error': 'Forbidden'}), 403
            # Slide expiry
            new_expiry = (datetime.utcnow() + timedelta(hours=SESSION_HOURS)).isoformat()
            get_db().execute("UPDATE sessions SET expires_at=? WHERE token=?", (new_expiry, token))
            get_db().commit()
            g.user = dict(session)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# ── Portal Auth (volunteer self-service, phone-based) ─────────────────────────

def get_portal_session(token):
    return get_db().execute(
        '''SELECT ps.token, ps.volunteer_id, v.name, v.phone, v.role,
                  v.wa_phone, v.wa_apikey
           FROM portal_sessions ps JOIN volunteers v ON ps.volunteer_id = v.id
           WHERE ps.token=? AND ps.expires_at > ?''',
        (token, now())
    ).fetchone()

def require_portal_auth():
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get('Authorization', '')
            if not auth.startswith('Bearer '):
                return jsonify({'error': 'Unauthorized'}), 401
            session = get_portal_session(auth[7:])
            if not session:
                return jsonify({'error': 'Session expired — please log in again'}), 401
            g.pv = dict(session)  # portal volunteer
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ── Schema migration helper ───────────────────────────────────────────────────

VALID_ROLES = {'admin', 'volunteer', 'finance', 'treasurer', 'viewer'}

def _ensure_treasurer_role(conn):
    """Patch the users table CHECK constraint to include 'treasurer'.
    Uses PRAGMA writable_schema to update sqlite_master directly — no exclusive
    lock needed, safe with concurrent gunicorn workers in WAL mode."""
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()
    if not row or 'treasurer' in row[0]:
        return  # already migrated or table doesn't exist

    log.info('_ensure_treasurer_role: patching CHECK constraint via writable_schema')
    old_sql = row[0]
    # Replace the old CHECK list with one that includes treasurer
    old_check = "'admin','volunteer','finance','viewer'"
    new_check = "'admin','volunteer','finance','treasurer','viewer'"
    if old_check in old_sql:
        new_sql = old_sql.replace(old_check, new_check)
    else:
        # Fallback: try without spaces variant
        old_check2 = "'admin', 'volunteer', 'finance', 'viewer'"
        new_check2 = "'admin', 'volunteer', 'finance', 'treasurer', 'viewer'"
        if old_check2 in old_sql:
            new_sql = old_sql.replace(old_check2, new_check2)
        else:
            log.warning(f'_ensure_treasurer_role: unrecognised CHECK format, falling back to table recreation\nSQL: {old_sql}')
            _recreate_users_table(conn)
            return

    try:
        conn.execute('PRAGMA writable_schema = ON')
        conn.execute(
            "UPDATE sqlite_master SET sql=? WHERE type='table' AND name='users'",
            (new_sql,)
        )
        # Bump schema_version so all connections reparse the schema
        ver = conn.execute('PRAGMA schema_version').fetchone()[0]
        conn.execute(f'PRAGMA schema_version = {ver + 1}')
        conn.execute('PRAGMA writable_schema = OFF')
        conn.commit()
        log.info('_ensure_treasurer_role: CHECK constraint patched successfully')
    except Exception as _e:
        conn.execute('PRAGMA writable_schema = OFF')
        log.warning(f'_ensure_treasurer_role: writable_schema patch failed ({_e}), trying table recreation')
        _recreate_users_table(conn)


def _recreate_users_table(conn):
    """Full table-recreation migration as fallback. Requires an exclusive DB lock."""
    try:
        conn.execute('PRAGMA foreign_keys=OFF')
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users_new (
                id            TEXT PRIMARY KEY,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                name          TEXT,
                role          TEXT NOT NULL DEFAULT 'viewer'
                              CHECK(role IN ('admin','volunteer','finance','treasurer','viewer')),
                email         TEXT,
                wa_phone      TEXT,
                wa_apikey     TEXT,
                active        INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT NOT NULL
            );
            INSERT OR IGNORE INTO users_new
                (id, username, password_hash, name, role, email, wa_phone, wa_apikey, active, created_at)
            SELECT id, username, password_hash, name, role, email, wa_phone, wa_apikey, active, created_at
            FROM users;
            DROP TABLE IF EXISTS users;
            ALTER TABLE users_new RENAME TO users;
        ''')
        conn.execute('PRAGMA foreign_keys=ON')
        log.info('_recreate_users_table: migration complete')
    except Exception as _e:
        conn.execute('PRAGMA foreign_keys=ON')
        log.warning(f'_recreate_users_table: failed ({_e})')

# ── WhatsApp (CallMeBot) ──────────────────────────────────────────────────────

def _wa_send(phone, apikey, message):
    """Send a WhatsApp message via CallMeBot. Free, no Twilio needed.
    Volunteer opt-in: ask them to WhatsApp +1 (206) 337-5002 → they receive their apikey.
    Returns True on success, False on failure (never raises).
    No-ops silently when WA_ENABLED=0."""
    if not WA_ENABLED:
        log.info(f'WA disabled — skipping send to {phone}')
        return True
    import urllib.request, urllib.parse
    try:
        url = ('https://api.callmebot.com/whatsapp.php?'
               + urllib.parse.urlencode({'phone': phone, 'text': message, 'apikey': apikey}))
        urllib.request.urlopen(url, timeout=10)
        log.info(f'WhatsApp sent to {phone}')
        return True
    except Exception as e:
        log.warning(f'WhatsApp send failed to {phone}: {e}')
        return False


def _wa_send_async(sends):
    """Fire a list of WA messages in a background thread so the caller returns immediately.
    sends: list of (phone, apikey, message) tuples — items with missing phone/apikey are skipped.
    No-ops silently when WA_ENABLED=0."""
    if not WA_ENABLED:
        return
    import threading as _t
    items = [(p, k, m) for p, k, m in sends if p and k]
    if not items:
        return
    def _run():
        for phone, apikey, msg in items:
            _wa_send(phone, apikey, msg)
    _t.Thread(target=_run, daemon=True).start()

def _send_sms(phone_digits, message):
    """Send an SMS via Twilio. phone_digits = 10-digit US number (no country code).
    Returns True on success, False on failure. Never raises.
    No-ops if TWILIO env vars are not set."""
    if not SMS_ENABLED:
        log.warning(f'SMS not configured — skipping send to {phone_digits}. '
                    'Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM in Railway.')
        return False
    try:
        from twilio.rest import Client
        to = '+1' + phone_digits if not phone_digits.startswith('+') else phone_digits
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(body=message, from_=TWILIO_FROM, to=to)
        log.info(f'SMS sent to {phone_digits}')
        return True
    except Exception as e:
        log.warning(f'SMS send failed to {phone_digits}: {e}')
        return False


def _today_central():
    """Return today's date in US Central time (America/Chicago).
    Uses zoneinfo (Python 3.9+, always available on Railway).
    Falls back to UTC if zoneinfo is unavailable."""
    try:
        from zoneinfo import ZoneInfo
        from datetime import datetime as _dt
        return _dt.now(ZoneInfo('America/Chicago')).date()
    except Exception:
        from datetime import date as _d
        return _d.today()

def _log_order_event(db, request_id, event_type, actor='system', payload=None):
    """Append an event to food_request_events. Never raises — failures are logged only.
    event_type: confirmed | items_edited | cancelled | admin_override | auto_skipped
    actor:      family | admin | scheduler | system
    payload:    dict — e.g. {'removed': ['Whole Chicken'], 'added': ['Brown Lentils']}
    """
    import json as _json
    try:
        db.execute(
            "INSERT INTO food_request_events (id, request_id, event_type, actor, payload, created_at) VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), request_id, event_type, actor,
             _json.dumps(payload or {}), now())
        )
    except Exception as _e:
        log.warning(f'_log_order_event failed ({event_type} on {request_id}): {_e}')

def _notify_coordinators(db, message):
    """Send WA to all active admin users — fires in background thread (non-blocking)."""
    try:
        admins = db.execute(
            "SELECT wa_phone, wa_apikey FROM users WHERE role='admin' AND active=1 AND wa_phone IS NOT NULL AND wa_apikey IS NOT NULL"
        ).fetchall()
        sends = [(a['wa_phone'], a['wa_apikey'], message) for a in admins]
        _wa_send_async(sends)
    except Exception as _e:
        log.warning(f'_notify_coordinators failed: {_e}')

def _email_send(to_email, subject, text_body):
    """Send an email via SendGrid Web API v3 (no SDK — pure urllib).
    Requires SENDGRID_API_KEY env var. Falls back silently if not configured.
    Returns True on success, False on failure (never raises)."""
    import urllib.request, urllib.parse, json as _json
    if not SENDGRID_API_KEY:
        log.warning('Email not sent — SENDGRID_API_KEY not configured')
        return False
    payload = _json.dumps({
        'personalizations': [{'to': [{'email': to_email}]}],
        'from': {'email': NOTIFY_FROM_EMAIL, 'name': 'SIHAA Ops Hub'},
        'subject': subject,
        'content': [{'type': 'text/plain', 'value': text_body}]
    }).encode('utf-8')
    req = urllib.request.Request(
        'https://api.sendgrid.com/v3/mail/send',
        data=payload,
        headers={
            'Authorization': f'Bearer {SENDGRID_API_KEY}',
            'Content-Type': 'application/json'
        },
        method='POST'
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        log.info(f'Email sent to {to_email}: {subject}')
        return True
    except Exception as e:
        log.warning(f'Email send failed to {to_email}: {e}')
        return False

def _notify_treasurers(db, subject, message):
    """Notify all active treasurer users via WhatsApp + email.
    Used for new reimbursement requests, receipt submissions, etc."""
    treasurers = db.execute(
        "SELECT name, email, wa_phone, wa_apikey FROM users WHERE role='treasurer' AND active=1"
    ).fetchall()
    for t in treasurers:
        if t['wa_phone'] and t['wa_apikey']:
            _wa_send(t['wa_phone'], t['wa_apikey'], message)
        if t['email']:
            _email_send(t['email'], subject, message)
    if not treasurers:
        log.info('No active treasurers found to notify.')

# ── Health ────────────────────────────────────────────────────────────────────

@app.route('/api/health')
def health():
    return jsonify({'status': 'ok', 'version': '1.0.0', 'time': now()})

# ── Auth Routes ───────────────────────────────────────────────────────────────

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username=? AND active=1", (username,)
    ).fetchone()
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(hours=SESSION_HOURS)).isoformat()
    db.execute(
        "INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?,?,?,?)",
        (token, user['id'], expires_at, now())
    )
    db.commit()
    log.info(f'Login: {username} ({user["role"]})')
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'], 'username': user['username'],
            'name': user['name'], 'role': user['role']
        }
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        db = get_db()
        db.execute("DELETE FROM sessions WHERE token=?", (auth[7:],))
        db.commit()
    return jsonify({'ok': True})

@app.route('/api/auth/me')
def me():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    session = get_session(auth[7:])
    if not session:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({
        'id': session['user_id'], 'username': session['username'],
        'name': session['name'], 'role': session['role']
    })

# ── Users (Admin only) ────────────────────────────────────────────────────────

@app.route('/api/users', methods=['GET'])
@require_auth(roles=['admin'])
def list_users():
    rows = get_db().execute(
        "SELECT id, username, name, role, email, wa_phone, wa_apikey, active, created_at FROM users ORDER BY created_at"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/users', methods=['POST'])
@require_auth(roles=['admin'])
def create_user():
    data = request.json or {}
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 422
    new_role = data.get('role', 'viewer')
    if new_role not in VALID_ROLES:
        return jsonify({'error': f'Invalid role "{new_role}"'}), 400
    uid = str(uuid.uuid4())
    db = get_db()
    try:
        db.execute(
            '''INSERT INTO users (id, username, password_hash, name, role, email, wa_phone, wa_apikey, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)''',
            (uid, data['username'], generate_password_hash(data['password']),
             data.get('name'), new_role,
             data.get('email'), data.get('wa_phone'), data.get('wa_apikey'), now())
        )
        db.commit()
    except sqlite3.IntegrityError as e:
        if 'CHECK constraint' in str(e):
            _ensure_treasurer_role(db)
            db.execute(
                '''INSERT INTO users (id, username, password_hash, name, role, email, wa_phone, wa_apikey, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (uid, data['username'], generate_password_hash(data['password']),
                 data.get('name'), new_role,
                 data.get('email'), data.get('wa_phone'), data.get('wa_apikey'), now())
            )
            db.commit()
        else:
            return jsonify({'error': 'Username already exists'}), 409
    return jsonify({'id': uid, 'username': data['username']}), 201

@app.route('/api/users/<uid>', methods=['PUT'])
@require_auth(roles=['admin'])
def update_user(uid):
    data = request.json or {}
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    new_role = data.get('role', row['role'])
    if new_role not in VALID_ROLES:
        return jsonify({'error': f'Invalid role "{new_role}". Must be one of: {", ".join(sorted(VALID_ROLES))}'}), 400
    new_hash = generate_password_hash(data['password']) if data.get('password') else row['password_hash']
    params = (
        data.get('name', row['name']), new_role,
        data.get('active', row['active']), new_hash,
        data.get('email', row['email']), data.get('wa_phone', row['wa_phone']),
        data.get('wa_apikey', row['wa_apikey']), uid
    )
    try:
        db.execute(
            "UPDATE users SET name=?, role=?, active=?, password_hash=?, email=?, wa_phone=?, wa_apikey=? WHERE id=?",
            params
        )
        db.commit()
    except sqlite3.IntegrityError as e:
        if 'CHECK constraint' in str(e):
            # Schema migration didn't complete — patch it now and retry
            _ensure_treasurer_role(db)
            try:
                db.execute(
                    "UPDATE users SET name=?, role=?, active=?, password_hash=?, email=?, wa_phone=?, wa_apikey=? WHERE id=?",
                    params
                )
                db.commit()
            except Exception as retry_e:
                return jsonify({'error': f'Role update failed after schema fix attempt: {retry_e}'}), 500
        else:
            return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'ok': True})


@app.route('/api/admin/fix-schema', methods=['POST'])
@require_auth(roles=['admin'])
def fix_schema():
    """Manual schema repair endpoint — call if role migrations fail at startup."""
    db = get_db()
    before = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
    _ensure_treasurer_role(db)
    after = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
    had_treasurer_before = before and 'treasurer' in before[0]
    has_treasurer_after  = after  and 'treasurer' in after[0]
    return jsonify({
        'had_treasurer_before': had_treasurer_before,
        'has_treasurer_after':  has_treasurer_after,
        'fixed': not had_treasurer_before and has_treasurer_after,
    })

# ── Public Donate Stats (no auth — safe aggregate data only) ─────────────────

@app.route('/api/donate-stats')
def public_donate_stats():
    """Public endpoint: aggregate donation data for the Wix embed."""
    db = get_db()
    this_month = datetime.utcnow().strftime('%Y-%m')

    # Monthly totals — last 8 months for chart
    monthly_rows = db.execute("""
        SELECT substr(date,1,7) AS month,
               COALESCE(SUM(amount),0) AS total,
               COUNT(*) AS count,
               COUNT(DISTINCT donor_name) AS donors
        FROM donations
        WHERE date >= date('now','-8 months') AND amount > 0
        GROUP BY month
        ORDER BY month ASC
    """).fetchall()
    monthly = [dict(r) for r in monthly_rows]

    # Projection: 3-month run rate + trend
    proj_rows = db.execute("""
        SELECT substr(date,1,7) AS month,
               COUNT(DISTINCT donor_name) AS donors,
               COALESCE(SUM(amount),0) AS total
        FROM donations
        WHERE date >= date('now','-3 months') AND amount > 0
        GROUP BY month ORDER BY month ASC
    """).fetchall()
    proj_rows = [dict(r) for r in proj_rows]

    if proj_rows:
        totals         = [r['total']  for r in proj_rows]
        donor_counts   = [r['donors'] for r in proj_rows]
        avg_monthly    = sum(totals) / len(totals)
        total_donors   = sum(donor_counts)
        total_revenue  = sum(totals)
        avg_gift       = round(total_revenue / total_donors, 2) if total_donors else 0
        avg_donors     = round(sum(donor_counts) / len(donor_counts), 1)
        deltas         = [totals[i] - totals[i-1] for i in range(1, len(totals))]
        monthly_trend  = round(sum(deltas) / len(deltas), 2) if deltas else 0
    else:
        avg_monthly = avg_gift = avg_donors = monthly_trend = 0

    # High-level totals
    total_raised  = db.execute("SELECT COALESCE(SUM(amount),0) FROM donations").fetchone()[0]
    month_raised  = db.execute(
        "SELECT COALESCE(SUM(amount),0) FROM donations WHERE date LIKE ?",
        (f'{this_month}%',)
    ).fetchone()[0]
    families_active = db.execute(
        "SELECT COUNT(*) FROM families WHERE status='active'"
    ).fetchone()[0]
    lives_impacted = db.execute(
        "SELECT COALESCE(SUM(family_size), COUNT(*)) FROM families WHERE status='active'"
    ).fetchone()[0]
    volunteers_active = db.execute(
        "SELECT COUNT(*) FROM volunteers WHERE status='active'"
    ).fetchone()[0]

    return jsonify({
        'donations_by_month':        monthly,
        'proj_avg_donors_per_month': avg_donors,
        'proj_avg_gift':             avg_gift,
        'proj_avg_monthly':          round(avg_monthly, 2),
        'proj_monthly_trend':        monthly_trend,
        'total_raised':              total_raised,
        'month_raised':              month_raised,
        'families_active':           families_active,
        'lives_impacted':            lives_impacted,
        'volunteers_active':         volunteers_active,
    })

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/api/dashboard/stats')
@require_auth()
def dashboard_stats():
    db = get_db()
    this_month = datetime.utcnow().strftime('%Y-%m')

    stats = {
        # Families
        'families_total':    db.execute("SELECT COUNT(*) FROM families").fetchone()[0],
        'families_active':   db.execute("SELECT COUNT(*) FROM families WHERE status='active'").fetchone()[0],
        'families_pending':  db.execute("SELECT COUNT(*) FROM families WHERE status='pending'").fetchone()[0],
        'families_no_wa':    db.execute(
            "SELECT COUNT(*) FROM families WHERE status='active' AND (wa_phone IS NULL OR TRIM(wa_phone)='' OR wa_apikey IS NULL OR TRIM(wa_apikey)='')"
        ).fetchone()[0],
        # Volunteers
        'volunteers_total':  db.execute("SELECT COUNT(*) FROM volunteers").fetchone()[0],
        'volunteers_active': db.execute("SELECT COUNT(*) FROM volunteers WHERE status='active'").fetchone()[0],
        'volunteers_pending':db.execute("SELECT COUNT(*) FROM volunteers WHERE status='pending'").fetchone()[0],
        'volunteers_no_wa':  db.execute(
            "SELECT COUNT(*) FROM volunteers WHERE status='active' AND (wa_phone IS NULL OR TRIM(wa_phone)='' OR wa_apikey IS NULL OR TRIM(wa_apikey)='')"
        ).fetchone()[0],
        # Receipts
        'receipts_pending':  db.execute("SELECT COUNT(*) FROM receipts WHERE status='pending'").fetchone()[0],
        # Reimbursements
        'reimb_pending_count': db.execute(
            "SELECT COUNT(*) FROM reimbursements WHERE status='pending'"
        ).fetchone()[0],
        'reimb_pending_amount': db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM reimbursements WHERE status='pending'"
        ).fetchone()[0],
        'reimb_paid_month': db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM reimbursements WHERE status='paid' AND paid_date LIKE ?",
            (f'{this_month}%',)
        ).fetchone()[0],
        'reimb_paid_total': db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM reimbursements WHERE status='paid'"
        ).fetchone()[0],
        # Spend (paid reimbursements = actual money out to volunteers)
        'spend_this_month':  db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM reimbursements WHERE status='paid' AND paid_date LIKE ?",
            (f'{this_month}%',)
        ).fetchone()[0],
        'spend_total':       db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM reimbursements WHERE status='paid'"
        ).fetchone()[0],
        # Donations
        'donations_month':   db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM donations WHERE date LIKE ?",
            (f'{this_month}%',)
        ).fetchone()[0],
        'donations_total':   db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM donations"
        ).fetchone()[0],
        'donations_count':   db.execute("SELECT COUNT(*) FROM donations").fetchone()[0],
        'donations_recurring_month': db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM donations WHERE date LIKE ? AND frequency='monthly'",
            (f'{this_month}%',)
        ).fetchone()[0],
        # Change requests
        'pending_change_requests': db.execute(
            "SELECT COUNT(*) FROM order_change_requests WHERE status='pending'"
        ).fetchone()[0],
    }

    # Monthly donations — last 6 months for trend chart
    monthly_rows = db.execute("""
        SELECT substr(date,1,7) AS month,
               COALESCE(SUM(amount),0) AS total,
               COUNT(*) AS count,
               COALESCE(SUM(CASE WHEN frequency='monthly' THEN amount ELSE 0 END),0) AS recurring,
               COALESCE(SUM(CASE WHEN frequency<>'monthly' OR frequency IS NULL THEN amount ELSE 0 END),0) AS one_time,
               COUNT(DISTINCT CASE WHEN frequency='monthly' THEN donor_name END) AS recurring_donors
        FROM donations
        WHERE date >= date('now','-6 months')
        GROUP BY month
        ORDER BY month ASC
    """).fetchall()
    stats['donations_by_month'] = [dict(r) for r in monthly_rows]

    # Projection stats: last 3 months run rate + trend slope
    proj_rows = db.execute("""
        SELECT substr(date,1,7)           AS month,
               COUNT(DISTINCT donor_name) AS donors,
               COALESCE(SUM(amount),0)    AS total
        FROM donations
        WHERE date >= date('now','-3 months')
          AND amount > 0
        GROUP BY month
        ORDER BY month ASC
    """).fetchall()
    proj_rows = [dict(r) for r in proj_rows]

    if proj_rows:
        totals         = [r['total']  for r in proj_rows]
        donor_counts   = [r['donors'] for r in proj_rows]
        avg_monthly    = sum(totals) / len(totals)
        total_donors   = sum(donor_counts)
        total_revenue  = sum(totals)
        avg_gift_3mo   = round(total_revenue / total_donors, 2) if total_donors else 0
        avg_donors_3mo = round(sum(donor_counts) / len(donor_counts), 1)
        # Monthly trend: average change month-over-month (positive = growing)
        deltas = [totals[i] - totals[i-1] for i in range(1, len(totals))]
        monthly_trend  = round(sum(deltas) / len(deltas), 2) if deltas else 0
    else:
        avg_monthly    = 0
        avg_gift_3mo   = 0
        avg_donors_3mo = 0
        monthly_trend  = 0

    stats['proj_avg_donors_per_month'] = avg_donors_3mo
    stats['proj_avg_gift']             = avg_gift_3mo
    stats['proj_avg_monthly']          = round(avg_monthly, 2)
    stats['proj_monthly_trend']        = monthly_trend  # $ change per month

    # Active cycle stats
    active_cycle = db.execute(
        "SELECT id, title, status FROM delivery_cycles WHERE status IN ('upcoming','shopping') ORDER BY delivery_date_start LIMIT 1"
    ).fetchone()
    if active_cycle:
        cid = active_cycle['id']
        stats['cycle_id']      = cid
        stats['cycle_title']   = active_cycle['title']
        stats['cycle_status']  = active_cycle['status']
        stats['orders_this_cycle'] = db.execute(
            "SELECT COUNT(*) FROM food_requests WHERE cycle_id=?", (cid,)
        ).fetchone()[0]
        stats['slots_open']    = db.execute(
            "SELECT COUNT(*) FROM volunteer_slots WHERE cycle_id=? AND status='open'", (cid,)
        ).fetchone()[0]
        stats['slots_claimed'] = db.execute(
            "SELECT COUNT(*) FROM volunteer_slots WHERE cycle_id=? AND status='claimed'", (cid,)
        ).fetchone()[0]
        stats['slots_complete']= db.execute(
            "SELECT COUNT(*) FROM volunteer_slots WHERE cycle_id=? AND status='complete'", (cid,)
        ).fetchone()[0]
    else:
        stats.update({'cycle_id': None, 'cycle_title': None, 'cycle_status': None,
                      'orders_this_cycle': 0, 'slots_open': 0, 'slots_claimed': 0, 'slots_complete': 0})

    return jsonify(stats)

# ── Families ──────────────────────────────────────────────────────────────────

@app.route('/api/families', methods=['GET'])
@require_auth()
def list_families():
    db = get_db()
    status = request.args.get('status')
    search = (request.args.get('search') or '').strip()
    q = """
        SELECT f.*,
               (SELECT v.name
                FROM volunteer_slots vs
                JOIN volunteers v ON vs.claimed_by = v.id
                WHERE vs.family_id = f.id
                  AND vs.task_type = 'delivery'
                  AND vs.claimed_by IS NOT NULL
                ORDER BY vs.created_at DESC
                LIMIT 1) AS last_delivery_volunteer,
               (SELECT v.name
                FROM volunteer_slots vs
                JOIN volunteers v ON vs.claimed_by = v.id
                WHERE vs.family_id = f.id
                  AND vs.task_type = 'shopping'
                  AND vs.claimed_by IS NOT NULL
                ORDER BY vs.created_at DESC
                LIMIT 1) AS last_shopping_volunteer,
               (SELECT dc.delivery_date_start
                FROM volunteer_slots vs
                JOIN delivery_cycles dc ON vs.cycle_id = dc.id
                WHERE vs.family_id = f.id
                  AND vs.task_type = 'delivery'
                  AND vs.claimed_by IS NOT NULL
                ORDER BY vs.created_at DESC
                LIMIT 1) AS last_delivery_date,
               (SELECT dc.delivery_date_start
                FROM volunteer_slots vs
                JOIN delivery_cycles dc ON vs.cycle_id = dc.id
                WHERE vs.family_id = f.id
                  AND vs.task_type = 'shopping'
                  AND vs.claimed_by IS NOT NULL
                ORDER BY vs.created_at DESC
                LIMIT 1) AS last_shopping_date
        FROM families f
        WHERE 1=1"""
    params = []
    if status == 'needs_wa':
        q += " AND f.status='active' AND (f.wa_phone IS NULL OR TRIM(f.wa_phone)='' OR f.wa_apikey IS NULL OR TRIM(f.wa_apikey)='')"
    elif status:
        q += " AND f.status=?"; params.append(status)
    if search:
        q += " AND (f.name LIKE ? OR f.phone LIKE ? OR f.address LIKE ?)"; params += [f'%{search}%']*3
    q += " ORDER BY f.created_at DESC"
    return jsonify([dict(r) for r in db.execute(q, params).fetchall()])

@app.route('/api/families', methods=['POST'])
@require_auth(roles=['admin', 'finance', 'treasurer'])
def create_family():
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'Name is required'}), 422
    phone = _normalize_phone(data.get('phone'))
    fid = str(uuid.uuid4())
    db = get_db()
    family_code = _make_family_code(phone, data.get('family_size'), db_conn=db)
    db.execute(
        '''INSERT INTO families
           (id,name,phone,address,city,family_size,children_count,
            dietary_notes,frequency,income_range,status,notes,source,family_code,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (fid, data['name'], phone, data.get('address'), data.get('city'),
         data.get('family_size'), data.get('children_count'), data.get('dietary_notes'),
         data.get('frequency'), data.get('income_range'),
         data.get('status', 'pending'), data.get('notes'), data.get('source', 'admin'),
         family_code, now())
    )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone())), 201

@app.route('/api/families/<fid>', methods=['GET'])
@require_auth()
def get_family(fid):
    row = get_db().execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()
    return (jsonify(dict(row)) if row else (jsonify({'error': 'Not found'}), 404))

@app.route('/api/families/<fid>', methods=['PUT'])
@require_auth(roles=['admin', 'finance', 'treasurer'])
def update_family(fid):
    db = get_db()
    row = db.execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    new_phone = _normalize_phone(d.get('phone', row['phone']))
    new_size  = d.get('family_size', row['family_size'])
    new_code  = _make_family_code(new_phone, new_size, db_conn=db, exclude_id=fid)
    prev_status = row['status']
    new_status  = d.get('status', row['status'])
    db.execute(
        '''UPDATE families SET name=?,phone=?,address=?,city=?,family_size=?,children_count=?,
           dietary_notes=?,frequency=?,income_range=?,status=?,bundle_size=?,notes=?,family_code=?,
           wa_phone=?,wa_apikey=?,updated_at=? WHERE id=?''',
        (d.get('name', row['name']), new_phone,
         d.get('address', row['address']), d.get('city', row['city']),
         new_size, d.get('children_count', row['children_count']),
         d.get('dietary_notes', row['dietary_notes']), d.get('frequency', row['frequency']),
         d.get('income_range', row['income_range']), new_status,
         d.get('bundle_size', row['bundle_size']),
         d.get('notes', row['notes']), new_code,
         d.get('wa_phone', row['wa_phone']), d.get('wa_apikey', row['wa_apikey']),
         now(), fid)
    )
    db.commit()
    # Pre-create volunteer slots when a family is activated for the first time
    if new_status == 'active' and prev_status != 'active':
        try:
            slots = _pre_create_slots_for_family(db, fid)
            db.commit()
            log.info(f'update_family: pre-created {slots} volunteer slots for newly active family {fid}')
        except Exception as _e:
            log.warning(f'update_family: slot pre-creation failed for family {fid}: {_e}')
    return jsonify(dict(db.execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()))

# ── Bundle size change request (family self-serve, coordinator must approve) ──

@app.route('/api/families/<fid>/request-bundle-change', methods=['POST'])
def request_bundle_change(fid):
    """Family portal: request a bundle size change. Stored as pending until coordinator approves."""
    data = request.json or {}
    new_size = (data.get('bundle_size') or '').upper().strip()
    if new_size not in ('S', 'M', 'L'):
        return jsonify({'error': 'Bundle size must be S, M, or L'}), 422
    db = get_db()
    family = db.execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()
    if not family:
        return jsonify({'error': 'Family not found'}), 404
    if family['bundle_size'] == new_size:
        return jsonify({'error': 'That is already your current bundle size'}), 409
    if family['pending_bundle_size'] == new_size:
        return jsonify({'ok': True, 'message': 'Your request is already pending coordinator approval.'}), 200
    db.execute(
        "UPDATE families SET pending_bundle_size=?, updated_at=? WHERE id=?",
        (new_size, now(), fid)
    )
    db.commit()
    # Notify coordinator
    coord = db.execute(
        "SELECT name, wa_phone, wa_apikey FROM users WHERE role='admin' AND active=1 AND wa_phone IS NOT NULL LIMIT 1"
    ).fetchone()
    if coord and coord['wa_phone'] and coord['wa_apikey']:
        sizes = {'S': 'Small', 'M': 'Medium', 'L': 'Large'}
        msg = (f"Bundle size change request:\n"
               f"Family: {family['name']} ({family['family_code']})\n"
               f"Current: {sizes.get(family['bundle_size'] or 'M', family['bundle_size'])}\n"
               f"Requested: {sizes.get(new_size, new_size)}\n"
               f"Please log in to approve or deny.")
        _wa_send(coord['wa_phone'], coord['wa_apikey'], msg)
    log.info(f'Bundle change request: family {fid} → {new_size}')
    return jsonify({'ok': True, 'message': 'Your request has been sent. The coordinator will review it and let you know.'}), 200


@app.route('/api/families/<fid>/approve-bundle-change', methods=['POST'])
@require_auth(roles=['admin'])
def approve_bundle_change(fid):
    """Admin: approve or deny a pending bundle size change request."""
    data = request.json or {}
    action = data.get('action')  # 'approve' or 'deny'
    if action not in ('approve', 'deny'):
        return jsonify({'error': 'action must be approve or deny'}), 422
    db = get_db()
    family = db.execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()
    if not family:
        return jsonify({'error': 'Not found'}), 404
    if not family['pending_bundle_size']:
        return jsonify({'error': 'No pending bundle size request for this family'}), 409
    if action == 'approve':
        db.execute(
            "UPDATE families SET bundle_size=?, pending_bundle_size=NULL, updated_at=? WHERE id=?",
            (family['pending_bundle_size'], now(), fid)
        )
        msg = f"Approved. Bundle size changed to {family['pending_bundle_size']}."
    else:
        db.execute(
            "UPDATE families SET pending_bundle_size=NULL, updated_at=? WHERE id=?",
            (now(), fid)
        )
        msg = "Bundle size change request denied. Current size kept."
    db.commit()
    log.info(f'Bundle change {action}: family {fid}')
    return jsonify({'ok': True, 'message': msg})


# ── Volunteers ────────────────────────────────────────────────────────────────

@app.route('/api/volunteers', methods=['GET'])
@require_auth()
def list_volunteers():
    db = get_db()
    status = request.args.get('status')
    search = (request.args.get('search') or '').strip()
    q = "SELECT * FROM volunteers WHERE 1=1"
    params = []
    if status == 'needs_wa':
        q += " AND status='active' AND (wa_phone IS NULL OR TRIM(wa_phone)='' OR wa_apikey IS NULL OR TRIM(wa_apikey)='')"
    elif status:
        q += " AND status=?"; params.append(status)
    if search:
        q += " AND (name LIKE ? OR phone LIKE ? OR email LIKE ?)"; params += [f'%{search}%']*3
    q += " ORDER BY created_at DESC"
    return jsonify([dict(r) for r in db.execute(q, params).fetchall()])

@app.route('/api/volunteers', methods=['POST'])
@require_auth(roles=['admin'])
def create_volunteer():
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'Name is required'}), 422
    vid = str(uuid.uuid4())
    get_db().execute(
        '''INSERT INTO volunteers
           (id,name,phone,email,role,availability,service_area,
            wa_phone,wa_apikey,status,notes,source,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (vid, data['name'], data.get('phone'), data.get('email'),
         data.get('role', 'shopper'), data.get('availability'), data.get('service_area'),
         data.get('wa_phone'), data.get('wa_apikey'),
         data.get('status', 'pending'), data.get('notes'), data.get('source', 'admin'), now())
    )
    get_db().commit()
    return jsonify(dict(get_db().execute("SELECT * FROM volunteers WHERE id=?", (vid,)).fetchone())), 201

@app.route('/api/volunteers/<vid>', methods=['GET'])
@require_auth()
def get_volunteer(vid):
    row = get_db().execute("SELECT * FROM volunteers WHERE id=?", (vid,)).fetchone()
    return (jsonify(dict(row)) if row else (jsonify({'error': 'Not found'}), 404))

@app.route('/api/volunteers/<vid>', methods=['PUT'])
@require_auth(roles=['admin'])
def update_volunteer(vid):
    db = get_db()
    row = db.execute("SELECT * FROM volunteers WHERE id=?", (vid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute(
        '''UPDATE volunteers SET name=?,phone=?,email=?,role=?,availability=?,
           service_area=?,wa_phone=?,wa_apikey=?,status=?,notes=?,updated_at=? WHERE id=?''',
        (d.get('name', row['name']), d.get('phone', row['phone']),
         d.get('email', row['email']), d.get('role', row['role']),
         d.get('availability', row['availability']), d.get('service_area', row['service_area']),
         d.get('wa_phone', row['wa_phone']), d.get('wa_apikey', row['wa_apikey']),
         d.get('status', row['status']), d.get('notes', row['notes']), now(), vid)
    )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM volunteers WHERE id=?", (vid,)).fetchone()))

# ── Assignments ───────────────────────────────────────────────────────────────

@app.route('/api/assignments', methods=['GET'])
@require_auth()
def list_assignments():
    db = get_db()
    status = request.args.get('status')
    q = '''SELECT a.*, f.name as family_name, v.name as volunteer_name
           FROM assignments a
           LEFT JOIN families f ON a.family_id = f.id
           LEFT JOIN volunteers v ON a.volunteer_id = v.id
           WHERE 1=1'''
    params = []
    if status:
        q += " AND a.status=?"; params.append(status)
    # Volunteers only see their own assignments
    if g.user.get('role') == 'volunteer':
        vol = db.execute("SELECT id FROM volunteers WHERE email=?",
                         (g.user.get('username'),)).fetchone()
        if vol:
            q += " AND a.volunteer_id=?"; params.append(vol['id'])
    q += " ORDER BY a.due_date ASC, a.created_at DESC"
    return jsonify([dict(r) for r in db.execute(q, params).fetchall()])

@app.route('/api/assignments', methods=['POST'])
@require_auth(roles=['admin'])
def create_assignment():
    data = request.json or {}
    if not data.get('family_id'):
        return jsonify({'error': 'family_id is required'}), 422
    aid = str(uuid.uuid4())
    get_db().execute(
        '''INSERT INTO assignments
           (id,family_id,volunteer_id,task_type,due_date,status,notes,created_by,created_at)
           VALUES (?,?,?,?,?,?,?,?,?)''',
        (aid, data['family_id'], data.get('volunteer_id'), data.get('task_type', 'shopping'),
         data.get('due_date'), data.get('status', 'pending'), data.get('notes'),
         g.user['user_id'], now())
    )
    get_db().commit()
    return jsonify({'id': aid}), 201

@app.route('/api/assignments/<aid>', methods=['PUT'])
@require_auth(roles=['admin', 'volunteer'])
def update_assignment(aid):
    db = get_db()
    row = db.execute("SELECT * FROM assignments WHERE id=?", (aid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute(
        '''UPDATE assignments SET volunteer_id=?,task_type=?,due_date=?,status=?,notes=?,updated_at=?
           WHERE id=?''',
        (d.get('volunteer_id', row['volunteer_id']), d.get('task_type', row['task_type']),
         d.get('due_date', row['due_date']), d.get('status', row['status']),
         d.get('notes', row['notes']), now(), aid)
    )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM assignments WHERE id=?", (aid,)).fetchone()))

# ── Receipts ──────────────────────────────────────────────────────────────────

@app.route('/api/receipts', methods=['GET'])
@require_auth()
def list_receipts():
    db = get_db()
    status = request.args.get('status')
    q = '''SELECT r.*, f.name as family_name, v.name as volunteer_name
           FROM receipts r
           LEFT JOIN families f ON r.family_id = f.id
           LEFT JOIN volunteers v ON r.volunteer_id = v.id
           WHERE 1=1'''
    params = []
    if status:
        q += " AND r.status=?"; params.append(status)
    q += " ORDER BY r.created_at DESC"
    return jsonify([dict(r) for r in db.execute(q, params).fetchall()])

@app.route('/api/receipts', methods=['POST'])
@require_auth(roles=['admin', 'volunteer'])
def create_receipt():
    data = request.json or {}
    rid = str(uuid.uuid4())
    db = get_db()
    db.execute(
        '''INSERT INTO receipts
           (id,assignment_id,volunteer_id,family_id,store,purchase_date,amount,file_url,slot_id,status,notes,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
        (rid, data.get('assignment_id'), data.get('volunteer_id'), data.get('family_id'),
         data.get('store'), data.get('purchase_date'), data.get('amount'),
         data.get('file_url'), data.get('slot_id'), 'pending', data.get('notes'), now())
    )
    db.commit()
    # Notify treasurers of new receipt submission
    try:
        vol = db.execute("SELECT name FROM volunteers WHERE id=?", (data.get('volunteer_id'),)).fetchone()
        vol_name = vol['name'] if vol else 'A volunteer'
        amount = data.get('amount') or 0
        store  = data.get('store') or 'unknown store'
        subject = f'New Reimbursement Request — ${amount:.2f} from {vol_name}'
        msg = (f'New receipt submitted on SIHAA Ops Hub.\n'
               f'Volunteer: {vol_name}\n'
               f'Store: {store}\n'
               f'Amount: ${amount:.2f}\n'
               f'Date: {data.get("purchase_date","")}\n\n'
               f'Log in to review and pay: https://sihha-ops-hub-production.up.railway.app')
        _notify_treasurers(db, subject, msg)
    except Exception as e:
        log.warning(f'Treasurer notification failed: {e}')
    return jsonify({'id': rid}), 201

@app.route('/api/receipts/<rid>', methods=['PUT'])
@require_auth(roles=['admin', 'finance', 'treasurer'])
def update_receipt(rid):
    db = get_db()
    row = db.execute("SELECT * FROM receipts WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute(
        "UPDATE receipts SET status=?,notes=?,updated_at=? WHERE id=?",
        (d.get('status', row['status']), d.get('notes', row['notes']), now(), rid)
    )
    # Auto-create reimbursement when receipt is approved
    if d.get('status') == 'approved' and row['status'] != 'approved':
        reimb_id = str(uuid.uuid4())
        db.execute(
            '''INSERT INTO reimbursements
               (id,receipt_id,volunteer_id,amount,status,approved_by,created_at)
               VALUES (?,?,?,?,?,?,?)''',
            (reimb_id, rid, row['volunteer_id'], row['amount'],
             'pending', g.user['user_id'], now())
        )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM receipts WHERE id=?", (rid,)).fetchone()))

@app.route('/api/receipts/upload', methods=['POST'])
@require_auth(roles=['admin', 'volunteer'])
def upload_receipt():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    f = request.files['file']
    if not f.filename or not allowed_file(f.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    filename = str(uuid.uuid4()) + '.' + secure_filename(f.filename).rsplit('.', 1)[-1]
    f.save(os.path.join(UPLOAD_FOLDER, filename))
    return jsonify({'file_url': f'/uploads/{filename}'}), 201

# ── Reimbursements ────────────────────────────────────────────────────────────

@app.route('/api/reimbursements', methods=['GET'])
@require_auth(roles=['admin', 'finance', 'treasurer'])
def list_reimbursements():
    db = get_db()
    status = request.args.get('status')
    try:
        q = '''SELECT rb.*, v.name as volunteer_name,
                      r.store, r.purchase_date, r.file_url as receipt_photo, r.amount as receipt_amount
               FROM reimbursements rb
               LEFT JOIN volunteers v ON rb.volunteer_id = v.id
               LEFT JOIN receipts r ON rb.receipt_id = r.id
               WHERE 1=1'''
        params = []
        if status:
            q += " AND rb.status=?"; params.append(status)
        q += " ORDER BY rb.created_at DESC"
        return jsonify([dict(r) for r in db.execute(q, params).fetchall()])
    except Exception as e:
        log.error(f'list_reimbursements error: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/reimbursements/<rid>', methods=['PUT'])
@require_auth(roles=['admin', 'finance', 'treasurer'])
def update_reimbursement(rid):
    db = get_db()
    row = db.execute("SELECT * FROM reimbursements WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    new_status = d.get('status', row['status'])
    paid_date  = d.get('paid_date', row['paid_date']) or (now()[:10] if new_status == 'paid' else row['paid_date'])
    db.execute(
        '''UPDATE reimbursements SET status=?,payment_method=?,payment_ref=?,paid_date=?,
           approved_by=?,notes=?,updated_at=? WHERE id=?''',
        (new_status,
         d.get('payment_method', row['payment_method']),
         d.get('payment_ref', row['payment_ref']),
         paid_date,
         d.get('approved_by', row['approved_by']) or g.user['user_id'],
         d.get('notes', row['notes']), now(), rid)
    )
    # When reimbursement is paid, mark the linked receipt as approved too
    if new_status == 'paid' and row['status'] != 'paid' and row['receipt_id']:
        db.execute(
            "UPDATE receipts SET status='approved', updated_at=? WHERE id=? AND status='pending'",
            (now(), row['receipt_id'])
        )
    db.commit()
    # Notify volunteer via WhatsApp when payment is sent
    if new_status == 'paid' and row['status'] != 'paid':
        try:
            vol = db.execute(
                "SELECT name, wa_phone, wa_apikey FROM volunteers WHERE id=?", (row['volunteer_id'],)
            ).fetchone()
            if vol and vol['wa_phone'] and vol['wa_apikey']:
                method = d.get('payment_method', row['payment_method']) or 'bank transfer'
                ref    = d.get('payment_ref', row['payment_ref'])
                amount = row['amount'] or 0
                ref_line = f'\nReference: {ref}' if ref else ''
                msg = (f'✅ SIHAA Reimbursement Sent!\n'
                       f'Amount: ${amount:.2f}\n'
                       f'Method: {method.title()}{ref_line}\n'
                       f'JazakAllah Khair for your service!')
                _wa_send(vol['wa_phone'], vol['wa_apikey'], msg)
        except Exception as e:
            log.warning(f'Volunteer payment notification failed: {e}')
    return jsonify(dict(db.execute("SELECT * FROM reimbursements WHERE id=?", (rid,)).fetchone()))

# ── Donations ─────────────────────────────────────────────────────────────────

@app.route('/api/donations', methods=['GET'])
@require_auth(roles=['admin', 'finance', 'treasurer'])
def list_donations():
    rows = get_db().execute(
        "SELECT * FROM donations ORDER BY date DESC, created_at DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/donations/export', methods=['GET'])
@require_auth(roles=['admin', 'finance', 'treasurer'])
def export_donations():
    """Download all donations as an Excel file."""
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment
    from flask import send_file
    import io

    db   = get_db()
    rows = db.execute(
        "SELECT date, donor_name, donor_email, amount, frequency, type, source, notes, reference_id, created_at "
        "FROM donations ORDER BY date DESC, created_at DESC"
    ).fetchall()

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = 'Donations'

    # Header styling
    header_font = Font(bold=True, color='FFFFFF')
    header_fill = PatternFill('solid', fgColor='1A3A2A')
    headers = ['Date', 'Donor', 'Email', 'Amount ($)', 'Frequency', 'Type', 'Source', 'Campaign / Notes', 'Reference ID', 'Imported At']
    for col, h in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col, value=h)
        cell.font      = header_font
        cell.fill      = header_fill
        cell.alignment = Alignment(horizontal='center')

    # Column widths
    col_widths = [12, 18, 24, 12, 12, 10, 10, 28, 36, 20]
    for i, w in enumerate(col_widths, 1):
        ws.column_dimensions[openpyxl.utils.get_column_letter(i)].width = w

    # Data rows
    alt_fill = PatternFill('solid', fgColor='F0FAF5')
    for row_idx, r in enumerate(rows, 2):
        vals = [
            r['date'] or '',
            r['donor_name'] or 'Anonymous',
            r['donor_email'] or '',
            round(r['amount'] or 0, 2),
            r['frequency'] or 'one-time',
            r['type'] or 'online',
            r['source'] or 'manual',
            r['notes'] or '',
            r['reference_id'] or '',
            (r['created_at'] or '')[:10],
        ]
        for col_idx, val in enumerate(vals, 1):
            cell = ws.cell(row=row_idx, column=col_idx, value=val)
            if row_idx % 2 == 0:
                cell.fill = alt_fill

    # Freeze header row
    ws.freeze_panes = 'A2'

    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    filename = f"sihaa_donations_{datetime.utcnow().strftime('%Y%m%d')}.xlsx"
    return send_file(buf, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True, download_name=filename)

@app.route('/api/donations', methods=['POST'])
@require_auth(roles=['admin', 'finance', 'treasurer'])
def create_donation():
    data = request.json or {}
    did = str(uuid.uuid4())
    db = get_db()
    # ensure donor_email column exists
    try:
        db.execute("ALTER TABLE donations ADD COLUMN donor_email TEXT")
        db.commit()
    except Exception:
        pass
    try:
        db.execute("ALTER TABLE donations ADD COLUMN type TEXT")
        db.commit()
    except Exception:
        pass
    try:
        db.execute("ALTER TABLE donations ADD COLUMN reference_id TEXT")
        db.commit()
    except Exception:
        pass
    db.execute(
        '''INSERT INTO donations (id,donor_name,donor_email,amount,type,date,source,reference_id,notes,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (did, data.get('donor_name'), data.get('donor_email'), data.get('amount'),
         data.get('type'), data.get('date'), data.get('source'),
         data.get('reference_id'), data.get('notes'), now())
    )
    db.commit()
    return jsonify({'id': did}), 201

@app.route('/api/donations/sync-wix', methods=['POST'])
@require_auth(roles=['admin', 'treasurer'])
def sync_wix_donations():
    """Pull all PAID donation orders from Wix eCommerce API and upsert into donations table."""
    try:
        import urllib.request as _req
        import urllib.error as _ureq
        import json as _json

        api_key = os.environ.get('WIX_API_KEY', '').strip()
        site_id = os.environ.get('WIX_SITE_ID', '038c9d97-1ce8-4495-982b-37591dce50ee').strip()

        if not api_key:
            return jsonify({'error': 'WIX_API_KEY not configured in environment variables'}), 400

        db = get_db()
        # ensure columns exist
        for col_name, col_type in [('donor_email','TEXT'), ('type','TEXT'), ('reference_id','TEXT'), ('frequency','TEXT')]:
            try:
                db.execute(f'ALTER TABLE donations ADD COLUMN {col_name} {col_type}')
                db.commit()
            except Exception:
                pass

        # Anonymize any previously synced full names (one-time cleanup)
        # Detects unabbreviated names: no period, source='wix', more than one word
        existing_full = db.execute(
            "SELECT id, donor_name, donor_email FROM donations WHERE source='wix' AND donor_name NOT LIKE '%.%'"
        ).fetchall()
        for row in existing_full:
            parts = (row['donor_name'] or '').split()
            if len(parts) >= 2:
                f_abbr = parts[0][:3].capitalize()
                l_abbr = parts[-1][:1].upper()
                new_name = f"{f_abbr}. {l_abbr}."
            elif len(parts) == 1:
                new_name = parts[0][:3].capitalize() + '.'
            else:
                new_name = 'Anonymous'
            # Mask email domain if it looks like a full address
            raw_e = row['donor_email'] or ''
            if '@' in raw_e and not raw_e.startswith('***'):
                new_email = '***@' + raw_e.split('@', 1)[1]
            else:
                new_email = raw_e
            db.execute(
                "UPDATE donations SET donor_name=?, donor_email=? WHERE id=?",
                (new_name, new_email, row['id'])
            )
        if existing_full:
            db.commit()
            log.info(f'Anonymized {len(existing_full)} existing Wix donor records')

        url      = 'https://www.wixapis.com/ecom/v1/orders/search'
        headers  = {'Content-Type': 'application/json',
                    'Authorization': api_key,
                    'wix-site-id': site_id}
        cursor   = None
        imported = 0
        skipped  = 0

        while True:
            body = {'search': {'cursorPaging': {'limit': 100}},
                    'sort': [{'fieldName': 'createdDate', 'order': 'DESC'}]}
            if cursor:
                body['search']['cursorPaging']['cursor'] = cursor

            req_obj = _req.Request(url, data=_json.dumps(body).encode(),
                                   headers=headers, method='POST')
            try:
                with _req.urlopen(req_obj, timeout=20) as resp:
                    result = _json.loads(resp.read())
            except _ureq.HTTPError as e:
                body_text = e.read().decode('utf-8', errors='replace')
                log.error(f'Wix HTTPError {e.code}: {body_text}')
                return jsonify({'error': f'Wix API {e.code}: {body_text[:200]}', 'imported': imported}), 502
            except Exception as e:
                log.error(f'Wix request error: {e}')
                return jsonify({'error': f'Wix request error: {str(e)}', 'imported': imported}), 502

            orders = result.get('orders', [])
            for order in orders:
                if order.get('paymentStatus') != 'PAID':
                    continue
                line_items = order.get('lineItems', [])
                is_donation = any(
                    li.get('itemType', {}).get('custom') == 'DONATION'
                    for li in line_items
                )
                if not is_donation:
                    continue

                wix_order_id = order['id']
                existing = db.execute(
                    "SELECT id FROM donations WHERE reference_id=?", (wix_order_id,)
                ).fetchone()
                if existing:
                    skipped += 1
                    continue

                li        = line_items[0]
                opts      = li.get('catalogReference', {}).get('options', {})
                amount    = float(opts.get('amount') or li.get('price', {}).get('amount') or 0)
                freq_raw  = opts.get('frequency', 'ONE_TIME')
                frequency = 'monthly' if freq_raw == 'MONTH' else 'one-time'
                product   = li.get('productName', {}).get('original', 'Food Donation')

                buyer    = order.get('buyerInfo', {})
                billing  = order.get('billingInfo', {}).get('contactDetails', {})
                fname    = billing.get('firstName', '').strip()
                lname    = billing.get('lastName', '').strip()
                # Abbreviate for privacy: first 2 letters of first name + first letter of last name
                # e.g. "Ahmer Kamal" → "Ah. K."
                f_abbr   = fname[:3].capitalize() if fname else ''
                l_abbr   = lname[:1].upper() if lname else ''
                if f_abbr or l_abbr:
                    donor = f"{f_abbr}. {l_abbr}.".strip() if (f_abbr and l_abbr) else f"{f_abbr or l_abbr}."
                else:
                    donor = 'Anonymous'
                # Store only email domain for privacy (e.g. "***@gmail.com")
                raw_email = buyer.get('email', '')
                if '@' in raw_email:
                    email = '***@' + raw_email.split('@', 1)[1]
                else:
                    email = ''
                date_str = (order.get('purchasedDate') or order.get('createdDate', ''))[:10]

                did = str(uuid.uuid4())
                db.execute(
                    '''INSERT INTO donations
                       (id,donor_name,donor_email,amount,type,frequency,date,source,reference_id,notes,created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                    (did, donor, email, amount, 'online', frequency, date_str,
                     'wix', wix_order_id, product, now())
                )
                imported += 1

            db.commit()

            # Next page
            meta   = result.get('metadata', {})
            cursor = meta.get('cursors', {}).get('next')
            if not cursor or not orders:
                break

        return jsonify({'ok': True, 'imported': imported, 'skipped_duplicates': skipped})

    except Exception as e:
        log.error(f'sync_wix_donations unhandled error: {e}', exc_info=True)
        return jsonify({'error': f'Server error: {str(e)}'}), 500

# ── Food Categories ───────────────────────────────────────────────────────────

@app.route('/api/food-categories', methods=['GET'])
@require_auth()
def list_food_categories():
    rows = get_db().execute(
        "SELECT * FROM food_categories ORDER BY display_order, name"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/food-categories', methods=['POST'])
@require_auth(roles=['admin'])
def create_food_category():
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'Name is required'}), 422
    cid = str(uuid.uuid4())
    max_order = get_db().execute("SELECT COALESCE(MAX(display_order),0) FROM food_categories").fetchone()[0]
    get_db().execute(
        "INSERT INTO food_categories (id, name, display_order, is_active, created_at) VALUES (?,?,?,?,?)",
        (cid, data['name'].strip(), data.get('display_order', max_order + 1),
         data.get('is_active', 1), now())
    )
    get_db().commit()
    return jsonify(dict(get_db().execute("SELECT * FROM food_categories WHERE id=?", (cid,)).fetchone())), 201

@app.route('/api/food-categories/<cid>', methods=['PUT'])
@require_auth(roles=['admin'])
def update_food_category(cid):
    db = get_db()
    row = db.execute("SELECT * FROM food_categories WHERE id=?", (cid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute(
        "UPDATE food_categories SET name=?, display_order=?, is_active=? WHERE id=?",
        (d.get('name', row['name']), d.get('display_order', row['display_order']),
         d.get('is_active', row['is_active']), cid)
    )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM food_categories WHERE id=?", (cid,)).fetchone()))

@app.route('/api/food-categories/<cid>', methods=['DELETE'])
@require_auth(roles=['admin'])
def delete_food_category(cid):
    db = get_db()
    if db.execute("SELECT id FROM food_items WHERE category_id=? AND is_active=1", (cid,)).fetchone():
        return jsonify({'error': 'Cannot delete category with active items'}), 409
    db.execute("UPDATE food_categories SET is_active=0 WHERE id=?", (cid,))
    db.commit()
    return jsonify({'ok': True})

# ── Food Items ────────────────────────────────────────────────────────────────

@app.route('/api/food-items', methods=['GET'])
@require_auth()
def list_food_items():
    db = get_db()
    active_only = request.args.get('active') == '1'
    cat_id = request.args.get('category_id')
    q = '''SELECT fi.*, fc.name as category_name
           FROM food_items fi
           JOIN food_categories fc ON fi.category_id = fc.id
           WHERE 1=1'''
    params = []
    if active_only:
        q += " AND fi.is_active=1 AND fc.is_active=1"
    if cat_id:
        q += " AND fi.category_id=?"; params.append(cat_id)
    q += " ORDER BY fc.display_order, fi.display_order, fi.name"
    return jsonify([dict(r) for r in db.execute(q, params).fetchall()])

@app.route('/api/food-items', methods=['POST'])
@require_auth(roles=['admin'])
def create_food_item():
    data = request.json or {}
    if not data.get('name') or not data.get('category_id'):
        return jsonify({'error': 'Name and category_id are required'}), 422
    iid = str(uuid.uuid4())
    db = get_db()
    if not db.execute("SELECT id FROM food_categories WHERE id=?", (data['category_id'],)).fetchone():
        return jsonify({'error': 'Category not found'}), 404
    max_order = db.execute(
        "SELECT COALESCE(MAX(display_order),0) FROM food_items WHERE category_id=?",
        (data['category_id'],)
    ).fetchone()[0]
    db.execute(
        "INSERT INTO food_items (id, category_id, name, unit, is_active, display_order, created_at) VALUES (?,?,?,?,?,?,?)",
        (iid, data['category_id'], data['name'].strip(),
         data.get('unit', 'each'), data.get('is_active', 1),
         data.get('display_order', max_order + 1), now())
    )
    db.commit()

    # Seed empty bundle quantities for S/M/L
    for size in ('S', 'M', 'L'):
        db.execute(
            "INSERT OR IGNORE INTO bundle_quantities (id, food_item_id, bundle_size, quantity) VALUES (?,?,?,?)",
            (str(uuid.uuid4()), iid, size, '0')
        )
    db.commit()

    item = dict(db.execute(
        '''SELECT fi.*, fc.name as category_name FROM food_items fi
           JOIN food_categories fc ON fi.category_id = fc.id WHERE fi.id=?''', (iid,)
    ).fetchone())
    return jsonify(item), 201

@app.route('/api/food-items/<iid>', methods=['PUT'])
@require_auth(roles=['admin'])
def update_food_item(iid):
    db = get_db()
    row = db.execute("SELECT * FROM food_items WHERE id=?", (iid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute(
        "UPDATE food_items SET name=?, unit=?, is_active=?, display_order=?, category_id=? WHERE id=?",
        (d.get('name', row['name']), d.get('unit', row['unit']),
         d.get('is_active', row['is_active']), d.get('display_order', row['display_order']),
         d.get('category_id', row['category_id']), iid)
    )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM food_items WHERE id=?", (iid,)).fetchone()))

# ── Bundle Quantities ─────────────────────────────────────────────────────────

@app.route('/api/bundle-quantities', methods=['GET'])
@require_auth()
def get_bundle_quantities():
    db = get_db()
    item_id = request.args.get('item_id')
    if item_id:
        rows = db.execute(
            "SELECT * FROM bundle_quantities WHERE food_item_id=? ORDER BY bundle_size",
            (item_id,)
        ).fetchall()
    else:
        rows = db.execute(
            '''SELECT bq.*, fi.name as item_name, fi.unit, fc.name as category_name
               FROM bundle_quantities bq
               JOIN food_items fi ON bq.food_item_id = fi.id
               JOIN food_categories fc ON fi.category_id = fc.id
               ORDER BY fc.display_order, fi.display_order, bq.bundle_size'''
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/bundle-quantities', methods=['PUT'])
@require_auth(roles=['admin'])
def update_bundle_quantities():
    """Bulk update: expects list of {food_item_id, bundle_size, quantity}"""
    items = request.json or []
    if not isinstance(items, list):
        return jsonify({'error': 'Expected array'}), 422
    db = get_db()
    for item in items:
        if not all(k in item for k in ('food_item_id', 'bundle_size', 'quantity')):
            continue
        db.execute(
            '''INSERT INTO bundle_quantities (id, food_item_id, bundle_size, quantity)
               VALUES (?,?,?,?)
               ON CONFLICT(food_item_id, bundle_size) DO UPDATE SET quantity=excluded.quantity''',
            (str(uuid.uuid4()), item['food_item_id'], item['bundle_size'], item['quantity'])
        )
    db.commit()
    return jsonify({'ok': True})

# ── Bundle Size Rules ─────────────────────────────────────────────────────────

@app.route('/api/bundle-size-rules', methods=['GET'])
@require_auth()
def get_bundle_size_rules():
    rows = get_db().execute(
        "SELECT * FROM bundle_size_rules ORDER BY min_household"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/bundle-size-rules', methods=['PUT'])
@require_auth(roles=['admin'])
def update_bundle_size_rules():
    """Bulk update: expects list of {bundle_size, min_household, max_household, label}"""
    items = request.json or []
    db = get_db()
    for item in items:
        db.execute(
            '''UPDATE bundle_size_rules
               SET min_household=?, max_household=?, label=?
               WHERE bundle_size=?''',
            (item.get('min_household'), item.get('max_household'),
             item.get('label'), item.get('bundle_size'))
        )
    db.commit()
    return jsonify([dict(r) for r in db.execute(
        "SELECT * FROM bundle_size_rules ORDER BY min_household"
    ).fetchall()])

# ── Delivery Cycles ───────────────────────────────────────────────────────────

def auto_update_cycle_statuses(db):
    """No-op — cycles are now manually advanced (upcoming→shopping→delivered)."""
    pass


def _ensure_volunteer_slots(db, cycle_id, family_id):
    """Ensure open slots exist for a family in a cycle for all is_family_slot task types.
    Idempotent — SELECT-first to avoid duplicates. Creates open slots only if absent.
    Returns the number of new slots created (0 if they already existed).
    Called as a safety net on order confirmation, cycle creation, and family activation.
    """
    cycle = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cycle_id,)).fetchone()
    if not cycle:
        return 0
    delivery_date = cycle['delivery_date_start']
    task_types = db.execute(
        "SELECT slug FROM volunteer_task_types WHERE is_active=1 AND is_family_slot=1 ORDER BY display_order"
    ).fetchall()
    created = 0
    for tt_row in task_types:
        task_type = tt_row['slug']
        task_date = delivery_date if task_type == 'delivery' else None
        try:
            existing = db.execute(
                "SELECT id FROM volunteer_slots WHERE cycle_id=? AND family_id=? AND task_type=? AND status!='cancelled'",
                (cycle_id, family_id, task_type)
            ).fetchone()
            if not existing:
                db.execute(
                    "INSERT INTO volunteer_slots (id,cycle_id,family_id,task_type,task_date,status,created_at) VALUES (?,?,?,?,?,?,?)",
                    (str(uuid.uuid4()), cycle_id, family_id, task_type, task_date, 'open', now())
                )
                created += 1
        except Exception as e:
            log.warning(f'_ensure_volunteer_slots: could not create {task_type} slot for family {family_id}: {e}')
    return created


def _pre_create_slots_for_cycle(db, cycle_id):
    """Pre-create open slots for ALL active families in a cycle.
    Called when a new cycle is created or seeded. Returns total slots created.
    """
    families = db.execute(
        "SELECT id FROM families WHERE status='active'"
    ).fetchall()
    total = 0
    for fam in families:
        total += _ensure_volunteer_slots(db, cycle_id, fam['id'])
    return total


def _pre_create_slots_for_family(db, family_id):
    """Pre-create open slots for a newly activated family across all future cycles.
    Called when a family's status is set to 'active'. Returns total slots created.
    """
    future_cycles = db.execute(
        "SELECT id FROM delivery_cycles WHERE status NOT IN ('delivered') AND delivery_date_start >= date('now')"
    ).fetchall()
    total = 0
    for cyc in future_cycles:
        total += _ensure_volunteer_slots(db, cyc['id'], family_id)
    return total


def _enroll_families_in_cycle(db, cycle_id, delivery_date_start):
    """Auto-create food_requests for all active families in a new cycle."""
    families = db.execute(
        "SELECT id, family_size FROM families WHERE status='active'"
    ).fetchall()
    items = db.execute(
        "SELECT id FROM food_items WHERE is_active=1"
    ).fetchall()
    enrolled = 0
    for fam in families:
        # Compute bundle size from household size
        bundle = db.execute(
            "SELECT bundle_size FROM bundle_size_rules WHERE min_household<=? AND (max_household IS NULL OR max_household>=?) ORDER BY min_household DESC LIMIT 1",
            (fam['family_size'] or 1, fam['family_size'] or 1)
        ).fetchone()
        bsize = bundle['bundle_size'] if bundle else 'M'
        token = str(uuid.uuid4())
        rid = str(uuid.uuid4())
        try:
            db.execute(
                '''INSERT INTO food_requests
                   (id, cycle_id, family_id, bundle_size, submitted_at, status, confirmation_token)
                   VALUES (?,?,?,?,?,?,?)''',
                (rid, cycle_id, fam['id'], bsize, now(), 'pending_confirmation', token)
            )
            # Pre-populate all food items as selected
            for item in items:
                db.execute(
                    'INSERT OR IGNORE INTO food_request_items (id, request_id, food_item_id, selected) VALUES (?,?,?,1)',
                    (str(uuid.uuid4()), rid, item['id'])
                )
            enrolled += 1
        except Exception:
            pass  # Already enrolled (UNIQUE constraint)
    db.commit()
    log.info(f'Auto-enrolled {enrolled} families in cycle {cycle_id}')
    return enrolled

@app.route('/api/delivery-cycles', methods=['GET'])
@require_auth()
def list_delivery_cycles():
    db = get_db()
    auto_update_cycle_statuses(db)
    status = request.args.get('status')
    q = "SELECT * FROM delivery_cycles WHERE 1=1"
    params = []
    if status:
        q += " AND status=?"; params.append(status)
    q += " ORDER BY delivery_date_start ASC"
    return jsonify([dict(r) for r in db.execute(q, params).fetchall()])

def _fix_delivery_cycles_schema(db):
    """
    Ensure delivery_cycles.status CHECK includes 'upcoming'.
    Works regardless of which columns exist on the live DB.
    Idempotent — no-ops if schema is already correct.
    """
    schema_row = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='delivery_cycles'"
    ).fetchone()
    if not schema_row or 'upcoming' in schema_row[0]:
        return  # nothing to do

    log.info('_fix_delivery_cycles_schema: rebuilding table to add upcoming status')
    db.execute('PRAGMA foreign_keys=OFF')

    # Discover which columns actually exist in the live table
    col_info  = db.execute('PRAGMA table_info(delivery_cycles)').fetchall()
    live_cols = {row[1] for row in col_info}   # row[1] = column name

    # Build the SELECT list, supplying '' for missing TEXT NOT NULL columns
    wanted = [
        ('id',                  'id'),
        ('title',               'title'),
        ('delivery_date_start', 'delivery_date_start'),
        ('delivery_date_end',   'delivery_date_end'),
        ('request_open_at',     "COALESCE(request_open_at,'')"),
        ('request_close_at',    "COALESCE(request_close_at,'')"),
        ('status',              'status'),
        ('notes',               'notes'),
        ('created_by',          'created_by'),
        ('created_at',          'created_at'),
    ]
    dst_cols = []
    src_exprs = []
    for col_name, expr in wanted:
        raw = col_name if 'COALESCE' not in expr else col_name
        if raw in live_cols:
            dst_cols.append(col_name)
            src_exprs.append(expr)
        elif col_name in ('request_open_at', 'request_close_at'):
            # Column doesn't exist at all — supply empty string
            dst_cols.append(col_name)
            src_exprs.append("''")

    db.execute('DROP TABLE IF EXISTS delivery_cycles_new')
    db.execute('''
        CREATE TABLE delivery_cycles_new (
            id                  TEXT PRIMARY KEY,
            title               TEXT NOT NULL,
            delivery_date_start TEXT NOT NULL,
            delivery_date_end   TEXT NOT NULL,
            request_open_at     TEXT NOT NULL DEFAULT '',
            request_close_at    TEXT NOT NULL DEFAULT '',
            status              TEXT NOT NULL DEFAULT 'upcoming'
                                CHECK(status IN
                                  ('draft','open','closed','upcoming','shopping','delivered')),
            notes               TEXT,
            created_by          TEXT,
            created_at          TEXT NOT NULL,
            updated_at          TEXT
        )''')

    db.execute(
        f"INSERT INTO delivery_cycles_new ({', '.join(dst_cols)}) "
        f"SELECT {', '.join(src_exprs)} FROM delivery_cycles"
    )
    db.execute('DROP TABLE delivery_cycles')
    db.execute('ALTER TABLE delivery_cycles_new RENAME TO delivery_cycles')
    db.commit()
    db.execute('PRAGMA foreign_keys=ON')
    log.info('_fix_delivery_cycles_schema: done')


@app.route('/api/delivery-cycles', methods=['POST'])
@require_auth(roles=['admin'])
def create_delivery_cycle():
    data = request.json or {}
    if not all(data.get(k) for k in ('title', 'delivery_date_start', 'delivery_date_end')):
        return jsonify({'error': 'title, delivery_date_start and delivery_date_end are required'}), 422
    cid = str(uuid.uuid4())
    db  = get_db()

    # Ensure schema supports 'upcoming' before inserting
    try:
        _fix_delivery_cycles_schema(db)
    except Exception as _e:
        log.error(f'create_delivery_cycle: schema fix failed: {_e}')
        return jsonify({'error': f'Schema migration failed: {_e}'}), 500

    req_open  = data.get('request_open_at')  or ''
    req_close = data.get('request_close_at') or ''
    db.execute(
        '''INSERT INTO delivery_cycles
           (id, title, delivery_date_start, delivery_date_end,
            request_open_at, request_close_at, status, notes, created_by, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (cid, data['title'], data['delivery_date_start'], data['delivery_date_end'],
         req_open, req_close,
         data.get('status') or 'upcoming', data.get('notes'),
         g.user['user_id'], now())
    )
    db.commit()
    # Pre-create volunteer slots for all active families in this new cycle
    try:
        slots_created = _pre_create_slots_for_cycle(db, cid)
        db.commit()
        log.info(f'create_delivery_cycle: pre-created {slots_created} volunteer slots for cycle {cid}')
    except Exception as _e:
        log.warning(f'create_delivery_cycle: slot pre-creation failed: {_e}')
    result = dict(db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cid,)).fetchone())
    return jsonify(result), 201

@app.route('/api/delivery-cycles/<cid>', methods=['PUT'])
@require_auth(roles=['admin'])
def update_delivery_cycle(cid):
    db = get_db()
    row = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute(
        '''UPDATE delivery_cycles SET title=?, delivery_date_start=?, delivery_date_end=?,
           request_open_at=?, request_close_at=?, status=?, notes=?, updated_at=? WHERE id=?''',
        (d.get('title', row['title']),
         d.get('delivery_date_start', row['delivery_date_start']),
         d.get('delivery_date_end', row['delivery_date_end']),
         d.get('request_open_at', row['request_open_at']),
         d.get('request_close_at', row['request_close_at']),
         d.get('status', row['status']),
         d.get('notes', row['notes']), now(), cid)
    )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cid,)).fetchone()))

@app.route('/api/delivery-cycles/<cid>/orders', methods=['GET'])
@require_auth()
def get_cycle_orders(cid):
    db = get_db()
    orders = db.execute(
        '''SELECT fr.*, f.name as family_name, f.phone as family_phone,
                  f.address as family_address, f.city as family_city,
                  f.family_code, f.wa_phone as family_wa_phone, f.wa_apikey as family_wa_apikey
           FROM food_requests fr
           JOIN families f ON fr.family_id = f.id
           WHERE fr.cycle_id=?
           ORDER BY fr.submitted_at''', (cid,)
    ).fetchall()
    result = []
    for order in orders:
        o = dict(order)
        items = db.execute(
            '''SELECT fri.*, fi.name, fi.unit, fc.name as category
               FROM food_request_items fri
               JOIN food_items fi ON fri.food_item_id = fi.id
               JOIN food_categories fc ON fi.category_id = fc.id
               WHERE fri.request_id=? AND fri.selected=1
               ORDER BY fc.display_order, fi.display_order''',
            (o['id'],)
        ).fetchall()
        o['selected_items'] = [dict(i) for i in items]
        result.append(o)
    return jsonify(result)

@app.route('/api/food-requests/<rid>', methods=['PUT'])
@require_auth(roles=['admin'])
def update_food_request_status(rid):
    """Admin manually overrides a family's confirmation status (confirmed or skipped)."""
    db  = get_db()
    row = db.execute("SELECT * FROM food_requests WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d      = request.json or {}
    status = d.get('status')
    if status not in ('confirmed', 'skipped', 'pending_confirmation'):
        return jsonify({'error': 'status must be confirmed, skipped, or pending_confirmation'}), 422
    ts = now()
    try:
        db.execute(
            "UPDATE food_requests SET status=?, confirmed_at=?, updated_at=? WHERE id=?",
            (status, ts if status == 'confirmed' else None, ts, rid)
        )
    except sqlite3.OperationalError:
        # Fallback: confirmed_at/updated_at columns may not exist yet on old DB
        db.execute("UPDATE food_requests SET status=? WHERE id=?", (status, rid))

    # Auto-create volunteer slots when coordinator confirms a family
    if status == 'confirmed':
        _ensure_volunteer_slots(db, row['cycle_id'], row['family_id'])

    _log_order_event(db, rid, 'admin_override', actor='admin',
                     payload={'new_status': status})
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM food_requests WHERE id=?", (rid,)).fetchone()))


@app.route('/api/families/<fid>/manual-confirm', methods=['POST'])
@require_auth(roles=['admin'])
def manual_confirm_family(fid):
    """Coordinator manually adds a family to the current open cycle as confirmed."""
    db = get_db()
    family = db.execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()
    if not family:
        return jsonify({'error': 'Family not found'}), 404

    # Find open or shopping cycle (coordinator may be confirming mid-cycle)
    cycle = db.execute(
        "SELECT * FROM delivery_cycles WHERE status IN ('open','shopping') ORDER BY delivery_date_start LIMIT 1"
    ).fetchone()
    if not cycle:
        return jsonify({'error': 'No active delivery cycle (open or shopping). Create or open a cycle first.'}), 409

    # Don't duplicate
    existing = db.execute(
        "SELECT id FROM food_requests WHERE cycle_id=? AND family_id=?",
        (cycle['id'], fid)
    ).fetchone()
    if existing:
        return jsonify({'error': 'Family already has an order for this cycle.', 'request_id': existing['id']}), 409

    # Determine bundle size
    bundle_size = family['bundle_size'] or None
    if not bundle_size:
        size = db.execute(
            "SELECT bundle_size FROM bundle_size_rules WHERE min_household<=? AND (max_household IS NULL OR max_household>=?) ORDER BY min_household DESC LIMIT 1",
            (family['family_size'] or 1, family['family_size'] or 1)
        ).fetchone()
        bundle_size = size['bundle_size'] if size else 'M'

    ts  = now()
    rid = str(uuid.uuid4())
    try:
        db.execute(
            '''INSERT INTO food_requests
               (id, cycle_id, family_id, bundle_size, submitted_at, status, confirmed_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?)''',
            (rid, cycle['id'], fid, bundle_size, ts, 'confirmed', ts, ts)
        )
    except Exception:
        # Fallback if extra columns don't exist
        db.execute(
            '''INSERT INTO food_requests
               (id, cycle_id, family_id, bundle_size, submitted_at, status)
               VALUES (?,?,?,?,?,?)''',
            (rid, cycle['id'], fid, bundle_size, ts, 'confirmed')
        )

    # Record all items as selected by default
    all_items = db.execute("SELECT id FROM food_items WHERE is_active=1").fetchall()
    for item in all_items:
        db.execute(
            "INSERT OR IGNORE INTO food_request_items (id, request_id, food_item_id, selected) VALUES (?,?,?,1)",
            (str(uuid.uuid4()), rid, item['id'])
        )

    # Auto-create volunteer slots immediately (creates open slots if absent)
    slots_created = _ensure_volunteer_slots(db, cycle['id'], fid)

    # Flip any already-claimed slots to confirmed — volunteer signed up before admin added the family
    claimed_slots = db.execute(
        '''SELECT vs.*, v.name as vol_name, v.wa_phone, v.wa_apikey
           FROM volunteer_slots vs
           JOIN volunteers v ON vs.claimed_by = v.id
           WHERE vs.cycle_id=? AND vs.family_id=? AND vs.status='claimed' ''',
        (cycle['id'], fid)
    ).fetchall()
    for slot in claimed_slots:
        db.execute(
            "UPDATE volunteer_slots SET status='confirmed', updated_at=? WHERE id=?",
            (now(), slot['id'])
        )
    slots_confirmed = len(claimed_slots)

    _log_order_event(db, rid, 'admin_override', actor='admin',
                     payload={'new_status': 'confirmed', 'note': 'manual confirm by coordinator'})
    db.commit()

    # Notify volunteers whose slots just became confirmed
    for slot in claimed_slots:
        try:
            address_line = f"\n📍 {family['address']}, {family['city']}" if slot['task_type'] == 'delivery' and family.get('address') else ''
            msg = (f"✅ Your {slot['task_type']} slot for family {family['family_code'] or fid[:8]} "
                   f"({cycle['title']}) is now confirmed — the coordinator has added them to this delivery.{address_line}")
            _send_wa(slot['wa_phone'], slot['wa_apikey'], msg)
        except Exception as e:
            log.warning(f'manual_confirm WA notify failed for slot {slot["id"]}: {e}')

    log.info(f'Manual confirm: family {fid} added to cycle {cycle["id"]} — {slots_created} slots created, {slots_confirmed} slots confirmed')
    return jsonify({'ok': True, 'request_id': rid, 'cycle_title': cycle['title'], 'bundle_size': bundle_size,
                    'slots_created': slots_created, 'slots_confirmed': slots_confirmed}), 201

@app.route('/api/delivery-cycles/<cid>/shopping-list', methods=['GET'])
@require_auth()
def get_cycle_shopping_list(cid):
    db = get_db()
    # Get all selected items across all orders for this cycle, with bundle quantities
    rows = db.execute(
        '''SELECT fi.id as item_id, fi.name as item_name, fi.unit,
                  fc.name as category, fc.display_order as cat_order, fi.display_order as item_order,
                  fr.bundle_size,
                  bq.quantity,
                  COUNT(DISTINCT fr.id) as order_count
           FROM food_requests fr
           JOIN food_request_items fri ON fri.request_id = fr.id AND fri.selected = 1
           JOIN food_items fi ON fri.food_item_id = fi.id
           JOIN food_categories fc ON fi.category_id = fc.id
           LEFT JOIN bundle_quantities bq ON bq.food_item_id = fi.id AND bq.bundle_size = fr.bundle_size
           WHERE fr.cycle_id=? AND fr.status = 'confirmed'
           GROUP BY fi.id, fr.bundle_size
           ORDER BY fc.display_order, fi.display_order, fr.bundle_size''',
        (cid,)
    ).fetchall()

    # Aggregate by item, summing across bundle sizes
    from collections import defaultdict
    items = defaultdict(lambda: {'category': '', 'unit': '', 'cat_order': 0, 'item_order': 0, 'breakdown': []})
    for r in rows:
        key = r['item_name']
        items[key]['category'] = r['category']
        items[key]['unit'] = r['unit']
        items[key]['cat_order'] = r['cat_order']
        items[key]['item_order'] = r['item_order']
        items[key]['breakdown'].append({
            'bundle_size': r['bundle_size'],
            'quantity': r['quantity'],
            'order_count': r['order_count']
        })

    shopping_list = []
    for name, info in sorted(items.items(), key=lambda x: (x[1]['cat_order'], x[1]['item_order'])):
        shopping_list.append({
            'item_name': name,
            'category': info['category'],
            'unit': info['unit'],
            'breakdown': info['breakdown']
        })

    cycle = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cid,)).fetchone()
    total_orders = db.execute(
        "SELECT COUNT(*) FROM food_requests WHERE cycle_id=? AND status = 'confirmed'", (cid,)
    ).fetchone()[0]

    return jsonify({
        'cycle': dict(cycle) if cycle else {},
        'total_orders': total_orders,
        'shopping_list': shopping_list,
        'generated_at': now()  # UTC — volunteers can see if list was generated before recent edits
    })

# ── Print Reports (HTML → browser PDF) ────────────────────────────────────────

PRINT_CSS = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         font-size: 12px; color: #111; background: #fff; padding: 24px; }
  .header { background: #1a3a2a; color: #fff; padding: 14px 20px;
            border-radius: 6px; margin-bottom: 20px;
            display: flex; justify-content: space-between; align-items: center; }
  .header h1 { font-size: 18px; font-weight: 700; }
  .header .sub { font-size: 12px; opacity: 0.8; margin-top: 3px; }
  .header .right { text-align: right; font-size: 11px; opacity: 0.8; }
  .meta { display: flex; gap: 16px; margin-bottom: 18px; flex-wrap: wrap; }
  .meta-box { background: #f5f5f0; border-radius: 6px; padding: 10px 16px;
              border-left: 3px solid #1a3a2a; }
  .meta-box .label { font-size: 10px; text-transform: uppercase;
                     letter-spacing: 0.5px; color: #888; margin-bottom: 3px; }
  .meta-box .value { font-size: 20px; font-weight: 700; color: #1a3a2a; }
  .meta-box .hint  { font-size: 11px; color: #666; }
  h2 { font-size: 13px; font-weight: 700; color: #1a3a2a; text-transform: uppercase;
       letter-spacing: 0.5px; margin: 20px 0 8px; border-bottom: 2px solid #1a3a2a;
       padding-bottom: 4px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 16px; }
  th { background: #1a3a2a; color: #fff; font-weight: 700; font-size: 11px;
       padding: 7px 10px; text-align: left; }
  td { padding: 6px 10px; border-bottom: 1px solid #eee; vertical-align: top; }
  tr:nth-child(even) td { background: #fafaf8; }
  .total { font-weight: 700; color: #1a3a2a; }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 10px;
           font-size: 10px; font-weight: 700; text-transform: uppercase; }
  .badge-pending  { background: #fff3cd; color: #856404; }
  .badge-delivered{ background: #d1f5e0; color: #0a5c2e; }
  .badge-complete { background: #d1f5e0; color: #0a5c2e; }
  .badge-claimed  { background: #cce5ff; color: #004085; }
  .badge-open     { background: #f8d7da; color: #721c24; }
  .footer { margin-top: 24px; font-size: 10px; color: #aaa;
            border-top: 1px solid #eee; padding-top: 10px;
            display: flex; justify-content: space-between; }
  @media print {
    body { padding: 0; }
    .no-print { display: none !important; }
    @page { margin: 15mm 12mm; }
  }
</style>
"""

def _print_page(title, subtitle, body_html, cycle_title=''):
    generated = datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>{title} — {cycle_title}</title>
{PRINT_CSS}
</head><body>
<div class="no-print" style="margin-bottom:16px;">
  <button onclick="window.print()" style="background:#1a3a2a;color:#fff;border:none;
    padding:8px 18px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;">
    Print / Save as PDF
  </button>
  <button onclick="window.close()" style="background:#eee;border:none;
    padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px;margin-left:8px;">
    Close
  </button>
</div>
<div class="header">
  <div><div class="sub">SIHAA Food Charity — Operations Hub</div>
    <h1>{cycle_title}</h1>
    <div class="sub">{subtitle}</div></div>
  <div class="right"><strong>{title}</strong><br>Generated {generated}</div>
</div>
{body_html}
<div class="footer">
  <span>SIHAA Food Charity — Operations Hub</span>
  <span>Generated {generated}</span>
</div>
<script>
  // Auto-trigger print dialog after a short delay so page is fully rendered
  // Remove this line if you prefer to click the button manually
  // setTimeout(() => window.print(), 600);
</script>
</body></html>"""


@app.route('/api/reports/shopping-list/<cid>', methods=['GET'])
@require_auth()
def report_shopping_list(cid):
    """Printable shopping list — returns HTML page, browser prints to PDF."""
    from collections import defaultdict
    db = get_db()
    cycle = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cid,)).fetchone()
    if not cycle:
        return jsonify({'error': 'Cycle not found'}), 404

    bundle_counts = {r['bundle_size']: r['cnt'] for r in db.execute(
        "SELECT bundle_size, COUNT(*) as cnt FROM food_requests WHERE cycle_id=? AND status='confirmed' GROUP BY bundle_size",
        (cid,)
    ).fetchall()}
    total_orders = sum(bundle_counts.values())

    rows = db.execute(
        '''SELECT fi.name as item_name, fi.unit,
                  fc.name as category, fc.display_order as cat_order, fi.display_order as item_order,
                  fr.bundle_size, bq.quantity, COUNT(DISTINCT fr.id) as order_count
           FROM food_requests fr
           JOIN food_request_items fri ON fri.request_id = fr.id AND fri.selected = 1
           JOIN food_items fi ON fri.food_item_id = fi.id
           JOIN food_categories fc ON fi.category_id = fc.id
           LEFT JOIN bundle_quantities bq ON bq.food_item_id = fi.id AND bq.bundle_size = fr.bundle_size
           WHERE fr.cycle_id=? AND fr.status = 'confirmed'
           GROUP BY fi.id, fr.bundle_size
           ORDER BY fc.display_order, fi.display_order, fr.bundle_size''',
        (cid,)
    ).fetchall()

    items = defaultdict(lambda: {'category':'','unit':'','cat_order':0,'item_order':0,'sizes':{}})
    for r in rows:
        k = r['item_name']
        items[k].update({'category': r['category'], 'unit': r['unit'],
                         'cat_order': r['cat_order'], 'item_order': r['item_order']})
        qty, count = r['quantity'] or 0, r['order_count'] or 0
        items[k]['sizes'][r['bundle_size']] = {'qty': qty, 'count': count, 'total': qty * count}

    by_cat = defaultdict(list)
    for name, info in sorted(items.items(), key=lambda x: (x[1]['cat_order'], x[1]['item_order'])):
        by_cat[info['category']].append((name, info['unit'], info['sizes'],
                                         sum(v['total'] for v in info['sizes'].values())))

    # Bundle summary
    body = f"""
    <div class="meta">
      <div class="meta-box"><div class="label">Small (S) · 1–2 people</div>
        <div class="value">{bundle_counts.get('S',0)}</div><div class="hint">families</div></div>
      <div class="meta-box"><div class="label">Medium (M) · 3–5 people</div>
        <div class="value">{bundle_counts.get('M',0)}</div><div class="hint">families</div></div>
      <div class="meta-box"><div class="label">Large (L) · 6+ people</div>
        <div class="value">{bundle_counts.get('L',0)}</div><div class="hint">families</div></div>
      <div class="meta-box"><div class="label">Total Orders</div>
        <div class="value">{total_orders}</div><div class="hint">families</div></div>
    </div>"""

    if not rows:
        body += '<p style="color:#888;padding:20px 0;">No orders submitted for this cycle yet.</p>'
    else:
        def fmt(sizes, sz):
            if sz not in sizes: return '—'
            d = sizes[sz]
            return f"{d['qty']} × {d['count']}" if d['count'] else '—'
        def fmt_total(sizes, sz):
            if sz not in sizes: return '—'
            d = sizes[sz]
            return str(d['total']) if d['total'] else '—'

        for cat_name, cat_items in by_cat.items():
            rows_html = ''
            for item_name, unit, sizes, row_total in cat_items:
                s_qty = fmt_total(sizes, 'S')
                m_qty = fmt_total(sizes, 'M')
                l_qty = fmt_total(sizes, 'L')
                rows_html += f"""<tr>
                  <td>{item_name}</td><td>{unit}</td>
                  <td style="text-align:center">{fmt(sizes,'S')}</td>
                  <td style="text-align:center">{fmt(sizes,'M')}</td>
                  <td style="text-align:center">{fmt(sizes,'L')}</td>
                  <td class="total" style="text-align:center">{row_total if row_total else '—'}</td>
                </tr>"""
            body += f"""
            <h2>{cat_name}</h2>
            <table>
              <thead><tr>
                <th>Item</th><th>Unit</th>
                <th style="text-align:center">S (qty×families)</th>
                <th style="text-align:center">M (qty×families)</th>
                <th style="text-align:center">L (qty×families)</th>
                <th style="text-align:center">TOTAL</th>
              </tr></thead>
              <tbody>{rows_html}</tbody>
            </table>"""

    subtitle = f"Delivery: {cycle['delivery_date_start']} – {cycle['delivery_date_end']}  ·  {total_orders} orders"
    html = _print_page('Shopping List', subtitle, body, cycle['title'])
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}


@app.route('/api/reports/cycle-summary/<cid>', methods=['GET'])
@require_auth()
def report_cycle_summary(cid):
    """Printable cycle summary — returns HTML page, browser prints to PDF."""
    db = get_db()
    cycle = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cid,)).fetchone()
    if not cycle:
        return jsonify({'error': 'Cycle not found'}), 404

    orders = db.execute(
        '''SELECT fr.bundle_size, fr.status, fr.delivered_at,
                  f.name as family_name, f.family_size
           FROM food_requests fr
           JOIN families f ON fr.family_id = f.id
           WHERE fr.cycle_id=? AND fr.status != 'cancelled'
           ORDER BY fr.bundle_size, f.name''', (cid,)
    ).fetchall()

    slots = db.execute(
        '''SELECT vs.task_type, vs.status, vs.task_date,
                  f.name as family_name,
                  v.name as volunteer_name, v.phone as volunteer_phone
           FROM volunteer_slots vs
           LEFT JOIN families f ON vs.family_id = f.id
           LEFT JOIN volunteers v ON vs.claimed_by = v.id
           WHERE vs.cycle_id=?
           ORDER BY vs.task_type, vs.task_date, f.name''', (cid,)
    ).fetchall()

    bundle_counts = {}
    for o in orders:
        bundle_counts[o['bundle_size']] = bundle_counts.get(o['bundle_size'], 0) + 1

    body = f"""
    <div class="meta">
      <div class="meta-box"><div class="label">Total Families</div>
        <div class="value">{len(orders)}</div></div>
      <div class="meta-box"><div class="label">Small Bundles</div>
        <div class="value">{bundle_counts.get('S',0)}</div></div>
      <div class="meta-box"><div class="label">Medium Bundles</div>
        <div class="value">{bundle_counts.get('M',0)}</div></div>
      <div class="meta-box"><div class="label">Large Bundles</div>
        <div class="value">{bundle_counts.get('L',0)}</div></div>
      <div class="meta-box"><div class="label">Volunteer Slots</div>
        <div class="value">{len(slots)}</div></div>
    </div>"""

    # Orders table
    order_rows = ''
    for o in orders:
        delivered = o['delivered_at'][:10] if o['delivered_at'] else ('Yes' if o['status']=='delivered' else '—')
        status_class = o['status'].lower()
        order_rows += f"""<tr>
          <td>{o['family_name']}</td>
          <td style="text-align:center">{o['family_size'] or '—'}</td>
          <td style="text-align:center">{o['bundle_size'] or '—'}</td>
          <td><span class="badge badge-{status_class}">{o['status']}</span></td>
          <td>{delivered}</td>
        </tr>"""
    body += f"""
    <h2>Family Orders ({len(orders)})</h2>
    <table>
      <thead><tr><th>Family</th><th style="text-align:center">HH Size</th>
        <th style="text-align:center">Bundle</th><th>Status</th><th>Delivered</th></tr></thead>
      <tbody>{order_rows if order_rows else '<tr><td colspan="5" style="color:#888">No orders</td></tr>'}</tbody>
    </table>"""

    # Slots table
    if slots:
        slot_rows = ''
        for s in slots:
            status_class = s['status'].lower()
            slot_rows += f"""<tr>
              <td>{s['task_type'].capitalize()}</td>
              <td>{s['task_date'] or '—'}</td>
              <td>{s['family_name'] or '—'}</td>
              <td>{s['volunteer_name'] or '<em style="color:#aaa">Unclaimed</em>'}</td>
              <td>{s['volunteer_phone'] or '—'}</td>
              <td><span class="badge badge-{status_class}">{s['status']}</span></td>
            </tr>"""
        body += f"""
        <h2>Volunteer Assignments ({len(slots)})</h2>
        <table>
          <thead><tr><th>Task</th><th>Date</th><th>Family</th>
            <th>Volunteer</th><th>Phone</th><th>Status</th></tr></thead>
          <tbody>{slot_rows}</tbody>
        </table>"""

    subtitle = f"Delivery: {cycle['delivery_date_start']} – {cycle['delivery_date_end']}  ·  Status: {cycle['status'].upper()}"
    html = _print_page('Cycle Summary', subtitle, body, cycle['title'])
    return html, 200, {'Content-Type': 'text/html; charset=utf-8'}

# ── Cycle Assignments ─────────────────────────────────────────────────────────

@app.route('/api/cycle-assignments', methods=['GET'])
@require_auth()
def list_cycle_assignments():
    db = get_db()
    cycle_id = request.args.get('cycle_id')
    q = '''SELECT ca.*, v.name as volunteer_name, v.phone as volunteer_phone,
                  f.name as family_name
           FROM cycle_assignments ca
           JOIN volunteers v ON ca.volunteer_id = v.id
           LEFT JOIN families f ON ca.family_id = f.id
           WHERE 1=1'''
    params = []
    if cycle_id:
        q += " AND ca.cycle_id=?"; params.append(cycle_id)
    q += " ORDER BY ca.task_type, ca.task_date, ca.created_at"
    return jsonify([dict(r) for r in db.execute(q, params).fetchall()])

@app.route('/api/cycle-assignments', methods=['POST'])
@require_auth(roles=['admin'])
def create_cycle_assignment():
    data = request.json or {}
    if not data.get('cycle_id') or not data.get('volunteer_id') or not data.get('task_type'):
        return jsonify({'error': 'cycle_id, volunteer_id, task_type required'}), 422
    aid = str(uuid.uuid4())
    get_db().execute(
        '''INSERT INTO cycle_assignments
           (id, cycle_id, volunteer_id, family_id, task_type, task_date, task_time, status, notes, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (aid, data['cycle_id'], data['volunteer_id'], data.get('family_id'),
         data['task_type'], data.get('task_date'), data.get('task_time'),
         'pending', data.get('notes'), now())
    )
    get_db().commit()
    return jsonify({'id': aid}), 201

@app.route('/api/cycle-assignments/<aid>', methods=['PUT'])
@require_auth(roles=['admin'])
def update_cycle_assignment(aid):
    db = get_db()
    row = db.execute("SELECT * FROM cycle_assignments WHERE id=?", (aid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute(
        '''UPDATE cycle_assignments SET volunteer_id=?, family_id=?, task_date=?,
           task_time=?, status=?, notes=?, updated_at=? WHERE id=?''',
        (d.get('volunteer_id', row['volunteer_id']), d.get('family_id', row['family_id']),
         d.get('task_date', row['task_date']), d.get('task_time', row['task_time']),
         d.get('status', row['status']), d.get('notes', row['notes']), now(), aid)
    )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM cycle_assignments WHERE id=?", (aid,)).fetchone()))

@app.route('/my-order')
def my_order_page():
    return send_from_directory('public', 'my-order.html')

@app.route('/volunteer-signup')
def volunteer_signup_page():
    return send_from_directory('public', 'volunteer-signup.html')

# ── Public Intake (no auth) ───────────────────────────────────────────────────

@app.route('/api/intake', methods=['POST'])
def public_intake():
    data = request.json or {}
    if not data.get('name') or not data.get('phone'):
        return jsonify({'error': 'Name and phone are required'}), 422
    phone = _normalize_phone(data['phone'])
    if not phone:
        return jsonify({'error': 'A valid phone number is required'}), 422
    db = get_db()
    # Duplicate guard — block a second record for the same phone number
    existing = db.execute(
        "SELECT id, status FROM families WHERE phone=?", (phone,)
    ).fetchone()
    if existing:
        if existing['status'] == 'inactive':
            return jsonify({
                'error': 'duplicate',
                'message': 'This phone number was previously registered but is no longer active. '
                           'Please message your coordinator on WhatsApp to reactivate your account.'
            }), 409
        return jsonify({
            'error': 'duplicate',
            'message': 'This phone number is already registered. '
                       'If you cannot log in, please send a WhatsApp message to your coordinator.'
        }), 409
    fid = str(uuid.uuid4())
    family_code = _make_family_code(phone, data.get('family_size'), db_conn=db)
    db.execute(
        '''INSERT INTO families
           (id,name,phone,address,city,family_size,children_count,
            dietary_notes,frequency,income_range,status,source,family_code,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (fid, data['name'], phone, data.get('address'), data.get('city'),
         data.get('family_size'), data.get('children_count'), data.get('dietary_notes'),
         data.get('frequency'), data.get('income_range'),
         'pending', 'intake_form', family_code, now())
    )
    db.commit()
    log.info(f'New intake: {data["name"]} ({phone})')
    # Notify coordinator via WhatsApp
    try:
        coord = db.execute(
            "SELECT wa_phone, wa_apikey FROM users WHERE role='admin' AND active=1 AND wa_phone IS NOT NULL LIMIT 1"
        ).fetchone()
        if coord and coord['wa_phone'] and coord['wa_apikey']:
            msg = (f"New family intake submitted:\n"
                   f"Name: {data['name']}\n"
                   f"Phone: {phone}\n"
                   f"City: {data.get('city') or '—'}\n"
                   f"Family size: {data.get('family_size') or '—'}\n"
                   f"Please log in to review and approve.")
            _wa_send(coord['wa_phone'], coord['wa_apikey'], msg)
    except Exception as _e:
        log.warning(f'Intake WA notify failed: {_e}')
    return jsonify({'ok': True, 'message': 'Thank you. We will be in touch within 48 hours.'}), 201

@app.route('/api/volunteer-signup', methods=['POST'])
def public_volunteer_signup():
    data = request.json or {}
    if not data.get('name') or not data.get('phone'):
        return jsonify({'error': 'Name and phone are required'}), 422
    if not data.get('role'):
        return jsonify({'error': 'Please select a role'}), 422
    phone = _normalize_phone(data['phone'])
    if not phone:
        return jsonify({'error': 'A valid phone number is required'}), 422
    db = get_db()
    existing = db.execute("SELECT id, status FROM volunteers WHERE phone=?", (phone,)).fetchone()
    if existing:
        return jsonify({
            'error': 'duplicate',
            'message': 'This phone number is already registered as a volunteer. '
                       'Visit /portal to log in, or contact a coordinator for help.'
        }), 409
    vid = str(uuid.uuid4())
    db.execute(
        '''INSERT INTO volunteers
           (id,name,phone,email,role,availability,notes,status,source,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (vid, data['name'], phone, data.get('email'),
         data.get('role', 'shopper'), data.get('availability'),
         data.get('notes'), 'pending', 'signup_form', now())
    )
    db.commit()
    log.info(f'New volunteer signup: {data["name"]} ({phone})')
    # Notify coordinator via WhatsApp
    try:
        coord = db.execute(
            "SELECT wa_phone, wa_apikey FROM users WHERE role='admin' AND active=1 AND wa_phone IS NOT NULL LIMIT 1"
        ).fetchone()
        if coord and coord['wa_phone'] and coord['wa_apikey']:
            role_label = {'shopper':'Shopper','delivery':'Delivery','both':'Shopper + Delivery','general':'General'}.get(data.get('role',''), data.get('role',''))
            msg = (f"New volunteer signed up:\n"
                   f"Name: {data['name']}\n"
                   f"Phone: {phone}\n"
                   f"Role: {role_label}\n"
                   f"Please log in to review and activate.")
            _wa_send(coord['wa_phone'], coord['wa_apikey'], msg)
    except Exception as _e:
        log.warning(f'Volunteer signup WA notify failed: {_e}')
    return jsonify({'ok': True, 'message': 'Thank you for signing up. We will be in touch soon.'}), 201

# ── Static Pages ──────────────────────────────────────────────────────────────

@app.route('/')
def admin_index():
    return send_from_directory('public', 'index.html')

@app.route('/donate-stats')
def donate_stats_page():
    return send_from_directory('public', 'donate-stats.html')

@app.route('/intake')
def intake_page():
    return send_from_directory('public', 'intake.html')

@app.route('/volunteer')
def volunteer_page():
    from flask import redirect
    return redirect('/portal', code=301)

@app.route('/order')
def order_page():
    from flask import redirect
    return redirect('/intake', code=301)

@app.route('/confirm/<token>')
def confirm_page(token):
    return send_from_directory('public', 'confirm.html')

@app.route('/api/family/confirm/<token>', methods=['GET'])
def get_family_confirmation(token):
    """Public — family views their pre-populated bundle via confirmation token."""
    db = get_db()
    req = db.execute(
        '''SELECT fr.*, f.name as family_name, f.family_size, f.dietary_notes,
                  dc.title as cycle_title, dc.delivery_date_start, dc.delivery_date_end
           FROM food_requests fr
           JOIN families f  ON fr.family_id  = f.id
           JOIN delivery_cycles dc ON fr.cycle_id = dc.id
           WHERE fr.confirmation_token = ?''',
        (token,)
    ).fetchone()
    if not req:
        return jsonify({'error': 'Invalid or expired link'}), 404
    req = dict(req)

    # Get all active food items with bundle quantities and current selection
    items = db.execute(
        '''SELECT fi.id, fi.name, fi.unit, fc.name as category, fc.display_order as cat_order,
                  fi.display_order as item_order,
                  bq.quantity,
                  COALESCE(fri.selected, 1) as selected
           FROM food_items fi
           JOIN food_categories fc ON fi.category_id = fc.id
           LEFT JOIN bundle_quantities bq ON bq.food_item_id = fi.id AND bq.bundle_size = ?
           LEFT JOIN food_request_items fri ON fri.food_item_id = fi.id AND fri.request_id = ?
           WHERE fi.is_active = 1
           ORDER BY fc.display_order, fi.display_order''',
        (req['bundle_size'], req['id'])
    ).fetchall()

    req['items'] = [dict(i) for i in items]
    return jsonify(req)

@app.route('/api/family/confirm/<token>', methods=['POST'])
def submit_family_confirmation(token):
    """Public — family confirms, modifies, or skips their bundle."""
    db  = get_db()
    req = db.execute(
        "SELECT * FROM food_requests WHERE confirmation_token=?", (token,)
    ).fetchone()
    if not req:
        return jsonify({'error': 'Invalid or expired link'}), 404
    if req['status'] in ('skipped',):
        return jsonify({'error': 'This order has already been processed'}), 400

    data   = request.json or {}
    action = data.get('action', 'confirm')  # confirm | skip

    if action == 'skip':
        db.execute(
            "UPDATE food_requests SET status='skipped', confirmed_at=?, notes=?, updated_at=? WHERE id=?",
            (now(), data.get('notes', ''), now(), req['id'])  # type: ignore
        )
        _log_order_event(db, req['id'], 'auto_skipped', actor='family')
        db.commit()
        return jsonify({'ok': True, 'action': 'skipped'})

    # Capture previous selections for diff (items_edited vs first-time confirmed)
    was_confirmed = req['status'] == 'confirmed'
    prev_items = {}
    if was_confirmed:
        for _pi in db.execute(
            "SELECT fi.name, fri.selected FROM food_request_items fri JOIN food_items fi ON fri.food_item_id=fi.id WHERE fri.request_id=?",
            (req['id'],)
        ).fetchall():
            prev_items[_pi['name']] = _pi['selected']

    # Save item selections
    selected_ids = set(data.get('selected_items', []))
    all_items = db.execute("SELECT id, name FROM food_items WHERE is_active=1").fetchall()
    for item in all_items:
        is_selected = 1 if item['id'] in selected_ids else 0
        db.execute(
            '''INSERT INTO food_request_items (id, request_id, food_item_id, selected)
               VALUES (?,?,?,?)
               ON CONFLICT(request_id, food_item_id) DO UPDATE SET selected=?''',
            (str(uuid.uuid4()), req['id'], item['id'], is_selected, is_selected)
        )

    db.execute(
        "UPDATE food_requests SET status='confirmed', confirmed_at=?, notes=?, updated_at=? WHERE id=?",
        (now(), data.get('notes', ''), now(), req['id'])  # type: ignore
    )

    # Log event — items_edited if re-confirming, confirmed if first time
    if was_confirmed and prev_items:
        _added   = [it['name'] for it in all_items if it['id'] in selected_ids and prev_items.get(it['name'], 0) == 0]
        _removed = [n for n, sel in prev_items.items() if sel == 1 and n not in {it['name'] for it in all_items if it['id'] in selected_ids}]
        _log_order_event(db, req['id'], 'items_edited', actor='family',
                         payload={'added': _added, 'removed': _removed})
    else:
        _log_order_event(db, req['id'], 'confirmed', actor='family')

    # Ensure slots exist (safety net)
    _ensure_volunteer_slots(db, req['cycle_id'], req['family_id'])

    # Confirm any claimed volunteer slots and notify those volunteers
    cycle_row = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (req['cycle_id'],)).fetchone()
    family_row = db.execute("SELECT * FROM families WHERE id=?", (req['family_id'],)).fetchone()
    claimed_slots_conf = db.execute(
        '''SELECT vs.id, vs.task_type, v.name as vol_name, v.wa_phone, v.wa_apikey,
                  f.address, f.city, f.name as family_name
           FROM volunteer_slots vs
           JOIN volunteers v ON vs.claimed_by = v.id
           JOIN families f ON vs.family_id = f.id
           WHERE vs.cycle_id=? AND vs.family_id=? AND vs.status IN ('claimed','confirmed') ''',
        (req['cycle_id'], req['family_id'])
    ).fetchall()
    bundle_sz = family_row['bundle_size'] if family_row else 'M'
    item_lines_conf = []
    if claimed_slots_conf:
        item_rows_conf = db.execute(
            '''SELECT fi.name, fi.unit, bq.quantity, fc.name as category
               FROM food_request_items fri
               JOIN food_items fi ON fri.food_item_id = fi.id
               JOIN food_categories fc ON fi.category_id = fc.id
               LEFT JOIN bundle_quantities bq ON bq.food_item_id = fi.id AND bq.bundle_size = ?
               WHERE fri.request_id = ? AND fri.selected = 1
               ORDER BY fc.display_order, fi.name''',
            (bundle_sz, req['id'])
        ).fetchall()
        for ir in item_rows_conf:
            qty_str = f"{ir['quantity']} {ir['unit']}" if ir['quantity'] else ir['unit'] or ''
            item_lines_conf.append(f"  • {ir['name']}{(' — ' + qty_str) if qty_str else ''}")
    wa_sends_conf = []
    for slot in claimed_slots_conf:
        db.execute("UPDATE volunteer_slots SET status='confirmed', updated_at=? WHERE id=?", (now(), slot['id']))
        if slot['wa_phone'] and slot['wa_apikey']:
            if slot['task_type'] == 'shopping':
                items_text = '\n'.join(item_lines_conf) if item_lines_conf else '  (no items selected)'
                wa_sends_conf.append((slot['wa_phone'], slot['wa_apikey'],
                    f"✅ Order Confirmed — Shopping Task\n"
                    f"Family: {slot['family_name']}\n"
                    f"Delivery: {cycle_row['delivery_date_start'] if cycle_row else 'TBD'}\n\n"
                    f"Shopping list:\n{items_text}\n\nJazakAllah Khair!"))
            else:
                wa_sends_conf.append((slot['wa_phone'], slot['wa_apikey'],
                    f"✅ Order Confirmed — Delivery Task\n"
                    f"Family: {slot['family_name']}\n"
                    f"Delivery: {cycle_row['delivery_date_start'] if cycle_row else 'TBD'}\n"
                    f"Address: {slot['address'] or 'TBD'}, {slot['city'] or ''}\n\nJazakAllah Khair!"))

    db.commit()
    _wa_send_async(wa_sends_conf)  # fire-and-forget — response returns immediately
    return jsonify({'ok': True, 'action': 'confirmed'})

# ── PWA assets ────────────────────────────────────────────────────────────────

@app.route('/sw.js')
def service_worker():
    resp = send_from_directory('public', 'sw.js', mimetype='application/javascript')
    resp.headers['Service-Worker-Allowed'] = '/'
    resp.headers['Cache-Control'] = 'no-cache'
    return resp

@app.route('/manifest-family.json')
def manifest_family():
    return send_from_directory('public', 'manifest-family.json', mimetype='application/manifest+json')

@app.route('/manifest-volunteer.json')
def manifest_volunteer():
    return send_from_directory('public', 'manifest-volunteer.json', mimetype='application/manifest+json')

@app.route('/icons/<path:filename>')
def pwa_icons(filename):
    return send_from_directory('public/icons', filename)

# ── Public Food Order (no auth) ───────────────────────────────────────────────

@app.route('/api/public/bundle-items', methods=['GET'])
def public_bundle_items():
    """Public — return active food items with bundle quantities for a given size.
    Used by the family My Order portal so families can select/deselect items."""
    size = (request.args.get('size') or 'M').upper()
    if size not in ('S', 'M', 'L'):
        size = 'M'
    db = get_db()
    rows = db.execute(
        '''SELECT fi.id, fi.name, fi.unit,
                  fc.name as category, fc.display_order as cat_order,
                  fi.display_order as item_order,
                  COALESCE(bq.quantity, '0') as quantity
           FROM food_items fi
           JOIN food_categories fc ON fi.category_id = fc.id
           LEFT JOIN bundle_quantities bq
                  ON bq.food_item_id = fi.id AND bq.bundle_size = ?
           WHERE fi.is_active = 1 AND fc.is_active = 1
           ORDER BY fc.display_order, fi.display_order''',
        (size,)
    ).fetchall()
    # Group by category
    cats = {}
    for r in rows:
        cat = r['category']
        if cat not in cats:
            cats[cat] = []
        cats[cat].append({
            'id': r['id'],
            'name': r['name'],
            'unit': r['unit'],
            'quantity': r['quantity']
        })
    return jsonify([{'category': k, 'items': v} for k, v in cats.items()])

@app.errorhandler(Exception)
def handle_unhandled_exception(e):
    """Return JSON for unhandled Python exceptions; pass HTTP exceptions through normally."""
    if isinstance(e, HTTPException):
        return e  # 404, 405, etc. keep their proper status codes
    log.exception(f'Unhandled exception: {e}')
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/food-order/check', methods=['GET'])
def check_food_order_eligibility():
    """Return family info + all delivery cycles within next 30 days with per-cycle order state."""
    import json as _json
    from datetime import timedelta, date as _date
    phone = _normalize_phone(request.args.get('phone') or '')
    if not phone:
        return jsonify({'error': 'Phone number required'}), 400

    db = get_db()

    # Column safety guards
    for _col, _def in [('bundle_size','TEXT'), ('pending_bundle_size','TEXT'),
                       ('wa_phone','TEXT'), ('wa_apikey','TEXT'), ('updated_at','TEXT'),
                       ('family_notes','TEXT')]:
        try:
            db.execute(f'ALTER TABLE families ADD COLUMN {_col} {_def}')
        except Exception:
            pass
    try:
        db.execute('ALTER TABLE food_requests ADD COLUMN family_notes TEXT')
    except Exception:
        pass

    # Family lookup — active only.
    # Normalise stored phones on comparison so dashes/spaces/country-codes never block login.
    # Also auto-fix any un-normalised phone found, so the DB stays clean going forward.
    family = None
    try:
        last10 = phone[-10:] if len(phone) >= 10 else phone
        for r in db.execute(
            "SELECT id, name, family_size, family_code, bundle_size, pending_bundle_size, phone "
            "FROM families WHERE status='active' COLLATE NOCASE"
        ).fetchall():
            stored_norm = _normalize_phone(r['phone'] or '')
            if stored_norm == phone or stored_norm[-10:] == last10:
                family = dict(r)
                # Auto-fix: if stored phone had dashes/spaces, clean it now
                if r['phone'] != stored_norm:
                    try:
                        db.execute("UPDATE families SET phone=? WHERE id=?", (stored_norm, r['id']))
                        db.commit()
                        log.info(f'Auto-normalised phone for family {r["id"]}: {r["phone"]!r} → {stored_norm!r}')
                    except Exception:
                        pass
                break
    except Exception as exc:
        log.exception(f'check_food_order_eligibility lookup error: {exc}')
        return jsonify({'error': f'DB error: {exc}'}), 500

    if not family:
        all_phones = db.execute("SELECT phone, status FROM families").fetchall()
        log.warning(f'PHONE MISS — searched={phone!r} stored={[(r["phone"],r["status"]) for r in all_phones]}')
        coord = db.execute(
            "SELECT wa_phone FROM users WHERE role='admin' AND active=1 AND wa_phone IS NOT NULL LIMIT 1"
        ).fetchone()
        coord_phone = coord['wa_phone'] if coord else None
        wa_link = f'https://wa.me/{coord_phone}' if coord_phone else None
        return jsonify({
            'registered': False,
            'coordinator_wa': wa_link,
            'message': (
                'We could not find an active record for that phone number. '
                'Make sure you are using the same number you registered with, '
                'or send a WhatsApp message to your coordinator for help.'
            )
        })

    # Resolve bundle size for this family
    bundle_size = family['bundle_size'] or None
    if not bundle_size:
        sz = db.execute(
            "SELECT bundle_size FROM bundle_size_rules WHERE min_household<=? AND (max_household IS NULL OR max_household>=?) ORDER BY min_household DESC LIMIT 1",
            (family['family_size'] or 1, family['family_size'] or 1)
        ).fetchone()
        bundle_size = sz['bundle_size'] if sz else 'M'

    today   = _today_central()
    cutoff  = today + timedelta(days=365)  # 12-month visibility window

    # All non-delivered cycles within next 12 months
    upcoming_rows = db.execute(
        """SELECT * FROM delivery_cycles
           WHERE delivery_date_start >= ? AND delivery_date_start <= ?
             AND status NOT IN ('delivered')
           ORDER BY delivery_date_start""",
        (today.isoformat(), cutoff.isoformat())
    ).fetchall()

    # Also include any cycle outside that window where the family has a non-terminal active order
    extra_rows = db.execute(
        """SELECT dc.* FROM food_requests fr
           JOIN delivery_cycles dc ON fr.cycle_id = dc.id
           WHERE fr.family_id=? AND fr.status NOT IN ('skipped','cancelled','delivered')
             AND dc.status NOT IN ('delivered')
             AND (dc.delivery_date_start < ? OR dc.delivery_date_start > ?)
           ORDER BY dc.delivery_date_start""",
        (family['id'], today.isoformat(), cutoff.isoformat())
    ).fetchall()

    seen = {r['id'] for r in upcoming_rows}
    all_cycles = list(upcoming_rows)
    for r in extra_rows:
        if r['id'] not in seen:
            all_cycles.append(r)
            seen.add(r['id'])
    all_cycles.sort(key=lambda r: r['delivery_date_start'])

    def _build_items_for_selection(bsize):
        """Return bundle item list grouped by category for the order placement form."""
        rows = db.execute(
            '''SELECT fi.id, fi.name, fi.unit,
                      fc.name as category, fc.display_order as cat_order,
                      COALESCE(bq.quantity,'') as quantity
               FROM food_items fi
               JOIN food_categories fc ON fi.category_id=fc.id
               LEFT JOIN bundle_quantities bq ON bq.food_item_id=fi.id AND bq.bundle_size=?
               WHERE fi.is_active=1 AND fc.is_active=1
               ORDER BY fc.display_order, fi.display_order''',
            (bsize,)
        ).fetchall()
        cats = {}
        for r in rows:
            cats.setdefault(r['category'], []).append(
                {'id': r['id'], 'name': r['name'], 'unit': r['unit'], 'quantity': r['quantity']}
            )
        return [{'category': k, 'items': v} for k, v in cats.items()]

    def _build_order_obj(existing, cycle):
        """Build the full order object for a cycle where an order exists."""
        bsize = existing['bundle_size'] or bundle_size

        # Backfill items if the order has no item rows
        item_count = db.execute(
            "SELECT COUNT(*) FROM food_request_items WHERE request_id=?", (existing['id'],)
        ).fetchone()[0]
        if item_count == 0:
            all_items = db.execute("SELECT id FROM food_items WHERE is_active=1").fetchall()
            for it in all_items:
                try:
                    db.execute(
                        "INSERT OR IGNORE INTO food_request_items (id,request_id,food_item_id,selected) VALUES (?,?,?,1)",
                        (str(uuid.uuid4()), existing['id'], it['id'])
                    )
                except Exception:
                    pass
            db.commit()

        # Selected items grouped by category
        sel_rows = db.execute(
            '''SELECT fi.name, fi.unit, fc.name as category,
                      COALESCE(bq.quantity,'') as quantity
               FROM food_request_items fri
               JOIN food_items fi ON fri.food_item_id=fi.id
               JOIN food_categories fc ON fi.category_id=fc.id
               LEFT JOIN bundle_quantities bq ON bq.food_item_id=fi.id AND bq.bundle_size=?
               WHERE fri.request_id=? AND fri.selected=1
               ORDER BY fc.display_order, fi.display_order''',
            (bsize, existing['id'])
        ).fetchall()
        sel_cats = {}
        for r in sel_rows:
            sel_cats.setdefault(r['category'], []).append(
                {'name': r['name'], 'unit': r['unit'], 'quantity': r['quantity']}
            )

        # Full bundle list (for change-request checklist)
        full_rows = db.execute(
            '''SELECT fi.id, fi.name, fi.unit, fc.name as category,
                      COALESCE(bq.quantity,'') as quantity
               FROM food_items fi
               JOIN food_categories fc ON fi.category_id=fc.id
               LEFT JOIN bundle_quantities bq ON bq.food_item_id=fi.id AND bq.bundle_size=?
               ORDER BY fc.display_order, fi.display_order''',
            (bsize,)
        ).fetchall()
        full_cats = {}
        for r in full_rows:
            full_cats.setdefault(r['category'], []).append(
                {'id': r['id'], 'name': r['name'], 'unit': r['unit'], 'quantity': r['quantity']}
            )

        # Cancel / change-request eligibility
        try:
            ddt = _date.fromisoformat(cycle['delivery_date_start'])
            days_until  = (ddt - today).days
            _terminal   = existing['status'] in ('skipped', 'delivered', 'cancelled')
            can_cancel  = days_until >= 1 and not _terminal
            can_request_change = (
                not _terminal
                and 1 <= days_until <= 30
                and cycle['status'] not in ('shopping', 'delivered')
            )
        except Exception:
            can_cancel = can_request_change = False

        # Pending change request
        pending_cr = db.execute(
            "SELECT * FROM order_change_requests WHERE request_id=? AND status='pending' ORDER BY created_at DESC LIMIT 1",
            (existing['id'],)
        ).fetchone()
        pending_change_request = None
        if pending_cr:
            try:
                cr_payload = _json.loads(pending_cr['payload'])
            except Exception:
                cr_payload = {}
            pending_change_request = {
                'id':           pending_cr['id'],
                'family_notes': pending_cr['family_notes'],
                'payload':      cr_payload,
                'created_at':   pending_cr['created_at'],
            }
            can_request_change = False

        # Event timeline
        ev_rows = db.execute(
            "SELECT event_type, actor, payload, created_at FROM food_request_events WHERE request_id=? ORDER BY created_at ASC",
            (existing['id'],)
        ).fetchall()
        events_list = []
        for ev in ev_rows:
            try:
                pl = _json.loads(ev['payload'])
            except Exception:
                pl = {}
            events_list.append({
                'event_type': ev['event_type'],
                'actor':      ev['actor'],
                'payload':    pl,
                'created_at': ev['created_at'],
            })

        fn = None
        try:
            fn = existing['family_notes']
        except Exception:
            pass

        # Volunteer assignment — show who's signed up (name only, no contact info)
        vol_slots = db.execute(
            '''SELECT vs.task_type, vs.status as slot_status, v.name as vol_name
               FROM volunteer_slots vs
               JOIN volunteers v ON vs.claimed_by = v.id
               WHERE vs.cycle_id=? AND vs.family_id=? AND vs.status IN ('claimed','confirmed')
               ORDER BY vs.task_type''',
            (cycle['id'], family['id'])
        ).fetchall()
        volunteers = {}
        for vs in vol_slots:
            volunteers[vs['task_type']] = {
                'name': vs['vol_name'],
                'confirmed': vs['slot_status'] == 'confirmed',
            }

        return {
            'id':                    existing['id'],
            'status':                existing['status'],
            'bundle_size':           bsize,
            'family_notes':          fn,
            'selected_categories':   [{'category': k, 'items': v} for k, v in sel_cats.items()],
            'bundle_categories':     [{'category': k, 'items': v} for k, v in full_cats.items()],
            'can_cancel':            can_cancel,
            'can_request_change':    can_request_change,
            'pending_change_request': pending_change_request,
            'events':                events_list,
            'volunteers':            volunteers,  # {shopping: {name, confirmed}, delivery: {name, confirmed}}
        }

    cycles_data = []
    for cycle in all_cycles:
        existing = db.execute(
            "SELECT id, bundle_size, status, family_notes FROM food_requests WHERE cycle_id=? AND family_id=?",
            (cycle['id'], family['id'])
        ).fetchone()

        cycle_obj = {
            'id':                   cycle['id'],
            'title':                cycle['title'],
            'status':               cycle['status'],
            'delivery_date_start':  cycle['delivery_date_start'],
            'delivery_date_end':    cycle['delivery_date_end'],
            'order':                None,
            'can_place_order':      False,
            'items_for_selection':  [],
        }

        if existing:
            cycle_obj['order'] = _build_order_obj(existing, cycle)
        elif cycle['status'] == 'open':
            cycle_obj['can_place_order']     = True
            cycle_obj['items_for_selection'] = _build_items_for_selection(bundle_size)

        cycles_data.append(cycle_obj)

    # History: all past orders (delivered cycles OR terminal order statuses)
    history_rows = db.execute(
        """SELECT fr.id, fr.status, fr.bundle_size, fr.submitted_at,
                  dc.title as cycle_title, dc.delivery_date_start, dc.delivery_date_end
           FROM food_requests fr
           JOIN delivery_cycles dc ON fr.cycle_id=dc.id
           WHERE fr.family_id=? AND (dc.status='delivered' OR fr.status IN ('delivered','cancelled','skipped'))
           ORDER BY dc.delivery_date_start DESC LIMIT 30""",
        (family['id'],)
    ).fetchall()

    return jsonify({
        'registered':         True,
        'family_name':        family['name'],
        'family_id':          family['id'],
        'bundle_size':        bundle_size,
        'pending_bundle_size': family['pending_bundle_size'],
        'cycles':             cycles_data,
        'history':            [dict(r) for r in history_rows],
    })

@app.route('/api/food-order', methods=['POST'])
def submit_food_order():
    """Place a food order for a family. Accepts optional notes field."""
    data = request.json or {}
    # selected_items can be [] (family deselects all) — check key presence, not truthiness
    if not data.get('family_id') or not data.get('cycle_id') or 'selected_items' not in data:
        return jsonify({'error': 'family_id, cycle_id, and selected_items required'}), 422

    db = get_db()
    auto_update_cycle_statuses(db)

    # Validate cycle is open
    cycle = db.execute(
        "SELECT * FROM delivery_cycles WHERE id=? AND status='open'", (data['cycle_id'],)
    ).fetchone()
    if not cycle:
        return jsonify({'error': 'This delivery is not currently accepting orders.'}), 409

    # Validate family
    family = db.execute("SELECT * FROM families WHERE id=?", (data['family_id'],)).fetchone()
    if not family:
        return jsonify({'error': 'Family not found.'}), 404

    # Enforce one order per family per cycle
    if db.execute("SELECT id FROM food_requests WHERE cycle_id=? AND family_id=?",
                  (data['cycle_id'], data['family_id'])).fetchone():
        return jsonify({'error': 'You have already placed an order for this delivery.'}), 409

    # Determine bundle size — family override takes priority over size rules
    bundle_size = family['bundle_size'] or None
    if not bundle_size:
        size = db.execute(
            "SELECT bundle_size FROM bundle_size_rules WHERE min_household<=? AND (max_household IS NULL OR max_household>=?) ORDER BY min_household DESC LIMIT 1",
            (family['family_size'] or 1, family['family_size'] or 1)
        ).fetchone()
        bundle_size = size['bundle_size'] if size else 'M'

    ts  = now()
    rid = str(uuid.uuid4())
    family_notes = (data.get('notes') or '').strip()

    # Insert food request — try with family_notes, fallback for older schema
    try:
        db.execute(
            '''INSERT INTO food_requests
               (id, cycle_id, family_id, bundle_size, submitted_at, status, confirmed_at, family_notes)
               VALUES (?,?,?,?,?,?,?,?)''',
            (rid, data['cycle_id'], data['family_id'], bundle_size, ts, 'confirmed', ts, family_notes or None)
        )
    except Exception:
        db.execute(
            '''INSERT INTO food_requests
               (id, cycle_id, family_id, bundle_size, submitted_at, status, confirmed_at)
               VALUES (?,?,?,?,?,?,?)''',
            (rid, data['cycle_id'], data['family_id'], bundle_size, ts, 'confirmed', ts)
        )

    # Save item selections
    selected_ids = set(data.get('selected_items', []))
    all_items = db.execute("SELECT id FROM food_items WHERE is_active=1").fetchall()
    for item in all_items:
        db.execute(
            "INSERT INTO food_request_items (id, request_id, food_item_id, selected) VALUES (?,?,?,?)",
            (str(uuid.uuid4()), rid, item['id'], 1 if item['id'] in selected_ids else 0)
        )

    # Ensure slots exist (safety net — should already be pre-created)
    slots_created = _ensure_volunteer_slots(db, data['cycle_id'], data['family_id'])

    # Confirm any claimed volunteer slots and notify those volunteers
    claimed_slots = db.execute(
        '''SELECT vs.id, vs.task_type, v.name as vol_name, v.wa_phone, v.wa_apikey,
                  f.address, f.city, f.name as family_name, f.bundle_size as fam_bundle
           FROM volunteer_slots vs
           JOIN volunteers v ON vs.claimed_by = v.id
           JOIN families f ON vs.family_id = f.id
           WHERE vs.cycle_id=? AND vs.family_id=? AND vs.status IN ('claimed','confirmed') ''',
        (data['cycle_id'], data['family_id'])
    ).fetchall()

    # Build item list for shoppers (fetch selected items + quantities)
    item_lines = []
    if claimed_slots:
        item_rows = db.execute(
            '''SELECT fi.name, fi.unit, bq.quantity, fc.name as category
               FROM food_request_items fri
               JOIN food_items fi ON fri.food_item_id = fi.id
               JOIN food_categories fc ON fi.category_id = fc.id
               LEFT JOIN bundle_quantities bq ON bq.food_item_id = fi.id AND bq.bundle_size = ?
               WHERE fri.request_id = ? AND fri.selected = 1
               ORDER BY fc.display_order, fi.name''',
            (bundle_size, rid)
        ).fetchall()
        for ir in item_rows:
            qty_str = f"{ir['quantity']} {ir['unit']}" if ir['quantity'] else ir['unit'] or ''
            item_lines.append(f"  • {ir['name']}{(' — ' + qty_str) if qty_str else ''}")

    # Update slot statuses to confirmed (DB only — no WA yet)
    for slot in claimed_slots:
        db.execute(
            "UPDATE volunteer_slots SET status='confirmed', updated_at=? WHERE id=?",
            (now(), slot['id'])
        )

    # Audit log (before commit so it's in the same transaction)
    try:
        _log_order_event(db, rid, 'confirmed', 'family', {
            'source': 'portal',
            'items_count': len(selected_ids),
            'notes': family_notes or None,
        })
    except Exception:
        pass

    db.commit()  # ← commit everything first, then notify in background

    # Build all WA sends — snapshot to plain dicts (sqlite Row not safe across threads)
    wa_sends = []
    cycle_start = cycle['delivery_date_start']
    items_text  = '\n'.join(item_lines) if item_lines else '  (no items selected)'
    for slot in [dict(s) for s in claimed_slots]:
        if slot.get('wa_phone') and slot.get('wa_apikey'):
            if slot['task_type'] == 'shopping':
                msg = (f"✅ Order Confirmed — Shopping Task\n"
                       f"Family: {slot['family_name']}\n"
                       f"Delivery: {cycle_start}\n\n"
                       f"Shopping list:\n{items_text}\n\n"
                       f"JazakAllah Khair!")
            else:
                msg = (f"✅ Order Confirmed — Delivery Task\n"
                       f"Family: {slot['family_name']}\n"
                       f"Delivery: {cycle_start}\n"
                       f"Address: {slot.get('address') or 'TBD'}, {slot.get('city') or ''}\n\n"
                       f"JazakAllah Khair!")
            wa_sends.append((slot['wa_phone'], slot['wa_apikey'], msg))

    coord_msg = (
        f"New order placed via portal:\n"
        f"Family: {family['name']}\n"
        f"Cycle: {cycle['title']}\n"
        f"Items selected: {len(selected_ids)}"
        + (f"\nNotes: {family_notes}" if family_notes else '')
    )
    try:
        for a in db.execute(
            "SELECT wa_phone, wa_apikey FROM users WHERE role='admin' AND active=1 AND wa_phone IS NOT NULL AND wa_apikey IS NOT NULL"
        ).fetchall():
            wa_sends.append((a['wa_phone'], a['wa_apikey'], coord_msg))
    except Exception:
        pass

    _wa_send_async(wa_sends)  # fire-and-forget — response returns immediately

    log.info(f'Food order placed: family {data["family_id"]} cycle {data["cycle_id"]} — {slots_created} new slots, {len(claimed_slots)} slots confirmed')
    return jsonify({
        'ok': True,
        'request_id': rid,
        'message': 'Your order has been placed.',
        'delivery_start': cycle['delivery_date_start'],
        'delivery_end':   cycle['delivery_date_end'],
    }), 201

@app.route('/api/food-order/cancel', methods=['POST'])
def cancel_food_order():
    """Family cancels their confirmed order — allowed up to 24 hours before delivery (Central time)."""
    try:
        data      = request.json or {}
        family_id = data.get('family_id')
        request_id = data.get('request_id')
        if not family_id or not request_id:
            return jsonify({'error': 'family_id and request_id required'}), 422

        db  = get_db()
        req = db.execute(
            '''SELECT fr.*, dc.delivery_date_start, dc.title as cycle_title,
                      f.name as family_name, f.family_code
               FROM food_requests fr
               JOIN delivery_cycles dc ON fr.cycle_id=dc.id
               JOIN families f ON fr.family_id=f.id
               WHERE fr.id=? AND fr.family_id=?''',
            (request_id, family_id)
        ).fetchone()
        if not req:
            return jsonify({'error': 'Order not found'}), 404
        if req['status'] in ('skipped', 'delivered', 'cancelled'):
            return jsonify({'error': 'Order cannot be cancelled in its current state'}), 409

        # Enforce 24-hour cutoff using Central time
        try:
            from datetime import date as _date
            delivery_dt = _date.fromisoformat(req['delivery_date_start'])
            days_until  = (delivery_dt - _today_central()).days
        except Exception:
            days_until = 99  # unknown date — allow cancellation
        if days_until < 1:
            return jsonify({'error': 'Orders can only be cancelled at least 1 day before delivery'}), 409

        # Find claimed/confirmed volunteers BEFORE releasing slots (for notification)
        claimed_volunteers = db.execute(
            '''SELECT v.name, v.wa_phone, v.wa_apikey, vs.task_type
               FROM volunteer_slots vs
               JOIN volunteers v ON vs.claimed_by = v.id
               WHERE vs.cycle_id=? AND vs.family_id=? AND vs.status IN ('claimed','confirmed') ''',
            (req['cycle_id'], family_id)
        ).fetchall()

        # Mark as cancelled (not skipped — this is family-initiated)
        try:
            db.execute(
                "UPDATE food_requests SET status='cancelled', updated_at=? WHERE id=?",
                (now(), request_id)
            )
        except Exception:
            db.execute(
                "UPDATE food_requests SET status='cancelled' WHERE id=?",
                (request_id,)
            )

        # Release claimed + confirmed volunteer slots back to open
        try:
            db.execute(
                "UPDATE volunteer_slots SET prev_claimed_by=claimed_by, claimed_by=NULL, claimed_at=NULL, status='open', updated_at=? WHERE cycle_id=? AND family_id=? AND status IN ('claimed','confirmed')",
                (now(), req['cycle_id'], family_id)
            )
        except Exception:
            db.execute(
                "UPDATE volunteer_slots SET claimed_by=NULL, claimed_at=NULL, status='open' WHERE cycle_id=? AND family_id=? AND status IN ('claimed','confirmed')",
                (req['cycle_id'], family_id)
            )

        _log_order_event(db, request_id, 'cancelled', actor='family',
                         payload={'days_until_delivery': days_until})

        # Gather coordinator WA details before commit (still have DB context)
        coord_sends = []
        try:
            coord_msg = (
                f"Order cancelled by family:\n"
                f"Family: {req['family_name']} ({req['family_code']})\n"
                f"Cycle: {req['cycle_title']}\n"
                f"Days until delivery: {days_until}\n"
                f"Volunteer slots released back to open."
            )
            for a in db.execute(
                "SELECT wa_phone, wa_apikey FROM users WHERE role='admin' AND active=1 AND wa_phone IS NOT NULL AND wa_apikey IS NOT NULL"
            ).fetchall():
                coord_sends.append((a['wa_phone'], a['wa_apikey'], coord_msg))
        except Exception:
            pass

        # Gather volunteer notification sends
        vol_sends = []
        for vol in claimed_volunteers:
            if vol['wa_phone'] and vol['wa_apikey']:
                vol_sends.append((vol['wa_phone'], vol['wa_apikey'],
                    f"Update: {req['family_name']} has cancelled their food order for {req['cycle_title']}.\n"
                    f"Your {vol['task_type']} slot has been released — no action needed."
                ))

        db.commit()

        # Fire all WA notifications in background — response returns immediately
        _wa_send_async(coord_sends + vol_sends)

        log.info(f'Family {family_id} cancelled order {request_id} — {days_until} days before delivery')
        return jsonify({'ok': True, 'message': 'Your order has been cancelled.'})

    except Exception as _e:
        log.exception(f'cancel_food_order ERROR — family={family_id!r} request={request_id!r}')
        return jsonify({'error': f'Server error: {str(_e)}'}), 500


# ── Family Change Requests ────────────────────────────────────────────────────

@app.route('/api/family-request', methods=['POST'])
def submit_family_change_request():
    """Family submits a change request for their current order.
    One pending request per order at a time. Cycle must be open/upcoming, not shopping, within 30 days."""
    import json as _json
    try:
        data       = request.json or {}
        family_id  = data.get('family_id')
        request_id = data.get('request_id')
        family_notes = (data.get('family_notes') or '').strip()
        selected_item_ids = data.get('selected_item_ids') or []

        if not family_id or not request_id:
            return jsonify({'error': 'family_id and request_id required'}), 422

        db = get_db()

        # Verify the order belongs to this family
        req = db.execute(
            '''SELECT fr.*, dc.delivery_date_start, dc.status as cycle_status, dc.title as cycle_title,
                      f.name as family_name, f.wa_phone, f.wa_apikey
               FROM food_requests fr
               JOIN delivery_cycles dc ON fr.cycle_id = dc.id
               JOIN families f ON fr.family_id = f.id
               WHERE fr.id=? AND fr.family_id=?''',
            (request_id, family_id)
        ).fetchone()
        if not req:
            return jsonify({'error': 'Order not found'}), 404
        if req['status'] in ('cancelled', 'skipped', 'delivered'):
            return jsonify({'error': 'Cannot request changes for this order'}), 409
        if req['cycle_status'] in ('shopping', 'delivered'):
            return jsonify({'error': 'Changes are not allowed once shopping has started'}), 409

        # 30-day window check
        try:
            from datetime import date as _d
            days_until = (_d.fromisoformat(req['delivery_date_start']) - _today_central()).days
        except Exception:
            days_until = 99
        if days_until > 30:
            return jsonify({'error': 'Change requests can only be submitted within 30 days of delivery'}), 409
        if days_until < 1:
            return jsonify({'error': 'Delivery is too soon to request changes'}), 409

        # No duplicate pending request for this order
        existing = db.execute(
            "SELECT id FROM order_change_requests WHERE request_id=? AND status='pending'",
            (request_id,)
        ).fetchone()
        if existing:
            return jsonify({'error': 'You already have a pending change request for this order'}), 409

        # Build payload — item selections
        payload = _json.dumps({'selected_item_ids': selected_item_ids})

        # Resolve item names for the event log (so history shows human-readable items)
        requested_item_names = []
        if selected_item_ids:
            try:
                placeholders = ','.join('?' * len(selected_item_ids))
                requested_item_names = [
                    r['name'] for r in db.execute(
                        f"SELECT name FROM food_items WHERE id IN ({placeholders})",
                        list(selected_item_ids)
                    ).fetchall()
                ]
            except Exception:
                pass

        cr_id = str(uuid.uuid4())
        db.execute(
            '''INSERT INTO order_change_requests
               (id, family_id, cycle_id, request_id, status, family_notes, payload, created_at)
               VALUES (?,?,?,?,?,?,?,?)''',
            (cr_id, family_id, req['cycle_id'], request_id, 'pending', family_notes, payload, now())
        )
        _log_order_event(db, request_id, 'change_requested', actor='family',
                         payload={
                             'change_request_id': cr_id,
                             'notes':             family_notes,
                             'requested_items':   requested_item_names,
                         })
        db.commit()

        # Notify coordinators
        _notify_coordinators(db,
            f"Change request from family:\n"
            f"Family: {req['family_name']}\n"
            f"Cycle: {req['cycle_title']}\n"
            f"Notes: {family_notes or '(no notes)'}\n"
            f"Items selected: {len(selected_item_ids)}\n"
            f"Review in admin → Requests"
        )

        log.info(f'Change request {cr_id} submitted by family {family_id} for order {request_id}')
        return jsonify({'ok': True, 'change_request_id': cr_id})

    except Exception as _e:
        log.exception(f'submit_family_change_request ERROR')
        return jsonify({'error': f'Server error: {str(_e)}'}), 500


@app.route('/api/family-request/<cr_id>/retract', methods=['POST'])
def retract_family_change_request(cr_id):
    """Family retracts their pending change request."""
    try:
        data      = request.json or {}
        family_id = data.get('family_id')
        if not family_id:
            return jsonify({'error': 'family_id required'}), 422

        db = get_db()
        cr = db.execute(
            "SELECT * FROM order_change_requests WHERE id=? AND family_id=? AND status='pending'",
            (cr_id, family_id)
        ).fetchone()
        if not cr:
            return jsonify({'error': 'Request not found or already reviewed'}), 404

        db.execute(
            "UPDATE order_change_requests SET status='retracted', reviewed_at=? WHERE id=?",
            (now(), cr_id)
        )
        _log_order_event(db, cr['request_id'], 'change_retracted', actor='family',
                         payload={'change_request_id': cr_id})
        db.commit()
        return jsonify({'ok': True})

    except Exception as _e:
        log.exception('retract_family_change_request ERROR')
        return jsonify({'error': f'Server error: {str(_e)}'}), 500


# ── Admin Change Request Routes ───────────────────────────────────────────────

@app.route('/api/admin/change-requests')
@require_auth()
def list_change_requests():
    """Admin: list change requests. Default: pending only. ?status=all for all."""
    db = get_db()
    status_filter = request.args.get('status', 'pending')
    if status_filter == 'all':
        rows = db.execute(
            '''SELECT ocr.*, f.name as family_name, f.family_code,
                      dc.title as cycle_title, dc.delivery_date_start,
                      u.name as reviewed_by_name
               FROM order_change_requests ocr
               JOIN families f ON ocr.family_id = f.id
               JOIN delivery_cycles dc ON ocr.cycle_id = dc.id
               LEFT JOIN users u ON ocr.reviewed_by = u.id
               ORDER BY ocr.created_at DESC LIMIT 100''',
        ).fetchall()
    else:
        rows = db.execute(
            '''SELECT ocr.*, f.name as family_name, f.family_code,
                      dc.title as cycle_title, dc.delivery_date_start,
                      u.name as reviewed_by_name
               FROM order_change_requests ocr
               JOIN families f ON ocr.family_id = f.id
               JOIN delivery_cycles dc ON ocr.cycle_id = dc.id
               LEFT JOIN users u ON ocr.reviewed_by = u.id
               WHERE ocr.status=?
               ORDER BY ocr.created_at DESC''',
            (status_filter,)
        ).fetchall()

    import json as _json
    result = []
    for r in rows:
        row = dict(r)
        try:
            row['payload'] = _json.loads(row['payload'])
        except Exception:
            row['payload'] = {}
        # Attach current item names for the selected IDs
        selected_ids = row['payload'].get('selected_item_ids', [])
        if selected_ids:
            placeholders = ','.join('?' * len(selected_ids))
            item_rows = db.execute(
                f"SELECT fi.id, fi.name, fi.unit, fc.name as category FROM food_items fi JOIN food_categories fc ON fi.category_id=fc.id WHERE fi.id IN ({placeholders})",
                selected_ids
            ).fetchall()
            row['selected_items'] = [dict(i) for i in item_rows]
        else:
            row['selected_items'] = []
        result.append(row)
    return jsonify(result)


@app.route('/api/admin/change-requests/<cr_id>/approve', methods=['POST'])
@require_auth()
def approve_change_request(cr_id):
    """Admin approves a change request — automatically applies item changes to the order."""
    import json as _json
    try:
        data = request.json or {}
        admin_notes = (data.get('admin_notes') or '').strip()
        db = get_db()

        cr = db.execute(
            '''SELECT ocr.*, f.name as family_name, f.wa_phone, f.wa_apikey,
                      dc.title as cycle_title, dc.status as cycle_status
               FROM order_change_requests ocr
               JOIN families f ON ocr.family_id = f.id
               JOIN delivery_cycles dc ON ocr.cycle_id = dc.id
               WHERE ocr.id=? AND ocr.status='pending' ''',
            (cr_id,)
        ).fetchone()
        if not cr:
            return jsonify({'error': 'Request not found or already reviewed'}), 404

        # Parse requested items
        try:
            payload = _json.loads(cr['payload'])
        except Exception:
            payload = {}
        selected_ids = set(payload.get('selected_item_ids', []))

        # Capture item names BEFORE applying changes (for the event log)
        def _item_names_for_request(rid, selected_only=True):
            cond = "AND fri.selected=1" if selected_only else ""
            rows = db.execute(
                f'''SELECT fi.name FROM food_request_items fri
                    JOIN food_items fi ON fri.food_item_id=fi.id
                    WHERE fri.request_id=? {cond}
                    ORDER BY fi.name''',
                (rid,)
            ).fetchall()
            return [r['name'] for r in rows]

        items_before = _item_names_for_request(cr['request_id']) if cr['request_id'] else []

        # Apply item changes to the order
        if selected_ids and cr['request_id']:
            all_items = db.execute(
                "SELECT food_item_id FROM food_request_items WHERE request_id=?",
                (cr['request_id'],)
            ).fetchall()
            for item in all_items:
                new_selected = 1 if item['food_item_id'] in selected_ids else 0
                db.execute(
                    "UPDATE food_request_items SET selected=? WHERE request_id=? AND food_item_id=?",
                    (new_selected, cr['request_id'], item['food_item_id'])
                )

        # Capture item names AFTER applying changes
        items_after = _item_names_for_request(cr['request_id']) if cr['request_id'] else []
        added   = [n for n in items_after  if n not in set(items_before)]
        removed = [n for n in items_before if n not in set(items_after)]

        # Mark request approved
        db.execute(
            '''UPDATE order_change_requests
               SET status='approved', admin_notes=?, reviewed_by=?, reviewed_at=?
               WHERE id=?''',
            (admin_notes, g.user['user_id'], now(), cr_id)
        )

        _log_order_event(db, cr['request_id'], 'change_approved', actor='admin',
                         payload={
                             'change_request_id': cr_id,
                             'admin_notes':       admin_notes,
                             'items_before':      items_before,
                             'items_after':       items_after,
                             'added':             added,
                             'removed':           removed,
                         })
        db.commit()

        # WA to family
        if cr['wa_phone'] and cr['wa_apikey']:
            msg = f"Your change request for {cr['cycle_title']} has been approved."
            if admin_notes:
                msg += f"\nCoordinator note: {admin_notes}"
            _wa_send(cr['wa_phone'], cr['wa_apikey'], msg)

        log.info(f'Change request {cr_id} approved by {g.user["username"]}')
        return jsonify({'ok': True})

    except Exception as _e:
        log.exception(f'approve_change_request ERROR cr_id={cr_id}')
        return jsonify({'error': f'Server error: {str(_e)}'}), 500


@app.route('/api/admin/change-requests/<cr_id>/reject', methods=['POST'])
@require_auth()
def reject_change_request(cr_id):
    """Admin rejects a change request — order stays unchanged."""
    try:
        data = request.json or {}
        admin_notes = (data.get('admin_notes') or '').strip()
        db = get_db()

        cr = db.execute(
            '''SELECT ocr.*, f.name as family_name, f.wa_phone, f.wa_apikey,
                      dc.title as cycle_title
               FROM order_change_requests ocr
               JOIN families f ON ocr.family_id = f.id
               JOIN delivery_cycles dc ON ocr.cycle_id = dc.id
               WHERE ocr.id=? AND ocr.status='pending' ''',
            (cr_id,)
        ).fetchone()
        if not cr:
            return jsonify({'error': 'Request not found or already reviewed'}), 404

        db.execute(
            '''UPDATE order_change_requests
               SET status='rejected', admin_notes=?, reviewed_by=?, reviewed_at=?
               WHERE id=?''',
            (admin_notes, g.user['user_id'], now(), cr_id)
        )
        _log_order_event(db, cr['request_id'], 'change_rejected', actor='admin',
                         payload={'change_request_id': cr_id, 'admin_notes': admin_notes})
        db.commit()

        # WA to family
        if cr['wa_phone'] and cr['wa_apikey']:
            msg = f"Your change request for {cr['cycle_title']} was not approved."
            if admin_notes:
                msg += f"\nCoordinator note: {admin_notes}"
            _wa_send(cr['wa_phone'], cr['wa_apikey'], msg)

        log.info(f'Change request {cr_id} rejected by {g.user["username"]}')
        return jsonify({'ok': True})

    except Exception as _e:
        log.exception(f'reject_change_request ERROR cr_id={cr_id}')
        return jsonify({'error': f'Server error: {str(_e)}'}), 500


@app.route('/api/families/<fid>/reset-order', methods=['POST'])
@require_auth()
def reset_family_order(fid):
    """Admin resets a family's order for the most recent active cycle.
    - Cancelled / skipped orders: DELETED entirely so the family can place a fresh order.
    - Confirmed orders: reset to pending_confirmation (items cleared, no WA sent).
    """
    try:
        db = get_db()
        family = db.execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()
        if not family:
            return jsonify({'error': 'Family not found'}), 404

        # Find most recent non-delivered order
        req = db.execute(
            '''SELECT fr.* FROM food_requests fr
               JOIN delivery_cycles dc ON fr.cycle_id = dc.id
               WHERE fr.family_id=? AND fr.status != 'delivered'
               ORDER BY dc.delivery_date_start DESC LIMIT 1''',
            (fid,)
        ).fetchone()
        if not req:
            return jsonify({'error': 'No order found to reset'}), 404

        ts = now()

        if req['status'] in ('cancelled', 'skipped', 'pending_confirmation'):
            # Hard delete — frees the slot so family can place a fresh portal order
            db.execute("DELETE FROM food_request_events     WHERE request_id=?", (req['id'],))
            db.execute("DELETE FROM food_request_items      WHERE request_id=?", (req['id'],))
            db.execute("DELETE FROM order_change_requests   WHERE request_id=?", (req['id'],))
            db.execute("DELETE FROM food_requests           WHERE id=?",         (req['id'],))
            db.execute("UPDATE families SET pending_bundle_size=NULL WHERE id=? AND pending_bundle_size IS NOT NULL", (fid,))
            db.commit()
            log.info(f'Order {req["id"]} DELETED (status={req["status"]}) by admin {g.user["username"]} for family {fid}')
            return jsonify({'ok': True, 'message': 'Order cleared. Family can now place a fresh order.'})

        # Confirmed order: soft reset back to pending_confirmation
        try:
            db.execute(
                "UPDATE food_requests SET status='pending_confirmation', confirmed_at=NULL, updated_at=? WHERE id=?",
                (ts, req['id'])
            )
        except Exception:
            db.execute(
                "UPDATE food_requests SET status='pending_confirmation', confirmed_at=NULL WHERE id=?",
                (req['id'],)
            )
        db.execute("UPDATE food_request_items SET selected=0 WHERE request_id=?", (req['id'],))
        db.execute(
            "UPDATE order_change_requests SET status='retracted', reviewed_at=? WHERE request_id=? AND status='pending'",
            (ts, req['id'])
        )
        # Release any claimed/confirmed volunteer slots back to open on reset
        db.execute(
            "UPDATE volunteer_slots SET prev_claimed_by=claimed_by, claimed_by=NULL, claimed_at=NULL, status='open', updated_at=? WHERE cycle_id=? AND family_id=? AND status IN ('claimed','confirmed')",
            (ts, req['cycle_id'], fid)
        )
        # Clear any pending bundle size change request
        db.execute("UPDATE families SET pending_bundle_size=NULL WHERE id=? AND pending_bundle_size IS NOT NULL", (fid,))
        _log_order_event(db, req['id'], 'order_reset', actor='admin', payload={'reset_by': g.user['username']})
        db.commit()

        log.info(f'Order {req["id"]} reset to pending_confirmation by admin {g.user["username"]} for family {fid}')
        return jsonify({'ok': True, 'message': 'Order reset to pending confirmation.'})

    except Exception as _e:
        log.exception(f'reset_family_order ERROR fid={fid}')
        return jsonify({'error': f'Server error: {str(_e)}'}), 500


@app.route('/api/families/<fid>/cancel-order', methods=['POST'])
@require_auth()
def admin_cancel_family_order(fid):
    """Admin cancels a family's order for a specific cycle (or most recent non-delivered).
    Logs the cancellation with actor='admin' so the family portal can distinguish it from
    a family-initiated cancellation. The order row is then deleted so the family can
    re-order for that delivery slot.
    Optional JSON body: { cycle_id: <id>, reason: <str> }
    """
    try:
        db     = get_db()
        data   = request.json or {}
        reason = (data.get('reason') or '').strip()

        family = db.execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()
        if not family:
            return jsonify({'error': 'Family not found'}), 404

        # Find the target order
        if data.get('cycle_id'):
            req = db.execute(
                "SELECT fr.*, dc.title as cycle_title FROM food_requests fr "
                "JOIN delivery_cycles dc ON fr.cycle_id=dc.id "
                "WHERE fr.family_id=? AND fr.cycle_id=? AND fr.status != 'delivered' LIMIT 1",
                (fid, data['cycle_id'])
            ).fetchone()
        else:
            req = db.execute(
                '''SELECT fr.*, dc.title as cycle_title FROM food_requests fr
                   JOIN delivery_cycles dc ON fr.cycle_id = dc.id
                   WHERE fr.family_id=? AND fr.status != 'delivered'
                   ORDER BY dc.delivery_date_start DESC LIMIT 1''',
                (fid,)
            ).fetchone()

        if not req:
            return jsonify({'error': 'No active order found for this family'}), 404

        # Release any claimed/confirmed volunteer slots back to open
        try:
            db.execute(
                "UPDATE volunteer_slots SET prev_claimed_by=claimed_by, claimed_by=NULL, "
                "claimed_at=NULL, status='open', updated_at=? "
                "WHERE cycle_id=? AND family_id=? AND status IN ('claimed','confirmed')",
                (now(), req['cycle_id'], fid)
            )
        except Exception:
            db.execute(
                "UPDATE volunteer_slots SET claimed_by=NULL, claimed_at=NULL, status='open' "
                "WHERE cycle_id=? AND family_id=? AND status IN ('claimed','confirmed')",
                (req['cycle_id'], fid)
            )

        # Log BEFORE deleting so the event is recorded
        _log_order_event(db, req['id'], 'cancelled', actor='admin',
                         payload={'cancelled_by': g.user['username'],
                                  'reason': reason or None,
                                  'prev_status': req['status']})
        db.commit()

        # Now hard-delete the order row so the family can place a fresh order
        db.execute("DELETE FROM food_request_events   WHERE request_id=?", (req['id'],))
        db.execute("DELETE FROM food_request_items    WHERE request_id=?", (req['id'],))
        db.execute("DELETE FROM order_change_requests WHERE request_id=?", (req['id'],))
        db.execute("DELETE FROM food_requests         WHERE id=?",         (req['id'],))
        db.commit()

        log.info(f'Order {req["id"]} admin-cancelled by {g.user["username"]} for family {fid}')

        try:
            _notify_coordinators(db,
                f"Order admin-cancelled:\n"
                f"Family: {family['name']}\n"
                f"Cycle: {req['cycle_title']}\n"
                f"Cancelled by: {g.user['username']}"
                + (f"\nReason: {reason}" if reason else "")
            )
        except Exception:
            pass

        return jsonify({'ok': True, 'message': 'Order cancelled. Family can now place a fresh order.'})

    except Exception as _e:
        log.exception(f'admin_cancel_family_order ERROR fid={fid}')
        return jsonify({'error': f'Server error: {str(_e)}'}), 500


@app.route('/api/food-order/items', methods=['PUT'])
def edit_food_order_items():
    """Family edits their item selections — allowed up to 48 hours before delivery (Central time).
    Cycle must still be open or upcoming (not shopping/delivered).
    Cancel is final — cancelled orders cannot be edited."""
    import json as _json
    data       = request.json or {}
    phone      = _normalize_phone(data.get('phone') or '')
    request_id = data.get('request_id')
    selected_ids = set(data.get('selected_item_ids') or [])

    if not phone or not request_id:
        return jsonify({'error': 'phone and request_id required'}), 422

    db = get_db()

    # Phone lookup
    family = db.execute("SELECT * FROM families WHERE phone=? AND status='active'", (phone,)).fetchone()
    if not family:
        # fuzzy fallback
        for f in db.execute("SELECT * FROM families WHERE status='active'").fetchall():
            if (f['phone'] or '').endswith(phone[-10:]) or phone.endswith((f['phone'] or '')[-10:]):
                family = f
                break
    if not family:
        return jsonify({'error': 'Phone number not found'}), 404

    # Load request and its cycle
    req = db.execute(
        '''SELECT fr.*, dc.delivery_date_start, dc.status as cycle_status, dc.title as cycle_title,
                  f.name as family_name, f.family_code
           FROM food_requests fr
           JOIN delivery_cycles dc ON fr.cycle_id=dc.id
           JOIN families f ON fr.family_id=f.id
           WHERE fr.id=? AND fr.family_id=?''',
        (request_id, family['id'])
    ).fetchone()
    if not req:
        return jsonify({'error': 'Order not found'}), 404
    if req['status'] in ('cancelled', 'skipped', 'delivered'):
        return jsonify({'error': 'This order can no longer be edited'}), 409
    if req['cycle_status'] in ('shopping', 'delivered'):
        return jsonify({'error': 'Editing is no longer available — the shopping cycle has started'}), 409

    # Enforce 48-hour edit window using Central time
    try:
        from datetime import date as _date
        delivery_dt = _date.fromisoformat(req['delivery_date_start'])
        days_until  = (delivery_dt - _today_central()).days
    except Exception:
        days_until = 99
    if days_until < 2:
        return jsonify({'error': 'Item editing closes 48 hours before delivery'}), 409

    # Capture previous selections for diff (item names, not IDs)
    prev_rows = db.execute(
        "SELECT fi.id, fi.name, fri.selected FROM food_request_items fri JOIN food_items fi ON fri.food_item_id=fi.id WHERE fri.request_id=?",
        (request_id,)
    ).fetchall()
    prev_by_id = {r['id']: (r['name'], r['selected']) for r in prev_rows}

    # Get all active items to upsert
    all_items = db.execute("SELECT id, name FROM food_items WHERE is_active=1").fetchall()
    for item in all_items:
        is_sel = 1 if item['id'] in selected_ids else 0
        db.execute(
            '''INSERT INTO food_request_items (id, request_id, food_item_id, selected)
               VALUES (?,?,?,?)
               ON CONFLICT(request_id, food_item_id) DO UPDATE SET selected=?''',
            (str(uuid.uuid4()), request_id, item['id'], is_sel, is_sel)
        )

    try:
        db.execute("UPDATE food_requests SET updated_at=? WHERE id=?", (now(), request_id))
    except Exception:
        pass

    # Compute diff using names
    added   = [it['name'] for it in all_items if it['id'] in selected_ids and prev_by_id.get(it['id'], ('', 0))[1] == 0]
    removed = [name for iid, (name, sel) in prev_by_id.items() if sel == 1 and iid not in selected_ids]

    _log_order_event(db, request_id, 'items_edited', actor='family',
                     payload={'added': added, 'removed': removed, 'days_until_delivery': days_until})
    db.commit()

    # Notify coordinators if items changed
    if added or removed:
        added_str   = ', '.join(added)   if added   else 'none'
        removed_str = ', '.join(removed) if removed else 'none'
        _notify_coordinators(db,
            f"Order items updated by family:\n"
            f"Family: {req['family_name']} ({req['family_code']})\n"
            f"Cycle: {req['cycle_title']}\n"
            f"Added: {added_str}\n"
            f"Removed: {removed_str}"
        )
        # Notify claimed volunteers (shopping list may have changed) — fire-and-forget
        claimed_vols = db.execute(
            '''SELECT v.name, v.wa_phone, v.wa_apikey, vs.task_type
               FROM volunteer_slots vs JOIN volunteers v ON vs.claimed_by=v.id
               WHERE vs.cycle_id=? AND vs.family_id=? AND vs.status IN ('claimed','confirmed') AND vs.task_type='shopping' ''',
            (req['cycle_id'], family['id'])
        ).fetchall()
        vol_sends = [
            (v['wa_phone'], v['wa_apikey'],
             f"Shopping list update: {req['family_name']} edited their order for {req['cycle_title']}.\n"
             f"Added: {added_str}\nRemoved: {removed_str}\n"
             f"Please check the updated shopping list.")
            for v in claimed_vols if v['wa_phone'] and v['wa_apikey']
        ]
        _wa_send_async(vol_sends)

    log.info(f'Family {family["id"]} edited items for order {request_id}: +{added} -{removed}')
    return jsonify({'ok': True, 'added': added, 'removed': removed,
                    'message': 'Your order has been updated.'})


@app.route('/api/food-requests/<rid>/items', methods=['PUT'])
@require_auth(roles=['admin'])
def admin_edit_food_request_items(rid):
    """Admin edits item selections for a family's order on their behalf."""
    import json as _json
    data         = request.json or {}
    selected_ids = set(data.get('selected_item_ids') or [])

    db  = get_db()
    req = db.execute(
        '''SELECT fr.*, f.name as family_name, f.family_code, dc.title as cycle_title
           FROM food_requests fr
           JOIN families f ON fr.family_id=f.id
           JOIN delivery_cycles dc ON fr.cycle_id=dc.id
           WHERE fr.id=?''',
        (rid,)
    ).fetchone()
    if not req:
        return jsonify({'error': 'Order not found'}), 404

    # Capture previous selections
    prev_rows = db.execute(
        "SELECT fi.id, fi.name, fri.selected FROM food_request_items fri JOIN food_items fi ON fri.food_item_id=fi.id WHERE fri.request_id=?",
        (rid,)
    ).fetchall()
    prev_by_id = {r['id']: (r['name'], r['selected']) for r in prev_rows}

    all_items = db.execute("SELECT id, name FROM food_items WHERE is_active=1").fetchall()
    for item in all_items:
        is_sel = 1 if item['id'] in selected_ids else 0
        db.execute(
            '''INSERT INTO food_request_items (id, request_id, food_item_id, selected)
               VALUES (?,?,?,?)
               ON CONFLICT(request_id, food_item_id) DO UPDATE SET selected=?''',
            (str(uuid.uuid4()), rid, item['id'], is_sel, is_sel)
        )

    try:
        db.execute("UPDATE food_requests SET updated_at=? WHERE id=?", (now(), rid))
    except Exception:
        pass

    added   = [it['name'] for it in all_items if it['id'] in selected_ids and prev_by_id.get(it['id'], ('', 0))[1] == 0]
    removed = [name for iid, (name, sel) in prev_by_id.items() if sel == 1 and iid not in selected_ids]

    _log_order_event(db, rid, 'admin_override', actor='admin',
                     payload={'action': 'items_edited', 'added': added, 'removed': removed})
    db.commit()

    log.info(f'Admin edited items for order {rid}: +{added} -{removed}')
    return jsonify({'ok': True, 'added': added, 'removed': removed})


@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    # Files use UUID-based names — not guessable without the URL
    return send_from_directory(UPLOAD_FOLDER, filename)

# ── Public Volunteer Portal ───────────────────────────────────────────────────

@app.route('/portal')
def portal_page():
    return send_from_directory('public', 'portal.html')

# ── OTP Authentication ────────────────────────────────────────────────────────

@app.route('/api/otp/request', methods=['POST'])
def otp_request():
    """Step 1: validate phone, generate PIN, send via SMS.
    Body: {phone, type}  where type='family'|'volunteer'
    """
    import random
    data  = request.json or {}
    phone = _normalize_phone(data.get('phone') or '')
    kind  = data.get('type', 'volunteer')

    if not phone:
        return jsonify({'error': 'Phone number required'}), 400
    if kind not in ('family', 'volunteer'):
        return jsonify({'error': 'Invalid type'}), 400

    db = get_db()

    # Validate phone exists and is active
    if kind == 'volunteer':
        row = db.execute(
            "SELECT id FROM volunteers WHERE phone=? AND status='active'", (phone,)
        ).fetchone()
        if not row:
            return jsonify({'error': 'No active volunteer found with this number. '
                                     'Contact a coordinator if you need help.'}), 404
    else:
        row = db.execute(
            "SELECT id FROM families WHERE phone=? AND status='active'", (phone,)
        ).fetchone()
        if not row:
            # Try fuzzy match (same logic as food-order/check)
            all_fams = db.execute("SELECT id, phone FROM families WHERE status='active'").fetchall()
            row = next(
                (f for f in all_fams if _normalize_phone(f['phone'] or '') == phone), None
            )
        if not row:
            return jsonify({'error': 'No active family account found with this number. '
                                     'Contact us if you need help.'}), 404

    # Expire any existing unused tokens for this phone+type
    db.execute(
        "UPDATE otp_tokens SET used=1 WHERE phone=? AND type=? AND used=0",
        (phone, kind)
    )

    # Generate 6-digit code
    code = str(random.randint(100000, 999999))
    expires_at = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    db.execute(
        "INSERT INTO otp_tokens (id, phone, code, type, expires_at, used, created_at) VALUES (?,?,?,?,?,0,?)",
        (str(uuid.uuid4()), phone, code, kind, expires_at, now())
    )
    db.commit()

    # Send SMS
    msg = f'Your SIHAA verification code is: {code}\nExpires in 10 minutes. Do not share this code.'
    sent = _send_sms(phone, msg)
    if not sent:
        log.error(f'OTP SMS failed for {phone} — code was {code}')
        return jsonify({'error': 'Could not send SMS. Please try again or contact a coordinator.'}), 500

    return jsonify({'sent': True})


@app.route('/api/otp/verify', methods=['POST'])
def otp_verify():
    """Step 2: verify PIN, issue session.
    Body: {phone, code, type}
    For volunteers: returns {token, volunteer}
    For families:   returns {verified: true, phone}
    """
    data  = request.json or {}
    phone = _normalize_phone(data.get('phone') or '')
    code  = str(data.get('code') or '').strip()
    kind  = data.get('type', 'volunteer')

    if not phone or not code:
        return jsonify({'error': 'Phone and code required'}), 400

    db = get_db()
    token_row = db.execute(
        """SELECT * FROM otp_tokens
           WHERE phone=? AND code=? AND type=? AND used=0
             AND expires_at > ?
           ORDER BY created_at DESC LIMIT 1""",
        (phone, code, kind, now())
    ).fetchone()

    if not token_row:
        return jsonify({'error': 'Invalid or expired code. Request a new one.'}), 400

    # Burn the token
    db.execute("UPDATE otp_tokens SET used=1 WHERE id=?", (token_row['id'],))
    db.commit()

    if kind == 'volunteer':
        vol = db.execute(
            "SELECT * FROM volunteers WHERE phone=? AND status='active'", (phone,)
        ).fetchone()
        if not vol:
            return jsonify({'error': 'Volunteer account not found'}), 404
        session_token = str(uuid.uuid4())
        expires_at = (datetime.utcnow() + timedelta(hours=48)).isoformat()
        db.execute(
            "INSERT INTO portal_sessions (token, volunteer_id, expires_at, created_at) VALUES (?,?,?,?)",
            (session_token, vol['id'], expires_at, now())
        )
        db.commit()
        return jsonify({
            'token': session_token,
            'volunteer': {'id': vol['id'], 'name': vol['name'],
                          'phone': vol['phone'], 'role': vol['role']}
        })
    else:
        # Family — stateless, just return verified phone
        return jsonify({'verified': True, 'phone': phone})


@app.route('/api/portal/login', methods=['POST'])
def portal_login():
    data = request.json or {}
    phone = _normalize_phone(data.get('phone') or '')
    if not phone:
        return jsonify({'error': 'Phone number required'}), 400
    db = get_db()
    vol = db.execute(
        "SELECT * FROM volunteers WHERE phone=? AND status='active'", (phone,)
    ).fetchone()
    if not vol:
        return jsonify({'error': 'No active volunteer found with this phone number. '
                                 'Make sure you use the same number you signed up with, '
                                 'or contact a coordinator for help.'}), 404
    token = str(uuid.uuid4())
    expires_at = (datetime.utcnow() + timedelta(hours=48)).isoformat()
    db.execute(
        "INSERT INTO portal_sessions (token, volunteer_id, expires_at, created_at) VALUES (?,?,?,?)",
        (token, vol['id'], expires_at, now())
    )
    db.commit()
    return jsonify({
        'token': token,
        'volunteer': {'id': vol['id'], 'name': vol['name'],
                      'phone': vol['phone'], 'role': vol['role']}
    })

@app.route('/api/portal/cycles')
@require_portal_auth()
def portal_list_cycles():
    """Return all non-delivered cycles within the next 12 months — volunteers can sign up to any."""
    cutoff = (datetime.utcnow() + timedelta(days=365)).strftime('%Y-%m-%d')
    today  = datetime.utcnow().strftime('%Y-%m-%d')
    rows = get_db().execute(
        """SELECT * FROM delivery_cycles
           WHERE status NOT IN ('delivered')
             AND delivery_date_start >= ?
             AND delivery_date_start <= ?
           ORDER BY delivery_date_start ASC""",
        (today, cutoff)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/portal/slots/<cycle_id>')
@require_portal_auth()
def portal_get_slots(cycle_id):
    db = get_db()
    cycle = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cycle_id,)).fetchone()
    if not cycle:
        return jsonify({'error': 'Cycle not found'}), 404
    vol_id = g.pv['volunteer_id']
    slots = db.execute(
        '''SELECT vs.*, f.name as family_name, f.family_size, f.family_code,
                  1 as hide_address,
                  CASE WHEN vs.claimed_by=? THEN 1 ELSE 0 END as is_mine,
                  v.name as claimed_by_name
           FROM volunteer_slots vs
           JOIN families f ON vs.family_id = f.id
           LEFT JOIN volunteers v ON vs.claimed_by = v.id
           WHERE vs.cycle_id=? AND vs.status != 'cancelled'
           ORDER BY vs.task_type, f.name''',
        (vol_id, cycle_id)
    ).fetchall()
    result = []
    for s in slots:
        row = dict(s)
        # Delivery volunteers see address only for their own claimed slots
        if row['task_type'] == 'delivery' and row['claimed_by'] == vol_id:
            family = db.execute("SELECT address, city FROM families WHERE id=?", (s['family_id'],)).fetchone()
            row['family_address'] = f"{family['address']}, {family['city']}" if family else ''
        result.append(row)
    return jsonify({'cycle': dict(cycle), 'slots': result, 'volunteer_id': vol_id})

@app.route('/api/portal/claim', methods=['POST'])
@require_portal_auth()
def portal_claim_slot():
    slot_id = (request.json or {}).get('slot_id')
    if not slot_id:
        return jsonify({'error': 'slot_id required'}), 422
    db = get_db()
    slot = db.execute("SELECT * FROM volunteer_slots WHERE id=?", (slot_id,)).fetchone()
    if not slot:
        return jsonify({'error': 'Slot not found'}), 404
    if slot['status'] != 'open':
        return jsonify({'error': 'This slot has already been claimed'}), 409
    vol_id = g.pv['volunteer_id']
    db.execute(
        "UPDATE volunteer_slots SET claimed_by=?, claimed_at=?, status='claimed', updated_at=? WHERE id=?",
        (vol_id, now(), now(), slot_id)
    )
    db.commit()

    # WhatsApp confirmation
    vol = db.execute("SELECT * FROM volunteers WHERE id=?", (vol_id,)).fetchone()
    family = db.execute("SELECT * FROM families WHERE id=?", (slot['family_id'],)).fetchone()
    cycle = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (slot['cycle_id'],)).fetchone()
    if vol['wa_phone'] and vol['wa_apikey']:
        fcode = family['family_code'] or ''
        if slot['task_type'] == 'delivery':
            msg = (f"SIHAA Delivery Confirmed!\n"
                   f"Family ID: {fcode}\n"
                   f"Address: {family['address']}, {family['city']}\n"
                   f"Deliver by: {cycle['delivery_date_end']} (by 5pm)\n"
                   f"JazakAllah Khair!")
        else:
            size_row = db.execute(
                "SELECT bundle_size FROM bundle_size_rules WHERE min_household<=? AND (max_household IS NULL OR max_household>=?) ORDER BY min_household DESC LIMIT 1",
                (family['family_size'] or 1, family['family_size'] or 1)
            ).fetchone()
            bsize = size_row['bundle_size'] if size_row else 'M'
            items = db.execute(
                '''SELECT fi.name, bq.quantity FROM bundle_quantities bq
                   JOIN food_items fi ON bq.food_item_id=fi.id
                   WHERE bq.bundle_size=? AND fi.is_active=1 ORDER BY fi.display_order''', (bsize,)
            ).fetchall()
            item_list = '\n'.join([f"- {i['name']}: {i['quantity']}" for i in items])
            msg = (f"SIHAA Shopping Confirmed!\n"
                   f"Family ID: {fcode} (Bundle {bsize})\n"
                   f"Shopping list:\n{item_list}\n"
                   f"Drop off at Abu Baqr by Sunday 2pm.\n"
                   f"Send receipt to treasurer. JazakAllah Khair!")
        _wa_send(vol['wa_phone'], vol['wa_apikey'], msg)
    return jsonify({'ok': True})


@app.route('/api/portal/my-tasks')
@require_portal_auth()
def portal_my_tasks():
    vol_id = g.pv['volunteer_id']
    db = get_db()

    # Active + completed assignments (including confirmed slots)
    rows = db.execute(
        '''SELECT vs.*, f.name as family_name, f.address, f.city, f.family_size, f.family_code,
                  dc.title as cycle_title, dc.delivery_date_start, dc.delivery_date_end
           FROM volunteer_slots vs
           JOIN families f ON vs.family_id = f.id
           JOIN delivery_cycles dc ON vs.cycle_id = dc.id
           WHERE vs.claimed_by=? AND vs.status IN ('claimed','confirmed','complete')
           ORDER BY dc.delivery_date_start ASC, vs.task_type''',
        (vol_id,)
    ).fetchall()
    result = []
    for r in rows:
        row = dict(r)
        row['was_released'] = False
        if row['task_type'] == 'shopping':
            row['address'] = None
            row['city'] = None
            # For confirmed shopping slots, include item list so shopper knows what to buy
            if row['status'] == 'confirmed':
                items = db.execute(
                    '''SELECT fi.name, bq.qty_s, bq.qty_m, bq.qty_l, fr.bundle_size
                       FROM food_requests fr
                       JOIN food_request_items fri ON fri.request_id = fr.id
                       JOIN food_items fi ON fi.id = fri.item_id
                       LEFT JOIN bundle_quantities bq ON bq.item_id = fi.id
                       WHERE fr.cycle_id=? AND fr.family_id=?
                       ORDER BY fi.name''',
                    (row['cycle_id'], row['family_id'])
                ).fetchall()
                shopping_items = []
                for it in items:
                    bundle = it['bundle_size'] or 'M'
                    qty = it['qty_s'] if bundle == 'S' else it['qty_l'] if bundle == 'L' else it['qty_m']
                    shopping_items.append({
                        'name': it['name'],
                        'qty': qty or 1,
                        'bundle_size': bundle
                    })
                row['shopping_items'] = shopping_items
            else:
                row['shopping_items'] = None
        result.append(row)

    # Recently released slots — where this volunteer was the last holder
    # Only show slots from cycles in the last 60 days to avoid stale history
    released = db.execute(
        '''SELECT vs.*, f.name as family_name, f.family_code,
                  dc.title as cycle_title, dc.delivery_date_start, dc.delivery_date_end
           FROM volunteer_slots vs
           JOIN families f ON vs.family_id = f.id
           JOIN delivery_cycles dc ON vs.cycle_id = dc.id
           WHERE vs.prev_claimed_by=? AND vs.claimed_by != ?
             AND vs.status IN ('open','claimed')
             AND dc.delivery_date_start >= date('now', '-60 days')
           ORDER BY dc.delivery_date_start DESC, vs.task_type''',
        (vol_id, vol_id)
    ).fetchall()
    for r in released:
        row = dict(r)
        row['was_released'] = True
        row['address'] = None  # never show address for released assignments
        row['city'] = None
        result.append(row)

    return jsonify(result)

@app.route('/api/portal/complete/<slot_id>', methods=['POST'])
@require_portal_auth()
def portal_complete_slot(slot_id):
    db = get_db()
    vol_id = g.pv['volunteer_id']
    slot = db.execute(
        "SELECT * FROM volunteer_slots WHERE id=? AND claimed_by=?", (slot_id, vol_id)
    ).fetchone()
    if not slot:
        return jsonify({'error': 'Slot not found or not yours'}), 404
    ts = now()
    db.execute(
        "UPDATE volunteer_slots SET status='complete', completed_at=?, updated_at=? WHERE id=?",
        (ts, ts, slot_id)
    )
    # When a delivery slot is marked complete, auto-set delivered_at on the food_request
    if slot['task_type'] == 'delivery':
        db.execute(
            "UPDATE food_requests SET delivered_at=?, status='delivered' WHERE cycle_id=? AND family_id=? AND delivered_at IS NULL",
            (ts, slot['cycle_id'], slot['family_id'])
        )
    db.commit()
    return jsonify({'ok': True})

# ── Portal: Receipt Submission ────────────────────────────────────────────────

@app.route('/api/portal/receipts/upload', methods=['POST'])
@require_portal_auth()
def portal_upload_receipt_file():
    """Upload a receipt photo from the volunteer portal."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    f = request.files['file']
    if not f.filename or not allowed_file(f.filename):
        return jsonify({'error': 'Invalid file type. Use JPG, PNG, PDF, or HEIC.'}), 400
    filename = str(uuid.uuid4()) + '.' + secure_filename(f.filename).rsplit('.', 1)[-1].lower()
    f.save(os.path.join(UPLOAD_FOLDER, filename))
    return jsonify({'file_url': f'/uploads/{filename}'}), 201

@app.route('/api/portal/receipts', methods=['POST'])
@require_portal_auth()
def portal_submit_receipt():
    """Volunteer submits a receipt for a shopping task via the portal.
    Auto-creates a receipt record + pending reimbursement + notifies treasurer."""
    data   = request.json or {}
    vol_id = g.pv['volunteer_id']
    slot_id = data.get('slot_id')
    db = get_db()

    # Validate the slot belongs to this volunteer and is a shopping task
    if slot_id:
        slot = db.execute(
            "SELECT * FROM volunteer_slots WHERE id=? AND claimed_by=? AND task_type='shopping'",
            (slot_id, vol_id)
        ).fetchone()
        if not slot:
            return jsonify({'error': 'Shopping slot not found or not yours'}), 404

    amount = float(data.get('amount') or 0)
    store  = (data.get('store') or '').strip()
    pdate  = data.get('purchase_date') or now()[:10]
    furl   = data.get('file_url')
    fid    = slot['family_id'] if slot_id and slot else None

    # Check for existing receipt for this slot — update instead of reject
    existing = None
    if slot_id:
        existing = db.execute(
            "SELECT id FROM receipts WHERE slot_id=? AND volunteer_id=?", (slot_id, vol_id)
        ).fetchone()

    if existing:
        # Update the existing receipt — reset status to pending for re-review
        rid = existing['id']
        update_fields = [
            ('amount', amount), ('store', store), ('purchase_date', pdate),
            ('status', 'pending'), ('updated_at', now())
        ]
        if furl:  # only overwrite photo if a new one was uploaded
            update_fields.append(('file_url', furl))
        set_clause = ', '.join(f'{col}=?' for col, _ in update_fields)
        vals = [v for _, v in update_fields] + [rid]
        db.execute(f'UPDATE receipts SET {set_clause} WHERE id=?', vals)

        # Also reset the linked reimbursement to pending
        db.execute(
            "UPDATE reimbursements SET amount=?, status='pending', updated_at=? WHERE receipt_id=?",
            (amount, now(), rid)
        )
        reimb_row = db.execute("SELECT id FROM reimbursements WHERE receipt_id=?", (rid,)).fetchone()
        reimb_id  = reimb_row['id'] if reimb_row else None
        db.commit()

        try:
            vol_name = g.pv['name']
            subject  = f'Receipt Updated — ${amount:.2f} from {vol_name}'
            msg = (f'Volunteer updated their receipt via the Portal.\n'
                   f'Volunteer: {vol_name}\n'
                   f'Store: {store or "not specified"}\n'
                   f'Amount: ${amount:.2f}\n'
                   f'Date: {pdate}\n\n'
                   f'Log in to review: https://sihha-ops-hub-production.up.railway.app')
            _notify_treasurers(db, subject, msg)
        except Exception as e:
            log.warning(f'Treasurer notification failed: {e}')

        return jsonify({'receipt_id': rid, 'reimbursement_id': reimb_id, 'updated': True}), 200

    # New receipt
    rid    = str(uuid.uuid4())
    db.execute(
        '''INSERT INTO receipts
           (id, volunteer_id, family_id, store, purchase_date, amount, file_url, slot_id, status, notes, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
        (rid, vol_id, fid, store, pdate, amount, furl, slot_id, 'pending', data.get('notes'), now())
    )

    # Auto-create reimbursement request
    reimb_id = str(uuid.uuid4())
    db.execute(
        '''INSERT INTO reimbursements
           (id, receipt_id, volunteer_id, amount, status, created_at)
           VALUES (?,?,?,?,?,?)''',
        (reimb_id, rid, vol_id, amount, 'pending', now())
    )

    # Auto-complete the slot — submitting receipt IS the completion signal
    if slot_id:
        db.execute(
            "UPDATE volunteer_slots SET status='complete', completed_at=?, updated_at=? WHERE id=? AND status='claimed'",
            (now(), now(), slot_id)
        )

    db.commit()

    # Notify treasurers
    try:
        vol_name = g.pv['name']
        subject  = f'New Reimbursement Request — ${amount:.2f} from {vol_name}'
        msg = (f'New receipt submitted via Volunteer Portal.\n'
               f'Volunteer: {vol_name}\n'
               f'Store: {store or "not specified"}\n'
               f'Amount: ${amount:.2f}\n'
               f'Date: {pdate}\n\n'
               f'Log in to review: https://ops.sihha.org')
        _notify_treasurers(db, subject, msg)
    except Exception as e:
        log.warning(f'Treasurer notification failed: {e}')

    return jsonify({'receipt_id': rid, 'reimbursement_id': reimb_id}), 201

@app.route('/api/portal/receipts', methods=['GET'])
@require_portal_auth()
def portal_list_receipts():
    """Volunteer sees their own receipt submissions + reimbursement status."""
    vol_id = g.pv['volunteer_id']
    rows = get_db().execute(
        '''SELECT r.id, r.store, r.purchase_date, r.amount, r.file_url, r.slot_id,
                  r.status as receipt_status, r.created_at,
                  rb.id as reimbursement_id, rb.status as reimbursement_status,
                  rb.payment_method, rb.payment_ref, rb.paid_date
           FROM receipts r
           LEFT JOIN reimbursements rb ON rb.receipt_id = r.id
           WHERE r.volunteer_id=?
           ORDER BY r.created_at DESC''',
        (vol_id,)
    ).fetchall()
    return jsonify([dict(r) for r in rows])

# ── History Endpoints ─────────────────────────────────────────────────────────

@app.route('/api/families/<fid>/history')
@require_auth()
def family_history(fid):
    """Per-cycle order history for a family. Includes items and volunteer info."""
    db = get_db()
    family = db.execute("SELECT id, name, family_size FROM families WHERE id=?", (fid,)).fetchone()
    if not family:
        return jsonify({'error': 'Not found'}), 404

    orders = db.execute(
        '''SELECT fr.id, fr.cycle_id, fr.bundle_size, fr.submitted_at,
                  fr.status, fr.delivered_at,
                  dc.title as cycle_title,
                  dc.delivery_date_start, dc.delivery_date_end
           FROM food_requests fr
           JOIN delivery_cycles dc ON fr.cycle_id = dc.id
           WHERE fr.family_id=?
           ORDER BY fr.submitted_at DESC''',
        (fid,)
    ).fetchall()

    result = []
    for order in orders:
        o = dict(order)

        # Selected items
        items = db.execute(
            '''SELECT fi.name, fi.unit, fc.name as category
               FROM food_request_items fri
               JOIN food_items fi ON fri.food_item_id = fi.id
               JOIN food_categories fc ON fi.category_id = fc.id
               WHERE fri.request_id=? AND fri.selected=1
               ORDER BY fc.display_order, fi.display_order''',
            (o['id'],)
        ).fetchall()
        o['selected_items'] = [dict(i) for i in items]

        # Volunteer slots for this order
        slots = db.execute(
            '''SELECT vs.id, vs.task_type, vs.status, vs.completed_at,
                      v.name as volunteer_name, v.id as volunteer_id
               FROM volunteer_slots vs
               LEFT JOIN volunteers v ON vs.claimed_by = v.id
               WHERE vs.cycle_id=? AND vs.family_id=?''',
            (o['cycle_id'], fid)
        ).fetchall()
        o['slots'] = [dict(s) for s in slots]

        # Order event log
        import json as _json
        ev_rows = db.execute(
            "SELECT event_type, actor, payload, created_at FROM food_request_events WHERE request_id=? ORDER BY created_at ASC",
            (o['id'],)
        ).fetchall()
        o['events'] = []
        for ev in ev_rows:
            try:
                payload = _json.loads(ev['payload'])
            except Exception:
                payload = {}
            o['events'].append({
                'event_type': ev['event_type'],
                'actor': ev['actor'],
                'payload': payload,
                'created_at': ev['created_at']
            })

        result.append(o)

    # Current active cycle (open or shopping) — used by admin UI to show "Add to Cycle" button
    active_cycle = db.execute(
        "SELECT id, title, status, delivery_date_start FROM delivery_cycles WHERE status IN ('open','shopping') ORDER BY delivery_date_start LIMIT 1"
    ).fetchone()
    active_cycle_data = dict(active_cycle) if active_cycle else None

    return jsonify({'family': dict(family), 'orders': result, 'active_cycle': active_cycle_data})


@app.route('/api/volunteers/<vid>/history')
@require_auth()
def volunteer_history(vid):
    """Task history for a volunteer: lifetime stats + per-task log."""
    db = get_db()
    vol = db.execute("SELECT id, name, role FROM volunteers WHERE id=?", (vid,)).fetchone()
    if not vol:
        return jsonify({'error': 'Not found'}), 404

    tasks = db.execute(
        '''SELECT vs.id, vs.task_type, vs.status, vs.task_date,
                  vs.claimed_at, vs.completed_at,
                  dc.title as cycle_title, dc.delivery_date_start,
                  f.id as family_id, f.family_size
           FROM volunteer_slots vs
           JOIN delivery_cycles dc ON vs.cycle_id = dc.id
           JOIN families f ON vs.family_id = f.id
           WHERE vs.claimed_by=?
           ORDER BY vs.claimed_at DESC''',
        (vid,)
    ).fetchall()

    task_list = [dict(t) for t in tasks]

    # Lifetime stats
    total      = len(task_list)
    completed  = sum(1 for t in task_list if t['status'] == 'complete')
    shopping   = sum(1 for t in task_list if t['task_type'] == 'shopping')
    delivery   = sum(1 for t in task_list if t['task_type'] == 'delivery')
    cycles_served = len({t['cycle_title'] for t in task_list})
    families_served = len({t['family_id'] for t in task_list if t['status'] == 'complete'})

    return jsonify({
        'volunteer': dict(vol),
        'stats': {
            'total_tasks': total,
            'completed':   completed,
            'shopping':    shopping,
            'delivery':    delivery,
            'cycles_served':   cycles_served,
            'families_served': families_served,
        },
        'tasks': task_list
    })


@app.route('/api/portal/history')
@require_portal_auth()
def portal_history():
    """Volunteer's own history — privacy-safe: family_id only, no names or addresses."""
    db = get_db()
    vol_id = g.pv['volunteer_id']

    tasks = db.execute(
        '''SELECT vs.id, vs.task_type, vs.status, vs.task_date,
                  vs.claimed_at, vs.completed_at,
                  dc.title as cycle_title, dc.delivery_date_start,
                  f.id as family_id, f.family_size
           FROM volunteer_slots vs
           JOIN delivery_cycles dc ON vs.cycle_id = dc.id
           JOIN families f ON vs.family_id = f.id
           WHERE vs.claimed_by=? AND vs.status='complete'
           ORDER BY vs.completed_at DESC''',
        (vol_id,)
    ).fetchall()

    task_list = [dict(t) for t in tasks]

    completed  = len(task_list)
    shopping   = sum(1 for t in task_list if t['task_type'] == 'shopping')
    delivery   = sum(1 for t in task_list if t['task_type'] == 'delivery')
    cycles_served   = len({t['cycle_title'] for t in task_list})
    families_served = len({t['family_id'] for t in task_list})

    return jsonify({
        'stats': {
            'completed':       completed,
            'shopping':        shopping,
            'delivery':        delivery,
            'cycles_served':   cycles_served,
            'families_served': families_served,
        },
        'tasks': task_list
    })


# ── Admin: Generate Slots for a Cycle ─────────────────────────────────────────

@app.route('/api/delivery-cycles/<cid>/generate-slots', methods=['POST'])
@require_auth(roles=['admin'])
def generate_cycle_slots(cid):
    db = get_db()
    cycle = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cid,)).fetchone()
    if not cycle:
        return jsonify({'error': 'Cycle not found'}), 404
    requests = db.execute(
        "SELECT * FROM food_requests WHERE cycle_id=? AND status IN ('confirmed','auto_confirmed','submitted')", (cid,)
    ).fetchall()
    created = 0
    for req in requests:
        # Delegate to _ensure_volunteer_slots — it SELECT-firsts to prevent duplicates
        created += _ensure_volunteer_slots(db, cid, req['family_id'])
    db.commit()
    total_slots = db.execute(
        "SELECT COUNT(*) FROM volunteer_slots WHERE cycle_id=? AND status!='cancelled'", (cid,)
    ).fetchone()[0]
    return jsonify({'ok': True, 'slots_created': created, 'slots_total': total_slots, 'total_requests': len(requests)})

@app.route('/api/volunteer-slots')
@require_auth()
def list_volunteer_slots():
    db = get_db()
    cycle_id = request.args.get('cycle_id')
    q = '''SELECT vs.*, f.name as family_name, f.family_size, f.family_code,
                  v.name as claimed_by_name
           FROM volunteer_slots vs
           JOIN families f ON vs.family_id = f.id
           LEFT JOIN volunteers v ON vs.claimed_by = v.id
           WHERE 1=1'''
    params = []
    if cycle_id:
        q += " AND vs.cycle_id=?"; params.append(cycle_id)
    q += " ORDER BY vs.task_type, f.name"
    return jsonify([dict(r) for r in db.execute(q, params).fetchall()])

@app.route('/api/volunteer-slots/<sid>', methods=['PUT'])
@require_auth(roles=['admin'])
def update_volunteer_slot(sid):
    db = get_db()
    slot = db.execute("SELECT * FROM volunteer_slots WHERE id=?", (sid,)).fetchone()
    if not slot:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}

    # Support assigning / unassigning a volunteer
    old_claimed_by = slot['claimed_by']
    claimed_by = d.get('claimed_by', old_claimed_by)
    # If a volunteer is being assigned, auto-set status to claimed
    if 'claimed_by' in d:
        default_status = 'claimed' if d['claimed_by'] else 'open'
    else:
        default_status = slot['status']

    # Track previous holder when slot is released or reassigned
    prev_claimed_by = slot.get('prev_claimed_by')
    if 'claimed_by' in d and old_claimed_by and old_claimed_by != d.get('claimed_by'):
        prev_claimed_by = old_claimed_by

    db.execute(
        """UPDATE volunteer_slots
           SET status=?, notes=?, task_date=?, claimed_by=?, prev_claimed_by=?, updated_at=?
           WHERE id=?""",
        (d.get('status', default_status), d.get('notes', slot['notes']),
         d.get('task_date', slot['task_date']), claimed_by, prev_claimed_by, now(), sid)
    )
    db.commit()

    # Notify the displaced volunteer via WA
    if 'claimed_by' in d and old_claimed_by and old_claimed_by != d.get('claimed_by'):
        try:
            old_vol = db.execute(
                "SELECT name, wa_phone, wa_apikey FROM volunteers WHERE id=?", (old_claimed_by,)
            ).fetchone()
            if old_vol and old_vol['wa_phone'] and old_vol['wa_apikey']:
                # Get family name for context
                fam = db.execute(
                    "SELECT f.name, dc.title FROM families f JOIN delivery_cycles dc ON dc.id=? WHERE f.id=?",
                    (slot['cycle_id'], slot['family_id'])
                ).fetchone()
                fam_name = fam['name'] if fam else 'a family'
                cycle_title = fam['title'] if fam else ''
                action = 'reassigned to another volunteer' if d.get('claimed_by') else 'released back to open'
                _wa_send(old_vol['wa_phone'], old_vol['wa_apikey'],
                    f"Update: Your {slot['task_type']} assignment for {fam_name} ({cycle_title}) has been {action} by a coordinator. "
                    f"No action needed from you."
                )
        except Exception as _e:
            log.warning(f'update_volunteer_slot: WA notify failed: {_e}')

    row = db.execute(
        """SELECT vs.*, v.name as volunteer_name
           FROM volunteer_slots vs
           LEFT JOIN volunteers v ON vs.claimed_by = v.id
           WHERE vs.id=?""", (sid,)
    ).fetchone()
    return jsonify(dict(row))

# ── Task Types ────────────────────────────────────────────────────────────────

@app.route('/api/task-types')
def list_task_types():
    db = get_db()
    rows = db.execute(
        "SELECT slug, label, display_order, is_active, is_family_slot FROM volunteer_task_types ORDER BY display_order, label"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/task-types', methods=['POST'])
@require_auth(roles=['admin'])
def create_task_type():
    d = request.json or {}
    label = (d.get('label') or '').strip()
    if not label:
        return jsonify({'error': 'label required'}), 422
    slug = label.lower().replace(' ', '_').replace('-', '_')
    db = get_db()
    if db.execute("SELECT slug FROM volunteer_task_types WHERE slug=?", (slug,)).fetchone():
        return jsonify({'error': 'Task type already exists'}), 409
    order = db.execute("SELECT COALESCE(MAX(display_order),0)+1 FROM volunteer_task_types").fetchone()[0]
    is_family_slot = 1 if d.get('is_family_slot') else 0
    db.execute(
        "INSERT INTO volunteer_task_types (slug, label, display_order, is_active, is_family_slot) VALUES (?,?,?,1,?)",
        (slug, label, order, is_family_slot)
    )
    db.commit()
    return jsonify({'slug': slug, 'label': label, 'display_order': order, 'is_active': 1, 'is_family_slot': is_family_slot}), 201

@app.route('/api/task-types/<slug>', methods=['PUT'])
@require_auth(roles=['admin'])
def update_task_type(slug):
    db = get_db()
    tt = db.execute("SELECT * FROM volunteer_task_types WHERE slug=?", (slug,)).fetchone()
    if not tt:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute(
        "UPDATE volunteer_task_types SET label=?, display_order=?, is_active=?, is_family_slot=? WHERE slug=?",
        (d.get('label', tt['label']), d.get('display_order', tt['display_order']),
         int(d.get('is_active', tt['is_active'])),
         int(d.get('is_family_slot', tt['is_family_slot'] if 'is_family_slot' in tt.keys() else 0)),
         slug)
    )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM volunteer_task_types WHERE slug=?", (slug,)).fetchone()))

# ── Volunteer Slot Admin ───────────────────────────────────────────────────────

@app.route('/api/volunteer-slots', methods=['POST'])
@require_auth(roles=['admin'])
def create_volunteer_slot():
    db = get_db()
    d = request.json or {}
    cycle_id   = d.get('cycle_id')
    family_id  = d.get('family_id')
    task_type  = d.get('task_type')
    claimed_by = d.get('claimed_by')
    if not all([cycle_id, family_id, task_type, claimed_by]):
        return jsonify({'error': 'cycle_id, family_id, task_type, claimed_by required'}), 422
    # Prevent duplicate assignment
    if db.execute(
        "SELECT id FROM volunteer_slots WHERE cycle_id=? AND family_id=? AND task_type=? AND claimed_by=?",
        (cycle_id, family_id, task_type, claimed_by)
    ).fetchone():
        return jsonify({'error': 'Volunteer already assigned to this task'}), 409
    cycle = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cycle_id,)).fetchone()
    slot_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO volunteer_slots (id,cycle_id,family_id,task_type,task_date,claimed_by,claimed_at,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (slot_id, cycle_id, family_id, task_type,
         cycle['delivery_date_start'] if cycle else None,
         claimed_by, now(), 'claimed', now())
    )
    db.commit()
    row = db.execute(
        "SELECT vs.*, v.name as volunteer_name FROM volunteer_slots vs LEFT JOIN volunteers v ON vs.claimed_by=v.id WHERE vs.id=?",
        (slot_id,)
    ).fetchone()
    return jsonify(dict(row)), 201

@app.route('/api/volunteer-slots/<sid>', methods=['DELETE'])
@require_auth(roles=['admin'])
def delete_volunteer_slot(sid):
    db = get_db()
    if not db.execute("SELECT id FROM volunteer_slots WHERE id=?", (sid,)).fetchone():
        return jsonify({'error': 'Not found'}), 404
    db.execute("DELETE FROM volunteer_slots WHERE id=?", (sid,))
    db.commit()
    return jsonify({'ok': True})

# ── Portal: Family Sign-up ─────────────────────────────────────────────────────

@app.route('/api/portal/families/<cycle_id>')
@require_portal_auth()
def portal_get_families(cycle_id):
    """Families enrolled in a cycle with the current volunteer's per-task signup status."""
    db = get_db()
    cycle = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cycle_id,)).fetchone()
    if not cycle:
        return jsonify({'error': 'Cycle not found'}), 404
    vol_id = g.pv['volunteer_id']

    # Only join to orders that are genuinely confirmed (not pending, cancelled, or skipped)
    families = db.execute(
        '''SELECT f.id, f.name, f.family_size, f.family_code, f.address, f.city,
                  fr.status as order_status, fr.id as request_id
           FROM families f
           LEFT JOIN food_requests fr ON fr.family_id = f.id AND fr.cycle_id = ?
                                     AND fr.status IN ('confirmed','submitted','delivered')
           WHERE f.status = 'active'
           ORDER BY f.name''',
        (cycle_id,)
    ).fetchall()

    task_types = db.execute(
        "SELECT slug, label, is_family_slot FROM volunteer_task_types WHERE is_active=1 ORDER BY display_order, label"
    ).fetchall()

    result = []
    for fam in families:
        fam_dict = dict(fam)
        # Ensure open slots exist (idempotent — creates only if missing)
        _ensure_volunteer_slots(db, cycle_id, fam['id'])
        slots = db.execute(
            '''SELECT vs.id, vs.task_type, vs.claimed_by, vs.status,
                      v.name as claimed_by_name
               FROM volunteer_slots vs
               LEFT JOIN volunteers v ON vs.claimed_by = v.id
               WHERE vs.cycle_id=? AND vs.family_id=? AND vs.status!='cancelled'
               ORDER BY vs.claimed_at''',
            (cycle_id, fam['id'])
        ).fetchall()
        my_slots    = {}   # {task_type: slot_id}  — slots I claimed/confirmed
        my_status   = {}   # {task_type: 'claimed'|'confirmed'}
        taken_by    = {}   # {task_type: volunteer_name}  — slots taken by someone else
        vol_counts  = {}   # {task_type: total_count}
        for s in slots:
            tt = s['task_type']
            vol_counts[tt] = vol_counts.get(tt, 0) + 1
            if s['claimed_by'] == vol_id:
                my_slots[tt]  = s['id']
                my_status[tt] = s['status']
            elif s['claimed_by'] and s['status'] in ('claimed', 'confirmed'):
                if tt not in taken_by:
                    taken_by[tt] = s['claimed_by_name'] or 'A volunteer'
        fam_dict['my_slots']         = my_slots
        fam_dict['my_status']        = my_status   # 'claimed' = pending order, 'confirmed' = order placed
        fam_dict['taken_by']         = taken_by
        fam_dict['volunteer_counts'] = vol_counts
        # Address only for volunteers signed up for delivery on a confirmed order
        if 'delivery' not in my_slots:
            fam_dict['address'] = None
            fam_dict['city']    = None
        result.append(fam_dict)

    db.commit()  # Persist any slots created by _ensure_volunteer_slots above

    return jsonify({
        'cycle':      dict(cycle),
        'families':   result,
        'task_types': [dict(t) for t in task_types]
    })

@app.route('/api/portal/signup', methods=['POST'])
@require_portal_auth()
def portal_signup():
    """Volunteer claims the open slot for a family+task in a cycle.
    One volunteer per slot — claims the existing open slot rather than creating a new row."""
    d = request.json or {}
    cycle_id   = d.get('cycle_id')
    family_id  = d.get('family_id')
    task_types = d.get('task_types', [])
    if not cycle_id or not family_id or not task_types:
        return jsonify({'error': 'cycle_id, family_id, task_types required'}), 422
    vol_id = g.pv['volunteer_id']
    db = get_db()
    cycle  = db.execute("SELECT * FROM delivery_cycles WHERE id=?", (cycle_id,)).fetchone()
    family = db.execute("SELECT * FROM families WHERE id=?", (family_id,)).fetchone()
    if not cycle:
        return jsonify({'error': 'Cycle not found'}), 404

    claimed = []
    ts = now()
    for task_type in task_types:
        # Already mine — skip silently
        if db.execute(
            "SELECT id FROM volunteer_slots WHERE cycle_id=? AND family_id=? AND task_type=? AND claimed_by=? AND status='claimed'",
            (cycle_id, family_id, task_type, vol_id)
        ).fetchone():
            continue

        # Already taken by someone else?  Check BEFORE touching the open slot.
        taken = db.execute(
            '''SELECT v.name FROM volunteer_slots vs
               JOIN volunteers v ON vs.claimed_by = v.id
               WHERE vs.cycle_id=? AND vs.family_id=? AND vs.task_type=?
                 AND vs.status='claimed' AND vs.claimed_by != ?''',
            (cycle_id, family_id, task_type, vol_id)
        ).fetchone()
        if taken:
            return jsonify({'error': f'{task_type.capitalize()} is already assigned to {taken["name"]}'}), 409

        # Claim the existing open slot (created by _ensure_volunteer_slots)
        open_slot = db.execute(
            "SELECT id FROM volunteer_slots WHERE cycle_id=? AND family_id=? AND task_type=? AND status='open'",
            (cycle_id, family_id, task_type)
        ).fetchone()

        if open_slot:
            db.execute(
                "UPDATE volunteer_slots SET claimed_by=?, claimed_at=?, status='claimed', updated_at=? WHERE id=?",
                (vol_id, ts, ts, open_slot['id'])
            )
        else:
            # Safety fallback: no pre-created slot (old cycle or edge case) — insert one
            db.execute(
                "INSERT INTO volunteer_slots (id,cycle_id,family_id,task_type,task_date,claimed_by,claimed_at,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), cycle_id, family_id, task_type, cycle['delivery_date_start'], vol_id, ts, 'claimed', ts)
            )
        claimed.append(task_type)

    db.commit()

    # WhatsApp confirmation
    if claimed:
        vol_row = db.execute("SELECT * FROM volunteers WHERE id=?", (vol_id,)).fetchone()
        vol = dict(vol_row) if vol_row else {}
        fam = dict(family) if family else {}
        if vol.get('wa_phone') and vol.get('wa_apikey'):
            fcode      = fam.get('family_code', '')
            task_label = ', '.join(t.capitalize() for t in claimed)
            msg = (f"SIHAA Confirmed: {task_label}\n"
                   f"Family: {fcode} · Size: {fam.get('family_size', '?')}\n"
                   f"Delivery: {cycle['delivery_date_start']}\n"
                   f"JazakAllah Khair!")
            if 'delivery' in claimed and fam.get('address'):
                msg += f"\nAddress: {fam['address']}, {fam.get('city', '')}"
            _wa_send(vol['wa_phone'], vol['wa_apikey'], msg)

    return jsonify({'ok': True, 'claimed': claimed}), 201

@app.route('/api/portal/cancel/<slot_id>', methods=['DELETE'])
@require_portal_auth()
def portal_cancel_slot(slot_id):
    """Volunteer releases their slot back to open so another volunteer can claim it."""
    vol_id = g.pv['volunteer_id']
    db = get_db()
    slot = db.execute(
        "SELECT * FROM volunteer_slots WHERE id=? AND claimed_by=?", (slot_id, vol_id)
    ).fetchone()
    if not slot:
        return jsonify({'error': 'Not found or not yours'}), 404
    # Release back to open — preserve prev_claimed_by for portal history
    db.execute(
        "UPDATE volunteer_slots SET prev_claimed_by=claimed_by, claimed_by=NULL, claimed_at=NULL, status='open', updated_at=? WHERE id=?",
        (now(), slot_id)
    )
    db.commit()
    return jsonify({'ok': True})

# ── WhatsApp Reminders ────────────────────────────────────────────────────────

def _send_reminders_job():
    """Core reminder logic. Called by scheduler and by the admin trigger endpoint.
    Uses a direct DB connection (no Flask request context needed).
    DB-idempotent: reminder_log UNIQUE(slot_id, sent_to) prevents double-sends
    even when both gunicorn workers run the job simultaneously."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        target_date = (datetime.utcnow() + timedelta(days=2)).strftime('%Y-%m-%d')
        slots = conn.execute(
            '''SELECT vs.*, v.name as vol_name, v.wa_phone, v.wa_apikey,
                      f.name as family_name, f.family_code, f.address, f.city
               FROM volunteer_slots vs
               JOIN volunteers v ON vs.claimed_by = v.id
               JOIN families f ON vs.family_id = f.id
               WHERE vs.status='claimed' AND vs.task_date=?
               AND v.wa_phone IS NOT NULL AND v.wa_apikey IS NOT NULL''',
            (target_date,)
        ).fetchall()
        sent = 0
        for s in slots:
            try:
                conn.execute(
                    "INSERT INTO reminder_log (id,slot_id,sent_to,sent_at) VALUES (?,?,?,?)",
                    (str(uuid.uuid4()), s['id'], s['wa_phone'], datetime.utcnow().isoformat())
                )
                conn.commit()
            except sqlite3.IntegrityError:
                continue  # Already sent to this volunteer for this slot
            fcode = s['family_code'] or ''
            if s['task_type'] == 'delivery':
                msg = (f"SIHAA Reminder: Delivery in 2 days!\n"
                       f"Family ID: {fcode}\n"
                       f"Address: {s['address']}, {s['city']}\n"
                       f"Deliver by 5pm. JazakAllah Khair!")
            else:
                msg = (f"SIHAA Reminder: Shopping in 2 days!\n"
                       f"Family ID: {fcode}\n"
                       f"Drop off at Abu Baqr by Sunday 2pm.\n"
                       f"Send receipt to treasurer. JazakAllah Khair!")
            if _wa_send(s['wa_phone'], s['wa_apikey'], msg):
                sent += 1
        log.info(f'Reminders: {sent} sent for target date {target_date}')
        return sent, target_date
    finally:
        conn.close()

@app.route('/api/admin/wipe-test-data', methods=['POST'])
@require_auth(roles=['admin'])
def wipe_test_data():
    """Wipe all operational data. Preserves: users, food catalog, donations, sessions."""
    db = get_db()
    db.execute('PRAGMA foreign_keys=OFF')
    counts = {}
    for t in ['reminder_log','portal_sessions','food_request_items','food_requests',
              'volunteer_slots','receipts','reimbursements','cycle_assignments',
              'delivery_cycles','volunteers','families']:
        try:
            n = db.execute(f'SELECT COUNT(*) FROM {t}').fetchone()[0]
            db.execute(f'DELETE FROM {t}')
            counts[t] = n
        except Exception:
            counts[t] = 0
    db.execute('PRAGMA foreign_keys=ON')
    db.commit()
    log.info(f'wipe-test-data: {counts}')
    return jsonify({'ok': True, 'wiped': counts})


@app.route('/api/admin/import-historical', methods=['POST'])
@require_auth(roles=['admin'])
def import_historical():
    """Import real families, volunteers and historical cycles in one shot.
    Bypasses auto-enrollment — handles delivery matrix directly."""
    data = request.json or {}
    db   = get_db()
    n    = now()

    results = {'families': 0, 'volunteers': 0, 'cycles': 0, 'food_requests': 0, 'errors': []}

    # ── Families ─────────────────────────────────────────────────────────────
    fam_id_map = {}  # name → id
    for f in data.get('families', []):
        fid = str(uuid.uuid4())
        # Derive family_size from bundle_size
        bsize = f.get('bundle_size', 'M')
        size_map = {'S': 2, 'M': 4, 'L': 6}
        family_size = size_map.get(bsize, 4)
        # Generate family_code
        phone = f.get('phone', '')
        digits = ''.join(c for c in phone if c.isdigit())
        code = digits[-4:] + bsize if digits else fid[:4].upper()
        try:
            db.execute(
                '''INSERT INTO families
                   (id,name,phone,address,city,family_size,dietary_notes,status,
                    source,family_code,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
                (fid, f['name'], phone, f.get('address',''),
                 f.get('city','Rochester'), family_size,
                 f.get('dietary_notes',''), 'active', 'import', code, n)
            )
            fam_id_map[f['name']] = fid
            results['families'] += 1
        except Exception as e:
            results['errors'].append(f"Family {f['name']}: {e}")

    # ── Volunteers ───────────────────────────────────────────────────────────
    vol_id_map = {}  # name → id
    for v in data.get('volunteers', []):
        vid = str(uuid.uuid4())
        try:
            db.execute(
                '''INSERT INTO volunteers
                   (id,name,phone,email,status,source,created_at)
                   VALUES (?,?,?,?,?,?,?)''',
                (vid, v['name'], v.get('phone',''), v.get('email',''),
                 'active', 'import', n)
            )
            vol_id_map[v['name']] = vid
            results['volunteers'] += 1
        except Exception as e:
            results['errors'].append(f"Volunteer {v['name']}: {e}")

    db.commit()

    # ── Food items for pre-populating requests ───────────────────────────────
    all_items = [r['id'] for r in db.execute("SELECT id FROM food_items WHERE is_active=1").fetchall()]

    # ── Historical cycles ────────────────────────────────────────────────────
    for cyc in data.get('cycles', []):
        cid = str(uuid.uuid4())
        try:
            db.execute(
                '''INSERT INTO delivery_cycles
                   (id,title,delivery_date_start,delivery_date_end,
                    request_open_at,request_close_at,status,notes,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)''',
                (cid, cyc['title'], cyc['delivery_date_start'], cyc['delivery_date_end'],
                 '', '', 'delivered', 'Imported from historical records', n)
            )
            results['cycles'] += 1
        except Exception as e:
            results['errors'].append(f"Cycle {cyc['title']}: {e}")
            continue

        # Create food_request for every family — confirmed if they received, skipped otherwise
        delivered_names = set(cyc.get('delivered_families', []))
        for fname, fid in fam_id_map.items():
            status = 'confirmed' if fname in delivered_names else 'skipped'
            token  = str(uuid.uuid4())
            rid    = str(uuid.uuid4())
            try:
                db.execute(
                    '''INSERT INTO food_requests
                       (id,cycle_id,family_id,bundle_size,submitted_at,status,
                        confirmation_token,confirmed_at)
                       VALUES (?,?,?,?,?,?,?,?)''',
                    (rid, cid, fid, 'M', cyc['delivery_date_start'],
                     status, token,
                     cyc['delivery_date_end'] if status == 'confirmed' else None)
                )
                if status == 'confirmed':
                    for item_id in all_items:
                        db.execute(
                            'INSERT OR IGNORE INTO food_request_items (id,request_id,food_item_id,selected) VALUES (?,?,?,1)',
                            (str(uuid.uuid4()), rid, item_id)
                        )
                results['food_requests'] += 1
            except Exception as e:
                results['errors'].append(f"food_request {fname}/{cyc['title']}: {e}")

    db.commit()
    log.info(f'import-historical: {results}')
    return jsonify({'ok': True, 'results': results})


@app.route('/api/admin/seed-cycles-2026', methods=['POST'])
@require_auth(roles=['admin'])
def seed_cycles_2026():
    """Create all bi-weekly 2026 delivery cycles (May–Dec). Idempotent — skips existing."""
    from datetime import date, timedelta

    def build_cycles():
        cycles = []
        d = date(2026, 5, 9)   # first Saturday after April 25-26 delivery
        while d <= date(2026, 12, 31):
            sat = d
            sun = d + timedelta(days=1)
            order_close = sat - timedelta(days=7)
            order_open  = sat - timedelta(days=13)
            month_name  = sat.strftime('%B')
            cycles.append({
                'title':               f'{month_name} {sat.day}–{sun.day}, 2026',
                'delivery_date_start': sat.isoformat(),
                'delivery_date_end':   sun.isoformat(),
                'request_open_at':     f'{order_open.isoformat()}T08:00:00',
                'request_close_at':    f'{order_close.isoformat()}T23:59:00',
                'status':              'upcoming',
                'notes':               'Auto-seeded by admin endpoint',
            })
            d += timedelta(days=14)
        return cycles

    db = get_db()
    cycles_to_seed = build_cycles()

    # Fix schema before any inserts
    try:
        _fix_delivery_cycles_schema(db)
    except Exception as _e:
        log.error(f'seed_cycles_2026: schema fix failed: {_e}')
        return jsonify({'error': f'Schema migration failed: {_e}'}), 500

    # Wipe any existing 2026 cycles (regardless of status) and reseed cleanly
    deleted = db.execute(
        "DELETE FROM delivery_cycles WHERE delivery_date_start >= '2026-01-01'"
    ).rowcount
    db.commit()

    created = 0
    cycle_ids = []
    for c in cycles_to_seed:
        cid = str(uuid.uuid4())
        db.execute(
            '''INSERT INTO delivery_cycles
               (id, title, delivery_date_start, delivery_date_end,
                request_open_at, request_close_at, status, notes, created_by, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (cid, c['title'], c['delivery_date_start'], c['delivery_date_end'],
             c['request_open_at'], c['request_close_at'], 'upcoming', c['notes'],
             g.user['user_id'], now())
        )
        created += 1
        cycle_ids.append(cid)
    db.commit()
    # Pre-create volunteer slots for all active families across all new cycles
    total_slots = 0
    try:
        for cid in cycle_ids:
            total_slots += _pre_create_slots_for_cycle(db, cid)
        db.commit()
    except Exception as _e:
        log.warning(f'seed-cycles-2026: slot pre-creation failed: {_e}')
    log.info(f'seed-cycles-2026: deleted={deleted}, created={created}, slots_created={total_slots}')
    return jsonify({'ok': True, 'created': created, 'deleted': deleted, 'slots_created': total_slots})


@app.route('/api/reminders/trigger', methods=['POST'])
@require_auth(roles=['admin'])
def trigger_reminders():
    """Admin manual trigger — also used if Railway Cron is configured."""
    sent, target_date = _send_reminders_job()
    return jsonify({'ok': True, 'reminders_sent': sent, 'target_date': target_date})


@app.route('/api/admin/db-debug', methods=['GET'])
@require_auth(roles=['admin'])
def db_debug():
    """Diagnostic: show delivery_cycles schema + all rows."""
    try:
        db = get_db()
        schema_row = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='delivery_cycles'"
        ).fetchone()
        schema_str = schema_row['sql'] if schema_row else None

        cycles_raw = db.execute(
            "SELECT id, title, delivery_date_start, status FROM delivery_cycles ORDER BY delivery_date_start"
        ).fetchall()
        cycles = [{'id': r['id'], 'title': r['title'],
                   'date': r['delivery_date_start'], 'status': r['status']}
                  for r in cycles_raw]

        test_error = None
        try:
            test_id = '__dbdebug_test__'
            db.execute(
                "INSERT INTO delivery_cycles (id,title,delivery_date_start,delivery_date_end,request_open_at,request_close_at,status,created_by,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (test_id,'Test','2099-01-01','2099-01-02','','','upcoming','diag','2026-01-01')
            )
            db.execute("DELETE FROM delivery_cycles WHERE id=?", (test_id,))
            db.commit()
        except Exception as e:
            test_error = str(e)

        return jsonify({
            'ok': True,
            'schema_has_upcoming': 'upcoming' in (schema_str or ''),
            'schema': schema_str,
            'cycle_count': len(cycles),
            'cycles': cycles,
            'upcoming_insert_test': 'OK' if test_error is None else f'FAILED: {test_error}'
        })
    except Exception as e:
        import traceback
        return jsonify({'ok': False, 'error': str(e), 'traceback': traceback.format_exc()}), 500

def _send_family_confirmation_reminders():
    """7 days before delivery: create food_requests for all active families then WhatsApp opt-in link.
    Families who have wa_phone + wa_apikey get a WA message.
    Families without WA credentials get a food_request created (admin handles manually).
    Idempotent — confirmation_sent_at prevents double-sends; INSERT OR IGNORE prevents duplicate records."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        target = (datetime.utcnow() + timedelta(days=7)).strftime('%Y-%m-%d')
        # Cutoff = T-5 (when _skip_nonresponding_families fires) = today + 2 days from now
        # We tell families to respond within 2 days, matching the actual auto-skip deadline
        cutoff_date = (datetime.utcnow() + timedelta(days=2)).strftime('%Y-%m-%d')
        base_url = os.environ.get('APP_URL', 'https://sihha-ops-hub-production.up.railway.app')

        # Find the cycle(s) with delivery_date_start = target
        # Include 'open' (Accepting Orders) as well as 'upcoming' — coordinator may have already
        # advanced the cycle before T-7, which is the normal flow
        cycles = conn.execute(
            "SELECT * FROM delivery_cycles WHERE delivery_date_start = ? AND status IN ('upcoming','open')",
            (target,)
        ).fetchall()

        for cycle in cycles:
            cycle_id = cycle['id']
            # Create food_requests for ALL active families (INSERT OR IGNORE — idempotent)
            families = conn.execute(
                "SELECT id, family_size FROM families WHERE status = 'active'"
            ).fetchall()
            items = conn.execute(
                "SELECT id FROM food_items WHERE is_active = 1"
            ).fetchall()
            for fam in families:
                bsize_row = conn.execute(
                    "SELECT bundle_size FROM bundle_size_rules WHERE min_household<=? AND (max_household IS NULL OR max_household>=?) ORDER BY min_household DESC LIMIT 1",
                    (fam['family_size'] or 1, fam['family_size'] or 1)
                ).fetchone()
                bsize = bsize_row['bundle_size'] if bsize_row else 'M'
                token = str(uuid.uuid4())
                rid   = str(uuid.uuid4())
                try:
                    conn.execute(
                        '''INSERT OR IGNORE INTO food_requests
                           (id, cycle_id, family_id, bundle_size, submitted_at, status, confirmation_token)
                           VALUES (?,?,?,?,?,?,?)''',
                        (rid, cycle_id, fam['id'], bsize, datetime.utcnow().isoformat(), 'pending_confirmation', token)
                    )
                    # Pre-populate items as selected (INSERT OR IGNORE — safe if record already existed)
                    req_row = conn.execute(
                        "SELECT id, confirmation_token FROM food_requests WHERE cycle_id=? AND family_id=?",
                        (cycle_id, fam['id'])
                    ).fetchone()
                    if req_row:
                        for item in items:
                            conn.execute(
                                'INSERT OR IGNORE INTO food_request_items (id, request_id, food_item_id, selected) VALUES (?,?,?,1)',
                                (str(uuid.uuid4()), req_row['id'], item['id'])
                            )
                except Exception as _e:
                    log.warning(f'_send_family_confirmation_reminders: insert error for family {fam["id"]}: {_e}')
            conn.commit()

        # Now send WA to families who have credentials and haven't been notified yet
        rows = conn.execute(
            '''SELECT fr.id, fr.confirmation_token, fr.bundle_size,
                      f.name as family_name, f.wa_phone, f.wa_apikey,
                      dc.title as cycle_title, dc.delivery_date_start
               FROM food_requests fr
               JOIN families f ON fr.family_id = f.id
               JOIN delivery_cycles dc ON fr.cycle_id = dc.id
               WHERE dc.delivery_date_start = ?
                 AND fr.status = 'pending_confirmation'
                 AND fr.confirmation_sent_at IS NULL
                 AND f.wa_phone IS NOT NULL AND f.wa_apikey IS NOT NULL''',
            (target,)
        ).fetchall()

        sent = 0
        for r in rows:
            link = f"{base_url}/confirm/{r['confirmation_token']}"
            msg  = (f"Assalamu Alaikum {r['family_name']}!\n\n"
                    f"SIHAA has a food delivery on {r['delivery_date_start']}.\n"
                    f"Would you like to receive your bundle?\n\n"
                    f"Tap to review your items and confirm or decline:\n{link}\n\n"
                    f"Please respond by {cutoff_date}.\n"
                    f"JazakAllah Khair!")
            if _wa_send(r['wa_phone'], r['wa_apikey'], msg):
                conn.execute(
                    "UPDATE food_requests SET confirmation_sent_at=? WHERE id=?",
                    (datetime.utcnow().isoformat(), r['id'])
                )
                sent += 1
        conn.commit()
        log.info(f'Family opt-in notifications: {sent} WA sent for delivery {target}')
        return sent
    finally:
        conn.close()

def _skip_nonresponding_families():
    """5 days before delivery (cutoff): mark all pending_confirmation families as skipped.
    These families did not respond to the opt-in WA — they are excluded from the shopping list."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        target = (datetime.utcnow() + timedelta(days=5)).strftime('%Y-%m-%d')
        rows = conn.execute(
            '''SELECT fr.id FROM food_requests fr
               JOIN delivery_cycles dc ON fr.cycle_id = dc.id
               WHERE dc.delivery_date_start = ?
                 AND fr.status = 'pending_confirmation' ''',
            (target,)
        ).fetchall()
        skipped = len(rows)
        if skipped:
            ts_skip = datetime.utcnow().isoformat()
            conn.execute(
                '''UPDATE food_requests SET status='skipped', confirmed_at=?
                   WHERE id IN ({})'''.format(','.join('?' * skipped)),
                [ts_skip] + [r['id'] for r in rows]
            )
            import json as _json
            for _r in rows:
                conn.execute(
                    "INSERT INTO food_request_events (id, request_id, event_type, actor, payload, created_at) VALUES (?,?,?,?,?,?)",
                    (str(uuid.uuid4()), _r['id'], 'auto_skipped', 'scheduler',
                     _json.dumps({'note': 'no response by cutoff'}), ts_skip)
                )
            conn.commit()
        log.info(f'Cutoff: {skipped} non-responding families marked skipped for delivery {target}')
        return skipped
    finally:
        conn.close()

def _release_unconfirmed_slots_job():
    """Daily job: release claimed slots where delivery is ≤3 days away and family has no confirmed order.
    Sends WA to each released volunteer. Idempotent via reminder_log (key: slot_id + 'autorelease').
    """
    from datetime import date as _date, timedelta as _td
    conn = _bootstrap_conn()
    try:
        conn.row_factory = sqlite3.Row
        cutoff_date = (_date.today() + _td(days=3)).isoformat()
        today_str   = _date.today().isoformat()

        # Find claimed slots within 3 days where the family's order is NOT confirmed
        slots = conn.execute(
            '''SELECT vs.id, vs.task_type, vs.claimed_by,
                      dc.delivery_date_start, dc.title as cycle_title,
                      f.name as family_name, f.id as family_id,
                      v.wa_phone, v.wa_apikey, v.name as vol_name
               FROM volunteer_slots vs
               JOIN delivery_cycles dc ON vs.cycle_id = dc.id
               JOIN families f ON vs.family_id = f.id
               JOIN volunteers v ON vs.claimed_by = v.id
               WHERE vs.status = 'claimed'
                 AND dc.delivery_date_start >= ?
                 AND dc.delivery_date_start <= ?
                 AND NOT EXISTS (
                     SELECT 1 FROM food_requests fr
                     WHERE fr.cycle_id = vs.cycle_id
                       AND fr.family_id = vs.family_id
                       AND fr.status IN ('confirmed','auto_confirmed','submitted')
                 )''',
            (today_str, cutoff_date)
        ).fetchall()

        released = 0
        for slot in slots:
            # Idempotency: skip if already sent auto-release for this slot
            already = conn.execute(
                "SELECT id FROM reminder_log WHERE slot_id=? AND sent_to='autorelease'",
                (slot['id'],)
            ).fetchone()
            if already:
                continue

            # Release the slot
            conn.execute(
                "UPDATE volunteer_slots SET prev_claimed_by=claimed_by, claimed_by=NULL, "
                "claimed_at=NULL, status='open', updated_at=? WHERE id=?",
                (datetime.utcnow().isoformat(), slot['id'])
            )
            # Log idempotency guard
            conn.execute(
                "INSERT OR IGNORE INTO reminder_log (id, slot_id, sent_to, sent_at) VALUES (?,?,?,?)",
                (str(uuid.uuid4()), slot['id'], 'autorelease', datetime.utcnow().isoformat())
            )
            conn.commit()
            released += 1

            # WA to volunteer
            if slot['wa_phone'] and slot['wa_apikey']:
                try:
                    _wa_send(slot['wa_phone'], slot['wa_apikey'],
                        f"Update — Slot Released\n"
                        f"{slot['family_name']} has not placed an order for {slot['cycle_title']} "
                        f"(delivery {slot['delivery_date_start']}).\n"
                        f"Your {slot['task_type']} slot has been released — no action needed.\n"
                        f"JazakAllah Khair for signing up!")
                except Exception:
                    pass

        log.info(f'_release_unconfirmed_slots_job: released {released} slots (checked {len(slots)})')
        return released
    finally:
        conn.close()


# ── Bootstrap on startup (runs under both gunicorn and direct execution) ──────

bootstrap_db()

# ── APScheduler: daily 8am UTC reminder job ───────────────────────────────────
# Runs in each gunicorn worker, but reminder_log idempotency prevents double-sends.
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    _scheduler = BackgroundScheduler(timezone='UTC')
    _scheduler.add_job(_send_reminders_job, 'cron', hour=8, minute=0,
                       id='daily_reminders', replace_existing=True)
    _scheduler.add_job(_send_family_confirmation_reminders, 'cron', hour=9, minute=0,
                       id='family_opt_in_notifications', replace_existing=True)
    _scheduler.add_job(_skip_nonresponding_families, 'cron', hour=9, minute=30,
                       id='family_cutoff_skip', replace_existing=True)
    _scheduler.add_job(_release_unconfirmed_slots_job, 'cron', hour=10, minute=0,
                       id='auto_release_unconfirmed_slots', replace_existing=True)

    def _purge_otp_tokens():
        """Delete used or expired OTP tokens daily — housekeeping only."""
        try:
            import sqlite3 as _sq
            _db = _sq.connect(DB_PATH)
            _db.row_factory = _sq.Row
            _db.execute("DELETE FROM otp_tokens WHERE used=1 OR expires_at < ?", (now(),))
            _db.commit()
            _db.close()
            log.info('OTP token cleanup complete')
        except Exception as _e:
            log.warning(f'OTP purge failed: {_e}')

    _scheduler.add_job(_purge_otp_tokens, 'cron', hour=3, minute=0,
                       id='otp_token_cleanup', replace_existing=True)
    _scheduler.start()
    log.info('APScheduler started — reminders 08:00, family confirmations 09:00, cutoff 09:30, auto-release slots 10:00, OTP cleanup 03:00 UTC')
except ImportError:
    log.warning('APScheduler not installed. Run: pip install apscheduler')
except Exception as _e:
    log.warning(f'APScheduler failed to start: {_e}')

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    log.info(f'SIHAA Ops Hub starting on port {PORT}')
    app.run(host='0.0.0.0', port=PORT, debug=False)

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

# ── Config ────────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder='public')
CORS(app)

DB_PATH         = os.environ.get('DB_PATH', 'data/sihaa.db')
UPLOAD_FOLDER   = os.environ.get('UPLOAD_FOLDER', 'data/uploads')
SESSION_HOURS   = int(os.environ.get('SESSION_EXPIRY_HOURS', 24))
PORT            = int(os.environ.get('PORT', 5000))
ALLOWED_EXT     = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'heic'}

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
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def now():
    return datetime.utcnow().isoformat()

def bootstrap_db():
    os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else '.', exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    c = conn.cursor()

    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            username    TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name        TEXT,
            role        TEXT NOT NULL DEFAULT 'viewer'
                        CHECK(role IN ('admin','volunteer','finance','viewer')),
            active      INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT NOT NULL
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
            id              TEXT PRIMARY KEY,
            name            TEXT NOT NULL,
            phone           TEXT,
            email           TEXT,
            role            TEXT DEFAULT 'shopper'
                            CHECK(role IN ('shopper','delivery','both')),
            availability    TEXT,
            service_area    TEXT,
            status          TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending','active','inactive')),
            notes           TEXT,
            source          TEXT DEFAULT 'admin',
            created_at      TEXT NOT NULL,
            updated_at      TEXT
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
            payment_method  TEXT CHECK(payment_method IN ('cash','bank_transfer','cheque','other')),
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
            amount      REAL,
            date        TEXT,
            source      TEXT,
            notes       TEXT,
            created_at  TEXT NOT NULL
        );
    ''')

    # Seed default admin if not present
    if not conn.execute("SELECT id FROM users WHERE username='admin'").fetchone():
        conn.execute(
            "INSERT INTO users (id, username, password_hash, name, role, created_at) VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), 'admin', generate_password_hash('admin123'),
             'Administrator', 'admin', now())
        )
        log.info('Default admin created — username: admin  password: admin123')
        log.info('IMPORTANT: Change the default password after first login.')

    conn.commit()
    conn.close()
    log.info('Database bootstrapped.')

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
        "SELECT id, username, name, role, active, created_at FROM users ORDER BY created_at"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/users', methods=['POST'])
@require_auth(roles=['admin'])
def create_user():
    data = request.json or {}
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 422
    uid = str(uuid.uuid4())
    try:
        get_db().execute(
            "INSERT INTO users (id, username, password_hash, name, role, created_at) VALUES (?,?,?,?,?,?)",
            (uid, data['username'], generate_password_hash(data['password']),
             data.get('name'), data.get('role', 'viewer'), now())
        )
        get_db().commit()
    except sqlite3.IntegrityError:
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
    new_hash = generate_password_hash(data['password']) if data.get('password') else row['password_hash']
    db.execute(
        "UPDATE users SET name=?, role=?, active=?, password_hash=? WHERE id=?",
        (data.get('name', row['name']), data.get('role', row['role']),
         data.get('active', row['active']), new_hash, uid)
    )
    db.commit()
    return jsonify({'ok': True})

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/api/dashboard/stats')
@require_auth()
def dashboard_stats():
    db = get_db()
    this_month = datetime.utcnow().strftime('%Y-%m')
    stats = {
        'families_total':   db.execute("SELECT COUNT(*) FROM families").fetchone()[0],
        'families_active':  db.execute("SELECT COUNT(*) FROM families WHERE status='active'").fetchone()[0],
        'families_pending': db.execute("SELECT COUNT(*) FROM families WHERE status='pending'").fetchone()[0],
        'volunteers_total': db.execute("SELECT COUNT(*) FROM volunteers").fetchone()[0],
        'volunteers_active':db.execute("SELECT COUNT(*) FROM volunteers WHERE status='active'").fetchone()[0],
        'volunteers_pending':db.execute("SELECT COUNT(*) FROM volunteers WHERE status='pending'").fetchone()[0],
        'assignments_open': db.execute("SELECT COUNT(*) FROM assignments WHERE status NOT IN ('completed','cancelled')").fetchone()[0],
        'receipts_pending': db.execute("SELECT COUNT(*) FROM receipts WHERE status='pending'").fetchone()[0],
        'spend_this_month': db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM receipts WHERE status='approved' AND purchase_date LIKE ?",
            (f'{this_month}%',)
        ).fetchone()[0],
        'spend_total':      db.execute(
            "SELECT COALESCE(SUM(amount),0) FROM receipts WHERE status='approved'"
        ).fetchone()[0],
    }
    return jsonify(stats)

# ── Families ──────────────────────────────────────────────────────────────────

@app.route('/api/families', methods=['GET'])
@require_auth()
def list_families():
    db = get_db()
    status = request.args.get('status')
    search = (request.args.get('search') or '').strip()
    q = "SELECT * FROM families WHERE 1=1"
    params = []
    if status:
        q += " AND status=?"; params.append(status)
    if search:
        q += " AND (name LIKE ? OR phone LIKE ? OR address LIKE ?)"; params += [f'%{search}%']*3
    q += " ORDER BY created_at DESC"
    return jsonify([dict(r) for r in db.execute(q, params).fetchall()])

@app.route('/api/families', methods=['POST'])
@require_auth(roles=['admin', 'finance'])
def create_family():
    data = request.json or {}
    if not data.get('name'):
        return jsonify({'error': 'Name is required'}), 422
    fid = str(uuid.uuid4())
    get_db().execute(
        '''INSERT INTO families
           (id,name,phone,address,city,family_size,children_count,
            dietary_notes,frequency,income_range,status,notes,source,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (fid, data['name'], data.get('phone'), data.get('address'), data.get('city'),
         data.get('family_size'), data.get('children_count'), data.get('dietary_notes'),
         data.get('frequency'), data.get('income_range'),
         data.get('status', 'pending'), data.get('notes'), data.get('source', 'admin'), now())
    )
    get_db().commit()
    return jsonify(dict(get_db().execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone())), 201

@app.route('/api/families/<fid>', methods=['GET'])
@require_auth()
def get_family(fid):
    row = get_db().execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()
    return (jsonify(dict(row)) if row else (jsonify({'error': 'Not found'}), 404))

@app.route('/api/families/<fid>', methods=['PUT'])
@require_auth(roles=['admin', 'finance'])
def update_family(fid):
    db = get_db()
    row = db.execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute(
        '''UPDATE families SET name=?,phone=?,address=?,city=?,family_size=?,children_count=?,
           dietary_notes=?,frequency=?,income_range=?,status=?,notes=?,updated_at=? WHERE id=?''',
        (d.get('name', row['name']), d.get('phone', row['phone']),
         d.get('address', row['address']), d.get('city', row['city']),
         d.get('family_size', row['family_size']), d.get('children_count', row['children_count']),
         d.get('dietary_notes', row['dietary_notes']), d.get('frequency', row['frequency']),
         d.get('income_range', row['income_range']), d.get('status', row['status']),
         d.get('notes', row['notes']), now(), fid)
    )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM families WHERE id=?", (fid,)).fetchone()))

# ── Volunteers ────────────────────────────────────────────────────────────────

@app.route('/api/volunteers', methods=['GET'])
@require_auth()
def list_volunteers():
    db = get_db()
    status = request.args.get('status')
    search = (request.args.get('search') or '').strip()
    q = "SELECT * FROM volunteers WHERE 1=1"
    params = []
    if status:
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
           (id,name,phone,email,role,availability,service_area,status,notes,source,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
        (vid, data['name'], data.get('phone'), data.get('email'),
         data.get('role', 'shopper'), data.get('availability'), data.get('service_area'),
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
           service_area=?,status=?,notes=?,updated_at=? WHERE id=?''',
        (d.get('name', row['name']), d.get('phone', row['phone']),
         d.get('email', row['email']), d.get('role', row['role']),
         d.get('availability', row['availability']), d.get('service_area', row['service_area']),
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
    get_db().execute(
        '''INSERT INTO receipts
           (id,assignment_id,volunteer_id,family_id,store,purchase_date,amount,file_url,status,notes,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
        (rid, data.get('assignment_id'), data.get('volunteer_id'), data.get('family_id'),
         data.get('store'), data.get('purchase_date'), data.get('amount'),
         data.get('file_url'), 'pending', data.get('notes'), now())
    )
    get_db().commit()
    return jsonify({'id': rid}), 201

@app.route('/api/receipts/<rid>', methods=['PUT'])
@require_auth(roles=['admin', 'finance'])
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
@require_auth(roles=['admin', 'finance'])
def list_reimbursements():
    db = get_db()
    status = request.args.get('status')
    q = '''SELECT rb.*, v.name as volunteer_name, r.store, r.purchase_date
           FROM reimbursements rb
           LEFT JOIN volunteers v ON rb.volunteer_id = v.id
           LEFT JOIN receipts r ON rb.receipt_id = r.id
           WHERE 1=1'''
    params = []
    if status:
        q += " AND rb.status=?"; params.append(status)
    q += " ORDER BY rb.created_at DESC"
    return jsonify([dict(r) for r in db.execute(q, params).fetchall()])

@app.route('/api/reimbursements/<rid>', methods=['PUT'])
@require_auth(roles=['admin', 'finance'])
def update_reimbursement(rid):
    db = get_db()
    row = db.execute("SELECT * FROM reimbursements WHERE id=?", (rid,)).fetchone()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    d = request.json or {}
    db.execute(
        '''UPDATE reimbursements SET status=?,payment_method=?,paid_date=?,
           approved_by=?,notes=?,updated_at=? WHERE id=?''',
        (d.get('status', row['status']), d.get('payment_method', row['payment_method']),
         d.get('paid_date', row['paid_date']), d.get('approved_by', row['approved_by']),
         d.get('notes', row['notes']), now(), rid)
    )
    db.commit()
    return jsonify(dict(db.execute("SELECT * FROM reimbursements WHERE id=?", (rid,)).fetchone()))

# ── Donations ─────────────────────────────────────────────────────────────────

@app.route('/api/donations', methods=['GET'])
@require_auth(roles=['admin', 'finance'])
def list_donations():
    rows = get_db().execute(
        "SELECT * FROM donations ORDER BY date DESC, created_at DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/donations', methods=['POST'])
@require_auth(roles=['admin', 'finance'])
def create_donation():
    data = request.json or {}
    did = str(uuid.uuid4())
    get_db().execute(
        "INSERT INTO donations (id,donor_name,amount,date,source,notes,created_at) VALUES (?,?,?,?,?,?,?)",
        (did, data.get('donor_name'), data.get('amount'), data.get('date'),
         data.get('source'), data.get('notes'), now())
    )
    get_db().commit()
    return jsonify({'id': did}), 201

# ── Public Intake (no auth) ───────────────────────────────────────────────────

@app.route('/api/intake', methods=['POST'])
def public_intake():
    data = request.json or {}
    if not data.get('name') or not data.get('phone'):
        return jsonify({'error': 'Name and phone are required'}), 422
    fid = str(uuid.uuid4())
    db = get_db()
    db.execute(
        '''INSERT INTO families
           (id,name,phone,address,city,family_size,children_count,
            dietary_notes,frequency,income_range,status,source,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (fid, data['name'], data['phone'], data.get('address'), data.get('city'),
         data.get('family_size'), data.get('children_count'), data.get('dietary_notes'),
         data.get('frequency'), data.get('income_range'),
         'pending', 'intake_form', now())
    )
    db.commit()
    log.info(f'New intake: {data["name"]} ({data["phone"]})')
    return jsonify({'ok': True, 'message': 'Thank you. We will be in touch within 48 hours.'}), 201

@app.route('/api/volunteer-signup', methods=['POST'])
def public_volunteer_signup():
    data = request.json or {}
    if not data.get('name') or not data.get('phone'):
        return jsonify({'error': 'Name and phone are required'}), 422
    vid = str(uuid.uuid4())
    db = get_db()
    db.execute(
        '''INSERT INTO volunteers
           (id,name,phone,email,role,availability,service_area,status,source,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (vid, data['name'], data['phone'], data.get('email'),
         data.get('role', 'shopper'), data.get('availability'), data.get('service_area'),
         'pending', 'signup_form', now())
    )
    db.commit()
    log.info(f'New volunteer signup: {data["name"]}')
    return jsonify({'ok': True, 'message': 'Thank you for signing up. We will be in touch soon.'}), 201

# ── Static Pages ──────────────────────────────────────────────────────────────

@app.route('/')
def admin_index():
    return send_from_directory('public', 'index.html')

@app.route('/intake')
def intake_page():
    return send_from_directory('public', 'intake.html')

@app.route('/volunteer')
def volunteer_page():
    return send_from_directory('public', 'volunteer.html')

@app.route('/uploads/<path:filename>')
@require_auth()
def serve_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ── Bootstrap on startup (runs under both gunicorn and direct execution) ──────

bootstrap_db()

# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    log.info(f'SIHAA Ops Hub starting on port {PORT}')
    app.run(host='0.0.0.0', port=PORT, debug=False)

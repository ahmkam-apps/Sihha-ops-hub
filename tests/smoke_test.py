"""
Sihha Ops Hub — Live Smoke Test
Hits the real Railway deployment to verify core routes are up and responding correctly.
Usage:
    python3 tests/smoke_test.py
    ADMIN_PASSWORD=yourpass python3 tests/smoke_test.py
"""
import sys, urllib.request, urllib.error, urllib.parse, json, ssl, os

BASE_URL = os.environ.get('BASE_URL', 'https://ops.sihha.org').rstrip('/')

# macOS Python doesn't use system certs by default — create unverified context
_ctx = ssl.create_default_context()
try:
    import certifi
    _ctx = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _ctx.check_hostname = False
    _ctx.verify_mode = ssl.CERT_NONE

PASS = '\033[92m✓\033[0m'
FAIL = '\033[91m✗\033[0m'
WARN = '\033[93m⚠\033[0m'

results = []

def check(label, passed, detail=''):
    icon = PASS if passed else FAIL
    status = 'PASS' if passed else 'FAIL'
    print(f'  {icon}  {label}' + (f'  →  {detail}' if detail else ''))
    results.append((label, passed))

def get(path, token=None):
    req = urllib.request.Request(BASE_URL + path)
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    try:
        with urllib.request.urlopen(req, timeout=10, context=_ctx) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')
    except Exception as e:
        return 0, {'error': str(e)}

def post(path, body, token=None):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(BASE_URL + path, data=data,
                                  headers={'Content-Type': 'application/json'})
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    try:
        with urllib.request.urlopen(req, timeout=10, context=_ctx) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b'{}')
    except Exception as e:
        return 0, {'error': str(e)}

if __name__ != '__main__':
    # Prevent pytest from importing and running this module during collection.
    # Run directly: python3 tests/smoke_test.py
    import pytest as _pytest
    _pytest.skip('live smoke test; run directly with python3 tests/smoke_test.py',
                 allow_module_level=True)

print(f'\n  Sihha Ops Hub — Smoke Test')
print(f'  Target: {BASE_URL}')
print(f'  {"-" * 52}')

# ── Health ────────────────────────────────────────────────────────────────────
print('\n  [ Health ]')
s, d = get('/api/health')
check('Health endpoint returns 200', s == 200, f'status={s}')
check('Status field is ok', d.get('status') == 'ok')

# ── Public Pages ──────────────────────────────────────────────────────────────
print('\n  [ Public Pages ]')
for path, name in [('/', 'Admin SPA'), ('/intake', 'Intake form'),
                   ('/volunteer-signup', 'Volunteer signup'), ('/portal', 'Volunteer portal')]:
    req = urllib.request.Request(BASE_URL + path)
    try:
        with urllib.request.urlopen(req, timeout=10, context=_ctx) as r:
            check(f'{name} ({path}) loads', r.status == 200, f'status={r.status}')
    except urllib.error.HTTPError as e:
        check(f'{name} ({path}) loads', False, f'status={e.code}')
    except Exception as e:
        check(f'{name} ({path}) loads', False, str(e))

# ── Auth ──────────────────────────────────────────────────────────────────────
print('\n  [ Auth ]')
s, d = post('/api/auth/login', {'username': 'admin', 'password': 'WRONG'})
check('Bad login returns 401', s == 401, f'status={s}')

s, d = post('/api/auth/login', {})
check('Empty login returns 400', s == 400, f'status={s}')

s, d = get('/api/families')
check('Protected route without token returns 401', s == 401, f'status={s}')

# Try admin login with correct password (entered at prompt if not in env)
import os
admin_pw = os.environ.get('ADMIN_PASSWORD', '')
token = None
if admin_pw:
    s, d = post('/api/auth/login', {'username': 'admin', 'password': admin_pw})
    if s == 200:
        token = d.get('token')
        check('Admin login with correct password', True, 'token received')
    else:
        check('Admin login with correct password', False, f'status={s} — check ADMIN_PASSWORD env var')
else:
    print(f'  {WARN}  Admin password not set — skipping authenticated checks')
    print(f'       Set ADMIN_PASSWORD env var to run full smoke test')

# ── Authenticated Routes ───────────────────────────────────────────────────────
if token:
    print('\n  [ Authenticated Routes ]')

    s, d = get('/api/auth/me', token)
    check('/api/auth/me returns user', s == 200 and d.get('username') == 'admin', f'status={s}')

    s, d = get('/api/families', token)
    check('/api/families returns list', s == 200 and isinstance(d, list), f'status={s}, count={len(d) if isinstance(d,list) else "?"}')

    s, d = get('/api/volunteers', token)
    check('/api/volunteers returns list', s == 200 and isinstance(d, list), f'status={s}, count={len(d) if isinstance(d,list) else "?"}')

    s, d = get('/api/food-categories', token)
    check('/api/food-categories has 3+ seeded categories', s == 200 and len(d) >= 3,
          f'status={s}, count={len(d) if isinstance(d,list) else "?"}')

    s, d = get('/api/food-items', token)
    check('/api/food-items has 10+ seeded items', s == 200 and len(d) >= 10,
          f'status={s}, count={len(d) if isinstance(d,list) else "?"}')

    s, d = get('/api/bundle-size-rules', token)
    check('/api/bundle-size-rules has S/M/L', s == 200 and len(d) == 3, f'status={s}')

    s, d = get('/api/delivery-cycles', token)
    check('/api/delivery-cycles returns list', s == 200 and isinstance(d, list), f'status={s}')

    s, d = get('/api/users', token)
    check('/api/users returns list (admin only)', s == 200 and isinstance(d, list), f'status={s}')

# ── Public Food Order Check ────────────────────────────────────────────────────
print('\n  [ Food Order — Public ]')
s, d = get('/api/food-order/check?phone=0000000000')
check('Legacy phone lookup is rejected', s == 401, f'status={s}')

# ── Portal Login ───────────────────────────────────────────────────────────────
print('\n  [ Volunteer Portal ]')
s, d = post('/api/portal/login', {'phone': '0000000000'})
check('Legacy portal login is gone', s == 410, f'status={s}')

s, d = post('/api/portal/login', {})
check('Legacy portal login stays gone without phone', s == 410, f'status={s}')

s, d = get('/api/portal/cycles')
check('Portal cycles requires auth', s == 401, f'status={s}')

# ── Summary ───────────────────────────────────────────────────────────────────
print(f'\n  {"-" * 52}')
passed = sum(1 for _, ok in results if ok)
total  = len(results)
failed = total - passed

if failed == 0:
    print(f'  {PASS}  All {total} checks passed\n')
    sys.exit(0)
else:
    print(f'  {FAIL}  {failed}/{total} checks failed\n')
    print('  Failed checks:')
    for label, ok in results:
        if not ok:
            print(f'    {FAIL}  {label}')
    print()
    sys.exit(1)

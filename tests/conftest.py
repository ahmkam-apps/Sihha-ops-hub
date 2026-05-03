"""
Test fixtures for Sihha Ops Hub.
Sets DB_PATH to a temp file and mocks APScheduler + _wa_send before importing server,
so tests are fully isolated and never touch the real DB or real WhatsApp.
"""
import os, sys, tempfile, pytest
from unittest.mock import patch, MagicMock

# ── 1. Point at a fresh temp DB before anything imports server ────────────────
_db_fd, _db_path = tempfile.mkstemp(suffix='.db')
os.environ['DB_PATH'] = _db_path
os.environ['ADMIN_PASSWORD'] = 'admin123'

# ── 2. Stub out APScheduler so no background threads spin up ─────────────────
_mock_scheduler = MagicMock()
sys.modules['apscheduler'] = MagicMock()
sys.modules['apscheduler.schedulers'] = MagicMock()
sys.modules['apscheduler.schedulers.background'] = MagicMock(
    BackgroundScheduler=MagicMock(return_value=_mock_scheduler)
)

# ── 3. Import server (bootstrap_db runs, scheduler is mocked) ─────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import server as _server

# ── 4. Pytest fixtures ────────────────────────────────────────────────────────

@pytest.fixture(scope='session')
def app():
    _server.app.config['TESTING'] = True
    yield _server.app
    os.close(_db_fd)
    os.unlink(_db_path)

@pytest.fixture(scope='session')
def client(app):
    return app.test_client()

@pytest.fixture(scope='session')
def admin_token(client):
    res = client.post('/api/auth/login',
                      json={'username': 'admin', 'password': 'admin123'})
    assert res.status_code == 200, f'Admin login failed: {res.data}'
    return res.get_json()['token']

@pytest.fixture(scope='session')
def auth(admin_token):
    return {'Authorization': f'Bearer {admin_token}'}

@pytest.fixture
def wa_mock():
    """Patches _wa_send so tests can assert on WhatsApp calls without HTTP."""
    with patch.object(_server, '_wa_send', return_value=True) as m:
        yield m

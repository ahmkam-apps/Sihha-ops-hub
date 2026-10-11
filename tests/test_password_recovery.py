"""Synthetic local recovery checks. Mail delivery and background dispatch are mocked."""
import hashlib
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from werkzeug.security import generate_password_hash, check_password_hash
import server

OLD = 'ExistingPass1!'
NEW = 'RecoveredPass2!'


@pytest.fixture
def recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(server, 'DB_PATH', str(tmp_path / 'recovery.db'))
    monkeypatch.setattr(server, 'UPLOAD_FOLDER', str(tmp_path / 'uploads'))
    monkeypatch.setattr(server, 'REQUIRE_EXISTING_DB', False)
    server.bootstrap_db()
    mail = []
    monkeypatch.setattr(server, '_email_send', lambda *a, **kw: mail.append((a, kw)) or True)
    monkeypatch.setattr(server, '_queue_recovery_mail', lambda fn, *a: fn(*a) or True)
    client = server.app.test_client()
    with server.app.app_context():
        db = server.get_db()
        uid = str(uuid.uuid4())
        db.execute('''INSERT INTO users (id,username,password_hash,name,role,email,active,
                      must_change_password,created_at,password_changed_at) VALUES (?,?,?,?,?,?,1,0,?,?)''',
                   (uid, 'recover.test', generate_password_hash(OLD), 'Synthetic Test', 'viewer',
                    'recover@example.org', server.now(), server.now()))
        server._verify_recovery_email(db, uid, 'recover@example.org', 'synthetic-proof', server.now())
        db.commit()
    return client, uid, mail


def db_row(sql, args=()):
    with server.make_conn() as db:
        return db.execute(sql, args).fetchone()


def execute(sql, args=()):
    with server.make_conn() as db:
        db.execute(sql, args)


def request_link(recovery, **kwargs):
    client, uid, mail = recovery
    res = client.post('/api/auth/password-recovery', json={'username': 'recover.test'}, **kwargs)
    assert res.status_code == 202
    calls = [a for a, kw in mail if a[1] == 'Reset Your Sihha Password']
    assert calls
    return calls[-1][2].split('#token=', 1)[1].split()[0]


def consume(client, token, **extra):
    return client.post('/api/auth/password-recovery/reset', json={
        'token': token, 'password': NEW, 'password_confirmation': NEW, **extra})


def age_limits():
    execute("UPDATE rate_limit_events SET created_at=? WHERE scope='recovery_request_identity'",
            ((datetime.utcnow() - timedelta(minutes=2)).isoformat(),))


def test_success_revokes_sessions_links_and_keeps_hash_only(recovery, caplog):
    client, uid, mail = recovery
    login = client.post('/api/auth/login', json={'username': 'recover.test', 'password': OLD}).get_json()
    temp = 'tmp_' + uuid.uuid4().hex
    execute('INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)',
            (temp, uid, (datetime.utcnow()+timedelta(hours=1)).isoformat(), server.now()))
    execute('''INSERT INTO account_invitations (id,user_id,token_hash,delivery_email,created_at,expires_at)
               VALUES (?,?,?,?,?,?)''', ('outstanding-invite', uid, uuid.uuid4().hex, 'recover@example.org',
                                        server.now(), (datetime.utcnow()+timedelta(hours=1)).isoformat()))
    token = request_link(recovery, headers={'Host': 'attacker.example', 'X-Forwarded-Host': 'evil.example'})
    row = db_row('SELECT * FROM account_password_recoveries WHERE user_id=?', (uid,))
    assert row['token_hash'] == hashlib.sha256(token.encode()).hexdigest()
    assert row['token_hash'] != token
    lifetime = datetime.fromisoformat(row['expires_at']) - datetime.fromisoformat(row['created_at'])
    assert 44*60 < lifetime.total_seconds() <= 45*60+1
    assert 'https://ops.sihha.org/reset-password#token=' in mail[0][0][2]
    assert '<a href="https://ops.sihha.org/reset-password#token=' in mail[0][1]['html_body']
    assert 'evil.example' not in mail[0][0][2]
    assert token not in caplog.text and NEW not in caplog.text
    info = client.post('/api/auth/password-recovery/validate', json={'token': token})
    assert info.get_json() == {'valid': True}
    assert not db_row('SELECT used_at FROM account_password_recoveries WHERE id=?', (row['id'],))[0]
    result = consume(client, token)
    assert result.status_code == 200 and result.get_json() == {'ok': True, 'login_url': '/login'}
    assert not db_row('SELECT 1 FROM sessions WHERE user_id=?', (uid,))
    assert client.get('/api/auth/me', headers={'Authorization': 'Bearer '+login['token']}).status_code == 401
    assert db_row('SELECT invalidated_at FROM account_invitations WHERE id=?', ('outstanding-invite',))[0]
    assert client.post('/api/auth/login', json={'username': 'recover.test', 'password': OLD}).status_code == 401
    assert client.post('/api/auth/login', json={'username': 'recover.test', 'password': NEW}).status_code == 200
    assert db_row("SELECT COUNT(*) FROM account_access_events WHERE event_type='password_recovered'")[0] == 1
    assert any(a[1] == 'Your Sihha Password Was Reset' for a, kw in mail)


@pytest.mark.parametrize('token', ['', 'invalid', 'x'*44, ['bad'], None, 'https://evil.example', 'x'*10000])
def test_invalid_malformed_tokens(recovery, token):
    client, uid, _ = recovery
    assert client.post('/api/auth/password-recovery/validate', json={'token': token}).status_code == 400
    assert consume(client, token).status_code == 400
    assert check_password_hash(db_row('SELECT password_hash FROM users WHERE id=?', (uid,))[0], OLD)


def test_expired_and_reused(recovery):
    client, uid, _ = recovery
    token = request_link(recovery)
    execute('UPDATE account_password_recoveries SET expires_at=?',
            ((datetime.utcnow()-timedelta(seconds=1)).isoformat(),))
    assert consume(client, token).status_code == 400
    age_limits()
    new = request_link(recovery)
    assert consume(client, new).status_code == 200
    assert consume(client, new).status_code == 400
    assert client.post('/api/auth/password-recovery/validate', json={'token': new}).status_code == 400


@pytest.mark.parametrize('state', ['unknown', 'unverified', 'inactive', 'missing_email', 'bad_email', 'new_email'])
def test_non_enumeration_and_eligibility(recovery, state):
    client, uid, mail = recovery
    if state == 'unverified':
        execute('DELETE FROM account_recovery_email_verifications')
    elif state == 'inactive':
        execute('UPDATE users SET active=0 WHERE id=?', (uid,))
    elif state in ('missing_email', 'bad_email', 'new_email'):
        execute('UPDATE users SET email=? WHERE id=?', ({'missing_email': None,
                'bad_email': 'not-an-email', 'new_email': 'different@example.org'}[state], uid))
    response = client.post('/api/auth/password-recovery', json={'username':
                           'does-not-exist' if state == 'unknown' else 'recover.test'})
    unknown = client.post('/api/auth/password-recovery', json={'username': 'another-unknown'})
    assert response.status_code == unknown.status_code == 202
    assert response.get_json() == unknown.get_json()
    assert mail == [] and not db_row('SELECT 1 FROM account_password_recoveries')


def test_repeats_keep_existing_link_and_credentials(recovery):
    client, uid, mail = recovery
    token = request_link(recovery)
    for _ in range(4):
        assert client.post('/api/auth/password-recovery', json={'username': 'recover.test'}).status_code == 202
    age_limits()
    request_link(recovery)
    assert len(mail) == 1
    assert consume(client, token).status_code == 200


def test_shared_ip_and_identity_limits(recovery):
    client, uid, mail = recovery
    for i in range(20):
        assert client.post('/api/auth/password-recovery', json={'username': f'unknown{i}'}).status_code == 202
    limited = client.post('/api/auth/password-recovery', json={'username': 'recover.test'})
    assert limited.status_code == 429 and limited.headers['Retry-After'] == '3600'
    assert mail == []
    assert all('unknown' not in r['bucket_key'] for r in server.make_conn().execute('SELECT bucket_key FROM rate_limit_events'))


def test_cross_ip_account_limit_and_pending_retry(recovery, monkeypatch):
    client, uid, mail = recovery
    monkeypatch.setattr(server, '_queue_recovery_mail', lambda *a: True)  # simulated interrupted worker
    request_responses = []
    for i in range(4):
        if i:
            age_limits()
        response = client.post('/api/auth/password-recovery', json={'username': 'recover.test'},
                               environ_base={'REMOTE_ADDR': f'192.0.2.{i}'})
        request_responses.append(response.get_json())
        execute('UPDATE account_password_recoveries SET created_at=?',
                ((datetime.utcnow()-timedelta(minutes=3)).isoformat(),))
    assert all(r == request_responses[0] for r in request_responses)
    assert db_row('SELECT COUNT(*) FROM account_password_recoveries')[0] == 3
    assert mail == []


@pytest.mark.parametrize('failure', ['provider_false', 'provider_exception', 'queue_full'])
def test_delivery_failure_keeps_password_and_allows_retry(recovery, monkeypatch, failure, caplog):
    client, uid, mail = recovery
    original = server._email_send
    if failure == 'queue_full':
        monkeypatch.setattr(server, '_queue_recovery_mail', lambda *a: False)
    elif failure == 'provider_false':
        monkeypatch.setattr(server, '_email_send', lambda *a, **kw: False)
    else:
        def fail(*a, **kw):
            raise RuntimeError('PRIVATE-mail-body')
        monkeypatch.setattr(server, '_email_send', fail)
    res = client.post('/api/auth/password-recovery', json={'username': 'recover.test'})
    assert res.status_code == 202
    row = db_row('SELECT * FROM account_password_recoveries')
    assert row['invalidated_at'] and not row['email_sent_at']
    assert check_password_hash(db_row('SELECT password_hash FROM users WHERE id=?', (uid,))[0], OLD)
    assert 'PRIVATE-mail-body' not in caplog.text
    monkeypatch.setattr(server, '_email_send', original)
    monkeypatch.setattr(server, '_queue_recovery_mail', lambda fn, *a: fn(*a) or True)
    age_limits()
    assert consume(client, request_link(recovery)).status_code == 200


def test_delivery_does_not_resurrect_link_during_account_change(recovery, monkeypatch):
    client, uid, mail = recovery
    def during_send(*a, **kw):
        mail.append((a,kw))
        execute('UPDATE users SET email=? WHERE id=?', ('changed@example.org',uid))
        return True
    monkeypatch.setattr(server, '_email_send', during_send)
    token = request_link(recovery)
    assert consume(client, token).status_code == 400
    assert db_row('SELECT invalidated_at FROM account_password_recoveries')[0]


def test_pending_delivery_blocks_consumption_and_stale_job_cannot_resurrect(recovery, monkeypatch):
    client, uid, mail = recovery
    tasks=[]
    monkeypatch.setattr(server, '_queue_recovery_mail', lambda fn,*a: tasks.append((fn,a)) or True)
    assert client.post('/api/auth/password-recovery', json={'username':'recover.test'}).status_code == 202
    old_token=tasks[0][1][1]
    assert consume(client,old_token).status_code == 400
    execute('UPDATE account_password_recoveries SET created_at=?',
            ((datetime.utcnow()-timedelta(minutes=3)).isoformat(),))
    age_limits()
    assert client.post('/api/auth/password-recovery', json={'username':'recover.test'}).status_code == 202
    assert len(tasks)==2
    tasks[0][0](*tasks[0][1])
    assert mail==[]
    tasks[1][0](*tasks[1][1])
    assert consume(client,tasks[1][1][1]).status_code==200


def test_password_validation_and_recovery_after_interrupted_response(recovery):
    client,uid,mail=recovery
    token=request_link(recovery)
    for payload in ({'password':'short','password_confirmation':'short'},
                    {'password_confirmation':'different'}, {'password': ['invalid']},
                    {'password':'A1!'+'a'*1024, 'password_confirmation':'A1!'+'a'*1024}):
        assert consume(client,token,**payload).status_code==422
    assert consume(client,token).status_code==200
    # A lost response never grants a second replacement. The new password still signs in.
    assert consume(client,token).status_code==400
    assert client.post('/api/auth/login',json={'username':'recover.test','password':NEW}).status_code==200


def test_atomic_double_consume(recovery):
    client,uid,mail=recovery
    token=request_link(recovery)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _: consume(server.app.test_client(),token).status_code,range(2)))
    assert sorted(results)==[200,400]
    assert db_row("SELECT COUNT(*) FROM account_access_events WHERE event_type='password_recovered'")[0]==1


def test_link_rate_limit_and_no_secret_logs(recovery):
    client,uid,mail=recovery
    token=request_link(recovery)
    for _ in range(20):
        assert client.post('/api/auth/password-recovery/validate',json={'token':token}).status_code==200
    assert consume(client,token).status_code==429
    assert not db_row('SELECT used_at FROM account_password_recoveries')[0]


def admin_headers(client):
    return {'Authorization':'Bearer '+client.post('/api/auth/login',json={
        'username':'admin','password':'admin123'}).get_json()['token']}


@pytest.mark.parametrize('action', ['email', 'role', 'active', 'admin-reset', 'force-reset', 'change-password', 'delete', 'send-access'])
def test_account_lifecycle_invalidates_link(recovery, action):
    client,uid,mail=recovery
    token=request_link(recovery)
    auth=admin_headers(client)
    if action in ('email','role','active'):
        payload={'email':'replacement@example.org'} if action=='email' else ({'role':'finance'} if action=='role' else {'active':0})
        result=client.put('/api/users/'+uid,headers=auth,json=payload)
        assert not db_row('SELECT 1 FROM account_recovery_email_verifications WHERE user_id=?',(uid,))
    elif action=='admin-reset':
        result=client.post('/api/users/'+uid+'/admin-reset-password',headers=auth,json={
            'password':'TemporaryPass9!','password_confirmation':'TemporaryPass9!'})
    elif action=='force-reset':
        result=client.post('/api/users/'+uid+'/force-reset',headers=auth)
    elif action=='delete':
        result=client.delete('/api/users/'+uid,headers=auth,json={'confirm_username':'recover.test'})
        assert not db_row('SELECT 1 FROM account_password_recoveries WHERE user_id=?',(uid,))
    elif action=='send-access':
        result=client.post('/api/users/'+uid+'/send-access-link',headers=auth)
    else:
        user_token=client.post('/api/auth/login',json={'username':'recover.test','password':OLD}).get_json()['token']
        result=client.post('/api/auth/change-password',headers={'Authorization':'Bearer '+user_token},json={
            'current_password':OLD,'new_password':'ChangedPass9!'})
    assert result.status_code==200
    assert consume(client,token).status_code==400


def test_noop_save_preserves_recovery(recovery):
    client,uid,mail=recovery
    token=request_link(recovery)
    result=client.put('/api/users/'+uid,headers=admin_headers(client),json={
        'email':'recover@example.org','role':'viewer','active':1,'must_change_password':0})
    assert result.status_code==200
    assert consume(client,token).status_code==200


def test_successful_invitation_establishes_email_proof_and_reset_cannot_activate(recovery):
    client,uid,mail=recovery
    execute('DELETE FROM account_recovery_email_verifications')
    assert client.post('/api/auth/password-recovery',json={'username':'recover.test'}).status_code==202
    assert mail==[]
    assert client.post('/api/users/'+uid+'/send-access-link',headers=admin_headers(client)).status_code==200
    invitation=mail[-1][0][2].split('#token=')[1].split()[0]
    assert client.post('/api/auth/access-invitation/activate',json={
        'token':invitation,'password':OLD,'password_confirmation':OLD}).status_code==200
    assert db_row('SELECT email FROM account_recovery_email_verifications')[0]=='recover@example.org'
    age_limits()
    token=request_link(recovery)
    assert client.post('/api/auth/access-invitation',json={'token':token}).status_code==400
    assert consume(client,invitation).status_code==400
    assert consume(client,token).status_code==200


def test_backfill_runs_once_and_preserves_data(recovery):
    client,uid,mail=recovery
    execute('DELETE FROM account_recovery_email_verifications')
    execute("DELETE FROM app_settings WHERE key='recovery_email_backfill_v1'")
    execute('''INSERT INTO account_invitations
               (id,user_id,token_hash,delivery_email,created_at,expires_at,email_sent_at,used_at)
               VALUES (?,?,?,?,?,?,?,?)''',('old-proof',uid,'old-hash','recover@example.org',
                 server.now(),server.now(),server.now(),server.now()))
    with server.make_conn() as db:
        server._bootstrap_password_recovery(db)
    assert db_row('SELECT invitation_id FROM account_recovery_email_verifications')[0]=='old-proof'
    execute('DELETE FROM account_recovery_email_verifications')
    server.bootstrap_db()
    assert not db_row('SELECT 1 FROM account_recovery_email_verifications')
    assert check_password_hash(db_row('SELECT password_hash FROM users WHERE id=?',(uid,))[0],OLD)
    assert db_row('PRAGMA quick_check')[0]=='ok'
    assert not db_row('PRAGMA foreign_key_check')


def test_headers_pages_and_fragment_only_ui(recovery):
    client,uid,mail=recovery
    for path in ['/forgot-password','/reset-password','/api/auth/password-recovery/validate']:
        response=client.get(path) if not path.startswith('/api') else client.post(path,json={'token':'bad'})
        assert response.headers['Cache-Control']=='no-store'
        assert response.headers['Referrer-Policy']=='no-referrer'
    assert b'href="/forgot-password"' in client.get('/login').data
    assert b'href="/forgot-password"' in client.get('/').data
    html=client.get('/reset-password').get_data(as_text=True)
    assert "query.get('token')" not in html
    assert "replaceState(null, '', '/reset-password')" in html
    assert 'localStorage' not in html and 'sessionStorage' not in html
    assert 'if (submitting) return;' in html
    assert '/auth/password-recovery/reset' in html
    assert '/forgot-password' in client.get('/sw.js').get_data(as_text=True)

@pytest.mark.parametrize('role,change', [('family','email'),('family','inactive'),('family','delete'),('volunteer','email'),('volunteer','inactive')])
def test_linked_account_lifecycle(recovery, role, change):
    client,uid,mail=recovery
    linked=str(uuid.uuid4())
    table='families' if role=='family' else 'volunteers'
    execute(f'INSERT INTO {table} (id,name,status,email,created_at) VALUES (?,?,?,?,?)',
            (linked,'Synthetic linked','active','recover@example.org',server.now()))
    execute('UPDATE users SET role=?,linked_id=?,linked_type=? WHERE id=?',(role,linked,role,uid))
    token=request_link(recovery)
    if role=='volunteer':
        execute('INSERT INTO portal_sessions (token,volunteer_id,expires_at,created_at) VALUES (?,?,?,?)',
                ('legacy-synthetic',linked,(datetime.utcnow()+timedelta(hours=1)).isoformat(),server.now()))
    auth=admin_headers(client)
    if change=='delete':
        result=client.delete('/api/families/'+linked,headers=auth)
    else:
        result=client.put('/api/'+table+'/'+linked,headers=auth,json={
            'email':'changed@example.org'} if change=='email' else {'status':'inactive'})
    assert result.status_code==200
    assert consume(client,token).status_code==400
    assert not db_row('SELECT 1 FROM account_recovery_email_verifications WHERE user_id=?',(uid,))
    if change=='delete':
        assert not db_row('SELECT 1 FROM account_password_recoveries WHERE user_id=?',(uid,))


def test_volunteer_success_revokes_legacy_session(recovery):
    client,uid,mail=recovery
    linked=str(uuid.uuid4())
    execute('INSERT INTO volunteers (id,name,status,email,created_at) VALUES (?,?,?,?,?)',
            (linked,'Synthetic linked','active','recover@example.org',server.now()))
    execute("UPDATE users SET role='volunteer',linked_type='volunteer',linked_id=? WHERE id=?",(linked,uid))
    execute('INSERT INTO portal_sessions (token,volunteer_id,expires_at,created_at) VALUES (?,?,?,?)',
            ('legacy-synthetic',linked,(datetime.utcnow()+timedelta(hours=1)).isoformat(),server.now()))
    assert consume(client,request_link(recovery)).status_code==200
    assert not db_row('SELECT 1 FROM portal_sessions WHERE volunteer_id=?',(linked,))


def test_atomic_rollback_on_event_failure(recovery,monkeypatch):
    client,uid,mail=recovery
    token=request_link(recovery)
    real=server._record_account_access_event
    def fail(db,user_id,event,*a,**kw):
        if event=='password_recovered':
            raise RuntimeError('Synthetic transaction failure')
        return real(db,user_id,event,*a,**kw)
    monkeypatch.setattr(server,'_record_account_access_event',fail)
    with patch.dict(server.app.config, {'TESTING':False, 'PROPAGATE_EXCEPTIONS':False}):
        assert consume(client,token).status_code==500
    assert not db_row('SELECT used_at FROM account_password_recoveries')[0]
    assert check_password_hash(db_row('SELECT password_hash FROM users WHERE id=?',(uid,))[0],OLD)
    monkeypatch.setattr(server,'_record_account_access_event',real)
    assert consume(client,token).status_code==200


def test_environment_reset_and_temporary_completion_invalidate(recovery):
    client,uid,mail=recovery
    # Configure a synthetic administrator for environment recovery without touching real settings.
    execute("UPDATE users SET username='synthetic-old-admin' WHERE username='admin'")
    execute("UPDATE users SET username='admin',role='admin' WHERE id=?",(uid,))
    execute("DELETE FROM app_settings WHERE key=?",(server.ADMIN_PASSWORD_ENV_STATE_KEY,))
    with server.make_conn() as db:
        server._sync_admin_password_from_env(db,OLD)
    assert client.post('/api/auth/password-recovery',json={'username':'admin'}).status_code==202
    token=mail[-1][0][2].split('#token=')[1].split()[0]
    with server.make_conn() as db:
        assert server._sync_admin_password_from_env(db,'SyntheticEnv8!') is True
    assert consume(client,token).status_code==400
    # Forced password change completion still works and invalidates recovery.
    execute("UPDATE users SET username='recover.test',role='viewer',must_change_password=1 WHERE id=?",(uid,))
    age_limits()
    token=request_link(recovery)
    temp=client.post('/api/auth/login',json={'username':'recover.test','password':'SyntheticEnv8!'}).get_json()['temp_token']
    result=client.post('/api/auth/set-password',json={'temp_token':temp,'password':NEW})
    assert result.status_code==200
    assert consume(client,token).status_code==400


def test_bounded_dispatch_capacity(recovery,monkeypatch):
    from threading import BoundedSemaphore
    queued=[]
    class Pool:
        def submit(self,fn):
            queued.append(fn)
    # Restore the actual dispatch function; the fixture uses synchronous mock delivery.
    import inspect
    source=inspect.getsourcefile(server)
    assert source
    # Read the defined function via a preserved reference below, without real workers.
    monkeypatch.setattr(server,'_recovery_mail_slots',BoundedSemaphore(2))
    monkeypatch.setattr(server,'_recovery_mail_pool',Pool())
    assert REAL_QUEUE(lambda:None)
    assert REAL_QUEUE(lambda:None)
    assert REAL_QUEUE(lambda:None) is False
    queued.pop(0)()
    assert REAL_QUEUE(lambda:None)
    for run in queued:
        run()


REAL_QUEUE=server._queue_recovery_mail

@pytest.mark.parametrize('unproven', ['not_sent','not_used','wrong_email','inactive','inactive_link'])
def test_backfill_requires_actual_active_email_ownership(recovery,unproven):
    client,uid,mail=recovery
    execute('DELETE FROM account_recovery_email_verifications')
    execute("DELETE FROM app_settings WHERE key='recovery_email_backfill_v1'")
    execute('''INSERT INTO account_invitations
               (id,user_id,token_hash,delivery_email,created_at,expires_at,email_sent_at,used_at)
               VALUES (?,?,?,?,?,?,?,?)''',('historical-proof',uid,'historical-hash',
                 'wrong@example.org' if unproven=='wrong_email' else 'recover@example.org',
                 server.now(),server.now(),None if unproven=='not_sent' else server.now(),
                 None if unproven=='not_used' else server.now()))
    if unproven=='inactive':
        execute('UPDATE users SET active=0 WHERE id=?',(uid,))
    elif unproven=='inactive_link':
        execute("INSERT INTO families (id,name,status,created_at) VALUES ('inactive-linked','Synthetic','inactive',?)",(server.now(),))
        execute("UPDATE users SET role='family',linked_type='family',linked_id='inactive-linked' WHERE id=?",(uid,))
    with server.make_conn() as db:
        server._bootstrap_password_recovery(db)
    assert not db_row('SELECT 1 FROM account_recovery_email_verifications')


def test_concurrent_backfill_marker_claim(recovery):
    execute("DELETE FROM app_settings WHERE key='recovery_email_backfill_v1'")
    from threading import Barrier
    barrier=Barrier(2)
    def migrate(_):
        with server.make_conn() as db:
            barrier.wait()
            server._bootstrap_password_recovery(db)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(migrate,range(2)))
    assert db_row("SELECT COUNT(*) FROM app_settings WHERE key='recovery_email_backfill_v1'")[0]==1


def test_family_delete_with_retained_invitation_preserves_recovery_on_rollback(recovery):
    client,uid,mail=recovery
    linked='family-with-retained-proof'
    execute('INSERT INTO families (id,name,status,email,created_at) VALUES (?,?,?,?,?)',
            (linked,'Synthetic retained proof','active','recover@example.org',server.now()))
    execute("UPDATE users SET role='family',linked_type='family',linked_id=? WHERE id=?",(linked,uid))
    execute('''INSERT INTO account_invitations
               (id,user_id,token_hash,delivery_email,created_at,expires_at,email_sent_at,used_at)
               VALUES (?,?,?,?,?,?,?,?)''',('retained-proof',uid,'retained-hash','recover@example.org',
                                         server.now(),server.now(),server.now(),server.now()))
    token=request_link(recovery)
    result=client.delete('/api/families/'+linked,headers=admin_headers(client))
    # Existing v1.2.5 safety boundary: retained invitation FK blocks hard deletion;
    # staff can deactivate instead. The failed delete must not invalidate recovery.
    assert result.status_code==409
    assert db_row('SELECT 1 FROM users WHERE id=?',(uid,))
    assert db_row('SELECT 1 FROM account_recovery_email_verifications WHERE user_id=?',(uid,))
    assert consume(client,token).status_code==200

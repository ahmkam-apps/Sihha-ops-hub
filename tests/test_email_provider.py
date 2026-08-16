"""Provider-level coverage for the SendGrid-to-Twilio Email cutover."""

import base64
import json
import urllib.error

import server as app_server


def test_twilio_email_send_uses_restricted_key_payload_and_attachment(monkeypatch):
    captured = {}

    class AcceptedResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def fake_urlopen(request, timeout):
        captured['request'] = request
        captured['timeout'] = timeout
        return AcceptedResponse()

    monkeypatch.setattr(app_server, 'EMAIL_PROVIDER', 'twilio')
    monkeypatch.setattr(app_server, 'TWILIO_EMAIL_API_KEY_SID', 'SK-test-production')
    monkeypatch.setattr(app_server, 'TWILIO_EMAIL_API_KEY_SECRET', 'secret-value')
    monkeypatch.setattr(app_server, 'NOTIFY_FROM_EMAIL', 'info@sihha.org')
    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)

    assert app_server._email_send(
        'family@example.org',
        'Delivery reminder',
        'Choose groceries & confirm\nThank you.',
        attachment=('backup.db.gz', b'backup-bytes'),
    ) is True

    request = captured['request']
    payload = json.loads(request.data)
    assert request.full_url == app_server.TWILIO_EMAIL_ENDPOINT
    assert request.method == 'POST'
    assert captured['timeout'] == 30
    assert request.get_header('Authorization') == (
        'Basic ' + base64.b64encode(b'SK-test-production:secret-value').decode('ascii')
    )
    assert payload['from'] == {'address': 'info@sihha.org', 'name': 'Sihha Ops Hub'}
    assert payload['to'] == [{'address': 'family@example.org'}]
    assert payload['content']['text'] == 'Choose groceries & confirm\nThank you.'
    assert payload['content']['html'] == 'Choose groceries &amp; confirm<br>Thank you.'
    assert payload['content']['attachments'] == [{
        'filename': 'backup.db.gz',
        'contentType': 'application/gzip',
        'content': base64.b64encode(b'backup-bytes').decode('ascii'),
    }]


def test_twilio_email_rejects_oversize_request_before_network(monkeypatch):
    def unexpected_urlopen(*_args, **_kwargs):
        raise AssertionError('oversize email must not reach the provider')

    monkeypatch.setattr(app_server, 'EMAIL_PROVIDER', 'twilio')
    monkeypatch.setattr(app_server, 'TWILIO_EMAIL_API_KEY_SID', 'SK-test-production')
    monkeypatch.setattr(app_server, 'TWILIO_EMAIL_API_KEY_SECRET', 'secret-value')
    monkeypatch.setattr(app_server, 'TWILIO_EMAIL_MAX_REQUEST_BYTES', 100)
    monkeypatch.setattr('urllib.request.urlopen', unexpected_urlopen)

    assert app_server._email_send(
        'family@example.org', 'Oversize', 'x' * 200
    ) is False


def test_twilio_email_preserves_trusted_html_for_clickable_access_link(monkeypatch):
    captured = {}

    class AcceptedResponse:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def fake_urlopen(request, timeout):
        captured['payload'] = json.loads(request.data)
        return AcceptedResponse()

    monkeypatch.setattr(app_server, 'EMAIL_PROVIDER', 'twilio')
    monkeypatch.setattr(app_server, 'TWILIO_EMAIL_API_KEY_SID', 'SK-test-production')
    monkeypatch.setattr(app_server, 'TWILIO_EMAIL_API_KEY_SECRET', 'secret-value')
    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)

    html_body = '<p><a href="https://ops.sihha.org/activate#token=test">Create password</a></p>'
    assert app_server._email_send(
        'user@example.org', 'Create Your Sihha Password',
        'Create password: https://ops.sihha.org/activate#token=test',
        html_body=html_body,
    ) is True
    assert captured['payload']['content']['html'] == html_body


def test_twilio_email_health_authenticates_without_sending(
        client, auth, monkeypatch):
    captured = {}

    def validation_response(request, timeout):
        captured['request'] = request
        captured['timeout'] = timeout
        raise urllib.error.HTTPError(
            request.full_url, 400, 'Bad Request', hdrs=None, fp=None
        )

    monkeypatch.setattr(app_server, 'EMAIL_PROVIDER', 'twilio')
    monkeypatch.setattr(app_server, 'TWILIO_EMAIL_API_KEY_SID', 'SK-test-production')
    monkeypatch.setattr(app_server, 'TWILIO_EMAIL_API_KEY_SECRET', 'secret-value')
    monkeypatch.setattr('urllib.request.urlopen', validation_response)

    response = client.get('/api/admin/communications/health', headers=auth)
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'ok'
    assert data['email'] == {
        'provider': 'twilio',
        'configured': True,
        'authenticated': True,
    }
    assert data['twilio_email']['authenticated'] is True
    assert captured['request'].method == 'POST'
    assert captured['request'].data == b'{}'
    assert captured['timeout'] == 10


def test_provider_health_never_echoes_malformed_sendgrid_secret(
        client, auth, monkeypatch):
    malformed = 'SENDGRID_API_KEY\nSG.do-not-echo-this-secret'
    monkeypatch.setattr(app_server, 'EMAIL_PROVIDER', 'sendgrid')
    monkeypatch.setattr(app_server, 'SENDGRID_API_KEY', malformed)

    response = client.get('/api/admin/communications/health', headers=auth)
    assert response.status_code == 503
    body = json.dumps(response.get_json())
    assert 'SG.do-not-echo-this-secret' not in body
    assert response.get_json()['sendgrid']['error'] == 'ValueError'

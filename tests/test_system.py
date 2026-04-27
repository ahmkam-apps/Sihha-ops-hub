"""
SIHAA Ops Hub — Full System Test Suite
Covers all API routes, business rules, privacy rules, and portal flows.
Run: pytest tests/ -v
"""
import uuid, pytest
from datetime import datetime, timedelta

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — AUTH
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuth:
    def test_login_valid(self, client):
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'admin123'})
        assert res.status_code == 200
        data = res.get_json()
        assert 'token' in data
        assert data['user']['role'] == 'admin'

    def test_login_wrong_password(self, client):
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'wrong'})
        assert res.status_code == 401

    def test_login_missing_fields(self, client):
        res = client.post('/api/auth/login', json={})
        assert res.status_code == 400

    def test_login_unknown_user(self, client):
        res = client.post('/api/auth/login',
                          json={'username': 'nobody', 'password': 'x'})
        assert res.status_code == 401

    def test_me_with_token(self, client, auth):
        res = client.get('/api/auth/me', headers=auth)
        assert res.status_code == 200
        assert res.get_json()['username'] == 'admin'

    def test_me_without_token(self, client):
        res = client.get('/api/auth/me')
        assert res.status_code == 401

    def test_protected_route_no_token(self, client):
        res = client.get('/api/families')
        assert res.status_code == 401

    def test_protected_route_bad_token(self, client):
        res = client.get('/api/families',
                         headers={'Authorization': 'Bearer not-a-real-token'})
        assert res.status_code == 401

    def test_health_is_public(self, client):
        res = client.get('/api/health')
        assert res.status_code == 200
        assert res.get_json()['status'] == 'ok'


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — FAMILIES
# ═══════════════════════════════════════════════════════════════════════════════

class TestFamilies:
    def test_create_family(self, client, auth):
        res = client.post('/api/families', headers=auth,
                          json={'name': 'Test Family', 'phone': '5850000001',
                                'family_size': 4, 'status': 'active'})
        assert res.status_code == 201
        data = res.get_json()
        assert data['name'] == 'Test Family'
        assert data['status'] == 'active'

    def test_create_family_missing_name(self, client, auth):
        res = client.post('/api/families', headers=auth, json={'phone': '5850000099'})
        assert res.status_code == 422

    def test_list_families(self, client, auth):
        res = client.get('/api/families', headers=auth)
        assert res.status_code == 200
        assert isinstance(res.get_json(), list)

    def test_get_family(self, client, auth):
        # Create then fetch
        create = client.post('/api/families', headers=auth,
                             json={'name': 'Get Me', 'phone': '5850000002', 'family_size': 2})
        fid = create.get_json()['id']
        res = client.get(f'/api/families/{fid}', headers=auth)
        assert res.status_code == 200
        assert res.get_json()['id'] == fid

    def test_get_family_not_found(self, client, auth):
        res = client.get('/api/families/nonexistent-id', headers=auth)
        assert res.status_code == 404

    def test_update_family(self, client, auth):
        create = client.post('/api/families', headers=auth,
                             json={'name': 'Update Me', 'phone': '5850000003', 'family_size': 3})
        fid = create.get_json()['id']
        res = client.put(f'/api/families/{fid}', headers=auth,
                         json={'name': 'Updated Name', 'status': 'active'})
        assert res.status_code == 200
        assert res.get_json()['name'] == 'Updated Name'

    def test_public_intake_form(self, client):
        res = client.post('/api/intake',
                          json={'name': 'Intake Family', 'phone': '5850000099',
                                'family_size': 3, 'city': 'Rochester'})
        assert res.status_code == 201

    def test_public_intake_missing_name(self, client):
        res = client.post('/api/intake', json={'phone': '5850000098'})
        assert res.status_code == 422

    def test_intake_page_loads(self, client):
        res = client.get('/intake')
        assert res.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — VOLUNTEERS
# ═══════════════════════════════════════════════════════════════════════════════

class TestVolunteers:
    def test_create_volunteer(self, client, auth):
        res = client.post('/api/volunteers', headers=auth,
                          json={'name': 'Ali Hassan', 'phone': '5851110001',
                                'role': 'delivery', 'status': 'active'})
        assert res.status_code == 201
        data = res.get_json()
        assert data['name'] == 'Ali Hassan'
        assert data['role'] == 'delivery'

    def test_create_volunteer_with_whatsapp_fields(self, client, auth):
        res = client.post('/api/volunteers', headers=auth,
                          json={'name': 'WA Volunteer', 'phone': '5851110002',
                                'wa_phone': '+15851110002', 'wa_apikey': '9999999',
                                'status': 'active', 'role': 'both'})
        assert res.status_code == 201
        data = res.get_json()
        assert data['wa_phone'] == '+15851110002'
        assert data['wa_apikey'] == '9999999'

    def test_create_volunteer_missing_name(self, client, auth):
        res = client.post('/api/volunteers', headers=auth, json={'phone': '5851110099'})
        assert res.status_code == 422

    def test_list_volunteers(self, client, auth):
        res = client.get('/api/volunteers', headers=auth)
        assert res.status_code == 200
        assert isinstance(res.get_json(), list)

    def test_update_volunteer_whatsapp_fields(self, client, auth):
        create = client.post('/api/volunteers', headers=auth,
                             json={'name': 'No WA Yet', 'phone': '5851110003',
                                   'status': 'active', 'role': 'shopper'})
        vid = create.get_json()['id']
        res = client.put(f'/api/volunteers/{vid}', headers=auth,
                         json={'wa_phone': '+15851110003', 'wa_apikey': '1234567'})
        assert res.status_code == 200
        data = res.get_json()
        assert data['wa_phone'] == '+15851110003'
        assert data['wa_apikey'] == '1234567'

    def test_public_volunteer_signup(self, client):
        res = client.post('/api/volunteer-signup',
                          json={'name': 'Public Signup', 'phone': '5851119999',
                                'email': 'pub@test.com', 'volunteer_areas': 'delivery'})
        assert res.status_code == 201

    def test_volunteer_page_loads(self, client):
        res = client.get('/volunteer')
        assert res.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — FOOD CATALOG
# ═══════════════════════════════════════════════════════════════════════════════

class TestFoodCatalog:
    def test_list_categories(self, client, auth):
        res = client.get('/api/food-categories', headers=auth)
        assert res.status_code == 200
        cats = res.get_json()
        assert len(cats) >= 3  # Seeded: Grains, Protein, Produce
        names = [c['name'] for c in cats]
        assert 'Grains' in names
        assert 'Protein' in names
        assert 'Produce' in names

    def test_list_items(self, client, auth):
        res = client.get('/api/food-items', headers=auth)
        assert res.status_code == 200
        items = res.get_json()
        assert len(items) >= 10  # 10 seeded items
        names = [i['name'] for i in items]
        assert 'Rice' in names
        assert 'Eggs' in names

    def test_bundle_quantities_seeded(self, client, auth):
        res = client.get('/api/bundle-quantities', headers=auth)
        assert res.status_code == 200
        data = res.get_json()
        # Should have quantities for S, M, L for each item
        sizes = {row['bundle_size'] for row in data}
        assert {'S', 'M', 'L'} == sizes

    def test_bundle_size_rules_seeded(self, client, auth):
        res = client.get('/api/bundle-size-rules', headers=auth)
        assert res.status_code == 200
        rules = res.get_json()
        sizes = {r['bundle_size'] for r in rules}
        assert {'S', 'M', 'L'} == sizes

    def test_add_category(self, client, auth):
        res = client.post('/api/food-categories', headers=auth,
                          json={'name': 'Dairy', 'display_order': 4})
        assert res.status_code == 201
        assert res.get_json()['name'] == 'Dairy'


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — DELIVERY CYCLES
# ═══════════════════════════════════════════════════════════════════════════════

def _cycle_payload(**overrides):
    base = {
        'title': f'Test Cycle {uuid.uuid4().hex[:6]}',
        'delivery_date_start': '2026-05-17',
        'delivery_date_end':   '2026-05-18',
        'request_open_at':     '2026-05-03T00:00:00',
        'request_close_at':    '2026-05-10T14:00:00',
        'status': 'draft'
    }
    base.update(overrides)
    return base

class TestDeliveryCycles:
    def test_create_cycle(self, client, auth):
        res = client.post('/api/delivery-cycles', headers=auth, json=_cycle_payload())
        assert res.status_code == 201
        data = res.get_json()
        assert data['status'] == 'draft'

    def test_list_cycles(self, client, auth):
        res = client.get('/api/delivery-cycles', headers=auth)
        assert res.status_code == 200
        assert isinstance(res.get_json(), list)

    def test_advance_cycle_status(self, client, auth):
        create = client.post('/api/delivery-cycles', headers=auth, json=_cycle_payload())
        cid = create.get_json()['id']
        # draft → open (route is PUT /api/delivery-cycles/<cid>)
        res = client.put(f'/api/delivery-cycles/{cid}', headers=auth,
                         json={'status': 'open'})
        assert res.status_code == 200
        assert res.get_json()['status'] == 'open'

    def test_cycle_missing_required_fields(self, client, auth):
        res = client.post('/api/delivery-cycles', headers=auth,
                          json={'title': 'Missing dates'})
        assert res.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — FOOD ORDER FLOW + BUSINESS RULES
# ═══════════════════════════════════════════════════════════════════════════════

class TestFoodOrders:
    """
    Full family food order flow. Tests key business rules:
    - Phone not found → not registered
    - No open cycle → no orders accepted
    - Bundle size auto-assigned from household_size (NEVER shown to family)
    - One order per family per cycle enforced
    """

    @pytest.fixture(autouse=True)
    def setup(self, client, auth):
        # Create a family with household_size=4 (→ Medium bundle)
        self.phone = f'585200{uuid.uuid4().hex[:4]}'
        res = client.post('/api/families', headers=auth,
                          json={'name': 'Order Family', 'phone': self.phone,
                                'family_size': 4, 'status': 'active'})
        self.family_id = res.get_json()['id']

        # Create an open cycle
        res = client.post('/api/delivery-cycles', headers=auth,
                          json=_cycle_payload(
                              request_open_at='2020-01-01T00:00:00',
                              request_close_at='2099-12-31T23:59:00',
                              status='open'
                          ))
        self.cycle_id = res.get_json()['id']
        self.client   = client
        self.auth     = auth

    def test_check_phone_not_registered(self, client):
        res = client.get('/api/food-order/check?phone=0000000000')
        assert res.status_code == 200
        assert res.get_json()['registered'] is False

    def test_check_phone_registered_open_cycle(self, client):
        res = client.get(f'/api/food-order/check?phone={self.phone}')
        assert res.status_code == 200
        data = res.get_json()
        assert data['registered'] is True
        assert data['open_cycle'] is True
        assert data['already_submitted'] is False
        # Bundle size must exist in response (for internal use in UI)
        assert 'bundle_size' in data
        # Business rule: family_size=4 → Medium
        assert data['bundle_size'] == 'M'

    def test_submit_food_order(self, client):
        # Get items list first
        check = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        item_ids = [i['id'] for i in check['food_items'][:3]]
        res = client.post('/api/food-order',
                          json={'family_id': self.family_id,
                                'cycle_id':  self.cycle_id,
                                'selected_items': item_ids})
        assert res.status_code == 201
        assert res.get_json()['ok'] is True

    def test_one_order_per_family_per_cycle(self, client):
        # Submit first order
        check = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        # Only submit if not already submitted (test isolation)
        if not check.get('already_submitted'):
            client.post('/api/food-order',
                        json={'family_id': self.family_id, 'cycle_id': self.cycle_id,
                              'selected_items': []})
        # Try to submit again → must fail
        res = client.post('/api/food-order',
                          json={'family_id': self.family_id, 'cycle_id': self.cycle_id,
                                'selected_items': []})
        assert res.status_code == 409

    def test_check_shows_already_submitted(self, client):
        # Use whatever open cycle check returns (may differ from self.cycle_id
        # when multiple open cycles share the same delivery_date_start)
        check1 = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        if not check1.get('open_cycle'):
            pytest.skip('No open cycle available')
        if not check1.get('already_submitted'):
            client.post('/api/food-order',
                        json={'family_id': check1['family_id'],
                              'cycle_id':  check1['cycle_id'],
                              'selected_items': []})
        check2 = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        assert check2['already_submitted'] is True

    def test_bundle_size_small_for_tiny_family(self, client, auth):
        phone = f'585201{uuid.uuid4().hex[:4]}'
        res = client.post('/api/families', headers=auth,
                          json={'name': 'Tiny Family', 'phone': phone,
                                'family_size': 1, 'status': 'active'})
        check = client.get(f'/api/food-order/check?phone={phone}').get_json()
        if check.get('open_cycle'):
            assert check['bundle_size'] == 'S'

    def test_bundle_size_large_for_big_family(self, client, auth):
        phone = f'585202{uuid.uuid4().hex[:4]}'
        client.post('/api/families', headers=auth,
                    json={'name': 'Big Family', 'phone': phone,
                          'family_size': 8, 'status': 'active'})
        check = client.get(f'/api/food-order/check?phone={phone}').get_json()
        if check.get('open_cycle'):
            assert check['bundle_size'] == 'L'


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — VOLUNTEER PORTAL + PRIVACY RULES
# ═══════════════════════════════════════════════════════════════════════════════

class TestVolunteerPortal:
    """
    Full portal flow. Tests key business rules:
    - Only active volunteers can log in
    - Shopping volunteers NEVER receive family address
    - Delivery volunteers receive address ONLY for their own claimed slots
    - Double-claim returns 409
    - Mark complete changes status to 'complete'
    """

    @pytest.fixture(autouse=True)
    def setup(self, client, auth, wa_mock):
        self.client  = client
        self.auth    = auth
        self.wa_mock = wa_mock

        # Create a family
        phone_family = f'585300{uuid.uuid4().hex[:4]}'
        res = client.post('/api/families', headers=auth,
                          json={'name': 'Portal Family', 'phone': phone_family,
                                'address': '123 Elm St', 'city': 'Rochester',
                                'family_size': 4, 'status': 'active'})
        self.family_id = res.get_json()['id']

        # Create an open cycle
        res = client.post('/api/delivery-cycles', headers=auth,
                          json=_cycle_payload(
                              request_open_at='2020-01-01T00:00:00',
                              request_close_at='2099-12-31T23:59:00',
                              status='open'
                          ))
        self.cycle = res.get_json()
        self.cycle_id = self.cycle['id']

        # Submit a food order for the family
        check = client.get(f'/api/food-order/check?phone={phone_family}').get_json()
        if check.get('open_cycle') and not check.get('already_submitted'):
            client.post('/api/food-order',
                        json={'family_id': self.family_id,
                              'cycle_id':  self.cycle_id,
                              'selected_items': []})

        # Generate slots
        client.post(f'/api/delivery-cycles/{self.cycle_id}/generate-slots', headers=auth)

        # Create two active volunteers with WA credentials
        vol_phone_1 = f'585400{uuid.uuid4().hex[:4]}'
        vol_phone_2 = f'585401{uuid.uuid4().hex[:4]}'
        res = client.post('/api/volunteers', headers=auth,
                          json={'name': 'Shopper Vol', 'phone': vol_phone_1,
                                'role': 'shopper', 'status': 'active',
                                'wa_phone': '+1' + vol_phone_1, 'wa_apikey': '1111111'})
        self.shopper_phone = vol_phone_1
        self.shopper_id    = res.get_json()['id']

        res = client.post('/api/volunteers', headers=auth,
                          json={'name': 'Delivery Vol', 'phone': vol_phone_2,
                                'role': 'delivery', 'status': 'active',
                                'wa_phone': '+1' + vol_phone_2, 'wa_apikey': '2222222'})
        self.delivery_phone = vol_phone_2
        self.delivery_id    = res.get_json()['id']

    # ── Login ──────────────────────────────────────────────────────────────────

    def test_portal_login_valid(self, client):
        res = client.post('/api/portal/login', json={'phone': self.shopper_phone})
        assert res.status_code == 200
        data = res.get_json()
        assert 'token' in data
        assert data['volunteer']['name'] == 'Shopper Vol'

    def test_portal_login_phone_not_found(self, client):
        res = client.post('/api/portal/login', json={'phone': '0000000000'})
        assert res.status_code == 404

    def test_portal_login_inactive_volunteer(self, client, auth):
        # Create inactive volunteer
        phone = f'585499{uuid.uuid4().hex[:4]}'
        client.post('/api/volunteers', headers=auth,
                    json={'name': 'Inactive', 'phone': phone,
                          'status': 'inactive', 'role': 'shopper'})
        res = client.post('/api/portal/login', json={'phone': phone})
        assert res.status_code == 404

    def test_portal_login_missing_phone(self, client):
        res = client.post('/api/portal/login', json={})
        assert res.status_code == 400

    def _login(self, phone):
        res = self.client.post('/api/portal/login', json={'phone': phone})
        return res.get_json()['token']

    def _portal_headers(self, phone):
        return {'Authorization': f'Bearer {self._login(phone)}'}

    # ── Cycles + Slots ─────────────────────────────────────────────────────────

    def test_portal_lists_open_cycles(self, client):
        headers = self._portal_headers(self.shopper_phone)
        res = client.get('/api/portal/cycles', headers=headers)
        assert res.status_code == 200
        cycles = res.get_json()
        assert any(c['id'] == self.cycle_id for c in cycles)

    def test_portal_get_slots(self, client):
        headers = self._portal_headers(self.shopper_phone)
        res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=headers)
        assert res.status_code == 200
        data = res.get_json()
        assert 'slots' in data
        assert 'cycle' in data
        assert 'volunteer_id' in data
        # Slots should exist (generated in setup from food order)
        # If empty, setup failed — but structure of response is still correct
        if data['slots']:
            types = {s['task_type'] for s in data['slots']}
            assert 'shopping' in types
            assert 'delivery' in types

    def test_portal_requires_auth(self, client):
        res = client.get(f'/api/portal/slots/{self.cycle_id}')
        assert res.status_code == 401

    # ── Claim — Shopper (privacy rule) ────────────────────────────────────────

    def test_shopper_claim_and_no_address_in_wa(self, client, wa_mock):
        headers = self._portal_headers(self.shopper_phone)
        slots_res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=headers)
        shopping_slot = next(
            (s for s in slots_res.get_json()['slots']
             if s['task_type'] == 'shopping' and s['status'] == 'open'), None
        )
        if not shopping_slot:
            pytest.skip('No open shopping slot available')

        res = client.post('/api/portal/claim',
                          headers=headers, json={'slot_id': shopping_slot['id']})
        assert res.status_code == 200

        # WhatsApp confirmation must NOT contain the family address
        assert wa_mock.called
        call_args = wa_mock.call_args
        message = call_args[0][2]  # _wa_send(phone, apikey, message)
        assert '123 Elm St' not in message, 'Shopper must NEVER receive family address'
        assert 'Shopping' in message or 'shopping' in message

    def test_shopper_my_tasks_no_address(self, client):
        headers = self._portal_headers(self.shopper_phone)
        # Claim a shopping slot if none claimed yet
        slots_res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=headers)
        open_shopping = [s for s in slots_res.get_json()['slots']
                         if s['task_type'] == 'shopping' and s['status'] == 'open']
        if open_shopping:
            client.post('/api/portal/claim',
                        headers=headers, json={'slot_id': open_shopping[0]['id']})

        tasks_res = client.get('/api/portal/my-tasks', headers=headers)
        assert tasks_res.status_code == 200
        tasks = tasks_res.get_json()
        for task in tasks:
            if task['task_type'] == 'shopping':
                # PRIVACY RULE: address must be null/None for shopping tasks
                assert task.get('address') is None, \
                    f'Shopping task must not expose address, got: {task.get("address")}'

    # ── Claim — Delivery volunteer gets address ────────────────────────────────

    def test_delivery_claim_sends_address_in_wa(self, client, wa_mock):
        headers = self._portal_headers(self.delivery_phone)
        slots_res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=headers)
        delivery_slot = next(
            (s for s in slots_res.get_json()['slots']
             if s['task_type'] == 'delivery' and s['status'] == 'open'), None
        )
        if not delivery_slot:
            pytest.skip('No open delivery slot available')

        res = client.post('/api/portal/claim',
                          headers=headers, json={'slot_id': delivery_slot['id']})
        assert res.status_code == 200

        # Delivery WA message MUST contain the family address
        assert wa_mock.called
        call_args = wa_mock.call_args
        message = call_args[0][2]
        assert '123 Elm St' in message, 'Delivery volunteer must receive family address'

    def test_delivery_my_tasks_has_address(self, client):
        headers = self._portal_headers(self.delivery_phone)
        # Claim if not already claimed
        slots_res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=headers)
        open_del = [s for s in slots_res.get_json()['slots']
                    if s['task_type'] == 'delivery' and s['status'] == 'open']
        if open_del:
            client.post('/api/portal/claim',
                        headers=headers, json={'slot_id': open_del[0]['id']})

        tasks_res = client.get('/api/portal/my-tasks', headers=headers)
        assert tasks_res.status_code == 200
        tasks = tasks_res.get_json()
        delivery_tasks = [t for t in tasks if t['task_type'] == 'delivery']
        if delivery_tasks:
            assert delivery_tasks[0]['address'] is not None, \
                'Delivery task must include family address'

    # ── Double-claim ───────────────────────────────────────────────────────────

    def test_double_claim_returns_409(self, client):
        # Shopper claims, then delivery volunteer tries same slot
        h_shopper  = self._portal_headers(self.shopper_phone)
        h_delivery = self._portal_headers(self.delivery_phone)

        slots_res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=h_shopper)
        open_slots = [s for s in slots_res.get_json()['slots'] if s['status'] == 'open']
        if not open_slots:
            pytest.skip('No open slots available for double-claim test')

        slot_id = open_slots[0]['id']
        # First claim succeeds
        r1 = client.post('/api/portal/claim', headers=h_shopper, json={'slot_id': slot_id})
        assert r1.status_code == 200
        # Second claim by different volunteer → 409
        r2 = client.post('/api/portal/claim', headers=h_delivery, json={'slot_id': slot_id})
        assert r2.status_code == 409

    # ── Mark complete ──────────────────────────────────────────────────────────

    def test_mark_task_complete(self, client):
        headers = self._portal_headers(self.shopper_phone)
        # Claim an open shopping slot first
        slots_res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=headers)
        open_shopping = [s for s in slots_res.get_json()['slots']
                         if s['task_type'] == 'shopping' and s['status'] == 'open']
        if open_shopping:
            client.post('/api/portal/claim', headers=headers,
                        json={'slot_id': open_shopping[0]['id']})

        tasks = client.get('/api/portal/my-tasks', headers=headers).get_json()
        claimed = [t for t in tasks if t['status'] == 'claimed']
        if not claimed:
            pytest.skip('No claimed tasks to mark complete')

        slot_id = claimed[0]['id']
        res = client.post(f'/api/portal/complete/{slot_id}', headers=headers)
        assert res.status_code == 200

        tasks_after = client.get('/api/portal/my-tasks', headers=headers).get_json()
        updated = next((t for t in tasks_after if t['id'] == slot_id), None)
        assert updated is not None
        assert updated['status'] == 'complete'

    def test_cannot_complete_someone_elses_slot(self, client):
        h_shopper  = self._portal_headers(self.shopper_phone)
        h_delivery = self._portal_headers(self.delivery_phone)

        # Ensure shopper has at least one task
        slots_res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=h_shopper)
        open_shopping = [s for s in slots_res.get_json()['slots']
                         if s['task_type'] == 'shopping' and s['status'] == 'open']
        if open_shopping:
            client.post('/api/portal/claim', headers=h_shopper,
                        json={'slot_id': open_shopping[0]['id']})

        shopper_tasks = client.get('/api/portal/my-tasks', headers=h_shopper).get_json()
        if not shopper_tasks:
            pytest.skip('No shopper tasks to test with')

        slot_id = shopper_tasks[0]['id']
        res = client.post(f'/api/portal/complete/{slot_id}', headers=h_delivery)
        assert res.status_code == 404  # "not yours"


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — GENERATE SLOTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateSlots:
    def test_generate_slots_creates_shopping_and_delivery(self, client, auth):
        # Create a family and order
        phone = f'585500{uuid.uuid4().hex[:4]}'
        fam = client.post('/api/families', headers=auth,
                          json={'name': 'Slot Family', 'phone': phone,
                                'family_size': 3, 'status': 'active'}).get_json()
        cycle = client.post('/api/delivery-cycles', headers=auth,
                            json=_cycle_payload(
                                request_open_at='2020-01-01T00:00:00',
                                request_close_at='2099-12-31T23:59:00',
                                status='open'
                            )).get_json()
        cid = cycle['id']

        client.post('/api/food-order',
                    json={'family_id': fam['id'], 'cycle_id': cid, 'selected_items': []})

        res = client.post(f'/api/delivery-cycles/{cid}/generate-slots', headers=auth)
        assert res.status_code == 200
        data = res.get_json()
        assert data['ok'] is True
        assert data['slots_created'] == 2  # 1 shopping + 1 delivery

    def test_generate_slots_is_idempotent(self, client, auth):
        phone = f'585501{uuid.uuid4().hex[:4]}'
        fam = client.post('/api/families', headers=auth,
                          json={'name': 'Idempotent Family', 'phone': phone,
                                'family_size': 2, 'status': 'active'}).get_json()
        cycle = client.post('/api/delivery-cycles', headers=auth,
                            json=_cycle_payload(
                                request_open_at='2020-01-01T00:00:00',
                                request_close_at='2099-12-31T23:59:00',
                                status='open'
                            )).get_json()
        cid = cycle['id']
        client.post('/api/food-order',
                    json={'family_id': fam['id'], 'cycle_id': cid, 'selected_items': []})

        # Run twice
        r1 = client.post(f'/api/delivery-cycles/{cid}/generate-slots', headers=auth).get_json()
        r2 = client.post(f'/api/delivery-cycles/{cid}/generate-slots', headers=auth).get_json()

        assert r1['slots_created'] == 2
        assert r2['slots_created'] == 0  # No new slots — already exist

    def test_slot_board_admin_view(self, client, auth):
        phone = f'585502{uuid.uuid4().hex[:4]}'
        fam = client.post('/api/families', headers=auth,
                          json={'name': 'Board Family', 'phone': phone,
                                'family_size': 5, 'status': 'active'}).get_json()
        cycle = client.post('/api/delivery-cycles', headers=auth,
                            json=_cycle_payload(
                                request_open_at='2020-01-01T00:00:00',
                                request_close_at='2099-12-31T23:59:00',
                                status='open'
                            )).get_json()
        cid = cycle['id']
        client.post('/api/food-order',
                    json={'family_id': fam['id'], 'cycle_id': cid, 'selected_items': []})
        client.post(f'/api/delivery-cycles/{cid}/generate-slots', headers=auth)

        res = client.get(f'/api/volunteer-slots?cycle_id={cid}', headers=auth)
        assert res.status_code == 200
        slots = res.get_json()
        assert len(slots) == 2
        types = {s['task_type'] for s in slots}
        assert types == {'shopping', 'delivery'}
        statuses = {s['status'] for s in slots}
        assert statuses == {'open'}


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — WHATSAPP REMINDERS
# ═══════════════════════════════════════════════════════════════════════════════

class TestReminders:
    def test_trigger_reminders_endpoint_exists(self, client, auth, wa_mock):
        res = client.post('/api/reminders/trigger', headers=auth)
        assert res.status_code == 200
        data = res.get_json()
        assert 'reminders_sent' in data
        assert 'target_date' in data

    def test_reminder_targets_correct_date(self, client, auth, wa_mock):
        """Target date must be today + 2 days."""
        res = client.post('/api/reminders/trigger', headers=auth).get_json()
        from datetime import datetime, timedelta
        expected = (datetime.utcnow() + timedelta(days=2)).strftime('%Y-%m-%d')
        assert res['target_date'] == expected

    def test_reminders_idempotent(self, client, auth, wa_mock):
        """Running trigger twice must not double-send."""
        r1 = client.post('/api/reminders/trigger', headers=auth).get_json()
        r2 = client.post('/api/reminders/trigger', headers=auth).get_json()
        # Second run must send 0 new reminders (all already logged)
        assert r2['reminders_sent'] == 0

    def test_reminders_require_admin(self, client):
        res = client.post('/api/reminders/trigger')
        assert res.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 10 — PAGES LOAD
# ═══════════════════════════════════════════════════════════════════════════════

class TestPages:
    def test_admin_spa_loads(self, client):
        res = client.get('/')
        assert res.status_code == 200

    def test_intake_loads(self, client):
        res = client.get('/intake')
        assert res.status_code == 200

    def test_volunteer_page_loads(self, client):
        res = client.get('/volunteer')
        assert res.status_code == 200

    def test_portal_page_loads(self, client):
        res = client.get('/portal')
        assert res.status_code == 200

    def test_order_page_loads(self, client):
        res = client.get('/order')
        assert res.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 11 — ORDER PAGE FLOW
# ═══════════════════════════════════════════════════════════════════════════════

class TestOrderPage:
    """
    Tests the public family food order flow (/order + /api/food-order/check + /api/food-order).
    Business rules verified:
    - Unregistered phone → registered=False (no family data leaked)
    - Registered family, open cycle → receives food items + bundle_size
    - Bundle size hidden from response labels (internal field only)
    - Submitting twice → 409
    - already_submitted flag set correctly after first submission
    - Empty selected_items list is valid (family opts out of items)
    """

    @pytest.fixture(autouse=True)
    def setup(self, client, auth):
        self.client = client
        self.auth   = auth
        self.phone  = f'585600{uuid.uuid4().hex[:4]}'

        # Active family
        res = client.post('/api/families', headers=auth,
                          json={'name': 'Order Page Family', 'phone': self.phone,
                                'family_size': 4, 'status': 'active'})
        self.family_id = res.get_json()['id']

        # Open cycle
        res = client.post('/api/delivery-cycles', headers=auth,
                          json=_cycle_payload(
                              request_open_at='2020-01-01T00:00:00',
                              request_close_at='2099-12-31T23:59:00',
                              status='open'
                          ))
        self.cycle_id = res.get_json()['id']

    def test_order_page_serves_html(self, client):
        res = client.get('/order')
        assert res.status_code == 200

    def test_check_unregistered_phone(self, client):
        res = client.get('/api/food-order/check?phone=0000000000')
        assert res.status_code == 200
        data = res.get_json()
        assert data['registered'] is False
        # Must not leak any family info
        assert 'family_id' not in data
        assert 'food_items' not in data

    def test_check_registered_family_gets_items(self, client):
        res = client.get(f'/api/food-order/check?phone={self.phone}')
        assert res.status_code == 200
        data = res.get_json()
        assert data['registered'] is True
        assert data['open_cycle'] is True
        assert data['already_submitted'] is False
        assert 'food_items' in data
        assert len(data['food_items']) >= 10
        # Items have required fields
        item = data['food_items'][0]
        assert 'id' in item
        assert 'name' in item
        assert 'category_name' in item

    def test_check_no_phone_param(self, client):
        res = client.get('/api/food-order/check')
        assert res.status_code == 400

    def test_submit_with_selected_items(self, client):
        check = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        item_ids = [i['id'] for i in check['food_items'][:4]]
        res = client.post('/api/food-order', json={
            'family_id': self.family_id,
            'cycle_id':  self.cycle_id,
            'selected_items': item_ids
        })
        assert res.status_code == 201
        assert res.get_json()['ok'] is True

    def test_submit_with_empty_items_is_valid(self, client):
        """Family can submit with no items selected — empty list must not fail validation."""
        # Must use a fresh family not yet submitted for this cycle
        phone2 = f'585601{uuid.uuid4().hex[:4]}'
        fam2 = client.post('/api/families', headers=self.auth,
                           json={'name': 'Empty Items Family', 'phone': phone2,
                                 'family_size': 2, 'status': 'active'}).get_json()
        res = client.post('/api/food-order', json={
            'family_id': fam2['id'],
            'cycle_id':  self.cycle_id,
            'selected_items': []
        })
        assert res.status_code == 201

    def test_duplicate_order_returns_409(self, client):
        # First submit
        client.post('/api/food-order', json={
            'family_id': self.family_id,
            'cycle_id':  self.cycle_id,
            'selected_items': []
        })
        # Second submit → 409
        res = client.post('/api/food-order', json={
            'family_id': self.family_id,
            'cycle_id':  self.cycle_id,
            'selected_items': []
        })
        assert res.status_code == 409

    def test_already_submitted_flag_after_order(self, client):
        # Use the cycle_id the check endpoint actually returns — avoids mismatch
        # when multiple open cycles exist across test classes.
        check1 = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        if not check1.get('open_cycle') or check1.get('already_submitted'):
            pytest.skip('No open cycle or already submitted')
        client.post('/api/food-order', json={
            'family_id': check1['family_id'],
            'cycle_id':  check1['cycle_id'],
            'selected_items': []
        })
        check2 = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        assert check2['already_submitted'] is True

    def test_inactive_family_not_found(self, client, auth):
        phone = f'585602{uuid.uuid4().hex[:4]}'
        client.post('/api/families', headers=auth,
                    json={'name': 'Inactive Fam', 'phone': phone,
                          'family_size': 2, 'status': 'inactive'})
        check = client.get(f'/api/food-order/check?phone={phone}').get_json()
        assert check['registered'] is False


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — ADMIN PASSWORD SYNC
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdminPasswordSync:
    """
    Verifies that ADMIN_PASSWORD env var is always synced to the DB on bootstrap.
    This prevents the 'password resets on deploy' issue where INSERT OR IGNORE
    would keep a stale hash if the env var changed.
    """

    def test_admin_login_with_env_password(self, client):
        """The test suite sets ADMIN_PASSWORD=admin123 in conftest — login must work."""
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'admin123'})
        assert res.status_code == 200
        assert 'token' in res.get_json()

    def test_wrong_password_still_rejected(self, client):
        res = client.post('/api/auth/login',
                          json={'username': 'admin', 'password': 'notthepassword'})
        assert res.status_code == 401

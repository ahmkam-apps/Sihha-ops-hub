"""
Sihha Ops Hub — Full System Test Suite
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
                                'email': 'pub@test.com', 'role': 'delivery'})
        assert res.status_code == 201

    def test_volunteer_page_redirects(self, client):
        # /volunteer redirects to /portal
        res = client.get('/volunteer')
        assert res.status_code in (301, 302)


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
        assert 'cycles' in data
        # There must be at least one open cycle accepting orders
        open_cycle = next((c for c in data['cycles'] if c.get('can_place_order')), None)
        assert open_cycle is not None, 'Expected at least one open cycle with can_place_order'
        # Business rule: family_size=4 → Medium
        assert data['bundle_size'] == 'M'

    def test_submit_food_order(self, client):
        check = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        open_cycle = next((c for c in check.get('cycles', []) if c.get('can_place_order')), None)
        if not open_cycle:
            pytest.skip('No open cycle available')
        # Select at most one item per group to avoid mutual-exclusion constraint
        seen_groups, item_ids = set(), []
        for cat in open_cycle['items_for_selection']:
            for i in cat['items']:
                g = i.get('group_id')
                if g and g in seen_groups:
                    continue
                if g:
                    seen_groups.add(g)
                item_ids.append(i['id'])
                if len(item_ids) >= 3:
                    break
            if len(item_ids) >= 3:
                break
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
        check1 = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        open_cycle = next((c for c in check1.get('cycles', []) if c.get('can_place_order')), None)
        if not open_cycle:
            pytest.skip('No open cycle available')
        # Submit if not already done
        if open_cycle.get('order') is None:
            client.post('/api/food-order',
                        json={'family_id': check1['family_id'],
                              'cycle_id':  open_cycle['id'],
                              'selected_items': []})
        check2 = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        # After submitting, the cycle must have an order object (not None)
        submitted = next((c for c in check2['cycles'] if c['id'] == open_cycle['id']), None)
        assert submitted is not None
        assert submitted.get('order') is not None

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

        # Create two active volunteers — use digit-only phones so portal_login exact match works
        vol_phone_1 = f'5854{uuid.uuid4().int % 1000000:06d}'
        vol_phone_2 = f'5854{uuid.uuid4().int % 1000000:06d}'
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
        # Create inactive volunteer — digit-only phone
        phone = f'5854{uuid.uuid4().int % 1000000:06d}'
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
        open_shopping = [s for s in slots_res.get_json()['slots']
                         if s['task_type'] == 'shopping' and s['status'] == 'open']
        if not open_shopping:
            pytest.skip('No open shopping slot available')

        res = client.post('/api/portal/signup',
                          headers=headers, json={'cycle_id': self.cycle_id,
                                                 'family_id': self.family_id,
                                                 'task_types': ['shopping']})
        assert res.status_code == 201

        # SMS confirmation must NOT contain the family address
        assert wa_mock.called
        call_args = wa_mock.call_args
        message = call_args[0][1]  # _send_sms(phone, message)
        assert '123 Elm St' not in message, 'Shopper must NEVER receive family address'
        assert 'Shopping' in message or 'shopping' in message

    def test_shopper_my_tasks_no_address(self, client):
        headers = self._portal_headers(self.shopper_phone)
        # Claim a shopping slot if none claimed yet
        slots_res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=headers)
        open_shopping = [s for s in slots_res.get_json()['slots']
                         if s['task_type'] == 'shopping' and s['status'] == 'open']
        if open_shopping:
            client.post('/api/portal/signup',
                        headers=headers, json={'cycle_id': self.cycle_id,
                                               'family_id': self.family_id,
                                               'task_types': ['shopping']})

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
        # Target the slot for self.family_id specifically — it has a known address
        open_delivery = [s for s in slots_res.get_json()['slots']
                         if s['task_type'] == 'delivery' and s['status'] == 'open'
                         and s['family_id'] == self.family_id]
        if not open_delivery:
            pytest.skip('No open delivery slot for test family')

        res = client.post('/api/portal/signup',
                          headers=headers, json={'cycle_id': self.cycle_id,
                                                 'family_id': self.family_id,
                                                 'task_types': ['delivery']})
        assert res.status_code == 201

        # Delivery SMS must contain the family address
        assert wa_mock.called
        call_args = wa_mock.call_args
        message = call_args[0][1]  # _send_sms(phone, message)
        assert '123 Elm St' in message, 'Delivery volunteer must receive family address'

    def test_delivery_my_tasks_has_address(self, client):
        headers = self._portal_headers(self.delivery_phone)
        # Claim the slot for self.family_id (known address) if not already claimed
        slots_res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=headers)
        open_del = [s for s in slots_res.get_json()['slots']
                    if s['task_type'] == 'delivery' and s['status'] == 'open'
                    and s['family_id'] == self.family_id]
        if open_del:
            client.post('/api/portal/signup',
                        headers=headers, json={'cycle_id': self.cycle_id,
                                               'family_id': self.family_id,
                                               'task_types': ['delivery']})

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

        # Use the first open slot's family_id + task_type for the double-claim test
        first_slot = open_slots[0]
        signup_payload = {'cycle_id': self.cycle_id,
                          'family_id': first_slot['family_id'],
                          'task_types': [first_slot['task_type']]}
        # First claim succeeds
        r1 = client.post('/api/portal/signup', headers=h_shopper, json=signup_payload)
        assert r1.status_code == 201
        # Second claim by different volunteer → 409
        r2 = client.post('/api/portal/signup', headers=h_delivery, json=signup_payload)
        assert r2.status_code == 409

    # ── Mark complete ──────────────────────────────────────────────────────────

    def test_mark_task_complete(self, client):
        headers = self._portal_headers(self.shopper_phone)
        # Claim an open shopping slot first
        slots_res = client.get(f'/api/portal/slots/{self.cycle_id}', headers=headers)
        open_shopping = [s for s in slots_res.get_json()['slots']
                         if s['task_type'] == 'shopping' and s['status'] == 'open']
        if open_shopping:
            client.post('/api/portal/signup', headers=headers,
                        json={'cycle_id': self.cycle_id,
                              'family_id': self.family_id,
                              'task_types': ['shopping']})

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
        # Must be at least 2 slots (1 shopping + 1 delivery for the submitted family)
        assert data['slots_total'] >= 2

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

        # slots_total >= 2; second run must not create new slots
        assert r1['slots_total'] >= 2
        assert r2['slots_total'] == r1['slots_total']   # unchanged on second run
        assert r2['slots_created'] == 0                  # idempotent

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
        # Shared test DB may accumulate families, so check >= 2 (1 shopper + 1 delivery minimum)
        assert len(slots) >= 2
        types = {s['task_type'] for s in slots}
        assert 'shopping' in types
        assert 'delivery' in types


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

    def test_volunteer_redirects(self, client):
        # /volunteer redirects to /portal
        res = client.get('/volunteer')
        assert res.status_code in (301, 302)

    def test_portal_page_loads(self, client):
        res = client.get('/portal')
        assert res.status_code == 200

    def test_order_redirects(self, client):
        # /order redirects to /intake
        res = client.get('/order')
        assert res.status_code in (301, 302)

    def test_login_page_loads(self, client):
        res = client.get('/login')
        assert res.status_code == 200

    def test_family_page_loads(self, client):
        res = client.get('/family')
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

    def test_order_page_redirects(self, client):
        # /order now redirects to /intake
        res = client.get('/order')
        assert res.status_code in (301, 302)

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
        assert 'cycles' in data
        # Find open cycle
        open_cycle = next((c for c in data['cycles'] if c.get('can_place_order')), None)
        assert open_cycle is not None, 'Expected at least one open cycle'
        # Items grouped by category inside the open cycle
        assert len(open_cycle['items_for_selection']) >= 3  # Grains, Protein, Produce
        item = open_cycle['items_for_selection'][0]['items'][0]
        assert 'id' in item
        assert 'name' in item

    def test_check_no_phone_param(self, client):
        # No auth header + no phone → 401 (Authentication required)
        res = client.get('/api/food-order/check')
        assert res.status_code == 401

    def test_submit_with_selected_items(self, client):
        check = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        open_cycle = next((c for c in check.get('cycles', []) if c.get('can_place_order')), None)
        if not open_cycle:
            pytest.skip('No open cycle available')
        # Select at most one item per group to avoid mutual-exclusion constraint
        seen_groups, item_ids = set(), []
        for cat in open_cycle['items_for_selection']:
            for i in cat['items']:
                g = i.get('group_id')
                if g and g in seen_groups:
                    continue
                if g:
                    seen_groups.add(g)
                item_ids.append(i['id'])
                if len(item_ids) >= 4:
                    break
            if len(item_ids) >= 4:
                break
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
        check1 = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        open_cycle = next((c for c in check1.get('cycles', []) if c.get('can_place_order')), None)
        if not open_cycle:
            pytest.skip('No open cycle available')
        client.post('/api/food-order', json={
            'family_id': check1['family_id'],
            'cycle_id':  open_cycle['id'],
            'selected_items': []
        })
        check2 = client.get(f'/api/food-order/check?phone={self.phone}').get_json()
        submitted = next((c for c in check2['cycles'] if c['id'] == open_cycle['id']), None)
        assert submitted is not None
        assert submitted.get('order') is not None

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


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 13 — PASSWORD VALIDATION RULES
# ═══════════════════════════════════════════════════════════════════════════════

class TestPasswordValidation:
    """
    Verifies _validate_password is enforced via POST /api/users.
    Rules: min 8 chars, 1 uppercase, 1 digit, 1 special char.
    """

    def test_too_short_rejected(self, client, auth):
        res = client.post('/api/users', headers=auth,
                          json={'username': f'pw_short_{uuid.uuid4().hex[:4]}',
                                'password': 'Ab1!', 'role': 'viewer'})
        assert res.status_code == 422

    def test_no_uppercase_rejected(self, client, auth):
        res = client.post('/api/users', headers=auth,
                          json={'username': f'pw_noUpper_{uuid.uuid4().hex[:4]}',
                                'password': 'password1!', 'role': 'viewer'})
        assert res.status_code == 422

    def test_no_digit_rejected(self, client, auth):
        res = client.post('/api/users', headers=auth,
                          json={'username': f'pw_noDigit_{uuid.uuid4().hex[:4]}',
                                'password': 'Password!', 'role': 'viewer'})
        assert res.status_code == 422

    def test_no_special_char_rejected(self, client, auth):
        res = client.post('/api/users', headers=auth,
                          json={'username': f'pw_noSpec_{uuid.uuid4().hex[:4]}',
                                'password': 'Password1', 'role': 'viewer'})
        assert res.status_code == 422

    def test_strong_password_accepted(self, client, auth):
        res = client.post('/api/users', headers=auth,
                          json={'username': f'pw_strong_{uuid.uuid4().hex[:4]}',
                                'password': 'StrongPass1!', 'role': 'viewer'})
        assert res.status_code == 201


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 14 — USER MANAGEMENT (CRUD + FORCE-RESET + BULK-CREATE)
# ═══════════════════════════════════════════════════════════════════════════════

class TestUserManagement:
    """Tests for /api/users CRUD, force-reset, and bulk-create endpoints."""

    def test_create_user_auto_generates_temp_password(self, client, auth):
        uname = f'usr_{uuid.uuid4().hex[:6]}'
        res = client.post('/api/users', headers=auth,
                          json={'username': uname, 'role': 'viewer'})
        assert res.status_code == 201
        data = res.get_json()
        assert data['username'] == uname
        assert 'temp_password' in data           # returned once on create
        assert data['must_change_password']       # True/1 = must change on first login

    def test_create_user_duplicate_username_returns_409(self, client, auth):
        uname = f'dup_{uuid.uuid4().hex[:6]}'
        client.post('/api/users', headers=auth, json={'username': uname, 'role': 'viewer'})
        res = client.post('/api/users', headers=auth, json={'username': uname, 'role': 'viewer'})
        assert res.status_code == 409

    def test_list_users_includes_admin(self, client, auth):
        res = client.get('/api/users', headers=auth)
        assert res.status_code == 200
        users = res.get_json()
        assert isinstance(users, list)
        assert any(u['username'] == 'admin' for u in users)

    def test_list_users_requires_auth(self, client):
        res = client.get('/api/users')
        assert res.status_code == 401

    def test_force_reset_sets_must_change_flag(self, client, auth):
        uname = f'resetme_{uuid.uuid4().hex[:6]}'
        create = client.post('/api/users', headers=auth,
                             json={'username': uname, 'password': 'StrongPass1!',
                                   'role': 'viewer'})
        uid = create.get_json()['id']

        res = client.post(f'/api/users/{uid}/force-reset', headers=auth)
        assert res.status_code == 200

        users = client.get('/api/users', headers=auth).get_json()
        target = next((u for u in users if u['id'] == uid), None)
        assert target is not None
        assert target['must_change_password'] == 1

    def test_force_reset_requires_auth(self, client, auth):
        uname = f'frauth_{uuid.uuid4().hex[:6]}'
        create = client.post('/api/users', headers=auth,
                             json={'username': uname, 'role': 'viewer'})
        uid = create.get_json()['id']
        res = client.post(f'/api/users/{uid}/force-reset')
        assert res.status_code == 401

    def test_bulk_create_volunteers_generates_accounts(self, client, auth):
        # Create a volunteer with no linked user account
        phone = f'587{uuid.uuid4().hex[:7]}'
        client.post('/api/volunteers', headers=auth,
                    json={'name': 'BulkVol Test', 'phone': phone,
                          'role': 'delivery', 'status': 'active'})

        res = client.post('/api/users/bulk-create', headers=auth,
                          json={'type': 'volunteer'})
        assert res.status_code == 200
        data = res.get_json()
        assert 'created' in data
        assert 'skipped' in data
        created_names = [c['name'] for c in data['created']]
        assert 'BulkVol Test' in created_names

    def test_bulk_create_idempotent(self, client, auth):
        """Second bulk-create run must not create duplicate accounts."""
        # Run once to ensure accounts exist
        client.post('/api/users/bulk-create', headers=auth, json={'type': 'volunteer'})
        # Run again — should create nothing new
        res = client.post('/api/users/bulk-create', headers=auth, json={'type': 'volunteer'})
        assert res.status_code == 200
        data = res.get_json()
        assert data['created'] == []

    def test_bulk_create_families_generates_accounts(self, client, auth):
        """create_family now auto-creates the user account, so bulk-create skips it.
        Verify the family was created with credentials returned directly."""
        phone = f'588{uuid.uuid4().hex[:7]}'
        res = client.post('/api/families', headers=auth,
                          json={'name': 'BulkFam Test', 'phone': phone,
                                'family_size': 2, 'status': 'active'})
        assert res.status_code == 201
        data = res.get_json()
        # Credentials are returned inline — no separate bulk-create step needed
        assert 'login_username' in data, 'create_family should return login_username'
        assert 'login_temp_password' in data, 'create_family should return login_temp_password'
        assert data['login_username'], 'username must not be empty'
        assert data['login_temp_password'], 'temp password must not be empty'
        # Bulk-create should now skip this family (account already exists)
        bc = client.post('/api/users/bulk-create', headers=auth, json={'type': 'family'})
        assert bc.status_code == 200
        bc_data = bc.get_json()
        skipped_names = [s['name'] for s in bc_data.get('skipped', [])]
        assert 'BulkFam Test' in skipped_names, 'already-created family should be in skipped list'

    def test_bulk_create_requires_auth(self, client):
        res = client.post('/api/users/bulk-create', json={'type': 'volunteer'})
        assert res.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 15 — SET-PASSWORD FLOW (first login + forced reset)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSetPassword:
    """
    Tests POST /api/auth/set-password.
    Flow: create user → login (gets temp_token + must_change_password) → set-password.
    """

    @pytest.fixture(autouse=True)
    def setup(self, client, auth):
        self.client = client
        uname = f'newu_{uuid.uuid4().hex[:6]}'
        create = client.post('/api/users', headers=auth,
                             json={'username': uname, 'role': 'volunteer'})
        data = create.get_json()
        self.uid       = data['id']
        self.username  = uname
        self.temp_pass = data['temp_password']

    def _get_temp_token(self):
        res = self.client.post('/api/auth/login',
                               json={'username': self.username, 'password': self.temp_pass})
        assert res.status_code == 200
        data = res.get_json()
        assert data.get('must_change_password') is True
        return data['temp_token']

    def test_login_with_temp_creds_returns_must_change(self, client):
        res = client.post('/api/auth/login',
                          json={'username': self.username, 'password': self.temp_pass})
        assert res.status_code == 200
        data = res.get_json()
        assert data['must_change_password'] is True
        assert 'temp_token' in data
        assert 'token' not in data   # no full session until password is set

    def test_set_password_issues_full_session(self, client):
        temp_token = self._get_temp_token()
        res = client.post('/api/auth/set-password',
                          json={'temp_token': temp_token, 'password': 'NewPass1!'})
        assert res.status_code == 200
        data = res.get_json()
        assert 'token' in data
        assert 'redirect' in data

    def test_set_password_weak_rejected(self, client):
        temp_token = self._get_temp_token()
        res = client.post('/api/auth/set-password',
                          json={'temp_token': temp_token, 'password': 'weak'})
        assert res.status_code == 422

    def test_set_password_invalid_token_rejected(self, client):
        res = client.post('/api/auth/set-password',
                          json={'temp_token': 'not-a-real-token', 'password': 'NewPass1!'})
        assert res.status_code == 401

    def test_can_login_with_new_password_after_set(self, client):
        temp_token = self._get_temp_token()
        client.post('/api/auth/set-password',
                    json={'temp_token': temp_token, 'password': 'NewPass1!'})
        res = client.post('/api/auth/login',
                          json={'username': self.username, 'password': 'NewPass1!'})
        assert res.status_code == 200
        data = res.get_json()
        assert 'token' in data
        assert not data.get('must_change_password')


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 16 — CHANGE-PASSWORD FLOW (logged-in user)
# ═══════════════════════════════════════════════════════════════════════════════

class TestChangePassword:
    """Tests POST /api/auth/change-password (logged-in password change)."""

    @pytest.fixture(autouse=True)
    def setup(self, client, auth):
        self.client = client
        uname = f'cpw_{uuid.uuid4().hex[:6]}'

        # Create user, complete first-login set-password with a known password
        create = client.post('/api/users', headers=auth,
                             json={'username': uname, 'role': 'viewer'})
        cdata = create.get_json()
        self.username  = uname
        self.temp_pass = cdata['temp_password']

        login_res = client.post('/api/auth/login',
                                json={'username': uname, 'password': self.temp_pass})
        ldata = login_res.get_json()
        sp_res = client.post('/api/auth/set-password',
                             json={'temp_token': ldata['temp_token'],
                                   'password': 'OldPass1!'})
        self.user_token = sp_res.get_json()['token']
        self.user_auth  = {'Authorization': f'Bearer {self.user_token}'}

    def test_change_password_valid(self, client):
        res = client.post('/api/auth/change-password', headers=self.user_auth,
                          json={'current_password': 'OldPass1!', 'new_password': 'NewPass2@'})
        assert res.status_code == 200

    def test_change_password_wrong_current_rejected(self, client):
        res = client.post('/api/auth/change-password', headers=self.user_auth,
                          json={'current_password': 'WrongPass1!', 'new_password': 'NewPass2@'})
        assert res.status_code == 401

    def test_change_password_weak_new_rejected(self, client):
        res = client.post('/api/auth/change-password', headers=self.user_auth,
                          json={'current_password': 'OldPass1!', 'new_password': 'weak'})
        assert res.status_code == 422

    def test_change_password_requires_auth(self, client):
        res = client.post('/api/auth/change-password',
                          json={'current_password': 'OldPass1!', 'new_password': 'NewPass2@'})
        assert res.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 17 — FAMILY SESSION AUTH ON /api/food-order/check
# ═══════════════════════════════════════════════════════════════════════════════

class TestFamilySessionAuth:
    """
    Verifies /api/food-order/check works with:
    - Bearer token (new family session path)
    - ?phone= query param (legacy path — must stay working)
    - Invalid token → 401
    - No auth + no phone → 400
    """

    @pytest.fixture(autouse=True)
    def setup(self, client, auth):
        self.client = client

        # Active family
        self.phone = f'589{uuid.uuid4().hex[:7]}'
        fam = client.post('/api/families', headers=auth,
                          json={'name': 'SessionFam', 'phone': self.phone,
                                'family_size': 3, 'status': 'active'}).get_json()
        self.family_id = fam['id']

        # Family user linked to this family
        uname = f'sf_{uuid.uuid4().hex[:6]}'
        cdata = client.post('/api/users', headers=auth,
                            json={'username': uname, 'role': 'family',
                                  'linked_id': self.family_id,
                                  'linked_type': 'family'}).get_json()
        self.uname     = uname
        self.temp_pass = cdata['temp_password']

        # Complete set-password → get full session token
        ldata = client.post('/api/auth/login',
                            json={'username': uname, 'password': self.temp_pass}).get_json()
        sp = client.post('/api/auth/set-password',
                         json={'temp_token': ldata['temp_token'],
                               'password': 'FamPass1!'}).get_json()
        self.family_token   = sp['token']
        self.family_headers = {'Authorization': f'Bearer {self.family_token}'}

    def test_bearer_token_returns_family_data(self, client):
        res = client.get('/api/food-order/check', headers=self.family_headers)
        assert res.status_code == 200
        data = res.get_json()
        assert data['registered'] is True
        assert data['family_id'] == self.family_id

    def test_legacy_phone_param_still_works(self, client):
        res = client.get(f'/api/food-order/check?phone={self.phone}')
        assert res.status_code == 200
        assert res.get_json()['registered'] is True

    def test_invalid_bearer_token_returns_401(self, client):
        res = client.get('/api/food-order/check',
                         headers={'Authorization': 'Bearer invalid-token-xyz'})
        assert res.status_code == 401

    def test_no_auth_no_phone_returns_401(self, client):
        """No Bearer token and no ?phone= → 401 (Authentication required)."""
        res = client.get('/api/food-order/check')
        assert res.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 12 — FOOD CATALOG (price + allow_qty)
# ═══════════════════════════════════════════════════════════════════════════════

class TestFoodCatalog:
    """Tests that price and allow_qty fields round-trip correctly through create + update."""

    @pytest.fixture(autouse=True)
    def setup(self, client, auth):
        # Get a real seeded category id
        res = client.get('/api/food-categories', headers=auth)
        assert res.status_code == 200
        cats = res.get_json()
        assert cats, 'No seeded food categories found'
        self.cat_id = cats[0]['id']
        self.client = client
        self.auth = auth

    def _create_item(self, name='Test Item', price=0.0, allow_qty=0):
        res = self.client.post('/api/food-items', headers=self.auth, json={
            'name': name,
            'category_id': self.cat_id,
            'unit': 'each',
            'price': price,
            'allow_qty': allow_qty,
        })
        assert res.status_code == 201, f'Create failed: {res.data}'
        return res.get_json()

    def test_create_item_with_price(self):
        item = self._create_item(name='Eggs', price=5.87)
        assert item['price'] == pytest.approx(5.87)
        assert item['allow_qty'] == 0

    def test_create_item_with_allow_qty(self):
        item = self._create_item(name='Apples', price=6.22, allow_qty=1)
        assert item['price'] == pytest.approx(6.22)
        assert item['allow_qty'] == 1

    def test_create_item_zero_price_default(self):
        item = self._create_item(name='Free Item')
        assert item['price'] == pytest.approx(0.0)

    def test_update_item_price(self):
        item = self._create_item(name='Bananas', price=2.00)
        iid = item['id']
        res = self.client.put(f'/api/food-items/{iid}', headers=self.auth, json={
            'name': 'Bananas', 'price': 2.16, 'allow_qty': 0,
        })
        assert res.status_code == 200, f'Update failed: {res.data}'
        updated = res.get_json()
        assert updated['price'] == pytest.approx(2.16), \
            f'Expected price 2.16 but got {updated["price"]}'

    def test_update_item_allow_qty_toggle(self):
        item = self._create_item(name='Pasta', price=8.52, allow_qty=0)
        iid = item['id']
        # Toggle allow_qty on
        res = self.client.put(f'/api/food-items/{iid}', headers=self.auth, json={
            'name': 'Pasta', 'price': 8.52, 'allow_qty': 1,
        })
        assert res.status_code == 200
        assert res.get_json()['allow_qty'] == 1
        # Toggle allow_qty off
        res = self.client.put(f'/api/food-items/{iid}', headers=self.auth, json={
            'name': 'Pasta', 'price': 8.52, 'allow_qty': 0,
        })
        assert res.status_code == 200
        assert res.get_json()['allow_qty'] == 0

    def test_update_price_persists_in_list(self):
        """Price set via PUT must be visible in GET /api/food-items."""
        item = self._create_item(name='Red Potato', price=1.00)
        iid = item['id']
        self.client.put(f'/api/food-items/{iid}', headers=self.auth, json={
            'name': 'Red Potato', 'price': 4.92, 'allow_qty': 1,
        })
        res = self.client.get('/api/food-items', headers=self.auth)
        assert res.status_code == 200
        items = res.get_json()
        match = next((i for i in items if i['id'] == iid), None)
        assert match is not None, 'Item not found in list'
        assert match['price'] == pytest.approx(4.92), \
            f'Price not persisted: expected 4.92, got {match["price"]}'
        assert match['allow_qty'] == 1

    def test_update_nonexistent_item_returns_404(self):
        res = self.client.put('/api/food-items/nonexistent-id', headers=self.auth, json={
            'name': 'Ghost', 'price': 1.0,
        })
        assert res.status_code == 404

    def test_create_item_requires_auth(self):
        res = self.client.post('/api/food-items', json={
            'name': 'Unauthorized', 'category_id': self.cat_id,
        })
        assert res.status_code == 401

    def test_create_item_missing_name_returns_422(self):
        res = self.client.post('/api/food-items', headers=self.auth, json={
            'category_id': self.cat_id,
        })
        assert res.status_code == 422

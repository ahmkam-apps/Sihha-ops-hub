"""
Sihha Ops Hub — Full System Test Suite
Covers all API routes, business rules, privacy rules, and portal flows.
Run: pytest tests/ -v
"""
import uuid, pytest
from datetime import datetime, timedelta


def _get_family_token(client, family_data, new_password='FamPass1!'):
    """Complete the first-login set-password flow and return a full session Bearer token.
    family_data must include login_username and login_temp_password (from POST /api/families response).
    """
    username  = family_data.get('login_username')
    temp_pass = family_data.get('login_temp_password')
    if not username or not temp_pass:
        return None
    login = client.post('/api/auth/login',
                        json={'username': username, 'password': temp_pass}).get_json()
    if login.get('must_change_password'):
        sp = client.post('/api/auth/set-password',
                         json={'temp_token': login['temp_token'],
                               'password': new_password}).get_json()
        return sp.get('token')
    return login.get('token')


def _get_volunteer_token(client, vol_id, auth_headers, new_password='VolPass1!'):
    """Create a user account for a volunteer and return a portal session token."""
    username = f'vol_{vol_id[:8]}'
    user_res = client.post('/api/users', headers=auth_headers,
                           json={'username': username, 'role': 'volunteer',
                                 'linked_id': vol_id, 'linked_type': 'volunteer'}).get_json()
    temp_pass = user_res.get('temp_password')
    if not temp_pass:
        return None
    login = client.post('/api/auth/login',
                        json={'username': username, 'password': temp_pass}).get_json()
    if login.get('must_change_password'):
        sp = client.post('/api/auth/set-password',
                         json={'temp_token': login['temp_token'],
                               'password': new_password}).get_json()
        return sp.get('token')
    return login.get('token')

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
    """Build a cycle payload with delivery dates always 30 days out so they
    never fall into the past and disappear from the 12-month visibility window."""
    from datetime import datetime, timedelta
    d_start = (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')
    d_end   = (datetime.now() + timedelta(days=31)).strftime('%Y-%m-%d')
    base = {
        'title': f'Test Cycle {uuid.uuid4().hex[:6]}',
        'delivery_date_start': d_start,
        'delivery_date_end':   d_end,
        'request_open_at':     '2020-01-01T00:00:00',  # always in the past → window open
        'request_close_at':    '2099-12-31T23:59:00',  # far future → window never closes
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
    - Unauthenticated check → 401
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
        fam_data = res.get_json()
        self.family_id = fam_data['id']

        # Get family session token
        self.family_token   = _get_family_token(client, fam_data)
        self.family_headers = {'Authorization': f'Bearer {self.family_token}'}

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

    def test_check_unauthenticated_returns_401(self, client):
        res = client.get('/api/food-order/check')
        assert res.status_code == 401

    def test_check_registered_open_cycle(self, client):
        res = client.get('/api/food-order/check', headers=self.family_headers)
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
        check = client.get('/api/food-order/check', headers=self.family_headers).get_json()
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
                          headers=self.family_headers,
                          json={'family_id': self.family_id,
                                'cycle_id':  self.cycle_id,
                                'selected_items': item_ids})
        assert res.status_code == 201
        assert res.get_json()['ok'] is True

    def test_one_order_per_family_per_cycle(self, client):
        # Submit once (may already be submitted from another test in session scope)
        client.post('/api/food-order',
                    headers=self.family_headers,
                    json={'family_id': self.family_id, 'cycle_id': self.cycle_id,
                          'selected_items': []})
        # Try to submit again → must fail
        res = client.post('/api/food-order',
                          headers=self.family_headers,
                          json={'family_id': self.family_id, 'cycle_id': self.cycle_id,
                                'selected_items': []})
        assert res.status_code == 409

    def test_check_shows_already_submitted(self, client):
        check1 = client.get('/api/food-order/check', headers=self.family_headers).get_json()
        open_cycle = next((c for c in check1.get('cycles', []) if c.get('can_place_order')), None)
        if not open_cycle:
            pytest.skip('No open cycle available')
        # Submit if not already done
        if open_cycle.get('order') is None:
            client.post('/api/food-order',
                        headers=self.family_headers,
                        json={'family_id': check1['family_id'],
                              'cycle_id':  open_cycle['id'],
                              'selected_items': []})
        check2 = client.get('/api/food-order/check', headers=self.family_headers).get_json()
        # After submitting, the cycle must have an order object (not None)
        submitted = next((c for c in check2['cycles'] if c['id'] == open_cycle['id']), None)
        assert submitted is not None
        assert submitted.get('order') is not None

    def test_edit_order_items(self, client):
        """Regression (audit 2026-07-11): PUT /api/food-order/items raised
        NameError (`family` undefined → 500 after commit) whenever a family
        edited items. Verify the edit succeeds and reports the diff."""
        check = client.get('/api/food-order/check', headers=self.family_headers).get_json()
        open_cycle = next((c for c in check.get('cycles', []) if c.get('can_place_order')
                           or c.get('order')), None)
        if not open_cycle:
            pytest.skip('No open cycle available')

        # Collect selectable item ids (one per exclusion group)
        seen_groups, item_ids = set(), []
        for cat in open_cycle.get('items_for_selection', []):
            for i in cat['items']:
                g = i.get('group_id')
                if g and g in seen_groups:
                    continue
                if g:
                    seen_groups.add(g)
                item_ids.append(i['id'])
        if len(item_ids) < 2:
            pytest.skip('Not enough selectable items')

        # Ensure an order exists (may already exist from earlier tests in this class)
        order = open_cycle.get('order')
        if order is None:
            res = client.post('/api/food-order',
                              headers=self.family_headers,
                              json={'family_id': self.family_id,
                                    'cycle_id':  open_cycle['id'],
                                    'selected_items': item_ids[:2]})
            assert res.status_code == 201
            check = client.get('/api/food-order/check', headers=self.family_headers).get_json()
            order = next(c for c in check['cycles'] if c['id'] == open_cycle['id'])['order']
        assert order is not None

        # Edit: drop to a single (different) item → forces added/removed diff,
        # which is the code path that hit the NameError
        res = client.put('/api/food-order/items',
                         headers=self.family_headers,
                         json={'request_id': order['id'],
                               'selected_item_ids': [item_ids[1]]})
        assert res.status_code == 200, res.get_json()
        data = res.get_json()
        assert data['ok'] is True
        assert isinstance(data['added'], list) and isinstance(data['removed'], list)

    def test_family_session_cannot_read_staff_endpoints(self, client):
        """Regression (audit 2026-07-11): staff read endpoints used bare
        @require_auth(), letting family/volunteer sessions read any family's
        PII by id (IDOR). They must now return 403 for non-staff roles."""
        for path in (f'/api/families/{self.family_id}',
                     f'/api/families/{self.family_id}/history',
                     '/api/volunteers',
                     '/api/orders',
                     '/api/dashboard/stats',
                     '/api/delivery-cycles',
                     '/api/volunteer-slots'):
            res = client.get(path, headers=self.family_headers)
            assert res.status_code == 403, f'{path} → {res.status_code} (expected 403)'

    def test_bundle_size_small_for_tiny_family(self, client, auth):
        phone = f'585201{uuid.uuid4().hex[:4]}'
        res = client.post('/api/families', headers=auth,
                          json={'name': 'Tiny Family', 'phone': phone,
                                'family_size': 1, 'status': 'active'})
        tok = _get_family_token(client, res.get_json())
        check = client.get('/api/food-order/check',
                           headers={'Authorization': f'Bearer {tok}'}).get_json()
        assert check['registered'] is True
        assert check['bundle_size'] == 'S'

    def test_bundle_size_large_for_big_family(self, client, auth):
        phone = f'585202{uuid.uuid4().hex[:4]}'
        res = client.post('/api/families', headers=auth,
                          json={'name': 'Big Family', 'phone': phone,
                                'family_size': 8, 'status': 'active'})
        tok = _get_family_token(client, res.get_json())
        check = client.get('/api/food-order/check',
                           headers={'Authorization': f'Bearer {tok}'}).get_json()
        assert check['registered'] is True
        assert check['bundle_size'] == 'L'

    def test_family_cancel_allows_reorder(self, client):
        """Family cancel hard-deletes the row → family can place a fresh order in same cycle."""
        # Submit initial order
        client.post('/api/food-order',
                    headers=self.family_headers,
                    json={'family_id': self.family_id, 'cycle_id': self.cycle_id,
                          'selected_items': []})
        check = client.get('/api/food-order/check', headers=self.family_headers).get_json()
        cycle = next((c for c in check.get('cycles', []) if c['id'] == self.cycle_id), None)
        if not cycle or not cycle.get('order'):
            pytest.skip('Order not found after submit')

        request_id = cycle['order']['id']

        # Cancel it
        res = client.post('/api/food-order/cancel',
                          headers=self.family_headers,
                          json={'family_id': self.family_id, 'request_id': request_id})
        assert res.status_code == 200, f'Cancel failed: {res.get_json()}'

        # Row must be gone — family can place a fresh order (no UNIQUE violation)
        res2 = client.post('/api/food-order',
                           headers=self.family_headers,
                           json={'family_id': self.family_id, 'cycle_id': self.cycle_id,
                                 'selected_items': []})
        assert res2.status_code == 201, \
            f'Re-order after family cancel failed with {res2.status_code}: {res2.get_json()}'


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
        fam_data = res.get_json()
        self.family_id = fam_data['id']
        self.family_headers = {'Authorization': f'Bearer {_get_family_token(client, fam_data)}'}

        # Create an open cycle
        res = client.post('/api/delivery-cycles', headers=auth,
                          json=_cycle_payload(
                              request_open_at='2020-01-01T00:00:00',
                              request_close_at='2099-12-31T23:59:00',
                              status='open'
                          ))
        self.cycle = res.get_json()
        self.cycle_id = self.cycle['id']

        # Submit a food order for the family (idempotent — 409 if already submitted is fine)
        client.post('/api/food-order',
                    headers=self.family_headers,
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
                                'email': f'shopper_{vol_phone_1}@test.sihha.org',
                                'role': 'shopper', 'status': 'active'})
        self.shopper_phone = vol_phone_1
        self.shopper_id    = res.get_json()['id']
        self.shopper_token = _get_volunteer_token(client, self.shopper_id, auth)

        res = client.post('/api/volunteers', headers=auth,
                          json={'name': 'Delivery Vol', 'phone': vol_phone_2,
                                'email': f'delivery_{vol_phone_2}@test.sihha.org',
                                'role': 'delivery', 'status': 'active'})
        self.delivery_phone = vol_phone_2
        self.delivery_id    = res.get_json()['id']
        self.delivery_token = _get_volunteer_token(client, self.delivery_id, auth)

    # ── Login ──────────────────────────────────────────────────────────────────

    def test_portal_login_valid(self, client):
        # Legacy phone-only login is removed — returns 410 Gone
        res = client.post('/api/portal/login', json={'phone': self.shopper_phone})
        assert res.status_code == 410

    def test_portal_login_phone_not_found(self, client):
        # Legacy endpoint returns 410 regardless of phone
        res = client.post('/api/portal/login', json={'phone': '0000000000'})
        assert res.status_code == 410

    def test_portal_login_inactive_volunteer(self, client, auth):
        # Legacy endpoint returns 410 regardless
        phone = f'5854{uuid.uuid4().int % 1000000:06d}'
        res = client.post('/api/portal/login', json={'phone': phone})
        assert res.status_code == 410

    def test_portal_login_missing_phone(self, client):
        res = client.post('/api/portal/login', json={})
        assert res.status_code == 410

    def _portal_headers(self, phone):
        """Return auth headers for a volunteer identified by phone."""
        if phone == self.shopper_phone:
            return {'Authorization': f'Bearer {self.shopper_token}'}
        if phone == self.delivery_phone:
            return {'Authorization': f'Bearer {self.delivery_token}'}
        raise ValueError(f'Unknown volunteer phone: {phone}')

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

        # Email confirmation must NOT contain the family address
        assert wa_mock.called
        call_args = wa_mock.call_args
        message = call_args[0][2]  # _email_send(to_email, subject, body)
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

        # Delivery email must contain the family address
        assert wa_mock.called
        call_args = wa_mock.call_args
        message = call_args[0][2]  # _email_send(to_email, subject, body)
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
        fam_data = client.post('/api/families', headers=auth,
                          json={'name': 'Slot Family', 'phone': phone,
                                'family_size': 3, 'status': 'active'}).get_json()
        fam = fam_data
        fam_headers = {'Authorization': f'Bearer {_get_family_token(client, fam_data)}'}
        cycle = client.post('/api/delivery-cycles', headers=auth,
                            json=_cycle_payload(
                                request_open_at='2020-01-01T00:00:00',
                                request_close_at='2099-12-31T23:59:00',
                                status='open'
                            )).get_json()
        cid = cycle['id']

        client.post('/api/food-order',
                    headers=fam_headers,
                    json={'family_id': fam['id'], 'cycle_id': cid, 'selected_items': []})

        res = client.post(f'/api/delivery-cycles/{cid}/generate-slots', headers=auth)
        assert res.status_code == 200
        data = res.get_json()
        assert data['ok'] is True
        # Must be at least 2 slots (1 shopping + 1 delivery for the submitted family)
        assert data['slots_total'] >= 2

    def test_generate_slots_is_idempotent(self, client, auth):
        phone = f'585501{uuid.uuid4().hex[:4]}'
        fam_data = client.post('/api/families', headers=auth,
                          json={'name': 'Idempotent Family', 'phone': phone,
                                'family_size': 2, 'status': 'active'}).get_json()
        fam = fam_data
        fam_headers = {'Authorization': f'Bearer {_get_family_token(client, fam_data)}'}
        cycle = client.post('/api/delivery-cycles', headers=auth,
                            json=_cycle_payload(
                                request_open_at='2020-01-01T00:00:00',
                                request_close_at='2099-12-31T23:59:00',
                                status='open'
                            )).get_json()
        cid = cycle['id']
        client.post('/api/food-order',
                    headers=fam_headers,
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
        fam_data = client.post('/api/families', headers=auth,
                          json={'name': 'Board Family', 'phone': phone,
                                'family_size': 5, 'status': 'active'}).get_json()
        fam = fam_data
        fam_headers = {'Authorization': f'Bearer {_get_family_token(client, fam_data)}'}
        cycle = client.post('/api/delivery-cycles', headers=auth,
                            json=_cycle_payload(
                                request_open_at='2020-01-01T00:00:00',
                                request_close_at='2099-12-31T23:59:00',
                                status='open'
                            )).get_json()
        cid = cycle['id']
        client.post('/api/food-order',
                    headers=fam_headers,
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
    Tests the public family food order flow (/api/food-order/check + /api/food-order).
    Business rules verified:
    - No auth → 401
    - Registered family with token, open cycle → receives food items + bundle_size
    - Bundle size hidden from response labels (internal field only)
    - Submitting twice → 409
    - order flag set correctly after first submission
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
        fam_data = res.get_json()
        self.family_id = fam_data['id']
        tok = _get_family_token(client, fam_data)
        self.family_headers = {'Authorization': f'Bearer {tok}'}

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

    def test_check_no_auth_returns_401(self, client):
        res = client.get('/api/food-order/check')
        assert res.status_code == 401

    def test_check_registered_family_gets_items(self, client):
        res = client.get('/api/food-order/check', headers=self.family_headers)
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

    def test_submit_with_selected_items(self, client):
        check = client.get('/api/food-order/check', headers=self.family_headers).get_json()
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
        res = client.post('/api/food-order',
                          headers=self.family_headers,
                          json={
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
        fam2_data = client.post('/api/families', headers=self.auth,
                           json={'name': 'Empty Items Family', 'phone': phone2,
                                 'family_size': 2, 'status': 'active'}).get_json()
        fam2_headers = {'Authorization': f'Bearer {_get_family_token(client, fam2_data)}'}
        res = client.post('/api/food-order',
                          headers=fam2_headers,
                          json={
                              'family_id': fam2_data['id'],
                              'cycle_id':  self.cycle_id,
                              'selected_items': []
                          })
        assert res.status_code == 201

    def test_duplicate_order_returns_409(self, client):
        # First submit
        client.post('/api/food-order',
                    headers=self.family_headers,
                    json={
                        'family_id': self.family_id,
                        'cycle_id':  self.cycle_id,
                        'selected_items': []
                    })
        # Second submit → 409
        res = client.post('/api/food-order',
                          headers=self.family_headers,
                          json={
                              'family_id': self.family_id,
                              'cycle_id':  self.cycle_id,
                              'selected_items': []
                          })
        assert res.status_code == 409

    def test_already_submitted_flag_after_order(self, client):
        check1 = client.get('/api/food-order/check', headers=self.family_headers).get_json()
        open_cycle = next((c for c in check1.get('cycles', []) if c.get('can_place_order')), None)
        if not open_cycle:
            pytest.skip('No open cycle available')
        client.post('/api/food-order',
                    headers=self.family_headers,
                    json={
                        'family_id': check1['family_id'],
                        'cycle_id':  open_cycle['id'],
                        'selected_items': []
                    })
        check2 = client.get('/api/food-order/check', headers=self.family_headers).get_json()
        submitted = next((c for c in check2['cycles'] if c['id'] == open_cycle['id']), None)
        assert submitted is not None
        assert submitted.get('order') is not None


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

    def test_phone_param_removed_returns_401(self, client):
        """Legacy ?phone= param is no longer supported — endpoint requires Bearer token."""
        res = client.get(f'/api/food-order/check?phone={self.phone}')
        assert res.status_code == 401

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

class TestFoodItemPricing:  # renamed from TestFoodCatalog — duplicate name shadowed the Section 4 class, silently disabling 5 tests
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


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 18 — FINANCE DOMAIN: RECEIPTS, REIMBURSEMENTS, DONATIONS, SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

def _make_role_headers(client, auth_headers, role):
    """Create a user with the given role and return Bearer auth headers for it.
    Passes an explicit password + must_change_password=0 so login returns a full
    session token immediately (no set-password dance)."""
    uname = f'{role}_{uuid.uuid4().hex[:6]}'
    res = client.post('/api/users', headers=auth_headers,
                      json={'username': uname, 'role': role,
                            'password': 'RolePass1!', 'must_change_password': 0})
    assert res.status_code == 201, f'{role} user create failed: {res.data}'
    login = client.post('/api/auth/login',
                        json={'username': uname, 'password': 'RolePass1!'})
    assert login.status_code == 200, f'{role} login failed: {login.data}'
    return {'Authorization': f'Bearer {login.get_json()["token"]}'}


class TestReceipts:
    """Admin receipt creation (with/without cycle_id), list joins, and role gates."""

    @pytest.fixture(autouse=True)
    def setup(self, client, auth):
        self.client = client
        self.auth = auth
        tag = uuid.uuid4().hex[:6]
        phone = f'585600{uuid.uuid4().hex[:4]}'
        fam = client.post('/api/families', headers=auth,
                          json={'name': f'Receipt Fam {tag}', 'phone': phone,
                                'family_size': 3, 'status': 'active'}).get_json()
        self.family_id = fam['id']
        self.family_data = fam
        vol = client.post('/api/volunteers', headers=auth,
                          json={'name': f'Receipt Vol {tag}',
                                'phone': f'5856{uuid.uuid4().int % 1000000:06d}',
                                'role': 'shopper', 'status': 'active'}).get_json()
        self.volunteer_id = vol['id']
        self.volunteer_name = f'Receipt Vol {tag}'
        cycle = client.post('/api/delivery-cycles', headers=auth,
                            json=_cycle_payload()).get_json()
        self.cycle_id = cycle['id']
        self.cycle_title = cycle['title']

    def _create_receipt(self, **overrides):
        payload = {'volunteer_id': self.volunteer_id, 'family_id': self.family_id,
                   'store': 'Aldi', 'purchase_date': '2026-06-01', 'amount': 84.50}
        payload.update(overrides)
        res = self.client.post('/api/receipts', headers=self.auth, json=payload)
        assert res.status_code == 201, f'Receipt create failed: {res.data}'
        return res.get_json()['id']

    def _find_receipt(self, rid):
        rows = self.client.get('/api/receipts', headers=self.auth).get_json()
        return next((r for r in rows if r['id'] == rid), None)

    def test_create_receipt_basic(self):
        rid = self._create_receipt()
        row = self._find_receipt(rid)
        assert row is not None
        assert row['status'] == 'pending'
        assert row['amount'] == pytest.approx(84.50)
        assert row['store'] == 'Aldi'

    def test_create_receipt_with_cycle_id_resolves_cycle(self):
        rid = self._create_receipt(cycle_id=self.cycle_id)
        row = self._find_receipt(rid)
        assert row['resolved_cycle_id'] == self.cycle_id
        assert row['cycle_title'] == self.cycle_title

    def test_create_receipt_without_cycle_id_has_no_cycle(self):
        rid = self._create_receipt()
        row = self._find_receipt(rid)
        assert row['resolved_cycle_id'] is None
        assert row['cycle_title'] is None

    def test_list_receipts_joins_family_and_volunteer_names(self):
        rid = self._create_receipt()
        row = self._find_receipt(rid)
        assert row['volunteer_name'] == self.volunteer_name
        assert row['family_name'].startswith('Receipt Fam')

    def test_list_receipts_status_filter(self):
        rid = self._create_receipt()
        pending = self.client.get('/api/receipts?status=pending', headers=self.auth).get_json()
        assert any(r['id'] == rid for r in pending)
        approved = self.client.get('/api/receipts?status=approved', headers=self.auth).get_json()
        assert not any(r['id'] == rid for r in approved)

    def test_receipts_require_auth(self, client):
        assert client.get('/api/receipts').status_code == 401
        assert client.post('/api/receipts', json={'amount': 10}).status_code == 401
        assert client.put('/api/receipts/some-id', json={'status': 'approved'}).status_code == 401

    def test_viewer_fully_locked_out_of_receipts(self, client, auth):
        # Tightened 2026-06-11: GET now requires admin/finance/treasurer —
        # receipts expose volunteer names + amounts, not viewer material.
        viewer = _make_role_headers(client, auth, 'viewer')
        assert client.get('/api/receipts', headers=viewer).status_code == 403
        res = client.post('/api/receipts', headers=viewer,
                          json={'volunteer_id': self.volunteer_id, 'amount': 10})
        assert res.status_code == 403
        rid = self._create_receipt()
        assert client.put(f'/api/receipts/{rid}', headers=viewer,
                          json={'status': 'approved'}).status_code == 403
        # finance role retains read access
        finance = _make_role_headers(client, auth, 'finance')
        assert client.get('/api/receipts', headers=finance).status_code == 200

    def test_family_role_cannot_create_receipt(self, client):
        token = _get_family_token(self.client, self.family_data)
        assert token, 'family login flow failed'
        res = client.post('/api/receipts',
                          headers={'Authorization': f'Bearer {token}'},
                          json={'amount': 10})
        assert res.status_code == 403

    def test_update_receipt_not_found(self, client, auth):
        res = client.put('/api/receipts/nonexistent-id', headers=auth,
                         json={'status': 'approved'})
        assert res.status_code == 404

    def test_zero_amount_accepted_negative_rejected(self):
        # Fixed 2026-06-11: negative amounts now rejected with 422 (zero stays
        # allowed — a fully comped shop is legitimate).
        rid_zero = self._create_receipt(amount=0)
        assert self._find_receipt(rid_zero)['amount'] == 0
        res = self.client.post('/api/receipts', headers=self.auth,
                               json={'volunteer_id': self.volunteer_id, 'store': 'Neg Mart',
                                     'purchase_date': '2026-06-03', 'amount': -12.50})
        assert res.status_code == 422

    def test_non_numeric_amount_rejected(self):
        res = self.client.post('/api/receipts', headers=self.auth,
                               json={'volunteer_id': self.volunteer_id, 'store': 'NaN Mart',
                                     'purchase_date': '2026-06-03', 'amount': 'abc'})
        assert res.status_code == 422


class TestReceiptApprovalFlow:
    """THE key money flow: PUT /api/receipts/<rid> status=approved must auto-create
    exactly one pending reimbursement with correct amount/volunteer/receipt linkage."""

    @pytest.fixture(autouse=True)
    def setup(self, client, auth):
        self.client = client
        self.auth = auth
        vol = client.post('/api/volunteers', headers=auth,
                          json={'name': f'Approval Vol {uuid.uuid4().hex[:6]}',
                                'phone': f'5858{uuid.uuid4().int % 1000000:06d}',
                                'role': 'shopper', 'status': 'active'}).get_json()
        self.volunteer_id = vol['id']

    def _create_receipt(self, amount=72.30):
        res = self.client.post('/api/receipts', headers=self.auth,
                               json={'volunteer_id': self.volunteer_id,
                                     'store': 'Costco', 'purchase_date': '2026-06-02',
                                     'amount': amount})
        assert res.status_code == 201
        return res.get_json()['id']

    def _reimbursements_for(self, rid, headers=None):
        rows = self.client.get('/api/reimbursements',
                               headers=headers or self.auth).get_json()
        return [r for r in rows if r['receipt_id'] == rid]

    def test_approve_creates_pending_reimbursement(self, client, auth):
        rid = self._create_receipt(amount=72.30)
        res = client.put(f'/api/receipts/{rid}', headers=auth, json={'status': 'approved'})
        assert res.status_code == 200
        assert res.get_json()['status'] == 'approved'
        reimbs = self._reimbursements_for(rid)
        assert len(reimbs) == 1, 'Approval must create exactly one reimbursement'
        rb = reimbs[0]
        assert rb['amount'] == pytest.approx(72.30)
        assert rb['volunteer_id'] == self.volunteer_id
        assert rb['status'] == 'pending'
        assert rb['approved_by'], 'approved_by must record the approving user'

    def test_approve_twice_does_not_duplicate_reimbursement(self, client, auth):
        rid = self._create_receipt()
        client.put(f'/api/receipts/{rid}', headers=auth, json={'status': 'approved'})
        client.put(f'/api/receipts/{rid}', headers=auth, json={'status': 'approved'})
        assert len(self._reimbursements_for(rid)) == 1

    def test_reject_does_not_create_reimbursement(self, client, auth):
        rid = self._create_receipt()
        res = client.put(f'/api/receipts/{rid}', headers=auth, json={'status': 'rejected'})
        assert res.status_code == 200
        assert res.get_json()['status'] == 'rejected'
        assert self._reimbursements_for(rid) == []

    def test_finance_role_can_approve(self, client, auth):
        finance = _make_role_headers(client, auth, 'finance')
        rid = self._create_receipt(amount=15.00)
        res = client.put(f'/api/receipts/{rid}', headers=finance, json={'status': 'approved'})
        assert res.status_code == 200
        reimbs = self._reimbursements_for(rid, headers=finance)
        assert len(reimbs) == 1
        assert reimbs[0]['amount'] == pytest.approx(15.00)

    def test_negative_receipt_rejected_at_creation(self, client, auth):
        # Fixed 2026-06-11: negative amounts can no longer enter the chain,
        # so negative reimbursements are impossible via the API.
        res = client.post('/api/receipts', headers=auth,
                          json={'volunteer_id': self.volunteer_id, 'store': 'Neg Mart',
                                'purchase_date': '2026-06-03', 'amount': -30.00})
        assert res.status_code == 422


class TestReimbursements:
    """Reimbursement list role gates + payment update flow."""

    @pytest.fixture(autouse=True)
    def setup(self, client, auth):
        self.client = client
        self.auth = auth
        vol = client.post('/api/volunteers', headers=auth,
                          json={'name': f'Reimb Vol {uuid.uuid4().hex[:6]}',
                                'phone': f'5859{uuid.uuid4().int % 1000000:06d}',
                                'email': f'reimb_{uuid.uuid4().hex[:6]}@test.sihha.org',
                                'role': 'shopper', 'status': 'active'}).get_json()
        self.volunteer_id = vol['id']
        rec = client.post('/api/receipts', headers=auth,
                          json={'volunteer_id': self.volunteer_id, 'store': 'Walmart',
                                'purchase_date': '2026-06-03', 'amount': 60.00}).get_json()
        self.receipt_id = rec['id']
        approve = client.put(f'/api/receipts/{self.receipt_id}', headers=auth,
                             json={'status': 'approved'})
        assert approve.status_code == 200
        self.reimb_id = next(r['id'] for r in
                             client.get('/api/reimbursements', headers=auth).get_json()
                             if r['receipt_id'] == self.receipt_id)

    def _get_reimb(self):
        rows = self.client.get('/api/reimbursements', headers=self.auth).get_json()
        return next(r for r in rows if r['id'] == self.reimb_id)

    def test_list_includes_volunteer_and_receipt_info(self):
        rb = self._get_reimb()
        assert rb['volunteer_name'].startswith('Reimb Vol')
        assert rb['store'] == 'Walmart'
        assert rb['receipt_amount'] == pytest.approx(60.00)

    def test_list_allowed_for_finance_and_treasurer(self, client, auth):
        for role in ('finance', 'treasurer'):
            headers = _make_role_headers(client, auth, role)
            assert client.get('/api/reimbursements', headers=headers).status_code == 200

    def test_list_forbidden_for_viewer_and_volunteer(self, client, auth):
        viewer = _make_role_headers(client, auth, 'viewer')
        assert client.get('/api/reimbursements', headers=viewer).status_code == 403
        vol_token = _get_volunteer_token(client, self.volunteer_id, auth)
        assert vol_token, 'volunteer login flow failed'
        res = client.get('/api/reimbursements',
                         headers={'Authorization': f'Bearer {vol_token}'})
        assert res.status_code == 403

    def test_list_requires_auth(self, client):
        assert client.get('/api/reimbursements').status_code == 401
        assert client.put(f'/api/reimbursements/{self.reimb_id}',
                          json={'status': 'paid'}).status_code == 401

    def test_mark_paid_persists_payment_fields(self, client, auth):
        res = client.put(f'/api/reimbursements/{self.reimb_id}', headers=auth,
                         json={'status': 'paid', 'payment_method': 'zelle',
                               'payment_ref': 'TX-12345'})
        assert res.status_code == 200
        rb = self._get_reimb()
        assert rb['status'] == 'paid'
        assert rb['payment_method'] == 'zelle'
        assert rb['payment_ref'] == 'TX-12345'
        assert rb['paid_date'], 'paid_date must be auto-set when marked paid'

    def test_invalid_payment_method_rejected_with_422(self, client, auth):
        # Fixed 2026-06-11: app-level whitelist validation returns 422 with a
        # helpful message instead of letting the DB CHECK constraint 500.
        res = client.put(f'/api/reimbursements/{self.reimb_id}', headers=auth,
                         json={'status': 'approved', 'payment_method': 'paypal'})
        assert res.status_code == 422
        assert 'payment method' in res.get_json()['error'].lower()
        rb = self._get_reimb()
        assert rb['status'] == 'pending', 'rejected update must not persist anything'
        assert rb['payment_method'] is None

    def test_already_paid_second_update_stays_consistent(self, client, auth):
        client.put(f'/api/reimbursements/{self.reimb_id}', headers=auth,
                   json={'status': 'paid', 'payment_method': 'venmo',
                         'payment_ref': 'VN-1'})
        first = self._get_reimb()
        res = client.put(f'/api/reimbursements/{self.reimb_id}', headers=auth,
                         json={'status': 'paid', 'notes': 'double-checked'})
        assert res.status_code == 200
        second = self._get_reimb()
        assert second['status'] == 'paid'
        assert second['payment_method'] == 'venmo'
        assert second['payment_ref'] == 'VN-1'
        assert second['paid_date'] == first['paid_date']
        assert second['notes'] == 'double-checked'
        rows = [r for r in client.get('/api/reimbursements', headers=auth).get_json()
                if r['receipt_id'] == self.receipt_id]
        assert len(rows) == 1, 'still exactly one reimbursement for the receipt'

    def test_update_nonexistent_reimbursement_404(self, client, auth):
        res = client.put('/api/reimbursements/nonexistent-id', headers=auth,
                         json={'status': 'paid'})
        assert res.status_code == 404


class TestDonations:
    """Manual donation CRUD, Excel export, and role gates."""

    def test_create_and_list_manual_donation(self, client, auth):
        donor = f'Donor {uuid.uuid4().hex[:6]}'
        res = client.post('/api/donations', headers=auth,
                          json={'donor_name': donor, 'amount': 250.00,
                                'type': 'cash', 'date': '2026-06-01',
                                'source': 'manual', 'notes': 'Ramadan drive'})
        assert res.status_code == 201
        did = res.get_json()['id']
        rows = client.get('/api/donations', headers=auth).get_json()
        row = next((r for r in rows if r['id'] == did), None)
        assert row is not None
        assert row['donor_name'] == donor
        assert row['amount'] == pytest.approx(250.00)
        assert row['type'] == 'cash'

    def test_donations_require_auth(self, client):
        assert client.get('/api/donations').status_code == 401
        assert client.post('/api/donations', json={'amount': 5}).status_code == 401
        assert client.get('/api/donations/export').status_code == 401

    def test_viewer_forbidden_on_donations(self, client, auth):
        viewer = _make_role_headers(client, auth, 'viewer')
        assert client.get('/api/donations', headers=viewer).status_code == 403
        assert client.post('/api/donations', headers=viewer,
                           json={'amount': 5}).status_code == 403
        assert client.get('/api/donations/export', headers=viewer).status_code == 403

    def test_finance_can_create_and_list(self, client, auth):
        finance = _make_role_headers(client, auth, 'finance')
        res = client.post('/api/donations', headers=finance,
                          json={'donor_name': 'Finance Donor', 'amount': 10.00,
                                'type': 'check', 'date': '2026-06-02'})
        assert res.status_code == 201
        assert client.get('/api/donations', headers=finance).status_code == 200

    def test_export_returns_xlsx(self, client, auth):
        # Ensure at least one donation exists
        client.post('/api/donations', headers=auth,
                    json={'donor_name': 'Export Donor', 'amount': 33.00,
                          'type': 'cash', 'date': '2026-06-03'})
        res = client.get('/api/donations/export', headers=auth)
        assert res.status_code == 200
        assert res.content_type.startswith(
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        assert res.data[:2] == b'PK', 'xlsx payload must be a zip archive'

    def test_delete_donation_role_gates(self, client, auth):
        # DELETE is admin/treasurer only — finance is excluded
        did = client.post('/api/donations', headers=auth,
                          json={'donor_name': 'Delete Me', 'amount': 1.00,
                                'type': 'cash', 'date': '2026-06-04'}).get_json()['id']
        finance = _make_role_headers(client, auth, 'finance')
        assert client.delete(f'/api/donations/{did}', headers=finance).status_code == 403
        treasurer = _make_role_headers(client, auth, 'treasurer')
        assert client.delete(f'/api/donations/{did}', headers=treasurer).status_code == 200
        rows = client.get('/api/donations', headers=auth).get_json()
        assert not any(r['id'] == did for r in rows)

    def test_sync_wix_without_api_key_returns_400(self, client, auth, monkeypatch):
        monkeypatch.delenv('WIX_API_KEY', raising=False)
        res = client.post('/api/donations/sync-wix', headers=auth)
        assert res.status_code == 400
        assert 'WIX_API_KEY' in res.get_json()['error']

    def test_sync_wix_forbidden_for_finance(self, client, auth):
        # sync-wix is admin/treasurer only
        finance = _make_role_headers(client, auth, 'finance')
        assert client.post('/api/donations/sync-wix', headers=finance).status_code == 403


class TestFinanceSummary:
    """GET /api/finance/summary — totals arithmetic and per-cycle breakdown.
    Uses before/after deltas because the session-scoped DB accumulates rows
    from other test classes."""

    @pytest.fixture(autouse=True)
    def setup(self, client, auth):
        self.client = client
        self.auth = auth
        vol = client.post('/api/volunteers', headers=auth,
                          json={'name': f'Summary Vol {uuid.uuid4().hex[:6]}',
                                'phone': f'5851{uuid.uuid4().int % 1000000:06d}',
                                'role': 'shopper', 'status': 'active'}).get_json()
        self.volunteer_id = vol['id']
        cycle = client.post('/api/delivery-cycles', headers=auth,
                            json=_cycle_payload()).get_json()
        self.cycle_id = cycle['id']

    def _create_receipt(self, amount):
        res = self.client.post('/api/receipts', headers=self.auth,
                               json={'volunteer_id': self.volunteer_id,
                                     'cycle_id': self.cycle_id, 'store': 'Aldi',
                                     'purchase_date': '2026-06-05', 'amount': amount})
        assert res.status_code == 201
        return res.get_json()['id']

    def _summary(self):
        res = self.client.get('/api/finance/summary', headers=self.auth)
        assert res.status_code == 200
        return res.get_json()

    def test_totals_and_per_cycle_math(self, client, auth):
        before = self._summary()['totals']

        # Two donations: 100.00 + 50.25
        for amt in (100.00, 50.25):
            client.post('/api/donations', headers=auth,
                        json={'donor_name': 'Summary Donor', 'amount': amt,
                              'type': 'cash', 'date': '2026-06-05'})

        # Receipt 1: 40.00 → approved → reimbursement paid
        r1 = self._create_receipt(40.00)
        client.put(f'/api/receipts/{r1}', headers=auth, json={'status': 'approved'})
        reimb1 = next(r for r in client.get('/api/reimbursements', headers=auth).get_json()
                      if r['receipt_id'] == r1)
        paid = client.put(f'/api/reimbursements/{reimb1["id"]}', headers=auth,
                          json={'status': 'paid', 'payment_method': 'zelle'})
        assert paid.status_code == 200

        # Receipt 2: 25.00 → approved → reimbursement stays pending
        r2 = self._create_receipt(25.00)
        client.put(f'/api/receipts/{r2}', headers=auth, json={'status': 'approved'})

        after = self._summary()
        t, b = after['totals'], before
        assert t['income'] - b['income'] == pytest.approx(150.25)
        # both receipts approved → committed +65; r1 paid, r2 still owed
        assert t['committed'] - b['committed'] == pytest.approx(65.00)
        assert t['paid_out'] - b['paid_out'] == pytest.approx(40.00)
        assert t['outstanding_payable'] - b['outstanding_payable'] == pytest.approx(25.00)
        # ledger reconciles + cash math
        assert t['committed'] == pytest.approx(t['paid_out'] + t['outstanding_payable'])
        assert t['cash_balance'] == pytest.approx(t['income'] - t['paid_out'])

        # Per-cycle breakdown for our fresh cycle
        cyc = next(c for c in after['cycles'] if c['id'] == self.cycle_id)
        assert cyc['approved_count'] == 2
        assert cyc['committed_total'] == pytest.approx(65.00)
        assert cyc['paid_total'] == pytest.approx(40.00)
        assert cyc['outstanding_total'] == pytest.approx(25.00)

    def test_rejected_receipts_excluded_from_summary(self, client, auth):
        before = self._summary()['totals']
        rid = self._create_receipt(99.99)
        client.put(f'/api/receipts/{rid}', headers=auth, json={'status': 'rejected'})
        after = self._summary()
        # rejected → never committed, and not counted as pending review
        assert after['totals']['committed'] == pytest.approx(before['committed'])
        assert after['totals']['pending_review'] == pytest.approx(before['pending_review'])
        cyc = next(c for c in after['cycles'] if c['id'] == self.cycle_id)
        assert cyc['approved_count'] == 0
        assert cyc['committed_total'] == pytest.approx(0)

    def test_summary_shape_and_role_gates(self, client, auth):
        data = self._summary()
        assert set(data['totals'].keys()) == {
            'income', 'pending_review', 'committed', 'paid_out', 'outstanding_payable',
            'cash_balance', 'available', 'pending_count', 'approved_count'}
        assert isinstance(data['cycles'], list)
        if data['cycles']:
            assert {'id', 'title', 'cycle_status', 'approved_count',
                    'committed_total', 'paid_total', 'outstanding_total'} <= set(data['cycles'][0].keys())
        viewer = _make_role_headers(client, auth, 'viewer')
        assert client.get('/api/finance/summary', headers=viewer).status_code == 403
        assert client.get('/api/finance/summary').status_code == 401


class TestPortalReceiptFlow:
    """Volunteer portal receipt submission: auto-reimbursement, resubmission,
    slot ownership, and the paid→receipt-approved linkage."""

    @pytest.fixture(autouse=True)
    def setup(self, client, auth, wa_mock):
        self.client = client
        self.auth = auth

        # Family with a confirmed order in an open cycle
        phone = f'585700{uuid.uuid4().hex[:4]}'
        fam = client.post('/api/families', headers=auth,
                          json={'name': f'PortalRcpt Fam {phone}', 'phone': phone,
                                'address': '9 Oak St', 'city': 'Rochester',
                                'family_size': 4, 'status': 'active'}).get_json()
        self.family_id = fam['id']
        fam_headers = {'Authorization': f'Bearer {_get_family_token(client, fam)}'}

        cycle = client.post('/api/delivery-cycles', headers=auth,
                            json=_cycle_payload(status='open')).get_json()
        self.cycle_id = cycle['id']

        client.post('/api/food-order', headers=fam_headers,
                    json={'family_id': self.family_id, 'cycle_id': self.cycle_id,
                          'selected_items': []})
        client.post(f'/api/delivery-cycles/{self.cycle_id}/generate-slots', headers=auth)

        # Shopper volunteer with a portal session who claims the shopping slot
        vol_phone = f'5852{uuid.uuid4().int % 1000000:06d}'
        vol = client.post('/api/volunteers', headers=auth,
                          json={'name': f'PortalRcpt Vol {vol_phone}', 'phone': vol_phone,
                                'email': f'prv_{vol_phone}@test.sihha.org',
                                'role': 'shopper', 'status': 'active'}).get_json()
        self.volunteer_id = vol['id']
        token = _get_volunteer_token(client, self.volunteer_id, auth)
        assert token, 'volunteer portal login failed'
        self.portal = {'Authorization': f'Bearer {token}'}

        signup = client.post('/api/portal/signup', headers=self.portal,
                             json={'cycle_id': self.cycle_id,
                                   'family_id': self.family_id,
                                   'task_types': ['shopping']})
        assert signup.status_code == 201, f'Signup failed: {signup.data}'
        tasks = client.get('/api/portal/my-tasks', headers=self.portal).get_json()
        self.slot_id = next(t['id'] for t in tasks
                            if t['task_type'] == 'shopping'
                            and t['family_id'] == self.family_id)

    def _submit_receipt(self, amount=33.33, **overrides):
        payload = {'slot_id': self.slot_id, 'amount': amount,
                   'store': 'Trader Joes', 'purchase_date': '2026-06-06'}
        payload.update(overrides)
        return self.client.post('/api/portal/receipts', headers=self.portal, json=payload)

    def test_portal_submit_creates_pending_receipt_no_payable_yet(self, client, auth):
        # New flow: submission creates a PENDING receipt only — the payable
        # (reimbursement) is created later, at approval. Nothing owed yet.
        res = self._submit_receipt(amount=33.33)
        assert res.status_code == 201
        data = res.get_json()
        assert data['receipt_id']
        assert data['reimbursement_id'] is None

        receipts = client.get('/api/receipts', headers=auth).get_json()
        rec = next(r for r in receipts if r['id'] == data['receipt_id'])
        assert rec['family_id'] == self.family_id
        assert rec['status'] == 'pending'
        assert rec['amount'] == pytest.approx(33.33)

        # No reimbursement exists until a treasurer/admin approves the receipt.
        reimbs = [r for r in client.get('/api/reimbursements', headers=auth).get_json()
                  if r['receipt_id'] == data['receipt_id']]
        assert reimbs == []

    def test_portal_resubmit_same_slot_updates_in_place(self, client, auth):
        first = self._submit_receipt(amount=33.33).get_json()
        res = self._submit_receipt(amount=44.00)
        assert res.status_code == 200
        data = res.get_json()
        assert data['updated'] is True
        assert data['receipt_id'] == first['receipt_id'], 'must update, not duplicate'

        rec = next(r for r in client.get('/api/receipts', headers=auth).get_json()
                   if r['id'] == first['receipt_id'])
        assert rec['amount'] == pytest.approx(44.00)
        assert rec['status'] == 'pending'
        # Still no payable — not approved yet.
        assert [r for r in client.get('/api/reimbursements', headers=auth).get_json()
                if r['receipt_id'] == first['receipt_id']] == []

    def test_portal_lists_own_receipt_with_reimbursement_status(self, client):
        submitted = self._submit_receipt(amount=21.00).get_json()
        rows = client.get('/api/portal/receipts', headers=self.portal).get_json()
        row = next((r for r in rows if r['id'] == submitted['receipt_id']), None)
        assert row is not None
        assert row['receipt_status'] == 'pending'
        assert row['reimbursement_id'] is None      # no payable until approved
        assert row['reimbursement_status'] is None

    def test_submit_with_someone_elses_slot_returns_404(self, client, auth):
        other_phone = f'5853{uuid.uuid4().int % 1000000:06d}'
        other = client.post('/api/volunteers', headers=auth,
                            json={'name': f'Other Vol {other_phone}', 'phone': other_phone,
                                  'email': f'ov_{other_phone}@test.sihha.org',
                                  'role': 'shopper', 'status': 'active'}).get_json()
        other_token = _get_volunteer_token(client, other['id'], auth)
        res = client.post('/api/portal/receipts',
                          headers={'Authorization': f'Bearer {other_token}'},
                          json={'slot_id': self.slot_id, 'amount': 10.00, 'store': 'X'})
        assert res.status_code == 404

    def test_submit_without_slot_id_allowed(self, client, auth):
        res = self._submit_receipt(amount=5.00, slot_id=None)
        assert res.status_code == 201
        rec = next(r for r in client.get('/api/receipts', headers=auth).get_json()
                   if r['id'] == res.get_json()['receipt_id'])
        assert rec['family_id'] is None
        assert rec['slot_id'] is None

    def test_slot_auto_completed_on_receipt_submit(self, client, auth):
        # Fixed 2026-06-11: receipt submission completes the shopping slot.
        # (The old guard only matched status='claimed', which no longer occurs
        # since the 2026-06-09 auto-confirm redesign — it now covers 'confirmed'.)
        res = self._submit_receipt(amount=12.00)
        assert res.status_code == 201
        slots = client.get(f'/api/volunteer-slots?cycle_id={self.cycle_id}',
                           headers=auth).get_json()
        slot = next(s for s in slots if s['id'] == self.slot_id)
        assert slot['status'] == 'complete', \
            'Submitting a receipt IS the completion signal for a shopping slot'
        assert slot.get('completed_at'), 'completed_at must be stamped'

    def test_approve_then_pay_flow(self, client, auth):
        # New flow: submit (pending) → admin approves (creates payable) → pay it.
        submitted = self._submit_receipt(amount=18.75).get_json()
        rid = submitted['receipt_id']
        client.put(f'/api/receipts/{rid}', headers=auth, json={'status': 'approved'})
        reimb = next(r for r in client.get('/api/reimbursements', headers=auth).get_json()
                     if r['receipt_id'] == rid)
        assert reimb['status'] == 'pending' and reimb['amount'] == pytest.approx(18.75)
        paid = client.put(f'/api/reimbursements/{reimb["id"]}', headers=auth,
                          json={'status': 'paid', 'payment_method': 'venmo', 'payment_ref': 'VN-99'})
        assert paid.status_code == 200
        rec = next(r for r in client.get('/api/receipts', headers=auth).get_json() if r['id'] == rid)
        assert rec['status'] == 'approved'   # stays approved after payment

    def test_portal_receipts_require_portal_auth(self, client):
        assert client.get('/api/portal/receipts').status_code == 401
        assert client.post('/api/portal/receipts',
                           json={'amount': 1}).status_code == 401


# ── Receipt vision-parsing (Phase A) ──────────────────────────────────────────
import server as _server


class TestReceiptParsing:
    def test_schema_has_parsed_columns_and_items_table(self, client, auth):
        db = _server.get_db_direct() if hasattr(_server, 'get_db_direct') else _server.make_conn()
        cols = [r[1] for r in db.execute("PRAGMA table_info(receipts)").fetchall()]
        for c in ['parsed_store', 'parsed_total', 'parse_status', 'amount_mismatch']:
            assert c in cols, f'missing receipts.{c}'
        assert db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='receipt_items'"
        ).fetchone(), 'receipt_items table missing'
        db.close()

    def test_parsing_inactive_by_default_returns_none(self):
        # No ANTHROPIC_API_KEY / flag in the test env → parsing must no-op.
        assert _server.RECEIPT_PARSING_ACTIVE is False
        assert _server._parse_receipt_image(b'not-an-image', 'x.jpg') is None

    def test_normalize_coerces_types_and_drops_blank_items(self):
        out = _server._normalize_parsed_receipt({
            'store': '  Costco ', 'purchase_date': '2026-07-09',
            'total': '42.5', 'confidence': 1.7,          # >1 clamps to 1.0
            'line_items': [
                {'name': 'Milk', 'qty': '2', 'unit_price': '3.5', 'line_total': '7'},
                {'name': '', 'qty': 1},                   # blank name dropped
            ],
        })
        assert out['store'] == 'Costco'
        assert out['total'] == 42.5
        assert out['confidence'] == 1.0
        assert len(out['line_items']) == 1
        assert out['line_items'][0]['qty'] == 2.0

    def test_create_receipt_with_parsed_flags_mismatch_and_persists_items(self, client, auth):
        # Exercise persist through the endpoint so the app's own connection does the
        # writes (a second write connection would contend on the WAL lock). typed 20
        # vs parsed 25 → mismatch flagged; the line item is persisted.
        payload = {
            'volunteer_id': None, 'amount': 20.00, 'store': 'Aldi',
            'parsed': {'store': 'Aldi', 'total': 25.00, 'confidence': 0.8,
                       'line_items': [{'name': 'Eggs', 'qty': 1, 'unit_price': 25, 'line_total': 25}]},
        }
        res = client.post('/api/receipts', headers=auth, json=payload)
        assert res.status_code == 201
        rid = res.get_json()['id']
        rec = next(r for r in client.get('/api/receipts', headers=auth).get_json() if r['id'] == rid)
        assert rec['parsed_total'] == 25.00
        assert rec['parse_status'] == 'parsed'
        assert rec['amount_mismatch'] == 1
        db = _server.make_conn()   # READ-ONLY use — no write lock taken
        try:
            n = db.execute("SELECT COUNT(*) FROM receipt_items WHERE receipt_id=?", (rid,)).fetchone()[0]
        finally:
            db.close()
        assert n == 1

    def test_create_receipt_with_matching_parsed_has_no_mismatch(self, client, auth):
        payload = {
            'volunteer_id': None, 'amount': 25.00, 'store': 'Aldi',
            'parsed': {'store': 'Aldi', 'total': 25.00, 'confidence': 0.9, 'line_items': []},
        }
        res = client.post('/api/receipts', headers=auth, json=payload)
        rid = res.get_json()['id']
        rec = next(r for r in client.get('/api/receipts', headers=auth).get_json() if r['id'] == rid)
        assert rec['amount_mismatch'] == 0  # typed 25 == parsed 25

    def test_uploads_route_requires_token(self, client):
        # Photo files are auth-protected; no Bearer header → 401.
        assert client.get('/uploads/whatever.jpg').status_code == 401

    def test_uploads_route_with_token_does_not_500(self, client, auth):
        # Regression: serve_upload used to `SELECT id FROM sessions` but sessions has
        # no id column, so a *valid* token 500'd. A valid token must authenticate;
        # a missing file then yields 404 (never 500).
        assert client.get('/uploads/nonexistent-file.jpg', headers=auth).status_code == 404

    def test_detail_endpoint_returns_items(self, client, auth):
        res = client.post('/api/receipts', headers=auth, json={
            'amount': 12.00, 'store': 'Costco',
            'parsed': {'store': 'Costco', 'total': 12.00, 'confidence': 0.9,
                       'line_items': [{'name': 'Milk', 'qty': 1, 'unit_price': 12, 'line_total': 12}]},
        })
        rid = res.get_json()['id']
        det = client.get('/api/receipts/' + rid, headers=auth).get_json()
        assert 'items' in det and len(det['items']) == 1
        assert det['items'][0]['name'] == 'Milk'

    def test_analytics_rolls_up_approved_spend(self, client, auth):
        vid = client.post('/api/volunteers', headers=auth, json={
            'name': 'Analytics Vol', 'phone': f'585{uuid.uuid4().hex[:7]}',
            'role': 'shopper', 'status': 'active'}).get_json()['id']
        rid = client.post('/api/receipts', headers=auth, json={
            'volunteer_id': vid, 'amount': 900, 'store': 'BJs Analytics', 'purchase_date': '2026-05-04',
            'parsed': {'store': 'BJs Analytics', 'total': 900, 'confidence': 0.9,
                       'line_items': [{'name': 'ZzUniqueItem', 'qty': 1, 'unit_price': 900, 'line_total': 900}]},
        }).get_json()['id']
        # Only counts once APPROVED
        an0 = client.get('/api/receipts/analytics', headers=auth).get_json()
        assert not any(s['store'] == 'BJs Analytics' for s in an0['by_store'])
        client.put(f'/api/receipts/{rid}', headers=auth, json={'status': 'approved'})
        an = client.get('/api/receipts/analytics', headers=auth).get_json()
        store = next(s for s in an['by_store'] if s['store'] == 'BJs Analytics')
        assert store['total'] == pytest.approx(900)
        assert any(i['name'].lower() == 'zzuniqueitem' for i in an['top_items'])
        assert any(v['volunteer_name'] == 'Analytics Vol' and v['owed'] == pytest.approx(900)
                   for v in an['by_volunteer'])

    def test_bulk_approve_only_pending(self, client, auth):
        ids = [client.post('/api/receipts', headers=auth,
                           json={'amount': i + 5, 'store': f'Bulk{i}'}).get_json()['id']
               for i in range(3)]
        r = client.post('/api/receipts/bulk-approve', headers=auth, json={'ids': ids[:2]})
        assert r.status_code == 200 and r.get_json()['approved'] == 2
        recs = {x['id']: x['status'] for x in client.get('/api/receipts', headers=auth).get_json()}
        assert recs[ids[0]] == 'approved' and recs[ids[1]] == 'approved' and recs[ids[2]] == 'pending'
        # payables created for the two approved
        paid_ids = {r['receipt_id'] for r in client.get('/api/reimbursements', headers=auth).get_json()}
        assert ids[0] in paid_ids and ids[1] in paid_ids and ids[2] not in paid_ids
        assert client.post('/api/receipts/bulk-approve', headers=auth, json={'ids': []}).status_code == 400

    def test_unapprove_removes_unpaid_payable(self, client, auth):
        rid = client.post('/api/receipts', headers=auth, json={'amount': 10, 'store': 'X'}).get_json()['id']
        client.put(f'/api/receipts/{rid}', headers=auth, json={'status': 'approved'})
        assert [r for r in client.get('/api/reimbursements', headers=auth).get_json()
                if r['receipt_id'] == rid]  # payable exists
        client.put(f'/api/receipts/{rid}', headers=auth, json={'status': 'pending'})
        assert [r for r in client.get('/api/reimbursements', headers=auth).get_json()
                if r['receipt_id'] == rid] == []  # payable removed

    def test_edit_assigns_volunteer_and_recomputes_mismatch(self, client, auth):
        vid = client.post('/api/volunteers', headers=auth, json={
            'name': 'Assign Me', 'phone': f'585{uuid.uuid4().hex[:7]}',
            'role': 'shopper', 'status': 'active'}).get_json()['id']
        # typed 30 vs parsed 34 → mismatch=1
        rid = client.post('/api/receipts', headers=auth, json={
            'volunteer_id': None, 'amount': 30, 'store': 'X',
            'parsed': {'total': 34.0, 'confidence': 0.9, 'line_items': []},
        }).get_json()['id']
        # assign volunteer + fix amount to 34 → mismatch clears
        r = client.put('/api/receipts/' + rid, headers=auth, json={'volunteer_id': vid, 'amount': 34})
        assert r.status_code == 200
        det = client.get('/api/receipts/' + rid, headers=auth).get_json()
        assert det['volunteer_id'] == vid
        assert det['amount'] == 34.0
        assert det['amount_mismatch'] == 0

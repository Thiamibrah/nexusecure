from tests.conftest import user_id, make_scan


def test_compare_scans_not_found(client, admin_token):
    res = client.get("/api/dashboard/compare?scan_before=999998&scan_after=999999",
                     headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 404


def test_compare_scans_forbidden_client(client, db, analyst_token, client_token, other_client_token):
    # Both scans belong to "testclient2" — "testclient" must not be able to compare them.
    analyst_id = user_id(db, "testanalyst")
    other_client_id = user_id(db, "testclient2")
    scan_a = make_scan(db, user_id=analyst_id, client_id=other_client_id, target="10.0.1.1")
    scan_b = make_scan(db, user_id=analyst_id, client_id=other_client_id, target="10.0.1.2")

    res = client.get(f"/api/dashboard/compare?scan_before={scan_a.id}&scan_after={scan_b.id}",
                     headers={"Authorization": f"Bearer {client_token}"})
    assert res.status_code == 404


def test_compare_scans_forbidden_one_out_of_scope(client, db, analyst_token, client_token, other_client_token):
    # scan_before belongs to the caller, scan_after belongs to someone else — still forbidden.
    analyst_id = user_id(db, "testanalyst")
    my_client_id = user_id(db, "testclient")
    other_client_id = user_id(db, "testclient2")
    my_scan = make_scan(db, user_id=analyst_id, client_id=my_client_id, target="10.0.1.3")
    other_scan = make_scan(db, user_id=analyst_id, client_id=other_client_id, target="10.0.1.4")

    res = client.get(f"/api/dashboard/compare?scan_before={my_scan.id}&scan_after={other_scan.id}",
                     headers={"Authorization": f"Bearer {client_token}"})
    assert res.status_code == 404


def test_compare_scans_ok_client(client, db, analyst_token, client_token):
    analyst_id = user_id(db, "testanalyst")
    my_client_id = user_id(db, "testclient")
    scan_a = make_scan(db, user_id=analyst_id, client_id=my_client_id, target="10.0.1.5")
    scan_b = make_scan(db, user_id=analyst_id, client_id=my_client_id, target="10.0.1.6")

    res = client.get(f"/api/dashboard/compare?scan_before={scan_a.id}&scan_after={scan_b.id}",
                     headers={"Authorization": f"Bearer {client_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["before"]["scan_id"] == scan_a.id
    assert data["after"]["scan_id"] == scan_b.id
    assert "diff" in data


def test_compare_scans_ok_analyst_own_scans(client, db, analyst_token):
    analyst_id = user_id(db, "testanalyst")
    scan_a = make_scan(db, user_id=analyst_id, target="10.0.1.7")
    scan_b = make_scan(db, user_id=analyst_id, target="10.0.1.8")

    res = client.get(f"/api/dashboard/compare?scan_before={scan_a.id}&scan_after={scan_b.id}",
                     headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 200


def test_compare_scans_forbidden_analyst_other_analyst_scan(client, db, analyst_token, other_analyst_token):
    other_analyst_id = user_id(db, "testanalyst2")
    scan_a = make_scan(db, user_id=other_analyst_id, target="10.0.1.9")
    scan_b = make_scan(db, user_id=other_analyst_id, target="10.0.1.10")

    res = client.get(f"/api/dashboard/compare?scan_before={scan_a.id}&scan_after={scan_b.id}",
                     headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 404


def test_compare_scans_admin_unrestricted(client, db, admin_token, analyst_token, client_token):
    analyst_id = user_id(db, "testanalyst")
    my_client_id = user_id(db, "testclient")
    scan_a = make_scan(db, user_id=analyst_id, client_id=my_client_id, target="10.0.1.11")
    scan_b = make_scan(db, user_id=analyst_id, client_id=my_client_id, target="10.0.1.12")

    res = client.get(f"/api/dashboard/compare?scan_before={scan_a.id}&scan_after={scan_b.id}",
                     headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200

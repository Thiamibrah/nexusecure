from tests.conftest import user_id, make_scan, make_host, make_vulnerability


def test_add_comment_not_found(client, admin_token):
    res = client.patch("/api/vulnerabilities/999999/comment", json={"comment": "hi"},
                       headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 404


def test_add_comment_forbidden_client_role(client, db, analyst_token, client_token):
    analyst_id = user_id(db, "testanalyst")
    scan = make_scan(db, user_id=analyst_id, target="10.0.2.1")
    host = make_host(db, scan.id)
    vuln = make_vulnerability(db, host.id)

    res = client.patch(f"/api/vulnerabilities/{vuln.id}/comment", json={"comment": "nope"},
                       headers={"Authorization": f"Bearer {client_token}"})
    assert res.status_code == 403


def test_add_comment_forbidden_other_analyst_scan(client, db, analyst_token, other_analyst_token):
    other_analyst_id = user_id(db, "testanalyst2")
    scan = make_scan(db, user_id=other_analyst_id, target="10.0.2.2")
    host = make_host(db, scan.id)
    vuln = make_vulnerability(db, host.id)

    res = client.patch(f"/api/vulnerabilities/{vuln.id}/comment", json={"comment": "sneaky"},
                       headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 404


def test_add_comment_ok_own_scan(client, db, analyst_token):
    analyst_id = user_id(db, "testanalyst")
    scan = make_scan(db, user_id=analyst_id, target="10.0.2.3")
    host = make_host(db, scan.id)
    vuln = make_vulnerability(db, host.id)

    res = client.patch(f"/api/vulnerabilities/{vuln.id}/comment", json={"comment": "reviewed"},
                       headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 200
    assert res.json()["comment"] == "reviewed"


def test_add_comment_ok_admin_any_scan(client, db, admin_token, other_analyst_token):
    other_analyst_id = user_id(db, "testanalyst2")
    scan = make_scan(db, user_id=other_analyst_id, target="10.0.2.4")
    host = make_host(db, scan.id)
    vuln = make_vulnerability(db, host.id)

    res = client.patch(f"/api/vulnerabilities/{vuln.id}/comment", json={"comment": "admin override"},
                       headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert res.json()["comment"] == "admin override"


def test_list_vulnerabilities_scoped_to_client(client, db, analyst_token, client_token, other_client_token):
    analyst_id = user_id(db, "testanalyst")
    my_client_id = user_id(db, "testclient")
    other_client_id = user_id(db, "testclient2")

    my_scan = make_scan(db, user_id=analyst_id, client_id=my_client_id, target="10.0.2.5")
    my_host = make_host(db, my_scan.id)
    my_vuln = make_vulnerability(db, my_host.id, title="My vuln")

    other_scan = make_scan(db, user_id=analyst_id, client_id=other_client_id, target="10.0.2.6")
    other_host = make_host(db, other_scan.id)
    make_vulnerability(db, other_host.id, title="Other client's vuln")

    res = client.get("/api/vulnerabilities/", headers={"Authorization": f"Bearer {client_token}"})
    assert res.status_code == 200
    titles = [v["title"] for v in res.json()]
    assert "My vuln" in titles
    assert "Other client's vuln" not in titles

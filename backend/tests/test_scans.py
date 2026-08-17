def test_create_scan_valid(client, analyst_token):
    res = client.post("/api/scans",
        json={"target": "127.0.0.1"},
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["target"] == "127.0.0.1"
    assert data["status"] in ("pending", "running", "completed")


def test_create_scan_invalid_target(client, analyst_token):
    res = client.post("/api/scans",
        json={"target": "not-an-ip"},
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res.status_code == 422


def test_create_scan_forbidden_client(client, db):
    from app.models.user import User, UserRole
    from app.auth.security import hash_password
    if not db.query(User).filter(User.username == "testclient").first():
        db.add(User(username="testclient", email="client@test.local",
                    password_hash=hash_password("Client@123!"), role=UserRole.client))
        db.commit()
    res_login = client.post("/api/auth/token", data={"username": "testclient", "password": "Client@123!"})
    token = res_login.json()["access_token"]
    res = client.post("/api/scans", json={"target": "127.0.0.1"},
                      headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403


def test_list_scans(client, analyst_token):
    res = client.get("/api/scans", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_get_scan_not_found(client, analyst_token):
    res = client.get("/api/scans/99999", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 404

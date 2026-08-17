def test_login_success(client, admin_token):
    assert admin_token is not None
    assert len(admin_token) > 10


def test_login_wrong_password(client):
    res = client.post("/api/auth/token", data={"username": "testadmin", "password": "wrong"})
    assert res.status_code == 401


def test_login_unknown_user(client):
    res = client.post("/api/auth/token", data={"username": "nobody", "password": "x"})
    assert res.status_code == 401


def test_me_authenticated(client, admin_token):
    res = client.get("/api/users/me", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert res.json()["role"] == "admin"


def test_me_unauthenticated(client):
    res = client.get("/api/users/me")
    assert res.status_code == 401

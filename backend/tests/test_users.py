def test_list_users_admin(client, admin_token):
    res = client.get("/api/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_list_users_forbidden(client, analyst_token):
    res = client.get("/api/users", headers={"Authorization": f"Bearer {analyst_token}"})
    assert res.status_code == 403


def test_create_user(client, admin_token):
    res = client.post("/api/users",
        json={"username": "newuser", "email": "new@test.local", "password": "Pass@5678!", "role": "client"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["username"] == "newuser"
    assert data["role"] == "client"


def test_create_user_duplicate(client, admin_token):
    payload = {"username": "dupuser", "email": "dup@test.local", "password": "Pass@5678!", "role": "client"}
    client.post("/api/users", json=payload, headers={"Authorization": f"Bearer {admin_token}"})
    res = client.post("/api/users", json=payload, headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 409


def test_password_too_short(client, admin_token):
    res = client.post("/api/users",
        json={"username": "shortpw", "email": "short@test.local", "password": "123", "role": "client"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 422

import uuid
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app


def test_seed_users_exist():
    with TestClient(app) as client:
        res = client.get("/api/v1/auth/users")
        assert res.status_code == 200
        users = res.json()
        assert len(users) >= 1
        usernames = [u["username"] for u in users]
        assert "abhiram" in usernames


def test_user_signup_and_login():
    unique_id = uuid.uuid4().hex[:6]
    test_email = f"agent_{unique_id}@forensix.ai"
    test_username = f"agent_{unique_id}"
    test_password = "SecretPassword123!"

    with TestClient(app) as client:
        # 1. Sign up new investigator
        signup_payload = {
            "email": test_email,
            "username": test_username,
            "password": test_password,
            "full_name": "Special Investigator",
            "role": "Senior Forensic Analyst",
        }
        res_signup = client.post("/api/v1/auth/signup", json=signup_payload)
        assert res_signup.status_code == 201
        data = res_signup.json()
        assert "access_token" in data
        assert data["user"]["email"] == test_email
        assert data["user"]["username"] == test_username
        assert data["user"]["role"] == "Senior Forensic Analyst"
        token = data["access_token"]

        # 2. Duplicate registration rejection
        dup_res = client.post("/api/v1/auth/signup", json=signup_payload)
        assert dup_res.status_code == 409

        # 3. Log in with username
        login_res = client.post(
            "/api/v1/auth/login",
            json={"username_or_email": test_username, "password": test_password},
        )
        assert login_res.status_code == 200
        assert "access_token" in login_res.json()

        # 4. Log in with email
        login_email_res = client.post(
            "/api/v1/auth/login",
            json={"username_or_email": test_email, "password": test_password},
        )
        assert login_email_res.status_code == 200

        # 5. Invalid credentials rejection
        bad_res = client.post(
            "/api/v1/auth/login",
            json={"username_or_email": test_username, "password": "WrongPassword999!"},
        )
        assert bad_res.status_code == 401

        # 6. Retrieve authenticated profile via /me
        me_res = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_res.status_code == 200
        assert me_res.json()["email"] == test_email


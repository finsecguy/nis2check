import base64
import hashlib
import threading

import pytest

pytest.importorskip("flask")

from nis2check.web import create_app  # noqa: E402
from nis2check.web.auth import SETUP_TOKEN_BYTES, SETUP_TOKEN_KEY  # noqa: E402
from nis2check.web.manage import create_admin  # noqa: E402
from nis2check.web.models import User  # noqa: E402
from nis2check.web.services import get_setting  # noqa: E402

PASSWORD = "CorrectHorse12"
SETUP_TOKEN = "test-setup-token"


def _form(**overrides):
    data = dict(
        org_name="Acme", name="Admin", email="admin@acme.sk",
        password=PASSWORD, password2=PASSWORD, token=SETUP_TOKEN,
    )
    data.update(overrides)
    return data


def _users(app) -> int:
    return app.extensions["nis2_db"]().query(User).count()


def _stored_token(app) -> str:
    return get_setting(app.extensions["nis2_db"](), SETUP_TOKEN_KEY, "")


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("NIS2CHECK_SETUP_TOKEN", SETUP_TOKEN)
    application = create_app(data_dir=tmp_path / "data", start_scheduler=False)
    application.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def test_setup_without_token_is_rejected(client, app):
    page = client.get("/setup")
    assert page.status_code == 404
    assert b"Set up the assessment" not in page.data
    followed = client.get("/login", follow_redirects=True)
    assert followed.status_code == 404
    posted = client.post("/setup", data=_form(token=""))
    assert posted.status_code == 404
    assert _users(app) == 0


def test_setup_wrong_token_is_rejected(client, app):
    assert client.get("/setup?token=wrong").status_code == 404
    posted = client.post("/setup", data=_form(token="wrong"))
    assert posted.status_code == 404
    assert _users(app) == 0
    # a wrong guess does not use up the real token
    assert client.get(f"/setup?token={SETUP_TOKEN}").status_code == 200


def test_setup_token_works_once_then_is_rejected(client, app):
    page = client.get(f"/setup?token={SETUP_TOKEN}")
    assert page.status_code == 200
    assert b"Set up the assessment" in page.data
    assert f'name="token" value="{SETUP_TOKEN}"'.encode() in page.data
    assert _stored_token(app) == hashlib.sha256(SETUP_TOKEN.encode()).hexdigest()

    created = client.post("/setup", data=_form())
    assert created.status_code == 302
    assert created.headers["Location"].endswith("/organisation")
    assert _users(app) == 1
    assert _stored_token(app) == ""

    again = client.post("/setup", data=_form(email="second@acme.sk"))
    assert again.status_code == 302
    assert again.headers["Location"].endswith("/login")
    assert client.get(f"/setup?token={SETUP_TOKEN}").headers["Location"].endswith("/login")
    assert _users(app) == 1


def test_invalid_setup_form_does_not_consume_the_token(client, app):
    rejected = client.post("/setup", data=_form(password="short", password2="short"))
    assert rejected.status_code == 200
    assert b"at least 12" in rejected.data
    assert _users(app) == 0
    assert _stored_token(app) == hashlib.sha256(SETUP_TOKEN.encode()).hexdigest()
    assert client.post("/setup", data=_form()).status_code == 302
    assert _users(app) == 1


def test_env_supplied_setup_token(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NIS2CHECK_SETUP_TOKEN", "operator-chosen-token")
    application = create_app(data_dir=tmp_path / "data", start_scheduler=False)
    application.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    out = capsys.readouterr().out
    assert "nis2check setup token:" not in out
    assert "operator-chosen-token" not in out
    assert _stored_token(application) == hashlib.sha256(b"operator-chosen-token").hexdigest()

    client = application.test_client()
    assert client.get("/setup").status_code == 404
    assert client.post("/setup", data=_form(token="test-setup-token")).status_code == 404
    # the query string is enough; the form field can be omitted
    created = client.post(
        "/setup?token=operator-chosen-token",
        data=dict(org_name="Acme", name="Admin", email="admin@acme.sk",
                  password=PASSWORD, password2=PASSWORD),
    )
    assert created.status_code == 302
    assert _users(application) == 1
    assert client.post(
        "/setup?token=operator-chosen-token",
        data=dict(org_name="Other", name="Other", email="other@acme.sk",
                  password=PASSWORD, password2=PASSWORD),
    ).headers["Location"].endswith("/login")
    assert _users(application) == 1


def test_generated_setup_token_is_printed_once_and_stored_as_a_hash(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("NIS2CHECK_SETUP_TOKEN", raising=False)
    application = create_app(data_dir=tmp_path / "data", start_scheduler=False)
    application.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    out = capsys.readouterr().out
    line = next(item for item in out.splitlines() if item.startswith("nis2check setup token: "))
    token = line.split(": ", 1)[1].strip()
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    assert SETUP_TOKEN_BYTES >= 32
    assert len(raw) >= 32
    assert _stored_token(application) == hashlib.sha256(token.encode()).hexdigest()
    assert token not in _stored_token(application)

    restarted = create_app(data_dir=tmp_path / "data", start_scheduler=False)
    restarted.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    assert "nis2check setup token:" not in capsys.readouterr().out
    client = restarted.test_client()
    assert client.get("/setup").status_code == 404
    assert client.get(f"/setup?token={token}").status_code == 200
    assert client.post("/setup", data=_form(token=token)).status_code == 302
    assert _users(restarted) == 1
    assert client.get(f"/setup?token={token}").headers["Location"].endswith("/login")


def test_command_line_admin_removes_the_setup_token(app):
    create_admin(app, "cli@acme.sk", PASSWORD)
    assert _stored_token(app) == ""
    client = app.test_client()
    assert client.get(f"/setup?token={SETUP_TOKEN}").headers["Location"].endswith("/login")
    assert client.post("/setup", data=_form(email="web@acme.sk")).headers["Location"].endswith("/login")
    assert _users(app) == 1


def test_concurrent_setup_creates_one_admin(app):
    barrier = threading.Barrier(2)
    results = []

    def attempt(email):
        client = app.test_client()
        barrier.wait(timeout=5)
        response = client.post("/setup", data=_form(email=email))
        results.append(response.status_code)

    threads = [
        threading.Thread(target=attempt, args=("one@acme.sk",)),
        threading.Thread(target=attempt, args=("two@acme.sk",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert [thread.is_alive() for thread in threads] == [False, False]
    assert sorted(results) == [302, 302]
    assert _users(app) == 1
    assert _stored_token(app) == ""

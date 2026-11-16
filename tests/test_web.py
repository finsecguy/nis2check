import datetime as dt
import io
import re
from pathlib import Path

import pytest

pytest.importorskip("flask")

from nis2check.web import create_app  # noqa: E402
from nis2check.web.auth import SSOError, resolve_sso_user  # noqa: E402
from nis2check.web.models import Evidence, Response, Snapshot, ThreatDataVersion, User  # noqa: E402
from nis2check.web.services import run_threat_check  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).resolve().parent / "fixtures" / "threat"
PASSWORD = "CorrectHorse12"


@pytest.fixture
def app(tmp_path):
    app = create_app(data_dir=tmp_path / "data", start_scheduler=False, threat_source_dir=str(FIX))
    app.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    from nis2check.web import auth
    auth._failures.clear()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def setup_admin(client):
    return client.post("/setup", data=dict(org_name="Acme", name="Admin", email="admin@acme.sk",
                                           password=PASSWORD, password2=PASSWORD))


def add_user(app, email, role):
    from nis2check.web.auth import hash_password
    db = app.extensions["nis2_db"]()
    db.add(User(email=email, role=role, password_hash=hash_password(PASSWORD)))
    db.commit()


def login(client, email, password=PASSWORD):
    return client.post("/login", data=dict(email=email, password=password))


def db(app):
    return app.extensions["nis2_db"]()


# ------------------------------------------------------------------ setup and login

def test_first_run_goes_to_setup(client):
    assert client.get("/").headers["Location"].startswith("/login")
    assert client.get("/login").headers["Location"] == "/setup"
    r = setup_admin(client)
    assert r.status_code == 302
    assert client.get("/").status_code == 200
    assert client.get("/setup").headers["Location"] == "/login"  # setup only once


def test_setup_rejects_weak_password(client):
    r = client.post("/setup", data=dict(org_name="A", name="A", email="a@a.sk", password="short", password2="short"))
    assert b"at least 12" in r.data
    assert client.get("/login").headers["Location"] == "/setup"


def test_login_and_throttling(app):
    c = app.test_client()
    setup_admin(c)
    c.post("/logout")
    assert b"Wrong email or password" in login(c, "admin@acme.sk", "nope").data
    for _ in range(9):
        login(c, "admin@acme.sk", "nope")
    assert login(c, "admin@acme.sk", PASSWORD).status_code == 429
    assert login(c, "admin@acme.sk", "nope").status_code == 429


def test_open_redirect_blocked(app):
    c = app.test_client()
    setup_admin(c)
    c.post("/logout")
    r = c.post("/login?next=//evil.example", data=dict(email="admin@acme.sk", password=PASSWORD))
    assert r.headers["Location"] == "/"


# ------------------------------------------------------------------ roles

def test_viewer_is_read_only(app):
    c = app.test_client()
    setup_admin(c)
    add_user(app, "viewer@acme.sk", "viewer")
    c.post("/logout")
    login(c, "viewer@acme.sk")
    assert c.get("/").status_code == 200
    assert c.get("/assessment/GOV").status_code == 200
    assert c.post("/assessment/question/GOV-01", data={"answer": "yes"}).status_code == 403
    assert c.get("/admin/users").status_code == 403
    assert c.post("/organisation", data={"name": "x"}).status_code == 403


def test_assessor_can_edit_not_admin(app):
    c = app.test_client()
    setup_admin(c)
    add_user(app, "assessor@acme.sk", "assessor")
    c.post("/logout")
    login(c, "assessor@acme.sk")
    assert c.post("/assessment/question/GOV-01", data={"answer": "yes"}).status_code == 302
    assert c.get("/admin/threat-data").status_code == 403


def test_last_admin_protected(app, client):
    setup_admin(client)
    admin = db(app).query(User).filter_by(email="admin@acme.sk").one()
    client.post(f"/admin/users/{admin.id}", data={"action": "role", "role": "viewer"})
    assert db(app).get(User, admin.id).role == "admin"
    client.post(f"/admin/users/{admin.id}", data={"action": "deactivate"})
    assert db(app).get(User, admin.id).active


def test_new_local_user_must_change_password(app, client):
    setup_admin(client)
    r = client.post("/admin/users", data={"email": "new@acme.sk", "role": "assessor", "method": "local"},
                    follow_redirects=True)
    temp = re.search(rb"Temporary password for new@acme.sk: (\S+) ", r.data).group(1).decode()
    client.post("/logout")
    login(client, "new@acme.sk", temp)
    assert client.get("/").headers["Location"] == "/account/password"
    client.post("/account/password", data={"current": temp, "password": "AnotherGood123", "password2": "AnotherGood123"})
    assert client.get("/").status_code == 200


# ------------------------------------------------------------------ assessment and evidence

def test_answer_saves_snapshot_and_audit(app, client):
    setup_admin(client)
    r = client.post("/assessment/question/GOV-01", data={"answer": "yes", "notes": "Board approved"})
    assert r.headers["Location"].endswith("/assessment/GOV#GOV-01")
    assert db(app).query(Snapshot).count() == 1
    page = client.get("/admin/audit").data
    assert b"Answer saved" in page and b"GOV-01" in page


def test_invalid_answer_rejected(client):
    setup_admin(client)
    assert client.post("/assessment/question/GOV-01", data={"answer": "maybe"}).status_code == 400
    assert client.post("/assessment/question/NOPE-1", data={"answer": "yes"}).status_code == 404


def test_evidence_upload_download_delete(app, client):
    setup_admin(client)
    data = {"answer": "yes", "file": (io.BytesIO(b"minutes"), "../../minutes.pdf")}
    client.post("/assessment/question/GOV-01", data=data, content_type="multipart/form-data")
    ev = db(app).query(Evidence).one()
    assert ev.filename == "minutes.pdf"           # path stripped
    stored = app.extensions["nis2_settings"].evidence_dir / ev.stored_name
    assert stored.read_bytes() == b"minutes"
    r = client.get(f"/evidence/{ev.id}/download")
    assert r.data == b"minutes" and "attachment" in r.headers["Content-Disposition"]
    client.post(f"/evidence/{ev.id}/delete")
    assert not stored.exists()
    assert db(app).query(Evidence).count() == 0


def test_disallowed_upload_and_link(app, client):
    setup_admin(client)
    r = client.post("/assessment/question/GOV-01", data={"answer": "yes", "file": (io.BytesIO(b"x"), "run.exe")},
                    content_type="multipart/form-data", follow_redirects=True)
    assert b"not accepted" in r.data
    r = client.post("/assessment/question/GOV-01", data={"answer": "yes", "link": "javascript:alert(1)"},
                    follow_redirects=True)
    assert b"must start with https://" in r.data
    assert db(app).query(Evidence).count() == 0


def test_bad_evidence_keeps_answer_and_leaves_no_orphan(app, client):
    setup_admin(client)
    # a rejected link must not discard the answer/notes saved alongside it
    r = client.post("/assessment/question/GOV-01",
                    data={"answer": "yes", "notes": "keep me", "link": "ftp://nope"},
                    follow_redirects=True)
    assert b"must start with https://" in r.data
    row = db(app).get(Response, "GOV-01")
    assert row is not None and row.answer == "yes" and row.notes == "keep me"

    # a rejected file must not be written to disk, and must not discard a valid link
    client.post("/assessment/question/GOV-02",
                data={"answer": "yes", "link": "https://x.example/doc", "file": (io.BytesIO(b"x"), "run.exe")},
                content_type="multipart/form-data")
    evid = db(app).query(Evidence).all()
    assert [e.kind for e in evid] == ["link"]  # the valid link saved, the bad file dropped
    assert db(app).get(Response, "GOV-02").answer == "yes"
    # only the one stored file ever written was none (the link has no stored file)
    assert list(app.extensions["nis2_settings"].evidence_dir.iterdir()) == []


def test_import_yaml_rejects_path_traversal(app, tmp_path):
    from nis2check.web.manage import import_yaml
    secret = tmp_path / "secret.txt"
    secret.write_text("TOPSECRET")
    assess_dir = tmp_path / "assess"
    assess_dir.mkdir()
    (assess_dir / "a.yaml").write_text(
        "entity:\n  name: T\n"
        "responses:\n"
        f"  GOV-01:\n    answer: yes\n    evidence:\n      - {secret}\n      - ../secret.txt\n"
    )
    counts = import_yaml(app, assess_dir / "a.yaml")
    assert counts["rejected_files"] == 2 and counts["files"] == 0
    assert db(app).query(Evidence).count() == 0


def test_expired_evidence_is_an_issue(app, client):
    setup_admin(client)
    past = (dt.date.today() - dt.timedelta(days=1)).isoformat()
    client.post("/assessment/question/BCM-02", data={"answer": "yes", "link": "https://x.example/restore-test",
                                                     "valid_until": past})
    page = client.get("/assessment/BCM").data
    assert b"Evidence expired" in page


def test_import_yaml(app):
    from nis2check.web.manage import import_yaml
    counts = import_yaml(app, ROOT / "examples" / "acme-assessment.yaml")
    assert counts["answers"] == 38 and counts["files"] >= 10 and counts["links"] == 1
    c = app.test_client()
    from nis2check.web.manage import create_admin
    create_admin(app, "admin@acme.sk", PASSWORD)
    login(c, "admin@acme.sk")
    assert b"Acme Logistics" in c.get("/").data


# ------------------------------------------------------------------ reports

def test_report_downloads(client):
    setup_admin(client)
    client.post("/assessment/question/GOV-01", data={"answer": "yes"})
    for fmt, marker in (("csv", b"Rank,Ref"), ("json", b'"weighting"'), ("html", b"Download PDF")):
        r = client.get(f"/report/download.{fmt}")
        assert r.status_code == 200 and marker in r.data
    view = client.get("/report/view").data
    assert b"1. Executive summary" in view and b"Download PDF" not in view  # embedded view, no toolbar
    assert client.get("/report/download.exe").status_code == 404


def test_report_pdf(client):
    pytest.importorskip("weasyprint")
    setup_admin(client)
    assert client.get("/report/download.pdf").data.startswith(b"%PDF")


# ------------------------------------------------------------------ security

def test_csrf_enforced(tmp_path):
    app = create_app(data_dir=tmp_path / "d", start_scheduler=False)
    c = app.test_client()
    assert c.post("/setup", data=dict(org_name="A", name="A", email="a@a.sk",
                                      password=PASSWORD, password2=PASSWORD)).status_code == 400


def test_security_headers(client):
    r = client.get("/login")
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_healthz(client):
    assert client.get("/healthz").json["status"] == "ok"


# ------------------------------------------------------------------ SSO account matching

class S:
    oidc_allowed_domains = ["acme.sk"]
    oidc_auto_provision = False
    oidc_default_role = "viewer"


def test_sso_unknown_user_refused(app):
    with pytest.raises(SSOError, match="Ask an administrator"):
        resolve_sso_user(db(app), S, "entra", {"email": "x@acme.sk", "sub": "1"})


def test_sso_domain_and_verification(app):
    with pytest.raises(SSOError, match="not allowed"):
        resolve_sso_user(db(app), S, "entra", {"email": "x@evil.com", "sub": "1"})
    with pytest.raises(SSOError, match="not verified"):
        resolve_sso_user(db(app), S, "google", {"email": "x@acme.sk", "sub": "1", "email_verified": False})


def test_sso_auto_provision_and_linking(app):
    class Auto(S):
        oidc_auto_provision = True
    d = db(app)
    user = resolve_sso_user(d, Auto, "entra", {"preferred_username": "New@Acme.sk", "sub": "abc", "name": "New"})
    assert user.email == "new@acme.sk" and user.role == "viewer" and user.sso_subject == "entra:abc"
    d.commit()
    assert resolve_sso_user(d, S, "entra", {"email": "new@acme.sk", "sub": "abc"}).id == user.id
    with pytest.raises(SSOError, match="different sign-in identity"):
        resolve_sso_user(d, S, "entra", {"email": "new@acme.sk", "sub": "other"})
    user.active = False
    with pytest.raises(SSOError, match="deactivated"):
        resolve_sso_user(d, S, "entra", {"email": "new@acme.sk", "sub": "abc"})


def test_sso_unverified_cannot_link_existing_account(app):
    # a pre-existing (e.g. local) account must not be taken over by an unverified SSO email
    add_user(app, "admin@acme.sk", "admin")
    d = db(app)
    with pytest.raises(SSOError, match="cannot be linked"):
        resolve_sso_user(d, S, "entra", {"email": "admin@acme.sk", "sub": "attacker"})
    # xms_edov vouches for the `email` claim, not a preferred_username fallback
    with pytest.raises(SSOError, match="cannot be linked"):
        resolve_sso_user(d, S, "entra", {"preferred_username": "admin@acme.sk", "sub": "x", "xms_edov": "true"})
    # with a verified email claim the tenant vouches for the address, so linking is allowed
    user = resolve_sso_user(d, S, "entra", {"email": "admin@acme.sk", "sub": "real", "xms_edov": "true"})
    assert user.sso_subject == "entra:real"


def test_login_next_rejects_backslash(client):
    setup_admin(client)
    for bad in ("/\\evil.com", "/%09/evil.com", "//evil.com"):
        r = client.post(f"/login?next={bad}", data={"email": "admin@acme.sk", "password": PASSWORD})
        assert r.status_code == 302 and "evil.com" not in r.headers["Location"]
    r = client.post("/login?next=/admin/audit", data={"email": "admin@acme.sk", "password": PASSWORD})
    assert r.headers["Location"].endswith("/admin/audit")


def test_env_disabled_auto_check_is_shown(app, client):
    setup_admin(client)
    app.extensions["nis2_settings"].threat_auto_check = False
    assert b"disabled by NIS2_THREAT_AUTO_CHECK" in client.get("/admin/threat-data").data
    assert b"has no effect until that is changed" in client.get("/admin/settings").data


# ------------------------------------------------------------------ threat data approval

def test_threat_update_needs_approval(app, client):
    setup_admin(client)
    before = client.get("/").data
    assert b"bundled" not in before  # dashboard does not show the source label
    version = run_threat_check(app.extensions["nis2_db"], app.extensions["nis2_catalogue"],
                               app.extensions["nis2_settings"], "test")
    assert version.status == "pending"
    page = client.get("/admin/threat-data").data
    assert b"Waiting for your approval" in page and b"Approve update" in page
    client.post(f"/admin/threat-data/{version.id}/approve")
    assert db(app).get(ThreatDataVersion, version.id).status == "active"
    assert b"approved update #" in client.get("/admin/threat-data").data
    # a second identical check finds nothing new
    again = run_threat_check(app.extensions["nis2_db"], app.extensions["nis2_catalogue"],
                             app.extensions["nis2_settings"], "test")
    assert again.status == "no_change"


def test_threat_update_reject_keeps_weights(app, client):
    setup_admin(client)
    v = run_threat_check(app.extensions["nis2_db"], app.extensions["nis2_catalogue"],
                         app.extensions["nis2_settings"], "test")
    client.post(f"/admin/threat-data/{v.id}/reject")
    assert db(app).get(ThreatDataVersion, v.id).status == "rejected"
    assert b"bundled snapshot" in client.get("/admin/threat-data").data

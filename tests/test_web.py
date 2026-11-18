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


def copy_session(src, dst):
    """Give dst the same session cookie as src, as a copied browser would have."""
    cookie = src.get_cookie("nis2check_session")
    assert cookie is not None
    dst.set_cookie(cookie.key, cookie.value)


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


def test_failed_login_email_is_truncated(app):
    from nis2check.web import auth
    from nis2check.web.models import AuditLog
    c = app.test_client()
    setup_admin(c)
    c.post("/logout")
    long_email = "a" * 500 + "@acme.sk"
    c.post("/login", data=dict(email=long_email, password="nope"))
    # the audit entry records the email capped at 254 chars, not the raw 508
    entry = db(app).query(AuditLog).filter_by(action="login.failed").one()
    assert entry.target == long_email[:254] and len(entry.target) == 254
    assert entry.actor == long_email[:254]
    # the throttle keys ("<ip>|<email>" and "account|<email>") carry the capped email too
    assert auth._failures and all(key.rsplit("|", 1)[-1] == long_email[:254] for key in auth._failures)


def test_failure_table_drops_expired_keys_and_stays_bounded(app, monkeypatch):
    from nis2check.web import auth
    monkeypatch.setattr(auth, "_MAX_FAILURE_KEYS", 3)
    clock = {"t": 1_000.0}
    monkeypatch.setattr(auth.time, "monotonic", lambda: clock["t"])
    auth._failures.clear()

    with app.test_request_context(environ_base={"REMOTE_ADDR": "10.0.0.8"}):
        # a lookup must not create a key; previously every probe left an empty deque
        for i in range(20):
            assert auth._throttled(f"ghost{i}@acme.sk") is False
        assert auth._failures == {}

        for _ in range(auth.MAX_FAILURES_PER_ACCOUNT):
            auth._record_failure("victim@acme.sk")
        assert auth._throttled("victim@acme.sk")
        locked = dict(auth._failures)

        # cap is 3: victim holds 2 keys, one more account fits, the rest are not stored
        auth._record_failure("other@acme.sk")
        auth._record_failure("third@acme.sk")
        assert len(auth._failures) <= 3
        assert "account|third@acme.sk" not in auth._failures
        # the lockout is still there, with the same attempts, after the table filled up
        assert auth._throttled("victim@acme.sk")
        assert list(auth._failures["account|victim@acme.sk"]) == list(locked["account|victim@acme.sk"])

        # once the window passes, expired keys are removed and the lockout lifts
        clock["t"] += auth.WINDOW_SECONDS + 1
        assert auth._throttled("victim@acme.sk") is False
        assert auth._failures == {}

        # a fresh failure after the sweep counts again, and does not revive the old key
        auth._record_failure("new@acme.sk")
        assert auth._recent("account|new@acme.sk") == 1
        assert "account|victim@acme.sk" not in auth._failures
        assert not auth._throttled("new@acme.sk")


def test_login_checks_password_hash_when_user_is_missing(app, monkeypatch):
    from nis2check.web import auth
    seen = []
    real = auth.check_password_hash

    def spy(stored, password):
        seen.append(stored)
        return real(stored, password)

    monkeypatch.setattr(auth, "check_password_hash", spy)
    c = app.test_client()
    setup_admin(c)
    c.post("/logout")

    seen.clear()
    missing = c.post("/login", data=dict(email="nobody@acme.sk", password="WhateverPass12"))
    assert b"Wrong email or password" in missing.data
    assert seen == [auth._DUMMY_PASSWORD_HASH]

    # a real account still checks its own hash, and the right password still signs in
    seen.clear()
    wrong = c.post("/login", data=dict(email="admin@acme.sk", password="wrong-password"))
    assert b"Wrong email or password" in wrong.data
    assert len(seen) == 1 and seen[0].startswith("scrypt:") and seen[0] != auth._DUMMY_PASSWORD_HASH
    seen.clear()
    assert login(c, "admin@acme.sk").status_code == 302
    assert len(seen) == 1 and seen[0] != auth._DUMMY_PASSWORD_HASH

    # inactive and passwordless accounts used to skip the hash check too
    c.post("/logout")
    add_user(app, "idle@acme.sk", "viewer")
    idle = db(app).query(User).filter_by(email="idle@acme.sk").one()
    idle.active = False
    db(app).add(User(email="sso@acme.sk", role="viewer"))
    db(app).commit()
    seen.clear()
    assert b"Wrong email or password" in login(c, "idle@acme.sk").data
    assert b"Wrong email or password" in login(c, "sso@acme.sk").data
    assert len(seen) == 2
    assert seen[0] != auth._DUMMY_PASSWORD_HASH  # inactive account, real hash
    assert seen[1] == auth._DUMMY_PASSWORD_HASH  # no password stored


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


def test_password_change_logs_out_other_sessions(app):
    c1, c2 = app.test_client(), app.test_client()
    setup_admin(c1)
    copy_session(c1, c2)  # a second browser holding the same session cookie
    assert c2.get("/").status_code == 200
    r = c1.post("/account/password",
                data={"current": PASSWORD, "password": "NewPassword123", "password2": "NewPassword123"})
    assert r.status_code == 302
    assert c1.get("/").status_code == 200                       # the session that changed it stays in
    assert c2.get("/").headers["Location"].startswith("/login")  # the other one is signed out


def test_logout_invalidates_copied_cookie(app):
    c = app.test_client()
    setup_admin(c)
    stolen = c.get_cookie("nis2check_session")
    assert stolen is not None
    assert c.post("/logout").status_code == 302
    replay = app.test_client()
    replay.set_cookie(stolen.key, stolen.value)
    assert replay.get("/").headers["Location"].startswith("/login")
    assert c.get("/").headers["Location"].startswith("/login")


def test_login_issues_a_fresh_session_token(app):
    c1 = app.test_client()
    setup_admin(c1)
    c1.post("/logout")
    login(c1, "admin@acme.sk")
    first = db(app).query(User).filter_by(email="admin@acme.sk").one().session_token
    stolen = c1.get_cookie("nis2check_session")
    assert stolen is not None
    c2 = app.test_client()
    login(c2, "admin@acme.sk")
    second = db(app).query(User).filter_by(email="admin@acme.sk").one().session_token
    assert first and second and first != second
    replay = app.test_client()
    replay.set_cookie(stolen.key, stolen.value)
    assert replay.get("/").headers["Location"].startswith("/login")
    assert c2.get("/").status_code == 200


def test_admin_reset_logs_out_user_sessions(app):
    ca = app.test_client()
    setup_admin(ca)
    add_user(app, "assessor@acme.sk", "assessor")
    cu = app.test_client()
    login(cu, "assessor@acme.sk")
    assert cu.get("/").status_code == 200
    uid = db(app).query(User).filter_by(email="assessor@acme.sk").one().id
    ca.post(f"/admin/users/{uid}", data={"action": "reset_password"})
    assert cu.get("/").headers["Location"].startswith("/login")  # their session is signed out


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


def test_evidence_link_scheme_validation(app, client):
    setup_admin(client)
    # http and https links are accepted and stored as evidence
    for i, url in enumerate(("http://x.example/doc", "https://x.example/doc")):
        qid = f"GOV-0{i + 1}"
        r = client.post(f"/assessment/question/{qid}", data={"answer": "yes", "link": url},
                        follow_redirects=True)
        assert b"must start with https://" not in r.data
    links = [e.url for e in db(app).query(Evidence).all()]
    assert links == ["http://x.example/doc", "https://x.example/doc"]

    # non-web schemes are rejected and never stored
    for bad in ("javascript:alert(1)", "data:text/html,<script>alert(1)</script>"):
        r = client.post("/assessment/question/GOV-03", data={"answer": "yes", "link": bad},
                        follow_redirects=True)
        assert b"must start with https://" in r.data
    assert db(app).query(Evidence).count() == 2  # only the two web links above


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

import datetime as dt

import pytest

pytest.importorskip("flask")

from nis2check.web import create_app  # noqa: E402
from nis2check.web.auth import hash_password  # noqa: E402
from nis2check.web.incident_models import Incident, IncidentReport  # noqa: E402
from nis2check.web.models import User  # noqa: E402

PASSWORD = "CorrectHorse12"
SETUP_TOKEN = "test-setup-token"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("NIS2CHECK_SETUP_TOKEN", SETUP_TOKEN)
    app = create_app(data_dir=tmp_path / "data", start_scheduler=False)
    app.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def _admin(client):
    client.post("/setup", data=dict(
        org_name="Acme", name="Admin", email="admin@acme.sk", password=PASSWORD, password2=PASSWORD,
        token=SETUP_TOKEN,
    ))


def _incident(client, detected="2026-01-31T10:00", title="Pump failure"):
    return client.post("/incidents/new", data={
        "title": title, "detected_at": detected, "summary": "Water treatment stopped",
        "time_is_utc": "1",
    })


def test_deadlines_render_in_utc_and_the_final_report_crosses_the_month_boundary(app, client):
    _admin(client)
    response = _incident(client)
    assert response.status_code == 302
    page = client.get(response.headers["Location"]).data.decode()
    assert 'data-utc="2026-02-01T10:00:00Z"' in page  # 24 hours
    assert 'data-utc="2026-02-03T10:00:00Z"' in page  # 72 hours
    assert 'data-utc="2026-03-03T10:00:00Z"' in page  # provisional final, one month after 72 hours
    assert "Overdue" in page
    assert "Intermediate report" in page
    assert "Progress report" in page
    assert "not legal advice" in page.lower()

    client.post("/incidents/1/reports", data={
        "stage": "notification",
        "submitted_at": "2026-01-31T18:00",
        "time_is_utc": "1",
        "suspected_unlawful": "yes",
        "cross_border": "unknown",
        "severity_impact": "Pumps offline in one city",
        "indicators": "none yet",
    })
    updated = client.get("/incidents/1").data.decode()
    # 31 January 18:00 plus one month is 28 February 18:00, not one month after detection.
    assert 'data-utc="2026-02-28T18:00:00Z"' in updated
    assert "Submitted on time" in updated

    stored = app.extensions["nis2_db"]().get(Incident, 1)
    assert stored.detected_at == dt.datetime(2026, 1, 31, 10, 0)
    assert stored.detected_at.tzinfo is None


def test_each_stage_exports_markdown_and_pdf(app):
    client = app.test_client()
    _admin(client)
    _incident(client)
    client.post("/incidents/1/reports", data={
        "stage": "early_warning", "time_is_utc": "1",
        "submitted_at": "2026-01-31T12:00",
        "suspected_unlawful": "yes", "cross_border": "no",
    })
    client.post("/incidents/1/reports", data={
        "stage": "final", "time_is_utc": "1",
        "severity_impact": "One city without water",
        "root_cause": "Failed remote access",
        "mitigation": "Isolated the link",
        "cross_border": "no",
        "ongoing": "on",
    })
    client.post("/incidents/1/reports", data={
        "stage": "intermediate", "time_is_utc": "1", "body": "Pumps restarting",
    })
    client.post("/incidents/1/reports", data={
        "stage": "progress", "time_is_utc": "1",
        "body": "Still restoring the second line",
        "handling_completed_at": "2026-03-31T09:00",
    })
    page = client.get("/incidents/1").data.decode()
    assert "Progress report" in page
    assert 'data-utc="2026-04-30T09:00:00Z"' in page  # one month after 31 March

    db = app.extensions["nis2_db"]()
    rows = list(db.query(IncidentReport))
    early = next(row for row in rows if row.stage == "early_warning")
    markdown = client.get(f"/incidents/1/reports/{early.id}.md")
    assert markdown.status_code == 200
    assert b"Suspected unlawful or malicious cause: Yes" in markdown.data
    pdf = client.get(f"/incidents/1/reports/{early.id}.pdf")
    assert pdf.data.startswith(b"%PDF")
    assert b"Early warning" in pdf.data
    assert b"unlawful" in pdf.data

    final = next(row for row in rows if row.stage == "final")
    final_pdf = client.get(f"/incidents/1/reports/{final.id}.pdf").data
    assert b"Failed remote access" in final_pdf
    assert b"Isolated the link" in final_pdf


def test_viewer_can_export_but_not_record(app):
    client = app.test_client()
    _admin(client)
    _incident(client)
    client.post("/incidents/1/reports", data={
        "stage": "early_warning", "time_is_utc": "1", "suspected_unlawful": "yes", "cross_border": "no",
    })
    client.post("/logout")
    db = app.extensions["nis2_db"]()
    db.add(User(email="viewer@acme.sk", role="viewer", password_hash=hash_password(PASSWORD)))
    db.commit()
    client.post("/login", data={"email": "viewer@acme.sk", "password": PASSWORD})
    assert client.get("/incidents").status_code == 200
    assert b"Incidents" in client.get("/").data
    report = db.query(IncidentReport).one()
    assert client.get(f"/incidents/1/reports/{report.id}.md").status_code == 200
    assert client.post("/incidents/new", data={"title": "Nope", "detected_at": "2026-02-01T00:00", "time_is_utc": "1"}).status_code == 403
    assert client.post("/incidents/1/reports", data={"stage": "final", "time_is_utc": "1"}).status_code == 403


def test_anonymous_incidents_go_to_sign_in(client):
    response = client.get("/incidents")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

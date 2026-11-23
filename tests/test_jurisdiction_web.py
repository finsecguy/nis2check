"""Web: country selection, national questions, dual citations, clocks and deadlines."""

import pytest

pytest.importorskip("flask")

from nis2check.web import create_app  # noqa: E402

PASSWORD = "CorrectHorse12"


@pytest.fixture
def app(tmp_path):
    app = create_app(data_dir=tmp_path / "data", start_scheduler=False)
    app.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def _admin(client):
    client.post("/setup", data=dict(
        org_name="Acme", name="Admin", email="admin@acme.sk", password=PASSWORD, password2=PASSWORD,
    ))


def _country(client, code):
    return client.post("/organisation", data={"name": "Acme", "country": code, "frameworks": "nis2"})


def test_country_change_adds_the_national_domain(client):
    _admin(client)
    before = client.get("/assessment").data.decode()
    assert "National requirements" not in before
    saved = _country(client, "sk")
    assert saved.status_code == 302
    page = client.get("/assessment").data.decode()
    assert "National requirements (SK)" in page
    assert "sk-reg-01" in client.get("/assessment/NAT-SK").data.decode()


def test_report_shows_dual_citation_and_unverified_marker(client):
    _admin(client)
    _country(client, "cz")
    html = client.get("/report/view").data.decode()
    assert "Assessed against:" in html
    assert "264/2025" in html
    assert "NIS2 Art. 21(2)(a)" in html
    assert "unverified" in html


def test_incident_page_names_the_national_authority(client):
    _admin(client)
    _country(client, "sk")
    created = client.post("/incidents/new", data={
        "title": "Outage", "detected_at": "2026-04-01T08:00", "summary": "Link down",
        "time_is_utc": "1",
    })
    page = client.get(created.headers["Location"]).data.decode()
    assert "Národný bezpečnostný úrad" in page
    assert "SK-CERT" in page
    assert "https://jiskb.nbu.gov.sk/" in page
    exported = client.post("/incidents/1/reports", data={
        "stage": "early_warning", "time_is_utc": "1",
        "submitted_at": "2026-04-01T09:00",
        "suspected_unlawful": "unknown", "cross_border": "no",
    })
    assert exported.status_code == 302
    markdown = client.get("/incidents/1/reports/1.md").data.decode()
    assert "Národný bezpečnostný úrad" in markdown
    assert "https://jiskb.nbu.gov.sk/" in markdown


def test_polish_dashboard_shows_the_april_2027_deadline(client):
    _admin(client)
    _country(client, "pl")
    page = client.get("/").data.decode()
    assert "3 Apr 2027" in page
    assert "National requirements (PL)" in client.get("/assessment").data.decode()


def test_hungarian_report_says_the_auditor_must_do_the_audit(client):
    _admin(client)
    _country(client, "hu")
    client.post("/language", data={"language": "en"})
    html = client.get("/report/view").data.decode()
    assert "Assessed against:" in html
    assert "SZTFH" in html
    assert "preparation material only" in html
    assert "unverified" in html
    assert "National requirements (HU)" in client.get("/assessment").data.decode()


def test_scope_wizard_shows_the_national_term(client):
    _admin(client)
    _country(client, "pl")
    page = client.post("/scope", data={
        "subsector_id": "electricity",
        "employees": "300",
        "annual_turnover_eur": "60000000",
        "balance_sheet_eur": "50000000",
    }).data.decode()
    assert "Essential entity / podmiot kluczowy" in page

import pytest

pytest.importorskip("flask")

from nis2check.web import create_app  # noqa: E402
from nis2check.web.services import organisation  # noqa: E402

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


def _setup(client):
    client.post("/setup", data=dict(
        org_name="Acme", name="Admin", email="admin@acme.sk", password=PASSWORD, password2=PASSWORD,
        token=SETUP_TOKEN,
    ))


def test_scope_page_is_public(client):
    page = client.get("/scope")
    assert page.status_code == 200
    body = page.data.decode()
    assert "not legal advice" in body.lower()
    assert "National transposition" in body
    assert "Annex I" in body
    assert "DNS service provider" in body


def test_sign_in_page_links_to_the_wizard(client):
    _setup(client)
    client.post("/logout")
    login = client.get("/login")
    assert login.status_code == 200
    assert b"/scope" in login.data


def test_wizard_reports_essential_important_and_out_of_scope(client):
    essential = client.post("/scope", data={"subsector_id": "electricity", "employees": "300"}).data.decode()
    assert "Essential entity" in essential
    assert "Art. 3(1)(a)" in essential

    important = client.post("/scope", data={"subsector_id": "food_business", "employees": "1000"}).data.decode()
    assert "Important entity" in important

    out = client.post("/scope", data={"subsector_id": "healthcare_providers", "employees": "12"}).data.decode()
    assert "Out of scope" in out

    missing = client.post("/scope", data={"subsector_id": "electricity"}).data.decode()
    assert "Not enough information" in missing


def test_small_dns_provider_is_essential_on_the_page(client):
    body = client.post("/scope", data={"employees": "3", "special": "dns_provider"}).data.decode()
    assert "Essential entity" in body
    assert "Art. 3(1)(b)" in body


def test_boundaries_on_the_page(client):
    at_ceiling = client.post("/scope", data={
        "subsector_id": "electricity", "employees": "249",
        "annual_turnover_eur": "50000000", "balance_sheet_eur": "43000000",
    }).data.decode()
    over = client.post("/scope", data={
        "subsector_id": "electricity", "employees": "249",
        "annual_turnover_eur": "50000000.01", "balance_sheet_eur": "43000000.01",
    }).data.decode()
    assert "Important entity" in at_ceiling
    assert "Essential entity" in over


def test_admin_can_start_an_assessment_from_the_result(app):
    client = app.test_client()
    _setup(client)
    client.post("/scope", data={"subsector_id": "dns", "employees": "3"})
    response = client.post("/scope/apply")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/assessment")
    org = organisation(app.extensions["nis2_db"]())
    assert org.sector == "digital_infrastructure"
    assert org.employees == 3
    assert org.size_exempt is True
    assert client.get("/assessment").status_code == 200


def test_result_survives_sign_in(app):
    anon = app.test_client()
    anon.post("/scope", data={"subsector_id": "electricity", "employees": "300"})
    _setup(anon)  # setup signs the new admin in and must keep the wizard answers
    kept = anon.get("/scope").data.decode()
    assert "Essential entity" in kept
    assert anon.post("/scope/apply").status_code == 302


def test_viewer_cannot_apply_the_result(app):
    from nis2check.web.auth import hash_password
    from nis2check.web.models import User
    client = app.test_client()
    _setup(client)
    client.post("/logout")
    db = app.extensions["nis2_db"]()
    db.add(User(email="viewer@acme.sk", role="viewer", password_hash=hash_password(PASSWORD)))
    db.commit()
    client.post("/login", data={"email": "viewer@acme.sk", "password": PASSWORD})
    client.post("/scope", data={"subsector_id": "electricity", "employees": "300"})
    assert client.post("/scope/apply").status_code == 403


def test_anonymous_apply_goes_to_sign_in(client):
    response = client.post("/scope/apply")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_signed_in_nav_links_to_scope(app):
    client = app.test_client()
    _setup(client)
    assert b"Scope" in client.get("/").data


@pytest.mark.parametrize(
    "payload, label",
    [
        ({"subsector_id": "dns", "employees": "80"}, "Essential entity"),
        ({"subsector_id": "electricity", "employees": "300"}, "Essential entity"),
        ({"subsector_id": "food_business", "employees": "1000"}, "Important entity"),
        ({"subsector_id": "healthcare_providers", "employees": "12"}, "Out of scope"),
        ({"subsector_id": "public_communications_networks", "employees": "80"}, "Essential entity"),
        ({"subsector_id": "trust_services", "employees": "4"}, "Important entity"),
    ],
)
def test_organisation_page_agrees_with_the_wizard(app, payload, label):
    client = app.test_client()
    _setup(client)
    wizard = client.post("/scope", data=payload).data.decode()
    assert label in wizard
    started = client.post("/scope/apply", follow_redirects=True)
    assert started.status_code == 200
    assert b"shorter" not in started.data
    organisation = client.get("/organisation").data.decode()
    assert label in organisation
    assert label in client.get("/scope").data.decode()
    assert "shorter size-cap" not in organisation


def test_organisation_form_uses_the_wizard_rules(app):
    client = app.test_client()
    _setup(client)
    saved = client.post("/organisation", data={
        "name": "Acme", "subsector_id": "dns", "employees": "80", "frameworks": "nis2",
    })
    assert saved.status_code == 302
    organisation = client.get("/organisation").data.decode()
    wizard = client.post("/scope", data={"subsector_id": "dns", "employees": "80"}).data.decode()
    assert "Essential entity" in organisation
    assert "Essential entity" in wizard
    org = organisation_db(app)
    assert org.subsector_id == "dns"
    assert org.sector == "digital_infrastructure"


def organisation_db(app):
    from nis2check.web.services import organisation
    return organisation(app.extensions["nis2_db"]())

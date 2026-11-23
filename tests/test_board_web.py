import datetime as dt

import pytest

pytest.importorskip("flask")
pytest.importorskip("fpdf")

from nis2check.web import create_app  # noqa: E402
from nis2check.web.auth import hash_password  # noqa: E402
from nis2check.web.board_models import GapAction  # noqa: E402
from nis2check.web.models import Response, Snapshot, User  # noqa: E402

PASSWORD = "CorrectHorse12"
SETUP_TOKEN = "test-setup-token"


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("NIS2CHECK_SETUP_TOKEN", SETUP_TOKEN)
    app = create_app(data_dir=tmp_path / "data", start_scheduler=False)
    app.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    return app


def _admin(client):
    client.post("/setup", data=dict(
        org_name="Acme", name="Admin", email="admin@acme.sk", password=PASSWORD, password2=PASSWORD,
        token=SETUP_TOKEN,
    ))


def _one_gap(app):
    db = app.extensions["nis2_db"]()
    catalogue = app.extensions["nis2_catalogue"]
    for qid in catalogue.question_ids:
        db.add(Response(question_id=qid, answer="no" if qid == "GOV-01" else "yes"))
    db.add(Snapshot(
        taken_at=dt.datetime(2026, 10, 1, 9, 0), score_pct=40.0, verified_pct=10.0,
        open_items=20, detail_json="{}",
    ))
    db.commit()


def test_board_page_and_pdf_include_score_owner_trend_and_article_20(app):
    client = app.test_client()
    _admin(client)
    _one_gap(app)
    page = client.get("/board")
    assert page.status_code == 200
    body = page.data.decode()
    assert "GOV-01" in body
    assert "Article 20" in body
    assert "01 Oct 2026" in body
    assert "Board report" in body

    saved = client.post("/board/gaps", data={
        "question_id": "GOV-01",
        "owner_GOV-01": "Ada Lovelace",
        "due_GOV-01": "2026-12-01",
    })
    assert saved.status_code == 302
    action = app.extensions["nis2_db"]().get(GapAction, "GOV-01")
    assert action.owner == "Ada Lovelace"
    assert action.due_on == dt.date(2026, 12, 1)

    pdf = client.get("/board/report.pdf")
    assert pdf.status_code == 200
    assert pdf.mimetype == "application/pdf"
    assert pdf.data.startswith(b"%PDF")
    assert b"/Count 1" in pdf.data
    assert b"Acme" in pdf.data
    assert b"GOV-01" in pdf.data
    assert b"Ada Lovelace" in pdf.data
    assert b"01 Dec 2026" in pdf.data
    assert b"Article 20" in pdf.data
    assert b"40%" in pdf.data


def test_viewer_can_download_but_not_edit_owners(app):
    client = app.test_client()
    _admin(client)
    client.post("/logout")
    db = app.extensions["nis2_db"]()
    db.add(User(email="viewer@acme.sk", role="viewer", password_hash=hash_password(PASSWORD)))
    db.commit()
    client.post("/login", data={"email": "viewer@acme.sk", "password": PASSWORD})
    assert b"Board report" in client.get("/").data
    assert client.get("/board/report.pdf").status_code == 200
    assert client.post("/board/gaps", data={"question_id": "GOV-01", "owner_GOV-01": "Ada"}).status_code == 403


def test_anonymous_board_page_goes_to_sign_in(app):
    response = app.test_client().get("/board")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

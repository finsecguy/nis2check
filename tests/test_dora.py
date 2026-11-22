"""DORA catalogue, shared scoring, and the CISO Assistant export."""

import csv
import io
import re
import zipfile
from pathlib import Path

import pytest
import yaml

from nis2check.assessment import AssessmentError, new_assessment, parse_assessment
from nis2check.ciso import (
    FRAMEWORK_NAMES, export_zip, render_assessment_csv, render_library_yaml,
)
from nis2check.cli import main
from nis2check.controls import load_catalogue
from nis2check.frameworks import (
    LEX_SPECIALIS, load_bundled_catalogue, parse_frameworks,
)
from nis2check.report import render_html
from nis2check.scoring import evaluate
from nis2check.threat.data import load_threat_data
from nis2check.weighting import compute_weights

NIS2 = load_catalogue()
DORA = load_bundled_catalogue(("dora",))
BOTH = load_bundled_catalogue(("nis2", "dora"))


def _articles(catalogue):
    mentioned = set()
    for question in catalogue.questions():
        for start, end in re.findall(r"(\d+)(?:-(\d+))?", question.article):
            mentioned.update(range(int(start), int(end or start) + 1))
    return mentioned


def _answered(catalogue, value, evidence=None):
    return {
        qid: {"answer": value, "evidence": evidence or []}
        for qid in catalogue.question_ids
    }


def test_dora_catalogue_covers_the_five_pillars():
    assert [d.id for d in DORA.domains] == ["DIRM", "DIIM", "DDOT", "DTPR", "DISH"]
    assert {d.framework for d in DORA.domains} == {"dora"}
    assert {d.framework for d in NIS2.domains} == {"nis2"}
    assert set(range(5, 46)) <= _articles(DORA)
    assert "Regulation (EU) 2022/2554" in DORA.source


def test_question_ids_fit_the_answer_table_and_do_not_collide():
    ids = DORA.question_ids
    assert len(ids) == len(set(ids)) == 27
    assert all(len(qid) <= 20 for qid in ids)
    assert set(ids).isdisjoint(NIS2.question_ids)
    for question in DORA.questions():
        assert question.text.endswith("?")
        assert len(question.text) < 300
        assert question.article.startswith("Art. ")


def test_dora_mitigations_exist_in_threat_data():
    known = set(load_threat_data().raw["attack_mitigation_names"])
    used = {m for q in DORA.questions() for m in q.attack_mitigations}
    assert used
    assert used <= known


def test_dora_scores_with_the_same_rules(tmp_path):
    empty = evaluate(DORA, parse_assessment({"responses": {}}, DORA, tmp_path))
    assert empty.score_pct == 0
    assert empty.counts["unanswered"] == len(DORA.question_ids)

    yes = evaluate(DORA, parse_assessment(
        {"responses": _answered(DORA, "yes", ["https://example.com/doc"])}, DORA, tmp_path))
    assert yes.score_pct == 100
    assert yes.verified_pct == 100
    assert yes.gaps == []

    partial = evaluate(DORA, parse_assessment(
        {"responses": _answered(DORA, "partial", ["https://example.com/doc"])}, DORA, tmp_path))
    assert partial.score_pct == 50

    only = _answered(DORA, "na")
    only["DIRM-01"] = {"answer": "yes", "evidence": ["https://example.com/doc"]}
    na = evaluate(DORA, parse_assessment({"responses": only}, DORA, tmp_path))
    assert na.score_pct == 100
    assert na.domains[0].score_pct == 100


def test_selecting_one_framework_does_not_score_the_other(tmp_path):
    responses = _answered(DORA, "yes", ["https://example.com/doc"])
    dora_only = evaluate(DORA, parse_assessment({"responses": responses}, DORA, tmp_path))
    assert dora_only.score_pct == 100
    # the same DORA answers inside a joint catalogue leave the NIS2 questions open
    joint = evaluate(BOTH, parse_assessment({"responses": responses, "frameworks": ["nis2", "dora"]}, BOTH, tmp_path))
    assert joint.score_pct < 100
    assert joint.counts["unanswered"] == len(NIS2.question_ids)
    assert "dora" in {d.domain.framework for d in joint.domains}
    assert "nis2" in {d.domain.framework for d in joint.domains}


def test_threat_weights_raise_a_linked_dora_control_only():
    weights = compute_weights(DORA, load_threat_data(), "threat")
    assert weights["DIRM-01"].weight == 3  # no threat link, baseline stays
    assert weights["DIRM-06"].weight > weights["DIRM-06"].base  # backups, via ATT&CK


def test_unknown_framework_is_rejected():
    with pytest.raises(ValueError, match="unknown framework"):
        parse_frameworks("iso")
    with pytest.raises(ValueError, match="at least one"):
        parse_frameworks([], default=None)
    assert parse_frameworks("dora, nis2") == ("nis2", "dora")
    assert parse_frameworks(None) == ("nis2",)


def test_parse_assessment_rejects_an_unknown_framework(tmp_path):
    with pytest.raises(AssessmentError, match="unknown framework"):
        parse_assessment({"frameworks": ["iso"], "responses": {}}, NIS2, tmp_path)


def test_lex_specialis_is_in_the_dora_report_only(tmp_path):
    nis2 = evaluate(NIS2, new_assessment(NIS2, name="Acme"))
    html = render_html(nis2, new_assessment(NIS2, name="Acme"), NIS2)
    assert "lex specialis" not in html
    assert "Articles 20, 21 and 23 of Directive (EU) 2022/2555." in html

    dora_assessment = new_assessment(DORA, name="Bank")
    dora = evaluate(DORA, dora_assessment)
    html = render_html(dora, dora_assessment, DORA)
    assert LEX_SPECIALIS in html
    assert "does not decide whether DORA applies" in html
    assert "Art. 5" in html

    both_assessment = new_assessment(BOTH, name="Bank")
    both = evaluate(BOTH, both_assessment)
    html = render_html(both, both_assessment, BOTH)
    assert "NIS2 and DORA gap assessment" in html
    assert LEX_SPECIALIS in html


def test_ciso_library_and_csv_carry_the_answers(tmp_path):
    responses = {
        "DIRM-01": {"answer": "yes", "evidence": ["https://example.com/minutes"], "notes": "Approved in March"},
        "DIRM-02": {"answer": "partial", "notes": "Training booked"},
        "DIRM-03": {"answer": "no"},
        "DIIM-06": {"answer": "na", "notes": "No payment services"},
    }
    assessment = parse_assessment({"responses": responses, "frameworks": ["dora"]}, DORA, tmp_path)
    result = evaluate(DORA, assessment)

    library = yaml.safe_load(render_library_yaml(DORA, "dora"))
    assert library["urn"] == "urn:intuitem:risk:library:nis2check-dora"
    framework = library["objects"]["framework"]
    assert framework["name"] == FRAMEWORK_NAMES["dora"]
    assert framework["min_score"] == 0 and framework["max_score"] == 100
    nodes = framework["requirement_nodes"]
    sections = [n for n in nodes if not n["assessable"]]
    questions = [n for n in nodes if n["assessable"]]
    assert [n["ref_id"] for n in sections] == ["DIRM", "DIIM", "DDOT", "DTPR", "DISH"]
    assert len(questions) == 27
    assert questions[0]["depth"] == 2
    assert questions[0]["parent_urn"].endswith(":dirm")
    assert questions[0]["importance"] == "mandatory"
    assert questions[0]["weight"] == 3

    rows = list(csv.DictReader(io.StringIO(render_assessment_csv(result, "dora"))))
    assert list(rows[0]) == [
        "urn", "assessable", "ref_id", "name", "description", "compliance_result",
        "requirement_progress", "score", "observations",
    ]
    by_ref = {row["ref_id"]: row for row in rows}
    assert by_ref["DIRM-01"]["compliance_result"] == "compliant"
    assert by_ref["DIRM-01"]["score"] == "100"
    assert by_ref["DIRM-01"]["assessable"] == "x"
    assert "Approved in March" in by_ref["DIRM-01"]["observations"]
    assert "https://example.com/minutes" in by_ref["DIRM-01"]["observations"]
    assert by_ref["DIRM-02"]["compliance_result"] == "partially_compliant"
    assert by_ref["DIRM-02"]["score"] == "50"
    assert by_ref["DIRM-03"]["compliance_result"] == "non_compliant"
    assert by_ref["DIRM-03"]["score"] == "0"
    assert by_ref["DIIM-06"]["compliance_result"] == "not_applicable"
    assert by_ref["DIIM-06"]["score"] == ""
    unanswered = by_ref["DISH-01"]
    assert unanswered["compliance_result"] == "not_assessed"
    assert unanswered["score"] == ""
    assert not render_assessment_csv(result, "dora").startswith("\ufeff")


def test_ciso_zip_contains_one_pair_per_selected_framework(tmp_path):
    dora = evaluate(DORA, new_assessment(DORA))
    blob = export_zip(dora, DORA)
    names = set(zipfile.ZipFile(io.BytesIO(blob)).namelist())
    assert names == {"IMPORT.txt", "dora-library.yaml", "dora-compliance-assessment.csv"}
    note = zipfile.ZipFile(io.BytesIO(blob)).read("IMPORT.txt").decode()
    assert "import-compliance-assessments" in note
    assert FRAMEWORK_NAMES["dora"] in note
    assert "intuitem" in note

    both = evaluate(BOTH, new_assessment(BOTH))
    names = set(zipfile.ZipFile(io.BytesIO(export_zip(both, BOTH))).namelist())
    assert "nis2-library.yaml" in names and "dora-compliance-assessment.csv" in names


def test_cli_init_and_export_follow_the_framework_flag(tmp_path):
    out = tmp_path / "dora.yaml"
    assert main(["init", "--frameworks", "dora", "-o", str(out), "--name", "Bank"]) == 0
    data = yaml.safe_load(out.read_text())
    assert data["frameworks"] == ["dora"]
    assert "DIRM-01" in data["responses"]
    assert "GOV-01" not in data["responses"]

    archive = tmp_path / "ciso.zip"
    html = tmp_path / "r.html"
    assert main(["report", str(out), "-o", str(html), "--ciso", str(archive), "-q"]) == 0
    assert "DORA gap assessment" in html.read_text()
    assert "dora-library.yaml" in zipfile.ZipFile(archive).namelist()

    assert main(["init", "--frameworks", "nope", "-o", str(tmp_path / "x.yaml")]) == 1
    assert main(["controls", "--frameworks", "dora"]) == 0


# ------------------------------------------------------------------ web

pytest.importorskip("flask")

from nis2check.web import create_app  # noqa: E402
from nis2check.web.models import Response  # noqa: E402


@pytest.fixture
def app(tmp_path):
    application = create_app(data_dir=tmp_path / "data", start_scheduler=False)
    application.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def _admin(client):
    client.post("/setup", data=dict(
        org_name="Acme", name="Admin", email="admin@acme.sk",
        password="CorrectHorse12", password2="CorrectHorse12",
    ))


def _save_org(client, *frameworks, name="Acme"):
    return client.post("/organisation", data={"name": name, "frameworks": list(frameworks)},
                       follow_redirects=True)


def test_web_defaults_to_nis2_and_can_switch(client):
    _admin(client)
    page = client.get("/assessment").data
    assert b"Governance and management accountability" in page
    assert b"ICT risk management" not in page
    assert b"lex specialis" not in page

    saved = _save_org(client, "dora")
    assert b"Organisation details saved" in saved.data
    page = client.get("/assessment").data
    assert b"ICT risk management" in page
    assert b"Governance and management accountability" not in page
    assert b"lex specialis" in page
    assert client.get("/assessment/GOV").status_code == 404
    domain = client.get("/assessment/DIRM").data
    assert b"DIRM-01" in domain and b"Art. 5" in domain

    _save_org(client, "nis2", "dora")
    page = client.get("/assessment").data
    assert b"ICT risk management" in page
    assert b"Governance and management accountability" in page


def test_web_rejects_an_empty_framework_selection(client):
    _admin(client)
    page = _save_org(client)
    assert b"Select at least one framework" in page.data
    assert b"Governance and management accountability" in client.get("/assessment").data


def test_web_keeps_answers_when_a_framework_is_hidden(app, client):
    _admin(client)
    client.post("/assessment/question/GOV-01", data={"answer": "yes", "notes": "Kept"})
    _save_org(client, "dora")
    _save_org(client, "nis2")
    page = client.get("/assessment/GOV").data
    assert b"Kept" in page
    row = app.extensions["nis2_db"]().get(Response, "GOV-01")
    assert row.answer == "yes"


def test_yaml_import_keeps_dora_answers_until_that_framework_is_selected(app, client, tmp_path):
    from nis2check.web.manage import import_yaml
    path = tmp_path / "dora.yaml"
    path.write_text(
        "frameworks: [dora]\nresponses:\n  DIRM-01:\n    answer: yes\n    notes: Imported\n"
    )
    assert import_yaml(app, path)["answers"] == 1
    _admin(client)
    assert b"ICT risk management" not in client.get("/assessment").data
    _save_org(client, "dora")
    assert b"Imported" in client.get("/assessment/DIRM").data


def test_web_ciso_download_matches_the_selection(client):
    _admin(client)
    client.post("/assessment/question/GOV-01", data={"answer": "yes", "notes": "Board"})
    packed = client.get("/report/download.ciso")
    assert packed.status_code == 200
    assert packed.mimetype == "application/zip"
    archive = zipfile.ZipFile(io.BytesIO(packed.data))
    assert "nis2-library.yaml" in archive.namelist()
    assert "dora-library.yaml" not in archive.namelist()
    text = archive.read("nis2-compliance-assessment.csv").decode()
    rows = list(csv.DictReader(io.StringIO(text)))
    gov = next(row for row in rows if row["ref_id"] == "GOV-01")
    assert gov["compliance_result"] == "compliant"
    assert "Board" in gov["observations"]

    _save_org(client, "nis2", "dora")
    names = set(zipfile.ZipFile(io.BytesIO(client.get("/report/download.ciso").data)).namelist())
    assert "dora-library.yaml" in names and "nis2-compliance-assessment.csv" in names

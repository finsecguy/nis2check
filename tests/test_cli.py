import json
from pathlib import Path

import yaml

from nis2check.assessment import load_assessment
from nis2check.cli import main
from nis2check.controls import load_catalogue

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "acme-assessment.yaml"


def test_init_creates_valid_template(tmp_path):
    out = tmp_path / "a.yaml"
    assert main(["init", "-o", str(out), "--name", "Test Co"]) == 0
    data = yaml.safe_load(out.read_text())
    assert data["entity"]["name"] == "Test Co"
    assert set(data["responses"]) == set(load_catalogue().question_ids)


def test_init_refuses_overwrite(tmp_path):
    out = tmp_path / "a.yaml"
    out.write_text("x")
    assert main(["init", "-o", str(out)]) == 1


def test_report_on_example_writes_html_and_json(tmp_path):
    html = tmp_path / "r.html"
    js = tmp_path / "r.json"
    assert main(["report", str(EXAMPLE), "-o", str(html), "--json", str(js), "-q"]) == 0
    assert "Acme Logistics" in html.read_text()
    data = json.loads(js.read_text())
    assert data["applicability"]["classification"] == "important"
    assert 0 < data["summary"]["score_pct"] < 100
    assert data["gaps"][0]["priority"] == "critical"


def test_fail_under(tmp_path):
    html = tmp_path / "r.html"
    assert main(["report", str(EXAMPLE), "-o", str(html), "-q", "--fail-under", "99"]) == 2
    assert main(["report", str(EXAMPLE), "-o", str(html), "-q", "--fail-under", "10"]) == 0


def test_interview_saves_answers(tmp_path, monkeypatch):
    path = tmp_path / "a.yaml"
    main(["init", "-o", str(path), "--name", "Co"])
    inputs = iter(["y", "evidence.md", "note one", "n", "", "q"])
    monkeypatch.setattr("builtins.input", lambda _: next(inputs))
    assert main(["interview", str(path)]) == 0
    a = load_assessment(path, load_catalogue())
    assert a.responses["GOV-01"].answer == "yes"
    assert a.responses["GOV-01"].evidence == ["evidence.md"]
    assert a.responses["GOV-01"].notes == "note one"
    assert a.responses["GOV-02"].answer == "no"
    assert a.responses["GOV-03"].answer is None


def test_round_trip_preserves_example(tmp_path):
    from nis2check.assessment import render_assessment
    cat = load_catalogue()
    original = load_assessment(EXAMPLE, cat)
    copy = tmp_path / "copy.yaml"
    copy.write_text(render_assessment(original, cat))
    again = load_assessment(copy, cat)
    assert again.entity == original.entity
    assert {k: (r.answer, r.evidence, r.notes) for k, r in again.responses.items()} == {
        k: (r.answer, r.evidence, r.notes) for k, r in original.responses.items()
    }


def test_version_comes_from_the_package_metadata():
    import tomllib
    from pathlib import Path

    from nis2check import __version__

    pyproject = tomllib.loads((Path(__file__).resolve().parent.parent / "pyproject.toml").read_text("utf-8"))
    assert __version__ == pyproject["project"]["version"]

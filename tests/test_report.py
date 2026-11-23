import csv
import io
from pathlib import Path

import pytest

from nis2check.assessment import load_assessment, parse_assessment
from nis2check.cli import main
from nis2check.controls import load_catalogue
from nis2check.jurisdictions import get_jurisdiction, with_national
from nis2check.report import (
    CSV_COLUMNS, NOT_LEGAL_ADVICE, executive_summary, fonts_css_uri, heat_map, render_csv, render_html,
)
from nis2check.sk_export import render_sk_self_assessment
from nis2check.scoring import evaluate

CATALOGUE = load_catalogue()
EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "acme-assessment.yaml"


@pytest.fixture
def example():
    assessment = load_assessment(EXAMPLE, CATALOGUE)
    return evaluate(CATALOGUE, assessment), assessment


def test_csv_gap_register(example):
    result, _ = example
    text = render_csv(result)
    assert text.startswith("﻿")  # BOM for Excel
    rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
    assert list(rows[0]) == CSV_COLUMNS
    assert len(rows) == len(result.gaps)
    assert rows[0]["Rank"] == "1"
    assert rows[0]["Priority"] == "Critical"
    assert all(r["Owner"] == "" for r in rows)


def test_heat_map_counts_add_up(example):
    result, _ = example
    total = sum(cell["count"] for row in heat_map(result) for cell in row["cells"])
    assert total == len(result.findings) - result.counts["na"]


def test_heat_map_colours():
    result = evaluate(CATALOGUE, parse_assessment({}, CATALOGUE, Path(".")))
    rows = {r["label"]: [c["colour"] for c in r["cells"]] for r in heat_map(result)}
    assert rows["Critical"] == ["red", "red", "amber", "green"]
    assert rows["Medium"] == ["amber", "amber", "yellow", "green"]


def test_summary_escapes_user_input(tmp_path):
    data = {"entity": {"name": "<script>alert(1)</script>", "sector": "energy", "employees": 400}}
    a = parse_assessment(data, CATALOGUE, tmp_path)
    paras = executive_summary(evaluate(CATALOGUE, a), a)
    assert "<script>" not in paras[0]
    assert "&lt;script&gt;" in paras[0]
    assert "<b>essential entity</b>" in paras[0]


def test_html_has_download_controls_and_sections(example):
    result, assessment = example
    html = render_html(result, assessment, CATALOGUE)
    for text in ("Download PDF", "Download gap register (CSV)", "1. Executive summary",
                 "3.2 Control heat map", "4. Remediation plan", "Appendix B. Methodology",
                 "Transport"):
        assert text in html
    assert f'<footer class="report-foot">{NOT_LEGAL_ADVICE}</footer>' in html


def test_sk_report_keeps_the_directive_article_20_duty(example):
    result, assessment = example
    assessment.country = "sk"
    html = render_html(result, assessment, CATALOGUE)
    assert "Art. 20(1) and (2)" in html
    assert "requires the management body to approve and oversee the measures and to follow training" in html
    paper = render_sk_self_assessment(
        result, assessment, with_national(CATALOGUE, get_jurisdiction("sk")), get_jurisdiction("sk"),
    )
    assert "Art. 20(1) and (2)" in paper


def test_sk_self_assessment_repeats_the_footer(example):
    result, assessment = example
    assessment.country = "sk"
    catalogue = with_national(CATALOGUE, get_jurisdiction("sk"))
    html = render_sk_self_assessment(result, assessment, catalogue, get_jurisdiction("sk"))
    assert f"<footer>{NOT_LEGAL_ADVICE}</footer>" in html


def test_cli_writes_csv(tmp_path):
    out = tmp_path / "gaps.csv"
    assert main(["report", str(EXAMPLE), "-o", str(tmp_path / "r.html"), "--csv", str(out), "-q"]) == 0
    assert "REP-02" in out.read_text("utf-8-sig")


def test_cli_writes_pdf(tmp_path):
    pytest.importorskip("weasyprint")
    out = tmp_path / "r.pdf"
    assert main(["report", str(EXAMPLE), "-o", str(tmp_path / "r.html"), "--pdf", str(out), "-q"]) == 0
    assert out.read_bytes().startswith(b"%PDF")
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert NOT_LEGAL_ADVICE in html


NATIONAL_TEXT = "Pôsobnosť Prehľad Článok spĺňa ťľžňčřůőűąęłśź ŘŽŐŰĄŁ 4 SDLC"


def test_pdf_fonts_cover_national_letters():
    fontTools = pytest.importorskip("fontTools.ttLib")
    css_path = Path(fonts_css_uri().removeprefix("file://"))
    css = css_path.read_text(encoding="utf-8")
    # One face per weight: WeasyPrint garbles glyphs when a family is split by unicode-range.
    assert "unicode-range" not in css
    files = [line.split('url("')[1].split('"')[0] for line in css.splitlines() if 'url("' in line]
    assert len(files) == 4
    for name in files:
        cmap = fontTools.TTFont(css_path.parent / name).getBestCmap()
        missing = [c for c in NATIONAL_TEXT if not c.isspace() and ord(c) not in cmap]
        assert not missing, f"{name} lacks {missing}"

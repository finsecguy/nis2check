"""Every wrapped UI sentence has a translation, and the main pages render in the chosen language."""

import ast
import re
from pathlib import Path

import pytest

from nis2check.i18n import _messages, gettext

PACKAGE = Path(__file__).resolve().parent.parent / "nis2check"
LANGS = ("sk", "cs", "hu", "pl")
PLACEHOLDER = re.compile(r"\{(\w+)\}")
TEMPLATE_CALL = re.compile(r'_\(\s*"((?:[^"\\]|\\.)*)"')


def _wrapped_strings() -> set[str]:
    found: set[str] = set()
    for path in list(PACKAGE.rglob("*.html")) + list(PACKAGE.rglob("*.j2")):
        for match in TEMPLATE_CALL.finditer(path.read_text("utf-8")):
            found.add(match.group(1).replace('\\"', '"'))
    for path in PACKAGE.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text("utf-8"))):
            if (isinstance(node, ast.Call) and getattr(node.func, "id", None) in ("_", "gettext")
                    and node.args and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                found.add(node.args[0].value)
    # Drop empty strings and bare context prefixes such as "size|" ~ value.
    return {s for s in found if s and not s.endswith("|")}


def _dynamic_strings() -> set[str]:
    """Labels that reach _() through a variable rather than a literal."""
    from nis2check.report import PRIORITY_LABELS, STATUS_LABELS
    from nis2check.scope import OUTCOME_LABELS, SIZE_LABELS
    from nis2check.scoring import MATURITY_BANDS
    from nis2check.web import ACTIVITY_LABELS, ANSWER_NAMES
    from nis2check.web.models import ROLE_LABELS

    out = set(STATUS_LABELS.values()) | set(PRIORITY_LABELS.values()) | set(OUTCOME_LABELS.values())
    out |= {f"size|{v}" for v in SIZE_LABELS.values()} | {label for _, label in MATURITY_BANDS}
    out |= set(ACTIVITY_LABELS.values()) | set(ANSWER_NAMES.values()) | set(ROLE_LABELS.values())
    return out


def test_every_wrapped_string_is_translated():
    catalogue = _messages()
    missing = {
        lang: sorted(s for s in _wrapped_strings() | _dynamic_strings() if not catalogue.get(s, {}).get(lang))
        for lang in LANGS
    }
    assert not any(missing.values()), missing


def test_translations_keep_their_placeholders_and_avoid_em_dashes():
    for english, translations in _messages().items():
        expected = set(PLACEHOLDER.findall(english))
        for lang, text in translations.items():
            assert set(PLACEHOLDER.findall(text)) == expected, (lang, english)
            assert "\u2014" not in text, (lang, english)


def test_context_keys_fall_back_to_the_plain_word():
    assert gettext("size|Medium", "en") == "Medium"
    assert gettext("size|Medium", "sk") == "Stredný"
    assert gettext("Medium", "sk") == "Stredná"
    assert gettext("Text nobody translated", "sk") == "Text nobody translated"


# ------------------------------------------------------------------ rendered pages

flask = pytest.importorskip("flask")
from nis2check.web import create_app  # noqa: E402

PASSWORD = "CorrectHorse12"
SETUP_TOKEN = "test-setup-token"

# English UI sentences that must not survive on a Slovak page.
ENGLISH_LEFTOVERS = (
    "Where you stand", "Start here", "Recent activity", "Download report", "Gap register for Excel",
    "Questions answered", "Organisation name", "Does NIS2 apply?", "In scope regardless of size",
    "Frameworks in this assessment", "Planned remediation date", "Attach evidence", "Recommended action",
    "Executive summary", "Remediation plan", "Appendix A", "Appendix B", "controls fully met",
)


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NIS2CHECK_SETUP_TOKEN", SETUP_TOKEN)
    app = create_app(data_dir=tmp_path / "data", start_scheduler=False)
    app.config.update(WTF_CSRF_ENABLED=False, TESTING=True)
    client = app.test_client()
    client.post("/setup", data=dict(org_name="Acme", name="Admin", email="admin@acme.sk",
                                    password=PASSWORD, password2=PASSWORD, token=SETUP_TOKEN))
    client.post("/organisation", data={"name": "Acme", "country": "sk", "frameworks": "nis2"})
    return client


@pytest.mark.parametrize("path", ["/", "/organisation", "/assessment", "/assessment/GOV", "/report/view"])
def test_slovak_pages_have_no_english_ui_text(client, path):
    page = client.get(path).data.decode()
    left = [s for s in ENGLISH_LEFTOVERS if s in page]
    assert not left, left
    assert '<html lang="sk">' in page


def test_language_menu_shows_native_names_and_switches(client):
    page = client.get("/").data.decode()
    for name in ("Slovenčina", "Čeština", "Magyar", "Polski", "English"):
        assert name in page
    assert client.post("/language", data={"language": "en", "next": "/"}).headers["Location"].endswith("/")
    assert "Where you stand" in client.get("/").data.decode()


def test_language_redirect_stays_on_this_site(client):
    for target in ("https://evil.example/", "//evil.example/", "/\\evil.example"):
        location = client.post("/language", data={"language": "", "next": target}).headers["Location"]
        assert "evil.example" not in location


def test_unanswered_requirements_show_as_not_assessed(client):
    page = client.get("/").data.decode()
    assert "Neposúdené" in page
    # Nothing answered, so no critical measure is reported as not met yet.
    assert "Nesplnené kritické opatrenia" in page
    facts = page.split('class="facts"')[1].split("</ul>")[0]
    assert "<strong>0</strong>Nesplnené kritické opatrenia" in facts


def test_answer_without_evidence_gets_a_neutral_note(client):
    saved = client.post("/assessment/question/GOV-01", data={"answer": "yes"}, follow_redirects=True)
    page = saved.data.decode()
    assert 'class="flash info"' in page
    assert "GOV-01: uložené. Dôkaz doplňte" in page

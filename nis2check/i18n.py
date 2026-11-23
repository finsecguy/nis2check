"""Small dictionary of UI labels and report headings.

Question text is not translated here. National extras carry their own wording,
and directive questions stay English until a ``translations`` entry is added
on the question.
"""

from __future__ import annotations

STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "nav.overview": "Overview",
        "nav.assessment": "Assessment",
        "nav.incidents": "Incidents",
        "nav.report": "Report",
        "nav.board": "Board report",
        "nav.organisation": "Organisation",
        "nav.scope": "Scope",
        "nav.administration": "Administration",
        "nav.people": "People and access",
        "nav.settings": "Settings",
        "nav.threat": "Threat data",
        "nav.activity": "Activity log",
        "nav.sign_out": "Sign out",
        "nav.change_password": "Change password",
        "nav.sign_in": "Sign in",
        "org.country": "Country",
        "org.country_help": "National law is shown next to the Directive. EU keeps the Directive text only.",
        "org.language": "Language",
        "org.language_follow": "Follow the organisation country",
        "org.save": "Save",
        "country.eu": "European Union (Directive only)",
        "country.sk": "Slovakia",
        "country.cz": "Czechia",
        "country.hu": "Hungary",
        "country.pl": "Poland",
        "report.kicker": "{label} gap assessment",
        "report.assessed_against": "Assessed against: {law}, transposing Directive (EU) 2022/2555.",
        "report.unverified": "unverified",
        "report.h_summary": "1. Executive summary",
        "report.h_scope": "2. Scope and applicability",
        "report.h_overview": "3. Compliance overview",
        "report.h_status": "3.1 Status by requirement",
        "report.h_plan": "4. Remediation plan",
        "report.h_evidence": "5. Evidence review",
        "report.col_article": "Article",
        "dash.deadlines": "National deadlines",
        "incident.authority": "Competent authority",
        "incident.csirt": "CSIRT",
        "incident.channel": "National reporting channel",
        "scope.outcome": "Outcome",
        "footer": "A self-assessment, not legal advice.",
    },
    "sk": {
        "nav.overview": "Prehľad",
        "nav.assessment": "Posúdenie",
        "nav.incidents": "Incidenty",
        "nav.report": "Správa",
        "nav.board": "Správa pre vedenie",
        "nav.organisation": "Organizácia",
        "nav.scope": "Pôsobnosť",
        "nav.administration": "Správa",
        "nav.people": "Ľudia a prístup",
        "nav.settings": "Nastavenia",
        "nav.threat": "Údaje o hrozbách",
        "nav.activity": "Záznam činnosti",
        "nav.sign_out": "Odhlásiť",
        "nav.change_password": "Zmeniť heslo",
        "nav.sign_in": "Prihlásiť",
        "org.country": "Krajina",
        "org.country_help": "Vnútroštátny predpis sa zobrazí vedľa smernice. EÚ ponechá len text smernice.",
        "org.language": "Jazyk",
        "org.language_follow": "Podľa krajiny organizácie",
        "org.save": "Uložiť",
        "country.eu": "Európska únia (len smernica)",
        "country.sk": "Slovensko",
        "country.cz": "Česko",
        "country.hu": "Maďarsko",
        "country.pl": "Poľsko",
        "report.kicker": "Posúdenie medzier {label}",
        "report.assessed_against": "Posúdené podľa: {law}, ktorým sa preberá smernica (EÚ) 2022/2555.",
        "report.unverified": "neoverené",
        "report.h_summary": "1. Zhrnutie",
        "report.h_scope": "2. Pôsobnosť",
        "report.h_overview": "3. Prehľad plnenia",
        "report.h_status": "3.1 Stav podľa požiadavky",
        "report.h_plan": "4. Plán nápravy",
        "report.h_evidence": "5. Preskúmanie dôkazov",
        "report.col_article": "Článok",
        "dash.deadlines": "Vnútroštátne lehoty",
        "incident.authority": "Príslušný orgán",
        "incident.csirt": "CSIRT",
        "incident.channel": "Vnútroštátny oznamovací kanál",
        "scope.outcome": "Výsledok",
        "footer": "Samohodnotenie, nie právne poradenstvo.",
    },
    "cs": {
        "nav.overview": "Přehled",
        "nav.assessment": "Posouzení",
        "nav.incidents": "Incidenty",
        "nav.report": "Zpráva",
        "nav.board": "Zpráva pro vedení",
        "nav.organisation": "Organizace",
        "nav.scope": "Působnost",
        "nav.administration": "Správa",
        "nav.people": "Lidé a přístup",
        "nav.settings": "Nastavení",
        "nav.threat": "Data o hrozbách",
        "nav.activity": "Záznam činnosti",
        "nav.sign_out": "Odhlásit",
        "nav.change_password": "Změnit heslo",
        "nav.sign_in": "Přihlásit",
        "org.country": "Země",
        "org.country_help": "Vnitrostátní předpis se zobrazí vedle směrnice. EU ponechá jen text směrnice.",
        "org.language": "Jazyk",
        "org.language_follow": "Podle země organizace",
        "org.save": "Uložit",
        "country.eu": "Evropská unie (jen směrnice)",
        "country.sk": "Slovensko",
        "country.cz": "Česko",
        "country.hu": "Maďarsko",
        "country.pl": "Polsko",
        "report.kicker": "Posouzení mezer {label}",
        "report.assessed_against": "Posouzeno podle: {law}, kterým se provádí směrnice (EU) 2022/2555.",
        "report.unverified": "neověřeno",
        "report.h_summary": "1. Shrnutí",
        "report.h_scope": "2. Působnost",
        "report.h_overview": "3. Přehled plnění",
        "report.h_status": "3.1 Stav podle požadavku",
        "report.h_plan": "4. Plán nápravy",
        "report.h_evidence": "5. Přezkum důkazů",
        "report.col_article": "Článek",
        "dash.deadlines": "Vnitrostátní lhůty",
        "incident.authority": "Příslušný orgán",
        "incident.csirt": "CSIRT",
        "incident.channel": "Vnitrostátní oznamovací kanál",
        "scope.outcome": "Výsledek",
        "footer": "Sebehodnocení, ne právní poradenství.",
    },
    "hu": {
        "nav.overview": "Áttekintés",
        "nav.assessment": "Értékelés",
        "nav.incidents": "Incidensek",
        "nav.report": "Jelentés",
        "nav.board": "Vezetői jelentés",
        "nav.organisation": "Szervezet",
        "nav.scope": "Hatály",
        "nav.administration": "Adminisztráció",
        "nav.people": "Személyek és hozzáférés",
        "nav.settings": "Beállítások",
        "nav.threat": "Fenyegetési adatok",
        "nav.activity": "Napló",
        "nav.sign_out": "Kijelentkezés",
        "nav.change_password": "Jelszó módosítása",
        "nav.sign_in": "Bejelentkezés",
        "org.country": "Ország",
        "org.country_help": "A nemzeti jog az irányelv mellett jelenik meg. Az EU csak az irányelv szövegét használja.",
        "org.language": "Nyelv",
        "org.language_follow": "A szervezet országa szerint",
        "org.save": "Mentés",
        "country.eu": "Európai Unió (csak az irányelv)",
        "country.sk": "Szlovákia",
        "country.cz": "Csehország",
        "country.hu": "Magyarország",
        "country.pl": "Lengyelország",
        "report.kicker": "{label} hiányosságértékelés",
        "report.assessed_against": "Értékelés alapja: {law}, amely átülteti az (EU) 2022/2555 irányelvet.",
        "report.unverified": "nem ellenőrzött",
        "report.h_summary": "1. Összefoglaló",
        "report.h_scope": "2. Hatály",
        "report.h_overview": "3. Megfelelési áttekintés",
        "report.h_status": "3.1 Állapot követelményenként",
        "report.h_plan": "4. Helyreállítási terv",
        "report.h_evidence": "5. Bizonyítékok áttekintése",
        "report.col_article": "Cikk",
        "dash.deadlines": "Nemzeti határidők",
        "incident.authority": "Illetékes hatóság",
        "incident.csirt": "CSIRT",
        "incident.channel": "Nemzeti bejelentési csatorna",
        "scope.outcome": "Eredmény",
        "footer": "Önértékelés, nem jogi tanács.",
    },
    "pl": {
        "nav.overview": "Przegląd",
        "nav.assessment": "Ocena",
        "nav.incidents": "Incydenty",
        "nav.report": "Raport",
        "nav.board": "Raport dla zarządu",
        "nav.organisation": "Organizacja",
        "nav.scope": "Zakres",
        "nav.administration": "Administracja",
        "nav.people": "Osoby i dostęp",
        "nav.settings": "Ustawienia",
        "nav.threat": "Dane o zagrożeniach",
        "nav.activity": "Dziennik",
        "nav.sign_out": "Wyloguj",
        "nav.change_password": "Zmień hasło",
        "nav.sign_in": "Zaloguj",
        "org.country": "Kraj",
        "org.country_help": "Prawo krajowe jest pokazane obok dyrektywy. UE zostawia sam tekst dyrektywy.",
        "org.language": "Język",
        "org.language_follow": "Według kraju organizacji",
        "org.save": "Zapisz",
        "country.eu": "Unia Europejska (tylko dyrektywa)",
        "country.sk": "Słowacja",
        "country.cz": "Czechy",
        "country.hu": "Węgry",
        "country.pl": "Polska",
        "report.kicker": "Ocena luk {label}",
        "report.assessed_against": "Ocena według: {law}, wdrażającej dyrektywę (UE) 2022/2555.",
        "report.unverified": "niezweryfikowane",
        "report.h_summary": "1. Podsumowanie",
        "report.h_scope": "2. Zakres",
        "report.h_overview": "3. Przegląd zgodności",
        "report.h_status": "3.1 Status według wymagania",
        "report.h_plan": "4. Plan działań",
        "report.h_evidence": "5. Przegląd dowodów",
        "report.col_article": "Artykuł",
        "dash.deadlines": "Krajowe terminy",
        "incident.authority": "Organ właściwy",
        "incident.csirt": "CSIRT",
        "incident.channel": "Krajowy kanał zgłoszeń",
        "scope.outcome": "Wynik",
        "footer": "Samoocena, nie porada prawna.",
    },
}


def t(key: str, lang: str | None = None, **kwargs) -> str:
    """Look up a label. Missing keys and languages fall back to English, then to the key."""
    code = (lang or "en").strip().lower()
    table = STRINGS.get(code) or STRINGS["en"]
    text = table.get(key) or STRINGS["en"].get(key) or key
    if kwargs:
        return text.format(**kwargs)
    return text


# ---------------------------------------------------------------- sentence catalogue
# Template text is written in English and wrapped in _("..."). The English text is the
# key, so a missing translation simply shows English. Translations live in
# nis2check/data/translations.yaml, one entry per English string.

_MESSAGES: dict[str, dict[str, str]] | None = None

NATIVE_LANGUAGE_NAMES = {
    "en": "English",
    "sk": "Slovenčina",
    "cs": "Čeština",
    "hu": "Magyar",
    "pl": "Polski",
}


def _messages() -> dict[str, dict[str, str]]:
    global _MESSAGES
    if _MESSAGES is None:
        from importlib import resources

        import yaml

        text = resources.files("nis2check").joinpath("data/translations.yaml").read_text("utf-8")
        loaded = yaml.safe_load(text) or {}
        _MESSAGES = {str(k): {str(lc): str(v) for lc, v in (tr or {}).items()} for k, tr in loaded.items()}
    return _MESSAGES


def gettext(text: str, lang: str | None = None, **kwargs) -> str:
    """Translate an English UI sentence. Unknown text or language falls back to English."""
    code = (lang or "en").strip().lower()
    out = None if code == "en" else _messages().get(text, {}).get(code)
    if out is None:
        # "context|Text" keys tell apart words that are the same in English only.
        out = text.split("|", 1)[1] if "|" in text else text
    return out.format(**kwargs) if kwargs else out



def format_date(value, lang: str | None = None, with_time: bool = False) -> str:
    """A date in the local style: 23 Nov 2026 (en), 23.11.2026 (sk, cs, pl), 2026. 11. 23. (hu)."""
    if value is None:
        return ""
    code = (lang or "en").strip().lower()
    fmt = {"en": "%d %b %Y", "hu": "%Y. %m. %d."}.get(code, "%d.%m.%Y")
    if with_time:
        fmt += ", %H:%M"
    return value.strftime(fmt)

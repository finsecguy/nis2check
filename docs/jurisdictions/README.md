# Country file

One YAML file per country, in `nis2check/data/jurisdictions/<code>.yaml`. `eu` is not a file: it means the Directive text only.

`verified: true` means the paragraph number and its title were read in the official consolidated text. Anything else is `verified: false`, including a best-reading ref. The report prints **unverified** on those citations.

```yaml
code: sk
language: sk
domain_title: National requirements (SK)
law:
  name: Zákon č. 69/2018 Z. z. o kybernetickej bezpečnosti
  number: 69/2018 Z. z.
  in_force: "2025-01-01"
  competent_authority: Národný bezpečnostný úrad (NBÚ)
  csirt: SK-CERT
  reporting_channel_url: https://jiskb.nbu.gov.sk/
  source_url: https://www.slov-lex.sk/ezbierky/pravne-predpisy/SK/ZZ/2018/69/20260430
  citation_label: Act 69/2018
entity_terms:
  essential:
    national: prevádzkovateľ kritickej základnej služby
  important:
    national: prevádzkovateľ základnej služby
article_map:
  "Art. 23":
    ref: § 24
    title: Hlásenia
    source_url: https://www.slov-lex.sk/ezbierky/pravne-predpisy/SK/ZZ/2018/69/20260430
    verified: true
    note: Early warning 24 hours, notification 72 hours, final report within one month.
national_extras:
  - id: sk-report-01
    text: Hlási organizácia závažný incident cez JISKB?
    text_en: Does the organisation report a significant incident through JISKB?
    priority: critical
    effort: low
    evidence_hint: Postup hlásenia
    remediation: Nastavte hlásenie v JISKB.
    article: § 24 ods. 3
    source_url: https://www.slov-lex.sk/ezbierky/pravne-predpisy/SK/ZZ/2018/69/20260430
    verified: true
incident_clocks:
  further_days: 30
  source_url: https://www.slov-lex.sk/ezbierky/pravne-predpisy/SK/ZZ/2018/69/20260430
  verified: true
  note: Only the updated final report differs, at 30 days. The 24 h / 72 h / one month clocks stay.
deadlines:
  - id: sk-measures
    description: Bezpečnostné opatrenia do 12 mesiacov od zápisu.
    description_en: Security measures within 12 months of registration.
    relative: 12 months from entry in the register
    source_url: https://www.slov-lex.sk/ezbierky/pravne-predpisy/SK/ZZ/2018/69/20260430
    verified: true
sector_authorities:
  energy:
    authority: ""
    csirt: ""
    note: TODO
notices:
  - id: example-note
    text: Text v národnom jazyku.
    text_en: Note in English. Not scored.
    source_url: https://www.slov-lex.sk/ezbierky/pravne-predpisy/SK/ZZ/2018/69/20260430
    status: under_review
    scored: false
```

`article_map` must contain every `article` in `controls.yaml` and every string in an `articles` list in `scope.yaml`, plus `Art. 2` and `Art. 3`. The ref may be empty. `source_url` may not. An unknown article key, a duplicate extra id, or a missing `source_url` fails at load. `sector_authorities` is optional; a key that is not an `organisation_sector` in `scope.yaml` fails. `deadlines` is optional. A dated deadline that is still ahead, and a deadline with no date, are shown on the dashboard and in the report.

Question ids on `national_extras` start with the country code and a hyphen (`sk-`, `cz-`, `hu-`, `pl-`). `text` is the local language. `text_en` is the English version. Directive questions stay English until a `translations` map is added on the question.

`incident_clocks` overrides the Directive's 24 hours, 72 hours or one month only where the file sets `early_hours`, `notification_hours`, `final_days` or `further_days`, and only when `verified` is true.

## Country support

Pick a country on the organisation page, or pass `--country sk|cz|hu|pl` to `init`, `interview`, `report` and `controls`. `eu` keeps the Directive text and changes nothing else. The language of the screen and of the report headings follows that country (Slovak, Czech, Hungarian or Polish) unless a user sets another language.

Each finding then shows the Directive article and the national provision, for example `NIS2 Art. 21(2)(a)` and `§ 20 ods. 2 písm. a) a c) a § 20 ods. 5 Act 69/2018`. A citation that was not confirmed against the official consolidated text is marked **unverified**. Do not file an unverified citation as if it had been checked. Hungary and Poland are unverified on purpose: the refs are a best reading, and the paragraph numbers still need a human check.

Slovakia can download a self-assessment summary (Report, or `nis2check report assessment.yaml --country sk --self-assessment summary.html`). It is a working paper for an NBU filing, not an official form. Hungary's report says an SZTFH-registered auditor has to perform the audit, and that this tool's output is only preparation.

| | Authority | Registration | Audit or self-assessment | A date to watch |
|---|---|---|---|---|
| Slovakia | NBÚ, reports through JISKB, CSIRT SK-CERT | Notify within 60 days of starting the activity | Audit within 2 years, or self-assessment for an operator who is not running a critical essential service, with an audit within 5 years | 12 months from entry in the register for the measures |
| Czechia | NÚKIB, reports through Portál NÚKIB | Notify within 60 days of meeting the conditions | Measures follow the higher-regime or lower-regime decree. No self-assessment shortcut is recorded here | 1 year from the registration decision for measures and incident reporting |
| Hungary | SZTFH for the NIS2 organisations it supervises | 30 days from starting operations or coming into scope | External audit by an SZTFH-registered auditor. No self-assessment alternative | Contract the auditor within 120 days of registration; first audit within 2 years |
| Poland | Sector authorities, coordinated by the minister for informatisation. CSIRT NASK, CSIRT GOV and CSIRT MON | Entry in the wykaz. The ministry page puts the first filing window's end at 3 October 2026 | Information-security management system. The high-risk vendor rules are noted as under review and are not scored | 3 April 2027 for the management system, for entities that already met the criteria on 3 April 2026 |

Czech, Hungarian and Polish rows above are best readings. Where the table states a Slovak period, it was read in the Slov-Lex consolidation in force from 30 April 2026. The NIS2 amendment of the Slovak act (Act No. 366/2024 Coll.) took effect on 1 January 2025. The Czech act is No. 264/2025 Coll., in force 1 November 2025, as stated by the Ministry of Foreign Affairs and by NÚKIB. Art. 21(2)(c) and Art. 23 were read in the e-Sbírka open data and are verified. The other Czech citations were not read in the official consolidated text, so they stay unverified.

### Adding a country

Add `nis2check/data/jurisdictions/<code>.yaml`. The file needs the law, the two entity names, an `article_map` entry for every Directive citation in `controls.yaml` and `scope.yaml` (a ref may be empty), `source_url` on every entry, and `national_extras` whose ids start with the country code. Set `verified: true` only after reading the paragraph and its title in the official consolidated text. `docs/jurisdictions/README.md` is the schema. The loader rejects an unknown article key, a duplicate question id, and a missing `source_url`.

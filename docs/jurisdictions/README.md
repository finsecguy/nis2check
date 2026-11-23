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

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
  note: Set further_days only when the national text counts that further report in days.
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

Each finding then shows the Directive article and the national provision, for example `NIS2 Art. 21(2)(a)` and `§ 20 ods. 2 písm. a) a c) a § 20 ods. 5 Act 69/2018`. A citation that was not confirmed against the official consolidated text is marked **unverified**. Do not file an unverified citation as if it had been checked. A country is offered only when its citations are verified, or when it is listed in `NIS2_EXPERIMENTAL_COUNTRIES` and every citation that is not verified has `status: blocked`. A blocked citation is not verified.

Slovakia can download a self-assessment summary (Report, or `nis2check report assessment.yaml --country sk --self-assessment summary.html`). It is a working paper for an NBU filing, not an official form. Hungary's report says an SZTFH-registered auditor has to perform the audit, and that this tool's output is only preparation.

| | Authority | Registration | Audit or self-assessment | A date to watch |
|---|---|---|---|---|
| Slovakia | NBÚ, reports through JISKB, CSIRT SK-CERT | Notify within 60 days of starting the activity | Audit within 2 years, or self-assessment for an operator who is not running a critical essential service, with an audit within 5 years | 12 months from entry in the register for the measures |
| Czechia | NÚKIB. Higher regime reports to the Office, lower regime to Národní CERT, through Portál NÚKIB | A provider who meets section 4(1) notifies within 60 days. Section 5 cases are started by the Office | Measures follow the higher-regime or lower-regime decree. The decree number is not stated here because the decree was not opened. No self-assessment shortcut is recorded here | 1 year from delivery of the registration decision for measures and incident reporting |
| Hungary | SZTFH supervises the organisations in section 1(1)(d) and (e). The Act does not print a reporting URL | Section 8(5): the named organisations send registration data to SZTFH within 30 days. Section 8(4) is a different 30-day notice, to the national cybersecurity authority | Where section 16(1) applies, an SZTFH-registered auditor. No self-assessment alternative is in section 16 | Where section 16 applies: contract within 120 days of registration and a first audit within two years. An organisation in that group that started before 1 January 2025 contracts by 31 August 2025 and completes the first audit by 30 June 2026 |
| Poland | Sector authorities named in art. 41. Serious incidents go to the sector CSIRT. CSIRT NASK, CSIRT GOV and CSIRT MON are the national teams | Within 6 months of meeting the criteria. An entity that already met them when the amendment entered into force follows the minister's schedule. The ministry page of 5 June 2026 states 3 October 2026 | Information security management system under art. 8. The high-risk vendor rules are in the Act. No referral to the Constitutional Tribunal was found in the texts that were read, so that note is not scored | 3 April 2027 for the chapter 3 duties, as the ministry page states. The amendment says 12 months from entry into force. Named administrative fines may first be imposed two years after that entry |

The Slovak periods were read in the Slov-Lex consolidation in force from 30 April 2026. The Czech periods were read in the e-Sbírka text of Act No. 264/2025 Coll. effective 1 November 2025. The Hungarian periods were read in Act LXIX of 2024 on njt.jog.gov.hu, temporal state 2026.10.01. The Polish periods were read in the Sejm consolidated text of 9 November 2026 and, for the calendar dates, in the amending act of 23 January 2026 and the ministry page of 5 June 2026. The date 3 April 2026 is not printed as the amendment's entry date. The Journal says the amendment was published on 2 March 2026 and enters into force one month after publication.

### Adding a country

Add `nis2check/data/jurisdictions/<code>.yaml`. The file needs the law, the two entity names, an `article_map` entry for every Directive citation in `controls.yaml` and `scope.yaml` (a ref may be empty), `source_url` on every entry, and `national_extras` whose ids start with the country code. Set `verified: true` only after reading the paragraph and its title in the official consolidated text. `docs/jurisdictions/README.md` is the schema. The loader rejects an unknown article key, a duplicate question id, and a missing `source_url`.

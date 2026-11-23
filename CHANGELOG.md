# Changelog

## 0.4.0

- A country on the organisation (EU, Slovakia, Czechia, Hungary or Poland) shows the national provision next to each NIS2 article. EU leaves the Directive text as it was.
- Slovakia and Czechia use Act No. 69/2018 Coll. and Act No. 264/2025 Coll. A citation is marked unverified unless the paragraph was read in the official consolidated text. Hungary and Poland are unverified throughout.
- National obligations that the Directive does not state as their own article are extra questions. Slovakia can export a working self-assessment for an NBU filing. That export is not an official form.
- Incident pages use the national reporting channel. A national deadline that is still ahead is listed on the dashboard and in the report.
- Screen labels and report headings are available in English, Slovak, Czech, Hungarian and Polish. The language follows the country unless a user picks another one.
- The report and the Slovak working paper say the tool is a self-assessment, not a certified audit, and that national citations have to be checked against the official text.

## 0.3.0

- Add a DORA question set for the five pillars of Regulation (EU) 2022/2554 (ICT risk management, incident management and reporting, resilience testing, ICT third-party risk, information sharing). Each question cites the article it is about. The wording is original.
- An assessment can cover NIS2, DORA, or both. Scoring, evidence and the report use the same engine. Turning a framework off keeps its answers.
- The organisation page, the assessment and the report note that DORA is lex specialis to NIS2 for financial entities, and that the size and sector check does not decide whether DORA applies.
- Export an assessment for CISO Assistant: a library YAML per selected framework and a compliance-assessment CSV of the answers. See the README.
- The tests workflow declares `permissions: contents: read`.

## 0.2.0

- Self-hosted NIS2 gap assessment: questionnaire, evidence, threat-informed weights and reports.

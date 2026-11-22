# Changelog

## 0.3.0

- Add a DORA question set for the five pillars of Regulation (EU) 2022/2554 (ICT risk management, incident management and reporting, resilience testing, ICT third-party risk, information sharing). Each question cites the article it is about. The wording is original.
- An assessment can cover NIS2, DORA, or both. Scoring, evidence and the report use the same engine. Turning a framework off keeps its answers.
- The organisation page, the assessment and the report note that DORA is lex specialis to NIS2 for financial entities, and that the size and sector check does not decide whether DORA applies.
- Export an assessment for CISO Assistant: a library YAML per selected framework and a compliance-assessment CSV of the answers. See the README.
- The tests workflow declares `permissions: contents: read`.

## 0.2.0

- Self-hosted NIS2 gap assessment: questionnaire, evidence, threat-informed weights and reports.

# Changelog

## Unreleased

- Requirements nobody has answered yet show as grey "not assessed" instead of a red 0%, and no longer count as critical measures not met. The overview says how many questions are still open.
- A requirement answered as in place without evidence stays amber instead of green. Score bars show the part backed by evidence as solid and the rest as light.
- Saving an answer without evidence shows a neutral note instead of a red error.
- The language menu moved to the header, lists languages by their own names (Slovenčina, Čeština, Magyar, Polski) and saves on change. It was removed from the organisation page.
- Screens, flash messages, the activity log and the report (headings, tables, summary, methodology) are translated into Slovak, Czech, Hungarian and Polish. Dates follow the language. Question texts, requirement titles and scope explanations are still English.
- Slovak and Czech pages name the law in their own language, for example "Zákon č. 69/2018 Z. z." and "§ 20 ods. 4 zákona č. 69/2018 Z. z.".
- The version shown in the app and report now comes from pyproject.toml only.
- Security: Docker Compose now binds to localhost by default. Set NIS2_BIND to expose it.
- Fixed: the PDF report drew wrong letters for Slovak, Czech, Hungarian and Polish characters (for example ť, ľ, ž, ň, Č). The PDF now uses one font file per weight that covers them.
- Fixed: the remediation plan table no longer runs off the A4 page, and long legal references wrap inside their column.

## 0.4.1

- Security fix. Before this release, anyone who could reach `/setup` on a fresh install with no administrator could create the first admin account and take over the instance. Installs from v0.4.0 and earlier should update before `/setup` is reachable by anyone else.
- First-run setup now needs a one-time token. A generated token is printed once to the logs (`docker logs nis2check`), or you can set `NIS2CHECK_SETUP_TOKEN`. Only a hash is stored. A missing or wrong token returns 404 and creates nothing. The token stops working once an admin exists, including an admin created from the command line.

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

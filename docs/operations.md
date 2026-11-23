## Running on a server

`docker compose up` binds the app to `127.0.0.1:8080`. On a server, set `NIS2_BIND` in `.env` (Compose reads that file when it publishes the port). Use `0.0.0.0` only to expose the app on the network, and only behind a reverse proxy with HTTPS.

Then set:

- `NIS2_SECURE_COOKIES=true`
- `NIS2_BEHIND_PROXY=true`

Restart with `docker compose up -d`.

### Recommended for production

1. Put the app behind HTTPS (your existing reverse proxy, load balancer or a tool such as Caddy).
2. Copy `.env.example` to `.env` and set:
   - `NIS2_BASE_URL=https://nis2.yourcompany.com`
   - `NIS2_SECURE_COOKIES=true`
   - `NIS2_BEHIND_PROXY=true` (only if a reverse proxy sits in front of the app)
3. Restart: `docker compose up -d`.
4. Set up backups (below).

## Backups and upgrades

All data (database, evidence files and the session key) lives in the `nis2check-data` volume.

```bash
# back up
docker run --rm -v nis2check_nis2check-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/nis2check-backup-$(date +%F).tgz -C /data .

# upgrade to a new version
git pull && docker compose up -d --build
```

## Moving an existing assessment into the app

If you started with the command-line version (a YAML file), import it with its evidence files:

```bash
docker cp my-assessment/ nis2check:/tmp/import
docker exec nis2check nis2check web import /tmp/import/assessment.yaml
```

## How priorities are calculated

### Scoring

- Each control has a weight: its **regulatory baseline** from the NIS2 priority (critical 3, high 2, medium 1), raised by threat data as described below.
- Yes = 1, partially = 0.5, no = 0, not assessed = 0; not applicable is excluded.
- The **overall score** is the weighted average of the applicable controls. The **evidence-backed score** counts an answer only if it has valid evidence: an existing file, a link, and not past its "valid until" date.
- Open items are ranked by **risk reduction**, `weight x (1 - score)`, or, if you choose in Settings, by risk reduction per unit of effort.

### Threat-informed weighting

The baseline is raised by up to 50% for controls that counter threats seen often in real incidents:

```
exposure   = sum of the prevalence of the threat patterns a control counters
multiplier = 1 + 0.5 x exposure / highest exposure of any control
weight     = baseline x multiplier
```

Threat data can raise a weight but never lower it, because every NIS2 control is a legal requirement however rare the threat it addresses. Every weight is explained in the app, the report (Appendix C) and the CSV, for example:

> Baseline 3 x 1.15 = 3.46. Counters: Stolen or brute-forced credentials 17% of incidents (ATT&CK M1032).

| Input | Source | Used for |
|---|---|---|
| Prevalence of 9 threat patterns | [VERIS Community Database](https://github.com/vz-risk/VCDB) | How common each threat is |
| Mitigation to technique links | [MITRE ATT&CK](https://github.com/mitre-attack/attack-stix-data) (STIX 2.1) | Which controls counter which threats |
| Newly exploited vulnerabilities, year on year | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [ENISA EUVD](https://euvd.enisa.europa.eu/) | Trend adjustment for vulnerability exploitation (0.8 to 1.25) |

Data handling choices:

- **Campaigns are counted once.** Mass campaigns are recorded in VCDB once per victim; MOVEit in 2023 alone produced 747 identical records. Records sharing a campaign ID, or five or more records in the same year with the same summary, count as one event.
- **Minimum sample.** The VCDB window (default 5 years) widens until it holds at least 300 events.
- **Caveats.** VCDB covers publicly reported incidents, mostly in the United States, and is not the full Verizon DBIR dataset. CISA KEV is US-centric; ENISA EUVD adds an EU view. These caveats are printed in every report.

### Threat data updates

The app checks the four sources weekly (or on demand under **Threat data**) and stores the result as a pending update with a change report: every pattern and weight that moved, with large moves flagged. Nothing changes until an administrator approves it. If CISA KEV or ENISA EUVD is unavailable the check continues without the trend adjustment; if VCDB or ATT&CK is unavailable nothing changes. For servers without internet access, copy the source files into a folder and set `NIS2_THREAT_SOURCE_DIR`.

### Effort and quick wins

Each control has an effort estimate (low, medium, high) for an SME. Open items are placed on an impact vs effort matrix: quick wins, major projects, fill-ins and items to schedule later.

## The report

The report follows the structure of an internal-audit gap assessment and prints cleanly to A4.

| Section | Content |
|---|---|
| Document control | Organisation, date, preparer, framework, weighting, classification |
| 1. Executive summary | Generated narrative plus key figures and quick wins |
| 2. Scope and applicability | Enterprise size, Annex I or II sector, likely classification |
| 3. Compliance overview | RAG status per requirement, priority x status heat map, impact vs effort matrix |
| 4. Remediation plan | Highest-priority open items with effort, recommended action, owner and target columns |
| 5. Evidence review | Controls claimed as met without valid evidence |
| Appendix A, B, C | Full control results, methodology, threat data sources and weight rationale |

## Coverage

| Domain | NIS2 reference | Topic |
|---|---|---|
| GOV | Art. 20 | Management approval, oversight and training |
| RISK | Art. 21(2)(a) | Risk analysis and information security policies |
| INC | Art. 21(2)(b) | Incident handling |
| BCM | Art. 21(2)(c) | Backups, disaster recovery, crisis management |
| SUP | Art. 21(2)(d) | Supply chain security |
| SDLC | Art. 21(2)(e) | Secure acquisition and development, vulnerability handling |
| EFF | Art. 21(2)(f) | Assessing the effectiveness of measures |
| HYG | Art. 21(2)(g) | Cyber hygiene and training |
| CRY | Art. 21(2)(h) | Cryptography and encryption |
| ACC | Art. 21(2)(i) | HR security, access control, asset management |
| MFA | Art. 21(2)(j) | Multi-factor authentication, secure communications |
| REP | Art. 23 | 24-hour early warning, 72-hour notification, final report |

DORA is a second question set. An assessment can use NIS2, DORA, or both.

| Pillar | DORA reference | Topic |
|---|---|---|
| DIRM | Art. 5-16 | ICT risk management, including the simplified framework |
| DIIM | Art. 17-23 | ICT incident management, major-incident reporting, payment-related incidents |
| DDOT | Art. 24-27 | Resilience testing, including threat-led penetration testing where it applies |
| DTPR | Art. 28-44 | ICT third-party strategy, register, contracts, exit, and critical providers |
| DISH | Art. 45 | Cyber threat information sharing |

DORA questions live in [`nis2check/data/dora.yaml`](../nis2check/data/dora.yaml). The text is original; the article number on each question says which duty it is about. Articles 31 to 44 are the oversight regime for critical ICT third-party providers. The question set covers what a financial entity has to do on that side (know a designation, answer the authority, follow findings), not the lead overseer's job.

For a financial entity, DORA is lex specialis to NIS2 (DORA Art. 1(2); NIS2 Art. 4). Where DORA covers ICT risk management and incident reporting, those NIS2 provisions do not apply to that entity. Other NIS2 duties can still apply. The organisation page, the assessment and the report say this in one paragraph. It is a pointer, not a legal opinion. The size and sector check remains the NIS2 test and does not decide whether DORA applies.

The NIS2 catalogue ([`nis2check/data/controls.yaml`](../nis2check/data/controls.yaml)) and threat pattern taxonomy ([`nis2check/data/patterns.yaml`](../nis2check/data/patterns.yaml)) are plain files you can review and adapt, for example to add national requirements.

## Security

- Passwords are hashed with scrypt; sign-in is rate-limited per address and per account.
- SSO uses OpenID Connect with state, nonce and ID-token signature checks; SSO accounts are bound to one identity.
- Every form is protected against cross-site request forgery; pages send a strict Content Security Policy.
- Evidence files are stored under random names, type-checked on upload and always downloaded as attachments.
- The container runs as an unprivileged user. Found a problem? Please open a private security advisory on GitHub.

## Command-line use

The same engine runs without the web app, for automation or CI:

```bash
pip install ".[pdf]"
nis2check init --name "Your Company s.r.o."            # creates assessment.yaml
nis2check report assessment.yaml --pdf report.pdf --csv gap-register.csv
nis2check init --frameworks dora -o dora.yaml   # or: nis2,dora
nis2check report assessment.yaml --fail-under 70 --evidence-backed   # exit code 2 below threshold
nis2check update-threat-data --change-report change.md   # refresh the bundled threat data
```

Run `nis2check --help` for all commands. The bundled threat data snapshot is refreshed by the weekly [`update-threat-data`](../.github/workflows/update-threat-data.yml) workflow, which opens a pull request for review.

## Development

```bash
pip install -e ".[dev,web]"
pytest
nis2check web serve --data-dir ./data      # development server on http://127.0.0.1:8080
```

## Limitations

- This is a self-assessment aid, not a certification or legal advice.
- Threat weights reflect public incident data, which over-represents incidents that become news and US organisations. Effort ratings are estimates.
- The scope check covers the NIS2 size-cap rule and Annex I and II sectors only. It does not decide whether DORA applies. National transposition, designations by the competent authority and the financial-entity list in DORA Article 2 can change the outcome.
- The DORA question set is a practical gap assessment of the five pillars, not the full text of the regulatory technical standards. Threat-led penetration testing and the simplified ICT risk framework are questions you can mark not applicable.
- Questions are original prompts keyed to article numbers. Implementing acts and national guidance may set more detailed requirements for some entity types.

## Your data

The app does not send telemetry. Answers, evidence and reports stay in the database on the machine where you run it. The only outbound calls are these:

- **Threat data.** When an administrator checks for an update, when the weekly check inside the app is due, or when you run `nis2check update-threat-data`, the app downloads public files from the VERIS Community Database, MITRE ATT&CK, CISA KEV and ENISA EUVD. Nothing is uploaded. Set `NIS2_THREAT_SOURCE_DIR` to read those files from disk instead, or `NIS2_THREAT_AUTO_CHECK=false` to stop the weekly check. The GitHub workflow that refreshes the bundled snapshot runs in GitHub, not on your server.
- **Sign-in.** If you configure Microsoft Entra ID or Google, the browser and the app talk to that provider. With neither configured, sign-in stays on the server.

The database is SQLite, not Postgres. In Docker it is `/data/nis2check.db` inside the `nis2check-data` volume, next to `evidence/` and `.secret_key`. A development server uses `./data` (or `NIS2_DATA_DIR`). Back up by copying that directory. The volume command is in [Backups and upgrades](#backups-and-upgrades). To delete everything, stop the app and remove the volume (`docker volume rm nis2check_nis2check-data`) or delete the data directory.

nis2check supports a self-assessment and does not replace a certified auditor. National citations must be checked against the official text.

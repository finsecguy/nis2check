## CISO Assistant export

An assessment can be downloaded as a zip for [CISO Assistant](https://github.com/intuitem/ciso-assistant-community) (community edition). The zip holds, for each selected framework:

- a **library YAML** in the format the library screen loads (`urn:intuitem:risk:library:nis2check-nis2` or `nis2check-dora`)
- a **compliance-assessment CSV** with one row per question

The CSV columns are the ones the CISO Assistant data wizard reads: `ref_id`, `urn`, `assessable`, `compliance_result`, `score`, `requirement_progress` and `observations`. Answers map as yes = compliant / 100, partial = partially_compliant / 50, no = non_compliant / 0, not applicable = not_applicable, and unanswered = not_assessed. Evidence notes and evidence problems go in `observations`.

Load each YAML under Catalog, Libraries. Then import the matching CSV. On the community edition that import is the [`clica`](https://github.com/intuitem/ciso-assistant-community/blob/main/cli/README.md) command `import-compliance-assessments` (it needs a folder and a perimeter). The Pro data wizard takes the same file. `IMPORT.txt` in the zip has the exact framework name to pass as `--framework`, for example `DORA (nis2check gap assessment)`.

```bash
uv run clica.py import-compliance-assessments \
  --file dora-compliance-assessment.csv \
  --framework "DORA (nis2check gap assessment)" \
  --perimeter "Your perimeter"
```

From the command line, the same zip is `nis2check report assessment.yaml --ciso ciso-assistant.zip`.

This export is nis2check's own question set plus this assessment's answers. CISO Assistant also ships its own DORA library (and a NOREA DORA-in-Control framework). Those use different requirement ids, so this zip does not fill an audit opened on them. CISO Assistant then averages requirement scores in its own way; the weighted score in the nis2check report can differ. Pushing the result through the CISO Assistant API is not implemented: the files above are what you can import without giving this app a token.

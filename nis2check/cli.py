"""Command-line interface: init, interview, report, controls."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
import yaml

from .applicability import SECTORS
from .assessment import AssessmentError, load_assessment, new_assessment, save_assessment
from .ciso import export_zip
from .controls import CatalogueError, load_catalogue
from .frameworks import FRAMEWORK_IDS, load_bundled_catalogue, parse_frameworks
from .report import fonts_css_uri, render_csv, render_html, render_json, render_summary, write_pdf
from .scoring import evaluate
from .threat.data import load_threat_data
from .weighting import compute_weights

ANSWER_KEYS = {"y": "yes", "p": "partial", "n": "no", "na": "na"}


def _catalogue(args, path: Path | None = None):
    """Bundled NIS2, unless --frameworks or the file's frameworks field says otherwise.

    --catalogue still wins: a custom file is used as a whole.
    """
    if args.catalogue:
        return load_catalogue(args.catalogue)
    if args.frameworks:
        try:
            ids = parse_frameworks(args.frameworks, default=None)
        except ValueError as exc:
            raise CatalogueError(str(exc)) from exc
        return load_bundled_catalogue(ids)
    if path is not None and path.is_file():
        try:
            data = yaml.safe_load(path.read_text("utf-8")) or {}
        except yaml.YAMLError:
            data = {}
        if isinstance(data, dict) and "frameworks" in data:
            try:
                ids = parse_frameworks(data.get("frameworks"), default=None)
            except ValueError as exc:
                raise CatalogueError(str(exc)) from exc
            return load_bundled_catalogue(ids)
    return load_catalogue()


def cmd_init(args) -> int:
    out = Path(args.output)
    if out.exists() and not args.force:
        print(f"{out} already exists (use --force to overwrite)", file=sys.stderr)
        return 1
    catalogue = _catalogue(args)
    assessment = new_assessment(catalogue, name=args.name or "", base_dir=out.resolve().parent)
    save_assessment(assessment, catalogue, out)
    print(f"Created {out} with {len(catalogue.question_ids)} questions.")
    print(f"Fill it in by hand, or run: nis2check interview {out}")
    return 0


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def _ask_number(prompt: str, current):
    while True:
        raw = _ask(prompt, "" if current is None else str(current))
        if raw == "":
            return None
        try:
            return float(raw) if "." in raw else int(raw)
        except ValueError:
            print("  Please enter a number, or leave empty.")


def cmd_interview(args) -> int:
    path = Path(args.assessment)
    catalogue = _catalogue(args, path if path.exists() and not args.frameworks else None)
    if path.exists():
        assessment = load_assessment(path, catalogue)
    else:
        assessment = new_assessment(catalogue, base_dir=path.resolve().parent)

    e = assessment.entity
    try:
        if args.all or not e.name:
            print("\nOrganisation details (press Enter to keep the current value)\n")
            e.name = _ask("Organisation name", e.name)
            print("Sectors: " + ", ".join(sorted(SECTORS)) + ", other")
            e.sector = _ask("Sector", e.sector or "") or None
            e.employees = _ask_number("Employees", e.employees)
            e.annual_turnover_eur = _ask_number("Annual turnover (EUR)", e.annual_turnover_eur)
            e.balance_sheet_eur = _ask_number("Balance sheet total (EUR)", e.balance_sheet_eur)
            assessment.assessor = _ask("Assessor", assessment.assessor)
            save_assessment(assessment, catalogue, path)

        pending = [
            q for q in catalogue.questions()
            if args.all or assessment.responses[q.id].answer is None
        ]
        if not pending:
            print("All questions are answered. Use --all to revise them.")
            return 0

        print(
            f"\n{len(pending)} questions. Answer y(es), p(artial), n(o), na, "
            "s(kip) or q(uit). Progress is saved after each answer.\n"
        )
        for i, q in enumerate(pending, 1):
            domain = catalogue.domain(q.domain_id)
            r = assessment.responses[q.id]
            print(f"[{i}/{len(pending)}] {q.id} ({domain.article}, {q.priority})")
            print(f"  {q.text}")
            if q.evidence_hint:
                print(f"  Evidence: {q.evidence_hint}")
            while True:
                raw = _ask("  Answer", r.answer or "").lower()
                if raw in ("q", "quit"):
                    print(f"\nSaved to {path}.")
                    return 0
                if raw in ("s", "skip", ""):
                    break
                answer = ANSWER_KEYS.get(raw, raw)
                if answer in ("yes", "partial", "no", "na"):
                    r.answer = answer
                    if answer in ("yes", "partial"):
                        ev = _ask("  Evidence (comma-separated paths or URLs)", ", ".join(r.evidence))
                        r.evidence = [x.strip() for x in ev.split(",") if x.strip()]
                    r.notes = _ask("  Notes", r.notes)
                    save_assessment(assessment, catalogue, path)
                    break
                print("  Please answer y, p, n, na, s or q.")
            print()
    except (KeyboardInterrupt, EOFError):
        save_assessment(assessment, catalogue, path)
        print(f"\nStopped. Progress saved to {path}.")
        return 130

    print(f"Done. Saved to {path}. Next: nis2check report {path}")
    return 0


def cmd_report(args) -> int:
    catalogue = _catalogue(args, Path(args.assessment))
    assessment = load_assessment(args.assessment, catalogue)
    threat = load_threat_data(args.threat_data) if args.weighting == "threat" else None
    weights = compute_weights(catalogue, threat, args.weighting)
    result = evaluate(catalogue, assessment, weights, args.weighting, args.rank_by)

    out = Path(args.output) if args.output else Path(args.assessment).with_suffix(".html")
    html = render_html(result, assessment, catalogue, top=args.top, threat=threat)
    out.write_text(html, "utf-8")
    written = [("HTML report", out)]
    if args.pdf:
        write_pdf(render_html(result, assessment, catalogue, top=args.top, threat=threat,
                              embedded=True, font_css=fonts_css_uri()), args.pdf)
        written.append(("PDF report", args.pdf))
    if args.csv:
        Path(args.csv).write_text(render_csv(result, threat), "utf-8")
        written.append(("Gap register", args.csv))
    if args.json:
        Path(args.json).write_text(render_json(result, assessment, catalogue, threat), "utf-8")
        written.append(("JSON", args.json))
    if args.ciso:
        Path(args.ciso).write_bytes(export_zip(result, catalogue, assessment))
        written.append(("CISO Assistant", args.ciso))

    if not args.quiet:
        print(render_summary(result, assessment))
        label = f"threat-informed, {threat.version_label}" if threat else "regulatory baseline"
        print(f"Weighting:      {label}; ranked by {args.rank_by}")
        print()
        for label, path in written:
            print(f"{label + ':':<14}{path}")

    if args.fail_under is not None:
        score = (result.verified_pct if args.evidence_backed else result.score_pct) or 0
        if score < args.fail_under:
            print(f"\nScore {score:.0f}% is below --fail-under {args.fail_under}.", file=sys.stderr)
            return 2
    return 0


def cmd_update_threat_data(args) -> int:
    import datetime as dt

    from .threat.data import ThreatData
    from .threat.sources import SourceError
    from .threat.update import change_report, collect, write_threat_data

    # Review weights for every bundled framework, so a DORA control with a threat
    # link is in the change report too. --catalogue still replaces that.
    catalogue = load_catalogue(args.catalogue) if args.catalogue else load_bundled_catalogue(FRAMEWORK_IDS)
    out = Path(args.output)
    old = load_threat_data(out) if out.exists() else None
    today = dt.date.fromisoformat(args.date) if args.date else dt.date.today()
    try:
        data, warnings = collect(
            today,
            Path(args.source_dir) if args.source_dir else None,
            window_years=args.window_years,
            min_sample=args.min_sample,
        )
    except SourceError as exc:
        print(f"error: required source failed, threat data left unchanged: {exc}", file=sys.stderr)
        return 1

    new = ThreatData(data, str(out))
    report, changed = change_report(catalogue, old, new, warnings)
    if args.change_report:
        Path(args.change_report).write_text(report, "utf-8")
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    if not changed and old is not None:
        print("No changes in threat data.")
        return 0
    write_threat_data(data, out)
    print(f"Threat data written to {out}.")
    if args.change_report:
        print(f"Change report: {args.change_report}")
    return 0


def _web_app(args):
    try:
        from .web import create_app
    except ImportError as exc:  # pragma: no cover - optional extra
        raise RuntimeError("The web app needs extra packages: pip install 'nis2check[web]'") from exc
    return create_app(data_dir=args.data_dir, start_scheduler=False) if args.data_dir \
        else create_app(start_scheduler=False)


def cmd_web_serve(args) -> int:
    from .web import create_app

    app = create_app(data_dir=args.data_dir) if args.data_dir else create_app()
    print(f"nis2check web app on http://{args.host}:{args.port} (development server; use Docker in production)")
    app.run(host=args.host, port=args.port, debug=False)
    return 0


def cmd_web_import(args) -> int:
    from .web.manage import import_yaml

    counts = import_yaml(_web_app(args), args.assessment)
    print(f"Imported {counts['answers']} answers, {counts['files']} files, {counts['links']} links"
          + (f" ({counts['missing_files']} evidence files not found)" if counts["missing_files"] else "") + ".")
    return 0


def cmd_web_create_admin(args) -> int:
    import getpass

    from .web.manage import create_admin

    password = args.password or getpass.getpass("Password: ")
    try:
        create_admin(_web_app(args), args.email, password, args.name or "")
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Administrator {args.email} created.")
    return 0


def cmd_controls(args) -> int:
    catalogue = _catalogue(args)
    for d in catalogue.domains:
        print(f"{d.id:<5} {d.article:<15} {d.title}")
        for q in d.questions:
            print(f"   {q.id:<8} [{q.priority:<8}] {q.text}")
    print(f"\n{len(catalogue.question_ids)} questions in {len(catalogue.domains)} domains.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nis2check",
        description="NIS2 and DORA self-assessment, evidence tracking and gap reports.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("--catalogue", help="use a custom control catalogue (YAML) instead of the bundled frameworks")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create a blank assessment file")
    s.add_argument("-o", "--output", default="assessment.yaml")
    s.add_argument("--name", help="organisation name")
    s.add_argument("--frameworks", help="comma-separated frameworks: nis2, dora, or both (default: nis2)")
    s.add_argument("--force", action="store_true", help="overwrite an existing file")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("interview", help="answer the questionnaire interactively")
    s.add_argument("assessment", nargs="?", default="assessment.yaml")
    s.add_argument("--all", action="store_true", help="revisit answered questions too")
    s.add_argument("--frameworks", help="comma-separated frameworks: nis2, dora, or both (default: the file's frameworks, or nis2)")
    s.set_defaults(func=cmd_interview)

    s = sub.add_parser("report", help="score an assessment and write the gap report")
    s.add_argument("assessment")
    s.add_argument("-o", "--output", help="HTML output path (default: <assessment>.html)")
    s.add_argument("--pdf", help="also write a PDF report (needs: pip install 'nis2check[pdf]')")
    s.add_argument("--csv", help="also write the gap register as CSV (opens in Excel)")
    s.add_argument("--json", help="also write machine-readable JSON")
    s.add_argument("--ciso", help="also write a CISO Assistant import zip (library YAML and compliance-assessment CSV)")
    s.add_argument("--top", type=int, default=10, help="number of priority gaps to show")
    s.add_argument("--fail-under", type=float, help="exit 2 if the score is below this percentage")
    s.add_argument("--evidence-backed", action="store_true",
                   help="use the evidence-backed score for --fail-under")
    s.add_argument("--weighting", choices=["threat", "static"], default="threat",
                   help="threat: baseline raised by threat data (default); static: baseline only")
    s.add_argument("--threat-data", help="use this threat_data.yaml instead of the bundled snapshot")
    s.add_argument("--rank-by", choices=["risk", "value"], default="risk",
                   help="order open items by risk reduction (default) or risk reduction per effort")
    s.add_argument("--frameworks", help="comma-separated frameworks: nis2, dora, or both (default: the file's frameworks, or nis2)")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("update-threat-data", help="refresh threat data from VCDB, ATT&CK, CISA KEV, ENISA EUVD")
    s.add_argument("-o", "--output", default="nis2check/data/threat_data.yaml",
                   help="threat data file to write (default: the bundled snapshot in a source checkout)")
    s.add_argument("--change-report", help="write a markdown summary of changes (e.g. for a pull request)")
    s.add_argument("--source-dir", help="read source files from a directory instead of downloading")
    s.add_argument("--window-years", type=int, default=5, help="VCDB window in years (default 5)")
    s.add_argument("--min-sample", type=int, default=300,
                   help="widen the VCDB window until it has this many events (default 300)")
    s.add_argument("--date", help="reference date YYYY-MM-DD (default: today)")
    s.set_defaults(func=cmd_update_threat_data)

    web = sub.add_parser("web", help="run or manage the self-hosted web app")
    web_sub = web.add_subparsers(dest="web_command", required=True)
    s = web_sub.add_parser("serve", help="start the web app (development server)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--data-dir", help="data folder (default: NIS2_DATA_DIR or ./data)")
    s.set_defaults(func=cmd_web_serve)
    s = web_sub.add_parser("import", help="import a YAML assessment into the web app")
    s.add_argument("assessment")
    s.add_argument("--data-dir")
    s.set_defaults(func=cmd_web_import)
    s = web_sub.add_parser("create-admin", help="create an administrator without the setup page")
    s.add_argument("email")
    s.add_argument("--name")
    s.add_argument("--password", help="prompted for if omitted")
    s.add_argument("--data-dir")
    s.set_defaults(func=cmd_web_create_admin)

    s = sub.add_parser("controls", help="list the controls in the selected frameworks")
    s.add_argument("--frameworks", help="comma-separated frameworks: nis2, dora, or both (default: nis2)")
    s.set_defaults(func=cmd_controls)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (AssessmentError, CatalogueError, FileNotFoundError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

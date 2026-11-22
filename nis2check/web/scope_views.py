"""Public NIS2 scope wizard.

Anyone can run the check. An administrator who is signed in can copy the
sector, size and size-exempt flag onto the organisation and open the assessment.
"""

from __future__ import annotations

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for

from ..scope import ScopeRulesError, assess_scope, cached_scope_rules
from .auth import require
from .services import audit, organisation

bp = Blueprint("scope", __name__)

SESSION_KEY = "scope_wizard"


def _blank() -> dict:
    return {
        "subsector_id": "",
        "employees": "",
        "annual_turnover_eur": "",
        "balance_sheet_eur": "",
        "special": [],
        "ready": False,
    }


def _number(field: str, cast):
    raw = request.form.get(field, "").strip().replace(" ", "").replace(",", "")
    if not raw:
        return None, ""
    try:
        value = cast(raw)
    except ValueError:
        raise ValueError(field) from None
    if value < 0:
        raise ValueError(field)
    return value, raw


def _read_form() -> dict:
    employees, employees_raw = _number("employees", int)
    turnover, turnover_raw = _number("annual_turnover_eur", float)
    balance, balance_raw = _number("balance_sheet_eur", float)
    # int() accepts "10.0" on some paths only as a failure; reject a fractional staff figure
    # so the number stored on the organisation (an integer column) is the number that was checked.
    if employees_raw and any(mark in employees_raw for mark in ".eE"):
        raise ValueError("employees")
    return {
        "subsector_id": request.form.get("subsector_id", "").strip(),
        "employees": employees_raw,
        "employees_value": employees,
        "annual_turnover_eur": turnover_raw,
        "turnover_value": turnover,
        "balance_sheet_eur": balance_raw,
        "balance_value": balance,
        "special": [item for item in request.form.getlist("special") if item],
        "ready": True,
    }


def _result_from(form: dict):
    return assess_scope(
        subsector_id=form.get("subsector_id") or None,
        employees=form.get("employees_value"),
        annual_turnover_eur=form.get("turnover_value"),
        balance_sheet_eur=form.get("balance_value"),
        special_case_ids=form.get("special") or [],
    )


def _restore_values(form: dict) -> dict:
    """Session stores the raw fields. Re-parse them when the result is shown again."""
    def cast(raw, kind):
        if raw in ("", None):
            return None
        return kind(raw)

    return {
        **form,
        "employees_value": cast(form.get("employees"), int),
        "turnover_value": cast(form.get("annual_turnover_eur"), float),
        "balance_value": cast(form.get("balance_sheet_eur"), float),
    }


@bp.route("/scope", methods=["GET", "POST"])
def wizard():
    rules = cached_scope_rules()
    form = dict(session.get(SESSION_KEY) or _blank())
    result = None
    if request.method == "POST":
        try:
            form = _read_form()
        except ValueError as exc:
            flash(f"Enter a number for {str(exc).replace('_', ' ')}.", "error")
            form = _blank()
            form["subsector_id"] = request.form.get("subsector_id", "")
            form["special"] = request.form.getlist("special")
        else:
            try:
                result = _result_from(form)
            except ScopeRulesError:
                flash("Choose a sector and any special cases from the list.", "error")
            else:
                session[SESSION_KEY] = {
                    "subsector_id": form["subsector_id"],
                    "employees": form["employees"],
                    "annual_turnover_eur": form["annual_turnover_eur"],
                    "balance_sheet_eur": form["balance_sheet_eur"],
                    "special": form["special"],
                    "ready": True,
                }
                session.modified = True
    elif form.get("ready"):
        try:
            result = _result_from(_restore_values(form))
        except (ScopeRulesError, ValueError):
            session.pop(SESSION_KEY, None)
            form = _blank()
    return render_template("scope_wizard.html", rules=rules, form=form, result=result)


@bp.route("/scope/apply", methods=["POST"])
@require("admin")
def apply_result():
    stored = session.get(SESSION_KEY)
    if not stored or not stored.get("ready"):
        flash("Run the scope check first.", "error")
        return redirect(url_for("scope.wizard"))
    try:
        result = _result_from(_restore_values(stored))
    except (ScopeRulesError, ValueError):
        flash("Run the scope check again.", "error")
        return redirect(url_for("scope.wizard"))

    values = _restore_values(stored)
    db = current_app.extensions["nis2_db"]()
    org = organisation(db)
    if result.organisation_sector:
        org.sector = result.organisation_sector
    org.employees = values["employees_value"]
    org.annual_turnover_eur = values["turnover_value"]
    org.balance_sheet_eur = values["balance_value"]
    org.size_exempt = result.size_exempt
    audit(db, "organisation.updated", org.name or result.sector_title, f"scope wizard: {result.outcome}")
    db.commit()
    flash(
        f"Assessment started from the scope wizard ({result.label.lower()}). "
        "The organisation page keeps the shorter size-cap check; the full reasoning stays on the scope page.",
        "ok",
    )
    return redirect(url_for("main.assessment_index"))

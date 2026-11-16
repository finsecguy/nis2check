"""Administration: users, settings, threat data approvals, audit log."""

from __future__ import annotations

import html
import re

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for
from markupsafe import Markup
from sqlalchemy import func, select

from .auth import hash_password, require, temporary_password
from .models import ROLES, AuditLog, ThreatDataVersion, User, utcnow
from .services import (
    active_threat_data, audit, check_running, current_app_parts, get_setting, set_setting, start_threat_check,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _admins(db) -> int:
    return db.execute(
        select(func.count(User.id)).where(User.role == "admin", User.active.is_(True))
    ).scalar() or 0


# ------------------------------------------------------------------ users

@bp.route("/users", methods=["GET", "POST"])
@require("admin")
def users():
    db, _c, settings = current_app_parts()
    temp = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "viewer")
        method = request.form.get("method", "sso" if settings.oidc_providers else "local")
        if not email or "@" not in email or role not in ROLES:
            flash("Enter a valid email address and role.", "error")
        elif db.execute(select(User).where(User.email == email)).scalar_one_or_none():
            flash("A user with that email already exists.", "error")
        else:
            user = User(email=email, name=request.form.get("name", "").strip(), role=role)
            if method == "local":
                temp = temporary_password()
                user.password_hash = hash_password(temp)
                user.must_change_password = True
            db.add(user)
            audit(db, "user.created", email, f"role {role}, {method}")
            db.commit()
            flash(f"{email} added.", "ok")
            if temp:
                flash(f"Temporary password for {email}: {temp} (shown once; they must change it at first sign-in).",
                      "secret")
            return redirect(url_for("admin.users"))
    all_users = db.execute(select(User).order_by(User.role, User.email)).scalars().all()
    return render_template("admin_users.html", users=all_users, roles=ROLES, settings=settings)


@bp.route("/users/<int:uid>", methods=["POST"])
@require("admin")
def update_user(uid: int):
    db, _c, _s = current_app_parts()
    user = db.get(User, uid)
    if user is None:
        abort(404)
    action = request.form.get("action")
    is_last_admin = user.role == "admin" and user.active and _admins(db) <= 1

    if action == "role":
        role = request.form.get("role")
        if role not in ROLES:
            abort(400)
        if is_last_admin and role != "admin":
            flash("You cannot remove the last administrator.", "error")
        else:
            audit(db, "user.role_changed", user.email, f"{user.role} -> {role}")
            user.role = role
            flash(f"{user.email} is now {role}.", "ok")
    elif action == "deactivate":
        if is_last_admin:
            flash("You cannot deactivate the last administrator.", "error")
        elif user.id == g.user.id:
            flash("You cannot deactivate yourself.", "error")
        else:
            user.active = False
            audit(db, "user.deactivated", user.email)
            flash(f"{user.email} deactivated.", "ok")
    elif action == "activate":
        user.active = True
        audit(db, "user.activated", user.email)
        flash(f"{user.email} reactivated.", "ok")
    elif action == "reset_password":
        temp = temporary_password()
        user.password_hash = hash_password(temp)
        user.must_change_password = True
        audit(db, "user.password_reset", user.email)
        flash(f"Temporary password for {user.email}: {temp} (shown once).", "secret")
    elif action == "unlink_sso":
        user.sso_subject = None
        audit(db, "user.sso_unlinked", user.email)
        flash(f"Single sign-on link removed for {user.email}. Their next SSO sign-in will link again.", "ok")
    else:
        abort(400)
    db.commit()
    return redirect(url_for("admin.users"))


# ------------------------------------------------------------------ settings

@bp.route("/settings", methods=["GET", "POST"])
@require("admin")
def settings_page():
    db, _c, settings = current_app_parts()
    if request.method == "POST":
        weighting = request.form.get("weighting")
        rank_by = request.form.get("rank_by")
        if weighting not in ("threat", "static") or rank_by not in ("risk", "value"):
            abort(400)
        auto = "1" if request.form.get("threat_auto_check") == "on" else "0"
        for key, value in (("weighting", weighting), ("rank_by", rank_by), ("threat_auto_check", auto)):
            if get_setting(db, key) != value:
                audit(db, "setting.changed", key, value)
                set_setting(db, key, value)
        db.commit()
        flash("Settings saved.", "ok")
        return redirect(url_for("admin.settings_page"))
    return render_template(
        "admin_settings.html",
        weighting=get_setting(db, "weighting", "threat"),
        rank_by=get_setting(db, "rank_by", "risk"),
        auto=get_setting(db, "threat_auto_check", "1") == "1",
        settings=settings,
    )


# ------------------------------------------------------------------ threat data

def markdown_to_html(md: str) -> Markup:
    """Small renderer for the change report (headings, bullets, tables, rules). Escapes all text."""
    out, in_list, table = [], False, []

    def flush_table():
        if not table:
            return
        rows = [r for r in table if not re.fullmatch(r"\|?\s*-[-|\s]*", r)]
        cells = [[html.escape(c.strip()) for c in r.strip().strip("|").split("|")] for r in rows]
        head, body = cells[0], cells[1:]
        parts = ["<table><thead><tr>", *[f"<th>{c}</th>" for c in head], "</tr></thead><tbody>"]
        for row in body:
            flag = ' class="flag"' if "FLAG" in row else ""
            parts.append(f"<tr{flag}>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>")
        parts.append("</tbody></table>")
        out.append("".join(parts))
        table.clear()

    for line in md.splitlines():
        if line.startswith("|"):
            table.append(line)
            continue
        flush_table()
        if in_list and not line.startswith("- "):
            out.append("</ul>")
            in_list = False
        if line.startswith("### "):
            out.append(f"<h4>{html.escape(line[4:])}</h4>")
        elif line.startswith("## "):
            out.append(f"<h3>{html.escape(line[3:])}</h3>")
        elif line.startswith("- "):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{html.escape(line[2:])}</li>")
        elif line.strip() == "---":
            out.append("<hr>")
        elif line.strip():
            out.append(f"<p>{html.escape(line)}</p>")
    flush_table()
    if in_list:
        out.append("</ul>")
    return Markup("\n".join(out))


@bp.route("/threat-data")
@require("admin")
def threat_data():
    db, _c, settings = current_app_parts()
    pending = db.execute(
        select(ThreatDataVersion).where(ThreatDataVersion.status == "pending")
        .order_by(ThreatDataVersion.fetched_at.desc())
    ).scalars().first()
    history = db.execute(
        select(ThreatDataVersion).order_by(ThreatDataVersion.fetched_at.desc()).limit(20)
    ).scalars().all()
    return render_template(
        "admin_threat.html",
        active=active_threat_data(db),
        pending=pending,
        pending_html=markdown_to_html(pending.change_report) if pending else None,
        history=history,
        running=check_running(),
        last_check=get_setting(db, "threat_last_check", ""),
        auto=get_setting(db, "threat_auto_check", "1") == "1",
        settings=settings,
    )


@bp.route("/threat-data/check", methods=["POST"])
@require("admin")
def threat_check():
    db, _c, _s = current_app_parts()
    if start_threat_check(current_app._get_current_object(), g.user.email):
        audit(db, "threat_data.check_started", actor=g.user.email)
        db.commit()
        flash("Checking the sources. This takes a minute or two; reload this page to see the result.", "ok")
    else:
        flash("A check is already running.", "error")
    return redirect(url_for("admin.threat_data"))


@bp.route("/threat-data/<int:vid>/<decision>", methods=["POST"])
@require("admin")
def threat_decide(vid: int, decision: str):
    db, _c, _s = current_app_parts()
    version = db.get(ThreatDataVersion, vid)
    if version is None or version.status != "pending" or decision not in ("approve", "reject"):
        abort(404)
    version.reviewed_by, version.reviewed_at = g.user.email, utcnow()
    if decision == "approve":
        for old in db.execute(
            select(ThreatDataVersion).where(ThreatDataVersion.status == "active")
        ).scalars():
            old.status = "superseded"
        version.status = "active"
        flash("Threat data update approved. New reports use the updated weights.", "ok")
    else:
        version.status = "rejected"
        flash("Threat data update rejected. Current weights are unchanged.", "ok")
    audit(db, f"threat_data.{decision}d", f"update #{vid}")
    db.commit()
    return redirect(url_for("admin.threat_data"))


# ------------------------------------------------------------------ audit log

@bp.route("/audit")
@require("admin")
def audit_log():
    db, _c, _s = current_app_parts()
    q = request.args.get("q", "").strip()
    stmt = select(AuditLog).order_by(AuditLog.ts.desc()).limit(500)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            AuditLog.actor.ilike(like) | AuditLog.action.ilike(like) | AuditLog.target.ilike(like)
        )
    return render_template("admin_audit.html", entries=db.execute(stmt).scalars().all(), q=q)

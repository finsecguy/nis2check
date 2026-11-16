"""Login, first-run setup, single sign-on (Entra ID, Google) and role checks."""

from __future__ import annotations

import functools
import secrets
import time
from collections import defaultdict, deque

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import func, select
from werkzeug.security import check_password_hash, generate_password_hash

from .models import User, utcnow
from .services import audit, organisation

bp = Blueprint("auth", __name__)

MIN_PASSWORD = 12
MAX_FAILURES, WINDOW_SECONDS = 10, 15 * 60
MAX_FAILURES_PER_ACCOUNT = 30  # across all addresses, against distributed guessing
_failures: dict[str, deque] = defaultdict(deque)


class SSOError(Exception):
    """Sign-in through SSO was refused; the message is safe to show to the user."""


# ------------------------------------------------------------------ helpers

def hash_password(password: str) -> str:
    return generate_password_hash(password, method="scrypt")


def password_problem(password: str) -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters."
    if password.lower() == password or password.upper() == password:
        return "Use a mix of upper- and lower-case letters."
    return None


def temporary_password() -> str:
    return secrets.token_urlsafe(12) + "Aa1"


def _client_ip() -> str:
    # remote_addr is the real peer; behind a reverse proxy, ProxyFix (NIS2_BEHIND_PROXY) sets it
    return request.remote_addr or ""


def _recent(key: str) -> int:
    q = _failures[key]
    now = time.monotonic()
    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()
    return len(q)


def _throttled(email: str) -> bool:
    return (_recent(f"{_client_ip()}|{email}") >= MAX_FAILURES
            or _recent(f"account|{email}") >= MAX_FAILURES_PER_ACCOUNT)


def _record_failure(email: str) -> None:
    now = time.monotonic()
    _failures[f"{_client_ip()}|{email}"].append(now)
    _failures[f"account|{email}"].append(now)


def _safe_next(nxt: str) -> str:
    """A post-login redirect target that stays on this site.

    Only same-site absolute paths are allowed. Reject scheme-relative URLs (``//evil``),
    backslash tricks (``/\\evil``) and embedded control characters (tab, CR, LF), all of
    which browsers strip or normalise into an off-site ``//evil`` target.
    """
    if (nxt.startswith("/") and not nxt.startswith("//")
            and "\\" not in nxt and all(ord(c) >= 0x20 for c in nxt)):
        return nxt
    return url_for("main.dashboard")


def login_user(user: User) -> None:
    session.clear()
    session["uid"] = user.id
    session["csrf_seed"] = secrets.token_hex(8)
    session.permanent = True
    user.last_login = utcnow()


def require(action: str):
    """Decorator: the signed-in user must be allowed to `view`, `edit` or `admin`."""
    def deco(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            user = g.get("user")
            if user is None:
                return redirect(url_for("auth.login", next=request.full_path))
            if user.must_change_password and request.endpoint != "auth.change_password":
                return redirect(url_for("auth.change_password"))
            if not user.can(action):
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return deco


def users_exist(db) -> bool:
    return (db.execute(select(func.count(User.id))).scalar() or 0) > 0


# ------------------------------------------------------------------ SSO account matching

def _email_verified(provider: str, claims: dict) -> bool:
    """Whether the provider actually attests that this email belongs to the user.

    Google sets ``email_verified``. Entra ID does *not* verify the ``email`` claim by
    default (the "nOAuth" problem): a tenant can put any address there, so matching on
    it alone would let an attacker link to an existing account. Entra signals a trusted
    address via ``xms_edov`` ("email domain owner verified"). If neither is present we
    treat the address as unverified.
    """
    def _true(value) -> bool:
        return value is True or str(value).lower() == "true"

    if _true(claims.get("email_verified")):
        return True
    # xms_edov vouches for the `email` claim specifically, so ignore it when the address
    # had to be taken from the preferred_username fallback instead.
    if provider != "google" and _true(claims.get("xms_edov")) and claims.get("email"):
        return True
    return False


def resolve_sso_user(db, settings, provider: str, claims: dict) -> User:
    """Match an SSO identity to a user account, or refuse.

    - the email must not be flagged unverified, and, if configured, must be in an allowed domain;
    - an existing account is linked to the SSO identity only on a verified email, and from
      then on only that identity can use it (so an unverified email cannot take it over);
    - unknown users are refused unless automatic provisioning is on, in which case they
      get the default role in a brand-new account that no existing account's data is at risk from.
    """
    email = (claims.get("email") or claims.get("preferred_username") or "").strip().lower()
    if not email or "@" not in email:
        raise SSOError("Your identity provider did not share an email address.")
    # If the provider explicitly says the address is unverified, never trust it.
    if str(claims.get("email_verified")).lower() == "false":
        raise SSOError("Your email address is not verified by your identity provider.")
    if provider == "google" and claims.get("email_verified") is not True:
        raise SSOError("Your Google email address is not verified.")
    verified = _email_verified(provider, claims)
    domain = email.rsplit("@", 1)[1]
    if settings.oidc_allowed_domains and domain not in settings.oidc_allowed_domains:
        raise SSOError(f"Accounts from {domain} are not allowed to sign in.")
    subject = f"{provider}:{claims.get('sub') or claims.get('oid')}"

    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is None:
        if not settings.oidc_auto_provision:
            raise SSOError("You do not have an account yet. Ask an administrator to add you.")
        # A brand-new account gets the default (low) role and puts no existing account at
        # risk; the domain allow-list is the guard here, so we do not require xms_edov.
        user = User(email=email, name=claims.get("name", ""), role=settings.oidc_default_role,
                    sso_subject=subject)
        db.add(user)
        db.flush()
        audit(db, "user.created_by_sso", email, f"role {user.role}", actor=email)
        return user
    if not user.active:
        raise SSOError("Your account is deactivated.")
    if user.sso_subject and user.sso_subject != subject:
        raise SSOError("This account is linked to a different sign-in identity.")
    if not user.sso_subject:
        # First SSO sign-in for a pre-existing account (e.g. the local setup admin).
        # Only bind it to this identity when the provider has verified the address,
        # otherwise anyone able to mint an unverified token for it takes the account over.
        if not verified:
            raise SSOError(
                "Your identity provider has not verified your email address, so it cannot "
                "be linked to an existing account. Ask an administrator for help."
            )
        user.sso_subject = subject
        audit(db, "user.sso_linked", email, provider, actor=email)
    if not user.name and claims.get("name"):
        user.name = claims["name"]
    return user


# ------------------------------------------------------------------ routes

@bp.route("/setup", methods=["GET", "POST"])
def setup():
    db = current_app.extensions["nis2_db"]()
    if users_exist(db):
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        org_name = request.form.get("org_name", "").strip()
        problem = password_problem(password)
        if not email or "@" not in email:
            flash("Enter a valid email address.", "error")
        elif problem:
            flash(problem, "error")
        elif password != request.form.get("password2", ""):
            flash("The passwords do not match.", "error")
        else:
            user = User(email=email, name=name, role="admin", password_hash=hash_password(password))
            db.add(user)
            organisation(db).name = org_name
            db.flush()
            audit(db, "setup.completed", email, actor=email)
            login_user(user)
            db.commit()
            flash("Setup complete. Start by checking your organisation details.", "ok")
            return redirect(url_for("main.organisation_page"))
    return render_template("setup.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    db = current_app.extensions["nis2_db"]()
    settings = current_app.extensions["nis2_settings"]
    if not users_exist(db):
        return redirect(url_for("auth.setup"))
    if request.method == "POST":
        if not settings.local_login:
            abort(404)
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if _throttled(email):
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html", providers=settings.oidc_providers, local=settings.local_login), 429
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user and user.active and user.password_hash and check_password_hash(user.password_hash, password):
            login_user(user)
            audit(db, "login", email, "local", actor=email)
            db.commit()
            return redirect(_safe_next(request.args.get("next", "")))
        _record_failure(email)
        audit(db, "login.failed", email, "local", actor=email or "unknown")
        db.commit()
        flash("Wrong email or password.", "error")
    return render_template("login.html", providers=settings.oidc_providers, local=settings.local_login)


@bp.route("/logout", methods=["POST"])
def logout():
    if g.get("user"):
        db = current_app.extensions["nis2_db"]()
        audit(db, "logout", g.user.email)
        db.commit()
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/account/password", methods=["GET", "POST"])
@require("view")
def change_password():
    db = current_app.extensions["nis2_db"]()
    user = g.user
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("password", "")
        problem = password_problem(new)
        if user.password_hash and not check_password_hash(user.password_hash, current):
            flash("Your current password is wrong.", "error")
        elif problem:
            flash(problem, "error")
        elif new != request.form.get("password2", ""):
            flash("The new passwords do not match.", "error")
        else:
            user.password_hash = hash_password(new)
            user.must_change_password = False
            audit(db, "password.changed", user.email)
            db.commit()
            flash("Password changed.", "ok")
            return redirect(url_for("main.dashboard"))
    return render_template("change_password.html")


@bp.route("/sso/<provider>")
def sso_start(provider: str):
    oauth = current_app.extensions.get("nis2_oauth")
    client = oauth.create_client(provider) if oauth else None
    if client is None:
        abort(404)
    settings = current_app.extensions["nis2_settings"]
    base = settings.base_url or request.host_url.rstrip("/")
    # Authlib adds state and nonce and checks both on the callback
    return client.authorize_redirect(f"{base}{url_for('auth.sso_callback', provider=provider)}")


@bp.route("/sso/<provider>/callback")
def sso_callback(provider: str):
    oauth = current_app.extensions.get("nis2_oauth")
    client = oauth.create_client(provider) if oauth else None
    if client is None:
        abort(404)
    db = current_app.extensions["nis2_db"]()
    settings = current_app.extensions["nis2_settings"]
    try:
        token = client.authorize_access_token()  # validates state, ID token signature, issuer, nonce
        claims = token.get("userinfo") or {}
        user = resolve_sso_user(db, settings, provider, dict(claims))
    except SSOError as exc:
        db.rollback()
        audit(db, "login.sso_refused", detail=str(exc), actor="unknown")
        db.commit()
        flash(str(exc), "error")
        return redirect(url_for("auth.login"))
    except Exception:  # token exchange or validation failed
        current_app.logger.exception("SSO callback failed")
        flash("Single sign-on failed. Try again or contact your administrator.", "error")
        return redirect(url_for("auth.login"))
    login_user(user)
    audit(db, "login", user.email, provider, actor=user.email)
    db.commit()
    return redirect(url_for("main.dashboard"))

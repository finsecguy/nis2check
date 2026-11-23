"""nis2check web app: a self-hosted NIS2 gap assessment for the whole team."""

from __future__ import annotations

import datetime as dt
import mimetypes
import os
import threading

from flask import Flask, g, render_template, session
from flask_wtf.csrf import CSRFError, CSRFProtect

from .. import __version__
from ..frameworks import FRAMEWORK_IDS, LEX_SPECIALIS, framework_label, load_bundled_catalogue
from ..i18n import t
from ..jurisdictions import COUNTRY_LANGUAGE, question_text
from .config import load_settings
from .models import ROLE_LABELS, User, make_session

csrf = CSRFProtect()

# Guarantee the manifest's type on minimal images that lack it, so nosniff does not reject it.
mimetypes.add_type("application/manifest+json", ".webmanifest")


def create_app(**overrides) -> Flask:
    # Import before create_all so an existing database gains the incident tables.
    from . import incident_models as _incident_models  # noqa: F401
    start_scheduler = overrides.pop("start_scheduler", os.environ.get("NIS2_DISABLE_SCHEDULER") != "1")
    settings = load_settings(**overrides)

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=settings.secret_key,
        MAX_CONTENT_LENGTH=settings.max_upload_mb * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.secure_cookies,
        SESSION_COOKIE_NAME="nis2check_session",
        PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=12),
        WTF_CSRF_TIME_LIMIT=None,
        TEMPLATES_AUTO_RELOAD=False,
    )

    if settings.behind_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Registers the gap-owner table before create_all runs inside make_session.
    from . import board_models as _board_models  # noqa: F401
    db = make_session(settings.db_url)
    app.extensions["nis2_db"] = db
    app.extensions["nis2_settings"] = settings
    app.extensions["nis2_catalogue"] = load_bundled_catalogue(FRAMEWORK_IDS)
    from .auth import ensure_setup_token
    ensure_setup_token(db)
    csrf.init_app(app)

    if settings.oidc_providers:
        from authlib.integrations.flask_client import OAuth

        oauth = OAuth(app)
        for p in settings.oidc_providers:
            oauth.register(
                name=p.key,
                client_id=p.client_id,
                client_secret=p.client_secret,
                server_metadata_url=p.discovery_url,
                client_kwargs={"scope": "openid email profile"},
            )
        app.extensions["nis2_oauth"] = oauth

    from . import admin, auth, scope_views, views
    app.register_blueprint(auth.bp)
    app.register_blueprint(scope_views.bp)
    app.register_blueprint(views.bp)
    app.register_blueprint(admin.bp)

    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("uid")
        if uid:
            user = db().get(User, uid)
            # session["sv"] must still match the user's token; a password change or
            # reset rotates the token and so invalidates sessions opened before it.
            if user and user.active and session.get("sv") == user.session_token:
                g.user = user
            else:
                session.clear()
        g.lang = "en"
        if g.user:
            from .services import organisation
            org = organisation(db())
            g.lang = (g.user.language or "").strip().lower() or COUNTRY_LANGUAGE.get(org.country_code, "en")

    @app.teardown_appcontext
    def remove_session(_exc=None):
        db.remove()

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; frame-ancestors 'self'; form-action 'self' https://login.microsoftonline.com "
            "https://accounts.google.com; base-uri 'none'",
        )
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        if settings.secure_cookies:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return resp

    from . import board_views
    app.register_blueprint(board_views.bp)

    from ..report import _pct, rag
    app.jinja_env.filters["pct"] = _pct
    app.jinja_env.filters["rag"] = rag

    def humanize(action: str) -> str:
        text = action.replace("threat_data", "threat data").replace(".", " ").replace("_", " ")
        return text[:1].upper() + text[1:]

    def filesize(n: int | None) -> str:
        if not n:
            return "0 KB"
        return f"{n} bytes" if n < 1024 else f"{n / 1024:.0f} KB" if n < 1024 ** 2 else f"{n / 1024 ** 2:.1f} MB"

    app.jinja_env.filters["humanize"] = humanize
    app.jinja_env.filters["filesize"] = filesize
    app.jinja_env.filters["qtext"] = lambda question: question_text(
        question, getattr(g, "lang", None) or "en",
    )

    @app.context_processor
    def globals_():
        org_name = ""
        framework_ids = ("nis2",)
        org_country = "eu"
        if g.get("user"):
            from .services import organisation
            org = organisation(db())
            org_name = org.name
            framework_ids = org.framework_ids
            org_country = org.country_code
        lang = getattr(g, "lang", None) or "en"
        return {"current_user": g.get("user"), "role_labels": ROLE_LABELS, "app_version": __version__,
                "org_name": org_name, "framework_ids": framework_ids,
                "framework_label": framework_label(framework_ids), "lex_specialis": LEX_SPECIALIS,
                "org_country": org_country,
                "tr": lambda key, **kwargs: t(key, lang, **kwargs), "lang": lang}

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403, message="You do not have permission to do that."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="Page not found."), 404

    @app.errorhandler(413)
    def too_large(_e):
        return render_template("error.html", code=413,
                               message=f"The file is larger than {settings.max_upload_mb} MB."), 413

    @app.errorhandler(CSRFError)
    def csrf_error(_e):
        return render_template("error.html", code=400,
                               message="Your session expired. Go back, reload the page and try again."), 400

    @app.route("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    if start_scheduler:
        from .services import scheduler
        threading.Thread(target=scheduler, args=(app,), name="nis2-scheduler", daemon=True).start()

    from . import incident_views
    app.register_blueprint(incident_views.bp)

    return app

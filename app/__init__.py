from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object("app.config.Config")

    db.init_app(app)

    # Check guidance is shared by every template (and, later, report exports),
    # so it lives on the Jinja environment rather than being passed per-route.
    from app.services import formatting, remediation
    app.jinja_env.globals["CHECK_GUIDANCE"] = remediation.GUIDANCE
    app.jinja_env.globals["severity_of"] = remediation.severity_of
    formatting.register(app)

    # The tenant switcher lives in base.html, so every view needs these without
    # each route having to pass them. Failures are swallowed: the switcher is
    # chrome, and a missing tenants table on first boot must not 500 every page.
    @app.context_processor
    def _tenant_context():
        from app.auth.graph_auth import get_active_tenant
        from app.models.tenant import Tenant

        def all_tenants():
            try:
                return Tenant.query.order_by(Tenant.name).all()
            except Exception:
                return []

        try:
            current = get_active_tenant()
        except Exception:
            current = None

        return {"ACTIVE_TENANTS": all_tenants, "CURRENT_TENANT": current}

    with app.app_context():
        from app.models import report, tenant  # noqa: F401
        db.create_all()

        # Move a legacy config.json tenant into the tenants table so existing
        # installs keep working without re-entering credentials.
        from app.auth.graph_auth import import_legacy_config
        try:
            import_legacy_config()
        except Exception:
            # Never block startup on this; the tenants page can be used instead.
            db.session.rollback()

        from app.routes import (landing, dashboard, security, licensing, users, sharepoint,
                                exchange, groups, reports, settings, tenants)
        app.register_blueprint(tenants.bp)
        app.register_blueprint(landing.bp)
        app.register_blueprint(dashboard.bp)
        app.register_blueprint(security.bp)
        app.register_blueprint(licensing.bp)
        app.register_blueprint(users.bp)
        app.register_blueprint(sharepoint.bp)
        app.register_blueprint(exchange.bp)
        app.register_blueprint(groups.bp)
        app.register_blueprint(reports.bp)
        app.register_blueprint(settings.bp)

    return app

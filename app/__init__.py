from flask import Flask
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object("app.config.Config")

    db.init_app(app)

    with app.app_context():
        from app.models import report  # noqa: F401
        db.create_all()

        from app.routes import dashboard, security, licensing, users, sharepoint, exchange, groups, reports, settings
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

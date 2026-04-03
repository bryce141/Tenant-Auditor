from flask import Blueprint, render_template, redirect, url_for
from app.auth.graph_auth import has_credentials

bp = Blueprint("landing", __name__)


@bp.route("/")
def index():
    if has_credentials():
        return redirect(url_for("dashboard.index"))
    return render_template("landing.html")


@bp.route("/landing")
def preview():
    return render_template("landing.html")

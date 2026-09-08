"""Sign-in, sign-out, and first-run administrator setup."""
from urllib.parse import urlparse

from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)

from app import db
from app.auth.session_auth import (clear_failures, log_in, log_out,
                                   lockout_remaining, record_failure)
from app.models.user import AdminUser, any_admin_exists, password_problem
from app.utils import utcnow

bp = Blueprint("auth", __name__)


def _safe_next(target):
    """Only redirect within this site.

    An attacker-supplied ?next= pointing elsewhere turns the login page into an
    open redirect, which is a convincing phishing primitive.
    """
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    if not target.startswith("/") or target.startswith("//"):
        return None
    return target


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    """Create the administrator. Only reachable while none exists."""
    if any_admin_exists():
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if not username:
            flash("Choose a username.", "error")
        elif password != confirm:
            flash("The passwords don't match.", "error")
        else:
            problem = password_problem(password)
            if problem:
                flash(problem, "error")
            else:
                user = AdminUser(username=username)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                log_in(user)
                return redirect(url_for("dashboard.index"))

    return render_template("auth/setup.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        remaining = lockout_remaining()
        if remaining:
            flash(f"Too many attempts. Try again in {remaining // 60 + 1} minute(s).", "error")
            return render_template("auth/login.html"), 429

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = AdminUser.query.filter_by(username=username).first()
        if user and user.check_password(password):
            clear_failures()
            log_in(user)
            user.last_login_at = utcnow()
            db.session.commit()
            return redirect(_safe_next(request.args.get("next")) or url_for("dashboard.index"))

        record_failure()
        # Deliberately identical whether the username exists or not, so the
        # response can't be used to enumerate accounts.
        flash("Incorrect username or password.", "error")

    return render_template("auth/login.html")


@bp.route("/logout", methods=["POST"])
def logout():
    log_out()
    return redirect(url_for("auth.login"))

"""Firm branding for client-facing reports.

Tenant credentials used to live here. They moved to /tenants when the app
became multi-tenant, and leaving the old form in place was worse than useless:
saving it wrote a config.json that the Tenant row takes precedence over, so
edits appeared to succeed and changed nothing.
"""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from app import db
from app.models.branding import (encode_logo, get_branding, logo_problem,
                                 normalise_colour)

bp = Blueprint("settings", __name__, url_prefix="/settings")


@bp.route("/")
def index():
    return render_template("settings/index.html", branding=get_branding())


@bp.route("/branding", methods=["POST"])
def save_branding():
    branding = get_branding()

    branding.firm_name = (request.form.get("firm_name") or "").strip() or None
    branding.contact_email = (request.form.get("contact_email") or "").strip() or None
    branding.contact_phone = (request.form.get("contact_phone") or "").strip() or None
    branding.website = (request.form.get("website") or "").strip() or None
    branding.footer_note = (request.form.get("footer_note") or "").strip() or None

    colour_input = request.form.get("accent_colour") or ""
    if colour_input.strip():
        colour = normalise_colour(colour_input)
        if colour is None:
            flash("Accent colour must be a hex code like #2563eb.", "error")
            return redirect(url_for("settings.index"))
        branding.accent_colour = colour
    else:
        branding.accent_colour = None

    if request.form.get("remove_logo") == "yes":
        branding.logo_data_uri = None
    else:
        upload = request.files.get("logo")
        if upload and upload.filename:
            data = upload.read()
            problem = logo_problem(upload.mimetype, data)
            if problem:
                flash(problem, "error")
                return redirect(url_for("settings.index"))
            branding.logo_data_uri = encode_logo(upload.mimetype, data)

    db.session.commit()
    flash("Branding saved.", "success")
    return redirect(url_for("settings.index"))

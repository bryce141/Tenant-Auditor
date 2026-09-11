"""Conditional Access policy simulator: compose a draft, see what it breaks.

Read-only throughout. The draft is evaluated against observed sign-ins and
handed back as Graph JSON for the admin to deploy themselves; nothing here ever
writes to a tenant.
"""
from flask import (Blueprint, Response, current_app, jsonify, render_template,
                   request)

from app.auth.graph_auth import get_active_tenant, get_headers, has_credentials
from app.services import ca_workspace
from app.services.ca_builder import (APP_GROUP_CHOICES, CLIENT_APP_CHOICES,
                                     GRANT_CHOICES, PLATFORM_CHOICES, PRESETS,
                                     RISK_CHOICES, STATE_CHOICES, BuilderError,
                                     build_policy, describe_gaps, export)
from app.services.ca_impact import assess
from app.services.ca_recommendations import (out_of_scope, recommend,
                                             unaddressed)
from app.services.ca_validation import (crosscheck_applied,
                                        fetch_membership_changes, validate)
from app.services.graph_client import GraphClient, GraphError

bp = Blueprint("simulator", __name__, url_prefix="/simulator")

DEFAULT_DAYS = 30

# Shown while traffic loads or the agreement check runs. Both are slow enough
# that an unchanged page reads as a hang.
LOADING_MESSAGES = [
    "convincing packets to move faster",
    "stealing bandwidth from the neighbors",
    "reticulating splines",
    "asking stackoverflow for help",
    "blaming DNS",
    "negotiating with the firewall",
    "rm -rf'ing doubts",
    "gaslighting the load balancer",
    "bribing the scheduler for more CPU time",
    "telling the server it's doing a great job",
    "deploying to prod on a Friday",
    "closing 47 chrome tabs to free up RAM",
    "pretending to read the logs",
    "asking ChatGPT what went wrong",
    "git push --force and praying",
    "turning it off and back on again",
    "blaming the intern",
    "adding more semicolons just in case",
    "checking if it works on my machine",
    "waiting for DNS to propagate (could be days)",
    "sudo make it work",
    "yelling at YAML indentation",
    "hoping nobody checks the commit history",
    "establishing a TCP handshake... it left me on read",
    "defragmenting the vibe",
    "running traceroute to find out who hurt you",
    "escalating privileges and expectations",
    "rebuilding node_modules for the 47th time",
    "warming up the cloud (it's chilly up there)",
    "performing mass unscheduled certificate rotation",
    "consulting the ancient scrolls (man pages)",
    "submitting a ticket to the universe",
    "politely asking the kernel for more threads",
    "stress testing your patience",
    "refactoring spaghetti into linguine",
    "deleting System32... just kidding",
    "teaching the AI to feel emotion",
    "segfaulting gracefully",
    "untangling the ethernet spaghetti",
    "sprinkling magic into the config file",
    "hoping this regex actually works",
    "converting coffee into code",
    "replacing all tabs with spaces (fight me)",
    "syncing the blockchain of trust issues",
    "performing percussive maintenance on the server",
    "telling Kubernetes what it wants to hear",
    "downloading more RAM",
    "alt-tabbing away from the problem",
    "invalidating the cache and my self-worth",
    "migrating data through the Suez Canal",
    "putting the 'no' in node_modules",
    "asking the rubber duck for guidance",
    "compiling excuses",
    "spinning up containers like a DJ",
    "hiding secrets in environment variables",
    "rewriting it in Rust (again)",
    "counting sheep in binary",
    "convincing cron it's the right time",
    "adjusting the cloud's thermostat",
    "opening a PR nobody will review",
    "feeding hamsters that power the server",
    "applying duct tape to the microservices",
    "trying to exit vim",
    "looking for the any key",
    "calculating the meaning of 404",
    "ssh'ing into the shadow realm",
    "grepping for the will to live",
    "chmod 777'ing everything (don't tell security)",
    "throttling the chaos monkey",
    "CTRL+Z'ing life decisions",
    "loading loading screen",
    "establishing quantum entanglement with the CDN",
    "resolving merge conflicts in my personal life",
    "rotating the SSL certs before they ghost us",
    "asking the packet sniffer to look away",
    "overclocking the vibes",
    "writing documentation (lol jk)",
    "piping output to /dev/happiness",
    "hot-swapping the hamster wheels",
    "brute forcing a good mood",
    "pinging localhost for emotional support",
]


def _client(tenant):
    """A Graph client, or None if credentials are unusable.

    Deliberately not required to view a cached workspace: the tenant id lives
    on the model, so a broken or expired secret costs you a rebuild rather than
    the results you already have.
    """
    try:
        headers, _ = get_headers(tenant)
        return GraphClient(headers)
    except Exception:
        return None


def _choices(workspace, client):
    """Directory objects the builder offers, so nobody types a GUID by hand."""
    groups, roles, apps = [], [], []
    if client is None:
        return {"groups": [], "roles": [], "applications": [], "locations": []}
    try:
        groups = [{"id": g["id"], "name": g.get("displayName") or g["id"]}
                  for g in client.get_all("/groups?$select=id,displayName&$top=999")]
    except GraphError:
        pass
    try:
        roles = [{"id": r.get("roleTemplateId") or r["id"],
                  "name": r.get("displayName") or r["id"]}
                 for r in client.get_all("/directoryRoles?$select=id,displayName,roleTemplateId")]
    except GraphError:
        pass

    # Offer the resources actually seen in this tenant's traffic. A cloud app
    # nobody has signed in to cannot show impact anyway, and a full service
    # principal list is thousands of rows of noise.
    seen = {}
    for observation in workspace.corpus.observations:
        resource_id = observation.conditions.resource_id
        if resource_id and resource_id not in seen:
            seen[resource_id] = observation.resource_display_name or resource_id
    apps = [{"id": k, "name": v} for k, v in sorted(seen.items(),
                                                    key=lambda kv: kv[1].lower())]

    locations = [{"id": loc.get("id"),
                  "name": loc.get("displayName") or loc.get("id"),
                  "trusted": bool(loc.get("isTrusted"))}
                 for loc in workspace.named_locations]

    return {"groups": sorted(groups, key=lambda g: g["name"].lower()),
            "roles": sorted(roles, key=lambda r: r["name"].lower()),
            "applications": apps, "locations": locations}


def _render(tenant, workspace=None, client=None, error=None, impact=None,
            draft=None, form=None, status=200):
    choices = _choices(workspace, client) if workspace else {
        "groups": [], "roles": [], "applications": [], "locations": []}
    return render_template(
        "simulator/index.html",
        tenant=tenant,
        workspace=workspace,
        summary=workspace.summary() if workspace else None,
        choices=choices,
        client_app_choices=CLIENT_APP_CHOICES,
        platform_choices=PLATFORM_CHOICES,
        risk_choices=RISK_CHOICES,
        grant_choices=GRANT_CHOICES,
        app_group_choices=APP_GROUP_CHOICES,
        state_choices=STATE_CHOICES,
        gaps=describe_gaps(),
        presets=PRESETS,
        loading_messages=LOADING_MESSAGES,
        error=error,
        impact=impact.summary() if impact else None,
        draft_json=export(draft) if draft else None,
        form=form or {},
        has_credentials=has_credentials(),
    ), status


@bp.route("/", methods=["GET"])
def index():
    tenant = get_active_tenant()
    if tenant is None:
        return _render(None, error="Select a tenant first.")[0]

    workspace = ca_workspace.get(tenant.tenant_id)
    client = _client(tenant) if workspace else None

    # A preset pre-fills the form so the first click produces a number rather
    # than an empty eleven-field form.
    preset = PRESETS.get(request.args.get("preset") or "")
    form = dict(preset["form"]) if preset else None
    return _render(tenant, workspace=workspace, client=client, form=form)[0]


@bp.route("/build", methods=["POST"])
def build():
    """Fetch the traffic a simulation runs against. Slow once, then cached."""
    tenant = get_active_tenant()
    if tenant is None:
        return jsonify({"error": "No tenant selected"}), 400

    days = request.form.get("days", type=int) or DEFAULT_DAYS
    force = request.form.get("force") in ("1", "true", "on")

    client = _client(tenant)
    if client is None:
        return _render(tenant, error="Could not authenticate to this tenant. "
                                     "Check its credentials under Tenants.")[0]
    try:
        workspace = ca_workspace.get_or_build(client, tenant.tenant_id, days=days,
                                              force=force)
    except GraphError as e:
        return _render(tenant, error=str(e))[0], 200
    except Exception as e:
        current_app.logger.exception("simulator workspace build failed")
        return _render(tenant, error=str(e))[0], 200

    return _render(tenant, workspace=workspace, client=client)[0]


@bp.route("/simulate", methods=["POST"])
def simulate():
    tenant = get_active_tenant()
    if tenant is None:
        return jsonify({"error": "No tenant selected"}), 400

    workspace = ca_workspace.get(tenant.tenant_id)
    if workspace is None:
        return _render(tenant, error="Load this tenant's sign-in traffic first.")[0]
    client = _client(tenant)

    form = {k: (request.form.getlist(k) if len(request.form.getlist(k)) > 1
                else request.form.get(k))
            for k in request.form}
    # Multi-selects with a single value still have to arrive as lists.
    for key in ("includeGroups", "includeRoles", "includeUsers", "excludeGroups",
                "excludeRoles", "excludeUsers", "includeApplications",
                "excludeApplications", "appGroups", "excludeAppGroups",
                "clientAppTypes", "includePlatforms", "excludePlatforms",
                "includeLocations", "excludeLocations", "signInRiskLevels",
                "userRiskLevels", "grantControls"):
        form[key] = request.form.getlist(key)

    try:
        draft = build_policy(form)
    except BuilderError as e:
        return _render(tenant, workspace=workspace, client=client, error=str(e),
                       form=form)[0]

    impact = assess(draft, workspace.corpus, workspace.memberships,
                    existing_policies=workspace.policies)
    return _render(tenant, workspace=workspace, client=client, impact=impact,
                   draft=draft, form=form)[0]


@bp.route("/export", methods=["POST"])
def export_policy():
    """Hand the draft back as Graph JSON. The tool never applies it."""
    form = {k: request.form.getlist(k) if len(request.form.getlist(k)) > 1
            else request.form.get(k) for k in request.form}
    for key in ("includeGroups", "includeRoles", "includeUsers", "excludeGroups",
                "excludeRoles", "excludeUsers", "includeApplications",
                "excludeApplications", "appGroups", "excludeAppGroups",
                "clientAppTypes", "includePlatforms", "excludePlatforms",
                "includeLocations", "excludeLocations", "signInRiskLevels",
                "userRiskLevels", "grantControls"):
        form[key] = request.form.getlist(key)

    try:
        draft = build_policy(form)
    except BuilderError as e:
        return jsonify({"error": str(e)}), 400

    name = (draft.get("displayName") or "policy").lower()
    safe = "".join(c if c.isalnum() or c in "-_" else "-" for c in name).strip("-")
    return Response(
        export(draft), mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{safe or "policy"}.json"'})


@bp.route("/recommendations", methods=["GET"])
def recommendations():
    """What the tenant is missing, and what each fix would cost.

    Joins the audit — which knows what is missing — to the simulator, which
    knows who would be affected.
    """
    from app.services.report_runner import SECURITY_CATEGORIES, get_latest_report

    tenant = get_active_tenant()
    context = {"tenant": tenant, "recommendations": [], "out_of_scope": [],
               "unaddressed": [], "error": None, "summary": None,
               "has_credentials": has_credentials(),
               "loading_messages": LOADING_MESSAGES}

    if tenant is None:
        context["error"] = "Select a tenant first."
        return render_template("simulator/recommendations.html", **context)

    workspace = ca_workspace.get(tenant.tenant_id)
    if workspace is None:
        context["error"] = "Load this tenant's sign-in traffic first."
        return render_template("simulator/recommendations.html", **context)
    context["summary"] = workspace.summary()

    checks = []
    for category in SECURITY_CATEGORIES:
        report = get_latest_report(category, tenant.tenant_id)
        if report:
            checks.extend(report.checks)

    if not checks:
        # Without an audit there is nothing to recommend from, and inventing
        # recommendations would be advice with no evidence behind it.
        context["error"] = ("No audit has run for this tenant yet. Run one from "
                            "the dashboard — the recommendations come from its "
                            "findings.")
        return render_template("simulator/recommendations.html", **context)

    found = recommend(checks, workspace.corpus, workspace.memberships,
                      existing_policies=workspace.policies)
    context["recommendations"] = [r.as_dict() for r in found]
    context["drafts"] = {r.remedy_id: export(r.draft) for r in found}
    context["out_of_scope"] = out_of_scope(checks)
    context["unaddressed"] = unaddressed(checks)
    return render_template("simulator/recommendations.html", **context)


@bp.route("/agreement", methods=["GET", "POST"])
def agreement():
    """The evidence that draft simulations can be trusted.

    A first-class page rather than a footnote: it is the answer to "why should
    I believe these numbers", and it is the only part of the tool that can be
    checked against Microsoft rather than asserted.
    """
    tenant = get_active_tenant()
    context = {"tenant": tenant, "report": None, "cross": None, "error": None,
               "summary": None, "has_credentials": has_credentials(),
               "loading_messages": LOADING_MESSAGES}

    if tenant is None:
        context["error"] = "Select a tenant first."
        return render_template("simulator/agreement.html", **context)

    workspace = ca_workspace.get(tenant.tenant_id)
    if workspace is None:
        context["error"] = "Load this tenant's sign-in traffic first."
        return render_template("simulator/agreement.html", **context)

    context["summary"] = workspace.summary()

    if request.method == "POST":
        client = _client(tenant)
        if client is None:
            context["error"] = "Could not authenticate to this tenant."
            return render_template("simulator/agreement.html", **context)
        max_tuples = request.form.get("max_tuples", type=int) or 50
        try:
            report = validate(client, workspace.corpus, workspace.policies,
                              workspace.memberships, max_tuples=max_tuples)
            cross = crosscheck_applied(workspace.corpus, workspace.policies,
                                       workspace.memberships,
                                       named_locations=workspace.named_locations,
                                       membership_changes=fetch_membership_changes(
                                           client, days=workspace.days))
        except GraphError as e:
            context["error"] = str(e)
            return render_template("simulator/agreement.html", **context)

        context["report"] = report.summary()
        context["disagreements"] = [d.as_dict() for d in report.disagreements]
        context["cross"] = cross.summary()
        context["ambiguous"] = cross.ambiguous

    return render_template("simulator/agreement.html", **context)

"""Reduce a tenant's sign-in log to the distinct condition tuples CA sees.

A Conditional Access policy does not look at a sign-in. It looks at a handful of
conditions attached to one — who, which app, which platform, which client, where
from, how risky, what state the device is in. Thousands of sign-ins collapse to
a few dozen distinct combinations of those, and evaluating a draft policy
against the distinct combinations gives the same answer as evaluating it against
every sign-in, for a fraction of the work.

Each tuple keeps a count of the real sign-ins behind it so impact can be
reported in units a person cares about ("417 sign-ins across 38 users") rather
than in tuples.

## The translation problem

The sign-in log and the CA schema describe the same conditions with different
vocabularies, and the sign-in side is free text:

    clientAppUsed             "Browser"          -> clientAppType  browser
    deviceDetail.operatingSystem  "Windows 10"   -> devicePlatform windows
    deviceDetail.trustType    "Azure AD joined"  -> join type      azureADJoined

`deviceDetail.operatingSystem` and `trustType` are documented as String, not as
enums — there is no fixed list to switch on, and Microsoft has renamed values
under us before ("Azure AD joined" became "Microsoft Entra joined").

So an unrecognised value is never quietly bucketed into `other` or `unknown`.
It is recorded in `Corpus.unmapped` and surfaced. Guessing here would be the
`allowedToUseSSPR` bug again in a new place: a legacy-auth block policy whose
traffic we filed under the wrong client type reports a confident, wrong number,
and a wrong number is worse than an admitted gap.

## Scope limits worth knowing

- v1.0 `/auditLogs/signIns` returns **interactive user sign-ins only**. Service
  principal and non-interactive sign-ins are beta-only and are not in the
  corpus, so policies targeting workload identities can't be simulated from it.
- Sign-in logs need Entra ID P1 or P2 at all — this is not a 7-vs-30-day
  difference, a tenant without P1 returns nothing here.
- Without P2, every risk level comes back `hidden`, which is not `none`.
  Risk-conditioned policies cannot be simulated against such a tenant, and
  `Corpus.risk_hidden` says so rather than letting `hidden` read as "no risk".
"""
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.utils import utcnow

SIGNINS_ENDPOINT = "/auditLogs/signIns"

# Graph emits .NET tick precision (7 fractional digits) on some records;
# fromisoformat accepts at most 6.
_FRACTION = re.compile(r"\.(\d+)")

# Graph caps and defaults a page at 1,000.
PAGE_SIZE = 1000

# How many distinct source addresses to remember per tuple. IP is deliberately
# not part of the dedup key (see build_corpus), but named-location matching
# needs the addresses later, and an unbounded set on a busy tuple is a
# memory leak with no reader.
MAX_IPS_PER_TUPLE = 200


# ---------------------------------------------------------------------------
# Vocabulary translation
# ---------------------------------------------------------------------------

# conditionalAccessClientApp, less "all" (a policy value, never an observation)
# and less "easSupported"/"easUnsupported" (policy-side spellings that the
# sign-in log does not produce).
CLIENT_APP_TYPES = {"browser", "mobileAppsAndDesktopClients",
                    "exchangeActiveSync", "other"}

# clientAppUsed is a display string. "Mobile Apps and Desktop clients" is what
# the log calls the "modern clients" bucket. Everything that speaks a protocol
# without modern auth support — POP, IMAP, SMTP, MAPI, EWS, PowerShell — is what
# the portal groups under "Other clients", and is the legacy auth an audit cares
# about. Exchange ActiveSync is its own CA bucket and must not be folded in.
CLIENT_APP_MAP = {
    "browser": "browser",
    "mobile apps and desktop clients": "mobileAppsAndDesktopClients",
    "exchange activesync": "exchangeActiveSync",
    "imap": "other",
    "imap4": "other",
    "pop": "other",
    "pop3": "other",
    "smtp": "other",
    "authenticated smtp": "other",
    "mapi": "other",
    "mapi over http": "other",
    "outlook anywhere (rpc over http)": "other",
    "exchange web services": "other",
    "exchange online powershell": "other",
    "reporting web services": "other",
    "offline address book": "other",
    "autodiscover": "other",
    "other clients": "other",
}

# conditionalAccessDevicePlatform, matched against the free-text operatingSystem
# by prefix. Order matters: "Windows Phone" must be tested before "Windows",
# and the iOS device names before anything shorter that could shadow them.
DEVICE_PLATFORM_PREFIXES = [
    ("windows phone", "windowsPhone"),
    ("windows", "windows"),
    ("ios", "iOS"),
    ("iphone", "iOS"),
    ("ipad", "iOS"),
    ("ipados", "iOS"),
    ("macos", "macOS"),
    ("mac os", "macOS"),
    ("macmac", "macOS"),
    ("android", "android"),
    ("linux", "linux"),
    ("ubuntu", "linux"),
    ("debian", "linux"),
    ("fedora", "linux"),
    ("centos", "linux"),
    ("red hat", "linux"),
    ("rhel", "linux"),
]

# trustType -> the device join state a CA device filter tests. Both the old
# "Azure AD" spelling and the current "Microsoft Entra" one appear in live
# tenants depending on when the device registered. "hybrid" is checked first
# because it contains the joined spelling.
JOIN_TYPE_PREFIXES = [
    ("hybrid azure ad joined", "hybridAzureADJoined"),
    ("microsoft entra hybrid joined", "hybridAzureADJoined"),
    ("azure ad joined", "azureADJoined"),
    ("microsoft entra joined", "azureADJoined"),
    ("azure ad registered", "azureADRegistered"),
    ("microsoft entra registered", "azureADRegistered"),
    ("workplace", "azureADRegistered"),
]

# riskLevel. "hidden" means the tenant isn't licensed for Identity Protection,
# which is a different statement from "no risk" and must not collapse into it.
RISK_LEVELS = {"none", "low", "medium", "high", "hidden"}


def _norm(value):
    return (value or "").strip().lower()


def map_client_app(client_app_used):
    """(clientAppType, unmapped_raw). Unknown input yields (None, raw)."""
    key = _norm(client_app_used)
    if not key:
        return None, None
    mapped = CLIENT_APP_MAP.get(key)
    return (mapped, None) if mapped else (None, client_app_used)


def map_device_platform(operating_system):
    """(devicePlatform, unmapped_raw).

    An absent operatingSystem is not an unmapped value: plenty of sign-ins
    genuinely carry no device information, and a policy's platform condition
    simply doesn't match them.
    """
    key = _norm(operating_system)
    if not key:
        return None, None
    for prefix, platform in DEVICE_PLATFORM_PREFIXES:
        if key.startswith(prefix):
            return platform, None
    return None, operating_system


def map_join_type(trust_type):
    """(join_type, unmapped_raw). Absent trustType means an unregistered device."""
    key = _norm(trust_type)
    if not key:
        return None, None
    for prefix, join_type in JOIN_TYPE_PREFIXES:
        if key.startswith(prefix):
            return join_type, None
    return None, trust_type


def map_risk(level):
    """(riskLevel, unmapped_raw). Absent risk is `none`, matching the CA default."""
    key = _norm(level)
    if not key:
        return "none", None
    if key in RISK_LEVELS:
        return key, None
    if key == "unknownfuturevalue":
        # Graph's forward-compatibility sentinel. Real, but not a risk level we
        # can evaluate against — treat it as unmapped rather than as "none".
        return None, level
    return None, level


# ---------------------------------------------------------------------------
# The tuple
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConditionTuple:
    """The conditions a CA policy evaluates, as observed on a real sign-in.

    Frozen because it is the dedup key.

    Group and role membership are absent on purpose even though policies target
    them: both are a function of `user_id`, which is already in the key, so
    resolving them separately and joining on user adds no tuples. IP is absent
    for the opposite reason — see build_corpus.
    """
    user_id: str
    app_id: str
    client_app_type: str        # conditionalAccessClientApp, or None
    device_platform: str        # conditionalAccessDevicePlatform, or None
    country: str                # ISO country code, or None
    is_compliant: bool          # tri-state: True / False / None = not reported
    join_type: str              # azureADJoined | hybridAzureADJoined | ... | None
    sign_in_risk_level: str
    user_risk_level: str

    def as_dict(self):
        return {
            "user_id": self.user_id,
            "app_id": self.app_id,
            "client_app_type": self.client_app_type,
            "device_platform": self.device_platform,
            "country": self.country,
            "is_compliant": self.is_compliant,
            "join_type": self.join_type,
            "sign_in_risk_level": self.sign_in_risk_level,
            "user_risk_level": self.user_risk_level,
        }


@dataclass
class Observation:
    """One condition tuple plus what the log says about the traffic behind it."""
    conditions: ConditionTuple
    sign_ins: int = 0
    ip_addresses: set = field(default_factory=set)
    ips_truncated: bool = False
    user_principal_name: str = None
    app_display_name: str = None
    first_seen: datetime = None
    last_seen: datetime = None
    # policy id -> {result: count}, straight from appliedConditionalAccessPolicies.
    # This is what the tenant actually did at sign-in time, and the second,
    # independent thing the engine gets checked against.
    applied_policies: dict = field(default_factory=dict)

    def record(self, signin, ip, when):
        self.sign_ins += 1
        if ip:
            if len(self.ip_addresses) < MAX_IPS_PER_TUPLE:
                self.ip_addresses.add(ip)
            elif ip not in self.ip_addresses:
                self.ips_truncated = True
        self.user_principal_name = self.user_principal_name or signin.get("userPrincipalName")
        self.app_display_name = self.app_display_name or signin.get("appDisplayName")
        if when:
            if self.first_seen is None or when < self.first_seen:
                self.first_seen = when
            if self.last_seen is None or when > self.last_seen:
                self.last_seen = when
        for applied in signin.get("appliedConditionalAccessPolicies") or []:
            policy_id = applied.get("id")
            if not policy_id:
                continue
            results = self.applied_policies.setdefault(policy_id, Counter())
            results[applied.get("result") or "unknown"] += 1

    def as_dict(self):
        return {
            "conditions": self.conditions.as_dict(),
            "sign_ins": self.sign_ins,
            "ip_addresses": sorted(self.ip_addresses),
            "ips_truncated": self.ips_truncated,
            "user_principal_name": self.user_principal_name,
            "app_display_name": self.app_display_name,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "applied_policies": {pid: dict(results)
                                 for pid, results in self.applied_policies.items()},
        }


@dataclass
class Corpus:
    """Every distinct condition tuple in the window, and how it was arrived at."""
    observations: list = field(default_factory=list)
    total_sign_ins: int = 0
    window_days: int = 0
    first_seen: datetime = None
    last_seen: datetime = None

    # True when the fetch stopped at max_records rather than at the end of the
    # window. Aggregate impact numbers from a truncated corpus understate the
    # real total, so every surface that reports them has to say this.
    truncated: bool = False

    # field name -> {raw value: times seen}. Non-empty means the engine is
    # blind to some real traffic; it is not cosmetic.
    unmapped: dict = field(default_factory=dict)

    # Sign-ins whose risk came back `hidden` — the tenant lacks Entra ID P2 and
    # risk-based policies cannot be simulated for them.
    risk_hidden: int = 0

    # False when no sign-in carried appliedConditionalAccessPolicies, which
    # means the app lacks the CA read permission and the cross-check in the
    # validation harness has nothing to compare against.
    ca_data_visible: bool = False

    @property
    def distinct_users(self):
        return len({o.conditions.user_id for o in self.observations
                    if o.conditions.user_id})

    @property
    def reduction_ratio(self):
        """Sign-ins per tuple. The number that says whether this approach works."""
        if not self.observations:
            return 0.0
        return self.total_sign_ins / len(self.observations)

    def summary(self):
        return {
            "sign_ins": self.total_sign_ins,
            "tuples": len(self.observations),
            "distinct_users": self.distinct_users,
            "reduction_ratio": round(self.reduction_ratio, 1),
            "window_days": self.window_days,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "truncated": self.truncated,
            "risk_hidden": self.risk_hidden,
            "ca_data_visible": self.ca_data_visible,
            "unmapped": {k: dict(v) for k, v in self.unmapped.items()},
        }


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def _parse_dt(value):
    """Graph timestamp to a naive UTC datetime, or None.

    Graph emits .NET tick precision (7 fractional digits) on some records and
    second precision on others; fromisoformat accepts at most 6, so the
    fraction is trimmed rather than the parse being allowed to fail.
    """
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6], text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def fetch_signins(client, days=30, max_records=None):
    """Sign-ins from the last `days`, newest first. Returns (records, truncated).

    Paged here rather than through GraphClient.get_all because a busy tenant
    over 30 days is hundreds of thousands of records and the caller needs a
    ceiling. Graph returns newest first, so a truncated fetch is the most
    recent slice of the window rather than an arbitrary one.
    """
    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    params = {"$filter": f"createdDateTime ge {since}", "$top": PAGE_SIZE}

    url = SIGNINS_ENDPOINT
    records = []
    while url:
        body = client.get_one(url, params=params) or {}
        params = None  # the nextLink already carries them
        records.extend(body.get("value", []))
        if max_records is not None and len(records) >= max_records:
            return records[:max_records], True
        url = body.get("@odata.nextLink")
    return records, False


# ---------------------------------------------------------------------------
# Reduce
# ---------------------------------------------------------------------------

def reduce_to_tuples(signins, window_days=30, truncated=False):
    """Collapse raw sign-in records into a Corpus of distinct condition tuples.

    Pure: no Graph calls, so the whole reduction is testable against fixtures
    without a tenant.

    The source IP is recorded per tuple but deliberately kept **out** of the
    dedup key. Keying on it would put every mobile-carrier address in its own
    tuple and destroy the reduction that makes this approach viable, while
    adding nothing an evaluator can use directly — what a policy actually tests
    is whether an address falls inside a named location. Once named locations
    are known, location membership becomes part of the key and splits the
    tuples that genuinely differ; the retained addresses are what make that
    possible.
    """
    corpus = Corpus(window_days=window_days, truncated=truncated)
    by_key = {}
    unmapped = {}

    def note_unmapped(field_name, raw):
        if raw is None:
            return
        unmapped.setdefault(field_name, Counter())[str(raw)] += 1

    for signin in signins:
        device = signin.get("deviceDetail") or {}
        location = signin.get("location") or {}

        client_app, raw = map_client_app(signin.get("clientAppUsed"))
        note_unmapped("clientAppUsed", raw)

        platform, raw = map_device_platform(device.get("operatingSystem"))
        note_unmapped("operatingSystem", raw)

        join_type, raw = map_join_type(device.get("trustType"))
        note_unmapped("trustType", raw)

        sign_in_risk, raw = map_risk(signin.get("riskLevelDuringSignIn"))
        note_unmapped("riskLevelDuringSignIn", raw)

        # riskLevelAggregated is the closest the sign-in log gets to the user
        # risk a policy tests. It is the risk as understood at sign-in time,
        # not the user's risk now, which is the honest thing to simulate
        # against historical traffic anyway.
        user_risk, raw = map_risk(signin.get("riskLevelAggregated"))
        note_unmapped("riskLevelAggregated", raw)

        if sign_in_risk == "hidden" or user_risk == "hidden":
            corpus.risk_hidden += 1

        if signin.get("appliedConditionalAccessPolicies"):
            corpus.ca_data_visible = True

        conditions = ConditionTuple(
            user_id=signin.get("userId"),
            app_id=signin.get("appId"),
            client_app_type=client_app,
            device_platform=platform,
            country=location.get("countryOrRegion") or None,
            # null is not False: the log reports no compliance state for
            # unregistered devices, and a "require compliant device" policy
            # treats that as non-compliant only once it has actually evaluated.
            is_compliant=device.get("isCompliant"),
            join_type=join_type,
            sign_in_risk_level=sign_in_risk,
            user_risk_level=user_risk,
        )

        observation = by_key.get(conditions)
        if observation is None:
            observation = Observation(conditions=conditions)
            by_key[conditions] = observation

        when = _parse_dt(signin.get("createdDateTime"))
        observation.record(signin, signin.get("ipAddress"), when)

        corpus.total_sign_ins += 1
        if when:
            if corpus.first_seen is None or when < corpus.first_seen:
                corpus.first_seen = when
            if corpus.last_seen is None or when > corpus.last_seen:
                corpus.last_seen = when

    corpus.observations = sorted(by_key.values(),
                                 key=lambda o: o.sign_ins, reverse=True)
    corpus.unmapped = unmapped
    return corpus


def build_corpus(client, days=30, max_records=None):
    """Fetch and reduce in one step. Raises GraphError like any other Graph call."""
    signins, truncated = fetch_signins(client, days=days, max_records=max_records)
    return reduce_to_tuples(signins, window_days=days, truncated=truncated)

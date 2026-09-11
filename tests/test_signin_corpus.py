"""Tests for the sign-in corpus reduction.

The fixtures here are shaped after the response bodies on Microsoft Learn's
signIn / deviceDetail pages rather than after what the code expects — including
the awkward parts, like `isCompliant: null` and `trustType: null` on an
unregistered device, and 7-digit fractional seconds. Six bugs on this project
came from real Graph responses disagreeing with a fixture, so the fixtures are
written to disagree first.
"""
from app.services.signin_corpus import (
    Corpus,
    build_corpus,
    fetch_signins,
    map_client_app,
    map_device_platform,
    map_join_type,
    map_risk,
    reduce_to_tuples,
    _parse_dt,
)


def signin(**overrides):
    """A sign-in record with the shape Graph actually returns."""
    record = {
        "id": "66ea54eb-6301-4ee5-be62-ff5a759b0100",
        "createdDateTime": "2023-12-01T16:03:35Z",
        "userDisplayName": "Test Contoso",
        "userPrincipalName": "testaccount1@contoso.com",
        "userId": "26be570a-ae82-4189-b4e2-a37c6808512d",
        "appId": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
        "appDisplayName": "Graph explorer",
        "ipAddress": "131.107.159.37",
        "clientAppUsed": "Browser",
        "conditionalAccessStatus": "notApplied",
        "isInteractive": True,
        "riskDetail": "none",
        "riskLevelAggregated": "none",
        "riskLevelDuringSignIn": "none",
        "riskState": "none",
        "resourceId": "00000003-0000-0000-c000-000000000000",
        "status": {"errorCode": 0, "failureReason": None},
        "deviceDetail": {
            "deviceId": "",
            "displayName": None,
            "operatingSystem": "Windows 10",
            "browser": "Edge 80.0.361",
            "isCompliant": None,
            "isManaged": None,
            "trustType": None,
        },
        "location": {"city": "Redmond", "state": "Washington",
                     "countryOrRegion": "US"},
        "appliedConditionalAccessPolicies": [],
    }
    device = overrides.pop("deviceDetail", None)
    location = overrides.pop("location", None)
    if device is not None:
        record["deviceDetail"] = {**record["deviceDetail"], **device}
    if location is not None:
        record["location"] = {**record["location"], **location}
    record.update(overrides)
    return record


class FakeClient:
    """Serves pre-baked pages the way Graph paginates them."""

    def __init__(self, pages):
        self.pages = pages
        self.requests = []

    def get_one(self, endpoint, params=None, beta=False):
        self.requests.append((endpoint, params))
        return self.pages[len(self.requests) - 1]


# ---------------------------------------------------------------------------
# Vocabulary translation
# ---------------------------------------------------------------------------

def test_known_client_apps_map_to_ca_enum_values():
    assert map_client_app("Browser") == ("browser", None)
    assert map_client_app("Mobile Apps and Desktop clients") == (
        "mobileAppsAndDesktopClients", None)
    assert map_client_app("Exchange ActiveSync") == ("exchangeActiveSync", None)


def test_legacy_protocols_map_to_other_not_to_activesync():
    # The portal groups POP/IMAP/SMTP/MAPI under "Other clients"; Exchange
    # ActiveSync is a separate CA bucket. Folding them together would mis-state
    # which traffic a legacy-auth block policy covers.
    for used in ["IMAP4", "POP3", "Authenticated SMTP", "MAPI Over HTTP",
                 "Exchange Web Services", "Other clients"]:
        assert map_client_app(used) == ("other", None), used


def test_unknown_client_app_is_reported_not_bucketed():
    # The failure this guards: quietly calling an unrecognised client "other"
    # would make it look like legacy auth and invent breakage that isn't there.
    mapped, raw = map_client_app("Some New Microsoft Client")
    assert mapped is None
    assert raw == "Some New Microsoft Client"


def test_windows_phone_is_not_matched_as_windows():
    assert map_device_platform("Windows Phone 8.1") == ("windowsPhone", None)
    assert map_device_platform("Windows 10") == ("windows", None)
    assert map_device_platform("Windows Server 2019") == ("windows", None)


def test_device_platforms_cover_the_ca_enum():
    assert map_device_platform("iOS 17.1") == ("iOS", None)
    assert map_device_platform("MacOs 14") == ("macOS", None)
    assert map_device_platform("Android 13") == ("android", None)
    assert map_device_platform("Ubuntu 22.04") == ("linux", None)


def test_absent_os_is_not_an_unmapped_value():
    # Plenty of sign-ins genuinely carry no device info. That is a normal
    # observation, not a gap in the translation table.
    assert map_device_platform(None) == (None, None)
    assert map_device_platform("") == (None, None)


def test_unknown_os_is_reported():
    assert map_device_platform("Chrome OS 120") == (None, "Chrome OS 120")


def test_both_entra_and_azure_ad_join_spellings_are_understood():
    # Microsoft renamed these; a tenant has devices registered under both.
    assert map_join_type("Azure AD joined") == ("azureADJoined", None)
    assert map_join_type("Microsoft Entra joined") == ("azureADJoined", None)
    assert map_join_type("Hybrid Azure AD joined") == ("hybridAzureADJoined", None)
    assert map_join_type("Microsoft Entra hybrid joined") == (
        "hybridAzureADJoined", None)
    assert map_join_type("Azure AD registered") == ("azureADRegistered", None)


def test_hybrid_join_is_not_matched_as_plain_join():
    assert map_join_type("Hybrid Azure AD joined")[0] == "hybridAzureADJoined"


def test_hidden_risk_is_not_none():
    # 'hidden' means the tenant has no Entra ID P2, which is a different claim
    # from 'this sign-in was not risky'. Collapsing them would let a
    # risk-conditioned policy read as inapplicable to the entire tenant.
    assert map_risk("hidden") == ("hidden", None)
    assert map_risk("none") == ("none", None)
    assert map_risk(None) == ("none", None)


def test_unknown_future_risk_value_is_reported():
    assert map_risk("unknownFutureValue") == (None, "unknownFutureValue")


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------

def test_parses_second_and_tick_precision():
    # Graph emits both; .NET tick precision has 7 fractional digits, one more
    # than fromisoformat accepts.
    assert _parse_dt("2023-12-01T16:03:35Z").isoformat() == "2023-12-01T16:03:35"
    parsed = _parse_dt("2022-04-01T18:55:43.1454565Z")
    assert parsed.year == 2022 and parsed.microsecond == 145456


def test_parsed_timestamps_are_naive_utc():
    # The rest of the app stores naive datetimes; an aware one raises TypeError
    # the first time it is compared against a model column.
    assert _parse_dt("2023-12-01T16:03:35Z").tzinfo is None
    assert _parse_dt("2023-12-01T18:03:35+02:00").isoformat() == "2023-12-01T16:03:35"


def test_unparseable_timestamp_does_not_raise():
    assert _parse_dt("not a date") is None
    assert _parse_dt(None) is None


# ---------------------------------------------------------------------------
# Reduction
# ---------------------------------------------------------------------------

def test_identical_conditions_collapse_to_one_tuple():
    corpus = reduce_to_tuples([signin(), signin(), signin()])
    assert len(corpus.observations) == 1
    assert corpus.observations[0].sign_ins == 3
    assert corpus.total_sign_ins == 3
    assert corpus.reduction_ratio == 3.0


def test_differing_country_splits_the_tuple():
    corpus = reduce_to_tuples([
        signin(location={"countryOrRegion": "US"}),
        signin(location={"countryOrRegion": "GB"}),
    ])
    assert len(corpus.observations) == 2


def test_ip_address_does_not_split_tuples_but_is_retained():
    # Keying on IP would put every mobile-carrier address in its own tuple and
    # destroy the reduction. The addresses still have to survive for named
    # location matching later.
    corpus = reduce_to_tuples([
        signin(ipAddress="131.107.159.37"),
        signin(ipAddress="203.0.113.9"),
    ])
    assert len(corpus.observations) == 1
    assert corpus.observations[0].ip_addresses == {"131.107.159.37", "203.0.113.9"}


def test_compliance_null_and_false_are_different_tuples():
    # null = the log reported no compliance state. False = it reported the
    # device as non-compliant. A "require compliant device" policy has to be
    # able to tell those apart.
    corpus = reduce_to_tuples([
        signin(deviceDetail={"isCompliant": None}),
        signin(deviceDetail={"isCompliant": False}),
        signin(deviceDetail={"isCompliant": True}),
    ])
    states = {o.conditions.is_compliant for o in corpus.observations}
    assert states == {None, False, True}
    assert len(corpus.observations) == 3


def test_distinct_users_counts_users_not_tuples():
    corpus = reduce_to_tuples([
        signin(userId="user-a", location={"countryOrRegion": "US"}),
        signin(userId="user-a", location={"countryOrRegion": "GB"}),
        signin(userId="user-b"),
    ])
    assert len(corpus.observations) == 3
    assert corpus.distinct_users == 2


def test_unmapped_values_are_collected_with_counts():
    corpus = reduce_to_tuples([
        signin(clientAppUsed="Some New Client"),
        signin(clientAppUsed="Some New Client"),
        signin(deviceDetail={"operatingSystem": "Chrome OS 120"}),
    ])
    assert corpus.unmapped["clientAppUsed"]["Some New Client"] == 2
    assert corpus.unmapped["operatingSystem"]["Chrome OS 120"] == 1


def test_clean_corpus_reports_no_unmapped_values():
    assert reduce_to_tuples([signin()]).unmapped == {}


def test_hidden_risk_sign_ins_are_counted():
    corpus = reduce_to_tuples([
        signin(riskLevelDuringSignIn="hidden", riskLevelAggregated="hidden"),
        signin(),
    ])
    assert corpus.risk_hidden == 1


def test_applied_policies_are_aggregated_per_tuple():
    # This is the second, independent check on the engine: what the tenant
    # actually enforced at sign-in time.
    policy = {"id": "de7e60eb-ed89-4d73-8205-2227def6b7c9",
              "displayName": "SharePoint limited access",
              "enforcedGrantControls": [], "enforcedSessionControls": [],
              "result": "notEnabled"}
    corpus = reduce_to_tuples([
        signin(appliedConditionalAccessPolicies=[policy]),
        signin(appliedConditionalAccessPolicies=[{**policy, "result": "success"}]),
    ])
    results = corpus.observations[0].applied_policies[policy["id"]]
    assert results == {"notEnabled": 1, "success": 1}
    assert corpus.ca_data_visible is True


def test_missing_applied_policies_flags_the_permission_gap():
    # Without Policy.Read.All the property is omitted entirely rather than
    # returned empty, and the cross-check silently has nothing to compare.
    record = signin()
    del record["appliedConditionalAccessPolicies"]
    assert reduce_to_tuples([record]).ca_data_visible is False


def test_window_bounds_come_from_the_records():
    corpus = reduce_to_tuples([
        signin(createdDateTime="2023-12-01T16:03:35Z"),
        signin(createdDateTime="2023-12-05T09:00:00Z"),
        signin(createdDateTime="2023-11-28T22:15:00Z"),
    ])
    assert corpus.first_seen.isoformat() == "2023-11-28T22:15:00"
    assert corpus.last_seen.isoformat() == "2023-12-05T09:00:00"


def test_empty_corpus_is_well_formed():
    corpus = reduce_to_tuples([])
    assert corpus.observations == []
    assert corpus.reduction_ratio == 0.0
    assert corpus.distinct_users == 0
    assert corpus.summary()["tuples"] == 0


def test_observations_are_ordered_by_volume():
    corpus = reduce_to_tuples(
        [signin(location={"countryOrRegion": "US"})] * 5
        + [signin(location={"countryOrRegion": "GB"})]
    )
    assert corpus.observations[0].sign_ins == 5


def test_summary_is_json_serialisable():
    import json

    corpus = reduce_to_tuples([signin(clientAppUsed="Some New Client")])
    json.dumps(corpus.summary())
    json.dumps(corpus.observations[0].as_dict())


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def test_fetch_follows_next_links():
    client = FakeClient([
        {"value": [signin(), signin()],
         "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=x"},
        {"value": [signin()]},
    ])
    records, truncated = fetch_signins(client, days=30)
    assert len(records) == 3
    assert truncated is False
    # Params ride on the first request only; the nextLink already carries them.
    assert client.requests[1][1] is None


def test_fetch_filters_on_the_window():
    client = FakeClient([{"value": []}])
    fetch_signins(client, days=7)
    _, params = client.requests[0]
    assert params["$filter"].startswith("createdDateTime ge ")
    assert params["$top"] == 1000


def test_fetch_stops_at_max_records_and_says_so():
    # A truncated corpus understates impact totals, so the flag has to reach
    # the caller rather than being inferred from a round number.
    client = FakeClient([
        {"value": [signin()] * 3,
         "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=x"},
    ])
    records, truncated = fetch_signins(client, days=30, max_records=2)
    assert len(records) == 2
    assert truncated is True


def test_build_corpus_carries_truncation_into_the_result():
    client = FakeClient([
        {"value": [signin()] * 3,
         "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=x"},
    ])
    corpus = build_corpus(client, days=30, max_records=2)
    assert isinstance(corpus, Corpus)
    assert corpus.truncated is True
    assert corpus.total_sign_ins == 2
    assert corpus.window_days == 30

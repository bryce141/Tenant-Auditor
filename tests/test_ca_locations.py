"""Tests for named location resolution.

Fixtures follow the ipNamedLocation and countryNamedLocation shapes on Microsoft
Learn, including the parts that are easy to get wrong: the @odata.type
discriminator, isTrusted defaulting absent, includeUnknownCountriesAndRegions,
and countryLookupMethod.
"""
from app.services.ca_engine import evaluate
from app.services.ca_locations import LocationResolver
from app.services.ca_memberships import Membership
from app.services.signin_corpus import ConditionTuple, reduce_to_tuples
from tests.test_signin_corpus import signin

OFFICE = "11111111-1111-1111-1111-111111111111"
COUNTRIES = "22222222-2222-2222-2222-222222222222"


def ip_location(location_id=OFFICE, ranges=("203.0.113.0/24",), trusted=True,
                name="HQ"):
    return {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "id": location_id, "displayName": name, "isTrusted": trusted,
        "ipRanges": [{"@odata.type": "#microsoft.graph.iPv4CidrRange",
                      "cidrAddress": r} for r in ranges],
    }


def country_location(location_id=COUNTRIES, countries=("US",),
                     include_unknown=False, lookup="clientIpAddress",
                     name="Allowed countries"):
    return {
        "@odata.type": "#microsoft.graph.countryNamedLocation",
        "id": location_id, "displayName": name,
        "countriesAndRegions": list(countries),
        "includeUnknownCountriesAndRegions": include_unknown,
        "countryLookupMethod": lookup,
    }


def conditions(**overrides):
    base = dict(user_id="u1", resource_id="app", client_app_type="browser",
                device_platform="windows", country="US", is_compliant=None,
                join_type=None, sign_in_risk_level="none", user_risk_level="none",
                named_location_ids=frozenset(), in_trusted_location=False)
    base.update(overrides)
    return ConditionTuple(**base)


def member():
    return Membership(user_id="u1", user_type="Member", resolved=True)


def policy(locations):
    return {"id": "p1", "displayName": "Location policy", "state": "enabled",
            "conditions": {"users": {"includeUsers": ["All"]},
                           "applications": {"includeApplications": ["All"]},
                           "clientAppTypes": ["all"], "signInRiskLevels": [],
                           "userRiskLevels": [], "locations": locations},
            "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
            "sessionControls": None}


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def test_ip_inside_a_range_matches():
    r = LocationResolver([ip_location()])
    match = r.resolve("203.0.113.9", "US")
    assert match.location_ids == {OFFICE}
    assert match.trusted is True


def test_ip_outside_every_range_matches_nothing():
    r = LocationResolver([ip_location()])
    assert r.resolve("198.51.100.4", "US").location_ids == frozenset()


def test_untrusted_ip_location_does_not_set_trusted():
    r = LocationResolver([ip_location(trusted=False)])
    assert r.resolve("203.0.113.9").trusted is False


def test_ipv6_ranges_are_supported():
    r = LocationResolver([ip_location(ranges=("2001:db8::/32",))])
    assert r.resolve("2001:db8::1").location_ids == {OFFICE}


def test_country_matches_case_insensitively():
    r = LocationResolver([country_location(countries=("US", "GB"))])
    assert r.resolve(None, "us").location_ids == {COUNTRIES}
    assert r.resolve(None, "FR").location_ids == frozenset()


def test_unknown_country_matches_only_when_the_location_opts_in():
    including = LocationResolver([country_location(include_unknown=True)])
    assert including.resolve("198.51.100.4", None).location_ids == {COUNTRIES}

    excluding = LocationResolver([country_location(include_unknown=False)])
    assert excluding.resolve("198.51.100.4", None).location_ids == frozenset()


def test_gps_based_country_location_is_unsupported():
    # countryLookupMethod authenticatorAppGps decides the country from device
    # GPS, which no sign-in record reports. Treating it as IP-based would give
    # a confident wrong answer about who a location policy affects.
    r = LocationResolver([country_location(lookup="authenticatorAppGps")])
    match = r.resolve("203.0.113.9", "US")
    assert match.resolved is False
    assert "authenticatorAppGps" in " ".join(match.unsupported)


def test_missing_ip_makes_ip_locations_unevaluable():
    r = LocationResolver([ip_location()])
    match = r.resolve(None, "US")
    assert match.resolved is False


def test_unparseable_ip_range_is_reported_not_skipped():
    r = LocationResolver([ip_location(ranges=("not-a-cidr",))])
    assert any("unparseable" in why for _, _, why in r.unsupported)


def test_unrecognised_location_type_is_reported():
    r = LocationResolver([{"@odata.type": "#microsoft.graph.somethingNew",
                           "id": "x", "displayName": "New"}])
    assert any("unrecognised" in why for _, _, why in r.unsupported)


def test_no_named_locations_at_all_resolves_cleanly():
    r = LocationResolver([])
    assert r.empty is True
    assert r.resolve("203.0.113.9", "US") .location_ids == frozenset()


# ---------------------------------------------------------------------------
# Corpus integration
# ---------------------------------------------------------------------------

def test_location_membership_splits_tuples():
    # Two sign-ins alike in every other respect but from different offices are
    # genuinely different to a location-scoped policy.
    resolver = LocationResolver([ip_location()])
    corpus = reduce_to_tuples([signin(ipAddress="203.0.113.9"),
                               signin(ipAddress="198.51.100.4")],
                              locations=resolver)
    assert len(corpus.observations) == 2
    inside = {frozenset(o.conditions.named_location_ids)
              for o in corpus.observations}
    assert inside == {frozenset({OFFICE}), frozenset()}


def test_without_a_resolver_location_membership_is_unknown_not_empty():
    corpus = reduce_to_tuples([signin()])
    assert corpus.observations[0].conditions.named_location_ids is None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

def test_include_named_location_matches_and_misses():
    p = policy({"includeLocations": [OFFICE]})
    assert evaluate(p, conditions(named_location_ids=frozenset({OFFICE})),
                    member()).applies is True
    assert evaluate(p, conditions(named_location_ids=frozenset()),
                    member()).applies is False


def test_exclude_named_location_beats_include():
    p = policy({"includeLocations": ["All"], "excludeLocations": [OFFICE]})
    assert evaluate(p, conditions(named_location_ids=frozenset({OFFICE})),
                    member()).applies is False


def test_all_locations_matches_anything_resolved():
    p = policy({"includeLocations": ["All"]})
    assert evaluate(p, conditions(named_location_ids=frozenset()),
                    member()).applies is True


def test_all_trusted_uses_the_trusted_flag_not_the_id_list():
    # The common "require MFA except from trusted locations" shape.
    p = policy({"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]})
    trusted = conditions(named_location_ids=frozenset({OFFICE}),
                         in_trusted_location=True)
    untrusted = conditions(named_location_ids=frozenset({OFFICE}),
                           in_trusted_location=False)
    assert evaluate(p, trusted, member()).applies is False
    assert evaluate(p, untrusted, member()).applies is True


def test_unresolved_locations_are_unsupported_not_a_non_match():
    # The failure this prevents: reading "we never resolved locations" as
    # "inside no location", so an exclude-trusted policy silently applies to
    # everybody.
    p = policy({"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]})
    e = evaluate(p, conditions(named_location_ids=None), member())
    assert e.applies is None
    assert "locations" in " ".join(e.unsupported_conditions)


def test_a_policy_without_a_location_condition_ignores_unresolved_locations():
    p = policy(None)
    assert evaluate(p, conditions(named_location_ids=None), member()).applies is True

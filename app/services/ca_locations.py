"""Resolve a sign-in's address and country to the named locations it falls in.

A Conditional Access policy targets locations by id, so the engine needs to know
which named locations a sign-in was inside. The sign-in log gives an IP address
and a country code; named locations are defined as CIDR ranges or as country
lists. This turns the former into the latter.

Resolution happens while the corpus is being built, per sign-in, and the result
becomes part of the tuple key. That is deliberate: two sign-ins from the same
user and app but different offices are genuinely different to a location-scoped
policy, and merging them would average away the thing being measured. It is
also why `signin_corpus` keeps the addresses rather than only a count — the key
cannot be computed without them.

## What stays unsupported, and why that matters

A `countryNamedLocation` can set `countryLookupMethod` to `authenticatorAppGps`,
which decides the user's country from device GPS rather than from the address.
Nothing in the sign-in log reports that, so such a location cannot be evaluated
and is reported rather than quietly treated as IP-based — a location the engine
silently mis-resolves would produce a confident wrong answer about who a
location-scoped policy affects.
"""
import ipaddress
from dataclasses import dataclass

IP_LOCATION = "#microsoft.graph.ipnamedlocation"
COUNTRY_LOCATION = "#microsoft.graph.countrynamedlocation"

# countryLookupMethodType. clientIpAddress is the default and the only one a
# sign-in record carries enough information to evaluate.
LOOKUP_CLIENT_IP = "clientipaddress"
LOOKUP_GPS = "authenticatorappgps"


@dataclass(frozen=True)
class LocationMatch:
    """Which named locations a sign-in fell inside."""
    location_ids: frozenset = frozenset()
    trusted: bool = False          # any matched location is explicitly trusted
    unsupported: tuple = ()        # locations that could not be evaluated

    @property
    def resolved(self):
        return not self.unsupported


class LocationResolver:
    """Named locations, indexed for lookup by address and country.

    Built once per tenant from `/identity/conditionalAccess/namedLocations`.
    Pure after construction, so the corpus reduction stays testable offline.
    """

    def __init__(self, named_locations):
        self.ip_locations = []       # (id, [ip_network], isTrusted)
        self.country_locations = []  # (id, {country}, include_unknown, isTrusted)
        self.unsupported = []        # (id, displayName, why)
        self._load(named_locations or [])

    def _load(self, named_locations):
        for location in named_locations:
            odata_type = (location.get("@odata.type") or "").lower()
            location_id = location.get("id")
            name = location.get("displayName") or location_id
            trusted = bool(location.get("isTrusted"))

            if odata_type == IP_LOCATION:
                networks = []
                for entry in location.get("ipRanges") or []:
                    cidr = entry.get("cidrAddress")
                    if not cidr:
                        continue
                    try:
                        networks.append(ipaddress.ip_network(cidr, strict=False))
                    except ValueError:
                        # A range Graph accepted but Python won't parse is a
                        # gap, not something to skip quietly.
                        self.unsupported.append(
                            (location_id, name, f"unparseable ip range {cidr!r}"))
                self.ip_locations.append((location_id, networks, trusted))

            elif odata_type == COUNTRY_LOCATION:
                lookup = (location.get("countryLookupMethod") or LOOKUP_CLIENT_IP).lower()
                if lookup == LOOKUP_GPS:
                    # Decided from device GPS, which no sign-in record reports.
                    self.unsupported.append(
                        (location_id, name,
                         "countryLookupMethod is authenticatorAppGps — not in the sign-in log"))
                    continue
                countries = {str(c).upper() for c in
                             (location.get("countriesAndRegions") or [])}
                self.country_locations.append(
                    (location_id, countries,
                     bool(location.get("includeUnknownCountriesAndRegions")), trusted))

            else:
                self.unsupported.append(
                    (location_id, name, f"unrecognised location type {odata_type!r}"))

    @property
    def empty(self):
        return not (self.ip_locations or self.country_locations)

    def resolve(self, ip_address=None, country=None):
        """Which named locations a sign-in from here falls inside."""
        matched, trusted = set(), False
        unsupported = [f"{name}: {why}" for _, name, why in self.unsupported]

        parsed = None
        if ip_address:
            try:
                parsed = ipaddress.ip_address(ip_address)
            except ValueError:
                parsed = None

        for location_id, networks, is_trusted in self.ip_locations:
            if parsed is None:
                if networks:
                    # Without a usable address an IP location cannot be ruled
                    # in or out, and "not matched" would be a guess.
                    unsupported.append(f"{location_id}: sign-in reported no usable IP")
                continue
            if any(parsed in network for network in networks):
                matched.add(location_id)
                trusted = trusted or is_trusted

        code = (country or "").upper()
        for location_id, countries, include_unknown, is_trusted in self.country_locations:
            hit = code in countries if code else include_unknown
            if hit:
                matched.add(location_id)
                trusted = trusted or is_trusted

        return LocationMatch(location_ids=frozenset(matched), trusted=trusted,
                             unsupported=tuple(unsupported))


def fetch_named_locations(client):
    """Named locations for the tenant. Raises GraphError like any Graph call."""
    return client.get_all("/identity/conditionalAccess/namedLocations")


def build_resolver(client):
    return LocationResolver(fetch_named_locations(client))

"""The onboarding material must list exactly the permissions the code needs.

Four places name this list: the diagnostic, the two setup scripts, and the page
sent to a client's administrator. A permission added to the code but missed in
the scripts means an onboarded tenant silently skips checks, and the client's
admin has to be asked back — which is exactly the friction this material exists
to remove.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def required_permissions():
    """The source of truth: what scripts/check_permissions.py demands."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "check_permissions", ROOT / "scripts" / "check_permissions.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {perm for perm, _alt, _why in module.REQUIRED}


def listed_in(path, pattern):
    """MULTILINE so ^ and $ anchor per line, not to the whole file."""
    text = (ROOT / path).read_text()
    return set(re.findall(pattern, text, re.MULTILINE))


def test_the_source_list_is_sane():
    """Guard the guard: a broken loader would make everything else pass."""
    perms = required_permissions()
    assert len(perms) >= 15
    assert "Reports.Read.All" in perms


@pytest.mark.parametrize("path,pattern", [
    # PowerShell: quoted strings inside the $Permissions array.
    ("scripts/setup_tenant.ps1", r'"([A-Za-z]+(?:\.[A-Za-z]+)+)"'),
    # Bash: bare words inside PERMISSIONS=( ... ).
    ("scripts/setup_tenant.sh", r'^\s{2}([A-Z][A-Za-z]+(?:\.[A-Za-z]+)+)$'),
    # The client-facing page lists them in a table as `Backticked.Names`.
    ("ONBOARDING.md", r'`([A-Z][A-Za-z]+(?:\.[A-Za-z]+)+)`'),
    ("README.md", r'`([A-Z][A-Za-z]+(?:\.[A-Za-z]+)+)`'),
])
def test_every_required_permission_is_listed(path, pattern):
    required = required_permissions()
    listed = listed_in(path, pattern)

    missing = required - listed
    assert not missing, f"{path} omits: {sorted(missing)}"


@pytest.mark.parametrize("path,pattern", [
    ("scripts/setup_tenant.ps1", r'^\s{4}"([A-Za-z]+(?:\.[A-Za-z]+)+)"$'),
    ("scripts/setup_tenant.sh", r'^\s{2}([A-Z][A-Za-z]+(?:\.[A-Za-z]+)+)$'),
])
def test_scripts_do_not_request_permissions_the_code_never_uses(path, pattern):
    """Asking a client's admin to consent to more than we need is not on."""
    extra = listed_in(path, pattern) - required_permissions()
    assert not extra, f"{path} requests unused permissions: {sorted(extra)}"


def test_setup_scripts_do_not_hardcode_permission_guids():
    """IDs are resolved from Graph at runtime; a pasted GUID would rot silently."""
    guid = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
    for path in ("scripts/setup_tenant.ps1", "scripts/setup_tenant.sh"):
        found = set(guid.findall((ROOT / path).read_text()))
        # The Microsoft Graph resource ID itself is a fixed, well-known constant.
        found.discard("00000003-0000-0000-c000-000000000000")
        assert not found, f"{path} hardcodes permission GUIDs: {found}"


def test_onboarding_page_insists_on_admin_consent():
    """Adding permissions without consenting is the classic silent failure."""
    text = (ROOT / "ONBOARDING.md").read_text().lower()
    assert "grant admin consent" in text
    assert "application permissions" in text
    assert "not delegated" in text or "not delegated" in text.replace("—", "")


def test_onboarding_page_warns_about_the_secret_value():
    """Copying Secret ID instead of Value is the most common mistake."""
    text = (ROOT / "ONBOARDING.md").read_text()
    assert "not `Secret ID`" in text or "not Secret ID" in text
    assert "shown once" in text.lower()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

"""Per-check guidance: what it measures, why it matters, how to fix it.

This lived as a JavaScript object inside security/index.html, where only that
one page could reach it and six of its keys had drifted away from the real
check_name values — so the help button silently did nothing on half the scored
checks, MFA included. Keeping it server-side means the dashboard, the category
pages, and any future report export all read the same text, and the test suite
can assert the keys still line up.

Keys must match the `check_name` values returned by the modules in app/checks/.
tests/test_remediation.py enforces that in both directions.

Portal links intentionally point at stable admin-centre roots rather than deep
blade URLs, which Microsoft reshuffles; the navigation path lives in `fix`.
"""

ENTRA = "https://entra.microsoft.com"
DEFENDER = "https://security.microsoft.com"
EXCHANGE = "https://admin.exchange.microsoft.com"
M365_ADMIN = "https://admin.microsoft.com"
SHAREPOINT_ADMIN = "https://admin.microsoft.com/sharepoint"

# severity: how much a failure here should worry you, independent of point weight.
GUIDANCE = {
    # ---- Identity -------------------------------------------------------
    "mfa_registration": {
        "title": "MFA Registration",
        "severity": "critical",
        "what": "Checks which users have a non-password authentication method registered, read from the tenant-wide authentication methods registration report.",
        "why": "Accounts without MFA are the leading vector for account takeover. Microsoft reports MFA blocks over 99.9% of automated credential attacks.",
        "fix": "Create a Conditional Access policy requiring MFA for all users. Prefer this over per-user MFA, which cannot be scoped or reported on cleanly.",
        "portal": ENTRA,
    },
    "stale_accounts": {
        "title": "Stale Accounts",
        "severity": "info",
        "what": "Identifies user accounts with no sign-in for 90 or more days, based on signInActivity from the Graph API.",
        "why": "Stale accounts that retain licenses and access are unnecessary attack surface. Forgotten accounts are often easy targets.",
        "fix": "Review inactive accounts and disable or delete them. Remove license assignments from accounts that no longer need access.",
        "portal": ENTRA,
    },
    "admin_role_hygiene": {
        "title": "Admin Role Hygiene",
        "severity": "high",
        "what": "Reviews privileged directory role assignments, flagging roles with many members, users holding several roles at once, and guest accounts with any role.",
        "why": "Each admin account is a high-value target. Too many Global Admins, or one user stacking several privileged roles, widens your blast radius considerably. A guest with a directory role is almost always a misconfiguration.",
        "fix": "Remove unnecessary assignments and keep Global Admins to 2–5 accounts. Strip roles from guest accounts. Use PIM for just-in-time elevation instead of standing access.",
        "portal": ENTRA,
    },
    "guest_users": {
        "title": "Guest Users",
        "severity": "info",
        "what": "Counts and lists all external guest accounts (userType = Guest) in the directory.",
        "why": "Guest accounts often persist long after a collaboration ends, retaining access to Teams, SharePoint, and other resources.",
        "fix": "Review guests regularly. Enable Access Reviews for guest accounts and configure a guest expiration policy.",
        "portal": ENTRA,
    },
    "risky_users": {
        "title": "Risky Users",
        "severity": "high",
        "what": "Pulls users flagged by Entra ID Identity Protection as medium or high risk, based on behavioural signals and leaked credentials.",
        "why": "A high-risk user likely has compromised credentials or is showing suspicious activity. These need attention immediately, not at the next review.",
        "fix": "In Identity Protection, review each risky user and either confirm compromise (disable and reset) or dismiss as a false positive. Add a Conditional Access policy requiring MFA on risky sign-ins.",
        "portal": ENTRA,
        "note": "Requires an Entra ID P2 licence. Skips on free and P1 tenants.",
    },
    "pim_standing_roles": {
        "title": "PIM / Standing Roles",
        "severity": "high",
        "what": "Compares permanent privileged role assignments against PIM eligible assignments, flagging standing admin access that should be just-in-time.",
        "why": "Standing admin access means an account is permanently privileged, so a compromise at any moment is a compromise of a live admin. PIM eligibility requires explicit activation with justification and MFA.",
        "fix": "Convert standing assignments to PIM-eligible under Identity Governance → Privileged Identity Management → Microsoft Entra roles.",
        "portal": ENTRA,
        "note": "Requires an Entra ID P2 licence to remediate.",
    },
    "password_policy": {
        "title": "Password Policy",
        "severity": "low",
        "what": "Checks which accounts have password expiration disabled via the DisablePasswordExpiration flag.",
        "why": "Microsoft's current guidance is not to expire passwords where MFA is in place — forced rotation drives predictable patterns (Password1 → Password2). Without MFA, expiration is a reasonable compensating control.",
        "fix": "If MFA is enforced, non-expiring passwords are the recommended posture and this check can be read as informational. If MFA is not enforced, prioritise fixing that first.",
        "portal": M365_ADMIN,
    },
    "sspr_enabled": {
        "title": "Self-Service Password Reset",
        "severity": "medium",
        "what": "Checks whether SSPR is enabled via the tenant authorization policy.",
        "why": "Without SSPR every lockout needs IT, which creates a standing social-engineering opportunity against your helpdesk.",
        "fix": "Enable SSPR under Protection → Password reset. Require at least two authentication methods.",
        "portal": ENTRA,
    },
    "secure_score": {
        "title": "Microsoft Secure Score",
        "severity": "info",
        "what": "Pulls Microsoft's own tenant score along with the highest-value improvement actions still outstanding.",
        "why": "Secure Score reflects Microsoft's view across the whole stack, wider than the CIS controls scored here. The two measure different things and are shown side by side rather than combined.",
        "fix": "Work the improvement actions in descending order of available points. Each links to its own remediation steps in the Defender portal.",
        "portal": f"{DEFENDER}/securescore",
    },

    # ---- Conditional access --------------------------------------------
    "conditional_access": {
        "title": "Conditional Access Policies",
        "severity": "critical",
        "what": "Lists all Conditional Access policies and checks for common gaps — no policies at all, or policies left in report-only mode.",
        "why": "CA is the primary enforcement layer for identity security. A policy in report-only mode logs what it would have done and blocks nothing.",
        "fix": "Promote report-only policies to enforced once you have reviewed their impact. Ensure every admin account is covered by at least one enforced policy requiring MFA.",
        "portal": ENTRA,
    },
    "legacy_auth_blocked": {
        "title": "Legacy Authentication Blocked",
        "severity": "high",
        "what": "Checks for a Conditional Access policy that blocks legacy authentication protocols such as basic auth and older IMAP, POP, and SMTP clients.",
        "why": "Legacy auth protocols cannot do MFA, so attackers target them specifically to bypass it. A tenant with MFA enforced but legacy auth open has a hole straight through the control.",
        "fix": "Create a CA policy with Client apps set to 'Exchange ActiveSync clients' and 'Other clients', with Block access as the grant control. Run it in report-only first to catch legitimate legacy clients.",
        "portal": ENTRA,
    },
    "named_locations": {
        "title": "Named Locations",
        "severity": "low",
        "what": "Checks whether named locations — trusted IP ranges or countries — are defined for use in Conditional Access.",
        "why": "Named locations let you write risk-based policies: step up to MFA outside trusted offices, or block sign-ins from countries you never operate in.",
        "fix": "Add office IP ranges as trusted named locations under Protection → Conditional Access → Named locations, then reference them in policies to cut MFA friction on trusted networks.",
        "portal": ENTRA,
    },

    # ---- Mail security --------------------------------------------------
    "email_authentication": {
        "title": "Email Authentication (SPF/DKIM/DMARC)",
        "severity": "high",
        "what": "Resolves live DNS for every verified tenant domain: SPF at the root, DMARC at _dmarc.<domain>, and DKIM at selector1/selector2._domainkey.<domain>.",
        "why": "Without these records anyone can send mail appearing to come from your domain, making impersonation phishing trivial. Google and Microsoft now require SPF and DMARC for bulk senders.",
        "fix": "Publish an SPF TXT record (v=spf1 include:spf.protection.outlook.com -all), enable DKIM in the Defender portal under Email authentication settings, and publish DMARC starting at p=quarantine before graduating to p=reject.",
        "portal": f"{DEFENDER}/authentication",
    },
    "mailbox_forwarding": {
        "title": "Mailbox Forwarding",
        "severity": "high",
        "what": "Reads each mailbox's settings for a forwarding address that sends mail outside the organisation.",
        "why": "External forwarding is a primary data exfiltration route. Attackers who compromise an account routinely add a forwarding rule to keep reading mail long after the password is reset.",
        "fix": "Remove unexpected forwarding rules, then block the behaviour with an outbound spam policy that disallows automatic forwarding. Enable alerting on newly created forwarding rules.",
        "portal": EXCHANGE,
    },
    "app_credential_expiry": {
        "title": "App Credential Expiry",
        "severity": "medium",
        "what": "Scans app registrations and service principals for client secrets and certificates that have expired or expire within 30 days.",
        "why": "Expired credentials cause silent integration outages. A long-lived secret that nobody rotates is also exactly the kind of credential that ends up committed somewhere it shouldn't be.",
        "fix": "Rotate credentials before expiry and prefer certificate credentials over client secrets for anything long-lived. Delete app registrations that are no longer used.",
        "portal": ENTRA,
    },
    "app_permissions": {
        "title": "App Permissions",
        "severity": "high",
        "what": "Identifies app registrations holding high-risk Graph permissions such as Directory.ReadWrite.All, Mail.ReadWrite, or Files.ReadWrite.All.",
        "why": "An app with write access to every mailbox or file is a full tenant compromise if its credentials leak. Overprivileged apps are the quiet version of an over-permissioned admin.",
        "fix": "Review each flagged app against its actual use case and reduce to least privilege. Remove consent for apps no longer in use.",
        "portal": ENTRA,
    },

    # ---- Licensing ------------------------------------------------------
    "license_summary": {
        "title": "License Summary",
        "severity": "info",
        "what": "Summarises subscribed SKUs and how many seats of each are assigned versus purchased.",
        "why": "Unassigned seats are recurring spend for nothing. This is usually the finding that pays for the audit.",
        "fix": "Reduce seat counts at renewal, or reassign to users currently unlicensed.",
        "portal": M365_ADMIN,
    },
    "user_licenses": {
        "title": "Per-User Licenses",
        "severity": "info",
        "what": "Lists active users and the licences assigned to each, flagging enabled accounts with none.",
        "why": "An enabled account with no licence often means an incomplete offboarding or a service account that should be reviewed.",
        "fix": "Assign licences to users who need them and disable accounts that should no longer be active.",
        "portal": M365_ADMIN,
    },

    # ---- Users ----------------------------------------------------------
    "user_activity": {
        "title": "User Sign-in Activity",
        "severity": "info",
        "what": "Reports last sign-in per user, highlighting licensed accounts inactive for 90 or more days.",
        "why": "A licensed account nobody signs into is both a cost and an unmonitored way in.",
        "fix": "Reclaim licences from inactive users and disable accounts that are no longer needed.",
        "portal": ENTRA,
    },
    "app_usage": {
        "title": "M365 App Usage",
        "severity": "info",
        "what": "Reports which Microsoft 365 applications and platforms each user has actually used in the last 30 days.",
        "why": "Shows whether the licences you are paying for are being used, and which workloads matter before you change anything.",
        "fix": "Informational. Use it to right-size licence tiers and to see which workloads a change would affect.",
        "portal": M365_ADMIN,
    },

    # ---- SharePoint -----------------------------------------------------
    "sharepoint_sites": {
        "title": "SharePoint Site Usage",
        "severity": "info",
        "what": "Reports site inventory, storage consumption, and sites with no activity in 90 days.",
        "why": "Dormant sites accumulate content nobody owns and nobody reviews, while still being shareable.",
        "fix": "Archive or delete inactive sites. Confirm each remaining site has an accountable owner.",
        "portal": SHAREPOINT_ADMIN,
    },
    "external_sharing": {
        "title": "External Sharing Policy",
        "severity": "high",
        "what": "Reads the tenant-level SharePoint and OneDrive external sharing configuration.",
        "why": "A tenant set to 'Anyone' allows anonymous links that need no sign-in and cannot be traced back to a person. This is the most common route to unintentionally public company data.",
        "fix": "Set sharing to 'New and existing guests' at most, so external recipients must authenticate. Reserve 'Anyone' links for specific sites that genuinely need them, with an expiry.",
        "portal": SHAREPOINT_ADMIN,
    },
    "onedrive_usage": {
        "title": "OneDrive Usage",
        "severity": "info",
        "what": "Reports per-account OneDrive storage consumption and activity.",
        "why": "OneDrive accounts belonging to departed staff often persist with company data long after offboarding.",
        "fix": "Confirm offboarding transfers or deletes OneDrive content rather than leaving it orphaned.",
        "portal": SHAREPOINT_ADMIN,
    },

    # ---- Exchange -------------------------------------------------------
    "mailbox_usage": {
        "title": "Mailbox Sizes",
        "severity": "info",
        "what": "Reports mailbox size against quota, highlighting mailboxes approaching their limit.",
        "why": "A mailbox at quota stops receiving mail, which usually surfaces as a user-reported outage rather than an alert.",
        "fix": "Enable archiving for large mailboxes or raise the quota where the licence permits.",
        "portal": EXCHANGE,
    },
    "shared_mailboxes": {
        "title": "Shared Mailboxes",
        "severity": "info",
        "what": "Lists shared mailboxes and who has access to each.",
        "why": "Shared mailboxes are often left with sign-in enabled, which turns them into unmonitored accounts with a password nobody rotates.",
        "fix": "Confirm shared mailbox accounts are blocked from direct sign-in and review delegated access regularly.",
        "portal": EXCHANGE,
    },
    "distribution_lists": {
        "title": "Distribution Lists",
        "severity": "info",
        "what": "Lists mail-enabled distribution groups and their membership counts.",
        "why": "Lists that accept external senders can be used to reach the whole organisation from outside it.",
        "fix": "Restrict delivery management on internal-only lists so external senders are rejected.",
        "portal": EXCHANGE,
    },

    # ---- Groups ---------------------------------------------------------
    "groups": {
        "title": "Group Inventory",
        "severity": "info",
        "what": "Inventories groups with their type and membership, flagging groups with no owner.",
        "why": "An ownerless group has nobody accountable for its membership or the resources attached to it, so access only ever accumulates.",
        "fix": "Assign at least two owners to every group. Remove groups that are no longer in use.",
        "portal": ENTRA,
    },
    "group_expiration": {
        "title": "Group Expiration Policy",
        "severity": "info",
        "what": "Checks whether a Microsoft 365 group lifecycle expiration policy is configured.",
        "why": "Without expiry, groups and their Teams, sites, and mailboxes accumulate indefinitely and nobody ever revisits who is in them.",
        "fix": "Configure a group expiration policy requiring owner renewal, typically on a 180 or 365 day cycle.",
        "portal": ENTRA,
        "note": "Requires Entra ID P1 for the group members involved.",
    },
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def get(check_name):
    """Guidance for one check, or None if there isn't any."""
    return GUIDANCE.get(check_name)


def severity_of(check_name):
    """Severity label for a check, defaulting to 'info' for unknown checks."""
    entry = GUIDANCE.get(check_name)
    return entry["severity"] if entry else "info"


def sort_key(check_name):
    """Order checks worst-first by severity. Useful for report summaries."""
    return SEVERITY_ORDER.get(severity_of(check_name), 99)

"""Expand the app-group tokens a CA policy can target instead of an app id.

`includeApplications` may contain `Office365` or `MicrosoftAdminPortals`, each
standing for a set of applications rather than one. Microsoft recommends the
Office 365 grouping over listing individual apps, so a tenant of any size uses
it, and a simulator that cannot evaluate it cannot evaluate most real policies.

## The two tokens are known with different confidence

`MicrosoftAdminPortals` is enumerated exhaustively in the Conditional Access
documentation, with application ids. Membership is decided exactly.

`Office365` is not. The reference lists the suite by *display name*, says
plainly that it "is subject to change as Microsoft adds or removes services",
and warns that enumerating a tenant's Microsoft service principals
"approximates the Office 365 app suite but might not match it exactly". So
expansion here means matching those published names against the service
principals actually present in the tenant, and that is an approximation by
Microsoft's own account.

Which is exactly why the agreement harness exists. The expansion is not
asserted on the strength of the name list; it is checked against Microsoft's
What If endpoint on real traffic, and a wrong membership decision shows up
there as a disagreement naming the `application` condition. If that ever
happens, the honest fallback is to treat a non-match as unknown rather than as
"outside the suite" — a false non-match reports a policy as affecting nobody,
which is the failure this engine exists to avoid.
"""
from dataclasses import dataclass

OFFICE365 = "office365"
MICROSOFT_ADMIN_PORTALS = "microsoftadminportals"

# Enumerated with ids in the Conditional Access target-resources reference, so
# this grouping is exact rather than approximate.
ADMIN_PORTAL_APP_IDS = frozenset({
    "497effe9-df71-4043-a8bb-14cf78c4b63b",  # Exchange Admin Center
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",  # Azure portal / Entra admin center
    "00000006-0000-0ff1-ce00-000000000000",  # Microsoft Office 365 Portal
    "80ccca67-54bd-44ab-8625-4b79c4dc7775",  # M365 Security and Compliance Center
})

# Display names of the services in the Office 365 app suite, from Microsoft's
# published reference. Matched against the tenant's own service principals to
# get ids, because the reference gives no ids and the ids differ per cloud.
OFFICE365_SUITE_NAMES = frozenset(name.lower() for name in {
    "AI Hub Services", "App Studio for Microsoft Teams", "Augmentation Loop",
    "Call Recorder", "Connectors", "Copilot Data Platform",
    "DataSecurityInvestigation", "Device Management Service", "EDU Assignments",
    "EnrichmentSvc", "Enterprise Copilot Platform", "Groups Service",
    "IC3 Gateway", "IC3 Gateway Non Cae", "Insights Services",
    "INT Augmentation Loop 1P", "Legacy Smart Compose", "Loop",
    "Loop Web Application", "Loop Web Service", "M365 Admin Services",
    "M365 Auditing Public Protected Web API app", "M365ChatClient",
    "make.gov.powerapps.us", "make.powerapps.com",
    "Media Analysis and Transformation Service", "Message Recall",
    "Messaging Async Media", "MessagingAsyncMediaProd",
    "Microsoft 365 eSignature", "Microsoft 365 eSignature PPE",
    "Microsoft 365 Reporting Service", "Microsoft Discovery Service",
    "Microsoft Exchange Online Protection", "Microsoft Flow Portal",
    "Microsoft Flow Portal GCC", "Microsoft Forms", "Microsoft Forms Web",
    "Microsoft Information Protection API", "Microsoft Office",
    "Microsoft Office 365 Portal", "Microsoft People Cards Service",
    "Microsoft Planner", "Microsoft Planner Client",
    "Microsoft SharePoint Online - SharePoint Home", "Microsoft Stream Portal",
    "Microsoft Stream Service", "Microsoft Teams",
    "Microsoft Teams - T4L Web Client",
    "Microsoft Teams - Teams And Channels Service", "Microsoft Teams Analytics",
    "Microsoft Teams Chat Aggregator", "Microsoft Teams Graph Service",
    "Microsoft Teams Mailhook", "Microsoft Teams Retail Service",
    "Microsoft Teams Services", "Microsoft Teams Targeting Application",
    "Microsoft Teams UIS", "Microsoft Teams Web Client",
    "Microsoft To-Do web app", "Microsoft Todo web app",
    "Microsoft Virtual Events Portal", "Microsoft Virtual Events Services",
    "Microsoft Visio Data Visualizer", "Microsoft Whiteboard Services",
    "MSAI Substrate Meeting Intelligence", "Natural Language Editor",
    "O365 Diagnostic Service", "O365 Suite UX", "O365 Suite UX PathFinder",
    "OCPS Checkin Service", "Office 365", "Office 365 Exchange Microservices",
    "Office 365 Exchange Online", "Office 365 Search Service",
    "Office 365 SharePoint Online", "Office Collab Actions", "Office Delve",
    "Office Hive", "Office Hive Fairfax", "Office MRO Device Manager Service",
    "Office Notification Service", "Office Online Add-in SSO",
    "Office Online Augmentation Loop SSO", "Office Online Core SSO",
    "Office Online Loki SSO", "Office Online Maker SSO",
    "Office Online Print SSO", "Office Online Search SSO",
    "Office Online Service", "Office Online Speech SSO",
    "Office Scripts Service", "Office Scripts Service - INT",
    "Office Scripts Service - Local", "Office Scripts Service - Test",
    "Office Shredding Service", "Office.com", "Office365 Shell DoD WCSS-Client",
    "Office365 Shell WCSS-Client", "OfficeClientService", "OfficeHome",
    "OfficePowerPointSGS", "OfficeServicesManager", "Olympus", "OMEX External",
    "One Outlook Web", "OneDrive", "OneDrive SyncEngine", "OneNote",
    "OneOutlook", "Outlook Browser Extension", "Outlook Service for Exchange",
    "PowerApps Service", "Project for the web", "ProjectWorkManagement",
    "ProjectWorkManagement_AdminTools", "ProjectWorkManagement_USGov",
    "Protection Center", "Reply-At-Mention", "SharePoint Notification Services",
    "SharePoint Notification Services Fairfax",
    "SharePoint Online Web Client Extensibility",
    "SharePoint Online Web Client Extensibility Isolated",
    "Skype and Teams Tenant Admin API", "Skype for Business",
    "Skype for Business Online", "Skype Presence Service", "Sway",
    "Targeted Messaging Service", "Teams CMD Services Artifacts",
    "Teams Device Management Services", "Teams Walkie Talkie Service",
    "Teams Walkie Talkie Service - GCC", "Viva Engage",
})


@dataclass(frozen=True)
class AppGroups:
    """Which app-group tokens a resource belongs to, as far as we can tell."""
    tokens: frozenset = frozenset()
    resolved: bool = False

    def contains(self, token):
        """True / False when resolved, None when membership is unknown."""
        if not self.resolved:
            return None
        return token in self.tokens


class AppGroupResolver:
    """Decides app-group membership from the tenant's service principals."""

    def __init__(self, service_principals):
        self.office365_app_ids = set()
        self.matched_names = set()
        for sp in service_principals or []:
            app_id = (sp.get("appId") or "").lower()
            name = (sp.get("displayName") or "").strip().lower()
            if app_id and name in OFFICE365_SUITE_NAMES:
                self.office365_app_ids.add(app_id)
                self.matched_names.add(name)

    @property
    def coverage(self):
        """How much of the published suite this tenant actually has provisioned."""
        return len(self.matched_names), len(OFFICE365_SUITE_NAMES)

    def resolve(self, resource_id):
        if not resource_id:
            return AppGroups(resolved=False)
        resource_id = resource_id.lower()
        tokens = set()
        if resource_id in self.office365_app_ids:
            tokens.add(OFFICE365)
        if resource_id in ADMIN_PORTAL_APP_IDS:
            tokens.add(MICROSOFT_ADMIN_PORTALS)
        return AppGroups(tokens=frozenset(tokens), resolved=True)


def fetch_service_principals(client):
    return client.get_all(
        "/servicePrincipals?$select=id,appId,displayName&$top=999")


def build_resolver(client):
    return AppGroupResolver(fetch_service_principals(client))

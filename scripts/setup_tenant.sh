#!/usr/bin/env bash
# Creates the app registration Tenant Auditor needs, grants admin consent, and
# prints the three values to hand back. Azure CLI equivalent of setup_tenant.ps1.
#
# Run by a Global Administrator in the tenant being audited:
#     az login --allow-no-subscriptions
#     ./setup_tenant.sh "Tenant Auditor (Acme Security)"
#
# Permission IDs are looked up from the Microsoft Graph service principal rather
# than hardcoded, so there are no magic GUIDs to mistype and nothing to drift.

set -euo pipefail

DISPLAY_NAME="${1:-Tenant Auditor}"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"

PERMISSIONS=(
  User.Read.All
  AuditLog.Read.All
  UserAuthenticationMethod.Read.All
  MailboxSettings.Read
  Directory.Read.All
  RoleManagement.Read.Directory
  Policy.Read.All
  IdentityRiskyUser.Read.All
  SecurityEvents.Read.All
  Application.Read.All
  Domain.Read.All
  Organization.Read.All
  Group.Read.All
  Reports.Read.All
  SharePointTenantSettings.Read.All
)

command -v az >/dev/null || { echo "Azure CLI not found: https://aka.ms/azure-cli"; exit 1; }
az account show >/dev/null 2>&1 || { echo "Run 'az login --allow-no-subscriptions' first."; exit 1; }

TENANT_ID=$(az account show --query tenantId -o tsv)
echo
echo "Tenant Auditor — app registration setup"
echo "Tenant: $TENANT_ID"
echo

echo "Resolving permission IDs..."
API_PERMISSIONS=""
for name in "${PERMISSIONS[@]}"; do
  id=$(az ad sp show --id "$GRAPH_APP_ID" \
        --query "appRoles[?value=='$name' && contains(allowedMemberTypes,'Application')].id | [0]" -o tsv)
  if [ -z "$id" ] || [ "$id" = "null" ]; then
    echo "  ERROR: Microsoft Graph has no application permission called '$name'"
    exit 1
  fi
  printf '  %-36s %s\n' "$name" "$id"
  API_PERMISSIONS="$API_PERMISSIONS $id=Role"
done

echo
echo "Creating the application..."
APP_ID=$(az ad app create --display-name "$DISPLAY_NAME" \
          --sign-in-audience AzureADMyOrg --query appId -o tsv)
az ad sp create --id "$APP_ID" >/dev/null 2>&1 || true

echo "Requesting permissions..."
# shellcheck disable=SC2086
az ad app permission add --id "$APP_ID" --api "$GRAPH_APP_ID" \
   --api-permissions $API_PERMISSIONS >/dev/null

echo "Granting admin consent (this can take a few seconds to propagate)..."
sleep 10
az ad app permission admin-consent --id "$APP_ID"

echo "Creating a client secret..."
SECRET=$(az ad app credential reset --id "$APP_ID" --display-name "Tenant Auditor" \
          --years 1 --query password -o tsv)

echo
echo "================================================================"
echo "Send these three values back. The secret is shown once."
echo "================================================================"
echo
echo "Directory (tenant) ID  : $TENANT_ID"
echo "Application (client) ID: $APP_ID"
echo "Client secret          : $SECRET"
echo
echo "================================================================"
echo
echo "Send them over something private — not email."
echo "To revoke access later, delete the '$DISPLAY_NAME' app registration."

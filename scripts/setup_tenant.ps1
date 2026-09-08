<#
.SYNOPSIS
  Creates the app registration Tenant Auditor needs, grants admin consent, and
  prints the three values to hand back.

.DESCRIPTION
  Run by a Global Administrator (or Privileged Role Administrator) in the tenant
  being audited. Every permission requested is read-only.

  Permission IDs are looked up from the Microsoft Graph service principal at
  runtime rather than hardcoded, so this can't drift as Microsoft's catalogue
  changes and there are no magic GUIDs to mistype.

.EXAMPLE
  ./setup_tenant.ps1 -DisplayName "Tenant Auditor (Acme Security)"
#>
[CmdletBinding()]
param(
    [string]$DisplayName = "Tenant Auditor",
    [int]$SecretMonths = 12
)

$ErrorActionPreference = "Stop"

# Read-only, and the same list the application checks for at runtime.
$Permissions = @(
    "User.Read.All"
    "AuditLog.Read.All"
    "UserAuthenticationMethod.Read.All"
    "MailboxSettings.Read"
    "Directory.Read.All"
    "RoleManagement.Read.Directory"
    "Policy.Read.All"
    "IdentityRiskyUser.Read.All"
    "SecurityEvents.Read.All"
    "Application.Read.All"
    "Domain.Read.All"
    "Organization.Read.All"
    "Group.Read.All"
    "Reports.Read.All"
    "SharePointTenantSettings.Read.All"
)

$GraphAppId = "00000003-0000-0000-c000-000000000000"

Write-Host "`nTenant Auditor — app registration setup" -ForegroundColor Cyan
Write-Host "This creates a read-only application and grants consent.`n"

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
    Write-Host "Installing the Microsoft.Graph module (one-off)..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
}

Import-Module Microsoft.Graph.Applications
Import-Module Microsoft.Graph.Authentication

Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All" -NoWelcome
$context = Get-MgContext
Write-Host "Signed in to tenant $($context.TenantId) as $($context.Account)`n"

# Resolve permission names to app role IDs.
$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
$resourceAccess = @()
foreach ($name in $Permissions) {
    $role = $graphSp.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains "Application" }
    if (-not $role) {
        throw "Microsoft Graph does not expose an application permission called '$name'."
    }
    $resourceAccess += @{ Id = $role.Id; Type = "Role" }
    Write-Host ("  resolved {0,-36} {1}" -f $name, $role.Id) -ForegroundColor DarkGray
}

Write-Host "`nCreating the application..." -ForegroundColor Cyan
$app = New-MgApplication -DisplayName $DisplayName -SignInAudience "AzureADMyOrg" `
    -RequiredResourceAccess @(@{ ResourceAppId = $GraphAppId; ResourceAccess = $resourceAccess })

$sp = New-MgServicePrincipal -AppId $app.AppId

# Assigning the app roles to the service principal *is* admin consent for
# application permissions. Without this the permissions are requested but inert.
Write-Host "Granting admin consent..." -ForegroundColor Cyan
foreach ($access in $resourceAccess) {
    try {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id `
            -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $access.Id | Out-Null
    } catch {
        Write-Warning "Could not grant $($access.Id): $($_.Exception.Message)"
    }
}

Write-Host "Creating a client secret..." -ForegroundColor Cyan
$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = "Tenant Auditor"
    EndDateTime = (Get-Date).AddMonths($SecretMonths)
}

Write-Host "`n" ("=" * 64)
Write-Host "Send these three values back. The secret is shown once." -ForegroundColor Green
Write-Host ("=" * 64)
Write-Host ""
Write-Host ("Directory (tenant) ID : {0}" -f $context.TenantId)
Write-Host ("Application (client) ID: {0}" -f $app.AppId)
Write-Host ("Client secret          : {0}" -f $secret.SecretText)
Write-Host ""
Write-Host ("Secret expires         : {0:yyyy-MM-dd}" -f $secret.EndDateTime)
Write-Host ("=" * 64)
Write-Host "`nSend them over something private — not email." -ForegroundColor Yellow
Write-Host "To revoke access later, delete the '$DisplayName' app registration."

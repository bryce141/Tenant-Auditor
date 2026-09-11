<#
.SYNOPSIS
    Seed a DEV tenant with report-only Conditional Access policies, to give the
    CA simulator's agreement harness something real to validate against.

.DESCRIPTION
    The simulator proves its evaluation engine correct by diffing it against
    Microsoft's What If endpoint on a tenant's existing policies. A tenant with
    no policies proves nothing, so this creates a spread chosen to exercise
    every condition the engine implements — and two it deliberately does not,
    so the report's UNSUPPORTED path is exercised honestly too.

    THIS SCRIPT WRITES TO YOUR TENANT. The auditor itself never does; this is
    dev-environment setup, not part of the product.

    Every policy is created in 'enabledForReportingButNotEnforced'.
    That is deliberate and you should not change it:

      * Report-only policies ARE returned by POST /identity/conditionalAccess/
        evaluate with policyApplies set, and they DO appear in sign-in logs as
        reportOnlySuccess / reportOnlyNotApplied, so both halves of the harness
        work at full fidelity.
      * They cannot lock anyone out. An enabled CA policy with a bad condition
        will lock you out of your own tenant, and on a small tenant with no
        break-glass account there is no way back in short of a support case.

    Run against a DEV tenant only. Never a client tenant.

.PARAMETER Execute
    Actually create the policies. Without it the script prints what it would
    create and exits, which is the default because writing to a directory
    should take a deliberate second step.

.PARAMETER Remove
    Delete the policies and groups this script created, matched by name prefix.

.EXAMPLE
    Install-Module Microsoft.Graph -Scope CurrentUser
    Connect-MgGraph -Scopes "Policy.ReadWrite.ConditionalAccess","Group.ReadWrite.All","Application.Read.All"
    ./scripts/seed_ca_test_policies.ps1              # dry run
    ./scripts/seed_ca_test_policies.ps1 -Execute
    ./scripts/seed_ca_test_policies.ps1 -Remove -Execute

.NOTES
    Connect-MgGraph is a first-party Microsoft application, so this needs no app
    registration and leaves no stored secret behind. The permission lives in
    your interactive session and ends with Disconnect-MgGraph.
#>
[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

# Everything this script creates carries this prefix, so -Remove can find its
# own work and nothing else.
$Prefix = "[SIM-TEST]"

# Well-known appIds, used so the policies target something real.
$ExchangeOnline = "00000002-0000-0ff1-ce00-000000000000"
$SharePointOnline = "00000003-0000-0ff1-ce00-000000000000"
# Global Administrator, by role template id.
$GlobalAdminTemplate = "62e90394-69f5-4237-9190-012177145e10"

$REPORT_ONLY = "enabledForReportingButNotEnforced"

function Assert-Connected {
    $context = Get-MgContext
    if (-not $context) {
        throw "Not connected. Run: Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess','Group.ReadWrite.All'"
    }
    Write-Host "Tenant : $($context.TenantId)" -ForegroundColor Cyan
    Write-Host "Account: $($context.Account)`n" -ForegroundColor Cyan
    return $context
}

function New-TestGroup {
    param([string]$Name)

    $full = "$Prefix $Name"
    $existing = Get-MgGroup -Filter "displayName eq '$full'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  group exists: $full" -ForegroundColor DarkGray
        return $existing.Id
    }
    if (-not $Execute) {
        Write-Host "  would create group: $full" -ForegroundColor Yellow
        return "00000000-0000-0000-0000-00000000group"
    }
    $group = New-MgGroup -DisplayName $full -MailEnabled:$false `
        -MailNickname ($Name -replace '[^a-zA-Z0-9]', '') -SecurityEnabled:$true
    Write-Host "  created group: $full" -ForegroundColor Green
    return $group.Id
}

function New-TestPolicy {
    param([string]$Name, [hashtable]$Conditions, [hashtable]$Grant,
          [string]$State = $REPORT_ONLY, [string]$Exercises)

    $full = "$Prefix $Name"
    $existing = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$full'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  exists: $full" -ForegroundColor DarkGray
        return
    }

    if (-not $Execute) {
        Write-Host "  would create: $full" -ForegroundColor Yellow
        Write-Host "      state    : $State"
        Write-Host "      exercises: $Exercises"
        return
    }

    $body = @{ displayName = $full; state = $State; conditions = $Conditions }
    if ($Grant) { $body.grantControls = $Grant }

    New-MgIdentityConditionalAccessPolicy -BodyParameter $body | Out-Null
    Write-Host "  created: $full" -ForegroundColor Green
    Write-Host "      exercises: $Exercises" -ForegroundColor DarkGray
}

function Remove-TestArtifacts {
    $policies = Get-MgIdentityConditionalAccessPolicy -All |
        Where-Object { $_.DisplayName -like "$Prefix*" }
    foreach ($p in $policies) {
        if ($Execute) {
            Remove-MgIdentityConditionalAccessPolicy -ConditionalAccessPolicyId $p.Id
            Write-Host "  deleted policy: $($p.DisplayName)" -ForegroundColor Green
        } else {
            Write-Host "  would delete policy: $($p.DisplayName)" -ForegroundColor Yellow
        }
    }

    $groups = Get-MgGroup -All | Where-Object { $_.DisplayName -like "$Prefix*" }
    foreach ($g in $groups) {
        if ($Execute) {
            Remove-MgGroup -GroupId $g.Id
            Write-Host "  deleted group: $($g.DisplayName)" -ForegroundColor Green
        } else {
            Write-Host "  would delete group: $($g.DisplayName)" -ForegroundColor Yellow
        }
    }

    if (-not $policies -and -not $groups) {
        Write-Host "  nothing to remove." -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------

Assert-Connected | Out-Null

if ($Remove) {
    Write-Host "Removing $Prefix artifacts" -ForegroundColor Cyan
    Remove-TestArtifacts
    if (-not $Execute) {
        Write-Host "`nDry run. Re-run with -Execute to actually delete.`n" -ForegroundColor Yellow
    }
    return
}

if (-not $Execute) {
    Write-Host "DRY RUN — nothing will be written. Re-run with -Execute.`n" -ForegroundColor Yellow
}

Write-Host "Groups" -ForegroundColor Cyan
$pilotGroup = New-TestGroup -Name "Pilot Users"
$breakGlassGroup = New-TestGroup -Name "Break Glass"

Write-Host "`nPolicies (all report-only — none of these can lock anyone out)" -ForegroundColor Cyan

# --- conditions the engine implements -------------------------------------

New-TestPolicy -Name "Baseline MFA for all users" -Exercises "users=All, apps=All, grant=mfa" -Conditions @{
    users = @{ includeUsers = @("All") }
    applications = @{ includeApplications = @("All") }
    clientAppTypes = @("all")
} -Grant @{ operator = "OR"; builtInControls = @("mfa") }

New-TestPolicy -Name "Block legacy authentication" -Exercises "clientAppTypes legacy, grant=block" -Conditions @{
    users = @{ includeUsers = @("All") }
    applications = @{ includeApplications = @("All") }
    clientAppTypes = @("exchangeActiveSync", "other")
} -Grant @{ operator = "OR"; builtInControls = @("block") }

New-TestPolicy -Name "Compliant device for Exchange" -Exercises "specific appId, grant=compliantDevice" -Conditions @{
    users = @{ includeUsers = @("All") }
    applications = @{ includeApplications = @($ExchangeOnline) }
    clientAppTypes = @("all")
} -Grant @{ operator = "OR"; builtInControls = @("compliantDevice") }

New-TestPolicy -Name "Admins require MFA" -Exercises "includeRoles by template id" -Conditions @{
    users = @{ includeUsers = @("None"); includeRoles = @($GlobalAdminTemplate) }
    applications = @{ includeApplications = @("All") }
    clientAppTypes = @("all")
} -Grant @{ operator = "OR"; builtInControls = @("mfa") }

New-TestPolicy -Name "Pilot group with exclusion" -Exercises "includeGroups + excludeGroups, exclusion wins" -Conditions @{
    users = @{ includeUsers = @("None"); includeGroups = @($pilotGroup); excludeGroups = @($breakGlassGroup) }
    applications = @{ includeApplications = @("All") }
    clientAppTypes = @("all")
} -Grant @{ operator = "OR"; builtInControls = @("mfa") }

New-TestPolicy -Name "Mobile platforms require compliance" -Exercises "platforms include/exclude" -Conditions @{
    users = @{ includeUsers = @("All") }
    applications = @{ includeApplications = @("All") }
    clientAppTypes = @("all")
    platforms = @{ includePlatforms = @("android", "iOS"); excludePlatforms = @() }
} -Grant @{ operator = "OR"; builtInControls = @("compliantDevice") }

New-TestPolicy -Name "Guests require MFA" -Exercises "GuestsOrExternalUsers token" -Conditions @{
    users = @{ includeUsers = @("GuestsOrExternalUsers") }
    applications = @{ includeApplications = @("All") }
    clientAppTypes = @("all")
} -Grant @{ operator = "OR"; builtInControls = @("mfa") }

New-TestPolicy -Name "Two controls with AND" -Exercises "grant operator AND with two controls" -Conditions @{
    users = @{ includeUsers = @("All") }
    applications = @{ includeApplications = @($SharePointOnline) }
    clientAppTypes = @("all")
} -Grant @{ operator = "AND"; builtInControls = @("mfa", "compliantDevice") }

# Needs Entra ID P2. On P1 every sign-in reports risk as 'hidden' and the
# engine will correctly call this UNSUPPORTED rather than guessing.
New-TestPolicy -Name "High sign-in risk blocked" -Exercises "signInRiskLevels (needs P2)" -Conditions @{
    users = @{ includeUsers = @("All") }
    applications = @{ includeApplications = @("All") }
    clientAppTypes = @("all")
    signInRiskLevels = @("high")
} -Grant @{ operator = "OR"; builtInControls = @("block") }

# --- states other than report-only ----------------------------------------

New-TestPolicy -Name "Disabled policy" -State "disabled" -Exercises "state=disabled path on both sides" -Conditions @{
    users = @{ includeUsers = @("All") }
    applications = @{ includeApplications = @("All") }
    clientAppTypes = @("all")
} -Grant @{ operator = "OR"; builtInControls = @("block") }

# --- conditions the engine deliberately does NOT implement ----------------
# These should show up in the agreement report as declared gaps, never as
# disagreements. If one of them is ever counted as a disagreement, or silently
# as an agreement, the harness has a bug.

New-TestPolicy -Name "GAP named location" -Exercises "locations — engine reports UNSUPPORTED" -Conditions @{
    users = @{ includeUsers = @("All") }
    applications = @{ includeApplications = @("All") }
    clientAppTypes = @("all")
    locations = @{ includeLocations = @("All"); excludeLocations = @("AllTrusted") }
} -Grant @{ operator = "OR"; builtInControls = @("mfa") }

New-TestPolicy -Name "GAP Office365 app suite" -Exercises "Office365 app group — engine reports UNSUPPORTED" -Conditions @{
    users = @{ includeUsers = @("All") }
    applications = @{ includeApplications = @("Office365") }
    clientAppTypes = @("all")
} -Grant @{ operator = "OR"; builtInControls = @("mfa") }

Write-Host ""
if ($Execute) {
    Write-Host "Done. All policies are report-only and enforce nothing." -ForegroundColor Green
    Write-Host "Next: FLASK_APP=run.py flask ca-validate" -ForegroundColor Cyan
    Write-Host "Clean up later with: ./scripts/seed_ca_test_policies.ps1 -Remove -Execute`n" -ForegroundColor DarkGray
} else {
    Write-Host "Dry run complete. Re-run with -Execute to create these.`n" -ForegroundColor Yellow
}

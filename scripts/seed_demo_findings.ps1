<#
.SYNOPSIS
    Give a DEV tenant the kind of real misconfiguration an audit is supposed to
    catch, so a demo shows findings instead of a clean slate.

.DESCRIPTION
    A freshly built tenant looks suspiciously healthy. That is a bad demo: the
    auditor's value is in what it finds, and the simulator's value is in showing
    who a fix would break. Both need a tenant with something wrong.

    Everything created here is a genuine misconfiguration of the kind that shows
    up in real tenants — standing Global Administrators, a guest with the same
    access as staff, an app registration holding a long-lived secret, an
    ownerless group. None of it is fabricated data: the auditor reads it out of
    the directory exactly as it would from a client's.

    THIS WRITES TO YOUR TENANT and it deliberately weakens it. DEV TENANT ONLY.
    Never point this at anything real. Every item is reversible with -Remove.

    What it does NOT do, and cannot:
      * Risky sign-ins and risky users come from Identity Protection detecting
        real anomalies — impossible travel, anonymised IPs, leaked credentials.
        They cannot be written through Graph. To demo risk you have to earn a
        detection, e.g. by signing in through Tor or a VPN in another country.
      * Mailbox and SharePoint findings need those workloads provisioned.

.PARAMETER TrustedIp
    The egress address to register as a trusted named location. Defaults to the
    address this tenant's own sign-ins actually come from, so the
    "except from trusted locations" pattern demonstrates on real traffic rather
    than on a range nothing matches.

.PARAMETER Execute
    Actually make changes. Without it, every step reports what it would do.

.PARAMETER Remove
    Undo: strip the role assignments, delete the guest, the app registration,
    the ownerless group and the named locations.

.EXAMPLE
    Connect-MgGraph -UseDeviceAuthentication -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Policy.Read.All","Policy.ReadWrite.ConditionalAccess","Application.ReadWrite.All","Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory"
    ./scripts/seed_demo_findings.ps1              # dry run
    ./scripts/seed_demo_findings.ps1 -Execute
    ./scripts/seed_demo_findings.ps1 -Remove -Execute
#>
[CmdletBinding()]
param(
    [string]$TrustedIp = "24.191.194.98",
    [int]$AdminCount = 4,
    [switch]$Execute,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"
$Prefix = "[SIM-TEST]"

$RequiredScopes = @(
    "User.ReadWrite.All", "Group.ReadWrite.All", "Policy.Read.All",
    "Policy.ReadWrite.ConditionalAccess", "Application.ReadWrite.All",
    "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"
)

foreach ($module in @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users",
                      "Microsoft.Graph.Groups", "Microsoft.Graph.Identity.SignIns",
                      "Microsoft.Graph.Identity.DirectoryManagement",
                      "Microsoft.Graph.Applications")) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Install-Module $module -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $module -ErrorAction Stop
}

$ConnectCommand = "Connect-MgGraph -UseDeviceAuthentication -Scopes " +
    (($RequiredScopes | ForEach-Object { "`"$_`"" }) -join ",")

$context = Get-MgContext
if (-not $context) { throw "Not connected. Run:`n`n  $ConnectCommand`n" }

Write-Host "Tenant : $($context.TenantId)" -ForegroundColor Cyan
Write-Host "Account: $($context.Account)" -ForegroundColor Cyan

$missing = $RequiredScopes | Where-Object { $_ -notin $context.Scopes }
if ($missing) {
    throw @"
Missing scope(s): $($missing -join ', ')

RoleManagement.ReadWrite.Directory is new for this script — assigning directory
roles needs it. Reconnect with the full set:

  Disconnect-MgGraph
  $ConnectCommand
"@
}

Write-Host "`nThis DELIBERATELY WEAKENS the tenant. Dev tenants only.`n" -ForegroundColor Yellow

function Step($n, $text) {
    Write-Host "`n[$n] $text" -ForegroundColor Cyan
    Write-Host ("-" * 70) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------

if ($Remove) {
    Step 1 "Removing demo findings"

    $roleNames = @("Global Administrator", "Security Administrator", "User Administrator")
    foreach ($roleName in $roleNames) {
        $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
        if (-not $role) { continue }
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
        foreach ($m in $members) {
            $user = Get-MgUser -UserId $m.Id -ErrorAction SilentlyContinue
            if ($user -and $user.UserPrincipalName -like "simuser*") {
                if ($Execute) {
                    Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -DirectoryObjectId $m.Id
                    Write-Host "  removed $($user.UserPrincipalName) from $roleName" -ForegroundColor Green
                } else {
                    Write-Host "  would remove $($user.UserPrincipalName) from $roleName" -ForegroundColor Yellow
                }
            }
        }
    }

    foreach ($u in (Get-MgUser -All | Where-Object { $_.UserPrincipalName -like "*demoguest*" })) {
        if ($Execute) { Remove-MgUser -UserId $u.Id; Write-Host "  deleted $($u.UserPrincipalName)" -ForegroundColor Green }
        else { Write-Host "  would delete $($u.UserPrincipalName)" -ForegroundColor Yellow }
    }
    foreach ($a in (Get-MgApplication -All | Where-Object { $_.DisplayName -like "$Prefix*" })) {
        if ($Execute) { Remove-MgApplication -ApplicationId $a.Id; Write-Host "  deleted app $($a.DisplayName)" -ForegroundColor Green }
        else { Write-Host "  would delete app $($a.DisplayName)" -ForegroundColor Yellow }
    }
    foreach ($g in (Get-MgGroup -All | Where-Object { $_.DisplayName -like "*Ownerless*" })) {
        if ($Execute) { Remove-MgGroup -GroupId $g.Id; Write-Host "  deleted group $($g.DisplayName)" -ForegroundColor Green }
        else { Write-Host "  would delete group $($g.DisplayName)" -ForegroundColor Yellow }
    }
    foreach ($loc in (Get-MgIdentityConditionalAccessNamedLocation -All | Where-Object { $_.DisplayName -like "$Prefix*" })) {
        if ($Execute) { Remove-MgIdentityConditionalAccessNamedLocation -NamedLocationId $loc.Id; Write-Host "  deleted location $($loc.DisplayName)" -ForegroundColor Green }
        else { Write-Host "  would delete location $($loc.DisplayName)" -ForegroundColor Yellow }
    }
    Write-Host ""
    if (-not $Execute) { Write-Host "Dry run. Re-run with -Execute.`n" -ForegroundColor Yellow }
    return
}

if (-not $Execute) {
    Write-Host "DRY RUN — nothing will be written. Re-run with -Execute.`n" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
Step 1 "Standing privileged access"
Write-Host "  Finding: admin rights held permanently instead of activated on demand." -ForegroundColor DarkGray
Write-Host "  Also makes the simulator's 'Require MFA for admins' preset meaningful —" -ForegroundColor DarkGray
Write-Host "  with one admin it reports one user and looks like a rounding error." -ForegroundColor DarkGray

$roleAssignments = @{
    "Global Administrator"   = 1..$AdminCount
    "Security Administrator" = @(5, 6)
    "User Administrator"     = @(7)
}

foreach ($roleName in $roleAssignments.Keys) {
    $role = Get-MgDirectoryRole -Filter "displayName eq '$roleName'" -ErrorAction SilentlyContinue
    if (-not $role) {
        # A role that has never been used exists only as a template.
        $template = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $roleName }
        if (-not $template) { Write-Host "  no such role: $roleName" -ForegroundColor Yellow; continue }
        if ($Execute) {
            $role = New-MgDirectoryRole -RoleTemplateId $template.Id
        } else {
            Write-Host "  would activate role $roleName" -ForegroundColor Yellow
            continue
        }
    }

    foreach ($i in $roleAssignments[$roleName]) {
        $upn = "simuser{0:d2}@{1}" -f $i, ($context.Account -split "@")[1]
        $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
        if (-not $user) { continue }
        if (-not $Execute) { Write-Host "  would grant $roleName to $upn" -ForegroundColor Yellow; continue }
        try {
            New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id `
                -BodyParameter @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.Id)" }
            Write-Host "  granted $roleName to $upn" -ForegroundColor Green
        } catch {
            Write-Host "  already a member: $upn ($roleName)" -ForegroundColor DarkGray
        }
    }
}

# ---------------------------------------------------------------------------
Step 2 "A guest with the same reach as staff"
Write-Host "  Finding: external identities are the usual soft edge of a tenant." -ForegroundColor DarkGray
Write-Host "  Also gives the 'Guests require MFA' policy something to apply to." -ForegroundColor DarkGray

$domain = ($context.Account -split "@")[1]
$guestUpn = "demoguest@$domain"
$guest = Get-MgUser -Filter "userPrincipalName eq '$guestUpn'" -ErrorAction SilentlyContinue
if ($guest) {
    Write-Host "  exists: $guestUpn" -ForegroundColor DarkGray
} elseif (-not $Execute) {
    Write-Host "  would create guest $guestUpn" -ForegroundColor Yellow
} else {
    # Created directly rather than invited: an invitation sends mail to a real
    # address, and there isn't one.
    $password = -join ((65..90) + (97..122) + (48..57) + (33, 35, 64) | Get-Random -Count 18 | ForEach-Object { [char]$_ })
    $guest = New-MgUser -BodyParameter @{
        AccountEnabled = $true
        DisplayName = "Demo Guest (Contractor)"
        MailNickname = "demoguest"
        UserPrincipalName = $guestUpn
        UserType = "Guest"
        UsageLocation = "US"
        PasswordProfile = @{ Password = $password; ForceChangePasswordNextSignIn = $false }
    }
    Write-Host "  created guest $guestUpn" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
Step 3 "An app registration holding a long-lived secret"
Write-Host "  Finding: a two-year client secret nobody will remember to rotate," -ForegroundColor DarkGray
Write-Host "  on an app requesting far more than it needs." -ForegroundColor DarkGray

$appName = "$Prefix Legacy Integration"
$app = Get-MgApplication -Filter "displayName eq '$appName'" -ErrorAction SilentlyContinue
if ($app) {
    Write-Host "  exists: $appName" -ForegroundColor DarkGray
} elseif (-not $Execute) {
    Write-Host "  would create $appName with a 24-month secret" -ForegroundColor Yellow
} else {
    $graph = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    # Requested, not consented — inert, and exactly how over-scoped apps look
    # in a real tenant before anyone notices.
    $wanted = @("Directory.Read.All", "User.Read.All", "Mail.Read")
    $access = @()
    foreach ($name in $wanted) {
        $role = $graph.AppRoles | Where-Object { $_.Value -eq $name }
        if ($role) { $access += @{ Id = $role.Id; Type = "Role" } }
    }
    $app = New-MgApplication -DisplayName $appName -SignInAudience "AzureADMyOrg" `
        -RequiredResourceAccess @(@{ ResourceAppId = $graph.AppId; ResourceAccess = $access })
    Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
        DisplayName = "never rotated"
        EndDateTime = (Get-Date).AddMonths(24)
    } | Out-Null
    Write-Host "  created $appName (24-month secret, $($access.Count) permissions requested)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
Step 4 "An ownerless group"
Write-Host "  Finding: nobody accountable for who is in it or when it should go." -ForegroundColor DarkGray

$groupName = "$Prefix Ownerless Shared Drive"
$group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
if ($group) {
    Write-Host "  exists: $groupName" -ForegroundColor DarkGray
} elseif (-not $Execute) {
    Write-Host "  would create $groupName with members and no owner" -ForegroundColor Yellow
} else {
    $group = New-MgGroup -DisplayName $groupName -MailEnabled:$false `
        -MailNickname "ownerlessshareddrive" -SecurityEnabled:$true
    foreach ($i in 8..12) {
        $upn = "simuser{0:d2}@{1}" -f $i, $domain
        $u = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
        if ($u) {
            try { New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $u.Id -ErrorAction Stop } catch {}
        }
    }
    Write-Host "  created $groupName with 5 members and no owner" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
Step 5 "Named locations"
Write-Host "  Not a finding — the simulator needs these to demonstrate the" -ForegroundColor DarkGray
Write-Host "  'require MFA except from trusted locations' pattern at all." -ForegroundColor DarkGray

$locations = @(
    @{ Name = "$Prefix HQ Office"; Type = "ip"; Trusted = $true; Ranges = @("$TrustedIp/32") }
    @{ Name = "$Prefix Branch Office"; Type = "ip"; Trusted = $true; Ranges = @("203.0.113.0/24") }
    @{ Name = "$Prefix Restricted Countries"; Type = "country"; Countries = @("RU", "KP", "IR", "CN") }
)

foreach ($spec in $locations) {
    $existing = Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq $spec.Name }
    if ($existing) { Write-Host "  exists: $($spec.Name)" -ForegroundColor DarkGray; continue }
    if (-not $Execute) { Write-Host "  would create $($spec.Name)" -ForegroundColor Yellow; continue }

    if ($spec.Type -eq "ip") {
        $body = @{
            "@odata.type" = "#microsoft.graph.ipNamedLocation"
            displayName = $spec.Name
            isTrusted = $spec.Trusted
            ipRanges = @($spec.Ranges | ForEach-Object {
                @{ "@odata.type" = "#microsoft.graph.iPv4CidrRange"; cidrAddress = $_ }
            })
        }
    } else {
        $body = @{
            "@odata.type" = "#microsoft.graph.countryNamedLocation"
            displayName = $spec.Name
            countriesAndRegions = $spec.Countries
            includeUnknownCountriesAndRegions = $false
        }
    }
    New-MgIdentityConditionalAccessNamedLocation -BodyParameter $body | Out-Null
    Write-Host "  created $($spec.Name)" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
Write-Host "`n" ("=" * 70)
if ($Execute) {
    Write-Host "Done. The tenant now has findings worth showing." -ForegroundColor Green
    Write-Host ("=" * 70)
    Write-Host @"

Already true and worth pointing at during the demo, no seeding needed:

  * Security defaults are OFF and every CA policy is report-only, so nothing
    in this tenant is actually enforced.
  * No user has registered MFA.
  * There are no enabled Conditional Access policies at all.

What this script cannot fake, and why:

  * Risky users and risky sign-ins come from Identity Protection detecting a
    real anomaly. To get one, sign in as a simuser through a VPN in another
    country, or over Tor — that reliably triggers anonymised-IP or impossible
    travel within a few minutes.

Undo everything with: ./scripts/seed_demo_findings.ps1 -Remove -Execute
"@
} else {
    Write-Host "Dry run complete. Re-run with -Execute." -ForegroundColor Yellow
    Write-Host ("=" * 70)
}
Write-Host ""

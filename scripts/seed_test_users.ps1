<#
.SYNOPSIS
    Populate a DEV tenant with test users and groups, so the CA simulator has a
    directory worth simulating against.

.DESCRIPTION
    A three-user tenant produces a corpus too thin to show anything, and two of
    the policies in seed_ca_test_policies.ps1 target groups that have to exist
    before they can be targeted.

    THIS SCRIPT WRITES TO YOUR TENANT, and it creates real accounts with real
    passwords in a real directory. Run it against a DEV tenant only.

    Passwords are written to test-users.json in the repo root, which is
    gitignored. generate_signin_traffic.py reads that file. Delete it when the
    tenant is torn down — a disposable tenant's credentials are still
    credentials.

.PARAMETER Count
    How many users to create. The default of 20 is chosen so aggregate impact
    numbers read as a real tenant rather than a toy.

.PARAMETER Execute
    Actually create things. Without it the script prints its plan and exits.

.PARAMETER Remove
    Delete the users and groups this script created, matched by name prefix.

.EXAMPLE
    Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Organization.Read.All"
    ./scripts/seed_test_users.ps1                 # dry run
    ./scripts/seed_test_users.ps1 -Execute
    ./scripts/seed_test_users.ps1 -Remove -Execute
#>
[CmdletBinding()]
param(
    [int]$Count = 20,
    [switch]$Execute,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

# Everything created here carries this, so -Remove finds its own work only.
$Prefix = "simuser"
$GroupPrefix = "[SIM-TEST]"
$CredentialFile = Join-Path (Split-Path $PSScriptRoot -Parent) "test-users.json"

function Get-InitialDomain {
    $domain = Get-MgDomain | Where-Object { $_.IsInitial } | Select-Object -First 1
    if (-not $domain) {
        $domain = Get-MgDomain | Where-Object { $_.IsDefault } | Select-Object -First 1
    }
    if (-not $domain) { throw "Could not determine a verified domain for this tenant." }
    return $domain.Id
}

function New-StrongPassword {
    # Entra rejects weak passwords, and a rejected password surfaces as an
    # opaque request error rather than a useful message. Guarantee one of each
    # required class rather than hoping randomness supplies them.
    $upper = [char[]]"ABCDEFGHJKLMNPQRSTUVWXYZ"
    $lower = [char[]]"abcdefghijkmnpqrstuvwxyz"
    $digit = [char[]]"23456789"
    $symbol = [char[]]"!@#$%^&*-_=+"
    $all = $upper + $lower + $digit + $symbol

    $chars = @(
        $upper | Get-Random
        $lower | Get-Random
        $digit | Get-Random
        $symbol | Get-Random
    )
    $chars += 1..12 | ForEach-Object { $all | Get-Random }
    return -join ($chars | Sort-Object { Get-Random })
}

function Remove-TestArtifacts {
    $users = Get-MgUser -All -Property "id,userPrincipalName,displayName" |
        Where-Object { $_.UserPrincipalName -like "$Prefix*" }
    foreach ($u in $users) {
        if ($Execute) {
            Remove-MgUser -UserId $u.Id
            Write-Host "  deleted user: $($u.UserPrincipalName)" -ForegroundColor Green
        } else {
            Write-Host "  would delete user: $($u.UserPrincipalName)" -ForegroundColor Yellow
        }
    }

    $groups = Get-MgGroup -All | Where-Object { $_.DisplayName -like "$GroupPrefix*" }
    foreach ($g in $groups) {
        if ($Execute) {
            Remove-MgGroup -GroupId $g.Id
            Write-Host "  deleted group: $($g.DisplayName)" -ForegroundColor Green
        } else {
            Write-Host "  would delete group: $($g.DisplayName)" -ForegroundColor Yellow
        }
    }

    if ($Execute -and (Test-Path $CredentialFile)) {
        Remove-Item $CredentialFile
        Write-Host "  deleted $CredentialFile" -ForegroundColor Green
    }
    if (-not $users -and -not $groups) {
        Write-Host "  nothing to remove." -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------

$context = Get-MgContext
if (-not $context) {
    throw "Not connected. Run: Connect-MgGraph -Scopes 'User.ReadWrite.All','Group.ReadWrite.All','Organization.Read.All'"
}
Write-Host "Tenant : $($context.TenantId)" -ForegroundColor Cyan
Write-Host "Account: $($context.Account)`n" -ForegroundColor Cyan

if ($Remove) {
    Write-Host "Removing test users and groups" -ForegroundColor Cyan
    Remove-TestArtifacts
    if (-not $Execute) {
        Write-Host "`nDry run. Re-run with -Execute to actually delete.`n" -ForegroundColor Yellow
    }
    return
}

if (-not $Execute) {
    Write-Host "DRY RUN — nothing will be written. Re-run with -Execute.`n" -ForegroundColor Yellow
}

$domain = Get-InitialDomain
Write-Host "Domain: $domain`n" -ForegroundColor Cyan

# --- users ----------------------------------------------------------------

Write-Host "Users" -ForegroundColor Cyan
$created = @()

for ($i = 1; $i -le $Count; $i++) {
    $name = "{0}{1:d2}" -f $Prefix, $i
    $upn = "$name@$domain"
    $password = New-StrongPassword

    $existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  exists: $upn" -ForegroundColor DarkGray
        continue
    }

    if (-not $Execute) {
        Write-Host "  would create: $upn" -ForegroundColor Yellow
        continue
    }

    $profile = @{
        AccountEnabled = $true
        DisplayName = "Sim User $i"
        MailNickname = $name
        UserPrincipalName = $upn
        PasswordProfile = @{
            Password = $password
            # ROPC sign-ins fail outright against an account that must change
            # its password, and a forced change cannot be completed headlessly.
            ForceChangePasswordNextSignIn = $false
        }
        UsageLocation = "US"
    }

    $user = New-MgUser -BodyParameter $profile
    $created += [pscustomobject]@{
        userPrincipalName = $upn
        password = $password
        id = $user.Id
    }
    Write-Host "  created: $upn" -ForegroundColor Green
}

# --- groups ---------------------------------------------------------------
# These names match the ones seed_ca_test_policies.ps1 targets.

Write-Host "`nGroups" -ForegroundColor Cyan
$groupPlan = @{
    "Pilot Users" = { param($index) $index % 3 -eq 0 }   # roughly a third
    "Break Glass" = { param($index) $index -eq 1 }       # exactly one
}

foreach ($groupName in $groupPlan.Keys) {
    $full = "$GroupPrefix $groupName"
    $group = Get-MgGroup -Filter "displayName eq '$full'" -ErrorAction SilentlyContinue

    if (-not $group) {
        if (-not $Execute) {
            Write-Host "  would create group: $full" -ForegroundColor Yellow
            continue
        }
        $group = New-MgGroup -DisplayName $full -MailEnabled:$false `
            -MailNickname ($groupName -replace '[^a-zA-Z0-9]', '') -SecurityEnabled:$true
        Write-Host "  created group: $full" -ForegroundColor Green
    } else {
        Write-Host "  group exists: $full" -ForegroundColor DarkGray
    }

    if (-not $Execute) { continue }

    $predicate = $groupPlan[$groupName]
    $added = 0
    for ($i = 1; $i -le $Count; $i++) {
        if (-not (& $predicate $i)) { continue }
        $upn = "{0}{1:d2}@{2}" -f $Prefix, $i, $domain
        $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
        if (-not $user) { continue }
        try {
            New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
            $added++
        } catch {
            # Already a member is the common case on a re-run, and is fine.
        }
    }
    Write-Host "    members added: $added" -ForegroundColor DarkGray
}

# --- credentials ----------------------------------------------------------

if ($Execute -and $created.Count -gt 0) {
    $existingFile = @()
    if (Test-Path $CredentialFile) {
        $existingFile = Get-Content $CredentialFile -Raw | ConvertFrom-Json
    }
    $all = @($existingFile) + $created | Where-Object { $_ }
    $all | ConvertTo-Json -Depth 3 | Set-Content $CredentialFile
    Write-Host "`nWrote $($created.Count) credential(s) to $CredentialFile" -ForegroundColor Green
    Write-Host "This file is gitignored. Delete it when the tenant is torn down." -ForegroundColor DarkGray
}

Write-Host ""
if ($Execute) {
    Write-Host "Done." -ForegroundColor Green
    Write-Host "Licences: assign Entra ID P2 to these users in the admin center — " -ForegroundColor Cyan
    Write-Host "  risk detection is per-user, and without it every sign-in reports risk as 'hidden'." -ForegroundColor DarkGray
    Write-Host "Next: ./scripts/seed_ca_test_policies.ps1 -Execute" -ForegroundColor Cyan
    Write-Host "Then: python scripts/generate_signin_traffic.py`n" -ForegroundColor Cyan
} else {
    Write-Host "Dry run complete. Re-run with -Execute.`n" -ForegroundColor Yellow
}

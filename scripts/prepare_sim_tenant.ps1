<#
.SYNOPSIS
    Take a blank, licensed dev tenant to the point where the CA simulator has
    something real to measure. One command after Connect-MgGraph.

.DESCRIPTION
    Runs the whole preparation in the order the dependencies demand:

      1. Disable Security Defaults        (CA policies cannot coexist with them)
      2. Create the auditor app registration, consent it, mint a secret
      3. Allow public client flows on it  (the traffic generator needs this)
      4. Create test users and groups
      5. Assign premium licences          (risk detection is per-user)
      6. Create the report-only CA policies

    Steps 1, 3 and 5 are Graph calls, not portal clicks. They are here because
    they are easy to forget and each one fails later in a way that reads as an
    unrelated bug: CA policy creation rejected, the traffic generator unable to
    authenticate, and every sign-in reporting risk as 'hidden' respectively.

    THIS WRITES TO YOUR TENANT — accounts, policies, and directory settings.
    Run it against a DEV tenant only. Never a client tenant.

.PARAMETER Execute
    Actually make changes. Without it every step reports what it would do.

.EXAMPLE
    pwsh
    Connect-MgGraph -UseDeviceAuthentication -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Organization.Read.All","Policy.ReadWrite.ConditionalAccess","Application.ReadWrite.All","Directory.ReadWrite.All"
    ./scripts/prepare_sim_tenant.ps1              # dry run
    ./scripts/prepare_sim_tenant.ps1 -Execute
#>
[CmdletBinding()]
param(
    [int]$UserCount = 20,
    [string]$AppDisplayName = "Tenant Auditor",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot

# Set-MgUserLicense lives in Users.Actions, which is not pulled in by the
# modules the other scripts need — and its absence only shows up at step 5,
# after the tenant has already been half prepared.
foreach ($module in @("Microsoft.Graph.Authentication", "Microsoft.Graph.Users",
                      "Microsoft.Graph.Users.Actions", "Microsoft.Graph.Groups",
                      "Microsoft.Graph.Identity.SignIns",
                      "Microsoft.Graph.Identity.DirectoryManagement",
                      "Microsoft.Graph.Applications")) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing $module (one-off)..." -ForegroundColor Yellow
        Install-Module $module -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $module -ErrorAction Stop
}

function Step($number, $text) {
    Write-Host "`n[$number] $text" -ForegroundColor Cyan
    Write-Host ("-" * 70) -ForegroundColor DarkGray
}

# Policy.Read.All is required to so much as READ the security defaults policy,
# and is required alongside Policy.ReadWrite.ConditionalAccess to update it.
# Leaving it out produces a 403 at step 1 and nowhere else.
$RequiredScopes = @(
    "User.ReadWrite.All"
    "Group.ReadWrite.All"
    "Organization.Read.All"
    "Policy.Read.All"
    "Policy.ReadWrite.ConditionalAccess"
    "Application.ReadWrite.All"
    "Directory.ReadWrite.All"
)

$ConnectCommand = "Connect-MgGraph -UseDeviceAuthentication -Scopes " +
    (($RequiredScopes | ForEach-Object { "`"$_`"" }) -join ",")

$context = Get-MgContext
if (-not $context) {
    throw "Not connected. Run:`n`n  $ConnectCommand`n"
}

Write-Host "Tenant : $($context.TenantId)" -ForegroundColor Cyan
Write-Host "Account: $($context.Account)" -ForegroundColor Cyan

# Check the consented scopes up front rather than discovering a gap partway
# through, with the tenant already half prepared.
$missing = $RequiredScopes | Where-Object { $_ -notin $context.Scopes }
if ($missing) {
    throw @"
The current session is missing scope(s): $($missing -join ', ')

Reconnect with the full set — consent is per-session, so an earlier connection
with fewer scopes does not carry over:

  Disconnect-MgGraph
  $ConnectCommand
"@
}

# The account exists in more than one tenant, and Connect-MgGraph picks one.
# Preparing the wrong tenant is slow to notice and annoying to undo.
Write-Host "`nCheck that tenant id is the NEW licensed tenant before continuing." -ForegroundColor Yellow

if (-not $Execute) {
    Write-Host "`nDRY RUN — nothing will be written. Re-run with -Execute.`n" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
Step 1 "Security Defaults"

# Read it explicitly rather than letting a failure fall through. A 403 here
# leaves $sd null, and `-not $sd.IsEnabled` is then TRUE — so a permission
# error reads as "already disabled", the precondition gets skipped, and step 6
# fails later for reasons that look nothing like the actual cause.
$sd = $null
try {
    $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
} catch {
    throw "Could not read the security defaults policy: " +
          $_.Exception.Message.Split([Environment]::NewLine)[0] +
          "`n`nThis is not the same as it being disabled, so preparation stops here."
}

if ($sd -eq $null) {
    throw "The security defaults policy read returned nothing. Stopping rather than assuming it is off."
} elseif (-not $sd.IsEnabled) {
    Write-Host "  already disabled." -ForegroundColor DarkGray
} elseif (-not $Execute) {
    Write-Host "  would disable (currently ENABLED — CA policy creation will fail)" -ForegroundColor Yellow
} else {
    Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -IsEnabled:$false
    Write-Host "  disabled." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
Step 2 "App registration"

$app = Get-MgApplication -Filter "displayName eq '$AppDisplayName'" -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($app) {
    Write-Host "  exists: $($app.DisplayName) ($($app.AppId))" -ForegroundColor DarkGray
    Write-Host "  NOTE: the secret is only shown when the app is first created." -ForegroundColor Yellow
    Write-Host "  If you don't have it, delete the app and re-run, or add a secret in the portal." -ForegroundColor Yellow
} elseif (-not $Execute) {
    Write-Host "  would create '$AppDisplayName', consent 15 permissions, mint a secret" -ForegroundColor Yellow
} else {
    & (Join-Path $here "setup_tenant.ps1") -DisplayName $AppDisplayName
    $app = Get-MgApplication -Filter "displayName eq '$AppDisplayName'" | Select-Object -First 1
}

# ---------------------------------------------------------------------------
Step 3 "Public client flows"

if (-not $app) {
    Write-Host "  skipped — no app yet (dry run)." -ForegroundColor DarkGray
} elseif ($app.IsFallbackPublicClient) {
    Write-Host "  already enabled." -ForegroundColor DarkGray
} elseif (-not $Execute) {
    Write-Host "  would enable (the traffic generator cannot authenticate without it)" -ForegroundColor Yellow
} else {
    Update-MgApplication -ApplicationId $app.Id -IsFallbackPublicClient
    Write-Host "  enabled." -ForegroundColor Green
}

# ---------------------------------------------------------------------------
Step 4 "Test users and groups"

if ($Execute) {
    & (Join-Path $here "seed_test_users.ps1") -Count $UserCount -Execute
} else {
    & (Join-Path $here "seed_test_users.ps1") -Count $UserCount
}

# ---------------------------------------------------------------------------
Step 5 "Licences"

$skus = Get-MgSubscribedSku
if (-not $skus) {
    Write-Host "  no subscriptions visible in this tenant — is it the licensed one?" -ForegroundColor Red
} else {
    # Prefer a SKU that actually carries Entra ID Premium P2, since that is what
    # turns risk levels from 'hidden' into real values.
    $preferred = @("AAD_PREMIUM_P2", "AAD_PREMIUM", "EMSPREMIUM", "ENTERPRISEPREMIUM")
    $sku = $null
    foreach ($part in $preferred) {
        $sku = $skus | Where-Object { $_.SkuPartNumber -eq $part } | Select-Object -First 1
        if ($sku) { break }
    }
    if (-not $sku) { $sku = $skus | Select-Object -First 1 }

    $free = $sku.PrepaidUnits.Enabled - $sku.ConsumedUnits
    Write-Host "  using $($sku.SkuPartNumber) — $free of $($sku.PrepaidUnits.Enabled) seats free"

    $simUsers = Get-MgUser -All -Property "id,userPrincipalName,usageLocation,assignedLicenses" |
        Where-Object { $_.UserPrincipalName -like "simuser*" }

    $assigned = 0
    foreach ($u in $simUsers) {
        if ($u.AssignedLicenses | Where-Object { $_.SkuId -eq $sku.SkuId }) { continue }
        if (-not $Execute) { $assigned++; continue }
        try {
            # assignLicense rejects a user with no usageLocation, which is why
            # seed_test_users.ps1 sets one at creation.
            Set-MgUserLicense -UserId $u.Id `
                -AddLicenses @(@{ SkuId = $sku.SkuId }) -RemoveLicenses @() | Out-Null
            $assigned++
        } catch {
            Write-Host "    could not licence $($u.UserPrincipalName): $($_.Exception.Message.Split([Environment]::NewLine)[0])" -ForegroundColor Yellow
        }
    }
    if ($Execute) {
        Write-Host "  licensed $assigned user(s)." -ForegroundColor Green
    } else {
        Write-Host "  would licence $assigned user(s)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
Step 6 "Conditional Access policies"

if ($Execute) {
    & (Join-Path $here "seed_ca_test_policies.ps1") -Execute
} else {
    & (Join-Path $here "seed_ca_test_policies.ps1")
}

# ---------------------------------------------------------------------------
Write-Host "`n" ("=" * 70)
if ($Execute) {
    Write-Host "Tenant prepared." -ForegroundColor Green
    Write-Host ("=" * 70)
    Write-Host @"

Remaining, and only these:

  1. Send the three values printed in step 2 (tenant id, client id, secret).
     Over something private, not chat with history.

  2. Sign in as two or three of the simuser accounts from a phone and a
     laptop, at https://portal.office.com — passwords are in test-users.json.
     Five minutes, and it is the only source of real device platform and
     country data. Scripted traffic cannot produce either.

Everything after that is scripted.
"@
} else {
    Write-Host "Dry run complete. Re-run with -Execute." -ForegroundColor Yellow
    Write-Host ("=" * 70)
}
Write-Host ""

<#

.SYNOPSIS
- Scans Exchange Online user mailboxes for U.S. Social Security Numbers (SSNs) using Microsoft Graph API.
- Applies confidence scoring (High, Medium, Low) based on keyword proximity and regex patterns.
- Exports matches to CSV for review, with optional per-item deletion prompt.

.DESCRIPTION
- This script is intended as a forensic and compliance gap solution where Microsoft Purview fails to detect or act on messages at rest in Exchange Online mailboxes.

Key Features:
- Full mailbox scan using Microsoft Graph (Mail.ReadWrite scope)
- Regex + contextual keyword scoring to avoid false positives
- CSV export of matches with subject, sender, timestamp, and confidence level
- Optional interactive deletion for matched messages

.NOTES
- Use in accordance with your organization's legal and compliance policies. 
- Production-use should incorporate access control, logging, and optional automation hardening.

.AUTHOR
Matthew Silcox
Data Security Architect

#>

#Set function max to account for outdated powershell versions...graph module can easily reach the default limit
$MaximumFunctionCount = 9999

# Check if Microsoft.Graph is installed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Output "Microsoft.Graph module not found. Installing..."
    try {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force -ErrorAction Stop
        Write-Output "Microsoft.Graph module installed successfully."
    } catch {
        Write-Error "Failed to install Microsoft.Graph module: $_"
        exit
    }
} else {
    Write-Output "Microsoft.Graph module already installed."
}

# Import the module if not already imported
if (-not (Get-Module -Name Microsoft.Graph)) {
    try {
        Import-Module Microsoft.Graph -ErrorAction Stop
        Write-Output "Microsoft.Graph module imported successfully."
    } catch {
        Write-Error "Failed to import Microsoft.Graph module: $_"
        exit
    }
} else {
    Write-Output "Microsoft.Graph module already imported."
}

# Tenant and App Registration Details
$tenantId     = "#YOUR TENANT ID"
$clientId     = "#YOUR CLIENT ID"
$clientSecret = "#YOUR CLIENT SECRET"

$secureClientSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
$clientCredential = New-Object System.Management.Automation.PSCredential($clientId, $secureClientSecret)

Write-Output "Connecting to Graph API..."
Connect-MgGraph -TenantId $tenantId -ClientSecretCredential $clientCredential

# SSN Patterns
$ssnFormatted    = '\b\d{3}-\d{2}-\d{4}\b'
$ssnUnformatted  = '\b\d{9}\b'
$ssnRandomized   = '\b\d{3}[\s-.]?\d{2}[\s-.]?\d{4}\b'

# Microsoft-defined SSN keywords
$ssnKeywords = @(
    "SSA Number", "social security number", "social security #", "social security#",
    "social security no", "Social Security#", "Soc Sec", "SSN", "SSNS", "SSN#", "SS#", "SSID"
)

function Remove-HtmlTags {
    param ([string]$html)
    return ([regex]::Replace($html, '<[^>]*>', ' '))
}

function Get-MatchContext {
    param (
        [string]$text,
        [string]$pattern,
        [int]$contextLength = 150
    )
    $matches = [regex]::Matches($text, $pattern)
    $contexts = @()
    foreach ($match in $matches) {
        $start = [Math]::Max(0, $match.Index - $contextLength)
        $length = [Math]::Min($contextLength * 2 + $match.Length, $text.Length - $start)
        $contexts += $text.Substring($start, $length).Replace("`r", "").Replace("`n", " ")
    }
    return $contexts -join "`n---`n"
}

function Classify-SSNConfidence {
    param ([string]$text)
    $confidence = "None"
    foreach ($keyword in $ssnKeywords) {
        if ($text -match "(?i)\b$keyword\b") {
            if ($text -match $ssnFormatted)       { return "High" }
            elseif ($text -match $ssnUnformatted) { return "Medium" }
            elseif ($text -match $ssnRandomized)  { return "Low" }
        }
    }
    return $confidence
}

# Collect results
Write-Output "Gathering user mailboxes..."
$users = Get-MgUser -All | Where-Object { $_.Mail -ne $null }
$results = @()

foreach ($user in $users) {
    Write-Host "Scanning mailbox:" $user.Mail -ForegroundColor Cyan
    try {
        $messages = Get-MgUserMessage -UserId $user.Id -Top 1000 -Select "id,subject,sentDateTime,from"
    } catch {
        Write-Warning "Failed to retrieve messages for $($user.Mail): $_"
        continue
    }

    foreach ($msg in $messages) {
        try {
            $fullMessage = Get-MgUserMessage -UserId $user.Id -MessageId $msg.Id
            $bodyContent = Remove-HtmlTags $fullMessage.Body.Content
        } catch {
            Write-Warning "Failed to retrieve full content for message ID $($msg.Id) in $($user.Mail): $_"
            continue
        }

        $confidence = Classify-SSNConfidence -text $bodyContent
        if ($confidence -ne "None") {
            $matchContext = Get-MatchContext -text $bodyContent -pattern $ssnRandomized
            Write-Host "Match found:" $msg.Subject "- Confidence:" $confidence -ForegroundColor Green

            $results += [PSCustomObject]@{
                Mailbox        = $user.Mail
                UserId         = $user.Id
                Subject        = $msg.Subject
                Confidence     = $confidence
                From           = $msg.From.EmailAddress.Address
                SentDateTime   = $msg.SentDateTime
                MessageId      = $msg.Id
                MatchPreview   = $matchContext
            }
        }
        Start-Sleep -Milliseconds 300
    }
}

# Export to CSV
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$csvPath = ".\\SSN_Email_Report_$timestamp.csv"
$results | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Report exported to $csvPath" -ForegroundColor Yellow

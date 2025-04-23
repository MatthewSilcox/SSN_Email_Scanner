function Remove-EmailsFromCsvReport {
    <#
    .SYNOPSIS
        Deletes Exchange Online emails based on a reviewed CSV report.

    .DESCRIPTION
        After manually reviewing a CSV report (exported from the SSN detection script), this function deletes the specified emails.

    .PARAMETER ReviewedCsvPath
        Path to the manually reviewed CSV file.

    .PARAMETER LogFilePath
        Optional log file path for deletion actions. Defaults to ".\SSN_Deletion_Log_[timestamp].txt".

    .EXAMPLE
        Remove-EmailsFromCsvReport -ReviewedCsvPath ".\Reviewed_SSN_Results.csv"

    .NOTES
        Ensure Microsoft Graph is connected (Connect-MgGraph) with appropriate Mail.ReadWrite permissions before running.

    .AUTHOR

        Matthew Silcox
        Data Security Architect
        
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ReviewedCsvPath,

        [Parameter(Mandatory=$false)]
        [string]$LogFilePath = ".\SSN_Deletion_Log_$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
    )

    if (-not (Get-MgContext)) {
        Write-Error "Authenticate first with Connect-MgGraph."
        return
    }

    if (-not (Test-Path $ReviewedCsvPath)) {
        Write-Error "CSV file not found: $ReviewedCsvPath"
        return
    }

    $entries = Import-Csv -Path $ReviewedCsvPath

    foreach ($entry in $entries) {
        $userId = $entry.UserId
        $messageId = $entry.MessageId
        $subject = $entry.Subject
        $mailbox = $entry.Mailbox

        Write-Host "Deleting '$subject' from $mailbox..." -ForegroundColor Cyan

        try {
            Remove-MgUserMessage -UserId $userId -MessageId $messageId
            $log = "[$(Get-Date -Format u)] Deleted: '$subject' from $mailbox (MessageId: $messageId)"
            Write-Host $log -ForegroundColor Green
        }
        catch {
            $log = "[$(Get-Date -Format u)] FAILED: '$subject' from $mailbox - $_"
            Write-Warning $log
        }

        Add-Content -Path $LogFilePath -Value $log

        Start-Sleep -Milliseconds 250
    }

    Write-Host "Deletion complete. Log saved to: $LogFilePath" -ForegroundColor Yellow
}

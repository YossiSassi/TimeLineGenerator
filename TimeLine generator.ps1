## AD account timeline generator - parse DC security logs for activity timeline
## by 1nTh35h311 (comments welcome to yossis@protonmail.com)
## work in progress (need to add help, etc)

param (
[cmdletbinding()]

[Parameter(Mandatory = $false)]
$PathToEvtxFiles = [System.String]::empty,

[Parameter(Mandatory = $false)]
[string]$DomainName = $env:USERDOMAIN,

[Parameter(Mandatory = $false)]
[string]$DomainFQDN = $env:USERDNSDOMAIN,

[ValidateSet("Full-Longer", "Focused-Quicker", IgnoreCase = $true)]
[Parameter(Mandatory = $false)]
[String[]]$ReportType = "Focused-Quicker",

[Parameter(Mandatory = $false)]
$MaxEventsPerDC = [long]::MaxValue # Can limit for the last X events from the log, if we'd like
)

## version info & other variables (as needed)
$version = "0.9";
[string]$ExportToCSVFileName = "$(Get-Location)\Timeline_Generator_Report_$ReportType_$(Get-Date -Format HHmmssddmmyyyy).csv"

## Helper functions
function Start-TimerLoop {
    [cmdletbinding()]
    param (
        [int]$Interval
    )

    [int]$counter = 1;

    while ((Get-Job -IncludeChildJob).ChildJobs | where state -ne "Completed") {
        cls; write-Host "[x] Checking completion status every $Interval seconds... (lapse $counter)`n";
        # Show jobs status, and memory consumption
        $((Get-Job -IncludeChildJob).ChildJobs) | select Location,state | Format-Table -AutoSize -Wrap
        
        Write-Host "`nLocal Working set (memory): $([math]::Round((ps -id $PID).WorkingSet64/1mb)) MB; Commit size: $([math]::Round((ps -id $PID).PM/1mb)) MB`n" -ForegroundColor Yellow;
        # Sleep for the specified interval
        Start-Sleep -Seconds $Interval; $counter++
    }
}

## Stage 1: Collect relevant events from all DCs, or a folder with .evtx file(s)
$Ascii = @'
  _______                __    _               ______                           __            
 /_  __(_)___ ___  ___  / /   (_)___  ___     / ____/__  ____  ___  _________ _/ /_____  _____
  / / / / __ `__ \/ _ \/ /   / / __ \/ _ \   / / __/ _ \/ __ \/ _ \/ ___/ __ `/ __/ __ \/ ___/
 / / / / / / / / /  __/ /___/ / / / /  __/  / /_/ /  __/ / / /  __/ /  / /_/ / /_/ /_/ / /    
/_/ /_/_/ /_/ /_/\___/_____/_/_/ /_/\___/   \____/\___/_/ /_/\___/_/   \__,_/\__/\____/_/     

'@

Write-Host "$Ascii`nAD account timeline generator v$Version (1nTh35h311 #yossi_sassi)`n" -ForegroundColor Magenta;

# Check if working with local EVTx files from a folder, or via the network against live Domain Controllers
if ($PathToEvtxFiles -ne [System.String]::Empty) {
    # get events from local folder with evtx file(s)
    $Files = Get-ChildItem $PathToEvtxFiles -Filter *.evtx -File | select -ExpandProperty fullname;
    Write-Host "[x] Parsing $(($Files | Measure-Object).Count) file(s) from folder $PathToEvtxFiles...";
    $Files | foreach {
    $FileName = $_;
    if ($ReportType -eq "Focused-Quicker") {
        if ($MaxEventsPerDC -eq [long]::MaxValue)
            {
                $global:JobsData += Get-WinEvent -Path $FileName -FilterXPath "*[System[EventID=4634 or EventID=4624 or EventID=4768 or EventID=4769 or EventID=4776 or EventID=4625 or EventID=4672]]"
            }
        else
            {
                $global:JobsData += Get-WinEvent -Path $FileName -FilterXPath "*[System[EventID=4634 or EventID=4624 or EventID=4768 or EventID=4769 or EventID=4776 or EventID=4625 or EventID=4672]]" -MaxEvents $MaxEventsPerDC
            }
        } 
    else {
        # Full-Longer report, from local Evtx folder
        if ($MaxEventsPerDC -eq [long]::MaxValue)
            {
                $global:JobsData += Get-WinEvent -Path $Filename
            }
        else 
            {
                $global:JobsData += Get-WinEvent -Path $fileName -MaxEvents $MaxEventsPerDC
            }
        }
    }   
    
    # parse events from local Evtx folder
    write-Host "[x] Parsing events and adding additional data. This may take a while..." -Foregroundcolor Cyan;
    $global:JobsData | foreach {                  
    $eventXML = [xml]$_.ToXml();
    For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
        Add-Member -InputObject $_ -MemberType NoteProperty -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text' -Force}
    }    
    
    [int]$JobsDataCount = $global:JobsData.count;

    # Check if ANY events were ultimately collected, before continuing
    if ($JobsDataCount -lt 1) {
            Write-Host "[!] No events were collected. Please check EVTx file inside $PathToEvtxFiles.`nAborting." -ForegroundColor Yellow;
            break
        }

    Write-Host "[x] Found $('{0:N0}' -f $JobsDataCount) potential events from $(($Files | Measure-Object).Count) file(s).`n" -ForegroundColor Yellow;

    # For local (Offline) evtx parsing, enter domain information manually
    $DomainName = Read-Host "Please enter domain netBIOS name (e.g. DOMAIN)";
    $DomainName = Read-Host "Please enter domain FQDN (e.g. CORP.DOMAIN.COM)";
}
# END OF 'Local EVTX files'
else
    {    
    # Get events data from the Domain Controllers on the network via WinRM (port 5985)
    $DCs = ([adsisearcher]"(&(objectCategory=computer)(|(primarygroupid=521)(primarygroupid=516)))").FindAll().Properties.name;

    # clean previous jobs from current process/runspace
    Get-Job | Remove-Job -Force;

    # Excute remote WinRM jobs on DCs (Note: fetching actual security.evtx will normally be quicker than Security Log interface as source, and WinRM quicker than WMI/RPC Event-Log-Mgmt)
    $null = Invoke-Command -ComputerName $DCs -ScriptBlock {
            if ($using:ReportType -eq "Focused-Quicker") {
                    if ($using:MaxEventsPerDC -eq [long]::MaxValue)
                        {
                            $events = Get-WinEvent -Path "$env:windir\system32\winevt\Logs\Security.evtx" -FilterXPath "*[System[EventID=4634 or EventID=4624 or EventID=4768 or EventID=4769 or EventID=4776 or EventID=4625 or EventID=4672]]"
                        }
                    else
                        {
                            $events = Get-WinEvent -Path "$env:windir\system32\winevt\Logs\Security.evtx" -FilterXPath "*[System[EventID=4634 or EventID=4624 or EventID=4768 or EventID=4769 or EventID=4776 or EventID=4625 or EventID=4672]]" -MaxEvents $using:MaxEventsPerDC
                        }
                } 
            else {
                if ($MaxEventsPerDC -eq [long]::MaxValue)
                    {
                        $events = Get-WinEvent -Path "$env:windir\system32\winevt\Logs\Security.evtx"
                    }
                else
                    {
                        $events = Get-WinEvent -Path "$env:windir\system32\winevt\Logs\Security.evtx" -MaxEvents $using:MaxEventsPerDC
                    }
                }
            $events | foreach {                  
            $eventXML = [xml]$_.ToXml();
            For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
                Add-Member -InputObject $_ -MemberType NoteProperty -Name $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text' -Force}
            }
            $events
        } -AsJob
    
    Write-Host "[x] Discovering events from $(($DCs | Measure-Object).count) Domain Controllers. This can take a while to complete..." -ForegroundColor Cyan;

    ## Job status monitor - check every X seconds and show status
    # allow 15 seconds to kick-off remote jobs on the DC(s)
    Start-Sleep -Seconds 15;
    # Check status every XX seconds
    [int]$Interval = 15;
    Start-TimerLoop -Interval $Interval;

    # get jobs data upon completion
    Write-Host "$Ascii`n" -ForegroundColor Magenta;
    $Jobs = (Get-Job).ChildJobs;
    Write-Host "[x] Preparing data & cleaning up memory..." -ForegroundColor Cyan;
    $global:JobsData = $Jobs | where state -eq "Completed" | Receive-Job -ErrorAction SilentlyContinue;
    
    # check if some DC jobs might have failed
    if (($Jobs | group state | Measure-Object).count -gt 1)
        {
            Write-Host "[!] Note: Some collection jobs might have failed. ensure connectivity to DCs via WinRM (port 5985)" -ForegroundColor Yellow;
            $Jobs | group State | select @{n='DC Count';e={$_.count}}, @{n="Status";e={$_.name}} | sort 'DC Count' -Descending
        }

    # temp mem cleanup
    Get-Job | Remove-Job -Force;
    [gc]::Collect();

    [int]$JobsDataCount = $global:JobsData.count;

    # Check if ANY events were ultimately collected, before continuing
    if ($JobsDataCount -lt 1) {
            Write-Host "[!] No events were collected. Please check connectivity to DCs via WinRM (port 5985) and try again.`nAborting." -ForegroundColor Yellow;
            break
        }

    if ($DomainName -eq $null -xor $DomainFQDN -eq $null)
        {
            Write-Host "[!] Some domain information is missing (Domain name:$DomainName, FQDN:$DomainFQDN)" -ForegroundColor Yellow;
            $DomainName = Read-Host "Please enter domain netBIOS name (e.g. DOMAIN)";
            $DomainName = Read-Host "Please enter domain FQDN (e.g. CORP.DOMAIN.COM)";
        }

    Write-Host "[x] Found $('{0:N0}' -f $JobsDataCount) potential events from $(($DCs | Measure-Object).count) Domain Controllers.`n" -ForegroundColor Yellow;
}

## Filter per user (take input for TargetUserName)
[string]$username = [string]::Empty;

while ($Username -eq [string]::Empty) {
    $Username = Read-Host "[*] Please enter samaccountname to build event timeline for (e.g. administrator, or SRV$)"
}

## Stage 2: parse events
Write-Host "[x] Adding event description & saving all activity to CSV for later observation..." -ForegroundColor Cyan;
# add event description to the data
$global:JobsData | foreach {
    $Message = $_.message;
    $ActivityDescription = "";
    switch ($_.id)
        {
            4624 {$ActivityDescription = "Logon"}
            4634  {$ActivityDescription = "Logoff"}
            4662  {$ActivityDescription = "Object access"}
            4776  {$ActivityDescription = "NTLM creds validation,can be on local SAM"}
            4769  {$ActivityDescription = "Kerberos Service Request (TGS Access)"}
            4768  {$ActivityDescription = "Kerberos Authentication (TGT)"}
            4673  {$ActivityDescription = "Privileged service operation"}
            4672  {$ActivityDescription = "Privileged user logon/Admin"}
            4648  {$ActivityDescription = "Explicit creds/Run as"}
            4688  {$ActivityDescription = "Process creation"}
            4625  {$ActivityDescription = "Logon Failed";
                    if ($Message | Select-String "Sub Status:\s+0xC000006A")
                    {$ActivityDescription = "Logon Failed (Wrong password)"}
                    elseif ($Message | Select-String "Sub Status:\s+0xC0000064")
                    {$ActivityDescription = "Logon Failed (Username does Not exist)"}
                    elseif ($Message | Select-String "Sub Status:\s+0xC0000234")
                    {$ActivityDescription = "Logon Failed (Account locked out)"}
	                elseif ($Message | Select-String "Sub Status:\s+0xC0000072")
                    {$ActivityDescription = "Logon Failed (Account disabled)"}
                    elseif ($Message | Select-String "Sub Status:\s+0xC000006F")
                    {$ActivityDescription = "Logon Failed (login out of day-time restriction)"}
                    elseif ($Message | Select-String "Sub Status:\s+0xC0000070")
                    {$ActivityDescription = "Logon Failed (workstation Restriction)"}
                    elseif ($Message | Select-String "Sub Status:\s+0xC0000193")
                    {$ActivityDescription = "Logon Failed (account expired)"}
                    elseif ($Message | Select-String "Sub Status:\s+0xC0000071")
                    {$ActivityDescription = "Logon Failed (password expired)"}
                    elseif ($Message | Select-String "Sub Status:\s+0xC0000133")
                    {$ActivityDescription = "Logon Failed (clock out of Sync)"}
                    elseif ($Message | Select-String "Sub Status:\s+0xC0000224")
                    {$ActivityDescription = "Logon Failed (Must change password on Next logon)"}
	                elseif ($Message | Select-String "Sub Status:\s+0xc000015b")
                    {$ActivityDescription = "Logon Failed (user Not granted the proper Logon Type)"}
                    }
            4771  {$ActivityDescription = "Kerberos pre-AuthN failed"}
            4770  {$ActivityDescription = "Kerberos ticket renewed"}
            4674  {$ActivityDescription = "Operation on priviliged object"}
            5136  {$ActivityDescription = "DS object modified"}
            4670  {$ActivityDescription = "Distribution group changed"}
            4728  {$ActivityDescription = "Member added to a Security global group"}
            4738  {$ActivityDescription = "User account changed"}
            4737  {$ActivityDescription = "Security global group changed"}
            4723  {$ActivityDescription = "User attempted to change his/her own password"}
            4740  {$ActivityDescription = "Lockout"}
            4767  {$ActivityDescription = "Unlocked"}
            4720  {$ActivityDescription = "User account created"}
            4724  {$ActivityDescription = "Password reset failed to meet pass policy"}
            5137  {$ActivityDescription = "DS object was created"}
            4755  {$ActivityDescription = "Security universal group was changed"}
            4756  {$ActivityDescription = "Member added to a Security universal group"}
            4722  {$ActivityDescription = "User Enabled"}
            4742  {$ActivityDescription = "Computer account was changed"}
            4741  {$ActivityDescription = "Computer account was created"}
            5059  {$ActivityDescription = "Key migration operation"}
            5058  {$ActivityDescription = "Key file operation"}
            4755  {$ActivityDescription = "A security-enabled universal group was changed"}
            4737  {$ActivityDescription = "A security-enabled global group was changed"}
            4781  {$ActivityDescription = "The name of an account was changed"}
            5061  {$ActivityDescription = "Cryptographic operation"}
            4616  {$ActivityDescription = "The system time was changed"}
            4799  {$ActivityDescription = "A security-enabled local group membership was enumerated"}
            4703  {$ActivityDescription = "A token right was adjusted"}
            default  {$ActivityDescription = "Other (please see eventID)"}
        }
    Add-Member -InputObject $_ -MemberType NoteProperty -Name Activity -Value $ActivityDescription -Force
}

# save all results to CSV 
$global:JobsData | select @{n='Time';e={$_.TimeCreated}}, Activity,@{n='AuditType';e={$_.KeywordsDisplayNames}},ServiceName,ipAddress,workstationname,@{n='LogonID';e={[int]$_.TargetLogonId}},@{n='DC';e={$_.MachineName}},@{n='EventID';e={[int]$_.Id}},TargetDomainName,@{n='Account';e={$_.TargetUserName}},@{n='AccountSid';e={if ($_.TargetUserSid -eq "S-1-0-0") {$UserSid}else{$_.TargetUserSid}}},@{n='ProcessID';e={[int]$_.ProcessId}} |
    Export-Csv $ExportToCSVFileName -NoTypeInformation -Encoding UTF8;

# filter by specific user
$UserData = $global:JobsData | Where-Object {$_.targetusername -eq $Username -xor $_.targetusername -eq "$DomainName\$Username" -xor $_.targetusername -eq "$Username@$DomainFQDN" -xor $_.targetusername -eq "$DomainFQDN\$Username"}

if ($UserData.count -le 0)
    {
        Write-Host "[!] No events found for account $($username.ToUpper()).`nMake sure you wrote the username correctly.`nOtherwise, there might be No relevant events for this account in the given scope/selected parameters." -ForegroundColor Yellow;
        Write-Host "[x] NOTE: Report with all activity data was saved to $ExportToCSVFileName." -ForegroundColor Green;
        Clear-Variable JobsData;
        [gc]::Collect();
        #Write-Host "[*] Try running the script again to query for another account, using the -UseCachedEvents parameter" -ForegroundColor Cyan;
        break
    }

if ($PathToEvtxFiles -eq [System.String]::Empty) {
    $UserObject = ([adsisearcher]"(samaccountname=$username)").FindOne();
    $UserDN = $UserObject.Properties.distinguishedname;
    $UserSid = (New-Object System.Security.Principal.NTAccount($DomainName,$username)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    Write-Host "[x] Found $('{0:N0}' -f $UserData.count) events for account $($username.ToUpper()) <$UserDN>.`nReport type selected: $ReportType." -NoNewline -ForegroundColor Green; Write-Host " Displaying timeline..." -ForegroundColor Cyan;
}
else
    # local / offline parsing
    {
    Write-Host "[x] Found $('{0:N0}' -f $UserData.count) events for account $($username.ToUpper()).`nReport type selected: $ReportType." -NoNewline -ForegroundColor Green; Write-Host " Displaying timeline..." -ForegroundColor Cyan;
}

## Stage 3: building timeline

# Display timeline Grid
$UserData | select @{n='Time';e={$_.TimeCreated}}, Activity,@{n='AuditType';e={$_.KeywordsDisplayNames}},ServiceName,ipAddress,workstationname,@{n='LogonID';e={[int]$_.TargetLogonId}},@{n='DC';e={$_.MachineName}},@{n='EventID';e={[int]$_.Id}},TargetDomainName,@{n='Account';e={$_.TargetUserName}},@{n='AccountSid';e={if ($_.TargetUserSid -eq "S-1-0-0") {$UserSid}else{$_.TargetUserSid}}},@{n='ProcessID';e={[int]$_.ProcessId}} | 
    sort Time -Descending | Out-GridView -Title "Timeline for $($username.ToUpper()) <$UserDN> | Generated at $(get-date) | Report Type: $ReportType"

# wrap up
Write-Host "[x] NOTE: Report with all activity data was saved to $ExportToCSVFileName." -ForegroundColor Green;
[gc]::Collect()
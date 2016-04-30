[CmdletBinding()]
param([parameter(Mandatory=$true)]$EsiConfig,[switch]$RemoveSnapshotsOnly,[switch]$NoImageAccess,[switch]$CreateInitialSnapshotSet)

$script:ScriptVersion = '1.1.04.29.16'
$debug = 1
if ($debug -eq 1) { $VerbosePreference = 'continue' } else { $VerbosePreference = 'SilentlyContinue' }   

#############################################################################################################
##### Define Global System Variables ########################################################################
#############################################################################################################
$script:storageSystem = $null
$script:storageSystemName = ''
$script:storageSystemType = ''
$script:RpSystem = $null
$script:RpSystemName = ''
$script:xtremioRpCgName = ''
$xtremioSnapshotSuffix = 'esiSnapshot'
$script:EsiScriptPath = 'c:\esiprotection'
$script:LogFile = "$($EsiScriptPath)\esiprotection.log"
$Domain = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\services\Tcpip\Parameters\' -Name 'Domain').Domain
$Hostname = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\services\Tcpip\Parameters\' -Name 'Hostname').Hostname
$Fqdn = "$Hostname.$Domain"


######## Import-EsiConfig ###################################################################################
function Import-EsiConfig
{
    param ([parameter(Mandatory=$true)]$EsiConfigFile)
    Write-LogFile -message "####################################################################################################"
    if (!(Test-Path -Path $EsiConfigFile))
    {
        $message = "ESI Config ($($EsiConfigFile)) could not be found. Please make sure a valid esiconfig.xml file is located in $($script:EsiScriptPath)."
        Write-LogFile -message $message
        Exit
    }
    else
    {
        Try
        {
            [xml]$EsiHostConfig = Get-Content $EsiConfigFile
            $EsiHostConfig
            $script:RpSystemName = $EsiHostConfig.esiprotection.rpsystem.name
            $script:StorageSystemName = $EsiHostConfig.esiprotection.storagesystem.name
            $script:StorageSystemType = $EsiHostConfig.esiprotection.storagesystem.type
            $script:xtremioRpCgName = $EsiHostConfig.esiprotection.xtremio_consistencygroup.name

            $EsiHosts = @()
                        
            foreach ($cg in $EsiHostConfig.esiprotection.rp_consistencygroup)
            {
                foreach ($EsiConfigHost in $cg.host) 
                {
                    $EsiHost = '' | Select -Property name,cg,roletype,ipaddress,initiator,lun
                    $EsiHost.name = $EsiConfigHost.Name
                    $EsiHost.cg = $cg.name
                    $EsiHost.roletype = $cg.roletype
                    $EsiHost.ipaddress = $EsiConfigHost.ipaddress
                    $EsiHost.initiator = $EsiConfigHost.initiator
                    $EsiHost.lun = $EsiConfigHost.lun
                    $EsiHosts += $EsiHost
                }
            }
            Write-LogFile -message "Successfuly imported ESI configuration ($EsiConfigFile)."        
            return $EsiHosts
        }
        Catch
        {
            Write-LogFile -message "ESI Config ($($EsiConfigFile)) is not a valid ESI Protection XML configuration."
            Exit
        }
    }
}

######## Write-LogFile ######################################################################################
function Write-LogFile
{
    param ([parameter(Mandatory=$true,ValueFromPipeline=$True)]$message)
    "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss"): $($message)" | Out-File -FilePath $LogFile -Append -NoClobber
    Write-Verbose $message
}

######## Write-EsiEvent #####################################################################################
function Write-EsiEvent
{
    param ([parameter(Mandatory=$true)]$EventMessage,
           [parameter(Mandatory=$true)]$EventId,
           $EventLevel='Information'
          )
    $EventID = $EventId
    $LogName = 'Application'
    $Source = "ESI RP Protection"
    $Level = $EventLevel
    $EventMessageFile = "$([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())\EventLogMessages.dll"
    $Message = "$($EventMessage)"
    Write-LogFile -message $Message
    If(![system.diagnostics.eventlog]::SourceExists($Source)){
        New-EventLog -LogName $LogName -Source $Source -MessageResourceFile $EventMessageFile    
    }
    Write-EventLog -LogName $LogName -Source $Source -EntryType $Level -Message $Message -EventId $EventID
}

######## Enable-ImageAccess #################################################################################
function Enable-ImageAccess
{
    param ([parameter(Mandatory=$true)]$ConsistencyGroup,
           $RoleType='RemoteCopy'
          )
    $ReplicaCopyImageAccess = $null
    $RpCg = Get-EmcConsistencyGroup | ? { $_.Name -eq $ConsistencyGroup }
    
    if ($RpCG -ne $null)
    {
        $message = "Remote copy volumes for Consistency Group $($ConsistencyGroup) found. Attempting to enable image-access..."
        Write-LogFile -message $message
        $RemoteCopy = Get-EmcReplicaCopy -ConsistencyGroup $RpCg -Role $RoleType
        if ($RemoteCopy.ImageAccessEnabled -eq $true)
        {
            $message = "Image access is already enabled for Consistency Group $($ConsistencyGroup). Aborting.`nPlease disable image access on the image before running ESI Protection."
            Write-EsiEvent -EventMessage $message -EventLevel 'Warning' -EventId 2001
            return
        }
        else
        {
            Try
            {
                $ReplicaCopyImageAccess = Enable-EmcReplicaCopyImageAccess -Copy $RemoteCopy -Confirm:$false
                Write-LogFile -message "Enabled image access for consistency group $($ConsistencyGroup). (Success)"
                return $True
            }
            Catch
            {
                $message = "Failed to enable image access for Consistency Group $($ConsistencyGroup)."
                Write-EsiEvent -EventMessage $message -EventLevel 'Error' -EventId 2003
                return
            }
        }
    }
    else
    {
        $message = "Unable to find the remote copy volumes for CG: $($ConsistencyGroup)."
        Write-EsiEvent -EventMessage $message -EventLevel 'Error' -EventId 2002
    }
   
}

######## Disable-ImageAccess ################################################################################
function Disable-ImageAccess
{
    param ([parameter(Mandatory=$true)]$ConsistencyGroup,
           $RoleType='RemoteCopy'
          )

    $RpCg = Get-EmcConsistencyGroup | ? { $_.Name -eq $ConsistencyGroup }
    
    Try
    {    
        $message = "Disabling Image Access for consistency group $($ConsistencyGroup)."
        Write-LogFile -message $message  
        $RemoteCopy = Get-EmcReplicaCopy -ConsistencyGroup $RpCg -Role $RoleType
        if ($RemoteCopy.ImageAccessEnabled -eq $True)
        {
            Disable-EmcReplicaCopyImageAccess -Copy $RemoteCopy -Confirm:$false | Out-Null
        }
        else
        {
            Write-LogFile -message "Image Access is already disabled for $($ConsistencyGroup)."
        }
    }
    Catch
    {
        $message = "Error disabling Image Access for consistency group $($ConsistencyGroup)."
        Write-EsiEvent -EventMessage $message -EventId 2004 -EventLevel 'Error'        
    }
}

#############################################################################################################################################
function Remove-EsiSnapshotSets
{
    #Removes the XtremIO Snapshotsets used to refresh the mapped volumes.
    param ($consistencyGroupSnapshotSet)
    Update-EmcSystem $Script:storageSystem
    $snapshotsets = (Get-EmcXtremIOSnapshotSet -XioStorageSystem $Script:storageSystem)   
    foreach ($snapshotset in $snapshotsets)
    {
        $snapshotsetVolumes = $snapshotset.SnapshotVolumes.Values | select -First 1
        $snapshotsetVolumes | % { 
            if ($_ -match 'esiSnapshot')
            {
                Write-Host -ForegroundColor green "$($snapshotset.DisplayName) was created by ESI protection and is no longer needed. Removing..." 
                Remove-EmcXtremIOSnapshotSet -SnapshotSet ($snapshotset) -Force
            }
        }
    }
    if ($consistencyGroupSnapshotSet)
    {
        Write-Host -ForegroundColor green "$($consistencyGroupSnapshotSet.Displayname) was created by ESI protection and is no longer needed. Removing..."
        Remove-EmcXtremIOSnapshotSet -SnapshotSet ($consistencyGroupSnapshotSet) -Force
    }
}
#############################################################################################################################################
function Create-InitialXtremioSnapshots
{
    #Creates the initial snapshots. These snapshots must be manually mapped to the XtremIO initiator groups
    Write-Host 'Creating initial ESI Snapshot Volumes' -ForegroundColor Green
    $snapshotset = New-EmcXtremIOSnapshotSet -SourceConsistencyGroupName $script:xtremioRpCgName -XioStorageSystem $script:storageSystem -SnapshotSetName "esiSnapshotSet.Initial" -SnapshotSuffix 'esiSnapshot'
    
    if ($snapshotset)
    {
        $snapshotluns = $snapshotset.SnapshotVolumes.Values
        Write-Host "*** New Snapshot Volumes *********************************************************"
        $snapshotluns | % { Write-Host "Snapshot LUN: $_" -ForegroundColor Green }
        Write-Host "*** New Snapshot Volumes *********************************************************"
        Write-Host "The new snapshot volumes are prepared and ready to be added to the appropriate XtremIO initiator group." -ForegroundColor Green
        Write-Host "Please use the XtremIO user interface to map the volumes."
        Read-Host "Once complete, press any key to continue"

        Remove-EsiSnapshotSets
    }
    else
    { Write-Host "Unable to create a snapshotset from consistency group [$script:xtremioRpCgName]" }
}
#############################################################################################################################################
function Refresh-XtremioSnapshots
{
    #Refresh the mapped XtremIO volumes with the new snapshots from RecoverPoint
    $snapshotSuffix = $(get-date -Format 'MMddyyhhmm')
    $script:esiSnapshotSuffix = 'esiSnapshot'

    $sourcevolumes = (Get-EmcXtremIOConsistencyGroup -ID $script:xtremioRpCgName).Volumes.Values
    $snapshotset = New-EmcXtremIOSnapshotSet -SourceConsistencyGroupName $script:xtremioRpCgName -XioStorageSystem $script:storageSystem -SnapshotSetName "esiSnapshotSet.$snapshotSuffix" -SnapshotSuffix $snapshotSuffix
    
    if ($sourcevolumes -eq $null -or $sourceVolumeCount -eq 0)
    {
        $message = "Esi Protection did not complete successfully. `nGet-EmcXtremIOConsistencyGroup did not return any source volumes for [$script:xtremioRpCgName]."
        Write-Host $message
        Write-EsiEvent -EventMessage $message -EventId 2001 -EventLevel 'Error'
    }
    elseif ($snapshotset -eq $null)
    {
        $message = "New-EmcXtremIOSnapshotSet was unable to create a new snapshotset from consistency group [$script:xtremioRpCgName]."
        Write-Host $message
        Write-EsiEvent -EventMessage $message -EventId 2001 -EventLevel 'Error'
    }
    else
    {
        $unmappedVolumes = @()
        $sourceVolumeCount = $sourceVolumes.Count
        Write-Host "Source and snapshot volumes successfully enumerated. [$sourceVolumeCount] volumes found."
        foreach ($sourceVolume in $sourcevolumes)
        {
            Write-Host "Performing protection operations for XtremIO volume [$sourceVolume]"

            $newSnapshotName = $null
            $newSnapshotName = "$sourceVolume.$snapshotSuffix"

            #Verify snapshot was previously created. If not, it may have been added to RP but not mapped to XtremIO
            $previousSnapshotName = "$sourceVolume.$script:esiSnapshotSuffix"
            $previousSnapshot = $null
            $previousSnapshot = Get-EmcLun -BlockStorageSystem $script:storageSystem -ID $previousSnapshotName
            if ($previousSnapshot)
            {
                Write-Host "Previous snapshot volume found for [$previousSnapshotName], updating..."
                Restore-EmcXtremIOSnapshots -FromVolumeName $newSnapshotName -ToVolumeName $previousSnapshotName -XioStorageSystem $script:storageSystem -NoBackup
            }
            else
            {
                Write-Host "WARNING: Previous snapshot volume [$previousSnapshotName] was not found." -ForegroundColor yellow
                Write-Host "WARNING: [$previousSnapshotName] must be created/manually mapped to the appropriate initiator group." -ForegroundColor Yellow
                Write-Host "WARNING: Use the XtremIO user interface to correct this volume, or rerun this script with -CreateInitialSnapshotSet" -ForegroundColor Yellow
                Write-Host "   NOTE: This may be caused by addding a volume to the RecoverPoint Consistency Group and not preparing it for ESI-Protection." -ForegroundColor Yellow
                $unmappedVolumes += $previousSnapshotName;
            }         
        }
        if ($unmappedVolumes.Count -gt 0)
        {
            $message = "One or more ESI volumes were not pre-created. Manually create and map these volumes in the XtremIO console.`n"
            $message += $unmappedVolumes -join ", "
            Write-EsiEvent -EventMessage $message -EventLevel 'Warning' -EventId 2006
        }
        else
        {
            $message = "Snapshot creation successful. ESI Protection completed successfully."
            Write-Host "$message [$(Get-Date)]"
            Write-EsiEvent -EventMessage $message -EventLevel 'Information' -EventId 1001

        }
        Remove-EsiSnapshotSets -consistencyGroupSnapshotSet $snapshotset
    }
}

######## Get-EmcSystem ######################################################################################
function Get-EmcSystem
{
param ([parameter(Mandatory=$true)]$EmcSystem,
       [parameter(Mandatory=$true)]$EmcSystemType
      )
    $system = $null
    if ($EmcSystemType -eq 'vnx' -or $EmcSystemType -eq 'xtremio')
    {
        $system = Get-EmcStorageSystem | ? { $_.UserFriendlyName -eq $EmcSystem }
    }
    elseif ($EmcSystemType -eq 'rp')
    {
        $system = Get-EmcReplicationService | ? { $_.UserFriendlyName -eq $EmcSystem }
    }
    return $system
}

#############################################################################################################
##### Begin ESI Protection ##################################################################################
#############################################################################################################
$EsiHosts = Import-EsiConfig -EsiConfigFile $EsiConfig

Write-EsiEvent -EventMessage "Starting ESI Protection version: $($ScriptVersion)`nHost: $($Fqdn)" -EventId 1000

$script:storageSystem = Get-EmcSystem -EmcSystem $script:storageSystemName -EmcSystemType $script:storageSystemType
$script:RpSystem = Get-EmcSystem -EmcSystem $script:RpSystemName -EmcSystemType 'rp'

if ($storageSystem -eq $null -or (($RpSystem -eq $null) -and ($NoImageAccess -eq $false)))
{
    $message = 'ESI Protection was unable to retrive a valid RecoverPoint or Storage Instance.'
    Write-EsiEvent -EventMessage $message -EventId 2000 -EventLevel 'Error'
}
else
{
    $message = 'ESI successfuly enumarated the RecoverPoint and Storage systems. Updating system details...'
    Write-LogFile -message $message
    Update-EmcSystem $storageSystem
    if ($NoImageAccess -eq $False)
    {
        Update-EmcSystem $RpSystem
    }
    else
    {
        Write-LogFile "NoImageAccess switch found. Skipping RecoverPoint Image Access."
    }

    if ($script:storageSystemType -eq 'xtremio')
    {
        if ($CreateInitialSnapshotSet -eq $true)
        {
             Create-InitialXtremioSnapshots
        }
        else
        {
            Refresh-XtremioSnapshots
        }
    }
    else
    {
        Write-logfile -message "XtremIO configuration was not detected. If this is for VNX storage, please use the Esi-protectionVnx.ps1 cmdlet."
    }
}
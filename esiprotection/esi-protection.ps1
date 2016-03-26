[CmdletBinding()]
param([parameter(Mandatory=$true)]$EsiConfig,[switch]$RemoveSnapshotsOnly,[switch]$NoImageAccess)

$script:ScriptVersion = '1.0.1109.15'
$debug = 1
if ($debug -eq 1) { $VerbosePreference = 'continue' } else { $VerbosePreference = 'SilentlyContinue' }   

#############################################################################################################
##### Define Global System Variables ########################################################################
#############################################################################################################
$script:VnxSystem = $null
$script:VnxSystemName = ''
$script:RpSystem = $null
$script:RpSystemName = ''
$script:EsiScriptPath = 'c:\esiprotection'
$script:LogFile = "$($EsiScriptPath)\esiprotection.log"
$script:SnapShotType = 'vnxsnapshot'    #'vnxsnapshot|snapview'
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
            $script:VnxSystemName = $EsiHostConfig.esiprotection.vnxsystem.name
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

######## Create-VnxSnapshots ################################################################################
function Create-VnxSnapshots
{
    param ($Luns)

    $SnapshotLuns = $Null
    $SnapshotLuns = @()
    $message = ''
    $SnapShotError = $False

    Write-LogFile -message "Script is configured for snapshot type: $($script:SnapShotType)."

    foreach($Lun in $Luns)
    {        
        $SnapshotLun = $null
        Write-LogFile -message "Create Snapshot for $($Lun.Name)"
    
        $SourceLun = (Get-EmcLun | ? { $_.Name -eq $Lun.Name })
        if ($SourceLun)
        {           
            if ($script:SnapShotType -eq 'vnxsnapshot')
            {
                $SnapShotMountPoint = Get-EmcVnxAdvancedSnapshotMountPoint | ? { $_.name -eq "$($SourceLun.Name)_SMP" }
                Write-Host $SnapShotMountPoint
                if ($SnapShotMountPoint -eq $null)
                {
                    Write-LogFile -message "Creating new snapshot mount point for LUN: $($SourceLun.Name)."
                    $SnapShotMountPoint = New-EmcVnxAdvancedSnapshotMountPoint -SourceLun $SourceLun -SnapshotMountPointName "$($SourceLun.Name)_SMP" -ErrorAction SilentlyContinue -ErrorVariable err
                }
                if ($SnapShotMountPoint -ne $null)
                {
                    #Creating Golden Snapshot. This snapshot is a point in time and is not mounted normally.
                    $GoldenSnapshotLun = Get-EmcVnxAdvancedSnapshot -SourceLun $SourceLun | ? { $_.Name -eq "$($Lun.Name)_Snap_Golden" }
                    if ($GoldenSnapshotLun)
                    {
                        Write-LogFile -message "Golden Snapshot LUN: $($Lun.Name) has already been created. This may be a clustered server (Success)."
                    }
                    else
                    {
                        Write-LogFile -message "Golden Snapshot LUN: $($Lun.Name) was not found, creating a new golden snapshot.`n"
                        $GoldenSnapshotLun = New-EmcVnxAdvancedSnapshot -SourceLun $SourceLun -Name "$($Lun.Name)_Snap_Golden" -AllowReadWrite $True -Description 'ESI Protection VNX Golden Snapshot'
                        $message += "Golden Snapshot LUN: $($Lun.Name) (Success)`n"
                        Write-LogFile -message $message
                    }
                    #Creating Snapshot for mountpoint
                    $SnapshotLun = Get-EmcVnxAdvancedSnapshot -SourceLun $SourceLun | ? { $_.Name -eq "$($Lun.Name)_Snap" }
                    if ($SnapshotLun)
                    {
                        Write-LogFile -message "Snapshot LUN: $($Lun.Name) has already been created. This may be a clustered server (Success)."
                    }
                    else
                    {
                        Write-LogFile -message "Snapshot LUN: $($Lun.Name) was not found, creating a new snapshot.`n"
                        $SnapshotLun = New-EmcVnxAdvancedSnapshot -SourceLun $SourceLun -Name "$($Lun.Name)_Snap" -AllowReadWrite $True -Description 'ESI Protection VNX Snapshot'
                        $message += "Snapshot LUN: $($Lun.Name) (Success)`n"
                        Write-LogFile -message $message
                        $SMP = Mount-EmcVnxAdvancedSnapshot -AdvancedSnapshot $SnapshotLun -AdvancedSnapshotMountPoint $SnapShotMountPoint -Confirm:$False
                    }
                    $SnapshotLuns += $SnapShotMountPoint
                }
            }
            else
            {
                $SnapshotLun = Get-EmcSnapshotLun -Silent -SourceLun $SourceLun | ? { $_.Name -eq "$($Lun.name)_Snap" }
                if ($SnapshotLun)
                {
                    $message += "Snapshot LUN: $($Lun.Name) has already been created. This may be a clustered server (Success).`n"
                }
                else
                {
                    $message += "Snapshot LUN: $($Lun.Name) was not found, creating a new snapshot.`n"
                    $SnapshotLun = New-EmcSnapshotLun -SourceLun $SourceLun -Name "$($Lun.Name)_Snap" -ErrorAction Stop
                    $message += "Snapshot LUN: $($Lun.Name) (Success)`n"
                }
                $SnapshotLuns += $SnapshotLun
            }
        }
        else
        {
            $message += "Source LUN: $($Lun.Name) definied in EsiConfig was not found.`n"
        }
    }
    if ($SnapShotError -eq $True)
    {
        $message += "Snapshot creation failed.`n"
        Write-EsiEvent -EventMessage $message -EventId 2005 -EventLevel 'Error'
    }
    else
    {
        $message += "Snapshot creation successful."
        Write-EsiEvent -EventMessage $message -EventId 1003 -EventLevel 'Information'
    }
    return $SnapshotLuns
}

######## Remove-PreviousSnapshots ###########################################################################
function Remove-PreviousSnapshots
{
    param ([parameter(Mandatory=$true)]$EsiHost)
    foreach ($Lun in $EsiHost.Lun)
    {
        $SourceLun = Get-EmcLun | ? { $_.Name -eq $Lun.Name }
        if ($SourceLun)
        {
            if ($script:SnapShotType -eq 'vnxsnapshot')
            {
                #Remove Golden Snapshot LUN
                $GoldenSnapshotLun = Get-EmcVnxAdvancedSnapshot -SourceLun $SourceLun | ? { $_.Name -eq "$($Lun.Name)_Snap_Golden" }
                if ($GoldenSnapshotLun)
                {
                    $message += "Golden Snapshot LUN: $($Lun.Name)_Snap_Golden found, dismounting from SMP.`n"
                    #Dismount-EmcVnxAdvancedSnapshot -AdvancedSnapshot $GoldenSnapshotLun -Force -ErrorAction SilentlyContinue -Silent
                    Remove-EmcVnxAdvancedSnapshot -AdvancedSnapshot $GoldenSnapshotLun -Force -ErrorAction SilentlyContinue -Silent
                }
                else
                {
                    $message += "Golden Snapshot LUN: $($Lun.Name)_Snap_Golden was not found. Nothing to remove.`n"
                }
                #Remove mountable snapshot LUN
                $SnapshotLun = Get-EmcVnxAdvancedSnapshot -SourceLun $SourceLun | ? { $_.Name -eq "$($Lun.Name)_Snap" }
                $SnapShotMountPoint = Get-EmcVnxAdvancedSnapshotMountPoint | ? { $_.name -eq "$($SourceLun.Name)_SMP" }
                if ($SnapshotLun)
                {
                    $message += "Snapshot LUN: $($Lun.Name)_Snap found, dismounting from SMP.`n"
                    Dismount-EmcVnxAdvancedSnapshot -AdvancedSnapshot $SnapshotLun -Force -ErrorAction SilentlyContinue -Silent
                    Remove-EmcVnxAdvancedSnapshot -AdvancedSnapshot $SnapshotLun -Force -ErrorAction SilentlyContinue -Silent
                }
                else
                {
                    $message += "Snapshot LUN: $($Lun.Name)_Snap was not found. Nothing to dismount.`n"
                }
                if ($SnapShotMountPoint)
                {   
                    $message += "Removing snapshot mount point $($SourceLun.Name)_SMP from host.`n"
                    Unpresent-VnxSnapshots -VnxSnapshots $SnapShotMountPoint -EsiHost $EsiHost
                }
            }
            else
            {
                $SnapshotLun = Get-EmcSnapshotLun -Silent -SourceLun $SourceLun
                if ($SnapshotLun)
                {
                    Try
                    {
                        $message += "Removing Previous Snapshot $($SnapshotLun.Name).`n"
                        Unpresent-VnxSnapshots -VnxSnapshots $SnapshotLun -EsiHost $EsiHost
                        Remove-EmcSnapshotLun -SnapshotLun $SnapshotLun -Confirm:$false -Silent -ErrorAction SilentlyContinue
                    }
                    Catch
                    {
                        $message += "Unable to remove Previous Snapshot $($SnapshotLun.Name).`n"
                    }
                }
                else
                {
                    $message += "A Previous Snapshot for LUN $($Lun.Name) was not found, or has already been removed.`n"
                }
            }
        }
        else
        {
            $message += "Source LUN: $($Lun.Name) definied in EsiConfig was not found.`n"
        }
    }
    Write-LogFile -message $message
}

######## Unpresent-VnxSnapshots #############################################################################
function Unpresent-VnxSnapshots
{
    param ([parameter(Mandatory=$true)]$VnxSnapshots,
           [parameter(Mandatory=$true)]$EsiHost
          )
    foreach ($VnxSnapshot in $VnxSnapshots)
    {
        foreach ($initiator in $EsiHost.initiator)
        {
            Write-LogFile -message "Removing snapshot access to host: $($EsiHost.Name), initiator: $($initiator)."
            Set-EmcLunAccess -Lun $VnxSnapshot -HostName $EsiHost.Name -HostIpAddress $EsiHost.IpAddress -InitiatorId $initiator -Unavailable
        }
    }
}

######## Present-VnxSnapshots ###############################################################################
function Present-VnxSnapshots
{
    param ([parameter(Mandatory=$true)]$VnxSnapshots,
           [parameter(Mandatory=$true)]$EsiHost
          )
    foreach ($VnxSnapshot in $VnxSnapshots)
    {
        foreach ($initiator in $EsiHost.initiator)
        {
            Write-LogFile -message "Adding snapshot access to host: $($EsiHost.Name), initiator: $($initiator)."
            Set-EmcLunAccess -Lun $VnxSnapshot -HostName $EsiHost.Name -HostIpAddress $EsiHost.IpAddress -InitiatorId $initiator -Available
        }
    }
}

######## Get-EmcSystem ######################################################################################
function Get-EmcSystem
{
param ([parameter(Mandatory=$true)]$EmcSystem,
       [parameter(Mandatory=$true)]$EmcSystemType
      )
    $system = $null
    if ($EmcSystemType -eq 'vnx')
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

$script:VnxSystem = Get-EmcSystem -EmcSystem $script:VnxSystemName -EmcSystemType 'vnx'
$script:RpSystem = Get-EmcSystem -EmcSystem $script:RpSystemName -EmcSystemType 'rp'

Write-EsiEvent -EventMessage "Starting ESI Protection version: $($ScriptVersion)`nHost: $($Fqdn)" -EventId 1000

if ($VnxSystem -eq $null -or $RpSystem -eq $null)
{
    $message = 'ESI Protection was unable to retrive a valid RecoverPoint or VNX Instance.'
    Write-EsiEvent -EventMessage $message -EventId 2000 -EventLevel 'Error'
}
else
{
    $message = 'ESI successfuly enumarated the RecoverPoint and VNX systems. Updating system details...'
    Write-LogFile -message $message
    Update-EmcSystem $VnxSystem
    if ($NoImageAccess -eq $False)
    {
        Update-EmcSystem $RpSystem
    }
    else
    {
        Write-LogFile "NoImageAccess switch found. Skipping RecoverPoint Image Access."
    }

    if ($EsiHosts.Count -gt 0)
    {
        $RpConsistencyGroups = ($EsiHosts | select -Property CG).CG | Select -Unique
        foreach ($RpConsistencyGroup in $RpConsistencyGroups)
        {
            $CgEsiHosts = $EsiHosts | ? { $_.cg -eq $RpConsistencyGroup }
            if ($RemoveSnapshotsOnly -eq $True)
            {
                #Remove Snapshots Only. This will remove all snapshots for LUNs defined in Esiconfig.
                Write-logfile -message "-RemoveSnapshotsOnly switch was detected. Removing snapshots only."
                foreach ($EsiHost in $CgEsiHosts)
                {
                    Remove-PreviousSnapshots -EsiHost $EsiHost
                }
            }
            else
            {
                #Perform Full ESI Protection Process.
                $RoleType = ($EsiHosts | ? { $_.CG -eq $RpConsistencyGroup }).RoleType
                
                if ($NoImageAccess -eq $False)
                {
                    $ImageAccessEnabled = Enable-ImageAccess -ConsistencyGroup $RpConsistencyGroup -RoleType $RoleType
                }
                if ($ImageAccessEnabled -or $NoImageAccess -eq $True)
                {    
                    #Remove Previous Snapshots
                    foreach ($EsiHost in $CgEsiHosts)
                    {
                        Remove-PreviousSnapshots -EsiHost $EsiHost
                    }
                    #Enumerate EsiHosts and create new snapshots for LUNs defined in EsiConfig
                    foreach ($EsiHost in $CgEsiHosts)
                    {
                        $EsiHostLuns = $EsiHost.Lun
                        $VnxSnapshots = Create-VnxSnapshots -Luns $EsiHostLuns
                        if ($VnxSnapshots)
                        {
                            Present-VnxSnapshots -VnxSnapshots $VnxSnapshots -EsiHost $EsiHost
                        }
                    }
                    if ($NoImageAccess -eq $False)
                    {
                        Disable-ImageAccess -ConsistencyGroup $RpConsistencyGroup -RoleType $RoleType
                    }
                }
            }
        }
    }
}

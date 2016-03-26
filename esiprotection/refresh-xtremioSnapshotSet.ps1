######## Remove-PreviousSnapshots ###########################################################################
function Refresh-XtremIOSnapshots
{
    #Define esiSnapshot suffix and protected XtremIO Consistency Group
    $esiSnapshotSet = $null
    $drArrayName = 'clt-dr-xio-bbt-xio-20TB'
    $xtremioSnapshotSuffix = 'esiSnapshot'
    $xtremioRpCgName = 'RP_SiteUID(0x68ccad3173754fa4)_512452647_0'
    $drArray = Get-EmcStorageSystem | ? { $_.UserFriendlyName -match $drArrayName }


    #Update the system so the cmdlets have the most current array information
    Update-EmcSystem -EmcSystem (Get-EmcStorageSystem | ? { $_.userfriendlyname -match $drArray.UserFriendlyName })

    #Retrieve XtremIO Consistency Groups created by RecoverPoint, then parse them to find the esiSnapshot volumes
    $snapshotSets = Get-EmcXtremIOSnapshotSet -XioStorageSystem $drArray | ? { $_.ConsistencyGroupName -eq $xtremioRpCgName }
    $snapshotSets | % {
        $currentSnapshotVolumes = ($_.SnapshotVolumes.Values | select -First 1).split(".")
        if ($currentSnapshotVolumes.count -gt 0 -and $currentSnapshotVolumes[$currentSnapshotVolumes.count -1] -eq $xtremioSnapshotSuffix) 
        {
            #We found the ESI volumes. Assign the current iteration to $esiSnapshotSet
            $esiSnapshotSet = $_  
        }
    }

    if ($esiSnapshotSet)
    {
        try
        {
            Restore-EmcXtremIOSnapshots -XioStorageSystem $drArray -FromConsistencyGroupName $xtremioRpCgName -ToSnapshotSetName $esiSnapshotSet.DisplayName -NoBackup #BackupSnapshotTypeReadOnly
        }
        catch
        {
            $message += "Unable to remove Previous Snapshot $($SnapshotLun.Name).`n"
        }
    }
    else
    {
        Write-Host "ESI Snapshots were not found on the XtremIO system. These must be precreated for ESI to function."
    }

    Write-LogFile -message $message
}

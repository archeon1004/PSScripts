#region Classes
class ObjectAudit {
    [string]$GetObjectType
    [string]$ClassType
    [Boolean]$IsAuditSet
    TranslateGuid() {
        $schema = (Get-ADRootDSE).schemaNamingContext
        $filter = "(objectclass=classschema)"
        $objs = Get-ADObject -LDAPFilter $filter -SearchBase $schema -Properties ldapdisplayname, schemaidguid
        foreach ($entry in $objs) {
            if (([system.guid]$entry.schemaidguid).guid.ToString() -eq $this.GetObjectType) {
                $this.ClassType = $entry.ldapdisplayname.ToString()
            }
        }
    }
}
#endregion Classes

function Get-MDIObjectLevelAuditing {
    <#
    .SYNOPSIS
        This functions checks Object Level Auditing Configuration for Microsoft Defender For Identity.
    .DESCRIPTION
        Proper object level auditing is required for the MDI to properly work. This function checks current state of object level auditing on the domain level and allows you to find
        if something is missing.
    .NOTES
        This function does not allow to use parameters..
    .EXAMPLE
        Get-MDIObjectLevelAuditing 
        This will result in returning object of auditing policies required for mdi. Value for IsAuditSet equaled to true means that required auditing is set for a proper class.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)][ValidateNotNullOrEmpty()][string]$DomainDistringuishedName
    )
    begin {
        Write-Warning "This is still under developement"
        $AuditingList = New-Object System.Collections.Generic.List[ObjectAudit]
        $AuditingGuids = "bf967aba-0de6-11d0-a285-00aa003049e2", "bf967a9c-0de6-11d0-a285-00aa003049e2", "bf967a86-0de6-11d0-a285-00aa003049e2", "7b8b558a-93a5-4af7-adca-c017e67f1057", "ce206244-5827-4a86-ba1c-1c0c386c1b64"
        foreach ($guid in $AuditingGuids) {
            $temp = new-object -TypeName ObjectAudit
            $temp.GetObjectType = $guid
            $temp.IsAuditSet = $false
            $temp.TranslateGuid()
            $AuditingList.Add($temp)
        }
        if($PSBoundParameters.ContainsKey("DomainDistringuishedName"))
        {
            throw [System.NotImplementedException]::new()
        }
    }   
    process {
            Write-host "MDIConfigHelper: Checking Object Level auditing"
            try {
                $RootDirEntry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://RootDSE")
                Write-Verbose "Connected to RootDSE: $($RootDirEntry.Path.ToString())"
                Write-verbose "Checking Domain: $($RootDirEntry.defaultNamingContext.ToString().Replace(',','.').Replace('DC=',''))"
                $distinguishedName = $RootDirEntry.Properties["defaultNamingContext"].Value
                $de = [System.DirectoryServices.DirectoryEntry]::new("LDAP://" + $distinguishedName)
                $de.PsBase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
                $de.RefreshCache()
                [System.DirectoryServices.ActiveDirectorySecurity]$sec = $de.ObjectSecurity
                foreach ($ar in $sec.GetAuditRules($true, $true, [System.Security.Principal.NTAccount])) {
                    $Identity = $ar.IdentityReference.ToString()
                    Write-Verbose "MDIConfigHelper: Got this Identity Reference in Audit Entry: $Identity"
                    if ($Identity -eq "Everyone") {
                        $GetAuditAccess = $ar.ActiveDirectoryRights.ToString()
                        if ($GetAuditAccess.Contains("CreateChild") -and $GetAuditAccess.Contains("DeleteChild") -and $GetAuditAccess.Contains("Self") -and $GetAuditAccess.Contains("WriteProperty") -and $GetAuditAccess.Contains("DeleteTree") -and $GetAuditAccess.Contains("ExtendedRight") -and $GetAuditAccess.Contains("Delete") -and $GetAuditAccess.Contains("WriteDacl") -and $GetAuditAccess.Contains("WriteOwner")) {
                            $GetObjectType = $ar.InheritedObjectType.ToString()
                            if ($GetObjectType.Equals(($AuditingList.Find({ param ($x) $x.GetObjectType -eq $GetObjectType })).GetObjectType)) {
                                $indx = $AuditingList.FindIndex({ param ($x) $x.GetObjectType -eq $GetObjectType })
                                $AuditingList[$indx].IsAuditSet = $true;
                            }
                            else {
                                $indx = $AuditingList.FindIndex({ param ($x) $x.GetObjectType -eq $GetObjectType })
                                $AuditingList[$indx].IsAuditSet = $false;
                            }
                        }
                    }
                }
            }
            catch {
                $e = [System.Exception]::new("Exception",$_.Exception)
                throw $e
            }
        }
    end {
        if($AuditingList.IsAuditSet -contains $false)
        {
            Write-Warning "Some of required audit entries are not present"
        }
        $AuditingList
    }
}

Write-Warning "Module is still under developement"
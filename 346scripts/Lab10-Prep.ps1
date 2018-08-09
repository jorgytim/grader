<# lab10 prep script
    Purpose: IST346 lab 10 preparation script
    AUTHOR:  tajorgen
    Changes:
    1.0 2018-08-09 - General cleanup of functions, added minimize box to output window
#>


$ErrorActionPreference = 'silentlycontinue'
import-module activedirectory

function Invoke-labprep {
    param()
    #constants
	$domain = "ad.fauxco.com"
    $linux = "linuxserver.$($domain)"
	$winclient = "winclient.$($domain)"
	$winsrv = "winserver.$($domain)"
    $linuxip = "192.168.10.10"
    $winclientip = "192.168.10.12"
    $user1 = "benweave"
    $user2 = "adente"
    $group1 = "winshare"
    $share1 = "shares"
    $share2 = "winshare"
    $homepath1 = "c:\shares\homes\benweave"
    $homepath2 = "c:\shares\homes\adente"
    $regKey = "HKLM:\SOFTWARE\IST346\lab10marker"
    
    $now = (get-date).ToString("yyy-MM-dd")

    write-host "Preparing lab environment...."
    write-host " "

    ### Alter DNS records
    remove-dnsServerResourceRecord -name "linuxserver" -zone $domain -RRType "A" -confirm:$false -force
    add-dnsServerResourceRecordA -name "linuxserver" -zone $domain -IPv4Address $linuxip

    remove-dnsServerResourceRecord -name "winclient" -zone $domain -RRType "A" -confirm:$false -force
    add-dnsServerResourceRecordA -name "winclient" -zone $domain -IPv4Address $winclientip

    Clear-DnsClientCache

    #alter memberships
    get-adgroupmember $group1 | ForEach-Object {Remove-ADGroupMember $group1 -members $_.samaccountname -confirm:$false} | out-null

    #alter user settings
    set-aduser $user1 -HomeDirectory $null | out-null
    set-aduser $user2 -HomeDirectory $null | out-null

    #alter shares
    remove-smbshare $share1 -confirm:$false

    #alter folder permissions
    $acl = get-acl $homepath2
    $acl.access | foreach-object {$acl.removeaccessrule($_)}
    set-acl $homepath2 $acl
 
    New-Item -Path HKLM:\SOFTWARE\IST346 -ErrorAction SilentlyContinue
    New-Itemproperty -Path HKLM:\SOFTWARE\IST346 -Name Lab10Marker -PropertyType String -Value $now -Force

    Clear-Host

    write-host " "
    write-host "Lab preparation complete, continue with lab!" -ForegroundColor yellow
}

#main script

#check which host this is being run on
#if ("$($env:computername).$($env:userdnsdomain)" -eq "$($winsrv)"){

    clear-host

    Write-host "This is the preparation script for IST346 Lab10.  Only run this script in the beginning of Lab10!" -ForegroundColor Yellow
    write-host "This script WILL alter your VMs and break some functionality!" -ForegroundColor Yellow
    write-host "RUN THIS ONCE AND ONLY ONCE!!!" -ForegroundColor red

    $yn = Read-Host "Would you like to run the Lab10 Preparation Script? [y,n]?"
    if ($yn -eq"y")
    {
		
        $yn = Read-Host "Are you absolutely sure you want to run this? [y,n]?"
        if ($yn -eq"y")
        {
		    Invoke-labprep
        }

        if ($yn -eq"n")
        {
		    write-host "Lab10 Prep Script was cancelled, exiting." -ForegroundColor Yellow
            exit
        }

    }
    else {
        write-host "Lab10 Prep Script was run successfully, continue with your lab." -ForegroundColor Yellow
        exit
    }
<#
}

else{
    write-host "Script run from the incorrect machine, please run this from the appropriate VM as instructed in your lab" -ForegroundColor Red
    exit
}
#>
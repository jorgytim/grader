<# IST346 Labcheck functions
    Purpose: Lab checking functions
    AUTHOR:  tajorgen
    Changes:
    1.0 2015-05-14 - Initial release
    1.1 2017-09-21 - Replaced send-smtpmail function to allow for authenticated smtp
#>

#region script helper functions

function Send-SMTPmail($to, $from, $subject, $body, $attachment, $cc, $port, $timeout, $smtpserver, $credentials, [switch] $html, [switch] $alert) {
    $defaultSecPass = ConvertTo-SecureString "KLJqBznuNR7pzRB04Ai2" -AsPlainText -Force
    $defaultUsername = "s-email-ist346labs"
    $defaultCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $defaultUsername, $defaultSecPass

    if (!($smtpserver)) {$smtpserver = "smtp-relay.syr.edu"}
    if (!($credentials)){$credentials = $defaultCreds}
    if (!($port)){$port = "587"}
    if (!($attachment)){$attachment = "none"}

    if ($html){
        Send-MailMessage -To $To -Body $body -Subject $subject -SmtpServer $smtpserver -From $from -Credential $credentials -Port $port -UseSsl -Cc $cc -BodyAsHtml
    }
    else{
        Send-MailMessage -To $To -Body $body -Subject $subject -SmtpServer $smtpserver -From $from -Credential $credentials -Port $port -UseSsl -Cc $cc
    }
}

function Test-Url {
    param([string] $url)

    # Declare default return value
    $isValid = $false
   
    try
    {
        #Set powershell to TLS1.2 for SSL encryption
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Create a request object to "ping" the URL
        $request = [System.Net.WebRequest]::Create($url)
        $request.Timeout = 1000
        $request.Method = "HEAD"
        $request.UseDefaultCredentials = $true

        # Capture the response from the "ping"
        $response = $request.GetResponse()
        $httpStatus = $response.StatusCode
   
        # Check the status code to see if the URL is valid
        $isValid = ($httpStatus -eq "OK")
    }
    catch
    {
        # Write error log
        #Write-Host $Error[0].Exception
        #Write-host "$destSite not reachable, check your internet connection" -ForegroundColor Yellow
    }
   
    return $isValid
}

function Get-SupplemantalFile {
    param($url,$filename)
    # download supplemental files here
    
    $fileSource = "$($url + "/" + $filename)"

    if ( -not (test-path -path ".\$filename")) 
    { 
       
        #test the connection before attempting to download the file
        if (!(Test-Url -url $fileSource)) {
            Write-host "$filesource not reachable, check your internet connection" -ForegroundColor Yellow
            write-host "Exiting grading script." -ForegroundColor Yellow
            exit 1
        }
        #Set powershell to TLS1.2 for SSL encryption
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Start-BitsTransfer -Source $filesource
    }
    #else {write-host "$filename already exists, no supplentary files to download"}
}

function Test-AdWebServices {
    param()
    $adwsChk = get-serivce adws
    if ($adwsChk.status -ne "Running"){
        start-service adws
    }
}

function Install-AdditionalModules {
    param()

    #check for nuget packageprovider, install if not found.
    $NugetChk = get-packageprovider -name "NuGet" -ErrorAction SilentlyContinue
    if (!($NugetChk)){
        Install-PackageProvider -name NuGet -force -confirm:$false
        Import-PackageProvider NuGet   
    }
    #check for posh-ssh module, install if not found and import into powershell session
    $poshsshChk = get-module posh-ssh -ErrorAction SilentlyContinue
    if (!($poshsshChk)){
        install-module Posh-ssh -force -confirm:$false
        import-module posh-ssh
    }
    else {
        import-module posh-ssh
    }
}

#endregion script helper functions

#region labcheckfunc-windows

function test-WindowsUpdates {
    param($threshold,$points)
    $result = 0
    
    $criteria = "Type='software' and IsAssigned=1 and IsHidden=0 and IsInstalled=0"
    $searcher = (New-Object -COM Microsoft.Update.Session).CreateUpdateSearcher()
    $updates  = $searcher.Search($criteria).Updates
    
    if ($updates.count -le $threshold)
	{
		$result = $points
	}
	
    $result -as [Int32]
    
}

function check-WinCriticalUpdates {
    param($threshold,$points)
    $result = 0
    
    write-host "Checking if Windows Security patches are up to date..." -ForegroundColor Yellow

    $session = New-Object -com "Microsoft.Update.Session"
    $updates = $Session.CreateUpdateSearcher().search(("IsInstalled=0 and Type='Software'")).updates
    $criticalupdates = [int]($updates | ?{$_.AutoSelectOnWebsites -eq "true"}).count
    
    if ($criticalupdates -le $threshold)
	{
		$result = $points
	}
	
    $result -as [Int32]
    
}

function New-RandomPasswordNG()
{
    $rand = New-Object System.Random
    #Generate a new 10 character password
    1..10 | ForEach { $NewPassword = $NewPassword + [char]$rand.next(33,127) }
    return $NewPassword
}

function Convert-DomainUserToSid ($NtAccount) {
    (new-object system.security.principal.NtAccount("AD",$NTaccount)).translate
    ([system.security.principal.securityidentifier])
}

function Test-ComputerOnDomain {
    param($fqdn,$points )

	$result = 0
	$dnsChk = resolve-DnsName -Name $fqdn -DnsOnly -ErrorAction SilentlyContinue
	if ($dnsChk)
	{
		$result = $points
	}
	$result -as [Int32]
}

function Test-FileShare {
	param($computer,$share,$points )
	$result = 0
	$sharetest = Test-Path "\\$($computer)\$($share)" -ErrorAction SilentlyContinue
	   
	if ($sharetest -eq $true)
	{
		$result = $points        
	}
	return $result -as [Int32]
}

function Test-FileShareConnect ( $unc, $user, $pass, $points)
{
	$result = 0
	$buff = net use $unc /delete
    $buff = net use $unc /user:$user $pass
	$token = "The command completed successfully"
	if (select-String -pattern $token -inputObject $buff -SimpleMatch)
	{
		$result = $points
	}
	$result -as [Int32]    
}

function Test-FileShareWrite {
    param($unc,$user,$pass,$points)
	$result = 0
    $file = "test.txt"
    $content = "7632507635"
	$buff = net use $unc /delete
    $buff = net use $unc /user:$user $pass
    $filespec = "$($unc)\$($file)"
    $buff = echo $content > $filespec
    $chkFile = Get-Content $filespec
    if (select-String -pattern $content -inputObject $chkFile -SimpleMatch)
	{
		$result = $points
	}
	$result -as [Int32]    
}

function Test-FileShareContainsFile ( $unc, $file, $points )
{
	$result = 0
	$buff = ""
	$token = Join-Path $unc $file
	if (Test-Path $token)
	{
		$result = $points
	}
	$result -as [Int32]
}

function Test-FileShareConnected ( $unc, $points )
{
	$result = 0
	$buff = net use 
	$token = $unc
	if (select-String -pattern $token -inputObject $buff -SimpleMatch)
	{
		$result = $points
	}
	$result -as [Int32]
}

function Test-Website {
    param($url,$text,$points)

	$result = 0
    
   	$webfile = invoke-webrequest -uri $url
    #get-WebFile $url -FileName $buff -quiet | out-null
    if ($webfile.content | select-String -pattern $text) {
	    $result = $points
	}
	    
	$result -as [Int32]
}

function Test-FileConstainsText ( $filespec, [String[]]$text, $points)
{
    $result = 0
    $buff = type  $filespec
    $count = 0
    $textcount = $text.count
    foreach ($token in $text)
    {   
         
        if ( select-String -pattern $token -inputObject $buff)
        {
            $count += 1
        }
    }
    if ($count -eq $textcount)
    {
        $result = $points
    }
    $result -as [Int32]
}

function Test-PathConstainsText{
	param($path, [String[]]$text,$filter,$points)
	
    $result = 0
    $getfiles = Get-childitem -Path $path | Get-Content | Select-String -Pattern $text
	if ($filter -ne $null){
		$gettext = select-String -pattern $filter -inputObject $getfiles
	}
	else{
		$gettext = $getfiles
	}

	if ($gettext)
	{
		$result = $points
	}
	
	$result -as [Int32]
}

function Test-PathConstainsFile{
	param($path,$filename,$filter,$points)
	
    $result = 0
    $filecount = 0
	if ($filter -ne $null){
		$filechk = (Get-childitem -Path $path -Filter $filname) | Where-Object {$_.name -ne $filter}
	}
	else {
		$filechk = (Get-childitem -Path $path -Filter $filename)
	}
	
    $filecount = $filechk.count
        
    if ($filecount -gt 0)
    {
        $result = $points
    }

    $result -as [Int32]
}

function Test-InAcl ($path, $principal, $points)
{
	$result = 0
    if (test-path -path $path)
    {
        foreach ($a in (get-acl -path $path).Access)
        {
           $a = $a.IdentityReference.value.ToString().ToLower()
            
           if ($a.EndsWith($principal))  
           {
                    $result = $points
           }
        }
    }
    return $result -as [Int32]
}

function Test-WebSiteNG {
    #basic website availability test
	param($URL)
	$result = $false
	$webClient = new-object System.Net.WebClient
	$webClient.Headers.Add("user-agent", "PowerShell Script")

	$output = ""

	$startTime = get-date
	$output = $webClient.DownloadString($url)
	$endTime = get-date

	if ($output -ne $null) {
		#"Success`t`t" + $startTime.DateTime + "`t`t" + ($endTime - $startTime).TotalSeconds + " seconds"
		$result = $true
	} else {
		#"Fail`t`t" + $startTime.DateTime + "`t`t" + ($endTime - $startTime).TotalSeconds + " seconds"
		$result = $false
	}
}

function Test-PathExists {
	param($path,$points)
	
    $result = 0
    if (Test-Path $path -ErrorAction SilentlyContinue)
    {
        $result = $points
    }
    return $result -as [Int32]
}

function Test-UserHomedirExists {
#tests just for user homedir setting in AD
	param($user,$points)
	$result = 0
	$aduser = Get-ADUser $user -properties * -ErrorAction SilentlyContinue
    $homeDir = $aduser.homeDirectory

    if ($homeDir){
	    if (test-path $homeDir -ErrorAction SilentlyContinue){
            $result = $points
        }
    }
	return $result -as [Int32]
}

function Test-UserHomedir {
#tests user homedir setting in AD, and that user has permissions
	param($user,$points)
	$result = 0
	$aduser = Get-ADUser $user -properties * -ErrorAction SilentlyContinue
    $homeDir = $aduser.homeDirectory
    $permsExist = $false
    $homedirExists = $false

    if ($homeDir){
 	    if (test-path $homeDir -ErrorAction SilentlyContinue){
            $homedirExists = $true
        }
 
        foreach ($a in (get-acl -path $homeDir).Access | ?{($_.filesystemrights -eq "fullcontrol") -or ($_.filesystemrights -like "*modify*")}) 
        {
            $a = $a.IdentityReference.value.ToString().ToLower()
            
            if ($a.EndsWith($user))  
            {
                $permsExist = $true
            }
        }
    }

    if ($homedirexists -and $permsExist){
        $result = $points
    }
	return $result -as [Int32]
}

function Test-UserProfileExists {
	param($user,$path,$points)

	$result = 0
	$aduser = Get-ADUser $user -properties * | Select-Object samaccountname,profilepath -ErrorAction SilentlyContinue
	
	if (select-String -pattern $path -inputObject $aduser.profilepath -simpleMatch)
	{
		$result = $points
	}
	return $result -as [Int32]
}

function Test-UserHasLoggedOn {
	param($user,$points)
	
	$result = 0
	$aduser = Get-ADUser $user -properties * | Select-Object samaccountname,logoncount -ErrorAction SilentlyContinue
        
	if  ($aduser.logoncount -gt "0")
	{
		$result = $points
	}
	return $result -as [Int32]
}

function Test-GroupExists{
	param($group,$points )

	$result = 0
	$grpchk = Get-ADGroup $group -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
	if ($grpchk -ne $null)
	{
		$result = $points
	}
	$result -as [Int32]
}

function Test-GroupExistsNG{
	param($group)

	$result = $false
	$grpchk = Get-ADGroup $group -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
	if ($grpchk -ne $null)
	{
		$result = $true
	}
}

function Test-UserExists{ 
	param($user,$points)

	$result = 0
	$usrchk = Get-ADUser $user -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
	if ($usrchk -ne $null)
	{
		$result = $points
	}
	return $result -as [Int32]
}

function Test-MemberOfGroup {
	#check individual user exists in a group
	param($account,$group,$points)
	$result = 0
	$users = Get-ADGroupMember $group | select SamAccountName
	foreach ($objitem in $users) {
		$user = [string]$objitem
		if (Select-String -pattern $account -InputObject $user -SimpleMatch)
		{
			$result = $points
		}
	}
	$result -as [Int32]
}

function Test-MembersOfGroup{
	#checking for all members of a group
	param($users,$group,$points)
	
    $grpchk = Get-ADGroup $group -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
	if ($grpchk -ne $null){
	
        $count = 0
        $actual = 0
        $result = 0

		foreach ($user in $users) {
			$usrchk = Get-ADUser $user -Properties * -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
			$memberof = [string]$usrchk.memberof
            
			$count += 1
			if (select-String -pattern $group -inputObject $memberof)         	{
    			$actual +=1
    	    }
        }
        
        if ($actual -eq $count) 
        {
            $result = $points
        }
    }
    return $result -as [Int32]
}

function Test-MembersOfGroupCSV{
	#checking for all members of a group
	param($users,$group,$points)
	
    $grpchk = Get-ADGroup $group -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
	if ($grpchk -ne $null){
	
		$ulist = $users.Split(";")
        $count = 0
        $membership = "false"
        $result = 0

		foreach ($user in $ulist) {
			$usrchk = Get-ADUser $user -Properties * -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
			$memberof = [string]$usrchk.memberof
            
			$count += 1
			if (select-String -pattern $group -inputObject $memberof) {
    			$membership = "true"
    	    }
            else {
                $membership = "false"
            }
        }
        
        if ($membership -eq "true") 
        {
            $result = $points
        }
    }
    return $result -as [Int32]
}

function Test-BackupExists {
#use either minfilecount or filename, not both
	param($path,$filename,$minfilecount,$points)
	$result = 0
	$pathtest = Test-Path $path -ErrorAction SilentlyContinue
	   
	if ($pathtest -eq $true){
		if ($fileName -ne $null){
			$fileName = "$path" + "\" + "$fileName"
			$filecheck = get-item $filename -ErrorAction SilentlyContinue
			if ($filecheck){
				$result = $points
			}
		}
		else{
			$filecheck = Get-ChildItem $path | Measure-Object
			if ($filecheck.count -ge $minfilecount){
				$result = $points        
			}
		}
	}
	return $result -as [Int32]
}

Function Test-TCPPortNG {
  param ($server = "localhost",[int]$port)
  &{
    trap{"Server $Server not Found";continue}
    $ping = New-Object  Net.NetworkInformation.Ping
    $script:result = $null
    $script:result = $ping.send($server)
  }
      Trap {"$port Not Open";continue}
      "Checking $server $port :"
      $client = New-Object Net.Sockets.TcpClient
      $client.connect($server,$port)
      if ($client.connected) {
        "$port is Open, Trying to get banner"
        $stream = $client.GetStream()
        $chars = @()
        sleep -m 1000 # Give server some time to react 
        while ($stream.DataAvailable) {$chars += [char]$stream.readByte()}
        [string]::concat($chars)
      }
}

function Test-TCPPort {
# test for open tcp port on endpoint
	Param(
        [Parameter(Mandatory=$True)]
        [string]$endpoint,
        [Parameter(Mandatory=$True)]
        [int]$tcpport,
        [Parameter(Mandatory=$False)]
        [switch]$testBlocked,
        [Parameter(Mandatory=$True)]
        [int32]$points
    )
	$result = 0
    
    $chkPort = Test-NetConnection -ComputerName $endpoint -Port $tcpport -InformationLevel Quiet

    if ($testBlocked) {
        if ($chkPort -eq $false){
            $result = $points
        }
    }
    else {
        if ($chkPort -eq $true){
            $result = $points
        }
    }

    $result -as [Int32]
}

function Test-PingHost {
	#input accepts ip or hostname
	param($hostname,$points)

	$result = 0
    $chkhost = Test-NetConnection $hostname -InformationLevel Quiet
    if ($chkhost -eq $true) {
        $result = $points
    }
    $result -as [Int32]
}

function Test-PingHostNG{
	#input accepts ip or hostname
	param($hostname)

    $result = $false
    $chkhost = Test-NetConnection $hostname -InformationLevel Quiet
    if ($chkhost -eq $true) {
        $result = $true
    }
}

Function Test-NSlookupHost{
	#cname parameter is optional, hostname required
	Param($hostname,$points)
	
	$result = 0
    $chkHost = Resolve-DnsName -Name $hostname -Type A -ErrorAction SilentlyContinue -QuickTimeout
    if ($chkHost){
        $result = $points
    }

	$result -as [Int32]
}

function Test-VSSEnabled{
	#input accepts ip or hostname
	param($computer,$points)

    $result = 0
    $chkvss = gwmi -Class Win32_ShadowStorage -ComputerName $computer
    if ($chkvss -ne $null)
    {
        $result = $points
    }
	$result -as [Int32]
}

function Test-WinFWStatus {
	param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("on","off")]
        $statusTochk,
        $points
    )
	$result = 0
	
    write-host "Checking Windows Firewall status..." -ForegroundColor Yellow

	# Create the firewall manager object
    $fwMgr = New-Object -com HNetCfg.FwMgr 
  
    # Get the current profile for the local firewall policy. 
    $profile = $fwMgr.LocalPolicy.CurrentProfile 
  
    if ($statusTochk -eq "on"){
        if ($profile.FirewallEnabled){
            $result = $points
        }
    }
    
    if ($statusTochk -eq "off"){
        if (!$profile.FirewallEnabled){
            $result = $points
        }
    }

    return $result -as [Int32]
}

function Test-winFWRule {
    param (
        $ports,
        [parameter(Mandatory=$true)]
        [validateset("allow","deny")]
        $action,
        $points
    )
    $result = 0

    if ($action -eq "allow"){$fwaction = 1}
    if ($action -eq "deny"){$fwaction = 0}

    $fw = New-Object -ComObject hnetcfg.fwpolicy2 
    $ruleMatch = $fw.rules | Where-Object {($_.action -eq $fwaction) -and ($_.localports -eq $ports) -and ($_.enabled)}

    if ($ruleMatch){
		$result = $points
	}
    
    return $result -as [Int32]
}

function Test-adPasswdPol {
    param($minPassLength,$maxPassAge,$PassHistCount,$Lockout,$points)

    $result = 0

    $passPol = get-adDefaultDomainPasswordPolicy
    if (($passpol.minpasswordlength -eq $minPassLength) -and ($passPol.maxpasswordage.days -eq $maxPassAge) -and ($passPol.passwordhistorycount -eq $PassHistCount) -and ($passpol.lockoutThreshold -eq $Lockout)){
        $result = $points
    }

    return $result -as [Int32]

}

#endregion labcheckfunc-windows

#region labcheckfunc-linux

Function New-SSHSessionNG {
    #uses Posh-SSH open source module
    param($lhost,$userName,$pwd)

    #check for new session, download module and install if not found, then import
    try{
        $chkSSHSession = get-SSHSession | ? {($_.host -eq $lhost) -and ($_.connected -eq $true)}
    }
    catch {
        #install/load SSH module as necessary
        $chkModuleExists = get-module -ListAvailable -All -Name Posh-SSH
        if (!($chkModuleExists)){
            write-host "Posh-SSH module not found, downloading and installing now..."
            iex (New-Object Net.WebClient).DownloadString("https://gist.github.com/darkoperator/6152630/raw/c67de4f7cd780ba367cccbc2593f38d18ce6df89/instposhsshdev")
        }
        
        $chkModuleLoaded = get-module -Name Posh-SSH
        if (!($chkModuleLoaded)){
            import-module Posh-SSH
        }
        
    }

    #check for an open ssh session to the linux host, create if not present
    if ($chkSSHSession){
        $SShSession = $chkSSHSession
    }
    elseif (!($chkSSHSession)){
        $securePass = $pwd | ConvertTo-SecureString -AsPlainText -Force
        $secureCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $securePass
        $SSHSession = new-sshsession -computername $lhost -credential $secureCreds -acceptKey
    }

    Return $SShSession
}

function Test-LinuxUserExists {
    #utilizes Posh-SSH module
	param($lhost,$user,$adminuser,$rootpw,$points)
	$result = 0
	
	$Commands = "cat /etc/passwd"
	
    #check to see if host is available first
    $checkhost = test-netconnection $lhost -InformationLevel Quiet
    if ($checkhost){
        $lsession = New-SSHSessionNG -lhost $lhost -userName $adminuser -pwd $rootpw
        $usercheck = (invoke-SSHCommand -command $commands -SSHSession $lsession).output
        $chkUserstring = select-string -inputobject $usercheck -pattern $user -simplematch
    	if ($chkUserstring) {
        	$result = $points
        }
    }
    return $result -as [Int32]
}

function Test-LinuxSMBMounted {
    #utilizes POSH-SSH
	param($lhost,$smbpath,$adminuser,$rootpw,$points)
	$result = 0
	
	$Commands = "mount"
	
    #check to see if host is available first
    $checkhost = test-netconnection $lhost -InformationLevel Quiet
    if ($checkhost){
        $lsession = New-SSHSessionNG -lhost $lhost -userName $adminuser -pwd $rootpw
        $smbcheck = (invoke-SSHCommand -command $commands -SSHSession $lsession).output
        $chkSMBstring = select-string -inputobject $smbcheck -pattern $smbpath -SimpleMatch
    	if ($chkSMBstring) {
        	$result = $points
        }
    }
    return $result -as [Int32]
}

function Test-LinuxFileExists {
    #utilizes POSH-SSH module
	param($lhost,$filepath,$adminuser,$rootpw,$points)
	$result = 0
	
	$Commands = "ls $filepath"
	
    #check to see if host is available first
    $checkhost = Test-NetConnection $lhost -InformationLevel Quiet
    if ($checkhost){
        $lsession = New-SSHSessionNG -lhost $lhost -userName $adminuser -pwd $rootpw
        $filecheck = (invoke-SSHCommand -command $commands -SSHSession $lsession).output
        $chkFEstring = select-string -inputobject $filecheck -pattern $filepath
    	if ($chkFEstring) {
        	$result = $points
        }
    }
    return $result -as [Int32]
}

function Test-LinuxFileContainsText {
    #utilizes Posh-SSH module
	param($lhost,$filepath,$text,$adminuser,$rootpw,$points)
	$result = 0
	
	$Commands = "cat $filepath"
	
    #check to see if host is available first
    $checkhost = Test-NetConnection $lhost -InformationLevel Quiet
    if ($checkhost){
        $lsession = New-SSHSessionNG -lhost $lhost -userName $adminuser -pwd $rootpw
        Invoke-SSHCommands -Username $adminuser -Hostname $Hostname -Password $Password -PlinkAndPath $PlinkAndPath -CommandArray $Commands
        $textcheck = (invoke-SSHCommand -command $commands -SSHSession $lsession).output
        $chkFilestring = select-string -inputobject $textcheck -pattern $text -simplematch
    	if ($chkFilestring) {
        	$result = $points
        }
    }
    return $result -as [Int32]
}

function Test-LinuxKerberosAuth {
    #inprogress, not ready for use
    #utilizes 
    param($lhost,$adminUser,$rootPW,$adUser,$adPW,$adDomain,$points)

    $result = 0
    
    $KerbSuccess = "Default Principal: $($adUser)@$($adDomain)"   
    $commands = "echo $($adPW) | kinit $($adUser);klist"
    	
    #check to see if host is available first
    $checkhost = Test-NetConnection $lhost -InformationLevel Quiet
    if ($checkhost){
        $lsession = New-SSHSessionNG -lhost $lhost -userName $adminuser -pwd $rootpw
        $KerbCheck = (invoke-SSHCommand -command $commands -SSHSession $lsession).output
        $chkKerbString = select-string -inputobject $Kerbcheck -pattern $KerbSuccess -SimpleMatch
    	if ($chkKerbString) {
        	$result = $points
        }
    }
    return $result -as [Int32]
}

function Test-LinuxFWStatus {
    #utilizes posh-ssh module
	param(
        $lhost,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet("active","inactive")]
        $statusTochk,
        $adminuser,
        $rootpw,
        $points
    )
	$result = 0
	
    if ($statusToChk -eq "active"){$FWStatus = "Status: active"}
    if ($statusToChk -eq "inactive"){$FWStatus = "Status: inactive"}
    
    $commands = "echo $($rootpw) | sudo -S ufw status"
    	
    #check to see if host is available first
    $checkhost = Test-NetConnection $lhost -InformationLevel Quiet
    if ($checkhost){
        $lsession = New-SSHSessionNG -lhost $lhost -userName $adminuser -pwd $rootpw
        $FWcheck = (invoke-SSHCommand -command $commands -SSHSession $lsession).output
        $chkFWstring = select-string -inputobject $FWcheck -pattern $FWStatus -SimpleMatch
    	if ($chkFWstring) {
        	$result = $points
        }
    }
    return $result -as [Int32]
}

#endregion labcheckfunc-linux

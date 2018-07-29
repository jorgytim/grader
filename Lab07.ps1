<# Lab07 check script
    Purpose: IST346 lab grader script
    AUTHOR:  tajorgen
    Changes:
    1.0 2015-06-02 - Initial script creation with winforms output
    1.1 2015-08-13 - Fine tuned grade submission and regmarker checks
#>

param(
    [parameter(Mandatory=$true,position=1)]
    [string]$stuEmail,
    [parameter(Mandatory=$true,position=2)]
    [string]$profEmail,
    [parameter(Mandatory=$true,position=3)]
    [string]$moduleFile,
    [parameter(Mandatory=$true,position=4)]
    [string]$keyFile
)

#region functions

function check-regmarkers {
    #used by all labs, do not edit below
    param($inputString,$keyfile,$scriptDir,$labNum)
    #Decrypt strings with AES key
    #Decrypt password from file
    $encryptedStudentString = ((get-itemproperty "hklm:\software\IST346").student)
    $encryptedProfString = ((get-itemproperty "hklm:\software\IST346").professor)

    #Decrypt key from file
    $key = (get-content "$($scriptDir)\$($keyfile)")

    $keyPath = "HKLM:Software\IST346\$($labNum)"
    $keyPathExists = test-path $keyPath
    if (!($keyPathExists)) {new-item $keyPath}

    #Convert the passwords to plain text
    $studentStringValue = $encryptedStudentString | ConvertTo-SecureString -key $key
    $profStringValue = $encryptedProfString | ConvertTo-SecureString -key $key
    $stuBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($studentStringValue)
    $profBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($profStringValue)
    $studentDecryptedString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($stuBSTR)
    $profDecryptedString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($profBSTR)

    #hashtable for return values based on matching of regkey marker and inputs
    $global:vmOwner = $studentDecryptedString
    $global:Professor = $profDecryptedString
    $global:runCount = (get-itemproperty $($keyPath)).RunCount

    if ($studentDecryptedString -eq $inputString){
        return "true"
    }
    else {
        $lastRunkey = (get-itemproperty hklm:\software\ist346).LastRun
        $regKeys = New-Object System.Collections.ArrayList
        $regKeys += "Student running = $stuEmail"
        $regKeys += "VMowner = $global:vmOwner"
        $regKeys += "Professor stored = $global:Professor"
        $regKeys += "Professor entered = $profEmail"
        $regKeys += "Last Run = $lastRunkey"
        $regKeys += "Encrypted student key = $encryptedStudentString"
        $regKeys += "Encrypted professor key = $encryptedProfString"
        [string]$global:regOutput = [string]::join("`r`n", ($regKeys))
        return "false"
    }
    
}

function out-score{
	param(
        [string]$rubric,
        [int]$pts,
        [int]$outof
    )
	Write-Output "$pts/$outof`t$rubric`n"
}

function Grade-Lab {
	param(
        [string]$stuEmail,
        [string]$profEmail,
        [string]$labName
    )
    #constants
    [string]$username = $stuEmail.Split("@")[0]	
    $score = 0

    #region customize lab
	$domain = "ad.fauxco.com"
    $linux = "linuxserver.$($domain)"
	$winclient = "winclient.$($domain)"
	$winsrv = "winserver.$($domain)"
    $nixadmin = "localadmin"
    $nixpw = "Adminpassw0rd!"
    $adAdmin = "administrator"
    $adAdminPw = "Adminpassw0rd!"
    $share1 = "shares"
    $groupsFile = "lab07-groups.csv"
    $usersFile = "lab07-users.csv"
    $backupShare = "backup"
    $linuxbackpath = "/media/backup"
	$linuxbackshare = "\\" + $winsrv + "\$($backupShare)\linux"
	$linuxbackfolder = $linuxbackshare + "\etc"
	$linuxbackfilename = "backuptest.txt"
	$lfilepath1 = "/etc/cron.weekly/ubuntu-backup.sh"
	$lsearchtext1 = "rsync --delete -rzv /etc/ /media/backup/etc"
	$smbmntpath1 = "//$($winsrv)/$($backupShare)/linux on /media/backup"
    $userpw = "Userpassw0rd"
    $groupsFldWin = "c:\shares\groups"
	$now = (date).ToString("yyy-MM-dd")
    
    # download supplemental files here
    Get-SupplemantalFile -url "$scriptsBaseUrl" -filename "$groupsFile" -quiet
    Get-SupplemantalFile -url "$scriptsBaseUrl" -filename "$usersFile" -quiet

    #import users/groups files
    $users = Import-Csv $usersFile
    $groups = Import-Csv $groupsFile

    #lab grading output
	write-output "Score`tRubric (what's being checked)`n"
	write-output "=====`t=============================`n"

    write-output " "
    write-output "-----Backup settings------"
    $backupPoints = 0

	$b1 = Test-VSSEnabled -computer $winsrv -points 1
	out-score "Snapshots enabled on [$winsrv]?" $b1 1
	
	$b2 = Test-LinuxSMBMounted -lhost $linux -smbpath $smbmntpath1 -adminuser $nixadmin -rootpw $nixpw -points 1
	out-score "Linux share mounted [$smbmntpath1]?" $b2 1
	<#
	$b3 = Test-LinuxFileContainsText -lhost $linux -filepath $lfilepath1 -text $lsearchtext1 -adminuser $nixadmin -rootpw $nixpw -points 1
	out-score "Linux Backup script configured properly [$lsearchtext1]?" $b3 1
	#>
	$b4 = Test-BackupExists -path $linuxbackfolder -minfilecount "50" -points 1
	out-score "Linux server backup performed of folder [$linuxbackfolder]?" $b4 1

    #backuppoints = 4
    $backupPoints = $b1 + $b2 + $b3 + $b4
 
    write-output " " 
    write-output "-----Windows/AD Users------"
    $userlgnhdescore = 0
    $hdescore = 0
    $lgnscore = 0
    $usrpoints = 0

    $users | foreach {
        $usrName = $_.uname

        #check if user exists and has logged on, and if homedir setting exists
		$usr = Test-UserExists -user $usrName -points 1
        #$lgn = Test-UserHasLoggedOn -user $usrName -points 1
        $hde = Test-UserHomedirExists -user $usrName -points 1
	    $usrhdetmp = ($usr + $hde)/2
		if($usrhdetmp -lt "1"){$usrhde = 0}
		else{$usrhde = $usrhdetmp}
		out-score "User created, home directory set, and logged on at least once [$usrName]?" $usrhde 1
        
        $usrhdescore = $usrhdescore + $usrhde
 
    }
    #userpoints = 8
    $userpoints = $usrhdescore

	write-output " "
    write-output "-----Windows/AD Groups and shares------"
	$grpfldscore = 0
	#$gfpscore = 0
    $grpmbrscore = 0
    $grpShareScore = 0

    #check membership of each group
    $groups | foreach {
        $groupName = $_.grpName
        $grpMembers = $_.members
        
        #test group membership
        $gmb = Test-MembersOfGroupCSV -users $grpMembers -group $groupName -points 1
        out-score "Group exists and check membership for group [$groupName]?" $gmb 1

        #Test group share is available
        $grpShare = Test-FileShare -computer $winsrv -share $groupName -points 1
        out-score "Share exists for [\\$($winsrv)\$($groupName)]?" $grpShare 1

        #check group folder permissions, if path exists
       	#if (test-path -Path "$($groupsFldWin)\$($groupName)" -ErrorAction SilentlyContinue){
		#    $gfp = Test-InAcl -path "$($groupsFldWin)\$($groupName)" -principal "$groupName" -points 1
    	#    out-score "Created folder and set permissions for group [$groupName]?" $gfp 1
        #}
        
        #$gfpscore = $gfpscore + $gfp
        $grpmbrscore += $gmb
        $grpShareScore += $grpShare
    }
    #grouppoints = 8
    $grouppoints = $grpmbrscore + $grpShareScore #+ $gfpscore

    write-output " "
    write-output "-----Linux Kerberos Auth------"
    $lkerbAuth = 0
    $linuxonline = Test-connection $linux -count 1 -quiet
    $lkerbAuth = Test-LinuxKerberosAuth -lhost $linux -adminUser $nixadmin -rootPW $nixpw -adUser $adAdmin -adPW $adAdminPw -points 2
    out-score "[$linux] joined to the Domain and Kerberos Authentication working?" $lkerbAuth 2

    write-output " "
    write-output "-----Linux Shares------"
    $lshareavail = 0
    $lsharewrite = 0
    $linuxpoints = 0
    $linuxonline = Test-connection $linux -count 1 -quiet

    $groups | foreach {
        $groupName = $_.grpName
        $grpMembers = $_.members
        $groupShare = "$($groupName)-projects"

        #check linux share availability        
        $lshare = Test-FileShare -computer $linux -share $groupShare -points 1
        out-score "Linux share exists for [$groupShare]?" $lshare 1
        $lshareavail = $lshareavail + $lshare

    }
    #linuxpoints = 6
    $linuxpoints = $lkerbAuth + $lshareavail # + $lsharewrite
	
	write-output ""

	$total = $backupPoints + $userpoints + $grouppoints + $linuxpoints

	out-score "Total Score for $($labName)" $total 25
	write-output "Completed by:  $username"
	write-output "Lab completed on:  $now"
    write-output "Run Count: $($global:runCount)"
    #endregion customize lab
}

#endregion functions

#region Constants, editable
$labName = "IST346 Lab07 Check Script - Snapshots, Backups, File Services"
$labNum = "Lab07"
#endregion global constants

#region main, used by all labs, do not edit below
cls
$scriptDir = $env:TEMP
[string]$scriptsBaseUrl = "https://tajorgen.mysite.syr.edu"
Import-Module activedirectory -ErrorAction SilentlyContinue
Import-Module "$($scriptDir)\$($moduleFile)"
Install-AdditionalModules
$Output = New-Object System.Collections.ArrayList
$global:regOutput = $null
[string]$global:profStored = $null
[string]$global:vmOwner = $null
[string]$global:runCount = $null

$authChk = check-regmarkers -inputString $stuEmail -keyfile $keyFile -scriptDir $scriptDir -labNum $labNum

if ($authChk -eq "true"){
    $Output += Grade-Lab -stuEmail $stuEmail -profEmail $profEmail -labName $labName
    [string]$GradeResults = [string]::join("`r`n", ($output))
}
elseif ($authChk -eq "false") {
    $Output += "Warning!!! You are in direct violation of academic integrity rules!"
    $Output += "-------------------------------------------------------------------"
    $Output += "You are not running this from your own VMs."
    $Output += "All work is supposed to be done individually on your personally assigned machines"
    $Output += "-------------------------------------------------------------------"
    $Output += "These VMs belong to $($vmowner)"
    $Output += "A notification email has been sent to $($profEmail) regarding this situation."
    $Output += "-------------------------------------------------------------------"
    $Output += "$global:regOutput"
    [string]$GradeResults = [string]::join("`r`n", ($output))
    Send-SMTPMail -to $profemail -from $stuEmail -Subject "IST346 Lab error - $labName" -body $GradeResults -cc "$stuEmail,$profStored,$vmowner"
}

#create winform
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")

$Form1 = New-Object System.Windows.Forms.Form
$Form1.ClientSize = New-Object System.Drawing.Size(500, 600)
$Form1.Text = "$labName"
$form1.topmost = $true
$form1.StartPosition = "CenterScreen"
$Form1.MinimizeBox = $False
$Form1.MaximizeBox = $False
$form1.AutoSize = $false
$form1.FormBorderStyle = "FixedDialog"
$Form1.ShowInTaskbar = $true

#output/feedback text area
$Overview = New-Object System.Windows.Forms.Label
$Overview.Location = New-Object System.Drawing.Point(10, 10)
$Overview.Size = New-Object System.Drawing.Size(500, 100)
$Overview.Text += "`nYou may run this script as much as you want but only submit it for a grade when you are ready."
$Overview.Text += "`n"
$Overview.Text += "`nIf you do not get a perfect score, it is YOUR RESPONSIBILITY to figure it out."
$Overview.Text += "`n"
$Overview.Text += "`nIMPORTANT: Only click the Submit Grade button once as it sends your grade to the Professor.  The first grade received will be counted."
$Overview.Text += "`n"
$Form1.Controls.Add($Overview)

#submit grade button
$submitButton = New-Object System.Windows.Forms.Button
$submitButton.Location = New-Object System.Drawing.Point(10, 110)
$submitButton.Size = New-Object System.Drawing.Size(100, 25)
$submitButton.Text = "Submit Grade"
$submitButton.add_Click({
        Send-SMTPMail -to $profemail -from $stuEmail -Subject "$labName - submission" -body $GradeResults -cc $stuEmail
        $Feedback.text = "Grading results sent to $stuEmail and $profemail"
        [System.Windows.Forms.MessageBox]::Show("Grading results sent to $($stuEmail) and $($profemail)","$($labNum) Completed")
        $form1.Tag = $null; $form1.Close()
    })#close button.add_click statement
$Form1.Controls.Add($submitButton)

# Close button.
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(120,110)
$cancelButton.Size = New-Object System.Drawing.Size(100,25)
$cancelButton.Text = "Close"
$cancelButton.Add_Click({ $form1.Tag = $null; $form1.Close() })
$Form1.Controls.Add($cancelButton)

#output/feedback text area
$Feedback = New-Object System.Windows.Forms.Label
$Feedback.Location = New-Object System.Drawing.Point(10, 135)
$Feedback.Size = New-Object System.Drawing.Size(400, 25)
$Feedback.Text += ""
$Form1.Controls.Add($Feedback)

#output/feedback text area
$Results = New-Object System.Windows.Forms.TextBox
$Results.Location = New-Object System.Drawing.Point(10, 170)
$Results.Size = New-Object System.Drawing.Size(470, 420)
$Results.Name = "Lab Grading Results"
$Results.Multiline = $true
$Results.ReadOnly = $true
$Results.ScrollBars = 'Both'
$Results.Text = "`nChecking your Lab work....."
$Results.Text = "$GradeResults"
$Form1.Controls.Add($Results)

[void]$form1.showdialog()
#endregion main

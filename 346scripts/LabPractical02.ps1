<# Lab Practical 02 check script
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
    $domain = "ad.profits.syr"
    $linux = "linuxserver.$($domain)"
	$winclient = "winclient.$($domain)"
	$winsrv = "winserver.$($domain)"
    $mail_dns = "mail.$($domain)"
	$blog_dns = "blog.$($domain)"
	$smtp_port = "25"
	$pop_port = "110"
	$blog_port = "80"
    $imap_port = "143"
	$webmail = "http://$($mail_dns)"
	$webmailtxt = "mailenable"
	$mailEnableRootFld = "\\$($winsrv)\c$\Program Files (x86)\Mail Enable"
    #$mailfolders = "\\$($winsrv)\c$\Program Files (x86)\Mail Enable\PostOffices\$($mail_dns)\MAILROOT"
	$smtplogpath = "\\$($winsrv)\c$\Program Files (x86)\Mail Enable\Logging\SMTP"
	$poplogpath = "\\$($winsrv)\c$\Program Files (x86)\Mail Enable\Logging\POP"
	$sflogpath = "\\$($winsrv)\c$\Program Files (x86)\Mail Enable\Logging\SF"
	$mailfiles = "*.mai"
	$logfiles = "*.log"
	$apacheurl = "http://$($blog_dns)"
	$apachemsg = "It works!"
	$blogurl = "http://$($blog_dns)/blog"
	$blogmsg = "profits"
	$sentmsgtxt = "Delivered Message From"
    $share1 = "homes"
    $groupsFile = "lp02-groups.csv"
    $usersFile = "lp02-users.csv"
	$now = (date).ToString("yyy-MM-dd")

    # download supplemental files here
    Get-SupplemantalFile -url "$scriptsBaseUrl" -filename "$groupsFile" -quiet
    Get-SupplemantalFile -url "$scriptsBaseUrl" -filename "$usersFile" -quiet
    
    #import csv files
    $users = Import-Csv $usersFile
    $groups = Import-Csv $groupsFile

    #lab grading output
	write-output "Score`tRubric (what's being checked)`n"
	write-output "=====`t=============================`n"

	#region basics
	# Hosts - 10
	write-output "-----Hosts------"
	$h1 =  Test-NsLookupHost -hostname $domain -points 5
	out-score "Resolving domain [$domain]?" $h1 5
	$h2 =  Test-NsLookupHost -hostname $linux -points 1
	out-score "Resolving name [$linux]?" $h2 1
	$h3 =  Test-NsLookupHost -hostname $mail_dns -cname $winserver -points 1
	out-score "Resolving name [$mail_dns]?" $h3 1
	$h4 =  Test-NsLookupHost -hostname $blog_dns -cname $linux -points 1
	out-score "Resolving name [$blog_dns]?" $h4 1
	$h5 =  Test-NsLookupHost -hostname $winclient -points 2
	out-score "Resolving name [$winclient]?" $h5 2
			
	$hosts = $h1 + $h2 + $h3 + $h4 + $h5
	
	# Shares - 2
	write-output ""
    write-output "-----Shares------"
    $share0 = Test-FileShare -computer $winsrv -share "$share1"  -points 2
    out-score "File Share exists [$share1]?" $share0 2
    $fileshares = $share0
    #endregion
	
	#region users
    #users - 12x2 = 24
	write-output ""
    write-output "-----Users------"
	$userscore = 0
	$hdelgnscore = 0
    
    $users | foreach {
        $hd = 0
        $usrName = $_.uname

        #check if users exist
		$usr = Test-UserExists -user "$usrname" -points 1
		out-score "User exists [$usrname]?" $usr 1
		$userscore += $usr
		
		#check if homedir user settings exist
		$hd = Test-UserHomedir -user "$usrname" -points 1
        out-score "Homedir setup properly for [$usrname]?" $hd 1	

        $hdelgnscore += $hd
    }	

	#endregion
	
	#region groups
    #groups - 5x4 = 20
	write-output ""
    write-output "-----Groups------"
	$grpscore = 0
    $grpMbrScore = 0
	$grpShareScore = 0
	$gfpscore = 0
	
    $groups | foreach {
        $groupName = $_.grpName
        $grpMembers = $_.members
        
        #check if groups exist
		$grp = Test-GroupExists -group "$groupName" -points 1
	    out-score "Group exists [$groupName]?" $grp 1
	    $grpscore += $grp

        $gm = Test-MembersOfGroupCSV -users $grpMembers -group $groupName -points 1
        out-score "Check membership for group [$groupname]?" $gm 1
        $grpMbrScore += $gm
		
		#check if group folders exist
		$gshare = Test-Fileshare -computer $winsrv -share $groupName -points 1
    	out-score "Group Share exists for [\\$($winsrv)\$($groupName)]?" $gshare 1
		$grpShareScore += $gshare
		
		#check group folder permissions
		$gfp = Test-InAcl -path "\\$($winsrv)\$($groupName)" -principal "$groupname" -points 1
    	out-score "Set group folder permissions for [$groupname]?" $gfp 1
		$gfpscore += $gfp

    }

	#endregion
	
	#region email
    #email - 2 + 4 + 4 + 12x1 = 22
	write-output ""
    write-output "-----Email------"
	$emsvcscore = 0
	$emconfirm = 0
	$emailscore = 0

	$emsvc1 = Test-PingHost -hostname $mail_dns -points 2
	out-score "Does DNS host name [$mail_dns] resolve to ping?" $emsvc1 2
	$emsvc2 = Test-TCPPort -endpoint $mail_dns -tcpport $smtp_port -points 4
	out-score "Is the SMTP service port [$smtp_port] runnning on [$mail_dns]?" $emsvc2 4
	$emsvc3 = Test-Website -url $webmail -text $webmailtxt -points 4
	out-score "Does Site [$webmail] exist with title [$webmailtxt]?" $emsvc3 4
	
	$emsvcscore = $emsvc1 + $emsvc2 + $emsvc3

    #check user emails sent/received
    #find postoffice folder first to determine mailfolders path
    $mailfolders = (get-childitem "$($mailEnableRootFld)\PostOffices\" -Directory).FullName + "\MAILROOT"

    $users | foreach {
        $usrName = $_.uname
		
		#check if emails were sent and received by each user
		$emrecvd = Test-PathConstainsFile -path "$mailfolders\$($usrName)\inbox" -filename "$mailfiles" -filter "default.mai" -points 1
		$emsent = Test-PathConstainsText -path "$sflogpath" -text "$($usrName)@$($mail_dns)" -filter "$sentmsgtxt" -points 1
		$emtmp = ($emrecvd + $emsent)/2
		if($emtmp -lt 1){$emconfirm = 0}
		else{$emconfirm = $emtmp}
		
		out-score "Has at least one email been sent and received by [$usrName]?" $emconfirm 1
				
		$emailscore += $emconfirm
	}
    #endregion
	
	#region blog services
    #blog - 2 + 4 + 8 + 12x1 = 26
	write-output ""
    write-output "-----Blog Services------"
	$blogsvcscore = 0
	$blogscore = 0
	
	$blogsvc1 = Test-TCPPort -endpoint $blog_dns -tcpport $blog_port -points 2
	out-score "Is the httpd service port ($blog_port) runnning on [$blog_dns]?" $blogsvc1 2
	
	$blogsvc2 = Test-Website -url $apacheurl -text $apachemsg -points 4
	out-score "Is the apache installed with the default website on Ubuntu? [$apacheurl]" $blogsvc2 4
	
	$blogsvc3 = Test-Website -url $blogurl -text $blogmsg -points 8
	out-score "Is the blog installed on Ubuntu? [$blogurl]" $blogsvc3 8
	
	$blogsvcscore = $blogsvc1 + $blogsvc2 + $blogsvc3
	
    $users | foreach {
        $usrName = $_.uname
        $lastName = $_.lname
		
		#check if blog messages were posted by and published for each user
		$blogpost = Test-Website -url $blogurl -text $lastName -points 1
		out-score "Did [$usrName] post a message the blog? [$blogurl]" $blogpost 1
			
		$blogscore = $blogscore + $blogpost
	}
	
	#endregion

    #region test IT user settings
    #ITuser = 1,IThde = 1, ITGrpscore = 2, ITEmconfirm = 1
    #ITScore - 1 + 1 + 1 + 2  = 5
    write-output ""
    write-output "-----IT User configuration------"
    $ITGrpScore = 0
    $ITEMConfirm = 0
    $ITScore = 0

    $ITusr = Test-UserExists -user "$username" -points 1
	out-score "User exists [$username]?" $usr 1
		
	$IThde = Test-UserHomedir -user "$username" -points 1
    out-score "Homedir setting correct for [$username]?" $IThde 1

    #detect if IT is a member of all groups
    $groups | foreach {
        $groupName = $_.grpName
        $grpMembers = $_.members
        $ITgrpsTmp = Test-MemberofGroup -account $username -group $groupname -points 1
        $ITGrps += $ITgrpsTmp
    }
    if ($ITgrps -eq $groups.count){
        $ITGrpScore = 2
    }
    out-score "Is [$username] a member of all necessary groups?" $ITGrpScore 2

    #check group emails sent/received
    $ITemrecvd = Test-PathConstainsFile -path "$mailfolders\$($userName)\inbox" -filename "$mailfiles" -filter "default.mai" -points 1
	$ITemsent = Test-PathConstainsText -path "$sflogpath" -text "$($userName)@$($mail_dns)" -filter "$sentmsgtxt" -points 1
	$ITemtmp = ($ITemrecvd + $ITemsent)/2
	if($ITemtmp -lt 1){$ITemconfirm = 0}
	else{$ITemconfirm = $ITemtmp}
	out-score "Has at least one email been sent and received by [$userName]?" $ITemconfirm 1

    $ITScore = $ITusr + $IThde + $ITGrpScore + $ITemconfirm

    #endregion test IT user

    
	write-output ""

	$total = $hosts + $fileshares + $userscore + $hdelgnscore + $grpscore + $grpfldscore + $gfpscore + $grpmbrscore + $emsvcscore + $emailscore + $blogsvcscore + $blogscore + $ITScore
    out-score -rubric "Total Score for '$examname'..." -pts $total -outof 100
    Write-Output "Mininum Score required for Full Credit = 100"
	$exampointstmp = $total * 0.7
	if ($exampointstmp -ge 70){$exampoints = "70"}
	else {$exampoints = $exampointstmp}

	write-output ""

	write-output "Points earned for LP02 (out of 70):  $exampoints"
	write-output ""
	write-output "Completed by:  $username"
	write-output "Completed on:  $now"
    write-output "Run Count: $($global:runCount)"
    #endregion customize lab
}

#endregion functions

#region Constants, editable
$labName ="IST346 LP02 Check Script - Lab Practical 02"
$labNum = "LP02"
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

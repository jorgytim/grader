<# Lab Practical 01 check script
    Purpose: IST346 lab grader script
    AUTHOR:  tajorgen
    Changes:
    1.0 2015-06-02 - Initial script creation with winforms output
    1.1 2015-08-13 - Fine tuned grade submission and regmarker checks
    1.2 2018-08-09 - General cleanup of functions, added minimize box to output window
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

function read-regmarkers {
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

function Get-Labresults {
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
    $share1 = "shares"
    $groupsFile = "lp01-groups.csv"
    $usersFile = "lp01-users.csv"
	$now = (get-date).ToString("yyy-MM-dd")
    
    # download supplemental files here
    #Get-SupplemantalFile -url "$scriptsBaseUrl" -filename "plink.exe" -quiet
    Get-SupplemantalFile -url "$scriptsIncludesBaseUrl" -filename "$groupsFile" -quiet
    Get-SupplemantalFile -url "$scriptsIncludesBaseUrl" -filename "$usersFile" -quiet
    
    #create plink command file
    if (-not (test-path -path ".\cmd.txt")) 
    {
        "/bin/cat /etc/passwd" | out-file -FilePath ".\cmd.txt" -Encoding "ASCII"
    }

    #lab grading output
	write-output "Score`tRubric (what's being checked)`n"
	write-output "=====`t=============================`n"

    # Shares
    $fschk = Test-FileShare -computer "$winsrv" -share "$share1"  -points 1
    out-score "File Share exists [$share1]?" $fschk 1
    $fsscore = $fschk
    
    #region users    
    # Users - 16
    # User homedir path - 8
    # User homedir settings - 16
    # User logins - 8
    write-output "-----Windows/AD Users------"
    $userscore = 0
    $hdpathscore = 0
    $hdescore = 0
    $lgnscore = 0
    
    $users = Import-Csv $usersFile
    $users | foreach-object {
        $usrName = $_.uname

        #check if users exist
		$usr = Test-UserExists -user "$usrname" -points 2
		out-score "User exists [$usrname]?" $usr 2
		$userscore = $userscore + $usr

        #check for homedir setting in user object
        $hde = Test-UserHomedirExists -user "$usrname" -points 2
		out-score "Homedir exists for [$usrname]?" $hde 2
        
        $hdescore = $hdescore + $hde

        #check if user has logged on at least once
        $lgn = Test-UserHasLoggedOn -user "$usrname" -points 2
	    out-score "Logged on as user [$usrname]?" $lgn 2
		
        $lgnscore = $lgnscore + $lgn

    }

    #endregion users

    #region groups
    #groups - 10
	#group folders - 5
	#group folder permissions = 10
	#group members - 10
	write-output "-----Windows/AD Groups------"
	$grpscore = 0
	$grpfldscore = 0
	$gfpscore = 0
    $grpmbrscore = 0
    
    $groups = Import-Csv $groupsFile
    $groups | foreach-object {
        $groupName = $_.grpName
        $grpMembers = $_.members

        #check if groups exist
		$grp = Test-GroupExists -group "$groupName" -points 2
	    out-score "Group exists [$groupName]?" $grp 2
	    $grpscore = $grpscore + $grp

        #check if group folders exist
		$gfld = Test-PathExists -path "c:\shares\groups\$($groupName)" -points 1
    	out-score "Group Folder exists for [$groupName]?" $gfld 1
		$grpfldscore = $grpfldscore + $gfld

        #check group folder permissions
		$gfp = Test-InAcl -path "c:\shares\groups\$($groupName)" -principal "$groupName" -points 2
    	out-score "Set group folder permissions for [$groupName]?" $gfp 2
		$gfpscore = $gfpscore + $gfp

        #check group memberships
        $gm = Test-MembersOfGroupCSV -users "$grpMembers" -group $groupName -points 2
        out-score "Check membership of group [$groupName] members = [$grpMembers]?" $gm 2
        $grpmbrscore = $grpmbrscore + $gm
    }
    
    #endregion groups
    
    #region linuxusers
    #linux users - 16
    write-output "-----Linux Users------"
    $luserscore = 0

    #import users list, check each
    $users = Import-Csv $usersFile
    $users | foreach-object {
        $usrName = $_.uname
        $lusr = Test-LinuxUserExists -adminuser $nixadmin -rootpw $nixpw -lhost $linux -user $usrName -points 2
        out-score "Linux user exists [$usrName]?" $lusr 2
        $luserscore = $luserscore + $lusr
    }

    #endregion linuxusers
        
	write-output ""
    #section for debugging grading
    #write-output "fsscore = $fsscore"
    #write-output "userscore = $userscore"
    #write-output "hdpathscore = $hdpathscore"
    #write-output "hdescore = $hdescore"
    #write-output "lgnscore = $lgnscore"
    #write-output "grpscore = $grpscore"
    #write-output "grpfldscore = $grpfldscore"
    #write-output "gfpscore = $gfpscore"
    #write-output "grpmbrscore = $grpmbrscore"
    #write-output "luserscore = $luserscore"
    #write-output ""

	$total = $fsscore + $userscore + $hdpathscore + $hdescore + $lgnscore + $grpscore + $grpfldscore + $gfpscore + $grpmbrscore + $luserscore
	out-score "Total Score for '$labname'..." $total 100
	$exampoints = $total * 0.3

	write-output ""

	write-output "Points earned for LP01 (out of 30):  $exampoints"
	write-output ""
	write-output "Completed by:  $username"
	write-output "Exam completed on:  $now"
    write-output "Run Count: $($global:runCount)"
    #endregion customize lab
}

#endregion functions

#region Constants, editable
$labName ="IST346 LP01 Check Script - Lab Practical Exam 01"
$labNum = "LP01"
#endregion global constants

#region main, used by all labs, do not edit below
Clear-Host
$scriptDir = $env:TEMP
[string]$scriptsIncludesBaseUrl = "https://raw.githubusercontent.com/jorgytim/grader/master/346includes"
Import-Module activedirectory -ErrorAction SilentlyContinue
Import-Module "$($scriptDir)\$($moduleFile)"
Install-AdditionalModules
$Output = New-Object System.Collections.ArrayList
$global:regOutput = $null
[string]$global:profStored = $null
[string]$global:vmOwner = $null
[string]$global:runCount = $null

$authChk = read-regmarkers -inputString $stuEmail -keyfile $keyFile -scriptDir $scriptDir -labNum $labNum

if ($authChk -eq "true"){
    $Output += Get-Labresults -stuEmail $stuEmail -profEmail $profEmail -labName $labName
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
$form1.topmost = $false
$form1.StartPosition = "CenterScreen"
$Form1.MinimizeBox = $True
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

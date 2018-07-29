<# Lab04 check script
    Purpose: IST346 lab grader script
    AUTHOR:  tajorgen
    Changes:
    1.0 2015-06-02 - Initial script creation with winforms output
    1.1 2015-08-13 - Fine tuned grade submission and regmarker checks
    1.2 2015-10-01 - Edited lab grading function to tweak file share checks
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
    #used by all labs, do not edit below
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
 	$linux = "linux"
	$winsrv = "winserver"
	$client = "winclient"
	$linshare = "linshare"
    $linshareUnc = "\\$($linux)\$($linshare)"
	$winshare = "winshare"
    $winshareUnc = "\\$($winsrv)\$($winshare)"
    $linshare2 = "linshare2"
    $linshare2Unc = "\\$($linux)\$($linshare2)"
	$winShare2 = "winshare2"
    $winshare2Unc = "\\$($winsrv)\$($winshare2)"
	$file = "message.txt"
    $usr = "testuser"
    $upass = "Userpassw0rd!"
	$now = (date).ToString("yyy-MM-dd")
    
    #lab grading output
	write-output ""
	write-output "Score`tRubric (what's being checked)`n"
	write-output "=====`t=============================`n"

    $n1 = Test-TCPPort -endpoint $linux -tcpport 445 -points 1
	out-score "Checking availability of file sharing services on [$linux]?" $n1 1
	
    $n2 = Test-TCPPort -endpoint $linux -tcpport 22 -points 2
	out-score "Checking availability of the ssh service on [$linux]?" $n2 2

	$n3 = Test-TCPPort -endpoint $winsrv -tcpport 25 -points 2
	out-score "Checking availability of SMTP service on [$winsrv]?" $n3 2

    $n4 =  Test-FileShare -computer $linux -share $linshare -points 2
    out-score "Fileshare [$linshare] exists on [$linux]?" $n4 2
    
    $n5 = Test-FileShareWrite -unc $linshareUnc -user $usr -pass $upass -points 1
    out-score "Fileshare [$linshareUnc] writeable by [$usr]?" $n5 1	

    $n6 =  Test-FileShare -computer $winsrv -share $winshare -points 1
    out-score "Fileshare [$winshare] exists on [$winsrv]?" $n6 1
    
    $n7 = Test-FileShareWrite -unc $winshareUnc -user $usr -pass $upass -points 1
    out-score "Fileshare [$winshareUnc] writeable by [$usr]?" $n7 1

	write-output ""

	$total = $n1 + $n2 + $n3 + $n4 + $n5 + $n6 + $n7
	out-score "Total Score for $($labName)" $total 10
	write-output "Completed by:  $username"
	write-output "Exam completed on:  $now"
    write-output "Run Count: $($global:runCount)"
    #endregion customize lab
}

#endregion functions
#region Constants, editable
$labName = "IST346 Lab04 Check Script - Services"
$labNum = "Lab04"
#endregion global constants

#region main, used by all labs, do not edit below
cls
$scriptDir = $env:TEMP
[string]$scriptsBaseUrl = "http://tajorgen.mysite.syr.edu"
Import-Module activedirectory -ErrorAction SilentlyContinue
Import-Module "$($scriptDir)\$($moduleFile)"
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

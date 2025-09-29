

#1. Paramaters, Logging, Prechecks.

param(
  [string]$DomainFqdn = "roguecapital.local",
  [switch]$DryRun,
  [switch]$VerboseLogging
)

$LogPath = "C:\Temp\roguecapital_seed.log"
New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[Sts] $Message"
    if ($VerboseLogging) {Write-Host $line}
    Add-Content -Path $LogPath -Value $line
  }
Write-Log "--Run started (DryRun=$DryRun) --"

try{Import-Module ActiveDirectory -ErrorAction Stop; Write-Log "AD module loaded"}
catch{throw "ActiveDirectory module missing. Install RSAT/AD DS tools and re-run."}

$DomainInfo = Get-ADDomain
$CurrentFqdn = $DomainInfo.DNSRoot
$BaseDN = $DomainInfo.DistinguishedName
if($CurrentFqdn -ne $DomainFqdn) {
    Write-Log "Wrong domain"
  } 
else {
    Write-Log "Correct domain"
  }

[void](Get-ADDomainController -Discover -ErrorAction Stop)
Write-Log "DC reachable"

try{Import-Module GroupPolicy -ErrorAction Stop; Write-Log "[Sts] GroupPolicy module loaded"}
catch{throw "GroupPolicy module missing"}

#2.Helpers

function Invoke-Idempotent {
    param([scriptblock]$Action, [string]$Desc)
    if($DryRun) {Write-Log "[DryRun] $Desc"}
    else {Write-Log $Desc; & $Action}
  }

function Ensure-OU {
    param(
      [Parameter(Mandatory)] [string]$Name,
      [Parameter(Mandatory)] [string]$ParentDN
    )
    $exists = Get-ADOrganizationalUnit -LDAPFilter "(ou=$Name)" -SearchBase $ParentDN -ErrorAction SilentlyContinue
    if($exists) {
        Write-Log "OU '$Name' already exists"
        return $exists.DistinguishedName
      }
    else {
        $dn = "OU=$Name,$ParentDN"
        Invoke-Idempotent -Desc "Creating OU '$Name' under '$ParentDN'." -Action {New-ADOrganizationalUnit -Name $Name -Path $ParentDN -ProtectedFromAccidentalDeletion:$false | Out-Null}
        return $dn
      }
  }

function Ensure-Group {
    param(
      [Parameter(Mandatory)] [string]$Name,
      [Parameter(Mandatory)] [string]$OUdn,
      [ValidateSet("Global","DomainLocal","Univeral")] [string]$Scope = "Global",
      [ValidateSet("Security","Distribution")] [string]$Category = "Security"
    )

    $exists = Get-ADGroup -Filter "SamAccountName -eq '$Name'" -SearchBase $OUdn -ErrorAction SilentlyContinue
    if ($exists) {
        Write-Log "Group exists"
        return $exists.DistinguishedName
      }

    Invoke-Idempotent -Desc "Creating group '$Name' in '$OUdn'." -Action {
        New-ADGroup -Name $Name -SamAccountName $Name `
          -GroupCategory $Category -GroupScope $Scope -Path $OUdn | Out-Null
      }

    return "CN=$Name,$OUdn"
  }

function Ensure-User {
    param(
      [Parameter(Mandatory)] [string]$Sam,
      [Parameter(Mandatory)] [string]$Given,
      [Parameter(Mandatory)] [string]$Surname,
      [Parameter(Mandatory)] [string]$OUdn,
      [Parameter(Mandatory)] [string]$Password,
      [string[]]$Groups
    )

    $exists = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -SearchBase $OUdn -ErrorAction SilentlyContinue
    if($exists) {
        Write-Log "User already exists"
        return $exists.DistinguishedName
      }

    $securePwd = ConvertTo-SecureString $Password -AsPlainText -Force
    $upn = "$Sam@$($DomainInfo.DNSRoot)"

    Invoke-Idempotent -Desc "Creating user '$Sam' in '$OUdn'." -Action {
        New-ADUser -Name "$Given $Surname" -GivenName $Given -Surname $Surname `
          -SamAccountName $Sam -UserPrincipalName $upn -Path $OUdn `
          -AccountPassword $securePwd -Enabled $true -ChangePasswordAtLogon $false | Out-Null

      }

    if($Groups) {
        foreach($g in $Groups) {
            try {
                $grp = Get-ADGroup -LDAPFilter "(sAMAccountName=$g)" -SearchBase $BaseDN -SearchScope Subtree -ErrorAction Stop

              } catch {
                  Write-Log "Group '$g' not found for user '$Sam': $($_.Exception.Message)"
                  continue
                }

            try {
                Add-ADGroupMember -Identity $grp.DistinguishedName -Members $Sam -ErrorAction Stop
                Write-Log "Added '$Sam' to '$($grp.SamAccountName)'"
              } catch {
                  Write-Log "failed to add '$Sam' to '$($grp.SamAccountName)': $($_.Exception.Message)"
                }
          }
      }

      return "CN=$Given $Surname,$OUdn"
  }

function Ensure-serviceAccount {
    param(
      [Parameter(Mandatory)] [string]$Sam,
      [Parameter(Mandatory)] [string]$OUdn,
      [Parameter(Mandatory)] [string]$password
    )

    $exists = Get-ADUser -Filter "SamAccountName -eq '$Sam'" -SearchBase $OUdn -ErrorAction SilentlyContinue
    if ($exists) {
       Write-Log "Service account exists"
       return $exists.DistinguishedName
      }

    $Secure = ConvertTo-SecureString $Password -AsPlainText -Force 
    $upn = "$Sam@$($DomainInfo.DNSRoot)"
    $Name = $Sam 

    Invoke-Idempotent -Desc "Creating service account '$Sam' in '$OUdn'." -Action {
        New-ADUser -Name $Name -SamAccountName $Sam -UserPrincipalName $upn -Path $OUdn `
          -AccountPassword $secure -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false `
          -SmartcardLogonRequired $false | Out-Null
      }

    return "CN=$name,$OUdn"
  }

  function Ensure-GPO {
      param([Parameter(Mandatory)][string]$Name)
      $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
      if($gpo) {Write-Log "GPO '$Name' exists"; return $gpo}
      Invoke-Idempotent -Desc "Creating GPO '$Name'." -Action { $script:lastGpo = New-GPO -Name $Name}
      return (Get-GPO -Name $Name)
    }

  function Ensure-GPLink {
      param(
        [Parameter(Mandatory)][string]$GpoName,
        [Parameter(Mandatory)][string]$TargetOUdn, 
        [switch]$Enforced
      )
      $enf = if($Enforced) {[Microsoft.GroupPolicy.EnforceLink]::Yes} else {[Microsoft.GroupPolicy.EnforceLink]::No}
      Invoke-Idempotent -Desc "Linking GPO '$GpoName' to '$TargetOUdn'." -Action {
          New-GPLink -Name $GpoName -Target $TargetOUdn -Enforced $enf -LinkEnabled Yes | Out-Null

        }
    }

  function Ensure-GPRegistryValue {
    param(
      [Parameter(Mandatory)][string]$GpoName,
      [Parameter(Mandatory)][string]$Key,
      [Parameter(Mandatory)][string]$ValueName,
      [Parameter(Mandatory)]
      [ValidateSet('String','DWord','QWord','Binary','MultiString','ExpandString')]$Type,
      [Parameter(Mandatory)]$Value
    )
    Write-Log "Setting $Key\$ValueName in GPO '$GpoName'."
    try {
      Set-GPRegistryValue -Name $GpoName -Key $Key -ValueName $ValueName -Type $Type -Value $Value -ErrorAction Stop | Out-Null
    } catch {
      Write-Log "Failed to set $Key\$ValueName in '$GpoName': $($_.Exception.Message)"
   }
  }

  function Ensure-NetlogonFile {
        param(
          [Parameter(Mandatory)][string]$FileName,
          [Parameter(Mandatory)][string]$Content,
          [ValidateSet('Ascii','Utf8')][string]$Encoding='Utf8'
        )
        $share = "\\$CurrentFqdn\NETLOGON"
        $path = Join-Path $share $FileName 
        Invoke-Idempotent -Desc "Publishing $FileName to NETLOGON." -Action {
            if($Encoding -eq 'Ascii'){Set-Content -Path $path -Value $Content -Encoding Ascii -Force}
            else{ Set-Content -Path $path -Value $Content -Encoding UTF8 -Force}
          }
        return $path 
      }

#3. OU names, group names, user table 

$TopLevelOUs = @(
  "Executives",
  "Banking_Department",
  "Compliance_Department",
  "IT_Department",
  "Service_Accounts",
  "Bank_Users",
  "Bank_Computers"
)

$ComputerChildOUs = @("Workstations", "Servers")

$Groups = @(
  @{Name = "Managers";                    OU = "OU=Bank_Users,$BaseDN"},
  @{Name = "All_Tellers";                 OU = "OU=Bank_Users,$BaseDN"},
  @{Name = "All_Compliance";              OU = "OU=Bank_Users,$BaseDN"},
  @{Name = "All_Employees";               OU = "OU=Bank_Users,$BaseDN"},
  @{Name = "Local Workstation Admins";    OU = "OU=IT_Department,$BaseDN"}
)

$Users = @(
  # Executives
  @{ Sam="ceo.jameson";   Given="Avery";  Surname="Jameson";  OU="OU=Executives,$BaseDN";          Password="Welcome!23";  Groups=@("Managers","All_Employees") },
  @{ Sam="cfo.morales";   Given="Camila"; Surname="Morales";  OU="OU=Executives,$BaseDN";          Password="Welcome!23";  Groups=@("Managers","All_Employees") },
  @{ Sam="cio.thompson";  Given="Evan";   Surname="Thompson"; OU="OU=Executives,$BaseDN";          Password="Welcome!23";  Groups=@("Managers","All_Employees") },
  @{ Sam="exec.asst.lee"; Given="Riley";  Surname="Lee";      OU="OU=Executives,$BaseDN";          Password="Welcome!23";  Groups=@("All_Employees") },

  # Banking Dept
  @{ Sam="mgr.garcia";    Given="Miguel"; Surname="Garcia";   OU="OU=Banking_Department,$BaseDN";  Password="Summer2025!"; Groups=@("Managers","All_Employees") },
  @{ Sam="teller1.khan";  Given="Noor";   Surname="Khan";     OU="OU=Banking_Department,$BaseDN";  Password="Summer2025!"; Groups=@("All_Tellers","All_Employees") },
  @{ Sam="teller2.smith"; Given="Jordan"; Surname="Smith";    OU="OU=Banking_Department,$BaseDN";  Password="Summer2025!"; Groups=@("All_Tellers","All_Employees") },
  @{ Sam="teller3.ortiz"; Given="Elena";  Surname="Ortiz";    OU="OU=Banking_Department,$BaseDN";  Password="Summer2025!"; Groups=@("All_Tellers","All_Employees") },
  @{ Sam="teller4.park";  Given="Min";    Surname="Park";     OU="OU=Banking_Department,$BaseDN";  Password="Summer2025!"; Groups=@("All_Tellers","All_Employees") },
  @{ Sam="teller5.roy";   Given="Arjun";  Surname="Roy";      OU="OU=Banking_Department,$BaseDN";  Password="Summer2025!"; Groups=@("All_Tellers","All_Employees") },
  @{ Sam="analyst1.cho";  Given="Daniel"; Surname="Cho";      OU="OU=Banking_Department,$BaseDN";  Password="Summer2025!"; Groups=@("All_Employees") },
  @{ Sam="analyst2.mendes";Given="Lara";  Surname="Mendes";   OU="OU=Banking_Department,$BaseDN";  Password="Summer2025!"; Groups=@("All_Employees") },
  @{ Sam="analyst3.jiang";Given="Wei";    Surname="Jiang";    OU="OU=Banking_Department,$BaseDN";  Password="Summer2025!"; Groups=@("All_Employees") },
  @{ Sam="ops.clerk.bauer";Given="Nina";  Surname="Bauer";    OU="OU=Banking_Department,$BaseDN";  Password="Summer2025!"; Groups=@("All_Employees") },

  # Compliance Dept
  @{ Sam="comp.head.dupont"; Given="Marc";   Surname="Dupont";   OU="OU=Compliance_Department,$BaseDN"; Password="Welcome!23";  Groups=@("Managers","All_Compliance","All_Employees") },
  @{ Sam="comp.officer1.ng"; Given="Anh";    Surname="Nguyen";   OU="OU=Compliance_Department,$BaseDN"; Password="Welcome!23";  Groups=@("All_Compliance","All_Employees") },
  @{ Sam="comp.officer2.alv";Given="Pablo";  Surname="Alvarez";  OU="OU=Compliance_Department,$BaseDN"; Password="Welcome!23";  Groups=@("All_Compliance","All_Employees") },
  @{ Sam="comp.audit.wu";    Given="Grace";  Surname="Wu";       OU="OU=Compliance_Department,$BaseDN"; Password="Welcome!23";  Groups=@("All_Compliance","All_Employees") },

  # IT Dept
  @{ Sam="it.admin.will";  Given="Taylor"; Surname="Williams"; OU="OU=IT_Department,$BaseDN";      Password="Welcome!23";  Groups=@("All_Employees","Local Workstation Admins") },
  @{ Sam="it.help1.ali";   Given="Samir";  Surname="Ali";      OU="OU=IT_Department,$BaseDN";      Password="Welcome!23";  Groups=@("All_Employees","Local Workstation Admins") },
  @{ Sam="it.help2.patel"; Given="Priya";  Surname="Patel";    OU="OU=IT_Department,$BaseDN";      Password="Welcome!23";  Groups=@("All_Employees","Local Workstation Admins") },
  @{ Sam="soc.analyst1.hs";Given="Omar";   Surname="Hassan";   OU="OU=IT_Department,$BaseDN";      Password="Welcome!23";  Groups=@("All_Employees") }
)

$ServiceAccounts = @(
  @{ Sam="svc.sqlbank"; OU="OU=Service_Accounts,$BaseDN"; Password="Svc!2025" },
  @{ Sam="svc.webapp";  OU="OU=Service_Accounts,$BaseDN"; Password="Svc!2025" },
  @{ Sam="svc.backup";  OU="OU=Service_Accounts,$BaseDN"; Password="Svc!2025" }
)


# GPO names
$Gpo_IT_EnableRdp           = "IT - Enable RDP"
$Gpo_Banking_BrowserHome    = "Users - Browser Home (Banking)"

# Logon drive-map scripts (cmd + ps1)
$MapDrivesPs1 = @'
function In-Group($name) {
  $domain = $env:USERDOMAIN
  $pattern = [regex]::Escape("$domain\$name")
  return (whoami /groups) -imatch $pattern
}
# Clean up existing letters
'@ + @('F:','P:','E:') | ForEach-Object { "if (Test-Path '$_') { net use $_ /delete /y | Out-Null }" } | Out-String
$MapDrivesPs1 += @'
# Always map Finance for all employees
net use F: \\FS01\Finance /persistent:no | Out-Null
# PrivateBanking for tellers
if (In-Group 'All_Tellers') { net use P: \\FS01\PrivateBanking /persistent:no | Out-Null }
# Execs share for Managers
if (In-Group 'Managers')    { net use E: \\FS01\Execs /persistent:no | Out-Null }
'@

$MapDrivesCmd = @'
@echo off
REM Wrapper to run the PowerShell mapping script from NETLOGON
powershell.exe -ExecutionPolicy Bypass -NoLogo -NoProfile -File "\\%USERDNSDOMAIN%\NETLOGON\MapDrives.ps1"
'@



#4.Create OU's 

Write-Log "--Creating top-level OUs--"
foreach($Name in $TopLevelOUs) {
    [void](Ensure-OU -Name $Name -ParentDN $BaseDN)
  }

Write-Log "--Creating child OUs under Bank_Computers--"
$computersOUdn = "OU=Bank_Computers,$BaseDN"
foreach($child in $ComputerChildOUs) {
    [void](Ensure-OU -Name $child -ParentDN $computersOUdn)
  }

#5. Create groups 

Write-Log "[Sts] --Creating groups--"
foreach ($g in $Groups) {
    [void](Ensure-Group -Name $g.Name -OUdn $g.OU)
  }

#6 Create Users and memberships 

Write-Log "[Sts] --creating users--"
foreach ($u in $Users) {
    [void](Ensure-User -Sam $u.Sam -Given $u.Given -Surname $u.Surname -OUdn $u.OU -Password $u.Password -Groups $u.Groups)
  }

Write-Log "[Sts] --Creating service accounts--"
foreach ($s in $ServiceAccounts) {
    [void](Ensure-serviceAccount -Sam $s.Sam -OUdn $s.OU -Password $s.Password)
  }

#7. Privileged memberships 

Write-Log "[Sts] --Adding Privileged memberships--"
try{Add-ADGroupMember "Domain Admins" -Members "ceo.jameson","cio.thompson","it.admin.will" -ErrorAction Stop; Write-Log "Added domain admins."} catch {Write-Log "DA add failed: $_"}


#8. Domain password policy 

$EnablePasswordPolicy = $true
if($EnablePasswordPolicy) {
    Write-Log "[Sts] --Setting baseline password policy--"
    try {
        Set-ADDefaultDomainPasswordPolicy `
          -Identity $DomainInfo.DistinguishedName `
          -MinPasswordLength 8 `
          -ComplexityEnabled $true `
          -LockoutThreshold 0 `
          -LockoutDuration 00:00:00 `
          -LockoutObservationWindow 00:00:00
        Write-Log "Password policy set"

      } catch {
          Write-Log "Password policy update failed"
        }
  }else {
      Write-Log "[Sts] skipping"
    }




#9 GPOs and Logon Scripts 

$itOuDn = "OU=IT_Department,$BaseDN"
[void](Ensure-GPO -Name $Gpo_IT_EnableRdp)
Ensure-GPLink -GpoName $Gpo_IT_EnableRdp -TargetOUdn $itOuDn
Ensure-GPRegistryValue -GpoName $Gpo_IT_EnableRdp `
  -Key "HKLM\System\CurrentControlSet\Control\Terminal Server" -ValueName "fDenyTSConnect" -Type DWord -Value 0 


$bankingOuDn = "OU=Banking_Department,$BaseDN"
[void](Ensure-GPO -Name $Gpo_Banking_BrowserHome)
Ensure-GPLink -GpoName $Gpo_Banking_BrowserHome -TargetOUdn $bankingOuDn
# Restore on startup to URLs (4) and define 1 URL
Ensure-GPRegistryValue -GpoName $Gpo_Banking_BrowserHome `
  -Key "HKCU\Software\Policies\Microsoft\Edge" -ValueName "RestoreOnStartup" -Type DWord -Value 4
Ensure-GPRegistryValue -GpoName $Gpo_Banking_BrowserHome `
  -Key "HKCU\Software\Policies\Microsoft\Edge\RestoreOnStartupURLs" -ValueName "1" -Type String -Value "https://intranet.roguecapital.local/"

Write-Log "[Sts] GPOs & logon scripts configured."



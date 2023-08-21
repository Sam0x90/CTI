Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /c echo This is a sample line of purple text. > C:\temp\cmdfile.txt"
objShell.Run "cmd.exe /c ping -n 1 github.com"
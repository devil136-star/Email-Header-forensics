@echo off
REM Quick command to analyze phish_email_4.txt
echo Analyzing phish_email_4.txt...
echo.
python email_header_analyzer.py samples/phish_email_4.txt
pause


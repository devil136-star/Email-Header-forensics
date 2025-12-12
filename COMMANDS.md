# Quick Command Reference

## Analyze Specific Email Files

### Analyze phish_email_4.txt (Bank Security Phishing)
```bash
python email_header_analyzer.py samples/phish_email_4.txt
```

### Analyze phish_email_1.txt (PayPal Phishing)
```bash
python email_header_analyzer.py samples/phish_email_1.txt
```

### Analyze phish_email_2.txt (Microsoft Phishing)
```bash
python email_header_analyzer.py samples/phish_email_2.txt
```

### Analyze phish_email_3.txt (Amazon Phishing)
```bash
python email_header_analyzer.py samples/phish_email_3.txt
```

### Analyze phish_email_5.txt (Apple Phishing)
```bash
python email_header_analyzer.py samples/phish_email_5.txt
```

## Interactive Commands

### Main Interactive Tool
```bash
python main.py
```

### Interactive Email Analyzer (No Arguments)
```bash
python email_header_analyzer.py
```

### Interactive SOC Report Generator
```bash
python generate_soc_report.py
```

## Batch Analysis Commands

### Analyze All Sample Emails
```bash
python generate_soc_report.py
# Then choose option 2
```

### Quick Test All Samples
```bash
python test_all_samples.py
```

## Generate Reports

### Generate SOC L1 Report for All Samples
```bash
python generate_soc_report.py
# Choose option 2: Analyze all sample emails
```

### Generate Report for Single Email
```bash
python email_header_analyzer.py samples/phish_email_4.txt
# Then answer 'y' when asked to save
```

## Example Usage

### Quick Analysis of phish_email_4.txt
```bash
python email_header_analyzer.py samples/phish_email_4.txt
```

**Expected Output:**
- SPF: pass (but suspicious!)
- DKIM: fail ⚠️
- DMARC: fail ⚠️
- Risk Level: HIGH

This email shows a sophisticated phishing attempt where SPF passes but DKIM and DMARC fail, indicating the email was likely tampered with or spoofed.


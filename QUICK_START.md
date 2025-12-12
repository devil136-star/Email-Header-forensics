# Quick Start Guide

## Testing the Email Header Forensics Project

### 1. Analyze a Single Email Header

```bash
python email_header_analyzer.py samples/phish_email_1.txt
```

### 2. Generate Complete SOC L1 Report

```bash
python generate_soc_report.py
```

This generates:
- `SOC_L1_Email_Header_Analysis_Report.txt` - Full detailed report
- `analysis_results.json` - JSON data for programmatic access

### 3. Quick Test All Samples

```bash
python test_all_samples.py
```

Shows a quick summary of all 5 email samples with risk scores.

### 4. Example Programmatic Usage

```bash
python example_usage.py
```

Shows how to use the analyzer in your own Python scripts.

## Sample Email Files

All sample emails are in the `samples/` directory:

1. **phish_email_1.txt** - PayPal phishing (CRITICAL risk)
2. **phish_email_2.txt** - Microsoft phishing (LOW risk - deceptive!)
3. **phish_email_3.txt** - Amazon phishing (HIGH risk)
4. **phish_email_4.txt** - Bank phishing (HIGH risk)
5. **phish_email_5.txt** - Apple phishing (HIGH risk)

## Using in Your Own Code

```python
from email_header_analyzer import EmailHeaderAnalyzer

# Read email header
with open('samples/phish_email_1.txt', 'r') as f:
    header_text = f.read()

# Analyze
analyzer = EmailHeaderAnalyzer(header_text)
analysis = analyzer.analyze()

# Access results
print(f"SPF: {analysis['spf']['spf_result']}")
print(f"DKIM: {analysis['dkim']['dkim_result']}")
print(f"DMARC: {analysis['dmarc']['dmarc_result']}")

# Generate report
report = analyzer.generate_report()
print(report)
```

## Expected Output

When you run the tests, you should see:

- ✅ Individual email analysis reports
- ✅ SOC L1 comprehensive report
- ✅ Risk scoring (0-11 scale)
- ✅ SPF, DKIM, DMARC analysis
- ✅ Mail hops tracing

All scripts are working and tested! 🎉


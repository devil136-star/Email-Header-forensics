# Email Header Forensics Project

A comprehensive toolset for analyzing email headers to detect phishing attempts, designed for SOC Level 1 analysts.

## Project Overview

This project demonstrates how Security Operations Center (SOC) Level 1 analysts investigate phishing emails by analyzing email headers. The analysis focuses on four critical security indicators:

1. **SPF (Sender Policy Framework)** - Verifies sender IP authorization
2. **DKIM (DomainKeys Identified Mail)** - Validates email authenticity
3. **DMARC (Domain-based Message Authentication)** - Overall policy compliance
4. **Mail Hops** - Tracks email routing path

## Features

- Automated email header parsing and analysis
- SPF, DKIM, and DMARC verification
- Mail hop tracing and analysis
- Risk scoring and assessment
- Comprehensive SOC L1 analysis reports
- Support for multiple email samples

## Project Structure

```
Email Header forensics/
│
├── gui_app.py                  # Desktop GUI (Tkinter)
├── main.py                      # Main interactive tool (START HERE!)
├── email_header_analyzer.py     # Core email header analysis engine
├── generate_soc_report.py       # SOC L1 report generator
├── samples/                     # Sample phishing email headers
│   ├── phish_email_1.txt       # PayPal phishing sample
│   ├── phish_email_2.txt       # Microsoft phishing sample
│   ├── phish_email_3.txt       # Amazon phishing sample
│   ├── phish_email_4.txt       # Bank phishing sample
│   └── phish_email_5.txt       # Apple phishing sample
├── README.md                    # Project documentation
├── QUICK_START.md              # Quick reference guide
└── requirements.txt             # Python dependencies
```
Screenshots

<img width="1920" height="1080" alt="Screenshot 2025-12-12 194211" src="https://github.com/user-attachments/assets/0f89d2a0-ef98-4010-b19e-e70ae5b3f251" />

<img width="1920" height="1080" alt="Screenshot 2025-12-12 194023" src="https://github.com/user-attachments/assets/632a7b8c-3dea-4265-b504-3470395c5c8f" />

<img width="1920" height="1080" alt="Screenshot 2025-12-12 194006" src="https://github.com/user-attachments/assets/109096e9-0441-411d-bf05-c941a57fd620" />

<img width="1245" height="915" alt="Screenshot 2025-12-12 185951" src="https://github.com/user-attachments/assets/e39b6b7a-dc1f-4f5b-9422-54da93caea49" />

<img width="1920" height="1080" alt="Screenshot 2025-12-12 193936" src="https://github.com/user-attachments/assets/030ac82f-e12e-49ae-89ba-6d90d274bab9" />

<img width="1920" height="1080" alt="Screenshot 2025-12-12 194235" src="https://github.com/user-attachments/assets/3bac7874-e147-4f60-bcad-b75cc9b658aa" />



## Installation

### Prerequisites

- Python 3.6 or higher
- No external dependencies required (uses only standard library)

### Setup

1. Clone or download this repository
2. Navigate to the project directory
3. No additional installation required - uses Python standard library only

## Usage

### GUI Mode (Desktop)

Run the Tkinter GUI:

```bash
python gui_app.py
```

Features:
- Paste or load email headers from file
- One-click analysis (SPF/DKIM/DMARC + mail hops)
- Status bar with live progress and footer credit
- Export report (TXT/PDF text) and copyable IOCs
- Attribution shown in-app: Designed by Himanshu Kumar

### Interactive Mode (Terminal)

Run the main interactive tool (CLI menu):

```bash
python main.py
```

Menu options:
1. Analyze a single email header (interactive)
2. Analyze a single email header with SOC L1 report
3. Analyze all sample emails in the 'samples' folder
4. Exit

### Command Line Usage

#### Analyze a Single Email Header

**With file path:**
```bash
python email_header_analyzer.py samples/phish_email_1.txt
```

**Interactive mode (no arguments):**
```bash
python email_header_analyzer.py
```
Then choose to:
- Enter a file path, or
- Paste email header directly

#### Generate Complete SOC L1 Report

**Interactive mode:**
```bash
python generate_soc_report.py
```

Choose from:
1. Analyze a single email header (interactive)
2. Analyze all sample emails in the 'samples' folder
3. Analyze multiple email files

**Analyze all samples:**
The script will automatically analyze all email samples in the `samples/` directory and generate:
- Comprehensive report: `SOC_L1_Email_Header_Analysis_Report.txt`
- Analysis data as JSON: `analysis_results.json`

### Using the Analyzer Programmatically

```python
from email_header_analyzer import EmailHeaderAnalyzer

# Read email header
with open('samples/phish_email_1.txt', 'r') as f:
    header_text = f.read()

# Analyze
analyzer = EmailHeaderAnalyzer(header_text)
analysis = analyzer.analyze()

# Generate report
report = analyzer.generate_report()
print(report)
```

## Sample Email Headers

The project includes 5 realistic phishing email samples:

1. **phish_email_1.txt** - PayPal phishing (SPF Fail, No DKIM, DMARC Fail)
2. **phish_email_2.txt** - Microsoft phishing (SPF Softfail, DKIM Pass, DMARC Pass)
3. **phish_email_3.txt** - Amazon phishing (SPF None, No DKIM, DMARC None)
4. **phish_email_4.txt** - Bank phishing (SPF Pass, DKIM Fail, DMARC Fail)
5. **phish_email_5.txt** - Apple phishing (SPF Temperror, No DKIM, DMARC None)

Each sample demonstrates different combinations of security failures commonly seen in phishing attempts.

## Analysis Methodology

### SOC L1 Analysis Workflow

1. **Extract Basic Information**
   - From, To, Subject
   - Return-Path
   - Message-ID

2. **SPF Analysis**
   - Check if sender IP is authorized by domain
   - Results: pass, fail, softfail, none, temperror

3. **DKIM Analysis**
   - Verify email signature authenticity
   - Results: pass, fail, none

4. **DMARC Analysis**
   - Check policy compliance
   - Results: pass, fail, none

5. **Mail Hops Analysis**
   - Trace email routing path
   - Identify suspicious IPs or routing patterns

6. **Risk Assessment**
   - Calculate risk score (0-11)
   - Determine risk level
   - Identify risk factors

7. **Recommended Actions**
   - Quarantine/Block/Escalate based on risk level

## Key Indicators of Phishing

- **SPF Fail/Softfail/None** - Sender not authorized by domain
- **DKIM None/Fail** - Missing or invalid signature
- **DMARC Fail** - Policy violation
- **Multiple Suspicious Hops** - Unusual routing patterns
- **Mismatch Between From and Return-Path** - Domain spoofing
- **Suspicious IP Addresses** - Private IPs in public context

## Risk Scoring

The analyzer calculates a risk score (0-11) based on:

- SPF Fail: +3 points
- SPF Softfail/None/Temperror: +1 point
- DKIM None: +2 points
- DKIM Fail: +3 points
- DMARC Fail: +3 points
- DMARC None: +1 point
- Suspicious IPs: +2 points

**Risk Levels:**
- 7-11: CRITICAL - High probability of phishing
- 4-6: HIGH - Suspicious, likely phishing
- 2-3: MEDIUM - Requires investigation
- 0-1: LOW - But verify sender

## Report Output

The SOC L1 report includes:

- Executive summary
- Detailed analysis for each email sample
- SPF, DKIM, DMARC analysis with explanations
- Mail hops tracing
- Risk assessment and scoring
- Recommended actions for SOC L1 analysts
- Analysis methodology and best practices

## Skills Demonstrated

- **Phishing Investigation**: Identifying phishing indicators through header analysis
- **Mail Forensics**: Extracting and analyzing email routing and authentication data
- **Security Analysis**: SPF, DKIM, DMARC verification
- **SOC Operations**: Level 1 analyst workflow and reporting

## Best Practices

- Always check all three: SPF, DKIM, and DMARC
- A single pass doesn't guarantee legitimacy
- Multiple failures strongly indicate phishing
- Compare Return-Path with From header
- Investigate unusual routing patterns
- Use threat intelligence feeds for IP/domain reputation
- Document findings for future reference

## Limitations

- This tool analyzes email headers only, not email content
- Real-world analysis should include content inspection
- Some advanced evasion techniques may not be detected
- Always verify findings with additional security tools

## Contributing

This is an educational project demonstrating email header forensics. Feel free to extend it with:
- Additional analysis features
- Integration with threat intelligence APIs
- GUI interface
- Email content analysis
- Machine learning-based detection

## License

This project is provided for educational purposes.

## References

- [SPF Record Syntax](https://tools.ietf.org/html/rfc7208)
- [DKIM Signatures](https://tools.ietf.org/html/rfc6376)
- [DMARC Specification](https://tools.ietf.org/html/rfc7489)
- [PhishTank](https://www.phishtank.com/) - Phishing database

## Author & Credits

**Designed and Developed by:** Himanshu Kumar

This project demonstrates SOC L1 email header forensics analysis skills, including:
- Phishing investigation techniques
- Email header forensics
- SPF, DKIM, DMARC analysis
- SOC operations workflow

The GUI footer displays: "Designed by Himanshu Kumar"



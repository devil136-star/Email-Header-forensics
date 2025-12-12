# Interactive Usage Guide

## Quick Start - Interactive Mode

### Option 1: Use Main Interactive Tool (Recommended)

```bash
python main.py
```

This will show you a menu:
```
================================================================================
MAIN MENU
================================================================================
1. Analyze a single email header
2. Analyze a single email header (with SOC L1 report)
3. Analyze all sample emails in 'samples' folder
4. Exit
```

**Choose option 1 or 2** to analyze your own email header. You'll then be asked:
- Option 1: Enter file path
- Option 2: Paste email header directly

### Option 2: Use Individual Scripts

#### Analyze Single Email (Interactive)

```bash
python email_header_analyzer.py
```

When prompted:
1. Choose "1" to enter a file path, or
2. Choose "2" to paste email header directly

If you paste headers, type `END` on a new line when finished.

#### Generate SOC Report (Interactive)

```bash
python generate_soc_report.py
```

Choose from:
1. Analyze a single email header (interactive)
2. Analyze all sample emails
3. Analyze multiple email files

## Example: Analyzing Your Own Email Header

### Step 1: Run the tool
```bash
python main.py
```

### Step 2: Choose option 1 or 2

### Step 3: Provide email header

**Option A - File Path:**
```
Enter your choice (1, 2, or 3): 1
Enter the path to the email header file: my_email.txt
```

**Option B - Paste Directly:**
```
Enter your choice (1, 2, or 3): 2
Paste the email header below.
(Type 'END' on a new line when finished):
--------------------------------------------------------------------------------
Return-Path: <sender@example.com>
Received: from mail.example.com...
[Paste your full email header here]
END
```

### Step 4: View results

The tool will display:
- SPF analysis
- DKIM analysis
- DMARC analysis
- Mail hops
- Risk assessment

### Step 5: Save report (optional)

When asked if you want to save:
```
Do you want to save this report to a file? (y/n): y
Enter output filename (default: email_report.txt): my_analysis.txt
```

## Tips

1. **Getting Email Headers:**
   - In Gmail: Open email → Click three dots → "Show original"
   - In Outlook: Right-click email → "View source"
   - Copy all header lines (from Return-Path to Content-Type)

2. **Pasting Headers:**
   - Copy the entire header section
   - Paste into the tool
   - Type `END` on a new line
   - Press Enter

3. **File Format:**
   - Save email headers as plain text (.txt)
   - Include all header lines
   - No need to include email body

## Command Line (Non-Interactive)

You can still use command line arguments:

```bash
# Analyze specific file
python email_header_analyzer.py samples/phish_email_1.txt

# This bypasses interactive mode
```

## Troubleshooting

**Problem:** "No email header provided"
- **Solution:** Make sure you typed `END` after pasting headers, or check your file path

**Problem:** "File not found"
- **Solution:** Use full path or relative path from current directory

**Problem:** Analysis shows "Not Found" for SPF/DKIM/DMARC
- **Solution:** This is normal - it means the email doesn't have those headers. This can be a phishing indicator!


#!/usr/bin/env python3
"""
SOC L1 Email Header Forensics Report Generator
Generates comprehensive analysis report for SOC Level 1 analysts
"""

import os
import json
from datetime import datetime
from email_header_analyzer import EmailHeaderAnalyzer


def analyze_all_samples():
    """Analyze all phishing email samples"""
    samples_dir = "samples"
    results = []
    
    if not os.path.exists(samples_dir):
        print(f"Error: {samples_dir} directory not found!")
        return None
    
    sample_files = sorted([f for f in os.listdir(samples_dir) if f.endswith('.txt')])
    
    for sample_file in sample_files:
        file_path = os.path.join(samples_dir, sample_file)
        print(f"Analyzing {sample_file}...")
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                header_text = f.read()
            
            analyzer = EmailHeaderAnalyzer(header_text)
            analysis = analyzer.analyze()
            analysis['sample_file'] = sample_file
            results.append(analysis)
        except Exception as e:
            print(f"Error analyzing {sample_file}: {e}")
    
    return results


def generate_soc_report(analyses):
    """Generate comprehensive SOC L1 report"""
    report = []
    
    report.append("=" * 100)
    report.append("SOC LEVEL 1 - EMAIL HEADER FORENSICS ANALYSIS REPORT")
    report.append("How SOC L1 Analyzes Email Headers")
    report.append("=" * 100)
    report.append(f"\nReport Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"Total Samples Analyzed: {len(analyses)}")
    report.append("\n" + "=" * 100)
    
    # Executive Summary
    report.append("\nEXECUTIVE SUMMARY")
    report.append("-" * 100)
    report.append("\nThis report demonstrates how SOC Level 1 analysts investigate phishing emails")
    report.append("by analyzing email headers. The analysis focuses on four critical security")
    report.append("indicators:")
    report.append("\n1. SPF (Sender Policy Framework) - Verifies sender IP authorization")
    report.append("2. DKIM (DomainKeys Identified Mail) - Validates email authenticity")
    report.append("3. DMARC (Domain-based Message Authentication) - Overall policy compliance")
    report.append("4. Mail Hops - Tracks email routing path")
    
    # Analysis of each email
    for idx, analysis in enumerate(analyses, 1):
        report.append("\n" + "=" * 100)
        report.append(f"SAMPLE {idx}: {analysis['sample_file']}")
        report.append("=" * 100)
        
        # Basic Info
        basic = analysis['basic_info']
        report.append("\n[1] BASIC EMAIL INFORMATION")
        report.append("-" * 100)
        report.append(f"From: {basic['from']}")
        report.append(f"To: {basic['to']}")
        report.append(f"Subject: {basic['subject']}")
        report.append(f"Return-Path: {basic['return_path']}")
        report.append(f"Message-ID: {basic['message_id']}")
        
        # SPF Analysis
        spf = analysis['spf']
        report.append("\n[2] SPF (Sender Policy Framework) ANALYSIS")
        report.append("-" * 100)
        spf_result = spf['spf_result'] or 'Not Found'
        report.append(f"SPF Result: {spf_result.upper()}")
        
        if spf_result == 'fail':
            report.append("  ⚠️  ALERT: SPF FAIL - Email failed SPF verification!")
            report.append("     This indicates the sending IP is not authorized by the domain.")
            report.append("     HIGH INDICATOR OF PHISHING ATTEMPT.")
        elif spf_result == 'softfail':
            report.append("  ⚠️  WARNING: SPF SOFTFAIL - Domain does not clearly authorize sender.")
            report.append("     Suspicious but not definitive. Requires further investigation.")
        elif spf_result == 'none':
            report.append("  ⚠️  WARNING: No SPF record found for this domain.")
            report.append("     Legitimate domains typically have SPF records configured.")
        elif spf_result == 'temperror':
            report.append("  ⚠️  WARNING: SPF TEMPERROR - Temporary error during SPF check.")
            report.append("     Could indicate DNS issues or evasion attempt.")
        elif spf_result == 'pass':
            report.append("  ✓ SPF PASS - Sender IP is authorized by domain.")
            report.append("     However, SPF pass alone does not guarantee legitimacy.")
        
        if spf['spf_smtp_mailfrom']:
            report.append(f"SMTP MailFrom: {spf['spf_smtp_mailfrom']}")
        
        # DKIM Analysis
        dkim = analysis['dkim']
        report.append("\n[3] DKIM (DomainKeys Identified Mail) ANALYSIS")
        report.append("-" * 100)
        dkim_result = dkim['dkim_result'] or 'Not Found'
        report.append(f"DKIM Result: {dkim_result.upper()}")
        
        if dkim_result == 'none':
            report.append("  ⚠️  ALERT: No DKIM signature found!")
            report.append("     Legitimate emails from major services typically have DKIM signatures.")
            report.append("     HIGH INDICATOR OF PHISHING ATTEMPT.")
        elif dkim_result == 'fail':
            report.append("  ⚠️  ALERT: DKIM FAIL - Signature verification failed!")
            report.append("     Email may have been tampered with or signature is invalid.")
            report.append("     HIGH INDICATOR OF PHISHING ATTEMPT.")
        elif dkim_result == 'pass':
            report.append("  ✓ DKIM PASS - Signature verified successfully.")
            report.append("     Email appears authentic from DKIM perspective.")
        
        if dkim['dkim_domain']:
            report.append(f"DKIM Domain: {dkim['dkim_domain']}")
        if dkim['dkim_selector']:
            report.append(f"DKIM Selector: {dkim['dkim_selector']}")
        
        # DMARC Analysis
        dmarc = analysis['dmarc']
        report.append("\n[4] DMARC (Domain-based Message Authentication) ANALYSIS")
        report.append("-" * 100)
        dmarc_result = dmarc['dmarc_result'] or 'Not Found'
        report.append(f"DMARC Result: {dmarc_result.upper()}")
        
        if dmarc_result == 'fail':
            report.append("  ⚠️  ALERT: DMARC FAIL - Email failed DMARC policy check!")
            report.append("     This is a STRONG INDICATOR OF PHISHING ATTEMPT.")
            report.append("     Email should be quarantined or rejected per policy.")
        elif dmarc_result == 'none':
            report.append("  ⚠️  WARNING: No DMARC policy found for this domain.")
            report.append("     Legitimate domains often have DMARC policies configured.")
        elif dmarc_result == 'pass':
            report.append("  ✓ DMARC PASS - Email passed DMARC policy check.")
            report.append("     Email appears compliant with domain's authentication policy.")
        
        if dmarc['dmarc_policy']:
            report.append(f"DMARC Policy: {dmarc['dmarc_policy']}")
        
        # Mail Hops Analysis
        hops = analysis['mail_hops']
        report.append("\n[5] MAIL HOPS ANALYSIS")
        report.append("-" * 100)
        report.append(f"Total Hops: {len(hops)}")
        
        if hops:
            report.append("\nEmail Routing Path (from recipient to sender):")
            for i, hop in enumerate(hops, 1):
                report.append(f"\n  Hop {i}:")
                report.append(f"    From: {hop['from'] or 'N/A'}")
                report.append(f"    By: {hop['by'] or 'N/A'}")
                report.append(f"    IP Address: {hop['ip_address'] or 'N/A'}")
                report.append(f"    With: {hop['with'] or 'N/A'}")
                report.append(f"    Timestamp: {hop['timestamp'] or 'N/A'}")
            
            # Analyze hop patterns
            report.append("\n  HOP ANALYSIS:")
            if len(hops) > 2:
                report.append("  ⚠️  WARNING: Multiple hops detected. May indicate relay/proxy usage.")
            
            # Check for suspicious IPs
            suspicious_ips = []
            for hop in hops:
                ip = hop.get('ip_address')
                if ip:
                    # Check for private IPs in public context
                    if ip.startswith(('192.168.', '10.', '172.16.')):
                        suspicious_ips.append(ip)
            
            if suspicious_ips:
                report.append(f"  ⚠️  ALERT: Suspicious IP addresses detected: {', '.join(suspicious_ips)}")
                report.append("     Private IPs in mail headers may indicate internal relay abuse.")
        
        # Risk Assessment
        report.append("\n[6] RISK ASSESSMENT")
        report.append("-" * 100)
        risk_score = 0
        risk_factors = []
        
        if spf_result == 'fail':
            risk_score += 3
            risk_factors.append("SPF Fail")
        elif spf_result in ['softfail', 'none', 'temperror']:
            risk_score += 1
            risk_factors.append(f"SPF {spf_result}")
        
        if dkim_result == 'none':
            risk_score += 2
            risk_factors.append("No DKIM")
        elif dkim_result == 'fail':
            risk_score += 3
            risk_factors.append("DKIM Fail")
        
        if dmarc_result == 'fail':
            risk_score += 3
            risk_factors.append("DMARC Fail")
        elif dmarc_result == 'none':
            risk_score += 1
            risk_factors.append("No DMARC")
        
        if suspicious_ips:
            risk_score += 2
            risk_factors.append("Suspicious IPs")
        
        if risk_score >= 7:
            risk_level = "CRITICAL - HIGH PROBABILITY OF PHISHING"
        elif risk_score >= 4:
            risk_level = "HIGH - SUSPICIOUS, LIKELY PHISHING"
        elif risk_score >= 2:
            risk_level = "MEDIUM - REQUIRES INVESTIGATION"
        else:
            risk_level = "LOW - BUT VERIFY SENDER"
        
        report.append(f"Risk Score: {risk_score}/11")
        report.append(f"Risk Level: {risk_level}")
        report.append(f"Risk Factors: {', '.join(risk_factors) if risk_factors else 'None identified'}")
        
        # SOC L1 Action Items
        report.append("\n[7] SOC L1 RECOMMENDED ACTIONS")
        report.append("-" * 100)
        if risk_score >= 7:
            report.append("  ✓ Quarantine email immediately")
            report.append("  ✓ Block sender domain/IP")
            report.append("  ✓ Escalate to SOC L2 for further investigation")
            report.append("  ✓ Check for similar emails in organization")
            report.append("  ✓ Update threat intelligence feeds")
        elif risk_score >= 4:
            report.append("  ✓ Flag email as suspicious")
            report.append("  ✓ Review email content for phishing indicators")
            report.append("  ✓ Check sender reputation")
            report.append("  ✓ Consider blocking if pattern matches known threats")
        else:
            report.append("  ✓ Review email content")
            report.append("  ✓ Verify sender legitimacy through other means")
            report.append("  ✓ Monitor for similar patterns")
    
    # Summary and Best Practices
    report.append("\n" + "=" * 100)
    report.append("SOC L1 ANALYSIS METHODOLOGY SUMMARY")
    report.append("=" * 100)
    
    report.append("\nKEY INDICATORS OF PHISHING:")
    report.append("1. SPF Fail/Softfail/None - Sender not authorized")
    report.append("2. DKIM None/Fail - Missing or invalid signature")
    report.append("3. DMARC Fail - Policy violation")
    report.append("4. Multiple suspicious hops - Unusual routing")
    report.append("5. Mismatch between From domain and Return-Path")
    report.append("6. Suspicious IP addresses in routing")
    
    report.append("\nANALYSIS WORKFLOW:")
    report.append("Step 1: Extract basic email information (From, To, Subject)")
    report.append("Step 2: Check SPF record - Is sender IP authorized?")
    report.append("Step 3: Verify DKIM signature - Is email authentic?")
    report.append("Step 4: Check DMARC policy - Does email comply?")
    report.append("Step 5: Analyze mail hops - Trace email path")
    report.append("Step 6: Calculate risk score based on findings")
    report.append("Step 7: Take appropriate action (quarantine/block/escalate)")
    
    report.append("\nBEST PRACTICES:")
    report.append("- Always check all three: SPF, DKIM, and DMARC")
    report.append("- A single pass doesn't guarantee legitimacy")
    report.append("- Multiple failures strongly indicate phishing")
    report.append("- Compare Return-Path with From header")
    report.append("- Investigate unusual routing patterns")
    report.append("- Use threat intelligence feeds for IP/domain reputation")
    report.append("- Document findings for future reference")
    
    report.append("\n" + "=" * 100)
    report.append("END OF REPORT")
    report.append("=" * 100)
    
    return "\n".join(report)


def analyze_single_email_interactive():
    """Analyze a single email provided by user"""
    from email_header_analyzer import EmailHeaderAnalyzer
    
    print("\n" + "=" * 80)
    print("SINGLE EMAIL ANALYSIS")
    print("=" * 80)
    print()
    print("How would you like to provide the email header?")
    print("1. Enter file path")
    print("2. Paste email header directly")
    print()
    
    choice = input("Enter your choice (1 or 2): ").strip()
    print()
    
    header_text = None
    
    if choice == "1":
        file_path = input("Enter the path to the email header file: ").strip()
        if not file_path:
            print("Error: No file path provided.")
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                header_text = f.read()
            print(f"\nEmail header loaded from: {file_path}")
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            return None
        except Exception as e:
            print(f"Error reading file: {e}")
            return None
    
    elif choice == "2":
        print("Paste the email header below.")
        print("(Press Enter after pasting, then type 'END' on a new line to finish):")
        print("-" * 80)
        
        header_lines = []
        while True:
            try:
                line = input()
                if line.strip().upper() == 'END':
                    break
                header_lines.append(line)
            except EOFError:
                break
        
        if not header_lines:
            print("Error: No email header provided.")
            return None
        
        header_text = '\n'.join(header_lines)
        print("\nEmail header received.")
    
    else:
        print("Invalid choice.")
        return None
    
    # Analyze the email
    print("\nAnalyzing email header...")
    analyzer = EmailHeaderAnalyzer(header_text)
    analysis = analyzer.analyze()
    
    return [analysis]


def main():
    """Main function to generate SOC report"""
    print("=" * 80)
    print("EMAIL HEADER FORENSICS - SOC L1 REPORT GENERATOR")
    print("=" * 80)
    print()
    print("What would you like to do?")
    print("1. Analyze a single email header (interactive)")
    print("2. Analyze all sample emails in the 'samples' folder")
    print("3. Analyze multiple email files")
    print()
    
    choice = input("Enter your choice (1, 2, or 3): ").strip()
    print()
    
    analyses = None
    
    if choice == "1":
        # Single email analysis
        analyses = analyze_single_email_interactive()
        if not analyses:
            return
        
        # Generate report for single email
        print("\nGenerating SOC L1 report...")
        report = generate_soc_report(analyses)
        
        # Display report
        print("\n" + "=" * 80)
        print("ANALYSIS REPORT")
        print("=" * 80)
        print(report)
        
        # Ask if user wants to save
        save = input("\nDo you want to save this report to a file? (y/n): ").strip().lower()
        if save == 'y':
            output_file = input("Enter output filename (default: email_analysis_report.txt): ").strip()
            if not output_file:
                output_file = "email_analysis_report.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"Report saved to: {output_file}")
            
            # Also save JSON
            json_file = output_file.replace('.txt', '.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(analyses, f, indent=2, default=str)
            print(f"Analysis data saved to: {json_file}")
    
    elif choice == "2":
        # Analyze all samples
        print("Analyzing all sample emails in the 'samples' folder...")
        analyses = analyze_all_samples()
        
        if not analyses:
            print("No samples found or error occurred during analysis.")
            return
        
        # Generate report
        print("\nGenerating SOC L1 report...")
        report = generate_soc_report(analyses)
        
        # Save report
        output_file = "SOC_L1_Email_Header_Analysis_Report.txt"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\nReport generated successfully: {output_file}")
        print("\nReport Preview:")
        print("-" * 60)
        print(report[:2000] + "\n... (full report saved to file)")
        
        # Also save JSON for programmatic access
        json_file = "analysis_results.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(analyses, f, indent=2, default=str)
        print(f"Analysis data saved to: {json_file}")
    
    elif choice == "3":
        # Multiple files
        print("Enter file paths (one per line). Type 'DONE' when finished:")
        file_paths = []
        while True:
            path = input().strip()
            if path.upper() == 'DONE':
                break
            if path:
                file_paths.append(path)
        
        if not file_paths:
            print("No files provided.")
            return
        
        print(f"\nAnalyzing {len(file_paths)} email(s)...")
        analyses = []
        for file_path in file_paths:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    header_text = f.read()
                from email_header_analyzer import EmailHeaderAnalyzer
                analyzer = EmailHeaderAnalyzer(header_text)
                analysis = analyzer.analyze()
                analysis['sample_file'] = os.path.basename(file_path)
                analyses.append(analysis)
                print(f"  ✓ Analyzed: {file_path}")
            except Exception as e:
                print(f"  ✗ Error analyzing {file_path}: {e}")
        
        if not analyses:
            print("No emails were successfully analyzed.")
            return
        
        # Generate report
        print("\nGenerating SOC L1 report...")
        report = generate_soc_report(analyses)
        
        # Save report
        output_file = input("\nEnter output filename (default: multi_email_report.txt): ").strip()
        if not output_file:
            output_file = "multi_email_report.txt"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        print(f"\nReport generated successfully: {output_file}")
        print("\nReport Preview:")
        print("-" * 60)
        print(report[:2000] + "\n... (full report saved to file)")
        
        # Also save JSON
        json_file = output_file.replace('.txt', '.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(analyses, f, indent=2, default=str)
        print(f"Analysis data saved to: {json_file}")
    
    else:
        print("Invalid choice. Please run the script again and select 1, 2, or 3.")


if __name__ == "__main__":
    main()


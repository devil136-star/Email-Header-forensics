#!/usr/bin/env python3
"""
Main Interactive Email Header Forensics Tool
Provides a user-friendly interface for analyzing email headers
"""

import os
import sys
from email_header_analyzer import EmailHeaderAnalyzer
from generate_soc_report import generate_soc_report, analyze_all_samples


def get_email_header():
    """Get email header from user"""
    print("\n" + "=" * 80)
    print("HOW WOULD YOU LIKE TO PROVIDE THE EMAIL HEADER?")
    print("=" * 80)
    print("1. Enter file path")
    print("2. Paste email header directly")
    print("3. Go back to main menu")
    print()
    
    choice = input("Enter your choice (1, 2, or 3): ").strip()
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
            print(f"\n✓ Email header loaded from: {file_path}")
        except FileNotFoundError:
            print(f"✗ Error: File '{file_path}' not found.")
            return None
        except Exception as e:
            print(f"✗ Error reading file: {e}")
            return None
    
    elif choice == "2":
        print("Paste the email header below.")
        print("(Type 'END' on a new line when finished):")
        print("-" * 80)
        
        header_lines = []
        while True:
            try:
                line = input()
                if line.strip().upper() == 'END':
                    break
                header_lines.append(line)
            except (EOFError, KeyboardInterrupt):
                print("\nInput finished.")
                break
        
        if not header_lines:
            print("✗ Error: No email header provided.")
            return None
        
        header_text = '\n'.join(header_lines)
        print("\n✓ Email header received.")
    
    elif choice == "3":
        return None
    
    else:
        print("✗ Invalid choice.")
        return None
    
    return header_text


def analyze_single_email():
    """Analyze a single email header"""
    print("\n" + "=" * 80)
    print("SINGLE EMAIL HEADER ANALYSIS")
    print("=" * 80)
    
    header_text = get_email_header()
    if not header_text:
        return
    
    print("\nAnalyzing email header...")
    print("-" * 80)
    
    try:
        analyzer = EmailHeaderAnalyzer(header_text)
        report = analyzer.generate_report()
        
        print("\n" + report)
        
        # Ask if user wants to save
        save = input("\n" + "=" * 80 + "\nDo you want to save this report to a file? (y/n): ").strip().lower()
        if save == 'y':
            output_file = input("Enter output filename (default: email_report.txt): ").strip()
            if not output_file:
                output_file = "email_report.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n✓ Report saved to: {output_file}")
    
    except Exception as e:
        print(f"\n✗ Error analyzing email: {e}")


def analyze_with_soc_report():
    """Analyze email and generate SOC L1 report"""
    print("\n" + "=" * 80)
    print("SOC L1 ANALYSIS REPORT")
    print("=" * 80)
    
    header_text = get_email_header()
    if not header_text:
        return
    
    print("\nAnalyzing email header...")
    
    try:
        analyzer = EmailHeaderAnalyzer(header_text)
        analysis = analyzer.analyze()
        analysis['sample_file'] = "user_provided_email"
        
        print("\nGenerating SOC L1 report...")
        report = generate_soc_report([analysis])
        
        print("\n" + report)
        
        # Ask if user wants to save
        save = input("\n" + "=" * 80 + "\nDo you want to save this report to a file? (y/n): ").strip().lower()
        if save == 'y':
            output_file = input("Enter output filename (default: soc_report.txt): ").strip()
            if not output_file:
                output_file = "soc_report.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"\n✓ Report saved to: {output_file}")
    
    except Exception as e:
        print(f"\n✗ Error analyzing email: {e}")


def analyze_all_samples_menu():
    """Analyze all sample emails"""
    print("\n" + "=" * 80)
    print("ANALYZING ALL SAMPLE EMAILS")
    print("=" * 80)
    
    print("\nAnalyzing all sample emails in the 'samples' folder...")
    analyses = analyze_all_samples()
    
    if not analyses:
        print("✗ No samples found or error occurred during analysis.")
        return
    
    print(f"\n✓ Successfully analyzed {len(analyses)} email(s)")
    print("\nGenerating SOC L1 report...")
    report = generate_soc_report(analyses)
    
    # Save report
    output_file = "SOC_L1_Email_Header_Analysis_Report.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n✓ Report generated successfully: {output_file}")
    print("\nReport Preview:")
    print("-" * 60)
    print(report[:1500] + "\n... (full report saved to file)")
    
    # Also save JSON
    import json
    json_file = "analysis_results.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(analyses, f, indent=2, default=str)
    print(f"✓ Analysis data saved to: {json_file}")


def main():
    """Main interactive menu"""
    print("=" * 80)
    print("EMAIL HEADER FORENSICS TOOL")
    print("SOC L1 Email Header Analysis")
    print("=" * 80)
    
    while True:
        print("\n" + "=" * 80)
        print("MAIN MENU")
        print("=" * 80)
        print("1. Analyze a single email header")
        print("2. Analyze a single email header (with SOC L1 report)")
        print("3. Analyze all sample emails in 'samples' folder")
        print("4. Exit")
        print()
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            analyze_single_email()
        elif choice == "2":
            analyze_with_soc_report()
        elif choice == "3":
            analyze_all_samples_menu()
        elif choice == "4":
            print("\nThank you for using Email Header Forensics Tool!")
            print("=" * 80)
            break
        else:
            print("\n✗ Invalid choice. Please select 1-4.")
        
        if choice != "4":
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user.")
        sys.exit(0)


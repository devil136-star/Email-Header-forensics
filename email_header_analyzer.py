#!/usr/bin/env python3
"""
Email Header Forensics Analyzer
Extracts SPF, DKIM, DMARC, and Mail Hops from email headers
"""

import re
import json
from typing import Dict, List, Optional
from datetime import datetime


class EmailHeaderAnalyzer:
    """Analyzes email headers for security and routing information"""
    
    def __init__(self, header_text: str):
        self.header_text = header_text
        self.headers = self._parse_headers()
    
    def _parse_headers(self) -> Dict[str, List[str]]:
        """Parse email headers into a dictionary"""
        headers = {}
        current_key = None
        current_value = []
        
        for line in self.header_text.split('\n'):
            # Check if line starts a new header (starts with a word followed by colon)
            if ':' in line and not line[0].isspace():
                # Save previous header if exists
                if current_key:
                    headers[current_key] = ' '.join(current_value)
                
                # Start new header
                parts = line.split(':', 1)
                current_key = parts[0].strip()
                current_value = [parts[1].strip()] if len(parts) > 1 else ['']
            elif current_key and line.strip():
                # Continuation of previous header (folded header)
                current_value.append(line.strip())
            elif not line.strip() and current_key:
                # Empty line might indicate end of headers
                if current_key:
                    headers[current_key] = ' '.join(current_value)
                    current_key = None
                    current_value = []
        
        # Save last header
        if current_key:
            headers[current_key] = ' '.join(current_value)
        
        return headers
    
    def extract_spf(self) -> Dict[str, Optional[str]]:
        """Extract SPF (Sender Policy Framework) information"""
        spf_info = {
            'received_spf': None,
            'authentication_results_spf': None,
            'spf_result': None,
            'spf_smtp_mailfrom': None
        }
        
        # Check Received-SPF header
        for key, value in self.headers.items():
            if 'received-spf' in key.lower():
                spf_info['received_spf'] = value
                # Extract result (pass, fail, softfail, neutral, etc.)
                result_match = re.search(r'\b(pass|fail|softfail|neutral|none|temperror|permerror)\b', value, re.IGNORECASE)
                if result_match:
                    spf_info['spf_result'] = result_match.group(1).lower()
            
            # Check Authentication-Results for SPF
            if 'authentication-results' in key.lower() and 'spf' in value.lower():
                spf_info['authentication_results_spf'] = value
                result_match = re.search(r'spf=(\w+)', value, re.IGNORECASE)
                if result_match:
                    spf_info['spf_result'] = result_match.group(1).lower()
            
            # Check for SMTP mailfrom
            if 'smtp.mailfrom' in value.lower():
                mailfrom_match = re.search(r'smtp\.mailfrom=([^\s;]+)', value, re.IGNORECASE)
                if mailfrom_match:
                    spf_info['spf_smtp_mailfrom'] = mailfrom_match.group(1)
        
        return spf_info
    
    def extract_dkim(self) -> Dict[str, Optional[str]]:
        """Extract DKIM (DomainKeys Identified Mail) information"""
        dkim_info = {
            'dkim_signature': None,
            'authentication_results_dkim': None,
            'dkim_result': None,
            'dkim_domain': None,
            'dkim_selector': None
        }
        
        # Check DKIM-Signature header
        for key, value in self.headers.items():
            if 'dkim-signature' in key.lower():
                dkim_info['dkim_signature'] = value
                # Extract domain
                domain_match = re.search(r'd=([^\s;]+)', value, re.IGNORECASE)
                if domain_match:
                    dkim_info['dkim_domain'] = domain_match.group(1)
                # Extract selector
                selector_match = re.search(r's=([^\s;]+)', value, re.IGNORECASE)
                if selector_match:
                    dkim_info['dkim_selector'] = selector_match.group(1)
            
            # Check Authentication-Results for DKIM
            if 'authentication-results' in key.lower() and 'dkim' in value.lower():
                dkim_info['authentication_results_dkim'] = value
                result_match = re.search(r'dkim=(\w+)', value, re.IGNORECASE)
                if result_match:
                    dkim_info['dkim_result'] = result_match.group(1).lower()
        
        return dkim_info
    
    def extract_dmarc(self) -> Dict[str, Optional[str]]:
        """Extract DMARC (Domain-based Message Authentication) information"""
        dmarc_info = {
            'authentication_results_dmarc': None,
            'dmarc_result': None,
            'dmarc_policy': None,
            'dmarc_domain': None
        }
        
        # Check Authentication-Results for DMARC
        for key, value in self.headers.items():
            if 'authentication-results' in key.lower() and 'dmarc' in value.lower():
                dmarc_info['authentication_results_dmarc'] = value
                # Extract DMARC result
                result_match = re.search(r'dmarc=(\w+)', value, re.IGNORECASE)
                if result_match:
                    dmarc_info['dmarc_result'] = result_match.group(1).lower()
                
                # Extract policy
                policy_match = re.search(r'policy=([^\s;]+)', value, re.IGNORECASE)
                if policy_match:
                    dmarc_info['dmarc_policy'] = policy_match.group(1)
                
                # Extract domain
                domain_match = re.search(r'dmarc=(\w+)\s+\(([^\)]+)\)', value, re.IGNORECASE)
                if domain_match:
                    dmarc_info['dmarc_domain'] = domain_match.group(2).split()[0] if len(domain_match.groups()) > 1 else None
        
        return dmarc_info
    
    def extract_mail_hops(self) -> List[Dict[str, Optional[str]]]:
        """Extract mail hops from Received headers"""
        hops = []
        received_headers = []
        
        # Collect all Received headers
        for key, value in self.headers.items():
            if key.lower().startswith('received'):
                received_headers.append(value)
        
        # Process Received headers (they appear in reverse chronological order)
        for received in received_headers:
            hop = {
                'from': None,
                'by': None,
                'with': None,
                'id': None,
                'timestamp': None,
                'ip_address': None
            }
            
            # Extract "from" information
            from_match = re.search(r'from\s+([^\s(]+)', received, re.IGNORECASE)
            if from_match:
                hop['from'] = from_match.group(1).strip('[]')
            
            # Extract "by" information
            by_match = re.search(r'by\s+([^\s(]+)', received, re.IGNORECASE)
            if by_match:
                hop['by'] = by_match.group(1).strip('[]')
            
            # Extract "with" information
            with_match = re.search(r'with\s+([^\s(]+)', received, re.IGNORECASE)
            if with_match:
                hop['with'] = with_match.group(1)
            
            # Extract ID
            id_match = re.search(r'id\s+([^\s;]+)', received, re.IGNORECASE)
            if id_match:
                hop['id'] = id_match.group(1)
            
            # Extract timestamp
            timestamp_match = re.search(r';\s*([A-Za-z]{3},\s*\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}:\d{2})', received)
            if timestamp_match:
                hop['timestamp'] = timestamp_match.group(1)
            
            # Extract IP address
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received)
            if ip_match:
                hop['ip_address'] = ip_match.group(1)
            
            if hop['from'] or hop['by']:
                hops.append(hop)
        
        return hops
    
    def analyze(self) -> Dict:
        """Perform complete analysis of email headers"""
        return {
            'spf': self.extract_spf(),
            'dkim': self.extract_dkim(),
            'dmarc': self.extract_dmarc(),
            'mail_hops': self.extract_mail_hops(),
            'basic_info': {
                'from': self.headers.get('From', 'N/A'),
                'to': self.headers.get('To', 'N/A'),
                'subject': self.headers.get('Subject', 'N/A'),
                'date': self.headers.get('Date', 'N/A'),
                'message_id': self.headers.get('Message-ID', 'N/A'),
                'return_path': self.headers.get('Return-Path', 'N/A')
            }
        }
    
    def generate_report(self) -> str:
        """Generate a human-readable report"""
        analysis = self.analyze()
        report = []
        
        report.append("=" * 80)
        report.append("EMAIL HEADER FORENSICS ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"\nAnalysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("\n" + "-" * 80)
        report.append("BASIC EMAIL INFORMATION")
        report.append("-" * 80)
        
        basic = analysis['basic_info']
        report.append(f"From: {basic['from']}")
        report.append(f"To: {basic['to']}")
        report.append(f"Subject: {basic['subject']}")
        report.append(f"Date: {basic['date']}")
        report.append(f"Message-ID: {basic['message_id']}")
        report.append(f"Return-Path: {basic['return_path']}")
        
        report.append("\n" + "-" * 80)
        report.append("SPF (Sender Policy Framework) ANALYSIS")
        report.append("-" * 80)
        spf = analysis['spf']
        report.append(f"SPF Result: {spf['spf_result'] or 'Not Found'}")
        report.append(f"SMTP MailFrom: {spf['spf_smtp_mailfrom'] or 'Not Found'}")
        if spf['received_spf']:
            report.append(f"Received-SPF: {spf['received_spf']}")
        if spf['authentication_results_spf']:
            report.append(f"Authentication-Results (SPF): {spf['authentication_results_spf']}")
        
        report.append("\n" + "-" * 80)
        report.append("DKIM (DomainKeys Identified Mail) ANALYSIS")
        report.append("-" * 80)
        dkim = analysis['dkim']
        report.append(f"DKIM Result: {dkim['dkim_result'] or 'Not Found'}")
        report.append(f"DKIM Domain: {dkim['dkim_domain'] or 'Not Found'}")
        report.append(f"DKIM Selector: {dkim['dkim_selector'] or 'Not Found'}")
        if dkim['dkim_signature']:
            report.append(f"DKIM Signature: {dkim['dkim_signature'][:100]}...")
        if dkim['authentication_results_dkim']:
            report.append(f"Authentication-Results (DKIM): {dkim['authentication_results_dkim']}")
        
        report.append("\n" + "-" * 80)
        report.append("DMARC (Domain-based Message Authentication) ANALYSIS")
        report.append("-" * 80)
        dmarc = analysis['dmarc']
        report.append(f"DMARC Result: {dmarc['dmarc_result'] or 'Not Found'}")
        report.append(f"DMARC Policy: {dmarc['dmarc_policy'] or 'Not Found'}")
        report.append(f"DMARC Domain: {dmarc['dmarc_domain'] or 'Not Found'}")
        if dmarc['authentication_results_dmarc']:
            report.append(f"Authentication-Results (DMARC): {dmarc['authentication_results_dmarc']}")
        
        report.append("\n" + "-" * 80)
        report.append("MAIL HOPS ANALYSIS")
        report.append("-" * 80)
        hops = analysis['mail_hops']
        if hops:
            report.append(f"Total Hops: {len(hops)}")
            report.append("\nHop Path (from recipient to sender):")
            for i, hop in enumerate(hops, 1):
                report.append(f"\n  Hop {i}:")
                report.append(f"    From: {hop['from'] or 'N/A'}")
                report.append(f"    By: {hop['by'] or 'N/A'}")
                report.append(f"    IP Address: {hop['ip_address'] or 'N/A'}")
                report.append(f"    With: {hop['with'] or 'N/A'}")
                report.append(f"    Timestamp: {hop['timestamp'] or 'N/A'}")
        else:
            report.append("No mail hops found")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)


def analyze_email_file(file_path: str) -> Dict:
    """Analyze email header from a file"""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        header_text = f.read()
    
    analyzer = EmailHeaderAnalyzer(header_text)
    return analyzer.analyze()


def generate_report_from_file(file_path: str) -> str:
    """Generate report from email header file"""
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        header_text = f.read()
    
    analyzer = EmailHeaderAnalyzer(header_text)
    return analyzer.generate_report()


if __name__ == "__main__":
    import sys
    
    print("=" * 80)
    print("EMAIL HEADER FORENSICS ANALYZER")
    print("=" * 80)
    print()
    
    # Check if file path provided as argument
    if len(sys.argv) >= 2:
        file_path = sys.argv[1]
        print(f"Analyzing email header from file: {file_path}")
        print()
        report = generate_report_from_file(file_path)
        print(report)
    else:
        # Interactive mode
        print("How would you like to provide the email header?")
        print("1. Enter file path")
        print("2. Paste email header directly")
        print()
        
        choice = input("Enter your choice (1 or 2): ").strip()
        print()
        
        if choice == "1":
            file_path = input("Enter the path to the email header file: ").strip()
            if not file_path:
                print("Error: No file path provided.")
                sys.exit(1)
            
            try:
                print(f"\nAnalyzing email header from file: {file_path}")
                print()
                report = generate_report_from_file(file_path)
                print(report)
                
                # Ask if user wants to save report
                save = input("\nDo you want to save this report to a file? (y/n): ").strip().lower()
                if save == 'y':
                    output_file = input("Enter output filename (default: email_report.txt): ").strip()
                    if not output_file:
                        output_file = "email_report.txt"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(report)
                    print(f"Report saved to: {output_file}")
            except FileNotFoundError:
                print(f"Error: File '{file_path}' not found.")
                sys.exit(1)
            except Exception as e:
                print(f"Error analyzing file: {e}")
                sys.exit(1)
        
        elif choice == "2":
            print("Paste the email header below.")
            print("(Press Enter after pasting, then press Ctrl+D (Linux/Mac) or Ctrl+Z then Enter (Windows) to finish)")
            print("Or type 'END' on a new line to finish:")
            print("-" * 80)
            
            header_lines = []
            try:
                while True:
                    line = input()
                    if line.strip().upper() == 'END':
                        break
                    header_lines.append(line)
            except EOFError:
                pass
            
            if not header_lines:
                print("Error: No email header provided.")
                sys.exit(1)
            
            header_text = '\n'.join(header_lines)
            print("\nAnalyzing email header...")
            print()
            
            analyzer = EmailHeaderAnalyzer(header_text)
            report = analyzer.generate_report()
            print(report)
            
            # Ask if user wants to save report
            save = input("\nDo you want to save this report to a file? (y/n): ").strip().lower()
            if save == 'y':
                output_file = input("Enter output filename (default: email_report.txt): ").strip()
                if not output_file:
                    output_file = "email_report.txt"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"Report saved to: {output_file}")
        
        else:
            print("Invalid choice. Please run the script again and select 1 or 2.")
            sys.exit(1)


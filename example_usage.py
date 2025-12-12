#!/usr/bin/env python3
"""
Example usage of the Email Header Analyzer
Demonstrates how to use the analyzer programmatically
"""

from email_header_analyzer import EmailHeaderAnalyzer

def example_analysis():
    """Example of analyzing an email header"""
    
    # Example email header (you can replace this with actual header text)
    sample_header = """
Return-Path: <noreply@example-phish.com>
Received: from mail.example-phish.com (mail.example-phish.com [192.168.1.100])
	by mail.company.com (Postfix) with ESMTP id ABC123
	for <user@company.com>; Mon, 15 Jan 2024 14:23:45 +0000
Received-SPF: fail (mail.example-phish.com: domain does not designate 192.168.1.100 as permitted sender)
Authentication-Results: mail.company.com;
	spf=fail smtp.mailfrom=example-phish.com;
	dkim=none header.d=example-phish.com;
	dmarc=fail (p=quarantine) action=quarantine header.from=example-phish.com
Message-ID: <20240115142345.ABC123@mail.company.com>
Date: Mon, 15 Jan 2024 14:23:45 +0000
From: Example Service <noreply@example-phish.com>
To: user@company.com
Subject: Urgent Action Required
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
"""
    
    print("=" * 80)
    print("EXAMPLE: Programmatic Email Header Analysis")
    print("=" * 80)
    print()
    
    # Create analyzer instance
    analyzer = EmailHeaderAnalyzer(sample_header)
    
    # Perform analysis
    analysis = analyzer.analyze()
    
    # Access specific results
    print("Analysis Results:")
    print("-" * 80)
    
    print("\n1. Basic Information:")
    basic = analysis['basic_info']
    print(f"   From: {basic['from']}")
    print(f"   To: {basic['to']}")
    print(f"   Subject: {basic['subject']}")
    
    print("\n2. SPF Analysis:")
    spf = analysis['spf']
    print(f"   Result: {spf['spf_result'] or 'Not Found'}")
    print(f"   SMTP MailFrom: {spf['spf_smtp_mailfrom'] or 'Not Found'}")
    
    print("\n3. DKIM Analysis:")
    dkim = analysis['dkim']
    print(f"   Result: {dkim['dkim_result'] or 'Not Found'}")
    print(f"   Domain: {dkim['dkim_domain'] or 'Not Found'}")
    
    print("\n4. DMARC Analysis:")
    dmarc = analysis['dmarc']
    print(f"   Result: {dmarc['dmarc_result'] or 'Not Found'}")
    print(f"   Policy: {dmarc['dmarc_policy'] or 'Not Found'}")
    
    print("\n5. Mail Hops:")
    hops = analysis['mail_hops']
    print(f"   Total Hops: {len(hops)}")
    for i, hop in enumerate(hops, 1):
        print(f"   Hop {i}: {hop['from']} -> {hop['by']} (IP: {hop['ip_address']})")
    
    # Generate full report
    print("\n" + "=" * 80)
    print("Full Report:")
    print("=" * 80)
    report = analyzer.generate_report()
    print(report)
    
    # Or access individual extraction methods
    print("\n" + "=" * 80)
    print("Individual Extraction Methods:")
    print("=" * 80)
    print("\nSPF Info:", analyzer.extract_spf())
    print("\nDKIM Info:", analyzer.extract_dkim())
    print("\nDMARC Info:", analyzer.extract_dmarc())
    print("\nMail Hops:", analyzer.extract_mail_hops())


if __name__ == "__main__":
    example_analysis()


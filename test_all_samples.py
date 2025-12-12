#!/usr/bin/env python3
"""
Quick test script to analyze all email samples
"""

import os
from email_header_analyzer import EmailHeaderAnalyzer

def test_all_samples():
    """Test analysis on all sample emails"""
    samples_dir = "samples"
    
    if not os.path.exists(samples_dir):
        print(f"Error: {samples_dir} directory not found!")
        return
    
    sample_files = sorted([f for f in os.listdir(samples_dir) if f.endswith('.txt')])
    
    print("=" * 80)
    print("TESTING ALL EMAIL SAMPLES")
    print("=" * 80)
    print()
    
    for sample_file in sample_files:
        file_path = os.path.join(samples_dir, sample_file)
        print(f"Testing: {sample_file}")
        print("-" * 80)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                header_text = f.read()
            
            analyzer = EmailHeaderAnalyzer(header_text)
            analysis = analyzer.analyze()
            
            # Quick summary
            basic = analysis['basic_info']
            spf = analysis['spf']
            dkim = analysis['dkim']
            dmarc = analysis['dmarc']
            hops = analysis['mail_hops']
            
            print(f"From: {basic['from']}")
            print(f"Subject: {basic['subject']}")
            print(f"SPF: {spf['spf_result'] or 'Not Found'}")
            print(f"DKIM: {dkim['dkim_result'] or 'Not Found'}")
            print(f"DMARC: {dmarc['dmarc_result'] or 'Not Found'}")
            print(f"Mail Hops: {len(hops)}")
            
            # Risk assessment
            risk_score = 0
            if spf['spf_result'] == 'fail':
                risk_score += 3
            elif spf['spf_result'] in ['softfail', 'none', 'temperror']:
                risk_score += 1
            
            if dkim['dkim_result'] == 'none':
                risk_score += 2
            elif dkim['dkim_result'] == 'fail':
                risk_score += 3
            
            if dmarc['dmarc_result'] == 'fail':
                risk_score += 3
            elif dmarc['dmarc_result'] == 'none':
                risk_score += 1
            
            if risk_score >= 7:
                risk_level = "CRITICAL"
            elif risk_score >= 4:
                risk_level = "HIGH"
            elif risk_score >= 2:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"
            
            print(f"Risk Score: {risk_score}/11 - {risk_level}")
            print()
            
        except Exception as e:
            print(f"Error analyzing {sample_file}: {e}")
            print()
    
    print("=" * 80)
    print("ALL TESTS COMPLETED")
    print("=" * 80)

if __name__ == "__main__":
    test_all_samples()


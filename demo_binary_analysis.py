#!/usr/bin/env python3
"""
Demo script showing binary analysis capabilities
"""

from src.binary_analyzer import BinaryAnalyzer


def demo_ch1_analysis():
    """Demonstrate analysis of ch1.exe"""
    print("=" * 80)
    print("DEMO: Binary Analysis of ch1.exe")
    print("=" * 80)
    print()
    
    analyzer = BinaryAnalyzer()
    
    # Check if it's a binary
    print("1. Checking if ch1.exe is a binary...")
    is_binary = analyzer.is_binary_file('ch1.exe')
    print(f"   Result: {'Yes' if is_binary else 'No'}")
    print()
    
    if not is_binary:
        print("Not a binary file. Exiting.")
        return
    
    # Get file type
    print("2. Detecting file type...")
    file_type = analyzer.get_file_type('ch1.exe')
    print(f"   Type: {file_type}")
    print()
    
    # Extract all strings
    print("3. Extracting strings...")
    all_strings = analyzer.extract_strings('ch1.exe')
    print(f"   Total strings found: {len(all_strings)}")
    print()
    
    # Filter security strings
    print("4. Filtering security-relevant strings...")
    security_strings = analyzer.filter_security_strings(all_strings)
    print(f"   Security-relevant strings: {len(security_strings)}")
    print()
    
    # Display security strings
    print("5. Security-Relevant Strings:")
    print("-" * 80)
    for string in security_strings:
        string_lower = string.lower()
        matched = [kw for kw in analyzer.security_keywords if kw in string_lower]
        print(f"   • {string}")
        if matched:
            print(f"     Keywords: {', '.join(matched)}")
    print()
    
    # Full analysis
    print("6. Running comprehensive analysis...")
    analysis = analyzer.analyze_binary('ch1.exe')
    print()
    
    # Format report
    print("7. Formatted Report:")
    print()
    report = analyzer.format_analysis_report(analysis)
    print(report)
    
    print("=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)
    print()
    print("Try these commands:")
    print("  python main.py --file ch1.exe --strings-only")
    print("  python main.py --file ch1.exe --analyze-binary --auto-disassemble")
    print()


if __name__ == '__main__':
    demo_ch1_analysis()

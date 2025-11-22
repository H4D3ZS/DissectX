#!/usr/bin/env python3
"""
DissectX - CTF Binary Analysis Tool

A command-line tool that translates x86-64 assembly code into human-readable English explanations.
Useful for CTF competitions and reverse engineering practice.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from src.input_handler import InputHandler
from src.parser import AssemblyParser
from src.analyzer import PatternAnalyzer
from src.translator import InstructionTranslator
from src.security_highlighter import SecurityHighlighter
from src.formatter import OutputFormatter
from src.binary_analyzer import BinaryAnalyzer
from src.advanced_detector import AdvancedDetector


def main():
    """Main entry point for the assembly translator CLI"""
    parser = argparse.ArgumentParser(
        description='🔍 DissectX - CTF Binary Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
📖 SUPER SIMPLE USAGE:
  
  Just provide a file - it figures out what to do automatically:
  
    python main.py binary.exe           # Extracts strings, finds flags/passwords
    python main.py assembly.asm         # Translates assembly to English
    python main.py binary.exe --full    # Complete analysis (auto-saves to file)
    python main.py binary.exe -o out.txt  # Save to specific file

🎯 EXAMPLES:

  CTF Challenge - Find the flag:
    python main.py challenge.exe
  
  Translate assembly:
    python main.py code.asm
  
  Full reverse engineering:
    python main.py program.exe --full
  
  Interactive mode:
    python main.py -i

💡 SMART DEFAULTS:
   • Binaries → Automatically extracts strings and finds secrets
   • Assembly → Automatically translates to English
   • --full mode → Auto-saves large output to <filename>_analysis.txt
   • No flags needed for basic usage!

📚 More: See BEGINNER_GUIDE.md
        """
    )
    
    # Positional argument for file (most common use case)
    parser.add_argument(
        'file',
        nargs='?',
        type=str,
        help='Binary or assembly file to analyze (auto-detects type)'
    )
    
    # Simple mode flags
    parser.add_argument(
        '--full',
        action='store_true',
        help='🚀 Full analysis: strings + disassembly + translation (for binaries)'
    )
    parser.add_argument(
        '--strings-only',
        action='store_true',
        help='📝 Only show strings from binary (skip translation)'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        type=str,
        metavar='FILE',
        help='💾 Save output to file instead of displaying'
    )
    
    # Advanced options (hidden from main help)
    advanced = parser.add_argument_group('⚙️  Advanced Options')
    advanced.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Enter interactive mode for multi-line input'
    )
    advanced.add_argument(
        '--no-auto-detect',
        action='store_true',
        help='Disable automatic binary detection'
    )
    
    args = parser.parse_args()
    
    try:
        # Check if we have input
        if not args.file and not args.interactive and sys.stdin.isatty():
            parser.print_help()
            print("\n❌ Error: No input provided", file=sys.stderr)
            print("💡 Try: dissectx yourfile.exe", file=sys.stderr)
            sys.exit(1)
        
        # Step 0: Smart binary detection and analysis
        binary_analysis = None
        is_binary = False
        
        if args.file and not args.no_auto_detect:
            binary_analyzer = BinaryAnalyzer()
            is_binary = binary_analyzer.is_binary_file(args.file)
            
            if is_binary:
                print("🔍 Binary file detected! Analyzing...\n", file=sys.stderr)
                
                # Perform binary analysis
                binary_analysis = binary_analyzer.analyze_binary(args.file)
                
                # Print binary analysis report
                report = binary_analyzer.format_analysis_report(binary_analysis)
                if report:
                    print(report)
                
                # If strings-only mode, exit after showing strings
                if args.strings_only:
                    print("\n✅ String analysis complete!", file=sys.stderr)
                    sys.exit(0)
                
                # If full mode, auto-disassemble
                if args.full:
                    print("\n🚀 Full analysis mode: Disassembling binary...\n", file=sys.stderr)
                    disassembly = binary_analyzer.disassemble_binary(args.file, syntax='intel')
                    
                    if disassembly:
                        # Save disassembly to temporary file
                        import tempfile
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.asm', delete=False) as f:
                            f.write(disassembly)
                            temp_asm_file = f.name
                        
                        print(f"�T Disassembly saved to: {temp_asm_file}", file=sys.stderr)
                        print("📖 Translating to English...\n", file=sys.stderr)
                        
                        # Auto-save to output file if not specified (full mode generates large output)
                        if not args.output:
                            # Generate output filename based on input
                            input_path = Path(args.file)
                            args.output = f"{input_path.stem}_analysis.txt"
                            print(f"💾 Large output detected - saving to: {args.output}", file=sys.stderr)
                        
                        # Override file argument to use disassembly
                        args.file = temp_asm_file
                    else:
                        print("❌ Could not disassemble binary.", file=sys.stderr)
                        print("💡 Try installing objdump or provide assembly manually", file=sys.stderr)
                        sys.exit(1)
                else:
                    # Binary detected but no --full flag - just show strings by default
                    print("\n✅ String analysis complete!", file=sys.stderr)
                    print("💡 Tip: Add --full for complete disassembly and translation", file=sys.stderr)
                    sys.exit(0)
        
        # Step 1: Read input
        input_handler = InputHandler()
        assembly_text = read_input(input_handler, args)
        
        # Step 2: Parse assembly code
        parser_obj = AssemblyParser()
        instructions = parser_obj.parse(assembly_text)
        
        if not instructions:
            print("Error: No valid instructions found in input", file=sys.stderr)
            sys.exit(1)
        
        # Step 3: Analyze patterns
        analyzer = PatternAnalyzer()
        blocks = analyzer.analyze(instructions)
        
        # Step 4: Translate instructions
        translator = InstructionTranslator()
        translations = [translator.translate(instr) for instr in instructions]
        
        # Step 5: Highlight security operations
        security_highlighter = SecurityHighlighter()
        security_observations = security_highlighter.highlight(instructions)
        
        # Format security observations for output
        security_highlights = []
        if security_observations:
            for obs in security_observations:
                severity = obs.get('severity', 'info').upper()
                description = obs.get('description', '')
                security_highlights.append(f"[{severity}] {description}")
        
        # Step 5.5: Advanced protection detection
        advanced_detector = AdvancedDetector()
        advanced_analysis = advanced_detector.analyze_advanced_techniques(instructions)
        advanced_report = advanced_detector.format_advanced_report(advanced_analysis)
        
        # Step 6: Format output
        formatter = OutputFormatter()
        output = formatter.format(instructions, blocks, translations, security_highlights)
        
        # Prepend advanced protection report if detected
        if advanced_report:
            output = advanced_report + output
        
        # Step 7: Write output
        write_output(output, args.output)
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


def read_input(input_handler: InputHandler, args: argparse.Namespace) -> str:
    """
    Read assembly code from the specified input source.
    
    Args:
        input_handler: InputHandler instance
        args: Parsed command-line arguments
        
    Returns:
        Assembly code as string
        
    Raises:
        ValueError: If input is empty or invalid
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read
    """
    if args.file:
        # Read from file
        return input_handler.read_from_file(args.file)
    elif args.interactive:
        # Interactive mode
        print("📝 Interactive mode - Enter assembly code (Ctrl+D when done):", file=sys.stderr)
        return input_handler.read_interactive(terminator='END')
    else:
        # Read from stdin
        return input_handler.read_from_stdin()


def write_output(output: str, output_path: Optional[str] = None):
    """
    Write the translation output to the specified destination.
    
    Args:
        output: Formatted translation string
        output_path: Optional file path to write to (None = stdout)
        
    Raises:
        IOError: If output file cannot be written
    """
    if output_path:
        # Write to file
        try:
            path = Path(output_path)
            path.write_text(output, encoding='utf-8')
            print(f"Translation written to {output_path}", file=sys.stderr)
        except Exception as e:
            raise IOError(f"Cannot write to output file: {output_path}") from e
    else:
        # Write to stdout
        print(output)


if __name__ == '__main__':
    main()

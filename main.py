#!/usr/bin/env python3
"""
DissectX - CTF Binary Analysis Tool

A command-line tool that translates x86-64 assembly code into human-readable English explanations.
Useful for CTF competitions and reverse engineering practice.
"""

import argparse
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from src.input_handler import InputHandler
from src.parser import AssemblyParser
from src.analyzer import PatternAnalyzer
from src.translator import InstructionTranslator
from src.security_highlighter import SecurityHighlighter
from src.formatter import OutputFormatter
from src.binary_analyzer import BinaryAnalyzer
from src.format_detector import FormatDetector
from src.advanced_detector import AdvancedDetector


def start_web_server_background(port=8000):
    """Start the web server with file upload capability
    
    Args:
        port: Port number to run the server on (default: 8000)
    """
    try:
        from src.web.server import WebUIServer
        from flask import request, jsonify, send_file
        import os
        import tempfile
        
        # Create WebUIServer instance (starts with no results)
        server = WebUIServer()
        app = server.app
        
        # Configure upload settings
        app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max file size
        app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
        
        # Store analysis cache
        analysis_cache = {}
        
        # Add upload route to handle file uploads
        @app.route('/upload', methods=['POST'])
        def upload_file():
            """Handle file upload and analysis"""
            if 'file' not in request.files:
                return {'error': 'No file uploaded'}, 400
            
            file = request.files['file']
            if file.filename == '':
                return {'error': 'No file selected'}, 400
            
            try:
                # Save uploaded file
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(temp_path)
                
                # Analyze the binary
                binary_analyzer = BinaryAnalyzer()
                
                # Check if it's a binary
                if not binary_analyzer.is_binary_file(temp_path):
                    return {'error': 'File is not a valid binary'}, 400
                
                # Get file type
                file_type = binary_analyzer.get_file_type(temp_path)
                
                # Extract strings
                strings = binary_analyzer.extract_strings(temp_path, min_length=4)
                
                # Filter security-relevant strings
                security_strings = binary_analyzer.filter_security_strings(strings)
                
                # Detect API calls
                api_calls = binary_analyzer.detect_api_calls(strings)
                
                # Detect Base64 strings
                base64_strings = binary_analyzer.detect_base64_strings(strings)
                
                # Detect flags
                from src.detectors.flag_detector import FlagDetector
                flag_detector = FlagDetector()
                with open(temp_path, 'rb') as f:
                    binary_data = f.read()
                flags = flag_detector.find_flags(binary_data, strings)
                
                # Try to disassemble
                disassembly = binary_analyzer.disassemble_binary(temp_path)
                
                # Extract string references if we have disassembly
                if disassembly:
                    binary_analyzer.extract_string_references_from_disassembly(disassembly, strings)
                    usage_classification = binary_analyzer.classify_string_usage(strings, disassembly)
                    vulnerabilities = binary_analyzer.detect_format_string_vulnerabilities(strings, usage_classification)
                
                # Detect architecture
                detected_arch = "Unknown"
                detected_format = "Unknown"
                try:
                    from src.architecture_detector import ArchitectureDetector
                    detector = ArchitectureDetector()
                    arch, is_64bit = detector.detect_from_file(temp_path)
                    if arch:
                        detected_arch = f"{arch.value} ({'64-bit' if is_64bit else '32-bit'})"
                        detected_format = detector.get_format_name()
                except:
                    pass
                
                # Checksec (Security Mitigations)
                security_mitigations = binary_analyzer.detect_security_mitigations(temp_path)

                # Vulnerability Scan
                vulnerabilities = binary_analyzer.detect_vulnerabilities(temp_path)

                # ============================================================
                # ADVANCED DETECTION MODULES
                # ============================================================
                
                # Syscall detection
                syscalls = []
                if binary_analyzer.syscall_detector and disassembly:
                    try:
                        syscall_results = binary_analyzer.syscall_detector.analyze(binary_data)
                        # Extract stubs for display
                        if 'stubs' in syscall_results:
                            for stub in syscall_results['stubs']:
                                syscalls.append({
                                    'name': binary_analyzer.syscall_detector.resolve_ssn_to_name(stub.ssn),
                                    'address': hex(stub.va),
                                    'description': stub.description
                                })
                    except Exception as e:
                        print(f"[WARNING] Syscall detection failed: {e}")
                
                # API hash resolution
                api_hashes = []
                if binary_analyzer.api_hash_resolver:
                    try:
                        hash_results = binary_analyzer.api_hash_resolver.analyze(binary_data)
                        # Extract matches for display
                        if 'matches' in hash_results:
                            for match in hash_results['matches']:
                                api_hashes.append({
                                    'hash': hex(match.hash_value),
                                    'api_name': match.api_name,
                                    'library': match.algorithm
                                })
                    except Exception as e:
                        print(f"[WARNING] API hash resolution failed: {e}")
                
                # Junk code detection
                junk_patterns = []
                if binary_analyzer.junk_detector and disassembly:
                    try:
                        junk_results = binary_analyzer.junk_detector.analyze(binary_data)
                        # Extract patterns for display
                        if 'patterns' in junk_results:
                            for pattern in junk_results['patterns']:
                                junk_patterns.append({
                                    'type': pattern.pattern_type,
                                    'address': hex(pattern.locations[0]) if pattern.locations else 'N/A',
                                    'confidence': pattern.severity
                                })
                    except Exception as e:
                        print(f"[WARNING] Junk code detection failed: {e}")
                
                # Advanced flag finding (FlagFinder)
                advanced_flags = []
                if binary_analyzer.flag_finder:
                    try:
                        # FlagFinder.find_flags expects (data: bytes, strings: List[str])
                        flag_results = binary_analyzer.flag_finder.find_flags(binary_data, strings)
                        # Results are already Flag objects
                        for flag in flag_results:
                            advanced_flags.append({
                                'value': flag.value,
                                'location': hex(flag.location) if flag.location else 'N/A',
                                'method': flag.method
                            })
                    except Exception as e:
                        print(f"[WARNING] Advanced flag finding failed: {e}")
                
                # String decryption (if Unicorn available)
                decrypted_strings = []
                if binary_analyzer.string_decryptor:
                    try:
                        decrypted = binary_analyzer.string_decryptor.decrypt_strings(binary_data)
                        for item in decrypted:
                            decrypted_strings.append({
                                'encrypted': item.get('encrypted', 'N/A'),
                                'decrypted': item.get('decrypted', ''),
                                'algorithm': item.get('algorithm', 'Unknown')
                            })
                    except Exception as e:
                        print(f"[WARNING] String decryption failed: {e}")
                
                # ============================================================
                # CALL GRAPH GENERATION
                # ============================================================
                
                call_graph_data = {}
                if disassembly:
                    try:
                        from src.call_graph_generator import CallGraphGenerator
                        from src.parser import AssemblyParser
                        
                        # Parse instructions if not already done
                        if 'instructions' not in locals():
                            parser = AssemblyParser()
                            instructions = parser.parse(disassembly)
                        
                        # Build call graph
                        cg_generator = CallGraphGenerator()
                        call_graph = cg_generator.build_graph(instructions)
                        
                        # Build detailed function information
                        function_details = {}
                        for func_addr in call_graph.get_all_functions():
                            # Get callers and callees
                            callers = call_graph.get_callers(func_addr)
                            callees = call_graph.get_callees(func_addr)
                            
                            # Determine function type
                            is_entry = func_addr in call_graph.entry_points
                            is_recursive = func_addr in call_graph.recursive_functions
                            is_dead = func_addr in call_graph.dead_code
                            
                            # Get function strings if available
                            func_strings = []
                            if binary_analyzer.function_to_strings and hex(func_addr) in binary_analyzer.function_to_strings:
                                func_strings = binary_analyzer.function_to_strings[hex(func_addr)]
                            
                            # Generate explanation for this specific function
                            explanation = []
                            
                            if is_entry:
                                explanation.append("🚀 ENTRY POINT - Program execution starts here")
                            if is_recursive:
                                explanation.append("🔄 RECURSIVE - Calls itself (watch for infinite loops)")
                            if is_dead:
                                explanation.append("💀 DEAD CODE - Never called (unreachable)")
                            
                            # Describe what it does based on calls
                            if callees:
                                explanation.append(f"Calls {len(callees)} function(s): {', '.join([hex(c) for c in list(callees)[:3]])}")
                            else:
                                explanation.append("Leaf function (doesn't call other functions)")
                            
                            if callers:
                                explanation.append(f"Called by {len(callers)} function(s)")
                            elif not is_entry:
                                explanation.append("No callers detected (might be called indirectly)")
                            
                            # Add string context
                            if func_strings:
                                explanation.append(f"References {len(func_strings)} string(s)")
                                if func_strings[:2]:
                                    explanation.append(f"  Examples: {', '.join([s[:30] + '...' if len(s) > 30 else s for s in func_strings[:2]])}")
                            
                            function_details[hex(func_addr)] = {
                                'address': hex(func_addr),
                                'is_entry': is_entry,
                                'is_recursive': is_recursive,
                                'is_dead': is_dead,
                                'callers': [hex(c) for c in callers],
                                'callees': [hex(c) for c in callees],
                                'caller_count': len(callers),
                                'callee_count': len(callees),
                                'strings': func_strings[:5],  # Limit to 5 strings
                                'explanation': '\n'.join(explanation)
                            }
                        
                        # Export to various formats
                        call_graph_data = {
                            'entry_points': [hex(addr) for addr in sorted(call_graph.entry_points)],
                            'recursive_functions': [hex(addr) for addr in sorted(call_graph.recursive_functions)],
                            'dead_code': [hex(addr) for addr in sorted(call_graph.dead_code)],
                            'mermaid': cg_generator.export_mermaid(),
                            'ascii': cg_generator.export_ascii(),
                            'total_functions': len(call_graph.get_all_functions()),
                            'total_calls': call_graph.graph.number_of_edges(),
                            'function_details': function_details  # Add detailed info
                        }
                        print(f"[INFO] Call graph generated: {call_graph_data['total_functions']} functions, {call_graph_data['total_calls']} calls")
                    except Exception as e:
                        print(f"[WARNING] Call graph generation failed: {e}")
                        import traceback
                        traceback.print_exc()
                
                # Build functions dict from string-to-function mapping
                # Note: Pseudocode generation is now done on-demand in the web interface
                # to avoid performance issues during upload
                functions = {}
                if binary_analyzer.function_to_strings:
                    for func_addr, func_strings in binary_analyzer.function_to_strings.items():
                        functions[func_addr] = {
                            'name': f'sub_{func_addr}',
                            'strings': func_strings,
                            'string_count': len(func_strings),
                            # Store basic info only - pseudocode generated on-demand
                        }
                
                # Update the server's analysis_results so all pages work
                server.analysis_results = {
                    'binary_info': {
                        'filename': file.filename,
                        'filepath': temp_path,
                        'file_type': file_type or 'Unknown',
                        'architecture': detected_arch,
                        'format': detected_format,
                        'total_strings': len(strings),
                        'security_strings': len(security_strings),
                        'base64_strings': len(base64_strings)
                    },
                    'strings': [
                        {'value': s, 'address': 'N/A'} for s in strings[:500]  # Limit to first 500
                    ],
                    'security_strings': [
                        {'value': s, 'address': 'N/A'} for s in security_strings
                    ],
                    'base64_strings': base64_strings,
                    'api_calls': api_calls,
                    'flags': flags,
                    'functions': functions,
                    'xrefs': {
                        'string_refs': binary_analyzer.string_to_functions,
                        'function_strings': binary_analyzer.function_to_strings
                    },
                    # Store disassembly for on-demand pseudocode generation
                    'disassembly': disassembly if disassembly else None,
                    # Advanced analysis results
                    'advanced_analysis': {
                        'syscalls': syscalls,
                        'api_hashes': api_hashes,
                        'junk_patterns': junk_patterns,
                        'advanced_flags': advanced_flags,
                        'decrypted_strings': decrypted_strings
                    },
                    'security_mitigations': security_mitigations,
                    'vulnerabilities': vulnerabilities,
                    # Call graph data
                    'call_graph': call_graph_data
                }
                
                # Return success with redirect flag
                return {
                    'success': True,
                    'redirect': '/',  # Redirect to dashboard to see results
                    'filename': file.filename,
                }
                
            except Exception as e:
                return {'error': str(e)}, 500
        
        @app.route('/download/<filename>')
        def download_file(filename):
            """Download analysis report"""
            if filename in analysis_cache:
                from flask import send_file
                return send_file(analysis_cache[filename], as_attachment=True, download_name=filename)
            return {'error': 'File not found'}, 404
        
        # Start server
        print(f"🌐 DissectX Web Server running on http://localhost:{port}")
        print("📁 Upload binaries for instant analysis!")
        print("Press Ctrl+C to stop\n")
        app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
        
    except Exception as e:
        print(f"⚠️  Web server failed to start: {e}", file=sys.stderr)


def main():
    """Main entry point for the assembly translator CLI"""
    parser = argparse.ArgumentParser(
        description='🔍 DissectX -    Binary Analysis & Reverse Engineering Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
📖 QUICK START:

  Basic Analysis (strings, flags, patterns):
    python main.py binary.exe

  Full Analysis (disassembly + translation):
    python main.py binary.exe --full

  Advanced Analysis (anti-debug, emulation):
    python main.py binary.exe --advanced --emulate

🎯 COMMON USE CASES:

  CTF Challenge - Find flags:
    python main.py challenge.exe
    python main.py challenge.exe --decrypt-strings

  Malware Analysis:
    python main.py malware.exe --advanced
    python main.py --generate-dump packed.exe

  Exploit Development:
    python -m src.rop_analyzer target.exe
    python main.py binary.exe --full --function vulnerable_func

  Binary Comparison:
    python -m src.binary_differ old.exe new.exe

📋 ASSEMBLY INPUT MODES:

  File input:
    python main.py code.asm

  Interactive mode (paste from Ghidra/IDA):
    python main.py -i
    # Paste assembly, press Ctrl+D when done

  Pipe from tools:
    objdump -d -M intel binary | python main.py
    pbpaste | python main.py  # macOS/Linux
    Get-Clipboard | python main.py  # Windows

  Supported formats (auto-detected):
    • objdump output (addresses + hex + instructions)
    • Ghidra listings
    • IDA Pro exports
    • Clean assembly

🔧 ANALYSIS OPTIONS:

  --full              Complete disassembly and translation
  --strings-only      Quick string extraction only
  --advanced          Enable all advanced detections
  --emulate           Safe CPU emulation for dynamic analysis
  --decrypt-strings   Decrypt obfuscated strings
  --arch ARCH         Specify architecture (x86, arm64, mips, etc.)
  --function NAME     Analyze specific function only
  --output FILE       Save results to file
  --unlimited         Remove output size limits

🛡️  ADVANCED FEATURES:

  Anti-Analysis Detection:
    --detect-syscalls   Find direct syscall stubs
    --resolve-hashes    Resolve API hashes
    --detect-junk       Detect junk code

  Dynamic Analysis:
    --generate-dump FILE    Run and generate memory dump
    --memory-dump FILE      Analyze memory dump

  Architecture Support:
    --arch x86          32-bit x86
    --arch x86_64       64-bit x86
    --arch arm          32-bit ARM
    --arch arm64        64-bit ARM (AArch64)
    --arch mips         32-bit MIPS
    --arch mips64       64-bit MIPS

📚 DOCUMENTATION:

  README.md                 - Feature overview and installation
  docs/ARCHITECTURE.md      - System design and components
  docs/PLUGIN_DEVELOPMENT.md - Create custom analyzers
  docs/CTF_WALKTHROUGHS.md  - Step-by-step CTF examples

🔌 SPECIALIZED TOOLS:

  ROP Gadget Finder:
    python -m src.rop_analyzer binary.exe

  XOR Analysis:
    python -m src.detectors.xor_analyzer binary.exe

  Shellcode Detection:
    python -m src.detectors.shellcode_detector binary.exe

  Binary Diffing:
    python -m src.binary_differ old.exe new.exe

  Call Graph Generation:
    python -m src.call_graph_generator binary.exe

  TUI Mode (Interactive):
    python demo_tui.py binary.exe

  Web UI:
    python demo_web_ui.py binary.exe

💡 TIPS:

  • Start simple: python main.py binary.exe
  • Use --full for complete analysis
  • Use --advanced for malware/packed binaries
  • Use --emulate for dynamic string decryption
  • Save large outputs: --output report.md
  • Focus analysis: --function main

🆘 GETTING HELP:

  python main.py --help          This help message
  python main.py -h              Short help
  
  Online Resources:
    GitHub: https://github.com/yourusername/dissectx
    Docs: https://dissectx.readthedocs.io
    Issues: https://github.com/yourusername/dissectx/issues

📄 LICENSE: MIT - Free for CTFs, learning, and security research

Made with ❤️  for the security research community
        """
    )
    
    # Positional argument for file (most common use case)
    parser.add_argument(
        'file',
        nargs='?',
        type=str,
        help='Binary or assembly file to analyze (auto-detects type)'
    )
    
    # Core Analysis Options
    core = parser.add_argument_group('🔍 Core Analysis Options')
    core.add_argument(
        '--full',
        action='store_true',
        help='Complete analysis: strings + disassembly + translation + decompilation'
    )
    core.add_argument(
        '--strings-only',
        action='store_true',
        help='Quick mode: only extract and display strings (no disassembly)'
    )
    core.add_argument(
        '--advanced',
        action='store_true',
        help='Enable all advanced detections (anti-debug, syscalls, API hashing, junk code)'
    )
    
    # Output Options
    output = parser.add_argument_group('💾 Output Options')
    output.add_argument(
        '--output', '-o',
        type=str,
        metavar='FILE',
        help='Save analysis results to file (recommended for --full mode)'
    )
    output.add_argument(
        '--unlimited',
        action='store_true',
        help='Remove 1000-line output limit (warning: generates very large files)'
    )
    output.add_argument(
        '--function', '-f',
        type=str,
        metavar='NAME',
        help='Analyze only a specific function (e.g., main, check_password, validate_input)'
    )
    
    # Architecture Options
    arch = parser.add_argument_group('🏗️  Architecture Options')
    arch.add_argument(
        '--arch',
        type=str,
        choices=['x86', 'x86_64', 'arm', 'arm64', 'mips', 'mips64'],
        metavar='ARCH',
        help='Manually specify architecture: x86, x86_64, arm, arm64, mips, mips64 (overrides auto-detection)'
    )
    arch.add_argument(
        '--no-auto-detect',
        action='store_true',
        help='Disable automatic binary format and architecture detection'
    )
    
    # Dynamic Analysis Options
    dynamic = parser.add_argument_group('🦄 Dynamic Analysis Options')
    dynamic.add_argument(
        '--emulate',
        action='store_true',
        help='Enable Unicorn CPU emulation for safe dynamic analysis'
    )
    dynamic.add_argument(
        '--decrypt-strings',
        action='store_true',
        help='Attempt to decrypt obfuscated strings using XOR brute-force and emulation'
    )
    dynamic.add_argument(
        '--generate-dump',
        type=str,
        metavar='FILE',
        help='Run binary in emulator and generate memory dump (for unpacking)'
    )
    dynamic.add_argument(
        '--memory-dump',
        type=str,
        metavar='FILE',
        help='Analyze a memory dump file (from --generate-dump or external source)'
    )
    
    # Advanced Detection Options
    detection = parser.add_argument_group('🛡️  Advanced Detection Options')
    detection.add_argument(
        '--detect-syscalls',
        action='store_true',
        help='Detect direct syscall stubs (bypassing API calls)'
    )
    detection.add_argument(
        '--resolve-hashes',
        action='store_true',
        help='Resolve API hashes to function names (common in malware)'
    )
    detection.add_argument(
        '--detect-junk',
        action='store_true',
        help='Detect junk code and anti-analysis techniques'
    )
    
    # Exploitation Tools
    exploit = parser.add_argument_group('💣 Exploitation Tools')
    exploit.add_argument(
        '--pattern-create',
        type=int,
        metavar='LENGTH',
        help='Generate a cyclic pattern of given length (De Bruijn sequence)'
    )
    exploit.add_argument(
        '--pattern-offset',
        type=str,
        metavar='VALUE',
        help='Find offset of a value in the cyclic pattern (e.g., 0x41414141 or AAAA)'
    )
    exploit.add_argument(
        '--list-shellcodes',
        action='store_true',
        help='List available shellcodes in the library'
    )
    exploit.add_argument(
        '--shellcode',
        type=str,
        metavar='ID',
        help='Get raw shellcode by ID (use --list-shellcodes to see IDs)'
    )
    exploit.add_argument(
        '--auto-exploit',
        action='store_true',
        help='Automatically find buffer overflow offset and generate exploit script'
    )
    exploit.add_argument(
        '--encode',
        action='store_true',
        help='Encode payload to avoid bad characters (XOR)'
    )
    exploit.add_argument(
        '--polymorph',
        action='store_true',
        help='Apply polymorphic mutations to payload'
    )
    
    # Input Mode Options
    input_mode = parser.add_argument_group('📝 Input Mode Options')
    input_mode.add_argument(
        '--interactive', '-i',
        action='store_true',
        help='Interactive mode: paste assembly code (Ctrl+D when done, shows preview)'
    )
    input_mode.add_argument(
        '--no-preview',
        action='store_true',
        help='Skip preview step in interactive mode (proceed directly to analysis)'
    )
    
    # Web Interface Options
    web = parser.add_argument_group('🌐 Web Interface Options')
    web.add_argument(
        '--web',
        action='store_true',
        help='Start web server on http://localhost:8000 for browser-based analysis'
    )
    web.add_argument(
        '--port',
        type=int,
        default=8000,
        metavar='PORT',
        help='Port for web server (default: 8000)'
    )
    
    args = parser.parse_args()
    
    try:
        # Handle Web Server Mode
        if args.web:
            print("🌐 Starting DissectX Web Server...")
            print(f"📁 Server will run on http://localhost:{args.port}")
            print("🔍 Upload binaries for instant analysis!")
            print("Press Ctrl+C to stop\n")
            
            # Modify the web server function to accept port
            def start_web_with_port():
                start_web_server_background(port=args.port)
            
            # Start in main thread (blocking)
            start_web_server_background(port=args.port)
            return  # Exit after web server stops
        
        # Check if we have input
        has_exploit_args = args.pattern_create or args.pattern_offset or args.list_shellcodes or args.shellcode or args.auto_exploit
        if not args.file and not args.interactive and not args.memory_dump and not args.generate_dump and not has_exploit_args and sys.stdin.isatty():
            parser.print_help()
            print("\n❌ Error: No input provided", file=sys.stderr)
            print("💡 Try: python main.py yourfile.exe", file=sys.stderr)
            print("💡 Or start web server: python main.py --web", file=sys.stderr)
            sys.exit(1)
            
        # Handle Generate Dump (Dynamic Unpacking)
        if args.generate_dump:
            try:
                from src.emulation.unicorn_emulator import UnicornEmulator
                from src.pe.memory_dump_analyzer import MemoryDumpAnalyzer
                
                target_file = args.generate_dump
                dump_file = target_file + ".dmp"
                
                print(f"🦄 Emulating {target_file} to generate memory dump...")
                
                # Read PE data
                with open(target_file, 'rb') as f:
                    pe_data = f.read()
                
                # Initialize Emulator
                emu = UnicornEmulator()
                emu.load_pe(pe_data)
                
                # Run for 100,000 instructions (should be enough for basic unpacking)
                print("⏳ Running 100,000 instructions (unpacking)...")
                emu.emulate(count=100000)
                
                # Dump memory
                emu.dump_memory(dump_file)
                
                # Analyze the new dump
                print(f"\n🧠 Analyzing generated dump: {dump_file}...")
                with open(dump_file, 'rb') as f:
                    dump_data = f.read()
                
                analyzer = MemoryDumpAnalyzer()
                results = analyzer.analyze_dump(dump_data, base_addr=emu.code_base)
                print(analyzer.format_report(results))
                return
                
            except Exception as e:
                print(f"❌ Error generating dump: {e}")
                return
        
        # Handle Memory Dump Analysis
        if args.memory_dump:
            try:
                from src.pe.memory_dump_analyzer import MemoryDumpAnalyzer
                print(f"🧠 Analyzing memory dump: {args.memory_dump}...")
                
                with open(args.memory_dump, 'rb') as f:
                    dump_data = f.read()
                
                analyzer = MemoryDumpAnalyzer()
                results = analyzer.analyze_dump(dump_data, base_addr=0x0) # Base addr 0 for raw dump
                print(analyzer.format_report(results))
                return
            except Exception as e:
                print(f"❌ Error analyzing memory dump: {e}")
                return

        # Handle Exploitation Tools
        if args.pattern_create:
            from src.utils.pattern_tools import PatternGenerator
            pg = PatternGenerator()
            pattern = pg.create(args.pattern_create)
            print(f"🌀 Cyclic Pattern ({args.pattern_create} bytes):")
            print(pattern)
            return

        if args.pattern_offset:
            from src.utils.pattern_tools import PatternGenerator
            pg = PatternGenerator()
            offset = pg.offset(args.pattern_offset)
            if offset != -1:
                print(f"🎯 Offset found at: {offset}")
            else:
                print("❌ Offset not found in pattern")
            return

        if args.list_shellcodes:
            from src.utils.shellcode_manager import ShellcodeManager
            sm = ShellcodeManager()
            shellcodes = sm.list_shellcodes()
            print("🐚 Available Shellcodes:")
            print(f"{'ID':<25} {'Arch':<6} {'Size':<6} {'Description'}")
            print("-" * 80)
            for sc in shellcodes:
                print(f"{sc['id']:<25} {sc['arch']:<6} {sc['size']:<6} {sc['description']}")
            return

        if args.shellcode:
            from src.utils.shellcode_manager import ShellcodeManager
            sm = ShellcodeManager()
            code = sm.format_shellcode(args.shellcode, format_type='python')
            print(f"🐚 Shellcode {args.shellcode}:")
            print(code)
            return

        # Handle Auto Exploitation
        if args.auto_exploit:
            if not args.file:
                print("❌ Error: --auto-exploit requires a binary file input")
                return
                
            print(f"🤖 Starting Automated Exploitation on {args.file}...")
            from src.exploitation.auto_exploiter import AutoExploiter
            
            exploiter = AutoExploiter()
            
            # 1. Find Offset
            print("⏳ Finding buffer overflow offset...")
            offset = exploiter.find_offset(args.file)
            
            if offset != -1:
                print(f"✅ Offset found at: {offset}")
                
                # 2. Generate Exploit
                print("📝 Generating exploit script...")
                script = exploiter.generate_exploit(
                    args.file, 
                    offset,
                    use_encoding=args.encode,
                    use_polymorph=args.polymorph
                )
                
                output_script = args.file + "_exploit.py"
                with open(output_script, 'w') as f:
                    f.write(script)
                    
                print(f"🚀 Exploit generated: {output_script}")
                print("-" * 40)
                print(script)
                print("-" * 40)
            else:
                print("❌ Could not find buffer overflow offset (binary might not be vulnerable or requires more complex input)")
            
            return

        # Step 0: Smart binary detection and analysis
        binary_analysis = None
        is_binary = False
        detected_arch = None
        
        if args.file and not args.no_auto_detect:
            binary_analyzer = BinaryAnalyzer()
            is_binary = binary_analyzer.is_binary_file(args.file)
            
            if is_binary:
                print("🔍 Binary file detected! Analyzing...\n", file=sys.stderr)
                
                # Detect architecture (unless manually specified)
                if args.arch:
                    # Manual override
                    arch_map = {
                        'x86': 'x86',
                        'x86_64': 'x86-64',
                        'arm': 'ARM',
                        'arm64': 'ARM64',
                        'mips': 'MIPS',
                        'mips64': 'MIPS64'
                    }
                    detected_arch = arch_map.get(args.arch, args.arch)
                    print(f"🎯 Architecture manually set to: {detected_arch}", file=sys.stderr)
                else:
                    # Auto-detect architecture
                    try:
                        from src.architecture_detector import ArchitectureDetector
                        detector = ArchitectureDetector()
                        arch, is_64bit = detector.detect_from_file(args.file)
                        
                        if arch:
                            detected_arch = arch.value
                            bit_str = "64-bit" if is_64bit else "32-bit"
                            format_name = detector.get_format_name()
                            print(f"🏗️  Detected architecture: {detected_arch} ({bit_str})", file=sys.stderr)
                            print(f"📦 Binary format: {format_name}", file=sys.stderr)
                        else:
                            print("⚠️  Could not auto-detect architecture", file=sys.stderr)
                            print("💡 Tip: Use --arch flag to specify manually", file=sys.stderr)
                    except Exception as e:
                        print(f"⚠️  Architecture detection failed: {e}", file=sys.stderr)
                        print("💡 Tip: Use --arch flag to specify manually", file=sys.stderr)
                
                # Perform binary analysis with advanced detection enabled by default
                binary_analysis = binary_analyzer.analyze_binary(
                    args.file, 
                    advanced=args.advanced or True, # Default to True for now
                    emulate=args.emulate,
                    decrypt_strings=args.decrypt_strings
                )
                
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
                            args.output = f"{input_path.stem}_analysis.md"
                            print(f"💾 Large output detected - saving to: {args.output}", file=sys.stderr)

                        # Override file argument to use disassembly
                        args.file = temp_asm_file
                        # Mark that this is from binary disassembly (skip preview)
                        args._from_binary = True
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
        assembly_text, input_stats = read_input(input_handler, args)

        # Step 1.5: Format detection and preview
        format_detector = FormatDetector()
        parser_obj = AssemblyParser()
        translator = InstructionTranslator()

        # Skip preview for binary --full mode (auto-disassembled) or if --no-preview flag set
        from_binary_disassembly = hasattr(args, '_from_binary') and args._from_binary
        no_preview = ((hasattr(args, 'no_preview') and args.no_preview) or
                     from_binary_disassembly)

        normalized_text, format_type = show_preview(
            parser_obj, translator, format_detector,
            assembly_text, input_stats, no_preview=no_preview
        )

        # Step 2: Parse assembly code (use normalized text)
        print("💾 Analyzing assembly...", file=sys.stderr)
        instructions = parser_obj.parse(normalized_text)
        
        if not instructions:
            print("Error: No valid instructions found in input", file=sys.stderr)
            sys.exit(1)
        
        # Step 3: Analyze patterns
        analyzer = PatternAnalyzer()
        blocks = analyzer.analyze(instructions)
        
        # Step 4: Translate instructions (translator already created above)
        translations = [translator.translate(instr) for instr in instructions]
        pseudocode = [translator.translate_to_pseudocode(instr) for instr in instructions]
        
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
        # 5. Format Output
        print("💾 Formatting analysis report (Markdown)...")

        # Determine max_lines based on --unlimited flag
        max_lines = None if args.unlimited else 1000

        # Filter to specific function if requested
        target_function = args.function if hasattr(args, 'function') else None

        formatter = OutputFormatter()
        report = formatter.format(
            instructions,
            blocks,
            translations,
            pseudocode,
            security_highlights=security_highlights,
            max_lines=max_lines,
            target_function=target_function
        )

        if args.output:
            output_file = args.output
        else:
            # Use args.file instead of args.binary_file (which doesn't exist)
            output_file = args.file.rsplit('.', 1)[0] + "_analysis.md"

        with open(output_file, 'w') as f:
            f.write(report)

        print(f"✅ Analysis report written to {output_file}")
        
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


def read_input(input_handler: InputHandler, args: argparse.Namespace) -> tuple[str, dict]:
    """
    Read assembly code from the specified input source.

    Args:
        input_handler: InputHandler instance
        args: Parsed command-line arguments

    Returns:
        Tuple of (assembly_code, stats_dict)

    Raises:
        ValueError: If input is empty or invalid
        FileNotFoundError: If file doesn't exist
        IOError: If file cannot be read
    """
    if args.file:
        # Read from file
        content = input_handler.read_from_file(args.file)
        stats = {
            'lines': len(content.split('\n')),
            'bytes': len(content),
            'source': 'file'
        }
        return content, stats
    elif args.interactive:
        # Interactive mode - enhanced prompt handled by input_handler
        return input_handler.read_interactive(terminator='END')
    else:
        # Read from stdin
        return input_handler.read_from_stdin()


def show_preview(parser: AssemblyParser, translator: InstructionTranslator,
                format_detector: FormatDetector, assembly_text: str,
                stats: dict, no_preview: bool = False) -> tuple[str, str]:
    """
    Show preview of parsed assembly and ask for confirmation.

    Args:
        parser: AssemblyParser instance
        translator: InstructionTranslator instance
        format_detector: FormatDetector instance
        assembly_text: Raw assembly text
        stats: Input statistics
        no_preview: Skip preview and auto-proceed

    Returns:
        Tuple of (normalized_assembly, format_type)
    """
    # Detect format
    format_type = format_detector.detect(assembly_text)
    format_desc = format_detector.get_format_description(format_type)

    print(f"✓ Detected format: {format_desc}", file=sys.stderr)

    # Normalize assembly
    normalized_text, normalized_lines = format_detector.normalize(assembly_text, format_type)

    if format_type != 'clean':
        print(f"✓ Normalized: Removed addresses and hex bytes", file=sys.stderr)

    # Skip preview if requested
    if no_preview:
        return normalized_text, format_type

    # Quick parse for preview
    preview_instrs, total_lines = parser.quick_parse(normalized_text, limit=5)

    if preview_instrs:
        print(f"\n📋 Preview (first {len(preview_instrs)} instructions):", file=sys.stderr)
        for idx, instr in enumerate(preview_instrs, 1):
            # Translate
            translation = translator.translate(instr)
            # Format instruction
            instr_text = instr.mnemonic
            if instr.operands:
                instr_text += " " + ", ".join(instr.operands)

            print(f"  {idx}. {instr_text:25s} → {translation}", file=sys.stderr)

        print(f"\n✅ Successfully parsed {len(preview_instrs)} instructions (preview)", file=sys.stderr)
        print(f"📊 Total: ~{total_lines} lines to process\n", file=sys.stderr)

        # Ask for confirmation
        try:
            response = input("Proceed with full analysis? [Y/n]: ")
            if response.lower() in ['n', 'no']:
                print("❌ Analysis cancelled", file=sys.stderr)
                sys.exit(0)
        except (EOFError, KeyboardInterrupt):
            # Default to yes on EOF/Ctrl+C
            print()

    return normalized_text, format_type


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

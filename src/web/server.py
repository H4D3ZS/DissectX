"""Flask web server for DissectX Web UI"""
import os
import json
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, Response
import tempfile

# Try to import WeasyPrint for PDF export
try:
    from weasyprint import HTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

# Try to import AutoExploiter (requires pwntools)
try:
    # Set environment variable to prevent pwntools from messing with signals/terminals
    os.environ['PWNLIB_NOTERM'] = '1'
    from src.exploitation.auto_exploiter import AutoExploiter
    AUTO_EXPLOITER_AVAILABLE = True
except ImportError:
    AUTO_EXPLOITER_AVAILABLE = False


class WebUIServer:
    """Web-based user interface server for binary analysis results"""
    
    def __init__(self, analysis_results: Optional[Dict[str, Any]] = None):
        """
        Initialize the Web UI server.
        
        Args:
            analysis_results: Dictionary containing analysis results
        """
        self.app = Flask(__name__, 
                        template_folder=self._get_template_folder(),
                        static_folder=self._get_static_folder())
        self.app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max file size
        self.analysis_results = analysis_results or {}
        self.port = 8080
        self.current_file = None
        self.current_filepath = None
        
        # Setup storage for recent scans
        self.scans_dir = Path(tempfile.gettempdir()) / 'dissectx_scans'
        self.scans_dir.mkdir(exist_ok=True)
        self.scans_db_path = self.scans_dir / 'scans.json'
        self.recent_scans = self._load_recent_scans()
        
        # Register routes
        self._register_routes()
    
    def _get_template_folder(self) -> str:
        """Get the path to the templates folder"""
        return str(Path(__file__).parent / 'templates')
    
    def _get_static_folder(self) -> str:
        """Get the path to the static folder"""
        return str(Path(__file__).parent / 'static')
    
    def _load_recent_scans(self) -> List[Dict[str, Any]]:
        """Load recent scans from storage"""
        if self.scans_db_path.exists():
            try:
                with open(self.scans_db_path, 'r') as f:
                    return json.load(f)
            except Exception:
                return []
        return []
    
    def _save_recent_scans(self):
        """Save recent scans to storage"""
        try:
            with open(self.scans_db_path, 'w') as f:
                json.dump(self.recent_scans, f, indent=2)
        except Exception as e:
            print(f"Error saving scans database: {e}")
    
    def _calculate_file_hash(self, file_path: str) -> Dict[str, str]:
        """Calculate multiple hashes for a file"""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for h in hashes.values():
                    h.update(chunk)
        
        return {name: h.hexdigest() for name, h in hashes.items()}
    
    def _add_scan_to_history(self, filename: str, file_path: str, hashes: Dict[str, str], 
                            analysis_summary: Dict[str, Any]):
        """Add a scan to the recent scans history"""
        scan_entry = {
            'id': hashes['sha256'][:16],  # Use first 16 chars of SHA256 as ID
            'filename': filename,
            'file_path': str(file_path),
            'timestamp': datetime.now().isoformat(),
            'hashes': hashes,
            'summary': analysis_summary
        }
        
        # Remove duplicate if exists (same SHA256)
        self.recent_scans = [s for s in self.recent_scans if s['hashes']['sha256'] != hashes['sha256']]
        
        # Add to beginning of list
        self.recent_scans.insert(0, scan_entry)
        
        # Keep only last 50 scans
        self.recent_scans = self.recent_scans[:50]
        
        # Save to disk
        self._save_recent_scans()
    
    def _generate_english_explanation(self, function_id, instructions, pseudocode):
        """Generate a plain English explanation of what the function does"""
        explanation_parts = []
        
        # Analyze the instructions to understand what the function does
        has_stack_setup = False
        has_function_calls = False
        has_comparisons = False
        has_loops = False
        has_memory_ops = False
        called_functions = []
        
        for instr in instructions:
            mnemonic = instr.mnemonic.lower() if instr.mnemonic else ""
            
            # Check for stack setup (function prologue)
            if mnemonic in ['push', 'sub'] and 'rsp' in str(instr.operands).lower():
                has_stack_setup = True
            
            # Check for function calls
            if mnemonic == 'call':
                has_function_calls = True
                if instr.operands:
                    called_functions.append(str(instr.operands[0]))
            
            # Check for comparisons/conditionals
            if mnemonic in ['cmp', 'test', 'je', 'jne', 'jg', 'jl', 'jge', 'jle']:
                has_comparisons = True
            
            # Check for loops
            if mnemonic in ['jmp', 'loop']:
                has_loops = True
            
            # Check for memory operations
            if mnemonic in ['mov', 'lea', 'load', 'store']:
                has_memory_ops = True
        
        # Build the explanation
        explanation_parts.append(f"This function at address {function_id}:")
        
        if has_stack_setup:
            explanation_parts.append("• Sets up a stack frame for local variables")
        
        if has_memory_ops:
            explanation_parts.append("• Performs memory operations (reading/writing data)")
        
        if has_comparisons:
            explanation_parts.append("• Contains conditional logic (if/else statements)")
        
        if has_loops:
            explanation_parts.append("• Contains loops or jumps")
        
        if has_function_calls:
            explanation_parts.append(f"• Calls {len(set(called_functions))} other function(s)")
            if called_functions[:3]:  # Show first 3
                explanation_parts.append(f"  - Examples: {', '.join(called_functions[:3])}")
        
        # Analyze pseudocode for additional context
        if pseudocode:
            if 'return' in pseudocode.lower():
                explanation_parts.append("• Returns a value to the caller")
            if 'void' in pseudocode.lower():
                explanation_parts.append("• Does not return a value (void function)")
        
        if not explanation_parts or len(explanation_parts) == 1:
            explanation_parts.append("• Performs basic operations")
        
        return "\n".join(explanation_parts)
    
    def _register_routes(self):
        """Register all Flask routes"""
        
        @self.app.route('/')
        def index():
            """Main dashboard page"""
            return render_template('index.html', 
                                 has_results=bool(self.analysis_results))
        
        @self.app.route('/analysis')
        def analysis():
            """Analysis results page"""
            if not self.analysis_results:
                return render_template('error.html', 
                                     error="No analysis results available")
            
            return render_template('analysis.html', 
                                 results=self.analysis_results)
        
        @self.app.route('/functions')
        def functions():
            """Functions listing page"""
            functions_data = self.analysis_results.get('functions', {})
            return render_template('functions.html', 
                                 functions=functions_data)
        
        @self.app.route('/advanced')
        def advanced_analysis():
            """Advanced detection results page"""
            advanced_data = self.analysis_results.get('advanced_analysis', {})
            return render_template('advanced_analysis.html', 
                                 advanced=advanced_data)
        
        @self.app.route('/graph')
        def call_graph():
            """Interactive call graph visualization"""
            graph_data = self.analysis_results.get('call_graph', {})
            return render_template('graph.html', 
                                 graph=graph_data)
        
        @self.app.route('/recent-scans')
        def recent_scans():
            """Recent scans history page"""
            return render_template('recent_scans.html', 
                                 scans=self.recent_scans)
                                 
        @self.app.route('/exploitation')
        def exploitation():
            """Exploitation tools dashboard"""
            return render_template('exploitation.html', 
                                 results=self.analysis_results,
                                 filename=self.current_file,
                                 filepath=self.current_filepath)
        
        @self.app.route('/scan/<scan_id>')
        def view_scan(scan_id):
            """View a specific scan from history"""
            # Find the scan
            scan = next((s for s in self.recent_scans if s['id'] == scan_id), None)
            
            if not scan:
                return render_template('error.html', 
                                     error=f"Scan {scan_id} not found")
            
            # Load the analysis results for this scan
            scan_file_path = Path(scan['file_path'])
            
            if not scan_file_path.exists():
                return render_template('error.html', 
                                     error=f"Binary file no longer exists")
            
            try:
                # Re-analyze or load cached results
                from src.binary_analyzer import BinaryAnalyzer
                
                analyzer = BinaryAnalyzer()
                raw_results = analyzer.analyze_binary(
                    str(scan_file_path), 
                    advanced=True, 
                    emulate=True, 
                    decrypt_strings=True
                )
                
                # Build results similar to upload route
                strings = raw_results.get('all_strings', [])
                security_strings = raw_results.get('security_strings', [])
                base64_strings = raw_results.get('base64_strings', [])
                api_calls = raw_results.get('api_calls', {})
                file_type = raw_results.get('file_type', 'Unknown')
                advanced_data = raw_results.get('advanced_analysis', {})
                
                scan_results = {
                    'binary_info': {
                        'filename': scan['filename'],
                        'filepath': str(scan_file_path),
                        'file_type': file_type,
                        'hashes': scan['hashes'],
                        'scan_date': scan['timestamp'],
                        'total_strings': len(strings),
                        'security_strings': len(security_strings)
                    },
                    'strings': [{'value': s, 'address': 'N/A'} for s in strings[:500]],
                    'security_strings': [{'value': s, 'address': 'N/A'} for s in security_strings],
                    'advanced_analysis': advanced_data
                }
                
                return render_template('scan_detail.html', 
                                     scan=scan,
                                     results=scan_results)
                
            except Exception as e:
                return render_template('error.html', 
                                     error=f"Error loading scan: {str(e)}")
        
        @self.app.route('/function/<function_id>')
        def function_detail(function_id):
            """Detailed view of a specific function"""
            functions_data = self.analysis_results.get('functions', {})
            function = functions_data.get(function_id)
            
            if not function:
                return render_template('error.html', 
                                     error=f"Function {function_id} not found")
            
            # Generate pseudocode and extract instructions on-demand if not already present
            if 'pseudocode' not in function or function.get('pseudocode') is None:
                disassembly = self.analysis_results.get('disassembly')
                if disassembly:
                    try:
                        from src.decompiler import Decompiler
                        from src.parser import AssemblyParser
                        
                        parser = AssemblyParser()
                        decompiler = Decompiler()
                        
                        # Parse the entire disassembly
                        instructions = parser.parse(disassembly)
                        
                        if instructions:
                            # DEBUG: Log what we're working with
                            print(f"[DEBUG] Function ID: {function_id}")
                            print(f"[DEBUG] Total instructions parsed: {len(instructions)}")
                            
                            # Count how many have addresses
                            with_addr = sum(1 for i in instructions if i.address is not None)
                            print(f"[DEBUG] Instructions with addresses: {with_addr}/{len(instructions)}")
                            
                            if instructions and instructions[0].address:
                                print(f"[DEBUG] First instruction address: {instructions[0].address}")
                            if instructions and instructions[-1].address:
                                print(f"[DEBUG] Last instruction address: {instructions[-1].address}")
                            
                            # Extract address for matching
                            func_addr_clean = function_id.strip().lower().replace('0x', '')
                            
                            # Find the starting instruction that matches our function address
                            start_idx = None
                            for i, instr in enumerate(instructions):
                                if instr.address:
                                    instr_addr = str(instr.address).lower().replace('0x', '').strip()
                                    
                                    # Check if this instruction's address matches our function
                                    if (func_addr_clean in instr_addr or
                                        instr_addr in func_addr_clean or
                                        (len(func_addr_clean) >= 6 and len(instr_addr) >= 6 and
                                         func_addr_clean[-6:] in instr_addr) or
                                        (len(func_addr_clean) >= 4 and len(instr_addr) >= 4 and
                                         func_addr_clean[-4:] == instr_addr[-4:])):
                                        start_idx = i
                                        print(f"[DEBUG] Found function start at index {i}, address: {instr.address}")
                                        break
                            
                            function_instructions = []
                            
                            if start_idx is not None:
                                # Found the function start, now collect all instructions until next function
                                # or until we see a significant address jump
                                last_addr = None
                                for i in range(start_idx, len(instructions)):
                                    instr = instructions[i]
                                    
                                    # Check if we've hit a new function boundary
                                    # (significant address jump or explicit function marker)
                                    if instr.address and last_addr:
                                        try:
                                            curr_addr_int = int(str(instr.address).replace('0x', ''), 16)
                                            last_addr_int = int(str(last_addr).replace('0x', ''), 16)
                                            
                                            # If address jumped by more than 0x1000 (4096 bytes), likely a new function
                                            if curr_addr_int - last_addr_int > 0x1000:
                                                print(f"[DEBUG] Address jump detected at index {i}, stopping")
                                                break
                                        except (ValueError, TypeError):
                                            pass
                                    
                                    function_instructions.append(instr)
                                    
                                    if instr.address:
                                        last_addr = instr.address
                                    
                                    # Primary limit: 20 instructions for display
                                    if len(function_instructions) >= 20:
                                        print(f"[DEBUG] Reached 20 instruction display limit")
                                        break
                                    
                                    # Safety limit: don't include more than 500 instructions
                                    if len(function_instructions) >= 500:
                                        print(f"[DEBUG] Hit 500 instruction safety limit")
                                        break
                                
                                print(f"[DEBUG] Extracted {len(function_instructions)} instructions for function")
                            else:
                                # Couldn't find function start, use first 20 instructions as fallback
                                print(f"[DEBUG] Could not find function start, using first 20 instructions")
                                function_instructions = instructions[:20]
                            
                            if function_instructions:
                                # Store the instructions for display
                                function['instructions'] = function_instructions
                                
                                # Generate pseudocode
                                pseudocode = decompiler.decompile_function(function_instructions)
                                function['pseudocode'] = pseudocode
                                print(f"[DEBUG] Generated pseudocode: {len(pseudocode) if pseudocode else 0} chars")
                                
                                # Generate English explanation
                                english_explanation = self._generate_english_explanation(
                                    function_id, 
                                    function_instructions, 
                                    pseudocode
                                )
                                function['english_explanation'] = english_explanation
                                print(f"[DEBUG] Generated English explanation: {len(english_explanation) if english_explanation else 0} chars")
                            else:
                                function['instructions'] = []
                                function['pseudocode'] = None
                                function['english_explanation'] = None
                    except Exception as e:
                        # If generation fails, set to None
                        function['instructions'] = []
                        function['pseudocode'] = None
            
            return render_template('function_detail.html', 
                                 function_id=function_id,
                                 function=function)
        
        @self.app.route('/strings')
        def strings():
            """Strings listing page"""
            strings_data = self.analysis_results.get('strings', [])
            return render_template('strings.html', 
                                 strings=strings_data)
        
        @self.app.route('/xrefs')
        def xrefs():
            """Cross-references page"""
            xrefs_data = self.analysis_results.get('xrefs', {})
            return render_template('xrefs.html', 
                                 xrefs=xrefs_data)
        
        @self.app.route('/api/results')
        def api_results():
            """API endpoint to get analysis results as JSON"""
            return jsonify(self.analysis_results)
        
        @self.app.route('/upload', methods=['POST'])
        def upload():
            """Handle binary file upload and trigger analysis"""
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
            
            file = request.files['file']
            
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
            
            try:
                # Save the uploaded file to a permanent location for history
                file_path = self.scans_dir / file.filename
                file.save(str(file_path))
                
                # Set executable permission for the binary
                import stat
                os.chmod(str(file_path), os.stat(str(file_path)).st_mode | stat.S_IEXEC | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                
                # Calculate file hashes
                file_hashes = self._calculate_file_hash(str(file_path))
                
                # Import the analyzer
                from src.binary_analyzer import BinaryAnalyzer
                
                # Check file size for optimization
                file_size = os.path.getsize(str(file_path))
                quick_mode = file_size > 10 * 1024 * 1024  # > 10MB
                
                if quick_mode:
                    print(f"⚡ Large file detected ({file_size/1024/1024:.2f} MB). Enabling Quick Mode (skipping disassembly/emulation).")

                # Create analyzer and analyze the binary
                analyzer = BinaryAnalyzer()
                # Enable all advanced features
                raw_results = analyzer.analyze_binary(
                    str(file_path), 
                    advanced=True, 
                    emulate=not quick_mode, # Skip emulation in quick mode
                    decrypt_strings=not quick_mode, # Skip decryption in quick mode
                    quick_mode=quick_mode
                )
                
                # Extract key data
                strings = raw_results.get('all_strings', [])
                security_strings = raw_results.get('security_strings', [])
                base64_strings = raw_results.get('base64_strings', [])
                api_calls = raw_results.get('api_calls', {})
                file_type = raw_results.get('file_type', 'Unknown')
                
                # Advanced analysis data
                advanced_data = raw_results.get('advanced_analysis', {})
                syscalls = advanced_data.get('syscalls', [])
                api_hashes = advanced_data.get('api_hashing', [])
                junk_patterns = advanced_data.get('junk_code', [])
                flags = advanced_data.get('flags', [])
                decrypted_strings = advanced_data.get('decrypted_strings', [])
                
                # Combine flags
                advanced_flags = []
                if flags:
                    for flag in flags:
                        advanced_flags.append({
                            'type': 'PlainText',
                            'value': flag,
                            'confidence': 'High'
                        })
                
                # Disassembly and Call Graph
                disassembly = None
                if not quick_mode:
                    disassembly = analyzer.disassemble_binary(str(file_path))
                
                # CALL GRAPH GENERATION
                call_graph_data = {}
                functions = {}
                
                if disassembly:
                    try:
                        from src.call_graph_generator import CallGraphGenerator
                        from src.parser import AssemblyParser
                        
                        # Parse instructions
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
                            if analyzer.function_to_strings and hex(func_addr) in analyzer.function_to_strings:
                                func_strings = analyzer.function_to_strings[hex(func_addr)]
                            
                            # Generate explanation
                            explanation = []
                            if is_entry: explanation.append("🚀 ENTRY POINT")
                            if is_recursive: explanation.append("🔄 RECURSIVE")
                            if is_dead: explanation.append("💀 DEAD CODE")
                            
                            if callees:
                                explanation.append(f"Calls {len(callees)} function(s)")
                            else:
                                explanation.append("Leaf function")
                                
                            if func_strings:
                                explanation.append(f"References {len(func_strings)} string(s)")
                            
                            function_details[hex(func_addr)] = {
                                'address': hex(func_addr),
                                'is_entry': is_entry,
                                'is_recursive': is_recursive,
                                'is_dead': is_dead,
                                'callers': [hex(c) for c in callers],
                                'callees': [hex(c) for c in callees],
                                'caller_count': len(callers),
                                'callee_count': len(callees),
                                'strings': func_strings[:5],
                                'explanation': '\n'.join(explanation)
                            }
                        
                        # Export call graph data
                        call_graph_data = {
                            'entry_points': [hex(addr) for addr in sorted(call_graph.entry_points)],
                            'recursive_functions': [hex(addr) for addr in sorted(call_graph.recursive_functions)],
                            'dead_code': [hex(addr) for addr in sorted(call_graph.dead_code)],
                            'mermaid': cg_generator.export_mermaid(),
                            'ascii': cg_generator.export_ascii(),
                            'total_functions': len(call_graph.get_all_functions()),
                            'total_calls': call_graph.graph.number_of_edges(),
                            'function_details': function_details
                        }
                        
                        # Build functions dict for listing
                        if analyzer.function_to_strings:
                            for func_addr, func_strings in analyzer.function_to_strings.items():
                                functions[func_addr] = {
                                    'name': f'sub_{func_addr}',
                                    'strings': func_strings,
                                    'string_count': len(func_strings)
                                }
                                
                    except Exception as e:
                        print(f"Call graph generation failed: {e}")
                
                # Construct the full analysis results dictionary
                self.analysis_results = {
                    'binary_info': {
                        'filename': file.filename,
                        'filepath': str(file_path),
                        'file_type': file_type,
                        'architecture': 'x86_64' if '64' in file_type else 'x86', # Simple heuristic
                        'format': 'PE' if 'PE' in file_type else 'ELF' if 'ELF' in file_type else 'Unknown',
                        'total_strings': len(strings),
                        'security_strings': len(security_strings),
                        'base64_strings': len(base64_strings),
                        'hashes': file_hashes
                    },
                    'strings': [
                        {'value': s, 'address': 'N/A'} for s in strings[:500]
                    ],
                    'security_strings': [
                        {'value': s, 'address': 'N/A'} for s in security_strings
                    ],
                    'base64_strings': base64_strings,
                    'api_calls': api_calls,
                    'flags': flags,
                    'functions': functions,
                    'xrefs': {
                        'string_refs': analyzer.string_to_functions,
                        'function_strings': analyzer.function_to_strings
                    },
                    'disassembly': disassembly if disassembly else None,
                    'advanced_analysis': {
                        'syscalls': syscalls,
                        'api_hashes': api_hashes,
                        'junk_patterns': junk_patterns,
                        'advanced_flags': advanced_flags,
                        'decrypted_strings': decrypted_strings
                    },
                    'call_graph': call_graph_data
                }
                
                # Store current file info for exploitation page
                self.current_file = file.filename
                self.current_filepath = str(file_path)
                
                # Add to scan history
                analysis_summary = {
                    'file_type': file_type,
                    'total_strings': len(strings),
                    'total_functions': len(functions),
                    'security_flags': len(flags),
                    'syscalls': len(syscalls)
                }
                self._add_scan_to_history(file.filename, file_path, file_hashes, analysis_summary)
                
                # Return success response with redirect
                return jsonify({
                    'success': True,
                    'message': 'Analysis complete',
                    'redirect': '/'
                })
                
            except Exception as e:
                return jsonify({'error': f'Analysis failed: {str(e)}'}), 500
        
        @self.app.route('/api/search')
        def api_search():
            """API endpoint for searching analysis results"""
            query = request.args.get('q', '')
            search_type = request.args.get('type', 'all')
            
            results = self._search_results(query, search_type)
            return jsonify(results)
            
        # ==========================================
        # Exploitation API Endpoints
        # ==========================================
        
        @self.app.route('/api/pattern/create')
        def api_pattern_create():
            try:
                length = int(request.args.get('length', 100))
                from src.utils.pattern_tools import PatternGenerator
                pg = PatternGenerator()
                pattern = pg.create(length)
                return jsonify({'pattern': pattern})
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        @self.app.route('/api/pattern/offset')
        def api_pattern_offset():
            try:
                value = request.args.get('value', '')
                from src.utils.pattern_tools import PatternGenerator
                pg = PatternGenerator()
                offset = pg.offset(value)
                return jsonify({'offset': offset})
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        @self.app.route('/api/shellcode/list')
        def api_shellcode_list():
            try:
                from src.utils.shellcode_manager import ShellcodeManager
                sm = ShellcodeManager()
                shellcodes = sm.list_shellcodes()
                # Convert bytes to hex string for JSON serialization
                for sc in shellcodes:
                    if 'code' in sc and isinstance(sc['code'], bytes):
                        sc['code'] = sc['code'].hex()
                return jsonify({'shellcodes': shellcodes})
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        @self.app.route('/api/shellcode/get')
        def api_shellcode_get():
            try:
                shellcode_id = request.args.get('id', '')
                encode = request.args.get('encode', 'false').lower() == 'true'
                polymorph = request.args.get('polymorph', 'false').lower() == 'true'
                
                from src.utils.shellcode_manager import ShellcodeManager
                sm = ShellcodeManager()
                shellcode = sm.get_shellcode(shellcode_id)
                
                if not shellcode:
                    return jsonify({'error': 'Shellcode not found'}), 404
                
                # Apply mutations if requested
                if polymorph:
                    from src.exploitation.polymorphic_engine import PolymorphicEngine
                    pe = PolymorphicEngine()
                    # Arch detection is simple here, assuming x64 for demo
                    shellcode = pe.mutate(shellcode, arch='x64')
                
                if encode:
                    from src.exploitation.payload_encoder import PayloadEncoder
                    pe = PayloadEncoder()
                    shellcode, key = pe.encode_xor(shellcode)
                
                # Format as hex string for display
                formatted = "".join([f"\\x{b:02x}" for b in shellcode])
                return jsonify({'code': formatted})
            except Exception as e:
                return jsonify({'error': str(e)}), 400

        @self.app.route('/api/exploit/auto')
        def api_exploit_auto():
            try:
                filepath = request.args.get('filepath', '')
                encode = request.args.get('encode', 'false').lower() == 'true'
                polymorph = request.args.get('polymorph', 'false').lower() == 'true'
                
                if not filepath or not os.path.exists(filepath):
                    return jsonify({'error': 'File not found'}), 404
                
                if not AUTO_EXPLOITER_AVAILABLE:
                    return jsonify({'error': 'AutoExploiter not available. Please install pwntools: pip install pwntools'}), 500
                
                exploiter = AutoExploiter()
                
                # Find offset
                print(f"[*] Finding buffer overflow offset for {filepath}")
                offset, buffer_addr = exploiter.find_offset(filepath)
                
                if offset == -1:
                    return jsonify({'error': 'Could not find buffer overflow offset'}), 200
                
                # Generate exploit
                use_encoding = request.args.get('encode', 'false').lower() == 'true'
                use_polymorph = request.args.get('polymorph', 'false').lower() == 'true'
                auto_run = request.args.get('autorun', 'true').lower() == 'true'
                
                # Remote exploitation parameters
                remote = request.args.get('remote', 'false').lower() == 'true'
                remote_host = request.args.get('host', None) if remote else None
                remote_port = int(request.args.get('port', 0)) if remote and request.args.get('port') else None
                
                print(f"[DEBUG] About to call generate_exploit with offset={offset}, buffer_addr={hex(buffer_addr)}")
                if remote_host and remote_port:
                    print(f"[+] Remote exploitation enabled: {remote_host}:{remote_port}")
                
                script = exploiter.generate_exploit(filepath, offset, buffer_addr, use_encoding, use_polymorph, remote_host, remote_port)
                print(f"[DEBUG] generate_exploit returned, script length: {len(script)}")
                
                response_data = {
                    'offset': offset,
                    'buffer_address': hex(buffer_addr) if buffer_addr else None,
                    'script': script
                }
                
                # Auto-execute if requested
                if auto_run:
                    print(f"[*] Auto-executing exploit...")
                    exec_result = exploiter.execute_exploit(filepath, script, timeout=5)
                    response_data['execution'] = exec_result
                
                return jsonify(response_data)
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 500
        
        @self.app.route('/export/html')
        def export_html():
            """Export analysis results as HTML"""
            html_content = self.generate_report(self.analysis_results)
            
            # Create a temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', 
                                            delete=False) as f:
                f.write(html_content)
                temp_path = f.name
            
            return send_file(temp_path, 
                           as_attachment=True,
                           download_name='dissectx_report.html',
                           mimetype='text/html')
        
        @self.app.route('/export/pdf')
        def export_pdf():
            """Export analysis results as PDF"""
            if not WEASYPRINT_AVAILABLE:
                return jsonify({
                    'error': 'PDF export requires weasyprint library'
                }), 500
            
            try:
                pdf_bytes = self.export_pdf(self.analysis_results)
                
                # Create a temporary file
                with tempfile.NamedTemporaryFile(mode='wb', suffix='.pdf', 
                                                delete=False) as f:
                    f.write(pdf_bytes)
                    temp_path = f.name
                
                return send_file(temp_path,
                               as_attachment=True,
                               download_name='dissectx_report.pdf',
                               mimetype='application/pdf')
            except Exception as e:
                return jsonify({'error': str(e)}), 500

        # ============================================================================
        # CTF TOOLS ROUTES
        # ============================================================================

        @self.app.route('/tools')
        def tools():
            """CTF tools dashboard"""
            from flask import render_template
            return render_template('tools.html')

        @self.app.route('/tools/cyberchef')
        def cyberchef():
            """CyberChef offline integration"""
            from flask import render_template
            return render_template('cyberchef.html')

        @self.app.route('/api/tools/hash/identify', methods=['POST'])
        def identify_hash():
            """Identify hash type"""
            from src.utils.hash_identifier import HashIdentifier
            from flask import request, jsonify
            
            data = request.get_json()
            hash_string = data.get('hash', '')
            
            results = HashIdentifier.identify(hash_string)
            return jsonify({"results": results})

        @self.app.route('/api/tools/cipher/decode', methods=['POST'])
        def decode_cipher():
            """Decode common ciphers"""
            from src.utils.cipher_tools import CipherTools
            from flask import request, jsonify
            
            data = request.get_json()
            cipher_type = data.get('type', 'rot13')
            text = data.get('text', '')
            key = data.get('key', '')
            
            if cipher_type == 'rot13':
                result = CipherTools.rot13(text)
            elif cipher_type == 'caesar_brute':
                result = CipherTools.caesar_bruteforce(text)
            elif cipher_type == 'atbash':
                result = CipherTools.atbash(text)
            elif cipher_type == 'vigenere' and key:
                result = CipherTools.vigenere_decrypt(text, key)
            elif cipher_type == 'base64':
                result = CipherTools.base64_decode(text)
            elif cipher_type == 'hex':
                result = CipherTools.hex_decode(text)
            else:
                result = "Unknown cipher type"
            
            return jsonify({" result": result})
        
        # New Crypto Tools API Routes
        @self.app.route('/tools/crypto')
        def crypto_tools():
            """Cryptography tools page"""
            from flask import render_template
            return render_template('tools_crypto.html')
        
        @self.app.route('/api/crypto/rsa/attack', methods=['POST'])
        def rsa_attack():
            """RSA attack endpoint"""
            from src.utils.rsa_tools import RSATools
            from flask import request, jsonify
            
            data = request.get_json()
            try:
                n = int(data.get('n', '0'))
                e = int(data.get('e', '0'))
                c = int(data.get('c', '0'))
                
                result = RSATools.attack_rsa(n, e, c)
                
                # Try to convert plaintext to text
                plaintext_text = None
                if result['plaintext']:
                    try:
                        # Convert to bytes and decode
                        plaintext_bytes = result['plaintext'].to_bytes(
                            (result['plaintext'].bit_length() + 7) // 8, 
                            byteorder='big'
                        )
                        plaintext_text = plaintext_bytes.decode('utf-8', errors='ignore')
                    except:
                        pass
                
                return jsonify({
                    'success': result['success'],
                    'method': result['method'],
                    'plaintext': str(result['plaintext']) if result['plaintext'] else None,
                    'plaintext_text': plaintext_text,
                    'factors': result['factors']
                })
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)}), 400
        
        @self.app.route('/api/crypto/xor/single', methods=['POST'])
        def xor_single():
            """Single-byte XOR bruteforce"""
            from src.utils.xor_tools import XORTools
            from flask import request, jsonify
            
            data = request.get_json()
            try:
                ciphertext_hex = data.get('ciphertext', '')
                ciphertext = bytes.fromhex(ciphertext_hex)
                
                results = XORTools.single_byte_xor_bruteforce(ciphertext, top_n=5)
                
                formatted_results = []
                for key, plaintext, score in results:
                    try:
                        plaintext_str = plaintext.decode('utf-8', errors='ignore')
                    except:
                        plaintext_str = repr(plaintext)
                    
                    formatted_results.append({
                        'key': key,
                        'plaintext': plaintext_str,
                        'score': score
                    })
                
                return jsonify({'results': formatted_results})
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/api/crypto/xor/repeating', methods=['POST'])
        def xor_repeating():
            """Repeating-key XOR breaker"""
            from src.utils.xor_tools import XORTools
            from flask import request, jsonify
            
            data = request.get_json()
            try:
                ciphertext_hex = data.get('ciphertext', '')
                keylen = data.get('keylen')
                
                ciphertext = bytes.fromhex(ciphertext_hex)
                
                key, plaintext = XORTools.break_repeating_key_xor(ciphertext, keylen)
                
                return jsonify({
                    'key_hex': key.hex(),
                    'key_text': key.decode('utf-8', errors='ignore'),
                    'plaintext': plaintext.decode('utf-8', errors='ignore')
                })
            except Exception as e:
                return jsonify({'error': str(e)}), 400
        
        # Steganography Tools API Routes
        @self.app.route('/tools/stego')
        def stego_tools():
            """Steganography tools page"""
            from flask import render_template
            return render_template('tools_stego.html')
        
        @self.app.route('/api/stego/lsb/extract', methods=['POST'])
        def lsb_extract():
            """LSB extraction endpoint"""
            from src.utils.steg_lsb import LSBExtractor
            from flask import request, jsonify
            import os
            import tempfile
            
            if 'image' not in request.files:
                return jsonify({'error': 'No image provided'}), 400
            
            image_file = request.files['image']
            channel = request.form.get('channel', 'all')
            bits = int(request.form.get('bits', 1))
            
            try:
                # Save uploaded file temporarily
                with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
                    image_file.save(tmp.name)
                    tmp_path = tmp.name
                
                # Extract LSB
                data = LSBExtractor.extract_lsb(tmp_path, bits, channel)
                
                # Clean up
                os.unlink(tmp_path)
                
                # Try to decode as text for preview
                try:
                    preview = data[:500].decode('utf-8', errors='ignore')
                except:
                    preview = data[:500].hex()
                
                return jsonify({
                    'data': data.hex(),
                    'preview': preview,
                    'length': len(data)
                })
            except Exception as e:
                if 'tmp_path' in locals():
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/api/stego/lsb/auto', methods=['POST'])
        def lsb_auto():
            """Auto-detect LSB hidden data"""
            from src.utils.steg_lsb import LSBExtractor
            from flask import request, jsonify
            import os
            import tempfile
            
            if 'image' not in request.files:
                return jsonify({'error': 'No image provided'}), 400
            
            image_file = request.files['image']
            
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
                    image_file.save(tmp.name)
                    tmp_path = tmp.name
                
                results = LSBExtractor.auto_detect_hidden_data(tmp_path)
                os.unlink(tmp_path)
                
                if not results:
                    return jsonify({'results': []})
                
                return jsonify({'results': results})
            except Exception as e:
                if 'tmp_path' in locals():
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
                return jsonify({'error': str(e)}), 400
        
        @self.app.route('/api/stego/forensics', methods=['POST'])
        def stego_forensics():
            """Image forensics analysis"""
            from src.utils.image_forensics import ImageForensics
            from flask import request, jsonify
            import os
            import tempfile
            
            if 'image' not in request.files:
                return jsonify({'error': 'No image provided'}), 400
            
            image_file = request.files['image']
            analysis_type = request.form.get('type', 'metadata')
            
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp:
                    image_file.save(tmp.name)
                    tmp_path = tmp.name
                
                if analysis_type == 'metadata':
                    result = ImageForensics.extract_metadata(tmp_path)
                elif analysis_type == 'color_planes':
                    result = ImageForensics.separate_color_planes(tmp_path)
                elif analysis_type == 'bit_planes':
                    channel = request.form.get('channel', 'red')
                    result = ImageForensics.extract_bit_planes(tmp_path, channel)
                elif analysis_type == 'transformations':
                    result = ImageForensics.apply_transformations(tmp_path)
                elif analysis_type == 'anomalies':
                    result = ImageForensics.detect_anomalies(tmp_path)
                else:
                    result = {'error': 'Unknown analysis type'}
                
                os.unlink(tmp_path)
                return jsonify(result)
            except Exception as e:
                if 'tmp_path' in locals():
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
                return jsonify({'error': str(e)}), 400
    
    
    def _search_results(self, query: str, search_type: str) -> Dict[str, Any]:
        """
        Search through analysis results.
        
        Args:
            query: Search query string
            search_type: Type of search ('all', 'strings', 'functions', 'code')
            
        Returns:
            Dictionary containing search results
        """
        results = {
            'query': query,
            'type': search_type,
            'matches': []
        }
        
        if not query:
            return results
        
        query_lower = query.lower()
        
        # Search strings
        if search_type in ['all', 'strings']:
            strings_data = self.analysis_results.get('strings', [])
            for string in strings_data:
                if isinstance(string, str) and query_lower in string.lower():
                    results['matches'].append({
                        'type': 'string',
                        'value': string
                    })
                elif isinstance(string, dict):
                    string_value = string.get('value', '')
                    if query_lower in string_value.lower():
                        results['matches'].append({
                            'type': 'string',
                            'value': string_value,
                            'address': string.get('address')
                        })
        
        # Search functions
        if search_type in ['all', 'functions']:
            functions_data = self.analysis_results.get('functions', {})
            for func_id, func_data in functions_data.items():
                if isinstance(func_data, dict):
                    func_name = func_data.get('name', '')
                    if query_lower in func_name.lower() or query_lower in func_id.lower():
                        results['matches'].append({
                            'type': 'function',
                            'id': func_id,
                            'name': func_name
                        })
        
        # Search in instructions/code
        if search_type in ['all', 'code']:
            instructions = self.analysis_results.get('instructions', [])
            for instr in instructions:
                if isinstance(instr, dict):
                    mnemonic = instr.get('mnemonic', '')
                    operands = ' '.join(instr.get('operands', []))
                    if query_lower in mnemonic.lower() or query_lower in operands.lower():
                        results['matches'].append({
                            'type': 'instruction',
                            'address': instr.get('address'),
                            'mnemonic': mnemonic,
                            'operands': operands
                        })
        
        return results
    
    def start(self, port: int = 8080, debug: bool = False):
        """
        Start the Flask web server.
        
        Args:
            port: Port number to listen on
            debug: Enable debug mode
        """
        self.port = port
        print(f"Starting DissectX Web UI on http://localhost:{port}")
        print(f"Press Ctrl+C to stop the server")
        self.app.run(host='0.0.0.0', port=port, debug=debug)
    
    def generate_report(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate an HTML report from analysis results.
        
        Args:
            analysis_results: Dictionary containing analysis results
            
        Returns:
            HTML string
        """
        # Generate a comprehensive HTML report
        html_parts = []
        
        html_parts.append("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DissectX Analysis Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .section {
            background: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .code {
            background: #f8f9fa;
            padding: 10px;
            border-left: 3px solid #007bff;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #007bff;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .badge-info { background: #17a2b8; color: white; }
        .badge-warning { background: #ffc107; color: #333; }
        .badge-danger { background: #dc3545; color: white; }
    </style>
</head>
<body>
    <h1>DissectX Binary Analysis Report</h1>
""")
        
        # Binary Information
        binary_info = analysis_results.get('binary_info', {})
        if binary_info:
            html_parts.append('<div class="section">')
            html_parts.append('<h2>Binary Information</h2>')
            html_parts.append('<table>')
            for key, value in binary_info.items():
                html_parts.append(f'<tr><th>{key}</th><td>{value}</td></tr>')
            html_parts.append('</table>')
            html_parts.append('</div>')
        
        # Strings
        strings_data = analysis_results.get('strings', [])
        if strings_data:
            html_parts.append('<div class="section">')
            html_parts.append(f'<h2>Strings ({len(strings_data)})</h2>')
            html_parts.append('<table>')
            html_parts.append('<tr><th>String</th><th>Address</th></tr>')
            for string in strings_data[:100]:  # Limit to first 100
                if isinstance(string, str):
                    html_parts.append(f'<tr><td>{self._escape_html(string)}</td><td>-</td></tr>')
                elif isinstance(string, dict):
                    value = string.get('value', '')
                    address = string.get('address', '-')
                    html_parts.append(f'<tr><td>{self._escape_html(value)}</td><td>{address}</td></tr>')
            html_parts.append('</table>')
            html_parts.append('</div>')
        
        # Functions
        functions_data = analysis_results.get('functions', {})
        if functions_data:
            html_parts.append('<div class="section">')
            html_parts.append(f'<h2>Functions ({len(functions_data)})</h2>')
            html_parts.append('<table>')
            html_parts.append('<tr><th>Address</th><th>Name</th><th>Size</th></tr>')
            for func_id, func_data in list(functions_data.items())[:50]:  # Limit to first 50
                if isinstance(func_data, dict):
                    name = func_data.get('name', func_id)
                    size = func_data.get('size', '-')
                    html_parts.append(f'<tr><td>{func_id}</td><td>{name}</td><td>{size}</td></tr>')
            html_parts.append('</table>')
            html_parts.append('</div>')
        
        html_parts.append('</body></html>')
        
        return '\n'.join(html_parts)
    
    def export_pdf(self, analysis_results: Dict[str, Any]) -> bytes:
        """
        Export analysis results as PDF.
        
        Args:
            analysis_results: Dictionary containing analysis results
            
        Returns:
            PDF file as bytes
        """
        if not WEASYPRINT_AVAILABLE:
            raise ImportError("PDF export requires weasyprint library")
        
        # Generate HTML report
        html_content = self.generate_report(analysis_results)
        
        # Convert HTML to PDF
        pdf_bytes = HTML(string=html_content).write_pdf()
        
        return pdf_bytes
    
    def serve_static_files(self):
        """Serve static files (CSS, JS, images)"""
        # Static files are automatically served by Flask from the static folder
        pass
    
    def handle_navigation(self, request: Any) -> Response:
        """
        Handle navigation requests.
        
        Args:
            request: Flask request object
            
        Returns:
            Flask response
        """
        # Navigation is handled by the route decorators
        pass
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))


def create_app(analysis_results: Optional[Dict[str, Any]] = None) -> Flask:
    """
    Factory function to create Flask app.
    
    Args:
        analysis_results: Dictionary containing analysis results
        
    Returns:
        Flask application instance
    """
    server = WebUIServer(analysis_results)
    return server.app

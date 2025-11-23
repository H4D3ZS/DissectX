"""Binary analyzer for extracting strings and metadata from executables"""
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

# Import advanced detection modules
try:
    from .detectors.syscall_detector import SyscallDetector
    from .detectors.api_hash_resolver import APIHashResolver
    from .detectors.junk_detector import JunkDetector
    from .detectors.junk_detector import JunkDetector
    from .detectors.flag_finder import FlagFinder
    from .detectors.checksec_detector import ChecksecDetector
    from .detectors.vulnerability_detector import VulnerabilityDetector
    
    # Emulation and Memory Analysis
    from .emulation.unicorn_emulator import UnicornEmulator, UNICORN_AVAILABLE
    from .emulation.string_decryptor import StringDecryptor
    from .pe.memory_parser import MemoryPEParser, PEFILE_AVAILABLE
    from .pe.memory_dump_analyzer import MemoryDumpAnalyzer
    
    ADVANCED_DETECTORS_AVAILABLE = True
except ImportError:
    ADVANCED_DETECTORS_AVAILABLE = False
    UNICORN_AVAILABLE = False
    PEFILE_AVAILABLE = False


class BinaryAnalyzer:
    """Analyzes binary executables to extract strings and metadata"""
    
    def __init__(self):
        """Initialize the binary analyzer"""
        self.security_keywords = [
            'password', 'passwd', 'pwd',
            'flag', 'key', 'secret',
            'check', 'verify', 'validate',
            'input', 'enter', 'prompt',
            'correct', 'wrong', 'invalid',
            'success', 'fail', 'error',
            'admin', 'root', 'user',
            'token', 'auth', 'login',
            'encrypt', 'decrypt', 'hash',
            'canary', 'cookie', 'stack'
        ]
        
        # String-to-function tracking (bidirectional mapping)
        self.string_to_functions = {}  # string -> [function_addresses]
        self.function_to_strings = {}  # function_address -> [strings]
        
        # Initialize advanced detectors if available
        if ADVANCED_DETECTORS_AVAILABLE:
            self.syscall_detector = SyscallDetector()
            self.api_hash_resolver = APIHashResolver()
            self.junk_detector = JunkDetector()
            self.junk_detector = JunkDetector()
            self.flag_finder = FlagFinder()
            self.checksec_detector = ChecksecDetector()
            self.vulnerability_detector = VulnerabilityDetector()
            
            # Initialize Emulation & Memory tools
            self.string_decryptor = StringDecryptor() if UNICORN_AVAILABLE else None
            self.memory_parser = MemoryPEParser() if PEFILE_AVAILABLE else None
            self.memory_analyzer = MemoryDumpAnalyzer() if PEFILE_AVAILABLE else None
        else:
            self.syscall_detector = None
            self.api_hash_resolver = None
            self.junk_detector = None
            self.junk_detector = None
            self.flag_finder = None
            self.checksec_detector = None
            self.vulnerability_detector = None
            self.string_decryptor = None
            self.memory_parser = None
            self.memory_analyzer = None
        
        # Windows API functions of interest
        self.windows_api_functions = {
            # File operations
            'CreateFile': 'Creates or opens a file',
            'WriteFile': 'Writes data to a file',
            'ReadFile': 'Reads data from a file',
            'CloseHandle': 'Closes an open handle',
            'DeleteFile': 'Deletes a file',
            'GetTempPath': 'Gets temporary directory path',
            'GetTempFileName': 'Creates temporary file name',
            
            # Process operations
            'CreateProcess': 'Creates a new process',
            'CreateThread': 'Creates a new thread',
            'TerminateProcess': 'Terminates a process',
            
            # Registry operations
            'RegOpenKey': 'Opens a registry key',
            'RegSetValue': 'Sets a registry value',
            'RegQueryValue': 'Queries a registry value',
            
            # Network operations
            'WSAStartup': 'Initializes Winsock',
            'socket': 'Creates a socket',
            'connect': 'Connects to a remote host',
            'send': 'Sends data over socket',
            'recv': 'Receives data from socket',
            
            # Memory operations
            'VirtualAlloc': 'Allocates virtual memory',
            'VirtualProtect': 'Changes memory protection',
            'HeapAlloc': 'Allocates heap memory',
            
            # Crypto operations
            'CryptEncrypt': 'Encrypts data',
            'CryptDecrypt': 'Decrypts data',
            'CryptCreateHash': 'Creates a hash object',
        }
    
    def is_binary_file(self, filepath: str) -> bool:
        """
        Check if a file is a binary executable.
        
        Args:
            filepath: Path to the file
            
        Returns:
            True if file is a binary executable
        """
        try:
            # Try using 'file' command if available
            result = subprocess.run(
                ['file', filepath],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                # Check for common executable formats
                return any(fmt in output for fmt in [
                    'executable', 'elf', 'pe32', 'mach-o', 'coff'
                ])
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        
        # Fallback: check file extension
        path = Path(filepath)
        binary_extensions = {'.exe', '.dll', '.so', '.dylib', '.elf', '.bin', '.out'}
        if path.suffix.lower() in binary_extensions:
            return True
            
        # Fallback 2: Check magic bytes for extensionless files
        try:
            with open(filepath, 'rb') as f:
                header = f.read(4)
                # ELF magic: 7F 45 4C 46
                if header.startswith(b'\x7fELF'):
                    return True
                # PE magic: 4D 5A (MZ)
                if header.startswith(b'MZ'):
                    return True
                # Mach-O magic: FE ED FA CE / FE ED FA CF / CE FA ED FE / CF FA ED FE
                if header in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
                    return True
        except:
            pass
            
        # Allow all file types as requested by user
        return True
    
    def get_file_type(self, filepath: str) -> Optional[str]:
        """
        Get detailed file type information.
        
        Args:
            filepath: Path to the file
            
        Returns:
            File type string or None
        """
        try:
            result = subprocess.run(
                ['file', filepath],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Remove filename prefix
                output = result.stdout
                if ':' in output:
                    return output.split(':', 1)[1].strip()
                return output.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        
        return None
    
    def extract_strings(self, filepath: str, min_length: int = 4) -> List[str]:
        """
        Extract printable strings from a binary file.
        
        Args:
            filepath: Path to the binary file
            min_length: Minimum string length to extract
            
        Returns:
            List of extracted strings
        """
        strings = []
        
        # Try using 'strings' command if available
        try:
            result = subprocess.run(
                ['strings', '-n', str(min_length), filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                strings = result.stdout.strip().split('\n')
                return [s for s in strings if s]
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        
        # Fallback: manual string extraction
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                
            # Extract ASCII strings
            ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
            matches = re.findall(ascii_pattern, data)
            strings.extend([m.decode('ascii', errors='ignore') for m in matches])
            
            # Extract Unicode strings (UTF-16LE, common in Windows binaries)
            unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
            matches = re.findall(unicode_pattern, data)
            strings.extend([m.decode('utf-16le', errors='ignore') for m in matches])
            
        except Exception:
            pass
        
        return strings
    
    def filter_security_strings(self, strings: List[str]) -> List[str]:
        """
        Filter strings that contain security-relevant keywords.
        
        Args:
            strings: List of all strings
            
        Returns:
            List of security-relevant strings
        """
        security_strings = []
        
        for string in strings:
            string_lower = string.lower()
            if any(keyword in string_lower for keyword in self.security_keywords):
                security_strings.append(string)
        
        return security_strings
    
    def disassemble_binary(self, filepath: str, syntax: str = 'intel') -> Optional[str]:
        """
        Disassemble a binary file using objdump.
        
        Args:
            filepath: Path to the binary file
            syntax: Assembly syntax ('intel' or 'att')
            
        Returns:
            Disassembly output or None
        """
        try:
            cmd = ['objdump', '-d']
            if syntax == 'intel':
                cmd.extend(['-M', 'intel'])
            cmd.append(filepath)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        
        return None
    
    def detect_api_calls(self, strings: List[str]) -> Dict[str, List[str]]:
        """
        Detect Windows API function calls in strings.
        
        Args:
            strings: List of all strings
            
        Returns:
            Dictionary of API categories and detected functions
        """
        detected_apis = {
            'file_operations': [],
            'process_operations': [],
            'registry_operations': [],
            'network_operations': [],
            'memory_operations': [],
            'crypto_operations': []
        }
        
        for string in strings:
            string_upper = string.upper()
            
            # Check for each API function
            for api_name, description in self.windows_api_functions.items():
                if api_name.upper() in string_upper:
                    # Categorize the API
                    if any(x in api_name for x in ['File', 'Temp', 'Delete', 'Close']):
                        if api_name not in detected_apis['file_operations']:
                            detected_apis['file_operations'].append(api_name)
                    elif any(x in api_name for x in ['Process', 'Thread']):
                        if api_name not in detected_apis['process_operations']:
                            detected_apis['process_operations'].append(api_name)
                    elif 'Reg' in api_name:
                        if api_name not in detected_apis['registry_operations']:
                            detected_apis['registry_operations'].append(api_name)
                    elif any(x in api_name for x in ['WSA', 'socket', 'connect', 'send', 'recv']):
                        if api_name not in detected_apis['network_operations']:
                            detected_apis['network_operations'].append(api_name)
                    elif any(x in api_name for x in ['Virtual', 'Heap']):
                        if api_name not in detected_apis['memory_operations']:
                            detected_apis['memory_operations'].append(api_name)
                    elif 'Crypt' in api_name:
                        if api_name not in detected_apis['crypto_operations']:
                            detected_apis['crypto_operations'].append(api_name)
        
        # Remove empty categories
        return {k: v for k, v in detected_apis.items() if v}
    
    def detect_pe_sections(self, filepath: str) -> List[Dict[str, str]]:
        """
        Detect PE sections in Windows executables.
        
        Args:
            filepath: Path to the binary file
            
        Returns:
            List of section information
        """
        sections = []
        
        try:
            # Try using objdump to get section info
            result = subprocess.run(
                ['objdump', '-h', filepath],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    # Parse section lines
                    if line.strip() and not line.startswith('Sections:') and not line.startswith('Idx'):
                        parts = line.split()
                        if len(parts) >= 3:
                            # Check for suspicious section names
                            section_name = parts[1] if len(parts) > 1 else ''
                            if section_name.startswith('.'):
                                sections.append({
                                    'name': section_name,
                                    'suspicious': self._is_suspicious_section(section_name)
                                })
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        
        return sections
    
    def _is_suspicious_section(self, section_name: str) -> bool:
        """Check if a PE section name is suspicious."""
        # Standard PE sections
        standard_sections = {
            '.text', '.data', '.rdata', '.bss', '.rsrc', 
            '.reloc', '.pdata', '.idata', '.edata', '.tls'
        }
        
        # Suspicious if not standard
        return section_name.upper() not in {s.upper() for s in standard_sections}
    
    def detect_base64_strings(self, strings: List[str]) -> List[Dict[str, str]]:
        """
        Detect and decode Base64 strings.
        
        Args:
            strings: List of all strings
            
        Returns:
            List of Base64 strings with decoded values
        """
        import base64
        import re
        
        base64_strings = []
        
        # Base64 pattern: at least 20 chars, alphanumeric + / + = padding
        base64_pattern = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')
        
        for string in strings:
            string = string.strip()
            if len(string) >= 20 and base64_pattern.match(string):
                try:
                    # Try to decode
                    decoded = base64.b64decode(string).decode('utf-8', errors='ignore')
                    
                    # Check if decoded string is printable
                    if decoded and all(c.isprintable() or c.isspace() for c in decoded):
                        base64_strings.append({
                            'encoded': string[:50] + '...' if len(string) > 50 else string,
                            'decoded': decoded,
                            'is_flag': 'flag' in decoded.lower() or 'pico' in decoded.lower()
                        })
                except:
                    pass
        
        return base64_strings
    
    def detect_packer(self, filepath: str, sections: List[Dict[str, str]]) -> Optional[str]:
        """
        Detect if binary is packed.
        
        Args:
            filepath: Path to the binary file
            sections: List of PE sections
            
        Returns:
            Packer name or indication if detected
        """
        indicators = []
        
        # Check for suspicious sections
        suspicious_sections = [s['name'] for s in sections if s.get('suspicious')]
        if suspicious_sections:
            indicators.append(f"Suspicious sections: {', '.join(suspicious_sections)}")
        
        # Check for common packer signatures in strings
        try:
            with open(filepath, 'rb') as f:
                data = f.read(1024 * 100)  # Read first 100KB
                
                # Common packer signatures
                if b'UPX' in data:
                    return "UPX (Ultimate Packer for eXecutables)"
                elif b'MPRESS' in data:
                    return "MPRESS"
                elif b'PECompact' in data:
                    return "PECompact"
                elif b'ASPack' in data:
                    return "ASPack"
                elif b'Themida' in data:
                    return "Themida"
        except:
            pass
        
        # Generic packer indication

        if indicators:
            return "Possibly packed: " + "; ".join(indicators)
        
        return None
    
    def track_string_usage(self, string: str, function_address: str):
        """
        Track that a string is used by a function (bidirectional mapping).
        
        Args:
            string: The string being referenced
            function_address: Address of the function using the string
        """
        # String -> Functions mapping
        if string not in self.string_to_functions:
            self.string_to_functions[string] = []
        if function_address not in self.string_to_functions[string]:
            self.string_to_functions[string].append(function_address)
        
        # Function -> Strings mapping
        if function_address not in self.function_to_strings:
            self.function_to_strings[function_address] = []
        if string not in self.function_to_strings[function_address]:
            self.function_to_strings[function_address].append(string)
    
    def get_functions_using_string(self, string: str) -> List[str]:
        """
        Get all functions that reference a given string.
        
        Args:
            string: The string to look up
            
        Returns:
            List of function addresses that use this string
        """
        return self.string_to_functions.get(string, [])
    
    def get_strings_in_function(self, function_address: str) -> List[str]:
        """
        Get all strings referenced by a given function.
        
        Args:
            function_address: Address of the function
            
        Returns:
            List of strings used by this function
        """
        return self.function_to_strings.get(function_address, [])
    
    def extract_string_references_from_disassembly(self, disassembly: str, strings: List[str]) -> Dict[str, List[str]]:
        """
        Extract string-to-function mappings from disassembly output.
        
        Args:
            disassembly: Disassembly output from objdump
            strings: List of strings found in the binary
            
        Returns:
            Dictionary mapping strings to function addresses
        """
        if not disassembly:
            return {}
        
        current_function = None
        lines = disassembly.split('\n')
        
        for line in lines:
            # Detect function boundaries (e.g., "0000000000001234 <main>:")
            if '<' in line and '>:' in line:
                # Extract function address and name
                parts = line.split('<')
                if len(parts) >= 2:
                    addr_part = parts[0].strip()
                    # Extract just the address
                    addr_match = re.search(r'([0-9a-fA-F]+)', addr_part)
                    if addr_match:
                        current_function = addr_match.group(1)
            
            # Look for string references in instructions
            if current_function:
                for string in strings:
                    # Check if string appears in the instruction line
                    # Common patterns: lea, mov with string addresses
                    if string in line:
                        self.track_string_usage(string, current_function)
        
        return self.string_to_functions
    
    def detect_string_usage_pattern(self, disassembly: str, string: str) -> Optional[str]:
        """
        Detect how a string is being used based on surrounding instructions.
        
        Args:
            disassembly: Disassembly output
            string: The string to analyze
            
        Returns:
            Usage pattern type: 'printf', 'strcmp', 'memcpy', 'strcpy', 'other', or None
        """
        if not disassembly or not string:
            return None
        
        lines = disassembly.split('\n')
        
        # Find lines that reference this string
        for i, line in enumerate(lines):
            if string in line:
                # Look at surrounding instructions (context window)
                context_start = max(0, i - 5)
                context_end = min(len(lines), i + 10)
                context = '\n'.join(lines[context_start:context_end]).lower()
                
                # Detect function calls in context
                if 'call' in context:
                    # Check for specific function patterns
                    if any(func in context for func in ['printf', 'fprintf', 'sprintf', 'snprintf']):
                        return 'printf'
                    elif any(func in context for func in ['strcmp', 'strncmp', 'strcasecmp']):
                        return 'strcmp'
                    elif any(func in context for func in ['memcpy', 'memmove']):
                        return 'memcpy'
                    elif any(func in context for func in ['strcpy', 'strncpy', 'strcat', 'strncat']):
                        return 'strcpy'
                    else:
                        return 'other'
        
        return None
    
    def classify_string_usage(self, strings: List[str], disassembly: str) -> Dict[str, Dict[str, any]]:
        """
        Classify usage patterns for all strings.
        
        Args:
            strings: List of strings to classify
            disassembly: Disassembly output
            
        Returns:
            Dictionary mapping strings to their usage information
        """
        usage_classification = {}
        
        for string in strings:
            pattern = self.detect_string_usage_pattern(disassembly, string)
            functions = self.get_functions_using_string(string)
            
            usage_classification[string] = {
                'pattern': pattern,
                'functions': functions,
                'usage_count': len(functions)
            }
        
        return usage_classification
    
    def detect_format_specifiers(self, string: str) -> List[str]:
        """
        Detect format specifiers in a string.
        
        Args:
            string: String to analyze
            
        Returns:
            List of format specifiers found (%s, %d, %x, etc.)
        """
        # Common format specifiers
        format_pattern = re.compile(r'%[-+0 #]?[*]?[0-9]*\.?[0-9]*[hlL]?[diouxXeEfFgGaAcspn%]')
        matches = format_pattern.findall(string)
        return matches
    
    def is_format_string_vulnerable(self, string: str, usage_pattern: Optional[str]) -> Tuple[bool, str]:
        """
        Check if a string represents a potential format string vulnerability.
        
        Args:
            string: The string to check
            usage_pattern: How the string is used (printf, strcmp, etc.)
            
        Returns:
            Tuple of (is_vulnerable, reason)
        """
        # Detect format specifiers
        format_specs = self.detect_format_specifiers(string)
        
        if not format_specs:
            return False, ""
        
        # If string has format specifiers and is used in printf-like functions
        if usage_pattern == 'printf':
            # Check for potentially dangerous patterns
            dangerous_specs = [spec for spec in format_specs if spec in ['%s', '%n', '%x', '%p']]
            
            if dangerous_specs:
                return True, f"Format string with potentially dangerous specifiers: {', '.join(dangerous_specs)}"
            else:
                return True, f"Format string with specifiers: {', '.join(format_specs)}"
        
        return False, ""
    
    def detect_format_string_vulnerabilities(self, strings: List[str], usage_classification: Dict[str, Dict[str, any]]) -> List[Dict[str, any]]:
        """
        Detect potential format string vulnerabilities.
        
        Args:
            strings: List of strings to check
            usage_classification: Classification of string usage patterns
            
        Returns:
            List of potential vulnerabilities with details
        """
        vulnerabilities = []
        
        for string in strings:
            usage_info = usage_classification.get(string, {})
            usage_pattern = usage_info.get('pattern')
            
            is_vulnerable, reason = self.is_format_string_vulnerable(string, usage_pattern)
            
            if is_vulnerable:
                vulnerabilities.append({
                    'string': string,
                    'reason': reason,
                    'usage_pattern': usage_pattern,
                    'functions': usage_info.get('functions', []),
                    'format_specifiers': self.detect_format_specifiers(string)
                })
        
        return vulnerabilities
    
    def generate_string_xref_report(self, string: str) -> str:
        """
        Generate a cross-reference report for a specific string.
        
        Args:
            string: The string to generate report for
            
        Returns:
            Formatted cross-reference report
        """
        report = []
        report.append(f"Cross-References for String: \"{string}\"")
        report.append("=" * 80)
        
        functions = self.get_functions_using_string(string)
        
        if not functions:
            report.append("No cross-references found.")
        else:
            report.append(f"Used in {len(functions)} function(s):")
            report.append("")
            for func_addr in functions:
                report.append(f"  • Function at address: 0x{func_addr}")
                # List other strings in the same function
                other_strings = [s for s in self.get_strings_in_function(func_addr) if s != string]
                if other_strings:
                    report.append(f"    Other strings in this function: {len(other_strings)}")
        
        return '\n'.join(report)
    
    def generate_function_xref_report(self, function_address: str) -> str:
        """
        Generate a cross-reference report for a specific function.
        
        Args:
            function_address: Address of the function
            
        Returns:
            Formatted cross-reference report
        """
        report = []
        report.append(f"Cross-References for Function: 0x{function_address}")
        report.append("=" * 80)
        
        strings = self.get_strings_in_function(function_address)
        
        if not strings:
            report.append("No string references found.")
        else:
            report.append(f"References {len(strings)} string(s):")
            report.append("")
            for string in strings:
                # Truncate long strings
                display_string = string if len(string) <= 60 else string[:57] + "..."
                report.append(f"  • \"{display_string}\"")
        
        return '\n'.join(report)
    
    def generate_all_xrefs_report(self) -> str:
        """
        Generate a comprehensive cross-reference report for all strings and functions.
        
        Returns:
            Formatted comprehensive cross-reference report
        """
        report = []
        report.append("=" * 80)
        report.append("STRING CROSS-REFERENCE REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Summary statistics
        total_strings = len(self.string_to_functions)
        total_functions = len(self.function_to_strings)
        
        report.append(f"Total Strings Tracked: {total_strings}")
        report.append(f"Total Functions Tracked: {total_functions}")
        report.append("")
        
        # Strings with most references
        if self.string_to_functions:
            report.append("-" * 80)
            report.append("STRINGS BY USAGE FREQUENCY")
            report.append("-" * 80)
            
            # Sort strings by number of references
            sorted_strings = sorted(
                self.string_to_functions.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )
            
            # Show top 10
            for string, functions in sorted_strings[:10]:
                display_string = string if len(string) <= 50 else string[:47] + "..."
                report.append(f"  • \"{display_string}\"")
                report.append(f"    Used in {len(functions)} function(s): {', '.join(['0x' + f for f in functions[:5]])}")
                if len(functions) > 5:
                    report.append(f"    ... and {len(functions) - 5} more")
                report.append("")
        
        # Functions with most string references
        if self.function_to_strings:
            report.append("-" * 80)
            report.append("FUNCTIONS BY STRING REFERENCE COUNT")
            report.append("-" * 80)
            
            # Sort functions by number of string references
            sorted_functions = sorted(
                self.function_to_strings.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )
            
            # Show top 10
            for func_addr, strings in sorted_functions[:10]:
                report.append(f"  • Function at 0x{func_addr}")
                report.append(f"    References {len(strings)} string(s)")
                # Show first few strings
                for string in strings[:3]:
                    display_string = string if len(string) <= 50 else string[:47] + "..."
                    report.append(f"      - \"{display_string}\"")
                if len(strings) > 3:
                    report.append(f"      ... and {len(strings) - 3} more")
                report.append("")
        
        report.append("=" * 80)
        
        return '\n'.join(report)

    def detect_security_mitigations(self, filepath: str) -> Dict[str, str]:
        """
        Detect security mitigations (Checksec).
        
        Args:
            filepath: Path to the binary file
            
        Returns:
            Dictionary of security features
        """
        if self.checksec_detector:
            return self.checksec_detector.check_security(filepath)
        return {}

    def detect_vulnerabilities(self, filepath: str) -> List[Dict[str, str]]:
        """
        Detect potential vulnerabilities.
        
        Args:
            filepath: Path to the binary file
            
        Returns:
            List of detected vulnerabilities
        """
        if self.vulnerability_detector:
            return self.vulnerability_detector.scan(filepath)
        return []

    def analyze_binary(self, filepath: str, advanced: bool = False, emulate: bool = False, 
                      decrypt_strings: bool = False, quick_mode: bool = False) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a binary file.
        
        Args:
            filepath: Path to the binary file
            advanced: Enable advanced detection modules
            emulate: Enable emulation-based analysis
            decrypt_strings: Attempt to decrypt strings
            quick_mode: Skip heavy analysis steps (disassembly) for large files
            
        Returns:
            Dictionary containing all analysis results
        """
        analysis = {
            'filepath': filepath,
            'file_type': None,
            'is_binary': False,
            'all_strings': [],
            'security_strings': [],
            'string_count': 0,
            'security_string_count': 0,
            'api_calls': {},
            'pe_sections': [],
            'packer': None,
            'base64_strings': [],
            'string_to_functions': {},
            'function_to_strings': {},
            'string_usage_patterns': {},
            'format_string_vulnerabilities': [],
            'security_mitigations': {},
            'vulnerabilities': [],
            'advanced_analysis': {}
        }
        
        # Check if it's a binary
        analysis['is_binary'] = self.is_binary_file(filepath)
        if not analysis['is_binary']:
            return analysis
        
        # Basic file info
        analysis['file_type'] = self.get_file_type(filepath)
        
        # String extraction
        strings = self.extract_strings(filepath)
        analysis['all_strings'] = strings
        analysis['string_count'] = len(strings)
        analysis['security_strings'] = self.filter_security_strings(strings)
        analysis['security_string_count'] = len(analysis['security_strings'])
        analysis['base64_strings'] = self.detect_base64_strings(strings)
        analysis['api_calls'] = self.detect_api_calls(strings)
        
        # Detect PE sections (for Windows executables)
        if 'PE' in str(analysis['file_type']):
            pe_sections = self.detect_pe_sections(filepath)
            analysis['pe_sections'] = pe_sections
            
            # Detect packer
            packer = self.detect_packer(filepath, pe_sections)
            analysis['packer'] = packer
        
        # Disassembly (Skip in quick_mode)
        disassembly = None
        if not quick_mode:
            disassembly = self.disassemble_binary(filepath)
            if disassembly:
                self.extract_string_references_from_disassembly(disassembly, strings)
                analysis['string_to_functions'] = self.string_to_functions
                analysis['function_to_strings'] = self.function_to_strings
                
                # Classify string usage patterns
                usage_classification = self.classify_string_usage(strings, disassembly)
                analysis['string_usage_patterns'] = usage_classification
                
                # Detect format string vulnerabilities
                format_string_vulns = self.detect_format_string_vulnerabilities(strings, usage_classification)
                analysis['format_string_vulnerabilities'] = format_string_vulns
        
        # Checksec (Security Mitigations)
        analysis['security_mitigations'] = self.detect_security_mitigations(filepath)

        # Vulnerability Scan
        analysis['vulnerabilities'] = self.detect_vulnerabilities(filepath)
        
        # Advanced analysis (if enabled)
        if advanced and ADVANCED_DETECTORS_AVAILABLE:
            advanced_results = {}
            
            try:
                with open(filepath, 'rb') as f:
                    binary_data = f.read()
            except Exception as e:
                advanced_results['error'] = f"Could not read binary data for advanced analysis: {e}"
                analysis['advanced_analysis'] = advanced_results
                return analysis

            # Syscall detection (SyscallDetector scans raw bytes, so it's relatively fast)
            if self.syscall_detector:
                try:
                    advanced_results['syscalls'] = self.syscall_detector.analyze(binary_data)
                except Exception as e:
                    print(f"Syscall detection error: {e}")
            
            # API Hash Resolution
            if self.api_hash_resolver:
                try:
                    advanced_results['api_hashing'] = self.api_hash_resolver.analyze(binary_data)
                except Exception as e:
                    print(f"API hash resolution error: {e}")
            
            # Junk Code
            if self.junk_detector:
                try:
                    advanced_results['junk_code'] = self.junk_detector.analyze(binary_data)
                except Exception as e:
                    print(f"Junk code detection error: {e}")
            
            # Flag Finding
            if self.flag_finder:
                try:
                    # FlagFinder returns list of Flag objects, convert to dicts or strings
                    flags = self.flag_finder.find_flags(binary_data, strings)
                    advanced_results['flags'] = [f.value for f in flags]
                except Exception as e:
                    print(f"Flag finding error: {e}")
            
            # String Decryption (Emulation) - Skip in quick_mode as it's very slow
            if decrypt_strings and self.string_decryptor and not quick_mode:
                try:
                    advanced_results['decrypted_strings'] = self.string_decryptor.detect_encrypted_strings(binary_data)
                except Exception as e:
                    print(f"String decryption error: {e}")
            
            # In-Memory PE Analysis (Static check on disk file as if it were memory)
            if self.memory_parser:
                try:
                    # Treat file content as memory dump for analysis
                    mem_analysis = self.memory_parser.parse_memory_dump(binary_data, base_addr=0x400000)
                    # analysis['advanced_analysis']['memory_pe'] = mem_analysis # Uncomment if needed
                except Exception as e:
                    # analysis['advanced_analysis']['error'] = str(e)
                    pass
        
        return analysis
    
    def format_analysis_report(self, analysis: Dict[str, any]) -> str:
        """
        Format binary analysis results as a readable report.
        
        Args:
            analysis: Analysis results dictionary
            
        Returns:
            Formatted report string
        """
        if not analysis['is_binary']:
            return ""
        
        report = []
        report.append("=" * 80)
        report.append("BINARY ANALYSIS REPORT")
        report.append("=" * 80)
        report.append("")
        
        # File information
        report.append(f"File: {analysis['filepath']}")
        if analysis['file_type']:
            report.append(f"Type: {analysis['file_type']}")
        report.append("")
        
        # String statistics
        report.append(f"Total Strings Found: {analysis['string_count']}")
        report.append(f"Security-Relevant Strings: {analysis['security_string_count']}")
        
        # Packer detection
        if analysis.get('packer'):
            report.append(f"⚠️  Packer Detected: {analysis['packer']}")
        
        # Security Mitigations (Checksec)
        if analysis.get('security_mitigations'):
            report.append("-" * 80)
            report.append("🛡️  SECURITY MITIGATIONS (CHECKSEC)")
            report.append("-" * 80)
            mitigations = analysis['security_mitigations']
            for feature, status in mitigations.items():
                icon = "✅" if status == 'Enabled' or status == 'Full' else "❌" if status == 'Disabled' else "⚠️"
                report.append(f"{icon} {feature}: {status}")
            report.append("")

        # Vulnerabilities
        if analysis.get('vulnerabilities'):
            report.append("-" * 80)
            report.append("🚨 POTENTIAL VULNERABILITIES DETECTED")
            report.append("-" * 80)
            for vuln in analysis['vulnerabilities']:
                report.append(f"⚠️  Function: {vuln['function']}")
                report.append(f"    Risk: {vuln['risk']}")
                report.append(f"    Location: {vuln['location']}")
                report.append("")
        
        report.append("")
        
        # PE Sections (for Windows executables)
        if analysis.get('pe_sections'):
            suspicious = [s for s in analysis['pe_sections'] if s.get('suspicious')]
            if suspicious:
                report.append("-" * 80)
                report.append("⚠️  SUSPICIOUS PE SECTIONS DETECTED")
                report.append("-" * 80)
                for section in suspicious:
                    report.append(f"  • {section['name']} - Non-standard section (possible packer/embedded data)")
                report.append("")
                report.append("💡 Tip: Use binwalk to extract embedded data:")
                report.append(f"   binwalk {analysis['filepath']} -e")
                report.append("")
        
        # Base64 strings
        if analysis.get('base64_strings'):
            report.append("-" * 80)
            report.append("🔓 BASE64 ENCODED STRINGS DETECTED")
            report.append("-" * 80)
            for b64 in analysis['base64_strings']:
                if b64.get('is_flag'):
                    report.append(f"  🚩 POSSIBLE FLAG:")
                else:
                    report.append(f"  •")
                report.append(f"     Encoded: {b64['encoded']}")
                report.append(f"     Decoded: {b64['decoded']}")
                report.append("")
        
        # Windows API calls detected
        if analysis.get('api_calls'):
            report.append("-" * 80)
            report.append("WINDOWS API CALLS DETECTED")
            report.append("-" * 80)
            
            api_calls = analysis['api_calls']
            
            if 'file_operations' in api_calls:
                report.append("📁 File Operations:")
                for api in api_calls['file_operations']:
                    desc = self.windows_api_functions.get(api, '')
                    report.append(f"  • {api} - {desc}")
                report.append("")
            
            if 'process_operations' in api_calls:
                report.append("⚙️  Process Operations:")
                for api in api_calls['process_operations']:
                    desc = self.windows_api_functions.get(api, '')
                    report.append(f"  • {api} - {desc}")
                report.append("")
            
            if 'registry_operations' in api_calls:
                report.append("📝 Registry Operations:")
                for api in api_calls['registry_operations']:
                    desc = self.windows_api_functions.get(api, '')
                    report.append(f"  • {api} - {desc}")
                report.append("")
            
            if 'network_operations' in api_calls:
                report.append("🌐 Network Operations:")
                for api in api_calls['network_operations']:
                    desc = self.windows_api_functions.get(api, '')
                    report.append(f"  • {api} - {desc}")
                report.append("")
            
            if 'memory_operations' in api_calls:
                report.append("💾 Memory Operations:")
                for api in api_calls['memory_operations']:
                    desc = self.windows_api_functions.get(api, '')
                    report.append(f"  • {api} - {desc}")
                report.append("")
            
            if 'crypto_operations' in api_calls:
                report.append("🔐 Crypto Operations:")
                for api in api_calls['crypto_operations']:
                    desc = self.windows_api_functions.get(api, '')
                    report.append(f"  • {api} - {desc}")
                report.append("")
        
        # Security-relevant strings
        if analysis['security_strings']:
            report.append("-" * 80)
            report.append("SECURITY-RELEVANT STRINGS")
            report.append("-" * 80)
            
            for string in analysis['security_strings']:
                # Highlight which keywords matched
                string_lower = string.lower()
                matched_keywords = [kw for kw in self.security_keywords if kw in string_lower]
                
                report.append(f"  • {string}")
                if matched_keywords:
                    report.append(f"    Keywords: {', '.join(matched_keywords)}")
            
            report.append("")
        
        # String usage patterns
        if analysis.get('string_usage_patterns'):
            report.append("-" * 80)
            report.append("STRING USAGE PATTERNS")
            report.append("-" * 80)
            
            patterns_summary = {}
            for string, info in analysis['string_usage_patterns'].items():
                pattern = info.get('pattern', 'unknown')
                if pattern:
                    patterns_summary[pattern] = patterns_summary.get(pattern, 0) + 1
            
            if patterns_summary:
                report.append("Pattern Distribution:")
                for pattern, count in sorted(patterns_summary.items(), key=lambda x: x[1], reverse=True):
                    report.append(f"  • {pattern}: {count} string(s)")
                report.append("")
        
        # Format string vulnerabilities
        if analysis.get('format_string_vulnerabilities'):
            vulns = analysis['format_string_vulnerabilities']
            if vulns:
                report.append("-" * 80)
                report.append("⚠️  FORMAT STRING VULNERABILITIES DETECTED")
                report.append("-" * 80)
                
                for vuln in vulns:
                    display_string = vuln['string'] if len(vuln['string']) <= 60 else vuln['string'][:57] + "..."
                    report.append(f"  • String: \"{display_string}\"")
                    report.append(f"    Reason: {vuln['reason']}")
                    report.append(f"    Usage: {vuln['usage_pattern']}")
                    if vuln['functions']:
                        report.append(f"    Functions: {', '.join(['0x' + f for f in vuln['functions'][:3]])}")
                    report.append("")
        
        # Cross-reference summary
        if analysis.get('string_to_functions') or analysis.get('function_to_strings'):
            report.append("-" * 80)
            report.append("STRING CROSS-REFERENCE SUMMARY")
            report.append("-" * 80)
            
            if analysis.get('string_to_functions'):
                total_tracked = len(analysis['string_to_functions'])
                report.append(f"Total strings with cross-references: {total_tracked}")
            
            if analysis.get('function_to_strings'):
                total_funcs = len(analysis['function_to_strings'])
                report.append(f"Total functions with string references: {total_funcs}")
            
            report.append("")
            report.append("💡 Tip: Use generate_all_xrefs_report() for detailed cross-reference listing")
            report.append("")
        
        # Advanced analysis results
        if analysis.get('advanced_analysis'):
            adv = analysis['advanced_analysis']
            
            # Flag detection (show first!)
            if 'flags' in adv and adv['flags']:
                report.append("-" * 80)
                if self.flag_finder:
                    report.append(self.flag_finder.format_report(adv['flags']))
            
            # Syscall detection
            if 'syscalls' in adv and adv['syscalls'].get('stubs_found', 0) > 0:
                report.append("-" * 80)
                if self.syscall_detector:
                    report.append(self.syscall_detector.format_report(adv['syscalls']))
            
            # API hashing
            if 'api_hashing' in adv and adv['api_hashing'].get('resolved_count', 0) > 0:
                report.append("-" * 80)
                if self.api_hash_resolver:
                    report.append(self.api_hash_resolver.format_report(adv['api_hashing']))
            
            # Junk code
            if 'junk_code' in adv and adv['junk_code'].get('threat_level') != 'NONE':
                report.append("-" * 80)
                if self.junk_detector:
                    report.append(self.junk_detector.format_report(adv['junk_code']))
            
            # Decrypted Strings
            if 'decrypted_strings' in adv and adv['decrypted_strings']:
                report.append("-" * 80)
                if self.string_decryptor:
                    report.append(self.string_decryptor.format_report(adv['decrypted_strings']))
            
            # Memory PE Analysis
            if 'memory_pe' in adv:
                report.append("-" * 80)
                if self.memory_parser:
                    report.append(self.memory_parser.format_report(adv['memory_pe']))
        
        report.append("=" * 80)
        report.append("")
        
        return '\n'.join(report)

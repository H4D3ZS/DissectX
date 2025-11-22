"""Binary analyzer for extracting strings and metadata from executables"""
import re
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# Import advanced detection modules
try:
    from .detectors.syscall_detector import SyscallDetector
    from .detectors.api_hash_resolver import APIHashResolver
    from .detectors.junk_detector import JunkDetector
    from .detectors.flag_finder import FlagFinder
    
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
        
        # Initialize advanced detectors if available
        if ADVANCED_DETECTORS_AVAILABLE:
            self.syscall_detector = SyscallDetector()
            self.api_hash_resolver = APIHashResolver()
            self.junk_detector = JunkDetector()
            self.flag_finder = FlagFinder()
            
            # Initialize Emulation & Memory tools
            self.string_decryptor = StringDecryptor() if UNICORN_AVAILABLE else None
            self.memory_parser = MemoryPEParser() if PEFILE_AVAILABLE else None
            self.memory_analyzer = MemoryDumpAnalyzer() if PEFILE_AVAILABLE else None
        else:
            self.syscall_detector = None
            self.api_hash_resolver = None
            self.junk_detector = None
            self.flag_finder = None
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
        return path.suffix.lower() in binary_extensions
    
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
    
    def analyze_binary(self, filepath: str, advanced: bool = False, 
                      emulate: bool = False, decrypt_strings: bool = False) -> Dict[str, any]:
        """
        Perform comprehensive binary analysis.
        
        Args:
            filepath: Path to the binary file
            advanced: Enable advanced detection (syscalls, API hashing, junk code)
            emulate: Enable emulation features
            decrypt_strings: Enable string decryption
            
        Returns:
            Analysis results dictionary
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
            'advanced_analysis': {}
        }
        
        # Check if it's a binary
        analysis['is_binary'] = self.is_binary_file(filepath)
        if not analysis['is_binary']:
            return analysis
        
        # Get file type
        analysis['file_type'] = self.get_file_type(filepath)
        
        # Extract strings
        all_strings = self.extract_strings(filepath)
        analysis['all_strings'] = all_strings
        analysis['string_count'] = len(all_strings)
        
        # Filter security-relevant strings
        security_strings = self.filter_security_strings(all_strings)
        analysis['security_strings'] = security_strings
        analysis['security_string_count'] = len(security_strings)
        
        # Detect API calls
        api_calls = self.detect_api_calls(all_strings)
        analysis['api_calls'] = api_calls
        
        # Detect PE sections (for Windows executables)
        if 'PE' in str(analysis['file_type']):
            pe_sections = self.detect_pe_sections(filepath)
            analysis['pe_sections'] = pe_sections
            
            # Detect packer
            packer = self.detect_packer(filepath, pe_sections)
            analysis['packer'] = packer
        
        # Detect Base64 strings
        base64_strings = self.detect_base64_strings(all_strings)
        analysis['base64_strings'] = base64_strings
        
        # Advanced analysis (if enabled)
        if advanced and ADVANCED_DETECTORS_AVAILABLE:
            try:
                with open(filepath, 'rb') as f:
                    binary_data = f.read()
                
                # Flag detection (always run for CTF binaries)
                if self.flag_finder:
                    flag_results = self.flag_finder.find_flags(binary_data, all_strings)
                    analysis['advanced_analysis']['flags'] = flag_results
                
                # Syscall detection
                if self.syscall_detector:
                    syscall_results = self.syscall_detector.analyze(binary_data)
                    analysis['advanced_analysis']['syscalls'] = syscall_results
                
                # API hash resolution
                if self.api_hash_resolver:
                    api_hash_results = self.api_hash_resolver.analyze(binary_data)
                    analysis['advanced_analysis']['api_hashing'] = api_hash_results
                
                # Junk code detection
                if self.junk_detector:
                    junk_results = self.junk_detector.analyze(binary_data)
                    analysis['advanced_analysis']['junk_code'] = junk_results
                
                # String Decryption (Emulation)
                if self.string_decryptor and decrypt_strings:
                    decrypted_strings = self.string_decryptor.detect_encrypted_strings(binary_data)
                    analysis['advanced_analysis']['decrypted_strings'] = decrypted_strings
                
                # In-Memory PE Analysis (Static check on disk file as if it were memory)
                if self.memory_parser:
                    # Treat file content as memory dump for analysis
                    mem_analysis = self.memory_parser.parse_memory_dump(binary_data, base_addr=0x400000)
                    analysis['advanced_analysis']['memory_pe'] = mem_analysis
                    
            except Exception as e:
                analysis['advanced_analysis']['error'] = str(e)
        
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

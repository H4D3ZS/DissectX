#!/usr/bin/env python3
"""
AntiAnalysisDetector for DissectX    Framework

Detects anti-debugging, anti-VM, timing attacks, and self-modifying code.
Provides bypass recommendations for each detected technique.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5
"""

import re
from typing import List, Dict, Optional, Set
from dataclasses import dataclass
from enum import Enum


class TechniqueType(Enum):
    """Types of anti-analysis techniques"""
    ANTI_DEBUG = "anti-debugging"
    ANTI_VM = "anti-vm"
    TIMING_ATTACK = "timing-attack"
    SELF_MODIFYING = "self-modifying-code"


@dataclass
class DetectedTechnique:
    """Represents a detected anti-analysis technique"""
    technique_type: TechniqueType
    name: str
    description: str
    address: Optional[str] = None
    instruction: Optional[str] = None
    bypass_recommendation: str = ""
    
    def __str__(self) -> str:
        addr_str = f" at {self.address}" if self.address else ""
        return (f"[{self.technique_type.value}] {self.name}{addr_str}\n"
                f"  Description: {self.description}\n"
                f"  Bypass: {self.bypass_recommendation}")


@dataclass
class AntiAnalysisReport:
    """Complete anti-analysis detection report"""
    techniques: List[DetectedTechnique]
    anti_debug_count: int = 0
    anti_vm_count: int = 0
    timing_attack_count: int = 0
    self_modifying_count: int = 0
    
    def __post_init__(self):
        """Calculate counts after initialization"""
        self.anti_debug_count = sum(1 for t in self.techniques 
                                   if t.technique_type == TechniqueType.ANTI_DEBUG)
        self.anti_vm_count = sum(1 for t in self.techniques 
                                if t.technique_type == TechniqueType.ANTI_VM)
        self.timing_attack_count = sum(1 for t in self.techniques 
                                      if t.technique_type == TechniqueType.TIMING_ATTACK)
        self.self_modifying_count = sum(1 for t in self.techniques 
                                       if t.technique_type == TechniqueType.SELF_MODIFYING)


class AntiAnalysisDetector:
    """
    Detects anti-analysis techniques in binary code.
    
    Features:
    - Anti-debugging API detection (IsDebuggerPresent, PEB checks, etc.)
    - VM detection (CPUID, registry checks, VMware artifacts)
    - Timing attack detection (rdtsc, timing-based checks)
    - Self-modifying code detection (writes to executable memory)
    - Bypass recommendations for each technique
    """
    
    # Anti-debugging API calls and patterns
    ANTI_DEBUG_APIS = {
        'IsDebuggerPresent': {
            'description': 'Windows API that checks if process is being debugged',
            'bypass': 'Patch return value to always return 0, or use ScyllaHide/TitanHide'
        },
        'CheckRemoteDebuggerPresent': {
            'description': 'Checks if remote debugger is attached',
            'bypass': 'Patch return value or hook the API to return FALSE'
        },
        'NtQueryInformationProcess': {
            'description': 'Can query ProcessDebugPort and other debug-related information',
            'bypass': 'Hook the function and filter debug-related queries'
        },
        'OutputDebugString': {
            'description': 'Can detect debugger by checking GetLastError after call',
            'bypass': 'Hook OutputDebugStringA/W to set appropriate error code'
        },
        'DebugActiveProcess': {
            'description': 'Attempts to debug itself to prevent external debuggers',
            'bypass': 'Hook the API to return failure'
        },
        'NtSetInformationThread': {
            'description': 'Can hide thread from debugger (ThreadHideFromDebugger)',
            'bypass': 'Hook and filter ThreadHideFromDebugger flag'
        },
        'NtQuerySystemInformation': {
            'description': 'Can detect debugger via SystemKernelDebuggerInformation',
            'bypass': 'Hook and filter debug-related queries'
        },
        'ZwQueryInformationProcess': {
            'description': 'Native API version of NtQueryInformationProcess',
            'bypass': 'Hook the function and filter debug-related queries'
        }
    }
    
    # PEB (Process Environment Block) checks
    PEB_CHECKS = {
        'BeingDebugged': {
            'patterns': [
                r'fs:\[0x30\]',  # PEB access (x86)
                r'gs:\[0x60\]',  # PEB access (x64)
                r'\[rax\+0x2\]',  # BeingDebugged offset
                r'\[eax\+0x2\]',  # BeingDebugged offset (32-bit)
            ],
            'description': 'Checks PEB.BeingDebugged flag',
            'bypass': 'Patch PEB.BeingDebugged to 0 or use anti-anti-debug plugin'
        },
        'NtGlobalFlag': {
            'patterns': [
                r'fs:\[0x30\].*0x68', 
                r'gs:\[0x60\].*0xbc',
                r'\[rax\+0x68\]',  # NtGlobalFlag offset (x64)
                r'\[eax\+0x68\]',  # NtGlobalFlag offset (x86)
            ],
            'description': 'Checks PEB.NtGlobalFlag for heap flags set by debugger',
            'bypass': 'Patch NtGlobalFlag to normal value (0x70 for debug, 0x0 for release)'
        },
        'HeapFlags': {
            'patterns': [r'heap.*flags', r'ProcessHeap.*0x[0-9a-f]+.*0x[0-9a-f]+'],
            'description': 'Checks heap flags that differ when debugger is present',
            'bypass': 'Patch heap flags to match non-debug values'
        }
    }
    
    # VM detection techniques
    VM_DETECTION = {
        'CPUID': {
            'patterns': [r'\bcpuid\b'],
            'description': 'Uses CPUID instruction to detect hypervisor presence',
            'bypass': 'Patch CPUID results or use VM with hidden hypervisor flag'
        },
        'VMware_Registry': {
            'patterns': [r'VMware', r'VBOX', r'VirtualBox'],
            'description': 'Checks registry for VMware/VirtualBox artifacts',
            'bypass': 'Clean registry of VM-related keys or use anti-VM detection tools'
        },
        'VMware_Files': {
            'patterns': [r'vmware.*\.sys', r'vbox.*\.sys', r'vmtools', r'VBoxGuest'],
            'description': 'Checks for VMware/VirtualBox driver files',
            'bypass': 'Rename or hide VM-related files and drivers'
        },
        'VMware_MAC': {
            'patterns': [r'00:0[cC]:29', r'00:50:56', r'00:05:69'],
            'description': 'Checks for VMware MAC address prefixes',
            'bypass': 'Change VM MAC address to non-VMware prefix'
        },
        'QEMU_Detection': {
            'patterns': [r'QEMU', r'qemu'],
            'description': 'Checks for QEMU artifacts',
            'bypass': 'Use QEMU with hidden signatures or different emulator'
        },
        'Hyper-V_Detection': {
            'patterns': [r'Hyper-V', r'Microsoft.*Hv'],
            'description': 'Checks for Hyper-V presence',
            'bypass': 'Disable Hyper-V enlightenments or use different hypervisor'
        }
    }
    
    # Timing attack patterns
    TIMING_PATTERNS = {
        'rdtsc': {
            'patterns': [r'\brdtsc\b'],
            'description': 'Reads CPU timestamp counter to detect debugger slowdown',
            'bypass': 'Patch rdtsc instructions to return consistent values'
        },
        'rdtscp': {
            'patterns': [r'\brdtscp\b'],
            'description': 'Serializing version of rdtsc for more accurate timing',
            'bypass': 'Patch rdtscp instructions or use hardware breakpoints sparingly'
        },
        'QueryPerformanceCounter': {
            'patterns': [r'QueryPerformanceCounter'],
            'description': 'High-resolution timer used to detect debugging delays',
            'bypass': 'Hook API to return consistent time deltas'
        },
        'GetTickCount': {
            'patterns': [r'GetTickCount'],
            'description': 'System uptime check to detect time manipulation',
            'bypass': 'Hook API to return consistent values'
        },
        'timeGetTime': {
            'patterns': [r'timeGetTime'],
            'description': 'Multimedia timer used for timing checks',
            'bypass': 'Hook API to return consistent values'
        }
    }
    
    def __init__(self):
        """Initialize the AntiAnalysisDetector"""
        self.detected_techniques: List[DetectedTechnique] = []
    
    def analyze(self, instructions: List, strings: List[str] = None) -> AntiAnalysisReport:
        """
        Analyze code for anti-analysis techniques.
        
        Args:
            instructions: List of Instruction objects or assembly strings
            strings: Optional list of extracted strings from binary
            
        Returns:
            AntiAnalysisReport with all detected techniques
        """
        self.detected_techniques = []
        
        if strings is None:
            strings = []
        
        # Detect anti-debugging techniques
        self._detect_anti_debug_apis(instructions, strings)
        self._detect_peb_checks(instructions)
        
        # Detect VM detection techniques
        self._detect_vm_detection(instructions, strings)
        
        # Detect timing attacks
        self._detect_timing_attacks(instructions)
        
        # Detect self-modifying code
        self._detect_self_modifying_code(instructions)
        
        # Create report
        report = AntiAnalysisReport(techniques=self.detected_techniques)
        
        return report
    
    def _detect_anti_debug_apis(self, instructions: List, strings: List[str]):
        """
        Detect anti-debugging API calls.
        
        Args:
            instructions: List of instructions
            strings: List of extracted strings
        """
        # Convert instructions to searchable text
        instruction_text = self._instructions_to_text(instructions)
        
        # Check for API calls in instructions
        for api_name, api_info in self.ANTI_DEBUG_APIS.items():
            # Search for API name in instructions (case-insensitive)
            pattern = re.compile(re.escape(api_name), re.IGNORECASE)
            
            for match in pattern.finditer(instruction_text):
                # Try to find the instruction containing this API call
                address, instruction = self._find_instruction_at_position(
                    instructions, instruction_text, match.start()
                )
                
                technique = DetectedTechnique(
                    technique_type=TechniqueType.ANTI_DEBUG,
                    name=api_name,
                    description=api_info['description'],
                    address=address,
                    instruction=instruction,
                    bypass_recommendation=api_info['bypass']
                )
                self.detected_techniques.append(technique)
        
        # Also check strings for API names (imports)
        for api_name, api_info in self.ANTI_DEBUG_APIS.items():
            if any(api_name.lower() in s.lower() for s in strings):
                # Only add if not already detected in instructions
                if not any(t.name == api_name for t in self.detected_techniques):
                    technique = DetectedTechnique(
                        technique_type=TechniqueType.ANTI_DEBUG,
                        name=api_name,
                        description=api_info['description'] + ' (found in imports)',
                        bypass_recommendation=api_info['bypass']
                    )
                    self.detected_techniques.append(technique)
    
    def _detect_peb_checks(self, instructions: List):
        """
        Detect PEB (Process Environment Block) checks.
        
        Args:
            instructions: List of instructions
        """
        instruction_text = self._instructions_to_text(instructions)
        
        for check_name, check_info in self.PEB_CHECKS.items():
            for pattern_str in check_info['patterns']:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                
                for match in pattern.finditer(instruction_text):
                    address, instruction = self._find_instruction_at_position(
                        instructions, instruction_text, match.start()
                    )
                    
                    technique = DetectedTechnique(
                        technique_type=TechniqueType.ANTI_DEBUG,
                        name=f"PEB Check: {check_name}",
                        description=check_info['description'],
                        address=address,
                        instruction=instruction,
                        bypass_recommendation=check_info['bypass']
                    )
                    self.detected_techniques.append(technique)
    
    def _detect_vm_detection(self, instructions: List, strings: List[str]):
        """
        Detect VM detection techniques.
        
        Args:
            instructions: List of instructions
            strings: List of extracted strings
        """
        instruction_text = self._instructions_to_text(instructions)
        
        for technique_name, technique_info in self.VM_DETECTION.items():
            for pattern_str in technique_info['patterns']:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                
                # Check instructions
                for match in pattern.finditer(instruction_text):
                    address, instruction = self._find_instruction_at_position(
                        instructions, instruction_text, match.start()
                    )
                    
                    technique = DetectedTechnique(
                        technique_type=TechniqueType.ANTI_VM,
                        name=technique_name,
                        description=technique_info['description'],
                        address=address,
                        instruction=instruction,
                        bypass_recommendation=technique_info['bypass']
                    )
                    self.detected_techniques.append(technique)
                
                # Check strings
                for string in strings:
                    if pattern.search(string):
                        # Only add if not already detected
                        if not any(t.name == technique_name and t.address is None 
                                 for t in self.detected_techniques):
                            technique = DetectedTechnique(
                                technique_type=TechniqueType.ANTI_VM,
                                name=technique_name,
                                description=technique_info['description'] + ' (found in strings)',
                                bypass_recommendation=technique_info['bypass']
                            )
                            self.detected_techniques.append(technique)
                        break  # Only add once per technique
    
    def _detect_timing_attacks(self, instructions: List):
        """
        Detect timing-based anti-debugging techniques.
        
        Args:
            instructions: List of instructions
        """
        instruction_text = self._instructions_to_text(instructions)
        
        for timing_name, timing_info in self.TIMING_PATTERNS.items():
            for pattern_str in timing_info['patterns']:
                pattern = re.compile(pattern_str, re.IGNORECASE)
                
                for match in pattern.finditer(instruction_text):
                    address, instruction = self._find_instruction_at_position(
                        instructions, instruction_text, match.start()
                    )
                    
                    technique = DetectedTechnique(
                        technique_type=TechniqueType.TIMING_ATTACK,
                        name=timing_name,
                        description=timing_info['description'],
                        address=address,
                        instruction=instruction,
                        bypass_recommendation=timing_info['bypass']
                    )
                    self.detected_techniques.append(technique)
    
    def _detect_self_modifying_code(self, instructions: List):
        """
        Detect self-modifying code patterns.
        
        Self-modifying code writes to executable memory regions, which can be
        detected by looking for write operations to code sections.
        
        Args:
            instructions: List of instructions
        """
        instruction_text = self._instructions_to_text(instructions)
        
        # Patterns that indicate writes to executable memory
        # Look for mov/write operations to code addresses or executable regions
        self_mod_patterns = [
            (r'\bmov\b.*\[.*\].*,', 'Memory write operation'),
            (r'\bstos[bwdq]\b', 'String store to memory'),
            (r'VirtualProtect', 'Changes memory protection (may enable code modification)'),
            (r'WriteProcessMemory', 'Writes to process memory'),
            (r'NtProtectVirtualMemory', 'Native API for memory protection change'),
        ]
        
        for pattern_str, description in self_mod_patterns:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            
            for match in pattern.finditer(instruction_text):
                address, instruction = self._find_instruction_at_position(
                    instructions, instruction_text, match.start()
                )
                
                # Additional heuristic: check if writing to nearby addresses
                # (potential self-modification)
                is_likely_self_mod = self._is_likely_self_modification(
                    instruction, address
                )
                
                if is_likely_self_mod or 'Protect' in pattern_str or 'Write' in pattern_str:
                    technique = DetectedTechnique(
                        technique_type=TechniqueType.SELF_MODIFYING,
                        name="Self-Modifying Code",
                        description=f"{description} - potential code modification",
                        address=address,
                        instruction=instruction,
                        bypass_recommendation=(
                            "Dump modified code after execution, or use emulation "
                            "to trace modifications. Consider using memory breakpoints "
                            "to catch modifications."
                        )
                    )
                    self.detected_techniques.append(technique)
    
    def _is_likely_self_modification(self, instruction: str, address: Optional[str]) -> bool:
        """
        Heuristic to determine if an instruction is likely self-modifying code.
        
        Args:
            instruction: Instruction string
            address: Address of instruction
            
        Returns:
            True if likely self-modifying, False otherwise
        """
        if not instruction:
            return False
        
        # Check for writes to code-like addresses (not stack/heap)
        # This is a simple heuristic - in practice, would need more context
        
        # Look for mov to memory with code-like addresses
        if 'mov' in instruction.lower():
            # Check if writing to an address that looks like code
            # (e.g., not rsp/rbp relative, not typical heap addresses)
            if '[' in instruction and ']' in instruction:
                # Extract memory reference
                mem_ref = instruction[instruction.find('['):instruction.find(']')+1]
                
                # If it's not stack-relative (rsp/rbp), might be code modification
                if 'rsp' not in mem_ref.lower() and 'rbp' not in mem_ref.lower():
                    # Check if it's writing to a nearby address (potential self-mod)
                    if address:
                        try:
                            addr_int = int(address, 16) if isinstance(address, str) else address
                            # Look for addresses in code range (heuristic)
                            if '0x' in mem_ref:
                                target = mem_ref[mem_ref.find('0x'):]
                                target = target.split()[0].rstrip(',]')
                                try:
                                    target_int = int(target, 16)
                                    # If writing to nearby address, likely self-mod
                                    if abs(target_int - addr_int) < 0x10000:  # Within 64KB
                                        return True
                                except ValueError:
                                    pass
                        except (ValueError, TypeError):
                            pass
        
        return False
    
    def _instructions_to_text(self, instructions: List) -> str:
        """
        Convert instructions to searchable text.
        
        Args:
            instructions: List of Instruction objects or strings
            
        Returns:
            Concatenated instruction text
        """
        text_parts = []
        
        for instr in instructions:
            if isinstance(instr, str):
                text_parts.append(instr)
            elif hasattr(instr, 'mnemonic'):
                # Instruction object
                instr_str = instr.mnemonic
                if hasattr(instr, 'operands') and instr.operands:
                    instr_str += ' ' + ', '.join(str(op) for op in instr.operands)
                if hasattr(instr, 'comment') and instr.comment:
                    instr_str += ' ; ' + instr.comment
                text_parts.append(instr_str)
            else:
                text_parts.append(str(instr))
        
        return '\n'.join(text_parts)
    
    def _find_instruction_at_position(
        self, 
        instructions: List, 
        text: str, 
        position: int
    ) -> tuple:
        """
        Find the instruction containing a specific text position.
        
        Args:
            instructions: List of instructions
            text: Full instruction text
            position: Character position in text
            
        Returns:
            Tuple of (address, instruction_string)
        """
        # Find which line contains this position
        lines = text[:position].split('\n')
        line_num = len(lines) - 1
        
        if line_num < len(instructions):
            instr = instructions[line_num]
            
            if isinstance(instr, str):
                return None, instr
            elif hasattr(instr, 'address'):
                instr_str = instr.mnemonic
                if hasattr(instr, 'operands') and instr.operands:
                    instr_str += ' ' + ', '.join(str(op) for op in instr.operands)
                return instr.address, instr_str
        
        return None, None
    
    def format_report(self, report: AntiAnalysisReport) -> str:
        """
        Format anti-analysis report as human-readable text.
        
        Args:
            report: AntiAnalysisReport object
            
        Returns:
            Formatted report string
        """
        if not report.techniques:
            return "No anti-analysis techniques detected."
        
        lines = []
        lines.append("=" * 80)
        lines.append("ANTI-ANALYSIS DETECTION REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Total Techniques Detected: {len(report.techniques)}")
        lines.append(f"  - Anti-Debugging: {report.anti_debug_count}")
        lines.append(f"  - Anti-VM: {report.anti_vm_count}")
        lines.append(f"  - Timing Attacks: {report.timing_attack_count}")
        lines.append(f"  - Self-Modifying Code: {report.self_modifying_count}")
        lines.append("")
        lines.append("=" * 80)
        lines.append("")
        
        # Group by technique type
        for tech_type in TechniqueType:
            techniques = [t for t in report.techniques if t.technique_type == tech_type]
            if techniques:
                lines.append(f"\n{tech_type.value.upper()}")
                lines.append("-" * 80)
                for i, technique in enumerate(techniques, 1):
                    lines.append(f"\n{i}. {technique.name}")
                    if technique.address:
                        lines.append(f"   Address: {technique.address}")
                    if technique.instruction:
                        lines.append(f"   Instruction: {technique.instruction}")
                    lines.append(f"   Description: {technique.description}")
                    lines.append(f"   Bypass: {technique.bypass_recommendation}")
                lines.append("")
        
        lines.append("=" * 80)
        
        return '\n'.join(lines)
    
    def get_techniques_by_type(
        self, 
        report: AntiAnalysisReport, 
        technique_type: TechniqueType
    ) -> List[DetectedTechnique]:
        """
        Get all techniques of a specific type.
        
        Args:
            report: AntiAnalysisReport object
            technique_type: Type of technique to filter
            
        Returns:
            List of DetectedTechnique objects
        """
        return [t for t in report.techniques if t.technique_type == technique_type]
    
    def get_bypass_recommendations(self, report: AntiAnalysisReport) -> Dict[str, List[str]]:
        """
        Get all bypass recommendations grouped by technique type.
        
        Args:
            report: AntiAnalysisReport object
            
        Returns:
            Dictionary mapping technique type to list of bypass recommendations
        """
        recommendations = {}
        
        for tech_type in TechniqueType:
            techniques = self.get_techniques_by_type(report, tech_type)
            if techniques:
                # Get unique recommendations
                unique_bypasses = list(set(t.bypass_recommendation for t in techniques))
                recommendations[tech_type.value] = unique_bypasses
        
        return recommendations


# Example usage
if __name__ == "__main__":
    # Test with sample assembly code
    test_instructions = [
        "call IsDebuggerPresent",
        "test eax, eax",
        "jnz debugger_detected",
        "mov rax, fs:[0x30]",
        "movzx eax, byte ptr [rax+0x2]",
        "test al, al",
        "jnz being_debugged",
        "cpuid",
        "cmp ecx, 0x40000000",
        "rdtsc",
        "mov [rsp+0x10], eax",
        "call some_function",
        "rdtsc",
        "sub eax, [rsp+0x10]",
        "cmp eax, 0x1000",
        "ja timing_detected",
        "mov dword ptr [0x401000], 0x90909090",
        "call VirtualProtect",
    ]
    
    test_strings = [
        "IsDebuggerPresent",
        "VMware",
        "VBOX",
        "CheckRemoteDebuggerPresent"
    ]
    
    detector = AntiAnalysisDetector()
    report = detector.analyze(test_instructions, test_strings)
    
    print(detector.format_report(report))
    
    print("\n" + "=" * 80)
    print("BYPASS RECOMMENDATIONS BY CATEGORY")
    print("=" * 80)
    
    bypasses = detector.get_bypass_recommendations(report)
    for category, recommendations in bypasses.items():
        print(f"\n{category.upper()}:")
        for i, bypass in enumerate(recommendations, 1):
            print(f"  {i}. {bypass}")

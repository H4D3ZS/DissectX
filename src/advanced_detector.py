"""Advanced detection for obfuscation, anti-analysis, and protection techniques"""
import re
from typing import List, Dict, Optional
from src.models import Instruction


class AdvancedDetector:
    """Detects advanced anti-analysis and obfuscation techniques"""
    
    def __init__(self):
        """Initialize the advanced detector"""
        # Direct syscall patterns
        self.syscall_patterns = [
            # mov r10, rcx; mov eax, <syscall_number>; syscall; ret
            (r'mov\s+r10,\s*rcx', r'mov\s+eax,', r'syscall'),
            # mov r10, rcx; mov eax, <number>
            (r'mov\s+r10,\s*rcx', r'mov\s+eax,\s*0x[0-9a-fA-F]+'),
        ]
        
        # Anti-debugging patterns
        self.anti_debug_patterns = {
            'int3_padding': r'int3',  # Excessive int3 instructions
            'timing_check': r'rdtsc',  # Timing checks
            'debug_check': r'IsDebuggerPresent',
            'peb_check': r'fs:\[0x60\]',  # PEB access
        }
        
        # Obfuscation patterns
        self.obfuscation_indicators = {
            'junk_code': ['nop', 'int3'],
            'control_flow': ['jmp', 'call'],
            'redundant_ops': ['push', 'pop'],
        }
    
    def detect_direct_syscalls(self, instructions: List[Instruction]) -> List[Dict[str, any]]:
        """
        Detect direct syscall usage (Hell's Gate, Tartarus' Gate techniques).
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of detected syscall patterns with details
        """
        detections = []
        
        for i in range(len(instructions) - 3):
            instr1 = instructions[i].mnemonic.lower()
            instr2 = instructions[i + 1].mnemonic.lower() if i + 1 < len(instructions) else ''
            instr3 = instructions[i + 2].mnemonic.lower() if i + 2 < len(instructions) else ''
            
            # Pattern: mov r10, rcx; mov eax, <number>; syscall
            if (instr1 == 'mov' and 'r10' in str(instructions[i].operands).lower() and
                instr2 == 'mov' and 'eax' in str(instructions[i + 1].operands).lower() and
                instr3 == 'syscall'):
                
                # Extract syscall number
                syscall_num = None
                if len(instructions[i + 1].operands) >= 2:
                    syscall_num = instructions[i + 1].operands[1]
                
                detections.append({
                    'type': 'direct_syscall',
                    'address': instructions[i].address,
                    'syscall_number': syscall_num,
                    'technique': "Hell's Gate / Direct Syscall",
                    'severity': 'HIGH',
                    'description': 'Direct syscall invocation (bypasses NTDLL hooks, EDR evasion)'
                })
        
        return detections
    
    def detect_anti_debugging(self, instructions: List[Instruction]) -> List[Dict[str, any]]:
        """
        Detect anti-debugging techniques.
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of detected anti-debugging techniques
        """
        detections = []
        
        # Count int3 instructions (excessive = anti-debug)
        int3_count = sum(1 for instr in instructions if instr.mnemonic.lower() == 'int3')
        if int3_count > 20:
            detections.append({
                'type': 'anti_debug',
                'technique': 'Excessive INT3 padding',
                'count': int3_count,
                'severity': 'MEDIUM',
                'description': f'{int3_count} INT3 instructions detected (anti-debugging/anti-emulation)'
            })
        
        # Detect timing checks (rdtsc)
        for instr in instructions:
            if instr.mnemonic.lower() == 'rdtsc':
                detections.append({
                    'type': 'anti_debug',
                    'address': instr.address,
                    'technique': 'Timing check (RDTSC)',
                    'severity': 'MEDIUM',
                    'description': 'Reads CPU timestamp counter (detects debuggers via timing)'
                })
        
        # Detect PEB access (Process Environment Block)
        for instr in instructions:
            if 'fs:' in str(instr.operands).lower() or 'gs:' in str(instr.operands).lower():
                detections.append({
                    'type': 'anti_debug',
                    'address': instr.address,
                    'technique': 'PEB/TEB access',
                    'severity': 'MEDIUM',
                    'description': 'Accesses Process Environment Block (checks for debugger)'
                })
                break  # Only report once
        
        return detections
    
    def detect_pe_parsing(self, instructions: List[Instruction]) -> Optional[Dict[str, any]]:
        """
        Detect manual PE parsing (common in loaders/packers).
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            Detection info if PE parsing found
        """
        # Look for MZ header check (0x5A4D)
        mz_check = False
        pe_check = False
        
        for instr in instructions:
            operands_str = ' '.join(instr.operands).lower()
            
            # Check for MZ signature (0x5A4D)
            if '0x5a4d' in operands_str or '0x4d5a' in operands_str:
                mz_check = True
            
            # Check for PE signature (0x4550)
            if '0x4550' in operands_str or '0x5045' in operands_str:
                pe_check = True
        
        if mz_check and pe_check:
            return {
                'type': 'pe_parsing',
                'technique': 'Manual PE parsing',
                'severity': 'HIGH',
                'description': 'Manually parses PE headers (custom loader/packer behavior)'
            }
        
        return None
    
    def detect_import_hashing(self, instructions: List[Instruction]) -> List[Dict[str, any]]:
        """
        Detect import hashing (API resolution by hash).
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of detected import hashing patterns
        """
        detections = []
        
        # Look for hash comparison patterns
        for i in range(len(instructions) - 2):
            instr = instructions[i]
            next_instr = instructions[i + 1] if i + 1 < len(instructions) else None
            
            # Pattern: call <hash_function>; cmp eax, <hash_value>
            if (instr.mnemonic.lower() == 'call' and 
                next_instr and next_instr.mnemonic.lower() == 'cmp' and
                'eax' in str(next_instr.operands).lower()):
                
                detections.append({
                    'type': 'import_hashing',
                    'address': instr.address,
                    'technique': 'API hashing',
                    'severity': 'HIGH',
                    'description': 'Resolves imports by hash (obfuscation/evasion technique)'
                })
                break  # Only report once
        
        return detections
    
    def detect_obfuscation_level(self, instructions: List[Instruction]) -> Dict[str, any]:
        """
        Assess overall obfuscation level.
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            Obfuscation assessment
        """
        if not instructions:
            return {'level': 'NONE', 'score': 0}
        
        score = 0
        indicators = []
        
        # Count junk instructions
        int3_count = sum(1 for i in instructions if i.mnemonic.lower() == 'int3')
        nop_count = sum(1 for i in instructions if i.mnemonic.lower() == 'nop')
        
        if int3_count > 20:
            score += 2
            indicators.append(f'{int3_count} INT3 instructions')
        
        if nop_count > 50:
            score += 1
            indicators.append(f'{nop_count} NOP instructions')
        
        # Count control flow changes
        jmp_count = sum(1 for i in instructions if 'jmp' in i.mnemonic.lower())
        call_count = sum(1 for i in instructions if i.mnemonic.lower() == 'call')
        
        if jmp_count > len(instructions) * 0.1:  # More than 10% jumps
            score += 2
            indicators.append(f'Excessive jumps ({jmp_count})')
        
        # Determine level
        if score >= 5:
            level = 'VERY HIGH'
        elif score >= 3:
            level = 'HIGH'
        elif score >= 1:
            level = 'MEDIUM'
        else:
            level = 'LOW'
        
        return {
            'level': level,
            'score': score,
            'indicators': indicators
        }
    
    def detect_vmprotect_patterns(self, instructions: List[Instruction]) -> List[Dict[str, any]]:
        """
        Detect VMProtect-like virtualization patterns.
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            List of detected VMProtect patterns
        """
        detections = []
        
        # Look for VM handler patterns
        # VMProtect uses a bytecode interpreter with handler dispatch
        
        # Pattern 1: Excessive indirect jumps/calls
        indirect_jumps = sum(1 for i in instructions 
                            if i.mnemonic.lower() in ['jmp', 'call'] and 
                            '[' in str(i.operands))
        
        if indirect_jumps > 10:
            detections.append({
                'type': 'vmprotect',
                'technique': 'VM handler dispatch',
                'count': indirect_jumps,
                'severity': 'VERY HIGH',
                'description': f'{indirect_jumps} indirect jumps/calls (VM bytecode interpreter)'
            })
        
        # Pattern 2: Context switching (push/pop many registers)
        for i in range(len(instructions) - 8):
            # Look for sequences of 8+ push instructions
            push_sequence = sum(1 for j in range(8) 
                              if i + j < len(instructions) and 
                              instructions[i + j].mnemonic.lower() == 'push')
            
            if push_sequence >= 8:
                detections.append({
                    'type': 'vmprotect',
                    'address': instructions[i].address,
                    'technique': 'VM context save',
                    'severity': 'HIGH',
                    'description': 'Saves all registers (VM context switching)'
                })
                break
        
        return detections
    
    def analyze_advanced_techniques(self, instructions: List[Instruction]) -> Dict[str, any]:
        """
        Comprehensive analysis of advanced techniques.
        
        Args:
            instructions: List of instructions to analyze
            
        Returns:
            Dictionary of all detected techniques
        """
        analysis = {
            'direct_syscalls': [],
            'anti_debugging': [],
            'pe_parsing': None,
            'import_hashing': [],
            'obfuscation': {},
            'vmprotect': [],
            'is_protected': False,
            'protection_level': 'NONE'
        }
        
        # Run all detections
        analysis['direct_syscalls'] = self.detect_direct_syscalls(instructions)
        analysis['anti_debugging'] = self.detect_anti_debugging(instructions)
        analysis['pe_parsing'] = self.detect_pe_parsing(instructions)
        analysis['import_hashing'] = self.detect_import_hashing(instructions)
        analysis['obfuscation'] = self.detect_obfuscation_level(instructions)
        analysis['vmprotect'] = self.detect_vmprotect_patterns(instructions)
        
        # Determine if protected
        detection_count = (
            len(analysis['direct_syscalls']) +
            len(analysis['anti_debugging']) +
            (1 if analysis['pe_parsing'] else 0) +
            len(analysis['import_hashing']) +
            len(analysis['vmprotect'])
        )
        
        analysis['is_protected'] = detection_count > 0
        
        # Determine protection level
        if detection_count >= 4 or analysis['vmprotect']:
            analysis['protection_level'] = 'VERY HIGH (VMProtect-like)'
        elif detection_count >= 2:
            analysis['protection_level'] = 'HIGH (Custom packer/protector)'
        elif detection_count >= 1:
            analysis['protection_level'] = 'MEDIUM (Basic protection)'
        else:
            analysis['protection_level'] = 'NONE or LOW'
        
        return analysis
    
    def format_advanced_report(self, analysis: Dict[str, any]) -> str:
        """
        Format advanced analysis report.
        
        Args:
            analysis: Analysis results
            
        Returns:
            Formatted report string
        """
        if not analysis['is_protected']:
            return ""
        
        report = []
        report.append("=" * 80)
        report.append("⚠️  ADVANCED PROTECTION DETECTED")
        report.append("=" * 80)
        report.append("")
        report.append(f"Protection Level: {analysis['protection_level']}")
        report.append("")
        
        # Direct syscalls
        if analysis['direct_syscalls']:
            report.append("-" * 80)
            report.append("🔴 DIRECT SYSCALLS (EDR Evasion)")
            report.append("-" * 80)
            for detection in analysis['direct_syscalls']:
                report.append(f"  • Address: {detection.get('address', 'N/A')}")
                report.append(f"    Technique: {detection['technique']}")
                report.append(f"    Syscall Number: {detection.get('syscall_number', 'Unknown')}")
                report.append(f"    ⚠️  {detection['description']}")
            report.append("")
        
        # Anti-debugging
        if analysis['anti_debugging']:
            report.append("-" * 80)
            report.append("🛡️  ANTI-DEBUGGING TECHNIQUES")
            report.append("-" * 80)
            for detection in analysis['anti_debugging']:
                report.append(f"  • {detection['technique']}")
                if 'address' in detection:
                    report.append(f"    Address: {detection['address']}")
                if 'count' in detection:
                    report.append(f"    Count: {detection['count']}")
                report.append(f"    ⚠️  {detection['description']}")
            report.append("")
        
        # PE parsing
        if analysis['pe_parsing']:
            report.append("-" * 80)
            report.append("📦 MANUAL PE PARSING")
            report.append("-" * 80)
            detection = analysis['pe_parsing']
            report.append(f"  • {detection['technique']}")
            report.append(f"    ⚠️  {detection['description']}")
            report.append("")
        
        # Import hashing
        if analysis['import_hashing']:
            report.append("-" * 80)
            report.append("🔐 API HASHING")
            report.append("-" * 80)
            for detection in analysis['import_hashing']:
                report.append(f"  • Address: {detection.get('address', 'N/A')}")
                report.append(f"    {detection['technique']}")
                report.append(f"    ⚠️  {detection['description']}")
            report.append("")
        
        # VMProtect
        if analysis['vmprotect']:
            report.append("-" * 80)
            report.append("🔴 VMPROTECT-LIKE VIRTUALIZATION")
            report.append("-" * 80)
            for detection in analysis['vmprotect']:
                report.append(f"  • {detection['technique']}")
                if 'address' in detection:
                    report.append(f"    Address: {detection['address']}")
                if 'count' in detection:
                    report.append(f"    Count: {detection['count']}")
                report.append(f"    ⚠️  {detection['description']}")
            report.append("")
        
        # Obfuscation level
        if analysis['obfuscation']['level'] != 'NONE':
            report.append("-" * 80)
            report.append("🌀 OBFUSCATION ANALYSIS")
            report.append("-" * 80)
            obf = analysis['obfuscation']
            report.append(f"  Level: {obf['level']} (Score: {obf['score']})")
            if obf.get('indicators'):
                report.append(f"  Indicators:")
                for indicator in obf['indicators']:
                    report.append(f"    • {indicator}")
            report.append("")
        
        # Warning message
        report.append("=" * 80)
        report.append("⚠️  WARNING: This binary uses advanced protection techniques")
        report.append("=" * 80)
        report.append("")
        report.append("This may indicate:")
        report.append("  • Commercial software protection (VMProtect, Themida, etc.)")
        report.append("  • Malware with anti-analysis features")
        report.append("  • Cracked/keygenned software")
        report.append("  • Advanced CTF challenge")
        report.append("")
        report.append("Recommended actions:")
        report.append("  1. Analyze in isolated environment (VM)")
        report.append("  2. Use advanced tools (IDA Pro, Ghidra, x64dbg)")
        report.append("  3. Consider dynamic analysis with API monitoring")
        report.append("  4. Look for OEP (Original Entry Point) after unpacking")
        report.append("")
        report.append("=" * 80)
        report.append("")
        
        return '\n'.join(report)

"""Assembly format detector and normalizer for various disassembly outputs"""
import re
from typing import Tuple, List


class FormatDetector:
    """Detects and normalizes various assembly format outputs"""

    def __init__(self):
        """Initialize format detector with regex patterns"""
        # objdump pattern: "  401000:  55                    push   rbp"
        self.objdump_pattern = re.compile(r'^\s*[0-9a-fA-F]+:\s+[0-9a-fA-F\s]+\s+\w+')

        # Ghidra pattern: "        001001a0 55              PUSH       RBP"
        self.ghidra_pattern = re.compile(r'^\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+[A-Z]+')

        # IDA pattern: ".text:0000000140001000                 push    rbp"
        self.ida_pattern = re.compile(r'^\.text:[0-9a-fA-F]+\s+\w+')

    def detect(self, text: str) -> str:
        """
        Detect assembly format from text sample.

        Args:
            text: Assembly code text

        Returns:
            Format name: 'objdump', 'ghidra', 'ida', or 'clean'
        """
        lines = text.strip().split('\n')[:50]  # Check first 50 lines

        objdump_count = 0
        ghidra_count = 0
        ida_count = 0

        for line in lines:
            if not line.strip() or line.strip().startswith(';') or line.strip().startswith('#'):
                continue

            if self.objdump_pattern.match(line):
                objdump_count += 1
            elif self.ghidra_pattern.match(line):
                ghidra_count += 1
            elif self.ida_pattern.match(line):
                ida_count += 1

        # Determine format by majority
        if objdump_count > 3:
            return 'objdump'
        elif ghidra_count > 3:
            return 'ghidra'
        elif ida_count > 3:
            return 'ida'
        else:
            return 'clean'

    def normalize(self, text: str, format_type: str = None) -> Tuple[str, int]:
        """
        Normalize assembly text by removing addresses, hex bytes, and metadata.

        Args:
            text: Raw assembly text
            format_type: Detected format (if None, will auto-detect)

        Returns:
            Tuple of (normalized_text, lines_processed)
        """
        if format_type is None:
            format_type = self.detect(text)

        lines = text.split('\n')
        normalized_lines = []

        if format_type == 'objdump':
            normalized_lines = self._normalize_objdump(lines)
        elif format_type == 'ghidra':
            normalized_lines = self._normalize_ghidra(lines)
        elif format_type == 'ida':
            normalized_lines = self._normalize_ida(lines)
        else:
            # Already clean, just filter empty lines and comments
            normalized_lines = self._normalize_clean(lines)

        normalized_text = '\n'.join(normalized_lines)
        return normalized_text, len(normalized_lines)

    def _normalize_objdump(self, lines: List[str]) -> List[str]:
        """
        Normalize objdump format.

        Example input:
          401000:  55                    push   rbp
          401001:  48 89 e5              mov    rbp,rsp

        Example output:
          push rbp
          mov rbp, rsp
        """
        normalized = []

        for line in lines:
            # Skip empty lines and section headers
            if not line.strip():
                continue
            if 'Disassembly of section' in line:
                continue
            if 'file format' in line:
                continue
            if line.strip().endswith(':') and not '\t' in line:
                # Function label like "main:"
                normalized.append(line.strip())
                continue

            # Match pattern: "  ADDRESS: HEX_BYTES    INSTRUCTION"
            match = re.match(r'^\s*[0-9a-fA-F]+:\s+[0-9a-fA-F\s]+\s+(.+)$', line)
            if match:
                instruction = match.group(1).strip()
                # Replace objdump's comma spacing with standard
                # "mov    rbp,rsp" -> "mov rbp, rsp"
                instruction = re.sub(r'(\w+)\s*,\s*', r'\1, ', instruction)
                normalized.append(instruction)
            elif line.strip() and not line.startswith('#'):
                # Keep other lines (labels, comments)
                normalized.append(line.strip())

        return normalized

    def _normalize_ghidra(self, lines: List[str]) -> List[str]:
        """
        Normalize Ghidra format.

        Example input:
                  001001a0 55              PUSH       RBP
                  001001a1 48 89 e5        MOV        RBP,RSP

        Example output:
          push rbp
          mov rbp, rsp
        """
        normalized = []

        for line in lines:
            # Skip empty lines, headers, and comment blocks
            if not line.strip():
                continue
            if line.strip().startswith('*') or line.strip().startswith('/'):
                continue
            if '****' in line:
                continue

            # Match Ghidra pattern: "  ADDRESS HEX MNEMONIC OPERANDS"
            match = re.match(r'^\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+([A-Z]+)\s*(.*)$', line)
            if match:
                mnemonic = match.group(1).lower()
                operands = match.group(2).strip()

                if operands:
                    # Normalize operand spacing
                    operands = re.sub(r',\s*', ', ', operands)
                    instruction = f"{mnemonic} {operands}"
                else:
                    instruction = mnemonic

                normalized.append(instruction)
            elif line.strip() and not any(skip in line for skip in ['XREF', 'FUN_', '***']):
                # Keep labels and other content
                normalized.append(line.strip())

        return normalized

    def _normalize_ida(self, lines: List[str]) -> List[str]:
        """
        Normalize IDA Pro format.

        Example input:
          .text:0000000140001000                 push    rbp
          .text:0000000140001001                 mov     rbp, rsp

        Example output:
          push rbp
          mov rbp, rsp
        """
        normalized = []

        for line in lines:
            # Skip empty lines and data definitions
            if not line.strip():
                continue
            if line.strip().startswith(';'):
                continue

            # Match IDA pattern: ".text:ADDRESS    INSTRUCTION"
            match = re.match(r'^\.text:[0-9a-fA-F]+\s+(.+)$', line)
            if match:
                instruction = match.group(1).strip()
                normalized.append(instruction)
            elif '<' in line and '>' in line:
                # Function label like "<main>"
                label = re.search(r'<([^>]+)>', line)
                if label:
                    normalized.append(f"{label.group(1)}:")
            elif line.strip() and not line.startswith('.data') and not line.startswith('.bss'):
                normalized.append(line.strip())

        return normalized

    def _normalize_clean(self, lines: List[str]) -> List[str]:
        """Normalize clean assembly (already in good format)"""
        normalized = []

        for line in lines:
            line = line.strip()
            # Skip empty lines and full-line comments
            if not line or line.startswith(';') or line.startswith('#'):
                continue
            normalized.append(line)

        return normalized

    def get_format_description(self, format_type: str) -> str:
        """Get human-readable format description"""
        descriptions = {
            'objdump': 'objdump (Intel syntax)',
            'ghidra': 'Ghidra listing',
            'ida': 'IDA Pro listing',
            'clean': 'Clean assembly'
        }
        return descriptions.get(format_type, 'Unknown format')

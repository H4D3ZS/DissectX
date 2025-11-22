"""Output formatter for assembly translations"""
from typing import List, Set
from datetime import datetime
from src.models import Instruction, CodeBlock


class OutputFormatter:
    """Formats assembly translations into readable output"""
    
    def __init__(self):
        """Initialize the output formatter"""
        pass
    
    def format(self, instructions: List[Instruction], blocks: List[CodeBlock],
               translations: List[str], pseudocode: List[str] = None, security_highlights: List[str] = None,
               max_lines: int = 1000, target_function: str = None) -> str:
        """
        Format the analysis results into a clean, structured Markdown report.

        Args:
            instructions: List of parsed instructions
            blocks: List of code blocks
            translations: English translations of instructions
            pseudocode: Pseudo-code translations
            security_highlights: Security findings
            max_lines: Maximum lines to output (None for unlimited)
            target_function: Specific function to analyze (None for all)

        Returns:
            Formatted markdown report
        """
        output_lines = []

        # Handle unlimited output
        effective_max = max_lines if max_lines is not None else 999999

        def add_line(line: str):
            if len(output_lines) < effective_max:
                output_lines.append(line)

        # Standard library functions - keep for reference
        std_lib_funcs = {
            'malloc', 'free', 'realloc', 'calloc', 'memset', 'memcpy', 'memmove',
            'strcpy', 'strncpy', 'strlen', 'strcmp', 'strncmp', 'strcat', 'strncat',
            'printf', 'sprintf', 'fprintf', 'vprintf', 'vsprintf',
            'fopen', 'fclose', 'fread', 'fwrite', 'fseek', 'ftell',
            'exit', 'abort', 'atexit',
            '__security_check_cookie', '__security_init_cookie'
        }

        # Filter instructions by target function if specified
        if target_function:
            filtered_instructions, filtered_translations, filtered_pseudocode = \
                self._filter_by_function(instructions, translations, pseudocode, target_function)
            if not filtered_instructions:
                add_line(f"# ❌ Function '{target_function}' not found in binary")
                add_line("")
                add_line(f"**Available functions:**")
                for instr in instructions:
                    if instr.label:
                        add_line(f"- {instr.label.strip('<>: ')}")
                return "\n".join(output_lines)
            instructions = filtered_instructions
            translations = filtered_translations
            pseudocode = filtered_pseudocode
            add_line(f"# 🎯 Function Analysis: {target_function}")
        else:
            add_line("# 🔍 Binary Reverse Engineering Report")

        add_line(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if max_lines:
            add_line(f"**Output Limit**: {max_lines} lines (use --unlimited for full output)")
        add_line("")

        # Group instructions by function
        functions = self._group_by_function(instructions, translations, pseudocode)

        # Process each function
        for func_name, func_data in functions.items():
            if len(output_lines) >= effective_max:
                add_line("")
                add_line(f"**⚠️ Output truncated at {effective_max} lines. Use --unlimited flag to see everything.**")
                break

            add_line("=" * 70)
            add_line(f"## Function: `{func_name}`")
            add_line("=" * 70)
            add_line("")

            # Generate one-line pseudo-code summary
            pseudo_oneline = self._generate_oneline_pseudocode(func_data['pseudocode'])
            add_line("**Reversed Assembly Code:**")
            add_line(f"```c")
            add_line(pseudo_oneline)
            add_line("```")
            add_line("")

            # What it does section
            add_line("**What it does:**")
            add_line("")
            high_level_desc = self._generate_high_level_description(
                func_data['instructions'],
                func_data['translations']
            )
            for line in high_level_desc:
                add_line(line)
            add_line("")

            # C/C++/Rust equivalent
            add_line("**C/C++ Equivalent Code:**")
            add_line("```c")
            c_equivalent = self._generate_c_equivalent(
                func_name,
                func_data['instructions'],
                func_data['pseudocode']
            )
            for line in c_equivalent:
                add_line(line)
            add_line("```")
            add_line("")

            # Breakdown section
            add_line("**Breakdown:**")
            add_line("")
            breakdown = self._generate_breakdown(
                func_data['instructions'],
                func_data['translations'],
                func_data['pseudocode']
            )
            for line in breakdown:
                add_line(line)
            add_line("")

        # Security summary at the end
        if security_highlights and not target_function:
            add_line("=" * 70)
            add_line("## 🛡️ Security Findings Summary")
            add_line("=" * 70)
            add_line("")

            # Categorize and deduplicate
            high_findings = []
            medium_findings = []
            low_findings = []

            for highlight in security_highlights:
                if '[HIGH]' in highlight:
                    high_findings.append(highlight)
                elif '[MEDIUM]' in highlight:
                    medium_findings.append(highlight)
                elif '[LOW]' in highlight:
                    low_findings.append(highlight)

            if high_findings:
                add_line("**🔴 HIGH Severity:**")
                deduped = self._deduplicate_findings(high_findings)
                for finding, count in deduped[:10]:
                    add_line(f"- {finding} ({count}x)" if count > 1 else f"- {finding}")
                add_line("")

            if medium_findings:
                add_line("**🟡 MEDIUM Severity:**")
                deduped = self._deduplicate_findings(medium_findings)
                for finding, count in deduped[:10]:
                    add_line(f"- {finding} ({count}x)" if count > 1 else f"- {finding}")
                add_line("")

            if low_findings:
                add_line(f"**🟢 LOW Severity:** {len(low_findings)} findings (use --unlimited to see all)")
                add_line("")

        return "\n".join(output_lines)

    def _filter_by_function(self, instructions: List[Instruction], translations: List[str],
                           pseudocode: List[str], target_func: str) -> tuple:
        """Filter instructions to only include a specific function"""
        filtered_instructions = []
        filtered_translations = []
        filtered_pseudocode = []

        in_target_function = False
        target_clean = target_func.strip().lower()

        for i, instr in enumerate(instructions):
            # Check if we're entering the target function
            if instr.label:
                clean_label = instr.label.strip('<>: ').lower()
                if clean_label == target_clean:
                    in_target_function = True
                elif in_target_function:
                    # Entered a different function, stop
                    break

            if in_target_function:
                filtered_instructions.append(instr)
                if i < len(translations):
                    filtered_translations.append(translations[i])
                if pseudocode and i < len(pseudocode):
                    filtered_pseudocode.append(pseudocode[i])

        return filtered_instructions, filtered_translations, filtered_pseudocode

    def _group_by_function(self, instructions: List[Instruction],
                          translations: List[str], pseudocode: List[str]) -> dict:
        """Group instructions by function"""
        functions = {}
        current_function = "unknown"
        current_instrs = []
        current_trans = []
        current_pseudo = []

        for i, instr in enumerate(instructions):
            if instr.label:
                # Save previous function
                if current_instrs:
                    functions[current_function] = {
                        'instructions': current_instrs,
                        'translations': current_trans,
                        'pseudocode': current_pseudo
                    }

                # Start new function
                current_function = instr.label.strip('<>: ')
                current_instrs = [instr]
                current_trans = [translations[i] if i < len(translations) else ""]
                current_pseudo = [pseudocode[i] if pseudocode and i < len(pseudocode) else ""]
            else:
                current_instrs.append(instr)
                if i < len(translations):
                    current_trans.append(translations[i])
                if pseudocode and i < len(pseudocode):
                    current_pseudo.append(pseudocode[i])

        # Save last function
        if current_instrs:
            functions[current_function] = {
                'instructions': current_instrs,
                'translations': current_trans,
                'pseudocode': current_pseudo
            }

        return functions

    def _generate_oneline_pseudocode(self, pseudocode_list: List[str]) -> str:
        """Generate a single-line pseudo-code summary"""
        # Filter out empty lines and join
        codes = [p.strip() for p in pseudocode_list if p and p.strip()]
        # Limit to reasonable length
        if len(codes) > 10:
            return " ".join(codes[:10]) + " ..."
        return " ".join(codes) if codes else "// No pseudo-code available"

    def _generate_high_level_description(self, instructions: List[Instruction],
                                        translations: List[str]) -> List[str]:
        """Generate high-level 'what it does' description"""
        lines = []

        # Group by logical operations
        for i, trans in enumerate(translations):
            if trans:
                # Clean up the translation and format it
                lines.append(f"{trans}")
                if i < len(instructions) - 1:
                    lines.append("(This prepares for the next operation.)")
                    lines.append("")

        if not lines:
            lines.append("Function performs low-level operations.")

        return lines[:15]  # Limit to first 15 descriptions

    def _generate_c_equivalent(self, func_name: str, instructions: List[Instruction],
                              pseudocode_list: List[str]) -> List[str]:
        """Generate pure C/C++ equivalent code with explanatory comments"""
        lines = []

        # Determine function signature based on calling convention analysis
        # RCX = first arg in Windows x64 calling convention
        first_arg_used = any(i.mnemonic == 'mov' and 'rcx' in str(i.operands) for i in instructions[:5])

        if func_name in ['malloc', 'calloc', 'realloc']:
            lines.append(f"void* {func_name}(size_t size) {{")
        elif func_name in ['free']:
            lines.append(f"void {func_name}(void* ptr) {{")
        elif func_name in ['strcmp', 'strncmp', 'memcmp']:
            lines.append(f"int {func_name}(const char* str1, const char* str2, size_t n) {{")
        elif first_arg_used:
            lines.append(f"void {func_name}(void* arg) {{")
        else:
            lines.append(f"void {func_name}(void) {{")

        # Analyze prologue
        has_rbx_save = any(i.mnemonic == 'push' and 'rbx' in str(i.operands) for i in instructions[:5])
        has_rdi_save = any(i.mnemonic == 'push' and 'rdi' in str(i.operands) for i in instructions[:5])
        has_rsi_save = any(i.mnemonic == 'push' and 'rsi' in str(i.operands) for i in instructions[:5])

        stack_alloc_size = None
        for instr in instructions[:10]:
            if instr.mnemonic == 'sub' and 'rsp' in str(instr.operands):
                if len(instr.operands) > 1:
                    stack_alloc_size = instr.operands[1]
                break

        # Add prologue explanation
        lines.append("    // Prologue: Save callee-saved registers")
        if has_rbx_save:
            lines.append("    // RBX saved → Will be used as local variable")
        if has_rdi_save:
            lines.append("    // RDI saved → Will preserve this register")
        if has_rsi_save:
            lines.append("    // RSI saved → Will preserve this register")

        if stack_alloc_size:
            lines.append(f"    // RSP -= {stack_alloc_size} → Allocate stack space for locals")
            lines.append(f"    char local_buffer[{stack_alloc_size}];")

        lines.append("")

        # Analyze what the function does at a high level
        has_call = any(i.mnemonic == 'call' for i in instructions)
        has_loop = any(i.mnemonic in ['loop', 'jmp'] for i in instructions)
        has_comparison = any(i.mnemonic in ['cmp', 'test'] for i in instructions)
        has_xor = any(i.mnemonic == 'xor' and len(i.operands) >= 2 and
                     i.operands[0] != i.operands[1] for i in instructions)

        # Generate high-level C code based on patterns
        lines.append("    // Function logic:")

        # First argument handling
        if first_arg_used:
            lines.append("    // RCX → First argument passed to function")
            if func_name == 'free':
                lines.append("    void* block_to_free = ptr;")
            elif func_name in ['malloc', 'realloc']:
                lines.append("    size_t requested_size = size;")
            else:
                lines.append("    void* parameter = arg;")
            lines.append("")

        # Detect common patterns
        if func_name in ['malloc', 'calloc', 'realloc']:
            lines.append("    // Call Windows Heap API")
            lines.append("    HANDLE heap = GetProcessHeap();")
            lines.append("    void* allocated_memory = HeapAlloc(heap, 0, requested_size);")
            lines.append("    ")
            lines.append("    // Validate allocation")
            lines.append("    if (allocated_memory == NULL) {")
            lines.append("        return NULL;  // Allocation failed")
            lines.append("    }")
            lines.append("    ")
            lines.append("    return allocated_memory;")
        elif func_name == 'free':
            lines.append("    // Call Windows Heap API")
            lines.append("    HANDLE heap = GetProcessHeap();")
            lines.append("    BOOL result = HeapFree(heap, 0, block_to_free);")
            lines.append("    ")
            lines.append("    // No return value for free")
            lines.append("    return;")
        elif func_name in ['strcmp', 'strncmp']:
            lines.append("    // Compare strings byte by byte")
            lines.append("    size_t i = 0;")
            lines.append("    while (i < n) {")
            lines.append("        if (str1[i] != str2[i]) {")
            lines.append("            return str1[i] - str2[i];  // Different")
            lines.append("        }")
            lines.append("        if (str1[i] == '\\0') {")
            lines.append("            break;  // End of string")
            lines.append("        }")
            lines.append("        i++;")
            lines.append("    }")
            lines.append("    return 0;  // Strings match")
        elif has_loop and has_comparison:
            lines.append("    // Loop through data")
            lines.append("    for (size_t i = 0; i < length; i++) {")
            lines.append("        // Process each element")
            if has_xor:
                lines.append("        buffer[i] ^= key;  // XOR operation")
            else:
                lines.append("        // Perform operation on buffer[i]")
            lines.append("    }")
        elif has_call:
            lines.append("    // Call external function(s)")
            lines.append("    // Perform operation and return result")
        else:
            lines.append("    // Perform low-level operations")
            lines.append("    // Function logic not fully reconstructed")

        lines.append("}")

        return lines

    def _generate_breakdown(self, instructions: List[Instruction],
                           translations: List[str], pseudocode_list: List[str]) -> List[str]:
        """Generate detailed breakdown with → arrows"""
        lines = []

        for i, instr in enumerate(instructions[:20]):  # Limit to first 20 instructions
            # Format the instruction
            mnemonic = instr.mnemonic
            operands_str = ", ".join(instr.operands) if instr.operands else ""

            if operands_str:
                lines.append(f"**{mnemonic} {operands_str}**")
            else:
                lines.append(f"**{mnemonic}**")

            # Add translation with arrow
            if i < len(translations) and translations[i]:
                lines.append(f"→ {translations[i]}")
            else:
                lines.append(f"→ Performs {mnemonic} operation")

            lines.append("")

        if len(instructions) > 20:
            lines.append(f"... and {len(instructions) - 20} more instructions")

        return lines

    def _map_instructions_to_blocks(self, instructions: List[Instruction],
                                   blocks: List[CodeBlock]) -> dict:
        """Map instruction indices to their containing blocks"""
        mapping = {}

        for block in blocks:
            for block_instr in block.instructions:
                # Find this instruction's index in the main list
                for i, instr in enumerate(instructions):
                    if instr is block_instr:
                        mapping[i] = block
                        break

        return mapping

    def _deduplicate_findings(self, findings: List[str]) -> List[tuple]:
        """
        Deduplicate security findings and return with counts.

        Args:
            findings: List of security finding strings

        Returns:
            List of tuples (finding_text, count) sorted by count descending
        """
        from collections import Counter

        # Remove severity tags for deduplication
        cleaned_findings = []
        for finding in findings:
            # Remove [HIGH], [MEDIUM], [LOW] tags
            clean = finding.replace('[HIGH] ', '').replace('[MEDIUM] ', '').replace('[LOW] ', '').replace('[INFO] ', '')
            cleaned_findings.append(clean)

        # Count occurrences
        counts = Counter(cleaned_findings)

        # Sort by count (descending), then alphabetically
        return sorted(counts.items(), key=lambda x: (-x[1], x[0]))

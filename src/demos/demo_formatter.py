"""Demo of the output formatter with a complete example"""
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.parser import AssemblyParser
from src.analyzer import PatternAnalyzer
from src.translator import InstructionTranslator
from src.security_highlighter import SecurityHighlighter
from src.formatter import OutputFormatter


def main():
    """Demonstrate the complete assembly translation pipeline"""
    
    # Sample assembly code from a simple function
    assembly_code = """
140001000 push rbp                    ; Save base pointer
140001001 mov rbp, rsp                ; Set up stack frame
140001004 sub rsp, 0x20               ; Allocate 32 bytes
140001008 mov rax, 0x0                ; Initialize counter
loop_start:
14000100c cmp rax, 0x10               ; Compare counter with 16
140001010 jge end_loop                ; Exit if >= 16
140001012 add rax, 0x1                ; Increment counter
140001016 jmp loop_start              ; Jump back to loop start
end_loop:
14000101a add rsp, 0x20               ; Deallocate stack space
14000101e pop rbp                     ; Restore base pointer
14000101f ret                         ; Return from function
"""
    
    print("=" * 70)
    print("ASSEMBLY TO ENGLISH TRANSLATOR - DEMO")
    print("=" * 70)
    print()
    
    # Step 1: Parse
    print("Step 1: Parsing assembly code...")
    parser = AssemblyParser()
    instructions = parser.parse(assembly_code)
    print(f"  ✓ Parsed {len(instructions)} instructions")
    print()
    
    # Step 2: Analyze patterns
    print("Step 2: Analyzing code patterns...")
    analyzer = PatternAnalyzer()
    blocks = analyzer.analyze(instructions)
    print(f"  ✓ Identified {len(blocks)} code blocks:")
    for block in blocks:
        print(f"    - {block.block_type}")
    print()
    
    # Step 3: Translate instructions
    print("Step 3: Translating instructions to English...")
    translator = InstructionTranslator()
    translations = [translator.translate(instr) for instr in instructions]
    print(f"  ✓ Generated {len(translations)} translations")
    print()
    
    # Step 4: Check for security issues
    print("Step 4: Checking for security-relevant operations...")
    highlighter = SecurityHighlighter()
    security_highlights = highlighter.highlight(instructions)
    if security_highlights:
        print(f"  ⚠ Found {len(security_highlights)} security observations")
    else:
        print("  ✓ No security issues detected")
    print()
    
    # Step 5: Format output
    print("Step 5: Formatting output...")
    formatter = OutputFormatter()
    output = formatter.format(instructions, blocks, translations, security_highlights)
    print("  ✓ Output formatted")
    print()
    
    # Display the final output
    print("=" * 70)
    print("TRANSLATED OUTPUT")
    print("=" * 70)
    print()
    print(output)
    print()
    print("=" * 70)


if __name__ == "__main__":
    main()

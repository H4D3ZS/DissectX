#!/usr/bin/env python3
"""Demo script to show SecurityHighlighter in action"""

from src.parser import AssemblyParser
from src.security_highlighter import SecurityHighlighter

# Sample assembly code with various security-relevant operations
sample_code = """
; Function prologue
push rbp
mov rbp, rsp
sub rsp, 0x40

; Load stack canary
mov rax, qword ptr [__security_cookie]  ; load security cookie
xor rax, rbp
mov qword ptr [rbp-0x8], rax

; Allocate buffer
mov rcx, 0x100
call malloc
test rax, rax
jz error_exit

; Unsafe string copy
mov rcx, rax
call strcpy

; XOR encryption loop
mov rcx, 0x100
xor_loop:
xor byte ptr [rax], 0x42
inc rax
dec rcx
jnz xor_loop

; Password check
call strcmp
test rax, rax
jne auth_failed

; Character comparison
cmp byte ptr [rbx], 0x50
je password_correct

; Bounds check before access
cmp rdx, 0x100
jae bounds_error
mov al, byte ptr [rsi+rdx]

; Free memory
mov rcx, rax
call free

; Verify stack canary
mov rax, qword ptr [rbp-0x8]
xor rax, rbp
call __security_check_cookie

; Function epilogue
add rsp, 0x40
pop rbp
ret
"""

def main():
    parser = AssemblyParser()
    highlighter = SecurityHighlighter()
    
    print("=" * 80)
    print("Security Highlighter Demo")
    print("=" * 80)
    print()
    
    # Parse the assembly code
    instructions = parser.parse(sample_code)
    print(f"Parsed {len(instructions)} instructions")
    print()
    
    # Highlight security-relevant operations
    observations = highlighter.highlight(instructions)
    
    print(f"Found {len(observations)} security observations:")
    print()
    
    # Group by type
    by_type = {}
    for obs in observations:
        obs_type = obs['type']
        if obs_type not in by_type:
            by_type[obs_type] = []
        by_type[obs_type].append(obs)
    
    # Display observations by category
    for obs_type, obs_list in sorted(by_type.items()):
        print(f"\n{obs_type.upper().replace('_', ' ')}:")
        print("-" * 80)
        for i, obs in enumerate(obs_list, 1):
            severity = obs.get('severity', 'info')
            print(f"  {i}. [{severity.upper()}] {obs['description']}")
            if obs.get('addresses'):
                print(f"     Addresses: {', '.join(obs['addresses'][:3])}")
        print()
    
    print("=" * 80)

if __name__ == "__main__":
    main()

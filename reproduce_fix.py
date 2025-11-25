
from typing import Dict, Any

# Mock BinaryAnalyzer class with the fix
class BinaryAnalyzer:
    def analyze_binary(self, filepath: str, advanced: bool = False) -> Dict[str, Any]:
        analysis = {
            'filepath': filepath,
            'advanced_analysis': {}
        }
        
        if advanced:
            advanced_results = {}
            # Simulate advanced detection
            advanced_results['syscalls'] = [{'name': 'execve', 'address': '0x1234'}]
            advanced_results['api_hashing'] = [{'hash': '0xdeadbeef', 'api': 'CreateFile'}]
            advanced_results['junk_code'] = [{'type': 'nop_sled', 'address': '0x5678'}]
            advanced_results['flags'] = ['flag{test_flag}']
            advanced_results['decrypted_strings'] = [{'encrypted': '...', 'decrypted': 'secret'}]
            
            # THE FIX: Assign advanced_results to analysis
            analysis['advanced_analysis'] = advanced_results
            
        return analysis

# Mock Server logic
def server_logic():
    analyzer = BinaryAnalyzer()
    raw_results = analyzer.analyze_binary("test_binary", advanced=True)
    
    # Extract data as server.py does
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
            
    # Construct final results
    analysis_results = {
        'advanced_analysis': {
            'syscalls': syscalls,
            'api_hashes': api_hashes,
            'junk_patterns': junk_patterns,
            'advanced_flags': advanced_flags,
            'decrypted_strings': decrypted_strings
        }
    }
    
    return analysis_results

# Verify
results = server_logic()
print("Syscalls:", len(results['advanced_analysis']['syscalls']))
print("API Hashes:", len(results['advanced_analysis']['api_hashes']))
print("Junk Patterns:", len(results['advanced_analysis']['junk_patterns']))
print("Advanced Flags:", len(results['advanced_analysis']['advanced_flags']))
print("Decrypted Strings:", len(results['advanced_analysis']['decrypted_strings']))

if (len(results['advanced_analysis']['syscalls']) > 0 and 
    len(results['advanced_analysis']['advanced_flags']) > 0):
    print("SUCCESS: Advanced analysis data is correctly propagated.")
else:
    print("FAILURE: Advanced analysis data is missing.")

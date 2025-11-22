#!/usr/bin/env python3
"""
Quick helper script for decoding passwords from CTF challenges
"""

def xor_decode(data, key):
    """XOR decode data with a key"""
    if isinstance(data, str):
        data = bytes.fromhex(data.replace('0x', '').replace(' ', ''))
    if isinstance(key, str):
        key = int(key, 0)
    
    result = bytes(b ^ key for b in data)
    return result.decode('ascii', errors='ignore')


def xor_decode_multi(data, key):
    """XOR decode with multi-byte key"""
    if isinstance(data, str):
        data = bytes.fromhex(data.replace('0x', '').replace(' ', ''))
    if isinstance(key, str):
        key = bytes.fromhex(key.replace('0x', '').replace(' ', ''))
    
    result = bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    return result.decode('ascii', errors='ignore')


def hex_to_string(hex_val):
    """Convert hex to ASCII string"""
    if isinstance(hex_val, int):
        hex_val = hex(hex_val)[2:]
    hex_val = hex_val.replace('0x', '').replace(' ', '')
    
    # Try little-endian
    try:
        le_bytes = bytes.fromhex(hex_val)[::-1]
        le_result = le_bytes.decode('ascii', errors='ignore')
    except:
        le_result = None
    
    # Try big-endian
    try:
        be_bytes = bytes.fromhex(hex_val)
        be_result = be_bytes.decode('ascii', errors='ignore')
    except:
        be_result = None
    
    return {
        'little_endian': le_result,
        'big_endian': be_result
    }


def caesar_decode(text, shift):
    """Caesar cipher decoder"""
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base - shift) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)


def rot13(text):
    """ROT13 decoder"""
    return caesar_decode(text, 13)


def base64_decode(text):
    """Base64 decoder"""
    import base64
    try:
        decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
        return decoded
    except:
        return None


def base64_encode(text):
    """Base64 encoder"""
    import base64
    try:
        encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
        return encoded
    except:
        return None


def brute_force_xor(data, max_key=256):
    """Try all single-byte XOR keys"""
    if isinstance(data, str):
        data = bytes.fromhex(data.replace('0x', '').replace(' ', ''))
    
    results = []
    for key in range(max_key):
        try:
            decoded = bytes(b ^ key for b in data)
            text = decoded.decode('ascii', errors='ignore')
            # Check if result looks like readable text
            if all(c.isprintable() or c.isspace() for c in text):
                results.append({
                    'key': f'0x{key:02x}',
                    'key_char': chr(key) if 32 <= key < 127 else '?',
                    'result': text
                })
        except:
            pass
    
    return results


# ============================================================================
# EXAMPLES
# ============================================================================

def example_ch3():
    """Example: Decode ch3.exe password"""
    print("=" * 60)
    print("Example: ch3.exe Password Decoding")
    print("=" * 60)
    
    # From analysis:
    # mov dword ptr [rbp - 0x19], 0x242b2c31
    # mov byte ptr [rbp - 0x15], 0x24
    # XOR key: 0x42
    
    encoded_hex = "312c2b2424"  # Little-endian bytes
    xor_key = 0x42
    
    print(f"\nEncoded (hex): {encoded_hex}")
    print(f"XOR Key: 0x{xor_key:02x} ('{chr(xor_key)}')")
    
    password = xor_decode(encoded_hex, xor_key)
    print(f"Decoded Password: {password}")
    print()


def interactive_mode():
    """Interactive decoder"""
    print("\n" + "=" * 60)
    print("🔓 Interactive Password Decoder")
    print("=" * 60)
    
    while True:
        print("\nOptions:")
        print("  1. XOR decode (single-byte key)")
        print("  2. XOR decode (multi-byte key)")
        print("  3. Hex to string")
        print("  4. Caesar/ROT13")
        print("  5. Brute force XOR")
        print("  6. Base64 decode")
        print("  7. Base64 encode")
        print("  8. Example (ch3.exe)")
        print("  0. Exit")
        
        choice = input("\nChoice: ").strip()
        
        if choice == '0':
            break
        
        elif choice == '1':
            data = input("Encoded data (hex): ").strip()
            key = input("XOR key (hex): ").strip()
            try:
                result = xor_decode(data, key)
                print(f"Result: {result}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '2':
            data = input("Encoded data (hex): ").strip()
            key = input("XOR key (hex, multi-byte): ").strip()
            try:
                result = xor_decode_multi(data, key)
                print(f"Result: {result}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '3':
            hex_val = input("Hex value: ").strip()
            try:
                results = hex_to_string(hex_val)
                print(f"Little-endian: {results['little_endian']}")
                print(f"Big-endian: {results['big_endian']}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '4':
            text = input("Text: ").strip()
            shift = input("Shift (default 13 for ROT13): ").strip()
            shift = int(shift) if shift else 13
            try:
                result = caesar_decode(text, shift)
                print(f"Result: {result}")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '5':
            data = input("Encoded data (hex): ").strip()
            try:
                results = brute_force_xor(data)
                print(f"\nFound {len(results)} possible results:")
                for r in results[:20]:  # Show top 20
                    print(f"  Key {r['key']} ('{r['key_char']}'): {r['result']}")
                if len(results) > 20:
                    print(f"  ... and {len(results) - 20} more")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '6':
            text = input("Base64 encoded text: ").strip()
            try:
                result = base64_decode(text)
                if result:
                    print(f"Decoded: {result}")
                else:
                    print("Failed to decode")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '7':
            text = input("Text to encode: ").strip()
            try:
                result = base64_encode(text)
                if result:
                    print(f"Encoded: {result}")
                else:
                    print("Failed to encode")
            except Exception as e:
                print(f"Error: {e}")
        
        elif choice == '8':
            example_ch3()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        # Command-line mode
        if sys.argv[1] == 'xor' and len(sys.argv) >= 4:
            data = sys.argv[2]
            key = sys.argv[3]
            print(xor_decode(data, key))
        
        elif sys.argv[1] == 'brute' and len(sys.argv) >= 3:
            data = sys.argv[2]
            results = brute_force_xor(data)
            for r in results:
                print(f"{r['key']}: {r['result']}")
        
        elif sys.argv[1] == 'hex' and len(sys.argv) >= 3:
            hex_val = sys.argv[2]
            results = hex_to_string(hex_val)
            print(f"LE: {results['little_endian']}")
            print(f"BE: {results['big_endian']}")
        
        elif sys.argv[1] == 'example':
            example_ch3()
        
        else:
            print("Usage:")
            print("  python decode_helper.py xor <hex_data> <key>")
            print("  python decode_helper.py brute <hex_data>")
            print("  python decode_helper.py hex <hex_value>")
            print("  python decode_helper.py example")
            print("  python decode_helper.py  (interactive mode)")
    
    else:
        # Interactive mode
        example_ch3()
        interactive_mode()

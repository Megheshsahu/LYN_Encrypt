import hashlib
import base64
import random
import os

def pad_pkcs7(data, block_size=16):
    """PKCS#7 padding - the standard padding method used in AES"""
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def unpad_pkcs7(data):
    """Remove PKCS#7 padding"""
    if len(data) == 0:
        return data
    padding_length = data[-1]
    if padding_length > 16 or padding_length == 0:
        return data
    # Verify padding is correct
    for i in range(padding_length):
        if data[-(i+1)] != padding_length:
            return data  # Invalid padding, return as is
    return data[:-padding_length]

def xor_bytes(data, key):
    """XOR each byte of data with the corresponding byte of the key"""
    return bytes(a ^ b for a, b in zip(data, key))

def create_substitution_box(key_seed):
    """Create a 256-byte substitution box based on key"""
    box = list(range(256))
    key_hash = hashlib.sha256(key_seed).digest()
    
    # Use key hash to seed the PRNG
    random.seed(int.from_bytes(key_hash, byteorder='big'))
    random.shuffle(box)
    
    # Create the inverse box
    inverse_box = [0] * 256
    for i, val in enumerate(box):
        inverse_box[val] = i
    
    return bytes(box), bytes(inverse_box)

def create_permutation_table(key_hash):
    """Create a fixed permutation table based on key hash"""
    # Create a deterministic but non-trivial permutation
    perm = list(range(16))
    
    # Use key hash bytes to create a deterministic shuffle
    temp_random = random.Random()
    temp_random.seed(int.from_bytes(key_hash[:8], byteorder='big'))
    temp_random.shuffle(perm)
    
    # Create inverse permutation
    inv_perm = [0] * 16
    for i, val in enumerate(perm):
        inv_perm[val] = i
    
    return perm, inv_perm

def calculate_rounds(key):
    """Calculate number of rounds based on key"""
    key_hash = hashlib.sha256(key).digest()
    # Use first 4 bytes of hash to determine rounds
    # Minimum 4 rounds, maximum 16 rounds
    rounds = 4 + (int.from_bytes(key_hash[:4], byteorder='big') % 13)
    return rounds

def simple_encrypt_block(block, key_hash, sbox, rounds):
    """Simple but effective block encryption with dynamic rounds"""
    result = bytearray(block)
    perm, _ = create_permutation_table(key_hash)
    
    for round_num in range(rounds):
        # Round operations cycle through the 4 basic operations
        operation = round_num % 4
        
        if operation == 0:  # Substitution
            for i in range(16):
                result[i] = sbox[result[i]]
        
        elif operation == 1:  # Key mixing
            for i in range(16):
                # Use different parts of key_hash for different rounds
                key_offset = (round_num // 4) % 2
                key_byte = key_hash[(i + key_offset * 16) % 32]
                result[i] = (result[i] + key_byte) % 256
        
        elif operation == 2:  # Permutation
            temp = bytearray(16)
            for i in range(16):
                temp[perm[i]] = result[i]
            result = temp
        
        elif operation == 3:  # Another substitution
            for i in range(16):
                result[i] = sbox[result[i]]
    
    return bytes(result)

def simple_decrypt_block(block, key_hash, inv_sbox, rounds):
    """Simple but effective block decryption with dynamic rounds"""
    result = bytearray(block)
    _, inv_perm = create_permutation_table(key_hash)
    
    # Reverse the rounds in opposite order
    for round_num in range(rounds - 1, -1, -1):
        operation = round_num % 4
        
        if operation == 3:  # Reverse substitution
            for i in range(16):
                result[i] = inv_sbox[result[i]]
        
        elif operation == 2:  # Reverse permutation
            temp = bytearray(16)
            for i in range(16):
                temp[inv_perm[i]] = result[i]
            result = temp
        
        elif operation == 1:  # Reverse key mixing
            for i in range(16):
                # Use same key offset calculation as encryption
                key_offset = (round_num // 4) % 2
                key_byte = key_hash[(i + key_offset * 16) % 32]
                result[i] = (result[i] - key_byte) % 256
        
        elif operation == 0:  # Reverse substitution
            for i in range(16):
                result[i] = inv_sbox[result[i]]
    
    return bytes(result)

def encrypt(plaintext, key):
    """Encrypt plaintext using a simplified but secure LYN algorithm"""
    if not plaintext or not key:
        raise ValueError("Plaintext and key cannot be empty")
    
    # Convert inputs to bytes
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Calculate number of rounds based on key
    rounds = calculate_rounds(key)
    
    # Generate random IV (initialization vector)
    iv = os.urandom(16)
    
    # Generate key hash
    key_hash = hashlib.sha256(key).digest()
    
    # Create substitution boxes
    sbox, _ = create_substitution_box(key + b'sbox')
    
    # Store original length and calculate checksum
    original_length = len(plaintext)
    checksum = hashlib.sha256(plaintext).digest()[:16]
    
    # Pad the plaintext to multiple of 16 bytes
    padded_data = pad_pkcs7(plaintext)
    
    # Process each block with CBC mode
    blocks = [padded_data[i:i+16] for i in range(0, len(padded_data), 16)]
    encrypted_blocks = []
    
    # Initialize with IV for CBC mode
    previous_block = iv
    
    for block in blocks:
        # XOR with previous block (CBC mode)
        xored_block = xor_bytes(block, previous_block)
        
        # Encrypt the block with dynamic rounds
        encrypted_block = simple_encrypt_block(xored_block, key_hash, sbox, rounds)
        
        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block  # For next block's CBC
    
    # Combine all encrypted blocks
    encrypted_data = b''.join(encrypted_blocks)
    
    # Create header: IV + checksum + original_length + rounds
    header = iv + checksum + original_length.to_bytes(4, byteorder='big') + rounds.to_bytes(1, byteorder='big')
    
    # Combine header with encrypted data
    result = header + encrypted_data
    
    # Return as base64
    return base64.b64encode(result).decode('utf-8')

def decrypt(ciphertext, key):
    """Decrypt ciphertext using the simplified LYN algorithm"""
    if not ciphertext or not key:
        raise ValueError("Ciphertext and key cannot be empty")
    
    # Convert key to bytes
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    try:
        # Decode base64
        binary_data = base64.b64decode(ciphertext)
        
        # Extract header: IV(16) + checksum(16) + original_length(4) + rounds(1) = 37 bytes
        if len(binary_data) < 37:
            return "Error: Invalid ciphertext format"
        
        iv = binary_data[:16]
        checksum = binary_data[16:32]
        original_length = int.from_bytes(binary_data[32:36], byteorder='big')
        rounds = int.from_bytes(binary_data[36:37], byteorder='big')
        
        # Extract encrypted data
        encrypted_data = binary_data[37:]
        
        # Verify we have complete blocks
        if len(encrypted_data) % 16 != 0:
            return "Error: Invalid encrypted data length"
        
        # Generate key hash
        key_hash = hashlib.sha256(key).digest()
        
        # Create substitution boxes
        _, inv_sbox = create_substitution_box(key + b'sbox')
        
        # Process each block
        blocks = [encrypted_data[i:i+16] for i in range(0, len(encrypted_data), 16)]
        decrypted_blocks = []
        
        # Initialize with IV for CBC mode
        previous_block = iv
        
        for encrypted_block in blocks:
            # Decrypt the block with stored rounds
            decrypted_block = simple_decrypt_block(encrypted_block, key_hash, inv_sbox, rounds)
            
            # XOR with previous block (CBC mode)
            plaintext_block = xor_bytes(decrypted_block, previous_block)
            
            decrypted_blocks.append(plaintext_block)
            previous_block = encrypted_block  # For next block's CBC
        
        # Combine all decrypted blocks
        decrypted_data = b''.join(decrypted_blocks)
        
        # Remove padding
        unpadded_data = unpad_pkcs7(decrypted_data)
        
        # Trim to original length
        if len(unpadded_data) >= original_length:
            final_data = unpadded_data[:original_length]
        else:
            return "Error: Decrypted data is shorter than expected"
        
        # Verify checksum
        calculated_checksum = hashlib.sha256(final_data).digest()[:16]
        if calculated_checksum != checksum:
            return "Error: Data integrity check failed - incorrect key or corrupted data"
        
        # Return decrypted plaintext
        return final_data.decode('utf-8')
        
    except Exception as e:
        return f"Error: {str(e)}"

def test_algorithm():
    """Test the algorithm with various inputs."""
    print("\nTesting Dynamic Rounds Algorithm...")
    print("=" * 50)
    
    test_cases = [
        ("hello", "key123"),
        ("monu is good boy", "12345"),
        ("Short", "k"),
        ("This is a longer message to test encryption", "testkey"),
        ("The LYN encryption algorithm provides a custom approach to data security", "secret123"),
        ("monuisdvwef", "1234"),  # Your test case
        ("", "key"),  # Edge case: empty string
        ("A", "x"),   # Single character
        ("Testing with special chars: !@#$%^&*()", "special_key"),
        ("Unicode test: 你好世界", "unicode_key")
    ]
    
    all_passed = True
    for i, (text, test_key) in enumerate(test_cases, 1):
        try:
            print(f"Test {i}: '{text[:30]}{'...' if len(text) > 30 else ''}' with key '{test_key}'")
            
            # Skip empty string test as it's handled by the ValueError
            if not text:
                print(f"  Skipped: Empty plaintext")
                continue
            
            # Show number of rounds for this key
            rounds = calculate_rounds(test_key.encode('utf-8'))
            print(f"  Rounds: {rounds}")
            
            encrypted = encrypt(text, test_key)
            print(f"  Encrypted: {encrypted[:50]}...")
            
            decrypted = decrypt(encrypted, test_key)
            print(f"  Decrypted: '{decrypted}'")
            
            if text == decrypted:
                print(f"  ✅ PASS")
            else:
                print(f"  ❌ FAIL")
                print(f"  Expected: '{text}'")
                print(f"  Got:      '{decrypted}'")
                all_passed = False
                
        except Exception as e:
            print(f"  ❌ ERROR: {str(e)}")
            all_passed = False
        
        print()
    
    print("=" * 50)
    if all_passed:
        print("🎉 ALL TESTS PASSED! ✅ Your Dynamic LYN algorithm is working perfectly!")
    else:
        print("❌ Some tests failed. Check the implementation.")
    
    return all_passed

def main():
    """Main function to run the encryption tool interactively"""
    print("Dynamic Rounds LYN Encryption/Decryption Tool")
    print("=============================================")
    
    # Run tests first
    test_algorithm()
    
    while True:
        print("\nOptions:")
        print("1. Encrypt text")
        print("2. Decrypt text")
        print("3. Run tests")
        print("4. Show rounds for a key")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            plaintext = input("Enter text to encrypt: ")
            key = input("Enter encryption key: ")
            try:
                rounds = calculate_rounds(key.encode('utf-8'))
                print(f"Using {rounds} rounds for this key")
                encrypted = encrypt(plaintext, key)
                print(f"\nEncrypted: {encrypted}")
            except Exception as e:
                print(f"Encryption error: {e}")
        
        elif choice == '2':
            ciphertext = input("Enter encrypted text: ")
            key = input("Enter decryption key: ")
            try:
                decrypted = decrypt(ciphertext, key)
                print(f"\nDecrypted: {decrypted}")
            except Exception as e:
                print(f"Decryption error: {e}")
        
        elif choice == '3':
            test_algorithm()
        
        elif choice == '4':
            key = input("Enter key to check rounds: ")
            rounds = calculate_rounds(key.encode('utf-8'))
            print(f"Key '{key}' will use {rounds} rounds")
        
        elif choice == '5':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

# Quick test to verify functionality
def quick_test():
    """Quick verification test"""
    test_cases = [
        ("hello world", "testkey"),
        ("short", "k"),
        ("longer message for testing", "password123")
    ]
    
    print("Quick Verification Test:")
    print("-" * 30)
    
    for text, key in test_cases:
        try:
            rounds = calculate_rounds(key.encode('utf-8'))
            print(f"Text: '{text}', Key: '{key}', Rounds: {rounds}")
            
            encrypted = encrypt(text, key)
            decrypted = decrypt(encrypted, key)
            
            status = "✅ PASS" if text == decrypted else "❌ FAIL"
            print(f"Result: {status}")
            
            if text != decrypted:
                print(f"  Expected: '{text}'")
                print(f"  Got: '{decrypted}'")
            
        except Exception as e:
            print(f"❌ ERROR: {e}")
        print()

if __name__ == "__main__":
    quick_test()
    main()
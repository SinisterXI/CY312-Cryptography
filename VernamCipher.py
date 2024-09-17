def vernam_cipher(plaintext, key):
    if len(plaintext) != len(key):
        raise ValueError("The key must be of the same length as the plaintext.")
    
    ciphertext = ''.join([chr(ord(p) ^ ord(k)) for p, k in zip(plaintext, key)])
    return ciphertext

def vernam_decipher(ciphertext, key):
    plaintext = ''.join([chr(ord(c) ^ ord(k)) for c, k in zip(ciphertext, key)])
    return plaintext

# Example
plaintext = "HELLO"
key = "XMCKL"  # Key should be the same length as plaintext
ciphertext = vernam_cipher(plaintext, key)
decrypted_text = vernam_decipher(ciphertext, key)

# Print statements
print(f"Vernam Cipher: {''.join([format(ord(c), '02x') for c in ciphertext])}")
print(f"Decrypted: {decrypted_text}")

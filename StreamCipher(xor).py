def stream_cipher(plaintext, key_stream):
    # XOR each character of the plaintext with the key stream
    ciphertext = ''.join([chr(ord(c) ^ ord(k)) for c, k in zip(plaintext, key_stream)])
    return ciphertext

def stream_decipher(ciphertext, key_stream):
    # XOR each character of the ciphertext with the key stream to get the plaintext
    return stream_cipher(ciphertext, key_stream)

# Example
plaintext = "HELLO"
key_stream = "XMCKL"  # Key stream should be the same length as plaintext
ciphertext = stream_cipher(plaintext, key_stream)
decrypted_text = stream_decipher(ciphertext, key_stream)

# Print statements
print(f"Stream Cipher: {''.join([format(ord(c), '02x') for c in ciphertext])}")
print(f"Decrypted: {decrypted_text}")

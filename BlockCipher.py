from Crypto.Cipher import AES 
import hashlib
import base64

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def block_cipher_encrypt(plaintext, key):
    key = hashlib.sha256(key.encode()).digest()  # Derive a key of correct length
    cipher = AES.new(key, AES.MODE_ECB)
    padded_plaintext = pad(plaintext)
    encrypted_text = base64.b64encode(cipher.encrypt(padded_plaintext.encode())).decode()
    return encrypted_text

def block_cipher_decrypt(ciphertext, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(ciphertext)).decode().strip()
    return decrypted_text

# Example
plaintext = "HELLO"
key = "supersecretkey"
ciphertext = block_cipher_encrypt(plaintext, key)
print(f"Block Cipher: {ciphertext}")
print(f"Decrypted: {block_cipher_decrypt(ciphertext, key)}")

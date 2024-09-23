from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Sample data
key = get_random_bytes(16)  # AES key size is 16 bytes for AES-128
data = b'This is a secret message'

# ECB Mode
def encrypt_ecb(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext

def decrypt_ecb(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# CBC Mode
def encrypt_cbc(key, data):
    iv = get_random_bytes(16)  # Initialization vector
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return iv + ciphertext  # IV is needed for decryption

def decrypt_cbc(key, ciphertext):
    iv = ciphertext[:16]  # Extract the IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    return plaintext

# OFB Mode
def encrypt_ofb(key, data):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB, iv)
    ciphertext = cipher.encrypt(data)
    return iv + ciphertext

def decrypt_ofb(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_OFB, iv)
    plaintext = cipher.decrypt(ciphertext[16:])
    return plaintext

# CFB Mode
def encrypt_cfb(key, data):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(data)
    return iv + ciphertext

def decrypt_cfb(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext[16:])
    return plaintext

# CTR Mode
from Crypto.Util import Counter

def encrypt_ctr(key, data):
    ctr = Counter.new(128)  # 128-bit counter for AES
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(data)
    return ciphertext  # No IV needed for CTR as the counter is included

def decrypt_ctr(key, ciphertext):
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

# Example usage
if __name__ == "__main__":
    # Encrypt and decrypt with ECB
    encrypted_ecb = encrypt_ecb(key, data)
    decrypted_ecb = decrypt_ecb(key, encrypted_ecb)
    print("ECB Decrypted:", decrypted_ecb)

    # Encrypt and decrypt with CBC
    encrypted_cbc = encrypt_cbc(key, data)
    decrypted_cbc = decrypt_cbc(key, encrypted_cbc)
    print("CBC Decrypted:", decrypted_cbc)

    # Encrypt and decrypt with OFB
    encrypted_ofb = encrypt_ofb(key, data)
    decrypted_ofb = decrypt_ofb(key, encrypted_ofb)
    print("OFB Decrypted:", decrypted_ofb)

    # Encrypt and decrypt with CFB
    encrypted_cfb = encrypt_cfb(key, data)
    decrypted_cfb = decrypt_cfb(key, encrypted_cfb)
    print("CFB Decrypted:", decrypted_cfb)

    # Encrypt and decrypt with CTR
    encrypted_ctr = encrypt_ctr(key, data)
    decrypted_ctr = decrypt_ctr(key, encrypted_ctr)
    print("CTR Decrypted:", decrypted_ctr)

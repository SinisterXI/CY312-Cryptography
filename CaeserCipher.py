def caesar_cipher(text, shift):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        else:
            result += chr((ord(char) + shift - 97) % 26 + 97)
    return result

def caesar_decipher(ciphertext, shift):
    return caesar_cipher(ciphertext, -shift)

# Example
plaintext = "HELLO"
shift = 3
ciphertext = caesar_cipher(plaintext, shift)
print(f"Caesar Cipher: {ciphertext}")
print(f"Decrypted: {caesar_decipher(ciphertext, shift)}")

def transposition_cipher(plaintext, key):
    # Pad plaintext if necessary
    if len(plaintext) % key != 0:
        num_padding = key - (len(plaintext) % key)
        plaintext += ' ' * num_padding

    # Create the grid (rows x columns)
    num_rows = len(plaintext) // key
    grid = [''] * num_rows
    for i, char in enumerate(plaintext):
        row = i // key
        grid[row] += char

    # Read columns to form the ciphertext
    ciphertext = ''
    for col in range(key):
        for row in range(num_rows):
            ciphertext += grid[row][col]

    return ciphertext

def transposition_decipher(ciphertext, key):
    # Calculate the number of rows needed
    num_rows = len(ciphertext) // key
    num_extra_chars = (key * num_rows) - len(ciphertext)
    
    # Create the grid (rows x columns)
    grid = [''] * num_rows
    col = 0
    for i, char in enumerate(ciphertext):
        row = i % num_rows
        grid[row] += char
    
    # Read rows to get the plaintext
    plaintext = ''
    for row in range(num_rows):
        for col in range(key):
            if col < len(grid[row]):
                plaintext += grid[row][col]

    return plaintext.rstrip()  # Remove any padding

# Example usage
plaintext = "HELLO"
key = 2
ciphertext = transposition_cipher(plaintext, key)
decrypted_text = transposition_decipher(ciphertext, key)

# Print statements
print(f"Transposition Cipher: {ciphertext}")
print(f"Decrypted: {decrypted_text}")

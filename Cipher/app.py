from flask import Flask, request, render_template, redirect
from werkzeug.utils import secure_filename
import os
import numpy as np

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Vigenère Cipher
def vigenere_cipher(message, key, decrypt=False):
    key = key.lower()
    result = []
    key_index = 0
    key_length = len(key)

    for char in message:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('a')
            if decrypt:
                shift = -shift

            if char.islower():
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            elif char.isupper():
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))

            key_index = (key_index + 1) % key_length
        else:
            result.append(char)

    return ''.join(result)

# Helper function to create 5x5 matrix key for Playfair Cipher
def create_playfair_matrix(key):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = ''.join(sorted(set(key.upper().replace('J', 'I')), key=key.index))
    matrix = [list() for _ in range(5)]
    used_letters = set()
    
    row, col = 0, 0
    for char in key:
        if char not in used_letters:
            matrix[row].append(char)
            used_letters.add(char)
            col += 1
            if col == 5:
                row += 1
                col = 0
    
    for char in alphabet:
        if char not in used_letters:
            matrix[row].append(char)
            used_letters.add(char)
            col += 1
            if col == 5:
                row += 1
                col = 0

    return matrix

# Helper function to find position of characters in Playfair matrix
def find_position(matrix, char):
    for row in range(5):
        if char in matrix[row]:
            return row, matrix[row].index(char)
    return None

# Playfair Cipher Encryption
def playfair_encrypt(plaintext, key):
    # Remove spaces and newline characters
    plaintext = plaintext.upper().replace('J', 'I').replace(' ', '').replace('\n', '')
    
    if len(plaintext) % 2 != 0:
        plaintext += 'X'
    
    matrix = create_playfair_matrix(key)
    ciphertext = ""
    
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        b = plaintext[i+1]
        
        row_a, col_a = find_position(matrix, a)
        row_b, col_b = find_position(matrix, b)
        
        if row_a == row_b:
            ciphertext += matrix[row_a][(col_a + 1) % 5]
            ciphertext += matrix[row_b][(col_b + 1) % 5]
        elif col_a == col_b:
            ciphertext += matrix[(row_a + 1) % 5][col_a]
            ciphertext += matrix[(row_b + 1) % 5][col_b]
        else:
            ciphertext += matrix[row_a][col_b]
            ciphertext += matrix[row_b][col_a]
        
        i += 2

    return ciphertext

# Playfair Cipher Decryption
def playfair_decrypt(ciphertext, key):
    # Remove spaces and newline characters
    ciphertext = ciphertext.upper().replace(' ', '').replace('\n', '')
    
    matrix = create_playfair_matrix(key)
    plaintext = ""
    
    i = 0
    while i < len(ciphertext):
        a = ciphertext[i]
        b = ciphertext[i+1]
        
        row_a, col_a = find_position(matrix, a)
        row_b, col_b = find_position(matrix, b)
        
        if row_a == row_b:
            plaintext += matrix[row_a][(col_a - 1) % 5]
            plaintext += matrix[row_b][(col_b - 1) % 5]
        elif col_a == col_b:
            plaintext += matrix[(row_a - 1) % 5][col_a]
            plaintext += matrix[(row_b - 1) % 5][col_b]
        else:
            plaintext += matrix[row_a][col_b]
            plaintext += matrix[row_b][col_a]
        
        i += 2

    return plaintext

# Helper functions for Hill Cipher
def letter_to_number(letter):
    return ord(letter.upper()) - ord('A')

def number_to_letter(number):
    return chr((number % 26) + ord('A'))

# Hill Cipher Encryption
def hill_encrypt(message, key_matrix):
    message = message.upper().replace(' ', '')
    n = len(key_matrix)
    if len(message) % n != 0:
        message += 'X' * (n - len(message) % n)

    vectors = [letter_to_number(char) for char in message]
    vectors = np.array(vectors).reshape(-1, n)

    encrypted_vectors = np.dot(vectors, key_matrix) % 26
    ciphertext = ''.join([number_to_letter(num) for num in encrypted_vectors.flatten()])

    return ciphertext

# Hill Cipher Decryption
def hill_decrypt(ciphertext, key_matrix):
    ciphertext = ciphertext.upper().replace(' ', '')

    det = int(np.round(np.linalg.det(key_matrix)))
    det_inv = mod_inverse(det, 26)
    if det_inv is None:
        return "Key matrix is not invertible in mod 26."

    key_matrix_inv = det_inv * np.round(np.linalg.inv(key_matrix) * det).astype(int) % 26
    n = len(key_matrix)
    vectors = [letter_to_number(char) for char in ciphertext]
    vectors = np.array(vectors).reshape(-1, n)

    decrypted_vectors = np.dot(vectors, key_matrix_inv) % 26
    plaintext = ''.join([number_to_letter(num) for num in decrypted_vectors.flatten()])

    return plaintext

# Modular inverse function
def mod_inverse(a, mod):
    a = a % mod
    for x in range(1, mod):
        if (a * x) % mod == 1:
            return x
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    key = request.form['key']
    cipher = request.form['cipher']
    operation = request.form['operation']
    
    message = request.form['message']
    if 'file' in request.files:
        file = request.files['file']
        if file and file.filename != '':
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
            file.save(filepath)
            with open(filepath, 'r') as f:
                message = f.read()

    if len(key) < 12:
        return "Key must be at least 12 characters long."

    if cipher == 'vigenere':
        result = vigenere_cipher(message, key, decrypt=(operation == 'decrypt'))
    elif cipher == 'playfair':
        if operation == 'encrypt':
            result = playfair_encrypt(message, key)
        else:
            result = playfair_decrypt(message, key)
    elif cipher == 'hill':
        key_matrix = np.array([[6, 24], [1, 13]])  # Example 2x2 key matrix
        if operation == 'encrypt':
            result = hill_encrypt(message, key_matrix)
        else:
            result = hill_decrypt(message, key_matrix)
    
    return f"<h2>Result:</h2><p>{result}</p>"

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)

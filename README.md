# Crypto CLI Tool

## Description

The **Crypto CLI Tool** is a command-line application for encrypting and decrypting text using various classical cryptographic algorithms. It supports the following encryption methods:

- **Shift Cipher (Caesar Cipher)**: A substitution cipher that shifts each character by a fixed number of positions in the alphabet.
- **Affine Cipher**: A cipher that combines multiplication and addition to transform characters. Requires two keys (a multiplier and an offset).
- **Substitution Cipher**: A cipher where each character is replaced based on a permutation of the alphabet.
- **Hill Cipher (2x2)**: A cipher based on linear algebra, using a 2x2 key matrix for encryption.
- **Transposition Cipher**: A cipher that rearranges the characters of the text based on a key.
- **Vigenere Cipher**: A cipher that applies multiple Caesar ciphers based on a repeating key.

Each command allows the user to specify input text, keys, and alphabet files, as well as the output file and mode (encryption or decryption).

---

## Run

1. Clone the repository:

   ```bash
   git clone git@github.com:LLIEPJIOK/crypto.git
   ```

2. Navigate to the project folder:

   ```bash
   cd crypto
   ```

3. Run the program:

   ```bash
   go run main.go
   ```

---

## General Command Format

```bash
crypto <command> -t <text file> -k <key file> -a <alphabet file> -o <output file> [-d]
```
import random
import json
import math # Used for math.gcd() to check if numbers are coprime
import secrets # For secure random number generation
from pathlib import Path
from sympy import isprime # Used to easily check if 'q' is a prime number
import sys
import os

# Using SystemRandom for better security
sr = secrets.SystemRandom()
def gen_superincreasing(n, pad_bits=12):
    """
    Generate a superincreasing sequence
    """
    e = []
    s = 0
    for i in range(n):
        pad = sr.getrandbits(pad_bits) + 1
        e_i = s + pad
        e.append(e_i)
        s += e_i
    return e



def generate_prime(min):
    """Find prime number greater than sum of previous numbers"""
    num = max(2, min)
    while not isprime(num):
        num += 1
    return num



def keygen(n, pad_bits = 12):
    """
    Generates public(h) key and private(e, q, w) key:
    """
    # 1. Create the superincreasing sequence (e)
    e = gen_superincreasing(n, pad_bits)

    # 2. Choose q such that no errors occur during encryption sum
    q = generate_prime(2 * e[-1] + 1)

    # 3. Choose w (multiplier) such that gcd(w, q) = 1 
    while True:
        w = sr.randrange(2, q - 1)
        if math.gcd(w, q) == 1:
            break
    
    # 4. Calculate the public key h (hi = (w * ei) mod q)
    h = [(w * ei) % q for ei in e]

    public_key = {"h": h}
    private_key = {"e": e, "q": q, "w": w}
    return public_key, private_key



def text_to_bits(text):
    """
    Converts string into list of bits (uses ASCII code).
    """
    bits = []
    for char in text:
        # Get ASCII code of the character
        ascii_val = ord(char)
        # Format as 8-bit binary string           
        binary = f"{ascii_val:08b}"  
        for b in binary:                
            bits.append(int(b))
    return bits



def split_bits_list(bits, size):
    """
    Splits the list of bits into equal sized blocks which is the same size as the key (n).
    Padding is added if the last block is too short.
    """
    chunks = []
    for i in range(0, len(bits), size):
        chunk = bits[i:i + size]
        # Add zeros to the end, when size is not met
        while len(chunk) < size:      
            chunk.append(0)
        chunks.append(chunk)
    return chunks



def encrypt_text(message, public_key):
    """
    Encrypts the message using the Knapsack Sum.
    Each block of bits (same length as key) is converted into a single number.
    """
    n = len(public_key)                
    all_bits = text_to_bits(message)   
    blocks = split_bits_list(all_bits, n)  

    ciphertexts = []                  
    for block in blocks:
        total = 0
        for i in range(len(public_key)):
            # If the bit is 1, the corresponding public key element is added
            total += block[i] * public_key[i]      
        ciphertexts.append(total)      

    return ciphertexts



def decrypt(ciphertexts, private_key):
    """"
     Decrypts the list of ciphertext numbers back into the original plaintext message.
     """

    e = private_key["e"]
    q = private_key["q"]
    w = private_key["w"]

    # Calculate modular inverse of w (w^-1 mod q)
    try:
        w_inv = pow(w, -1, q)
    except ValueError:
        return "Error: Mathematical error: Modular inverse does not exist."

    bits_all = []
    for c in ciphertexts:
        # Transform ciphertext c into c'
        c_prime = (c * w_inv) % q

        # Recover bits using the Greedy Algorithm
        block_bits = []
        remaining = c_prime
        for val in reversed(e):
            if remaining >= val:
                block_bits.insert(0, 1)
                remaining -= val
            else:
                block_bits.insert(0, 0)
        bits_all.extend(block_bits)

    # Convert the recovered bits back into characters
    chars = []
    for i in range(0, len(bits_all), 8):
        byte = bits_all[i:i+8]
        val = int("".join(str(b) for b in byte), 2)
        chars.append(chr(val))

    # Remove the padding from the end
    return "".join(chars).rstrip("\x00")



def save_keys(public_key, private_key, 
              public_filename = "public_key.txt", private_filename = "private_key.txt"):
    """
    Save the public and private keys to two normal text files, public_key.txt and private_key.txt
    """
    # Save the PUBLIC key
    try:
        public_filename = "public_key.txt"
        with open(public_filename, "w") as pub_file:
            pub_file.write("Public key:\n")
            pub_file.write("h: ")
            for key, value in public_key.items():   
                for number in value:
                    pub_file.write(str(number) + ",")
            pub_file.write("\n")
        print(f"Public key saved to {public_filename}")

        # Save the PRIVATE key
        private_filename = "private_key.txt"
        with open(private_filename, "w") as priv_file:
            for key, value in private_key.items():
                priv_file.write(f"{key}: ")
                if isinstance(value, list):
                    for v in value:
                        priv_file.write(str(v) + ",")
                    priv_file.write("\n")
                else:
                    priv_file.write(str(value) + "\n")

   
        print(f"Private key saved to {private_filename}")
        print("Keys have been successfully saved!\n")
    except IOError as e:
        print(f"Error saving keys to files: {e}")



def load_keys_from_txt(public_filename, private_filename):
    """
    Load the public and private keys from simple text files
    and returns (public_key, private_key) as dictionaries.
    """
    try:
        with open(public_filename, "r") as f:
            lines = f.readlines()
        h = []
        values = lines[1].strip()  
        values = values.replace("h", " ").replace(",", " ").replace(":", " ")     
        parts = values.split()             
        for item in parts:
            if item.isdigit():
                h.append(int(item)) # Appends 123 (Integer) 
                         
    
        public_key = {"h": h}
        print(f"Public key loaded from {public_filename}")
        
    except FileNotFoundError:
        print(f"Error: File '{public_filename}' not found.")
        return None, None
    except Exception as e:
        print(f"Error loading public key: {e}")
        return None, None

    try:
        with open(private_filename, "r") as f:
            lines = f.readlines()

        e_values = []
        q = 0
        w = 0

        for line in lines:
            line = line.strip()
            if not line:
                continue  # skip empty lines

            if line.startswith("e:"):
                # e 3 8 24 56 
                line = line.replace("e", " ").replace(",", " ").replace(":", " ")   
                parts = line.split()
                for item in parts:
                    if item.isdigit():
                        e_values.append(int(item)) # Appends 123 (Integer) 

            elif line.startswith("q:"):
                # q: 1403
                q = int(line.split(":")[1])

            elif line.startswith("w:"):
                # w: 643
                w = int(line.split(":")[1])
    
        private_key = {"e": e_values, "q": q, "w": w}
        print(f"Private key loaded from {private_filename}")

    except FileNotFoundError:
        print(f"Error: File '{private_filename}' not found.")
        return None, None
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None, None
        
    print("Keys loaded successfully!\n")
    return public_key, private_key



def encrypt_from_file(in_file, public_key): 
    """Read plaintext from file, encrypt, show and save results."""
    if not os.path.exists(in_file):
        print(f"Error: Input file '{in_file}' does not exist.")
        return

    try:
        with open(in_file, "r", encoding="utf-8") as f:
            plaintext = f.read()
        print("\nPlaintext to encrypt:")
        print(plaintext)

        ciphertexts = encrypt_text(plaintext, public_key["h"])
        print("\nCiphertext blocks:")
        print(ciphertexts)

        # Save result as space-separated numbers
        with open("ciph_out.txt", "w") as f_out:
            f_out.write(" ".join(str(c) for c in ciphertexts))
        print("Ciphertext saved to ciph_out.txt")

    except Exception as e:
        print(f"An error occurred during encryption: {e}")



def decrypt_from_file(in_file, private_key):
    """Read ciphertext from file, decrypt, show and save results."""
    if not os.path.exists(in_file):
        print(f"Error: Input file '{in_file}' does not exist.")
        return

    try:
        with open(in_file, "r") as f:
            data = f.read().strip()
            ciphertexts = [int(x) for x in data.split()]

        print("\nCiphertext to decrypt:")
        print(ciphertexts)

        plaintext = decrypt(ciphertexts, private_key)
        print("\nDecrypted plaintext:")
        print(plaintext)

        with open("plaintext_out.txt", "w", encoding="utf-8") as f:
            f.write(plaintext)
        print("Decrypted text saved to plaintext_out.txt") 

    except Exception as e:
        print(f"An error occurred during decryption: {e}")



def main():
    print("Alternative Method of Public-Key Encryption")
    public_key = None
    private_key = None

    while True:
        print("\nMenu:")
        print(" 1) Generate new key pair")
        print(" 2) Save keys to files")
        print(" 3) Load keys from files")
        print(" 4) Encrypt a message from text file")
        print(" 5) Decrypt a message from ciphertext file")
        print(" 0) Exit")

        choice = input("Enter your choice: ").strip()

        if choice == "1":
            n = int(input("Enter key size n (e.g. 8): "))
            pad_bits = int(input("Enter pad_bits (e.g. 10-14): "))
            public_key, private_key = keygen(n, pad_bits)
            print(" Keys generated!")
            print("Public key (h):", public_key["h"])
            print("Private key:", private_key)

        elif choice == "2":
            if not public_key or not private_key:
                print("No keys to save! Generate first.")
                continue
            save_keys(public_key, private_key)

        elif choice == "3":
            pfile= "public_key.txt"
            prfile=  "private_key.txt"
            public_key, private_key = load_keys_from_txt(pfile, prfile)
            print(" Keys loaded!")

        elif choice == "4":
            if not public_key:
                print("No public key loaded!")
                continue
            in_file = input("Enter plaintext file name: ").strip()
            encrypt_from_file(in_file, public_key)

        elif choice == "5":
            if not private_key:
                print(" No private key loaded!")
                continue
            in_file = input("Enter ciphertext file name: ").strip()
            decrypt_from_file(in_file, private_key)

        elif choice == "0":
            print("Exiting program.")
            break

        else:
            print("Please choose a valid option (0-5).")


if __name__ == "__main__":
    main()


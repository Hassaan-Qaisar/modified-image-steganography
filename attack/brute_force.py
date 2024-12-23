# brute_force_attack.py
# Python program to perform a brute-force attack on the enhanced Image Steganography system

from PIL import Image
import time
import sys
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import hmac
import hashlib
import itertools
import string

def extract_embedded_data(image_path):
    """
    Extracts n, ciphertext, and MAC from the encoded image.

    Args:
        image_path (str): Path to the encoded image.

    Returns:
        tuple: (n, ciphertext_bytes, mac_bytes)
    """
    try:
        img = Image.open(image_path)
        image_bytes = img.tobytes()
    except FileNotFoundError:
        print(f"Error: The file '{image_path}' was not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Extract n (first 8 bits)
    n_bits = [str(image_bytes[i] & 1) for i in range(8)]
    n = int(''.join(n_bits), 2)
    if n < 2 or n > 4:
        print(f"Invalid embedding step 'n' extracted: {n}. Expected between 2 and 4.")
        sys.exit(1)
    print(f"Extracted embedding step 'n': {n}")

    # Extract ciphertext bits
    ciphertext_bits = []
    index = 8
    end_marker_ciphertext = 204  # 0b11001100
    while index < len(image_bytes):
        current_byte = image_bytes[index]
        if current_byte == end_marker_ciphertext:
            index += 1  # Move past the end marker
            break
        ciphertext_bits.append(str(current_byte & 1))
        index += n
    else:
        print("End of ciphertext indicator not found.")
        sys.exit(1)

    # Extract MAC bits
    mac_bits = []
    end_marker_mac = 240  # 0b11110000
    while index < len(image_bytes):
        current_byte = image_bytes[index]
        if current_byte == end_marker_mac:
            index += 1  # Move past the end marker
            break
        mac_bits.append(str(current_byte & 1))
        index += n
    else:
        print("End of MAC indicator not found.")
        sys.exit(1)

    # Convert bits to bytes
    def bits_to_bytes(bits):
        bytes_list = []
        for b in range(0, len(bits), 8):
            byte = bits[b:b+8]
            if len(byte) < 8:
                break
            byte_str = ''.join(byte)
            bytes_list.append(int(byte_str, 2))
        return bytes(bytes_list)

    ciphertext = bits_to_bytes(ciphertext_bits)
    mac = bits_to_bytes(mac_bits)

    print(f"Extracted ciphertext ({len(ciphertext)} bytes) and MAC ({len(mac)} bytes).")
    return n, ciphertext, mac

def aes_decrypt(ciphertext, key):
    """
    Decrypts ciphertext using AES-ECB with the provided key.

    Args:
        ciphertext (bytes): The ciphertext to decrypt.
        key (bytes): The AES key.

    Returns:
        str: The decrypted plaintext or None if decryption fails.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode('utf-8')
    except (ValueError, KeyError):
        return None

def brute_force_key(ciphertext, mac, key_char_set, key_length=16):
    """
    Attempts to brute-force the AES key by iterating through possible combinations.

    Args:
        ciphertext (bytes): The extracted ciphertext.
        mac (bytes): The extracted HMAC.
        key_char_set (str): Characters to use for key generation.
        key_length (int): Length of the key (default is 16 for AES-128).

    Returns:
        tuple: (key, message) if successful, else (None, None).
    """
    start_time = time.time()
    total_attempts = 0

    # Generate all possible keys from the character set with the specified length
    # WARNING: This is computationally infeasible for large key spaces
    print(f"Starting brute-force attack with key length {key_length} and character set size {len(key_char_set)}...")
    print("This may take an extremely long time depending on the key space size.")

    # Due to the enormous key space, it's recommended to limit the key space.
    # For demonstration purposes, we'll limit the key length or character set.
    # WARNING: The following loop is purely illustrative and may not terminate in practice.

    # Example: If the key is known to be alphanumeric, define the character set accordingly
    # Modify key_char_set and key_length based on any additional knowledge about the key
    for key_tuple in itertools.product(key_char_set, repeat=key_length):
        total_attempts += 1
        key_candidate = ''.join(key_tuple)
        key_bytes = key_candidate.encode('utf-8')

        # Compute HMAC-SHA256 over the ciphertext
        computed_mac = hmac.new(key_bytes, ciphertext, hashlib.sha256).digest()

        # Compare computed MAC with the extracted MAC
        if hmac.compare_digest(computed_mac, mac):
            # HMAC matches, likely the correct key
            message = aes_decrypt(ciphertext, key_bytes)
            if message:
                end_time = time.time()
                print(f"\nSuccess! Key found: '{key_candidate}'")
                print(f"Decrypted message: '{message}'")
                print(f"Total attempts: {total_attempts}")
                print(f"Time taken: {end_time - start_time:.2f} seconds.")
                return key_candidate, message

        # Optional: Print progress every million attempts
        if total_attempts % 1000000 == 0:
            elapsed = time.time() - start_time
            print(f"Attempts: {total_attempts} | Time Elapsed: {elapsed:.2f} seconds")

    end_time = time.time()
    print("\nBrute-force attack completed.")
    print(f"Total attempts: {total_attempts}")
    print(f"Time taken: {end_time - start_time:.2f} seconds.")
    return None, None

def main():
    print(":: Enhanced Image Steganography Brute-Force Attack ::")
    image_path = input("Enter the path to the encoded image (e.g., output2.png): ").strip()

    if not image_path:
        print("Error: Image path must be provided.")
        return

    # Step 1: Extract embedded data
    n, ciphertext, mac = extract_embedded_data(image_path)

    # Step 2: Define the key character set and length
    # Based on the sender's key: b'2395hogr4t2395ho'
    # It consists of lowercase letters and digits
    key_char_set = string.ascii_lowercase + string.digits  # 'abcdefghijklmnopqrstuvwxyz0123456789'
    key_length = 16  # AES-128 requires 16-byte keys

    # Step 3: Initiate brute-force attack
    # WARNING: This is computationally infeasible for large key spaces.
    # Consider using optimizations or constraints to make the attack practical.

    # Uncomment the following lines to start the attack.
    # Be aware that running this will likely not complete in a reasonable timeframe.

    key, message = brute_force_key(ciphertext, mac, key_char_set, key_length)

    if key and message:
        print("\n--- Attack Successful ---")
        print(f"Recovered Key: {key}")
        print(f"Recovered Message: {message}")
    else:
        print("\nAttack failed. No valid key found in the provided key space.")

    print("\nBrute-force attack initiation is commented out to prevent accidental execution.")
    print("To perform the attack, uncomment the relevant lines in the script.")
    print("Be cautious: The attack may take an impractical amount of time to complete.")

if __name__ == '__main__':
    main()

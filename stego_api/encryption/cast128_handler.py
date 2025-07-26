# encryption/cast128_handler.py

from Cryptodome.Cipher import CAST
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

def encrypt_message(message: bytes, key: bytes): # Changed 'message' type hint to bytes
    """Encrypts a message using CAST-128."""
    # CAST-128 requires an Initialization Vector (IV)
    iv = get_random_bytes(CAST.block_size)
    cipher = CAST.new(key, CAST.MODE_CBC, iv)
    # Pad the data to be a multiple of the block size. 'message' is already bytes.
    padded_data = pad(message, CAST.block_size)
    ciphertext = cipher.encrypt(padded_data)
    # We need to return the iv to decrypt later
    return ciphertext, iv

def decrypt_message(key: bytes, ciphertext: bytes, iv: bytes):
    """Decrypts a message using CAST-128."""
    try:
        cipher = CAST.new(key, CAST.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        # Unpad the data to get the original message
        data = unpad(decrypted_padded_data, CAST.block_size)
        return data.decode('utf-8')
    except (ValueError, KeyError): # Indicates wrong key, bad padding, etc.
        return None # Indicates decryption failed
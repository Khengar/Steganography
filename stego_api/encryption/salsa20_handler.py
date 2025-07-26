# encryption/salsa20_handler.py

from Cryptodome.Cipher import Salsa20
from Cryptodome.Random import get_random_bytes

def encrypt_message(message: bytes, key: bytes): # Changed 'message' type hint to bytes
    """Encrypts a message using Salsa20."""
    # The nonce is created automatically
    cipher = Salsa20.new(key=key)
    # 'message' is already bytes, so pass it directly to encrypt()
    ciphertext = cipher.encrypt(message) 
    # Return the nonce and a placeholder for the tag (Salsa20 itself is a stream cipher, doesn't use MAC like Poly1305)
    return ciphertext, b'', cipher.nonce # b'' is a placeholder tag consistent with other handlers

def decrypt_message(key: bytes, ciphertext: bytes, tag: bytes, nonce: bytes):
    """Decrypts a message using Salsa20."""
    try:
        cipher = Salsa20.new(key=key, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
        return decrypted_data.decode('utf-8')
    except (ValueError, KeyError): # Indicates wrong key, bad nonce, etc.
        return None
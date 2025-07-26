# encryption/aes_handler.py

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes # Not directly used in this handler, but common import
import os # Not directly used in this handler, but common import

def encrypt_message(message: bytes, key: bytes): # Changed 'message' type hint to bytes
    # The message is ALREADY in bytes format when it reaches here from app.py.
    # So, we can directly use it for encryption. No need for .encode() here.
    cipher = AES.new(key, AES.MODE_GCM)
    
    # Encrypt the data
    ciphertext, tag = cipher.encrypt_and_digest(message) # 'message' is used directly
    
    # Return all necessary parts to decrypt later
    return ciphertext, tag, cipher.nonce

def decrypt_message(key: bytes, ciphertext: bytes, tag: bytes, nonce: bytes):
    """Decrypts a message using AES-GCM."""
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode('utf-8')
    except (ValueError, KeyError): # These exceptions are for decryption failures (e.g., wrong key/tag)
        return None # Indicates decryption failed
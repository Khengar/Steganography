from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def encrypt_message(message: str, key: bytes):
    # Encode the message to bytes
    data = message.encode('utf-8')
    # Create a new AES cipher
    cipher = AES.new(key, AES.MODE_GCM)
    # Encrypt the data
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Return all necessary parts to decrypt later
    return ciphertext, tag, cipher.nonce
def decrypt_message(key: bytes, ciphertext: bytes, tag: bytes, nonce: bytes):
    """Decrypts a message using AES-GCM."""
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode('utf-8')
    except (ValueError, KeyError):
        return None # Indicates decryption failed
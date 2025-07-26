# encryption/chacha20_handler.py

from Cryptodome.Cipher import ChaCha20_Poly1305
from Cryptodome.Random import get_random_bytes

def encrypt_message(message: bytes, key: bytes): # Changed 'message' type hint to bytes
    """Encrypts a message using ChaCha20-Poly1305."""
    # The nonce is created automatically by the library
    cipher = ChaCha20_Poly1305.new(key=key)
    # 'message' is already bytes, so pass it directly to encrypt_and_digest()
    ciphertext, tag = cipher.encrypt_and_digest(message) 
    # We need to return the nonce that was generated
    return ciphertext, tag, cipher.nonce

def decrypt_message(key: bytes, ciphertext: bytes, tag: bytes, nonce: bytes):
    """Decrypts a message using ChaCha20-Poly1305."""
    try:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode('utf-8')
    except (ValueError, KeyError): # Indicates wrong key, bad tag, etc.
        return None # Indicates decryption failed
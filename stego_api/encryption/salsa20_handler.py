from Cryptodome.Cipher import Salsa20
from Cryptodome.Random import get_random_bytes

def encrypt_message(message: str, key: bytes):
    """Encrypts a message using Salsa20."""
    data = message.encode('utf-8')
    # The nonce is created automatically
    cipher = Salsa20.new(key=key)
    ciphertext = cipher.encrypt(data)
    # Return the nonce and a placeholder for the tag
    return ciphertext, b'', cipher.nonce

def decrypt_message(key: bytes, ciphertext: bytes, tag: bytes, nonce: bytes):
    """Decrypts a message using Salsa20."""
    try:
        cipher = Salsa20.new(key=key, nonce=nonce)
        decrypted_data = cipher.decrypt(ciphertext)
        return decrypted_data.decode('utf-8')
    except (ValueError, KeyError):
        return None
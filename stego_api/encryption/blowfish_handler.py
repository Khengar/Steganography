from Cryptodome.Cipher import Blowfish
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

def encrypt_message(message: str, key: bytes):
    """Encrypts a message using Blowfish."""
    data = message.encode('utf-8')
    iv = get_random_bytes(Blowfish.block_size)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    padded_data = pad(data, Blowfish.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext, iv

def decrypt_message(key: bytes, ciphertext: bytes, iv: bytes):
    """Decrypts a message using Blowfish."""
    try:
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        data = unpad(decrypted_padded_data, Blowfish.block_size)
        return data.decode('utf-8')
    except (ValueError, KeyError):
        return None # Indicates decryption failed
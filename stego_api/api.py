from flask import Flask, request, jsonify
import os
from Cryptodome.Random import get_random_bytes

# Import all five handlers
from encryption import aes_handler, chacha_handler, salsa20_handler, cast128_handler, blowfish_handler
from steganography.image_handler import hide_message_in_image, extract_message_from_image
from steganography.audio_handler import hide_message_in_audio, extract_message_from_audio
from steganography.video_handler import hide_message_in_video, extract_message_from_video

UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route("/")
def status_check():
    return "API Server is running!"

# --- Generic Embed Function ---
def run_embed(media_type, file, message, algorithm):
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(input_path)

    key_size = 16 # Default key size for AES, CAST-128, Blowfish
    if algorithm.lower() in ['chacha20', 'salsa20']:
        key_size = 32
    
    key = get_random_bytes(key_size)
    algo = algorithm.lower()

    if algo == 'chacha20':
        ciphertext, tag, nonce = chacha_handler.encrypt_message(message, key)
        data_to_hide = nonce + tag + ciphertext
    elif algo == 'salsa20':
        ciphertext, _, nonce = salsa20_handler.encrypt_message(message, key)
        data_to_hide = nonce + ciphertext
    elif algo == 'cast128':
        ciphertext, iv = cast128_handler.encrypt_message(message, key)
        data_to_hide = iv + ciphertext
    elif algo == 'blowfish':
        ciphertext, iv = blowfish_handler.encrypt_message(message, key)
        data_to_hide = iv + ciphertext
    else: # Default to AES
        ciphertext, tag, nonce = aes_handler.encrypt_message(message, key)
        data_to_hide = nonce + tag + ciphertext
    
    # Steganography handling
    if media_type == 'image':
        output_path = os.path.join(OUTPUT_FOLDER, "stego_" + file.filename)
        hide_message_in_image(input_path, data_to_hide, output_path)
    elif media_type == 'audio':
        output_path = os.path.join(OUTPUT_FOLDER, "stego_" + os.path.splitext(file.filename)[0] + ".wav")
        hide_message_in_audio(input_path, data_to_hide, output_path)
    elif media_type == 'video':
        output_path = os.path.join(OUTPUT_FOLDER, "stego_" + os.path.splitext(file.filename)[0] + ".mp4")
        hide_message_in_video(input_path, data_to_hide, output_path)

    return {"message": f"Embedded successfully using {algorithm.upper()}!", "encryption_key_hex": key.hex()}

# --- Generic Extract Function ---
def run_extract(media_type, file, key_hex, algorithm):
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(input_path)
    
    hidden_data = b''
    if media_type == 'image':
        hidden_data = extract_message_from_image(input_path)
    elif media_type == 'audio':
        hidden_data = extract_message_from_audio(input_path)
    elif media_type == 'video':
        hidden_data = extract_message_from_video(input_path)

    key = bytes.fromhex(key_hex)
    original_message = None
    algo = algorithm.lower()
    
    if algo == 'chacha20':
        nonce, tag, ciphertext = hidden_data[:12], hidden_data[12:28], hidden_data[28:]
        original_message = chacha_handler.decrypt_message(key, ciphertext, tag, nonce)
    elif algo == 'salsa20':
        nonce, ciphertext = hidden_data[:8], hidden_data[8:]
        original_message = salsa20_handler.decrypt_message(key, ciphertext, b'', nonce)
    elif algo == 'cast128':
        iv, ciphertext = hidden_data[:8], hidden_data[8:]
        original_message = cast128_handler.decrypt_message(key, ciphertext, iv)
    elif algo == 'blowfish':
        iv, ciphertext = hidden_data[:8], hidden_data[8:]
        original_message = blowfish_handler.decrypt_message(key, ciphertext, iv)
    else: # Default to AES
        nonce, tag, ciphertext = hidden_data[:16], hidden_data[16:32], hidden_data[32:]
        original_message = aes_handler.decrypt_message(key, ciphertext, tag, nonce)

    if original_message:
        return {"secret_message": original_message}
    else:
        raise ValueError("Decryption failed. Is the key or algorithm correct?")

# --- API Routes ---
@app.route("/embed", methods=['POST'])
def embed_route():
    media_type = request.form.get('media_type', 'image').lower()
    file = request.files.get(media_type)
    message = request.form.get('message')
    algorithm = request.form.get('algorithm', 'aes')
    
    if not all([media_type, file, message]):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        result = run_embed(media_type, file, message, algorithm)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/extract", methods=['POST'])
def extract_route():
    media_type = request.form.get('media_type', 'image').lower()
    file = request.files.get(media_type)
    key_hex = request.form.get('key')
    algorithm = request.form.get('algorithm', 'aes')

    if not all([media_type, file, key_hex]):
        return jsonify({"error": "Missing required fields"}), 400
        
    try:
        result = run_extract(media_type, file, key_hex, algorithm)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
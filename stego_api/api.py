from flask import Flask, request, jsonify
import os
from encryption.aes_handler import encrypt_message, decrypt_message
from steganography.image_handler import hide_message_in_image, extract_message_from_image
from steganography.audio_handler import hide_message_in_audio, extract_message_from_audio
from steganography.video_handler import hide_message_in_video, extract_message_from_video
from Crypto.Random import get_random_bytes

UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route("/")
def status_check():
    """Confirms the API server is running."""
    return "API Server is running!"

@app.route("/embed", methods=['POST'])
def embed_message_route():
    """Embeds a secret message into an image."""
    if 'image' not in request.files or 'message' not in request.form:
        return jsonify({"error": "Missing image file or message field"}), 400

    image_file = request.files['image']
    secret_message = request.form['message']

    if image_file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    input_image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_file.filename)
    image_file.save(input_image_path)

    key = get_random_bytes(16)
    ciphertext, tag, nonce = encrypt_message(secret_message, key)
    data_to_hide = nonce + tag + ciphertext

    output_image_name = "stego_" + image_file.filename
    output_image_path = os.path.join(OUTPUT_FOLDER, output_image_name)

    try:
        hide_message_in_image(input_image_path, data_to_hide, output_image_path)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    print(f"Encryption Key (Hex): {key.hex()}")
    return jsonify({
        "message": "Image embedded successfully!",
        "encryption_key_hex": key.hex(),
        "note": "Save this key to extract the message."
    })

@app.route("/extract", methods=['POST'])
def extract_message_route():
    """Extracts a secret message from a stego-image."""
    if 'image' not in request.files or 'key' not in request.form:
        return jsonify({"error": "Missing stego-image file or key field"}), 400

    image_file = request.files['image']
    key_hex = request.form['key']

    if image_file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    input_image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_file.filename)
    image_file.save(input_image_path)

    try:
        # 1. Extract the hidden data from the image
        hidden_data = extract_message_from_image(input_image_path)

        # 2. Parse the hidden data (nonce, tag, ciphertext)
        nonce = hidden_data[:16]
        tag = hidden_data[16:32]
        ciphertext = hidden_data[32:]
        key = bytes.fromhex(key_hex)

        # 3. Decrypt the message
        original_message = decrypt_message(key, ciphertext, tag, nonce)

        if original_message:
            return jsonify({"secret_message": original_message})
        else:
            return jsonify({"error": "Decryption failed. Is the key correct?"}), 400

    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route("/embed_audio", methods=['POST'])
def embed_audio_route():
    if 'audio' not in request.files or 'message' not in request.form:
        return jsonify({"error": "Missing audio file or message field"}), 400

    audio_file = request.files['audio']
    secret_message = request.form['message']
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], audio_file.filename)
    audio_file.save(input_path)

    key = get_random_bytes(16)
    ciphertext, tag, nonce = encrypt_message(secret_message, key)
    data_to_hide = nonce + tag + ciphertext
    
    # We always save the output as WAV for integrity
    output_filename = "stego_" + os.path.splitext(audio_file.filename)[0] + ".wav"
    output_path = os.path.join(OUTPUT_FOLDER, output_filename)

    try:
        hide_message_in_audio(input_path, data_to_hide, output_path)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "message": "Audio embedded successfully! Output is a WAV file.",
        "encryption_key_hex": key.hex(),
        "note": "Save this key to extract the message."
    })

@app.route("/extract_audio", methods=['POST'])
def extract_audio_route():
    if 'audio' not in request.files or 'key' not in request.form:
        return jsonify({"error": "Missing stego-audio file or key field"}), 400

    audio_file = request.files['audio']
    key_hex = request.form['key']
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], audio_file.filename)
    audio_file.save(input_path)

    try:
        hidden_data = extract_message_from_audio(input_path)
        nonce, tag, ciphertext = hidden_data[:16], hidden_data[16:32], hidden_data[32:]
        key = bytes.fromhex(key_hex)
        original_message = decrypt_message(key, ciphertext, tag, nonce)

        if original_message:
            return jsonify({"secret_message": original_message})
        else:
            return jsonify({"error": "Decryption failed. Is the key correct?"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/embed_video", methods=['POST'])
def embed_video_route():
    if 'video' not in request.files or 'message' not in request.form:
        return jsonify({"error": "Missing video file or message field"}), 400
    video_file = request.files['video']
    secret_message = request.form['message']
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], video_file.filename)
    video_file.save(input_path)
    key = get_random_bytes(16)
    ciphertext, tag, nonce = encrypt_message(secret_message, key)
    data_to_hide = nonce + tag + ciphertext
    output_filename = "stego_" + os.path.splitext(video_file.filename)[0] + ".mp4"
    output_path = os.path.join(OUTPUT_FOLDER, output_filename)
    try:
        hide_message_in_video(input_path, data_to_hide, output_path)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"message": "Video embedded successfully!", "encryption_key_hex": key.hex()})

@app.route("/extract_video", methods=['POST'])
def extract_video_route():
    if 'video' not in request.files or 'key' not in request.form:
        return jsonify({"error": "Missing stego-video file or key field"}), 400
    video_file = request.files['video']
    key_hex = request.form['key']
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], video_file.filename)
    video_file.save(input_path)
    try:
        hidden_data = extract_message_from_video(input_path)
        nonce, tag, ciphertext = hidden_data[:16], hidden_data[16:32], hidden_data[32:]
        key = bytes.fromhex(key_hex)
        original_message = decrypt_message(key, ciphertext, tag, nonce)
        if original_message:
            return jsonify({"secret_message": original_message})
        else:
            return jsonify({"error": "Decryption failed. Is the key correct?"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
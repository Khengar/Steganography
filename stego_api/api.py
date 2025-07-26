import eventlet
eventlet.monkey_patch()

import traceback
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime 

# Your existing imports for steganography handlers
from encryption import aes_handler, chacha_handler, salsa20_handler, cast128_handler, blowfish_handler
from steganography.image_handler import hide_message_in_image, extract_message_from_image
# Assuming these are correct and not the current focus of the issue
from steganography.audio_handler import hide_message_in_audio, extract_message_from_audio 
from steganography.video_handler import hide_message_in_video, extract_message_from_video 
from Cryptodome.Random import get_random_bytes
import base64 # For returning base64 images

UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'outputs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}) # Enable CORS for all origins (for hackathon)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_super_secret_jwt_key' # CHANGE THIS IN PRODUCTION
app.config['SECRET_KEY'] = 'another_secret_key_for_flask_socketio' # CHANGE THIS TOO

db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*") # Enable CORS for SocketIO
connected_users = {} # Format: { user_id: [sid1, sid2, ...] }

# --- Database Models (Add these) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    accepter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False) # pending, accepted, rejected

    requester = db.relationship('User', foreign_keys=[requester_id], backref='requested_friends')
    accepter = db.relationship('User', foreign_keys=[accepter_id], backref='accepted_friends')

    __table_args__ = (db.UniqueConstraint('requester_id', 'accepter_id', name='_requester_accepter_uc'),)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False) # Store text message or image URL/base64
    message_type = db.Column(db.String(10), nullable=False) # 'text', 'image'
    key_for_decryption = db.Column(db.String(255), nullable=True) # The hex key for images
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    encryption_algorithm = db.Column(db.String(20), nullable=True) # Max 20 chars should be enough for algo names

    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

    def to_dict(self):
        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'content': self.content,
            'message_type': self.message_type,
            'key_for_decryption': self.key_for_decryption,
            'encryption_algorithm': self.encryption_algorithm,
            'timestamp': self.timestamp.isoformat() + 'Z' # ISO format for JS parsing
        }


# --- Your existing run_embed/run_extract functions (Modified for base64 output) ---
def run_embed(media_type, file, message, algorithm):
    print(f"DEBUG: run_embed - Processing file: {file.filename}, message_len: {len(message)}, algorithm: {algorithm}")
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(input_path)

    key_size = 16
    if algorithm.lower() in ['chacha20', 'salsa20']:
        key_size = 32
    key = get_random_bytes(key_size)

    algo = algorithm.lower()

    data_to_hide = b'' # Initialize data_to_hide

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
    else: # Default AES
        ciphertext, tag, nonce = aes_handler.encrypt_message(message, key)
        data_to_hide = nonce + tag + ciphertext

    print(f"DEBUG: run_embed - Encrypted data_to_hide length: {len(data_to_hide)}, Key hex (first 10): {key.hex()[:10]}...")

    base_name, original_ext = os.path.splitext(file.filename)
    output_filename = ""

    if media_type == 'image':
        output_filename = "stego_" + base_name + ".png"
    elif media_type == 'audio':
        output_filename = "stego_" + base_name + ".wav"
    elif media_type == 'video':
        output_filename = "stego_" + base_name + ".mp4"
    else:
        output_filename = "stego_" + file.filename

    output_path = os.path.join(OUTPUT_FOLDER, output_filename)

    if media_type == 'image':
        hide_message_in_image(input_path, data_to_hide, output_path)
    elif media_type == 'audio':
        hide_message_in_audio(input_path, data_to_hide, output_path)
    elif media_type == 'video':
        hide_message_in_video(input_path, data_to_hide, output_path)

    os.remove(input_path)

    with open(output_path, "rb") as f:
        encoded_file = base64.b64encode(f.read()).decode('utf-8')
    os.remove(output_path) 

    print(f"DEBUG: run_embed - Stego file base64 length: {len(encoded_file)}, Returned key_hex: {key.hex()}") # Log the full key
    return {
        "message": f"Embedded successfully using {algorithm.upper()}!",
        "encryption_key_hex": key.hex(),
        "steganographed_file_base64": encoded_file,
        "file_type": media_type
    }


def run_extract(media_type, file, key_hex, algorithm):
    print(f"DEBUG: run_extract - Processing file: {file.filename}, algorithm: {algorithm}, key_hex (first 10): {key_hex[:10]}...")
    input_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(input_path)

    hidden_data = None
    if media_type == 'image':
        hidden_data = extract_message_from_image(input_path)
    elif media_type == 'audio':
        hidden_data = extract_message_from_audio(input_path)
    elif media_type == 'video':
        hidden_data = extract_message_from_video(input_path)

    os.remove(input_path)

    if hidden_data is None:
        raise ValueError("No hidden data found or media type not supported for extraction.")
    # Add an explicit type check for robustness
    if not isinstance(hidden_data, bytes):
        raise TypeError(f"Extracted data is not bytes, got {type(hidden_data)}. Expected bytes from image handler.")

    key = bytes.fromhex(key_hex)
    original_message = None
    algo = algorithm.lower()

    print(f"DEBUG: run_extract - Extracted hidden_data length: {len(hidden_data)}, Decryption key (hex, first 10): {key.hex()[:10]}...")

    try:
        if algo == 'chacha20':
            nonce_len = 12
            tag_len = 16
            nonce = hidden_data[:nonce_len]
            tag = hidden_data[nonce_len : nonce_len + tag_len]
            ciphertext = hidden_data[nonce_len + tag_len :]
            print(f"DEBUG: run_extract - ChaCha20: Nonce len {len(nonce)}, Tag len {len(tag)}, Ciphertext len {len(ciphertext)}")
            original_message = chacha_handler.decrypt_message(key, ciphertext, tag, nonce)
        elif algo == 'salsa20':
            nonce_len = 8
            nonce = hidden_data[:nonce_len]
            ciphertext = hidden_data[nonce_len:]
            print(f"DEBUG: run_extract - Salsa20: Nonce len {len(nonce)}, Ciphertext len {len(ciphertext)}")
            original_message = salsa20_handler.decrypt_message(key, ciphertext, b'', nonce)
        elif algo == 'cast128':
            iv_len = 8
            iv = hidden_data[:iv_len]
            ciphertext = hidden_data[iv_len:]
            print(f"DEBUG: run_extract - CAST128: IV len {len(iv)}, Ciphertext len {len(ciphertext)}")
            original_message = cast128_handler.decrypt_message(key, ciphertext, iv)
        elif algo == 'blowfish':
            iv_len = 8
            iv = hidden_data[:iv_len]
            ciphertext = hidden_data[iv_len:]
            print(f"DEBUG: run_extract - Blowfish: IV len {len(iv)}, Ciphertext len {len(ciphertext)}")
            original_message = blowfish_handler.decrypt_message(key, ciphertext, iv)
        else: # Default AES
            nonce_len = 16
            tag_len = 16
            nonce = hidden_data[:nonce_len]
            tag = hidden_data[nonce_len : nonce_len + tag_len]
            ciphertext = hidden_data[nonce_len + tag_len :]
            print(f"DEBUG: run_extract - AES: Nonce len {len(nonce)}, Tag len {len(tag)}, Ciphertext len {len(ciphertext)}")
            original_message = aes_handler.decrypt_message(key, ciphertext, tag, nonce)
    except Exception as e:
        print(f"DEBUG: Decryption handler failed with exception: {e}") # Log handler specific errors
        raise ValueError(f"Decryption failed: {str(e)}. Check key or algorithm.")

    if original_message:
        print(f"DEBUG: Type of original_message after decryption handler: {type(original_message)}") # Added debug
        print(f"DEBUG: Decryption successful. Original message length: {len(original_message)}")
        # --- FIX: Removed .decode('utf-8') as handler already returns a string ---
        return {"secret_message": original_message} 
    else:
        print(f"DEBUG: Decrypt_message returned None for algo {algo}. Hidden data was: {hidden_data[:20]}...") # Log portion of hidden data
        raise ValueError("Decryption failed. Unknown reason.")

# --- API Routes (Extend these) ---

# Existing /embed and /extract routes:
@app.route("/embed", methods=['POST'])
@jwt_required()
def embed_route():
    media_type = request.form.get('media_type', 'image').lower()
    file = request.files.get(media_type)
    message = request.form.get('message') # This is the secret message
    algorithm = request.form.get('algorithm', 'aes') # Encryption algorithm

    if not all([file, message]): # media_type is defaulted
        return jsonify({"error": "Missing required fields (file or message)"}), 400

    # Ensure message is bytes for encryption
    message_bytes = message.encode('utf-8')

    try:
        result = run_embed(media_type, file, message_bytes, algorithm)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/extract", methods=['POST'])
@jwt_required()
def extract_route():
    media_type = request.form.get('media_type', 'image').lower()
    file = request.files.get(media_type) # This is the steganographed file
    key_hex = request.form.get('key') # This is the encryption key
    algorithm = request.form.get('algorithm', 'aes')

    if not all([file, key_hex]): # media_type is defaulted
        return jsonify({"error": "Missing required fields (file or key)"}), 400

    try:
        result = run_extract(media_type, file, key_hex, algorithm)
        return jsonify(result)
    except Exception as e:
        print(f"ERROR during /extract: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# New User/Auth Routes
@app.route('/api/register', methods=['POST'])
def register():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "Username already exists"}), 409

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User created successfully"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token, user_id=user.id, username=user.username), 200

# New Friend Request Routes
@app.route('/api/friend_requests/send', methods=['POST'])
@jwt_required()
def send_friend_request():
    current_user_id = get_jwt_identity()
    recipient_username = request.json.get('recipient_username', None)

    if not recipient_username:
        return jsonify({"msg": "Recipient username required"}), 400

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return jsonify({"msg": "Recipient not found"}), 404
    if recipient.id == current_user_id:
        return jsonify({"msg": "Cannot send request to self"}), 400

    # Check if request already exists (pending or accepted)
    existing_request = Friendship.query.filter(
        ((Friendship.requester_id == current_user_id) & (Friendship.accepter_id == recipient.id)) |
        ((Friendship.requester_id == recipient.id) & (Friendship.accepter_id == current_user_id))
    ).first()

    if existing_request:
        if existing_request.status == 'pending':
            return jsonify({"msg": "Friend request already pending"}), 409
        elif existing_request.status == 'accepted':
            return jsonify({"msg": "Already friends"}), 409

    new_request = Friendship(requester_id=current_user_id, accepter_id=recipient.id, status='pending')
    db.session.add(new_request)
    db.session.commit()
    return jsonify({"msg": "Friend request sent"}), 201

@app.route('/api/friend_requests/accept', methods=['POST'])
@jwt_required()
def accept_friend_request():
    current_user_id = get_jwt_identity()
    requester_id = request.json.get('requester_id', None)

    if not requester_id:
        return jsonify({"msg": "Requester ID required"}), 400

    friend_request = Friendship.query.filter_by(
        requester_id=requester_id,
        accepter_id=current_user_id,
        status='pending'
    ).first()

    if not friend_request:
        return jsonify({"msg": "Pending friend request not found"}), 404

    friend_request.status = 'accepted'
    db.session.commit()
    return jsonify({"msg": "Friend request accepted"}), 200

@app.route('/api/friend_requests/pending', methods=['GET'])
@jwt_required()
def get_pending_friend_requests():
    current_user_id = get_jwt_identity()
    pending_requests = Friendship.query.filter_by(accepter_id=current_user_id, status='pending').all()

    requesters = []
    for req in pending_requests:
        requester_user = User.query.get(req.requester_id)
        if requester_user:
            requesters.append({"id": requester_user.id, "username": requester_user.username})

    return jsonify(requesters), 200

@app.route('/api/friends', methods=['GET'])
@jwt_required()
def get_friends():
    current_user_id = get_jwt_identity()

    # Get friends where current_user is requester
    friends_as_requester = Friendship.query.filter_by(requester_id=current_user_id, status='accepted').all()
    # Get friends where current_user is accepter
    friends_as_accepter = Friendship.query.filter_by(accepter_id=current_user_id, status='accepted').all()

    friend_users = []
    for fship in friends_as_requester:
        friend_user = User.query.get(fship.accepter_id)
        if friend_user:
            friend_users.append({"id": friend_user.id, "username": friend_user.username})

    for fship in friends_as_accepter:
        friend_user = User.query.get(fship.requester_id)
        if friend_user:
            friend_users.append({"id": friend_user.id, "username": friend_user.username})

    # Remove duplicates if any (e.g., if a user sends request to self logic wasn't fully robust, though it should be prevented)
    unique_friends = []
    seen_ids = set()
    for friend in friend_users:
        if friend['id'] not in seen_ids:
            unique_friends.append(friend)
            seen_ids.add(friend['id'])

    return jsonify(unique_friends), 200

# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    
    token = request.args.get('token') 

    if not token:
        print(f"Connection rejected for SID {request.sid}: No token provided.")
        return False 

    try:
        with app.app_context():
            decoded_token = decode_token(token)
            user_id = str(decoded_token['sub'])
        
        if user_id not in connected_users:
            connected_users[user_id] = []
        if request.sid not in connected_users[user_id]:
            connected_users[user_id].append(request.sid)
        
        print(f"User {user_id} authenticated and joined room 'user_{user_id}' with SID {request.sid}. Active SIDs: {connected_users}")
        return True 

    except Exception as e:
        print(f"Connection rejected for SID {request.sid}: Authentication failed - {str(e)}")
        return False 

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client disconnected: {request.sid}")
    for user_id, sids in list(connected_users.items()): 
        if request.sid in sids:
            sids.remove(request.sid)
            if not sids: 
                del connected_users[user_id]
            break
    print(f"Active SIDs after disconnect: {connected_users}") 

@socketio.on('send_message')
def handle_send_message(data): 
    sender_id_str = None
    for uid, sids in connected_users.items():
        if request.sid in sids:
            sender_id_str = uid
            break
    
    if not sender_id_str:
        emit('error', {'message': 'Sender not authenticated via socket'}, room=request.sid)
        return

    sender_id = int(sender_id_str) 

    recipient_id_str = data.get('recipient_id') 
    message_type = data.get('message_type')
    content = data.get('content')
    key_for_decryption = data.get('key_for_decryption', None)
    
    encryption_algorithm = data.get('encryption_algorithm', None) 
    print(f"DEBUG: handle_send_message - Received encryption_algorithm from frontend: '{encryption_algorithm}'") 


    if not all([recipient_id_str, message_type, content]):
        emit('error', {'message': 'Missing message data'}, room=request.sid)
        return
    
    try:
        recipient_id = int(recipient_id_str)
    except ValueError:
        emit('error', {'message': 'Invalid recipient ID'}, room=request.sid)
        return

    is_friends = Friendship.query.filter(
        ((Friendship.requester_id == sender_id) & (Friendship.accepter_id == recipient_id) & (Friendship.status == 'accepted')) |
        ((Friendship.requester_id == recipient_id) & (Friendship.accepter_id == sender_id) & (Friendship.status == 'accepted'))
    ).first()

    if not is_friends:
        emit('error', {'message': 'You are not friends with this user'}, room=request.sid)
        return

    new_message = Message(
        sender_id=sender_id,
        recipient_id=recipient_id,
        content=content,
        message_type=message_type,
        key_for_decryption=key_for_decryption,
        encryption_algorithm=encryption_algorithm 
    )
    db.session.add(new_message)
    db.session.commit()
    print(f"DEBUG: handle_send_message - Message saved to DB. DB Algorithm: '{new_message.encryption_algorithm}'") 

    message_payload = {
        'id': new_message.id,
        'sender_id': new_message.sender_id,
        'recipient_id': new_message.recipient_id,
        'message_type': new_message.message_type,
        'content': new_message.content,
        'timestamp': new_message.timestamp.isoformat() + 'Z',
        'key_for_decryption': new_message.key_for_decryption,
        'encryption_algorithm': new_message.encryption_algorithm 
    }
    print(f"DEBUG: handle_send_message - Emitting message_payload with encryption_algorithm: '{message_payload['encryption_algorithm']}'")

    if sender_id_str in connected_users:
        for sid in connected_users[sender_id_str]:
            print(f"DEBUG: Emitting to sender {sender_id_str} SID: {sid}") 
            emit('receive_message', message_payload, room=sid)

    if recipient_id_str in connected_users:
        for sid in connected_users[recipient_id_str]:
            if sid != request.sid: 
                print(f"DEBUG: Emitting to recipient {recipient_id_str} SID: {sid}") 
                emit('receive_message', message_payload, room=sid)

@app.route('/api/users/search', methods=['GET'])
@jwt_required()
def search_users():
    query = request.args.get('q', '')
    current_user_id = get_jwt_identity()

    if not query:
        return jsonify([]), 200

    users = User.query.filter(
        User.username.ilike(f'%{query}%'),
        User.id != current_user_id
    ).all()

    friends_and_pending_ids = set()
    friendships = Friendship.query.filter(
        (Friendship.requester_id == current_user_id) |
        (Friendship.accepter_id == current_user_id)
    ).all()
    
    for fship in friendships:
        if fship.requester_id == current_user_id:
            friends_and_pending_ids.add(fship.accepter_id)
        else: 
            friends_and_pending_ids.add(fship.requester_id)

    results = []
    for user in users:
        if user.id not in friends_and_pending_ids:
            results.append({
                "id": user.id,
                "username": user.username
            })
    
    return jsonify(results), 200

@app.route('/api/messages/<int:friend_id>', methods=['GET'])
@jwt_required()
def get_message_history(friend_id):
    current_user_id = int(get_jwt_identity()) 

    is_friends = Friendship.query.filter(
        ((Friendship.requester_id == current_user_id) & (Friendship.accepter_id == friend_id) & (Friendship.status == 'accepted')) |
        ((Friendship.requester_id == friend_id) & (Friendship.accepter_id == current_user_id) & (Friendship.status == 'accepted'))
    ).first()

    if not is_friends:
        return jsonify({"msg": "You are not friends with this user or friendship not accepted."}), 403

    messages = Message.query.filter(
        ((Message.sender_id == current_user_id) & (Message.recipient_id == friend_id)) |
        ((Message.sender_id == friend_id) & (Message.recipient_id == current_user_id))
    ).order_by(Message.timestamp).all()

    return jsonify([msg.to_dict() for msg in messages]), 200

if __name__ == "__main__":
    with app.app_context():
        db.create_all() # Create database tables
    eventlet.wsgi.server(eventlet.listen(('19', 5000)), app)
import json
import base64
import binascii
import os
from flask import Flask, request, render_template, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

app = Flask(__name__)

SECRET_KEY = b'SuperSecretKey67' # 16 bytes for AES-128
FLAG = os.environ.get("FLAG", "Something went wrong with the environment variable setup.")

def create_starter_token():
    data = '{"user":"guest", "role":"user", "v":"1.0"}'
    iv = os.urandom(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    # Format: base64(iv + ciphertext)
    return base64.b64encode(iv + ct_bytes).decode('utf-8')

STARTER_TOKEN = create_starter_token()

@app.route('/')
def index():
    return render_template('index.html', token=STARTER_TOKEN)

@app.route('/api/migrate', methods=['POST'])
def migrate():
    data = request.json
    if not data or 'token' not in data:
        return jsonify({"error": "Missing token"}), 400
    
    token = data['token']
    
    try:
        # Step 1: Decode Base64
        raw_data = base64.b64decode(token)
        if len(raw_data) < 16:
            return jsonify({"error": "Token corrupted"}), 400
        
        iv = raw_data[:16]
        ciphertext = raw_data[16:]
        
        # Step 2: Decrypt
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Step 3: Check Padding
        try:
            unpadded = unpad(decrypted, AES.block_size)
        except ValueError:
            # Padding is invalid! Returns HTTP 500.
            return jsonify({"error": "Migration token corrupted (Invalid Padding)"}), 500
        
        # Step 4: Parse JSON
        try:
            profile = json.loads(unpadded.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return jsonify({"error": "Token decrypted, but profile data is unreadable"}), 400
        
        # Step 5: Check Role for the Flag
        if profile.get('role') == 'admin':
            return jsonify({
                "message": "Migration successful. Welcome back, Admin.",
                "flag": FLAG,
                "profile": profile
            }), 200
        else:
            return jsonify({
                "message": "Migration successful.",
                "profile": profile
            }), 200

    except binascii.Error:
        return jsonify({"error": "Invalid Base64 encoding"}), 400
    except Exception as e:
        return jsonify({"error": "An unknown error occurred"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
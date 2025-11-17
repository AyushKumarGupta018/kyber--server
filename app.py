# app.py - Complete Flask Server for Kyber512 Encryption/Decryption
# NEIGHBOUR NEST - Quantum-Safe File Sharing
# .\kyber_env\Scripts\activate
# python -c "from oqs import KeyEncapsulation; print('KYBER READY!')"
# cd C:\checkquantum\liboqs-python
# python -m pip install .
# cd C:\checkquantum

from flask import Flask, request, jsonify
from flask_cors import CORS
from oqs import KeyEncapsulation
import base64

app = Flask(__name__)
CORS(app)  # Enable CORS for Flutter app

ALGORITHM = 'Kyber512'

print("=" * 70)
print("  NEIGHBOUR NEST - Kyber512 Encryption Server")
print("=" * 70)
print(f"  Algorithm: {ALGORITHM}")
print(f"  Post-Quantum Encryption: ✓")
print("=" * 70)

# ==================== ROOT ENDPOINT ====================
@app.route('/')
def index():
    """API Documentation"""
    return jsonify({
        "message": "🔐 Kyber512 Encryption Server - Neighbour Nest",
        "status": "online",
        "algorithm": ALGORITHM,
        "endpoints": {
            "/": "GET - API documentation",
            "/api/health": "GET - Health check",
            "/api/info": "GET - Server info",
            "/api/generate-keypair": "POST - Generate new Kyber512 keypair",
            "/api/encrypt": "POST - Encrypt file with public key (multipart/form-data)",
            "/api/decrypt": "POST - Decrypt file with private key (application/json)"
        },
        "usage": {
            "generate_keypair": "POST /api/generate-keypair",
            "encrypt": "POST /api/encrypt with 'file' and 'public_key' fields",
            "decrypt": "POST /api/decrypt with JSON {'encrypted_data': '...', 'private_key': '...'}"
        }
    })

# ==================== HEALTH CHECK ====================
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'algorithm': ALGORITHM,
        'server': 'Neighbour Nest Kyber512'
    })

# ==================== SERVER INFO ====================
@app.route('/api/info', methods=['GET'])
def get_info():
    """Get server and algorithm information"""
    try:
        kem = KeyEncapsulation(ALGORITHM)
        return jsonify({
            'algorithm': ALGORITHM,
            'details': kem.details,
            'status': 'online',
            'description': 'Post-quantum key encapsulation mechanism'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== GENERATE KEYPAIR ====================
@app.route('/api/generate-keypair', methods=['POST'])
def generate_keypair():
    """
    Generate a new Kyber512 keypair
    
    Returns:
        JSON with public_key and private_key (base64 encoded)
    """
    try:
        print("\n🔑 Generating new Kyber512 keypair...")
        
        # Create Kyber instance
        kem = KeyEncapsulation(ALGORITHM)
        
        # Generate keypair
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        
        print(f"✅ Keypair generated successfully!")
        print(f"   Public key length: {len(public_key)} bytes")
        print(f"   Private key length: {len(private_key)} bytes")
        
        return jsonify({
            'algorithm': ALGORITHM,
            'public_key': base64.b64encode(public_key).decode('utf-8'),
            'private_key': base64.b64encode(private_key).decode('utf-8'),
            'public_key_length': len(public_key),
            'private_key_length': len(private_key),
            'status': 'success'
        })
    except Exception as e:
        print(f"❌ Error generating keypair: {str(e)}")
        return jsonify({'error': str(e), 'status': 'failed'}), 500

# ==================== ENCRYPT FILE ====================
@app.route('/api/encrypt', methods=['POST'])
def encrypt_file():
    """
    Encrypt file using recipient's public key
    
    Expected: multipart/form-data with:
        - 'file': The file to encrypt
        - 'public_key': Base64-encoded public key
    
    Returns:
        JSON with encrypted_data (base64 encoded)
    """
    try:
        print("\n🔐 Encrypting file...")
        
        # Validate request
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        public_key_b64 = request.form.get('public_key')
        
        if not public_key_b64:
            return jsonify({'error': 'No public key provided'}), 400
        
        # Decode public key
        public_key = base64.b64decode(public_key_b64)
        print(f"   Public key length: {len(public_key)} bytes")
        
        # Read file data
        file_data = file.read()
        print(f"   File size: {len(file_data)} bytes")
        
        # Create Kyber instance and encapsulate
        kem = KeyEncapsulation(ALGORITHM)
        ciphertext, shared_secret = kem.encap_secret(public_key)
        print(f"   Ciphertext length: {len(ciphertext)} bytes")
        print(f"   Shared secret length: {len(shared_secret)} bytes")
        
        # Encrypt data using XOR with shared secret
        encrypted = bytearray(file_data)
        for i in range(len(encrypted)):
            encrypted[i] ^= shared_secret[i % len(shared_secret)]
        
        # Combine ciphertext + encrypted data
        combined = ciphertext + bytes(encrypted)
        
        print(f"✅ File encrypted successfully!")
        print(f"   Total encrypted size: {len(combined)} bytes")
        
        return jsonify({
            'encrypted_data': base64.b64encode(combined).decode('utf-8'),
            'ciphertext_length': len(ciphertext),
            'encrypted_length': len(encrypted),
            'total_length': len(combined),
            'status': 'success'
        })
    except Exception as e:
        print(f"❌ Error encrypting file: {str(e)}")
        return jsonify({'error': str(e), 'status': 'failed'}), 500

# ==================== DECRYPT FILE ====================
@app.route('/api/decrypt', methods=['POST'])
def decrypt_file():
    """
    Decrypt file using private key
    
    Expected JSON:
        {
            "encrypted_data": "base64_string",
            "private_key": "base64_string"
        }
    
    Returns:
        JSON with decrypted_data (base64 encoded)
    """
    try:
        print("\n🔓 Decrypting file...")
        
        # Get data from request
        data = request.get_json()
        
        if not data or 'encrypted_data' not in data or 'private_key' not in data:
            return jsonify({'error': 'Missing encrypted_data or private_key'}), 400
        
        # Decode encrypted data and private key
        encrypted_blob = base64.b64decode(data['encrypted_data'])
        private_key = base64.b64decode(data['private_key'])
        
        print(f"   Encrypted blob length: {len(encrypted_blob)} bytes")
        print(f"   Private key length: {len(private_key)} bytes")
        
        # Create Kyber instance with private key
        kem = KeyEncapsulation(ALGORITHM, secret_key=private_key)
        
        # Get ciphertext length
        ct_len = kem.details['length_ciphertext']
        print(f"   Ciphertext length: {ct_len} bytes")
        
        # Split ciphertext and encrypted data
        ciphertext = encrypted_blob[:ct_len]
        encrypted_data = encrypted_blob[ct_len:]
        print(f"   Encrypted data length: {len(encrypted_data)} bytes")
        
        # Decapsulate to get shared secret
        shared_secret = kem.decap_secret(ciphertext)
        print(f"   Shared secret length: {len(shared_secret)} bytes")
        
        # Decrypt using XOR
        decrypted = bytearray(encrypted_data)
        for i in range(len(decrypted)):
            decrypted[i] ^= shared_secret[i % len(shared_secret)]
        
        print(f"✅ File decrypted successfully!")
        print(f"   Decrypted size: {len(decrypted)} bytes")
        
        return jsonify({
            'decrypted_data': base64.b64encode(bytes(decrypted)).decode('utf-8'),
            'decrypted_length': len(decrypted),
            'status': 'success'
        })
    except Exception as e:
        print(f"❌ Error decrypting file: {str(e)}")
        return jsonify({'error': str(e), 'status': 'failed'}), 500

# ==================== ERROR HANDLERS ====================
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'Please check the API documentation at /',
        'status': 'error'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'message': str(error),
        'status': 'error'
    }), 500

# ==================== MAIN ====================
if __name__ == '__main__':
    print("\n")
    print("=" * 70)
    print("  🚀 Server starting...")
    print("=" * 70)
    print("  📡 Running on: http://0.0.0.0:5000")
    print("  🌐 Access from network: http://YOUR_IP:5000")
    print("=" * 70)
    print("  📝 Find your IP address:")
    print("     Windows: ipconfig")
    print("     Linux/Mac: ifconfig or hostname -I")
    print("=" * 70)
    print("\n  Press CTRL+C to stop the server\n")
    
    # Run server
    # host='0.0.0.0' makes it accessible from other devices on network
    # port=5000 is the default port
    # debug=True provides helpful error messages (disable in production)
    app.run(host='0.0.0.0', port=5000, debug=True)

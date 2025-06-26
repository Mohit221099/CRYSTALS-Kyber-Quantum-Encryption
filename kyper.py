from flask import Flask, request, jsonify
from simulator import CRYSTALSKyberSimulator  # assuming you save your class there

app = Flask(__name__)
kyber = CRYSTALSKyberSimulator()

# Generate keypair (public key shared with clients)
PUBLIC_KEY, PRIVATE_KEY = kyber.keygen()

@app.route("/public-key", methods=["GET"])
def get_public_key():
    """Client uses this to get the public key to encrypt data"""
    return jsonify(PUBLIC_KEY)

@app.route("/submit-encrypted", methods=["POST"])
def receive_encrypted():
    """Receive encrypted data, decrypt it, and return the decrypted content"""
    try:
        data = request.get_json()
        kyber_ciphertext = data.get("kyber_ciphertext")
        encrypted_payload = data.get("encrypted_payload")

        # Simulate full structure as in your simulator
        packet = {
            "kyber_ciphertext": kyber_ciphertext,
            "encrypted_payload": encrypted_payload
        }

        # Decrypt
        decrypted_data = kyber.decapsulate(packet["kyber_ciphertext"], PRIVATE_KEY)
        decrypted_bytes = bytes.fromhex(packet["encrypted_payload"])
        key_stream = hashlib.sha256(decrypted_data).digest()

        decrypted_payload = bytearray(decrypted_bytes)
        for i in range(len(decrypted_payload)):
            decrypted_payload[i] ^= key_stream[i % len(key_stream)]

        return jsonify({
            "status": "success",
            "decrypted_data": decrypted_payload.decode('utf-8')
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True)

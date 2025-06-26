import hashlib
import json
import time
import random
import threading
from datetime import datetime

class CRYSTALSKyberSimulator:
    """
    Simplified CRYSTALS-Kyber implementation using only Python standard library.
    This demonstrates the key encapsulation mechanism concepts.
    """
    
    def __init__(self, security_level=512):
        self.security_level = security_level
        self.q = 3329  # Prime modulus used in Kyber
        self.n = 256   # Polynomial degree
        
    def _generate_polynomial(self):
        """Generate a random polynomial for key generation"""
        return [random.randint(0, self.q-1) for _ in range(self.n)]
    
    def _polynomial_add(self, a, b):
        """Add two polynomials mod q"""
        return [(a[i] + b[i]) % self.q for i in range(min(len(a), len(b)))]
    
    def _polynomial_multiply_simple(self, a, b):
        """Simplified polynomial multiplication mod q"""
        # Simple convolution for demonstration
        result = [0] * self.n
        for i in range(min(len(a), 64)):  # Limit for performance
            for j in range(min(len(b), 64)):
                if i + j < self.n:
                    result[i + j] = (result[i + j] + a[i] * b[j]) % self.q
        return result
    
    def _add_noise(self, poly):
        """Add noise to polynomial (simplified error distribution)"""
        noise = [random.randint(-2, 2) for _ in range(len(poly))]
        return [(poly[i] + noise[i]) % self.q for i in range(len(poly))]
    
    def keygen(self):
        """Generate Kyber key pair"""
        # Secret key (private)
        s = self._generate_polynomial()
        
        # Public matrix A (simplified to single polynomial)
        A = self._generate_polynomial()
        
        # Error polynomial
        e = self._add_noise([0] * self.n)
        
        # Public key: b = A*s + e
        As = self._polynomial_multiply_simple(A, s)
        b = self._polynomial_add(As, e)
        
        public_key = {'A': A[:64], 'b': b[:64]}  # Truncate for performance
        private_key = {'s': s[:64]}
        
        return public_key, private_key
    
    def encapsulate(self, public_key):
        """Encapsulate a shared secret"""
        # Generate random coins
        r = [random.randint(0, 1) for _ in range(64)]
        e1 = self._add_noise([0] * 64)
        e2 = random.randint(0, 2)
        
        # Ciphertext components
        Ar = self._polynomial_multiply_simple(public_key['A'], r)
        u = self._polynomial_add(Ar, e1)
        
        # Shared secret (simplified)
        shared_secret = hashlib.sha256(str(r).encode()).digest()[:32]
        
        # v = b*r + e2 + encode(shared_secret)
        br = self._polynomial_multiply_simple(public_key['b'], r)
        v = [(br[i] + e2) % self.q for i in range(len(br))]
        
        ciphertext = {'u': u, 'v': v}
        
        return ciphertext, shared_secret
    
    def decapsulate(self, ciphertext, private_key):
        """Decapsulate the shared secret"""
        # Recover shared secret: v - s*u
        su = self._polynomial_multiply_simple(private_key['s'], ciphertext['u'])
        recovered = [(ciphertext['v'][i] - su[i]) % self.q for i in range(len(su))]
        
        # Simplified recovery
        shared_secret = hashlib.sha256(str(recovered).encode()).digest()[:32]
        
        return shared_secret

class APIDataFlowVisualizer:
    def __init__(self):
        self.kyber = CRYSTALSKyberSimulator()
        self.data_packets = []
        self.running = False
        
        # Generate Kyber key pair
        self.public_key, self.private_key = self.kyber.keygen()
        
        # Statistics
        self.total_packets = 0
        self.encrypted_packets = 0
        self.decrypted_packets = 0
        
    def generate_api_data(self):
        """Generate sample API data"""
        api_endpoints = [
            '/api/users', '/api/orders', '/api/products', 
            '/api/analytics', '/api/payments', '/api/inventory'
        ]
        
        methods = ['GET', 'POST', 'PUT', 'DELETE']
        
        data = {
            'endpoint': random.choice(api_endpoints),
            'method': random.choice(methods),
            'timestamp': datetime.now().isoformat(),
            'user_id': random.randint(1000, 9999),
            'session_token': hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
            'payload_size': random.randint(100, 5000),
            'client_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        }
        
        return json.dumps(data, indent=2)
    
    def encrypt_data(self, data):
        """Encrypt data using Kyber"""
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
            
        # Use Kyber for key encapsulation
        ciphertext, shared_secret = self.kyber.encapsulate(self.public_key)
        
        # Use shared secret to encrypt actual data (XOR with key stream)
        encrypted_data = bytearray(data_bytes)
        key_stream = hashlib.sha256(shared_secret).digest()
        
        for i in range(len(encrypted_data)):
            encrypted_data[i] ^= key_stream[i % len(key_stream)]
        
        return {
            'kyber_ciphertext': ciphertext,
            'encrypted_payload': encrypted_data.hex(),
            'shared_secret_hash': hashlib.sha256(shared_secret).hexdigest()[:16],
            'encryption_time': time.time(),
            'original_size': len(data_bytes),
            'encrypted_size': len(encrypted_data)
        }
    
    def decrypt_data(self, encrypted_package):
        """Decrypt data using Kyber"""
        # Decapsulate the shared secret
        shared_secret = self.kyber.decapsulate(
            encrypted_package['kyber_ciphertext'], 
            self.private_key
        )
        
        # Decrypt the payload
        encrypted_data = bytes.fromhex(encrypted_package['encrypted_payload'])
        key_stream = hashlib.sha256(shared_secret).digest()
        
        decrypted_data = bytearray(encrypted_data)
        for i in range(len(decrypted_data)):
            decrypted_data[i] ^= key_stream[i % len(key_stream)]
        
        return decrypted_data.decode('utf-8')
    
    def create_data_packet(self, packet_id, data_type):
        """Create a data packet"""
        packet = {
            'id': packet_id,
            'type': data_type,
            'creation_time': time.time(),
            'status': 'created',
            'position': 0  # 0=client, 1=encrypting, 2=encrypted, 3=server
        }
        return packet
    
    def display_flow_state(self):
        """Display current flow state in console"""
        print("\n" + "="*80)
        print("🔐 CRYSTALS-KYBER API DATA FLOW VISUALIZATION")
        print("="*80)
        
        # System status
        print(f"📊 SYSTEM STATUS:")
        print(f"   Total Packets Processed: {self.total_packets}")
        print(f"   Currently Encrypted: {self.encrypted_packets}")
        print(f"   Successfully Decrypted: {self.decrypted_packets}")
        print(f"   Active Packets in Flow: {len(self.data_packets)}")
        
        # Key information
        pub_key_size = len(str(self.public_key))
        priv_key_size = len(str(self.private_key))
        print(f"\n🔑 KYBER KEY INFORMATION:")
        print(f"   Public Key Size: {pub_key_size} characters")
        print(f"   Private Key Size: {priv_key_size} characters")
        print(f"   Security Level: {self.kyber.security_level} bits")
        print(f"   Polynomial Degree: {self.kyber.n}")
        print(f"   Modulus: {self.kyber.q}")
        
        # Flow visualization
        print(f"\n🌊 DATA FLOW PIPELINE:")
        print("   CLIENT → [ENCRYPT] → TRANSMISSION → [DECRYPT] → SERVER")
        
        # Show active packets
        if self.data_packets:
            print(f"\n📦 ACTIVE PACKETS:")
            for i, packet in enumerate(self.data_packets[-5:]):  # Show last 5
                status_symbols = ["📱", "🔐", "📡", "🖥️"]
                status_names = ["Client", "Encrypting", "Transmitting", "Server"]
                symbol = status_symbols[packet['position']]
                name = status_names[packet['position']]
                age = time.time() - packet['creation_time']
                print(f"   {symbol} Packet {packet['id']:03d}: {name} (Age: {age:.1f}s)")
        
        print("="*80)
    
    def simulate_packet_flow(self, packet, api_data):
        """Simulate a packet moving through the system"""
        stages = [
            ("📱 Client", "Generating API request..."),
            ("🔐 Encrypting", "Applying CRYSTALS-Kyber encryption..."),
            ("📡 Transmitting", "Sending encrypted data..."),
            ("🔓 Decrypting", "Decapsulating with Kyber..."),
            ("🖥️ Server", "Processing decrypted request...")
        ]
        
        for i, (stage, description) in enumerate(stages):
            packet['position'] = i
            packet['status'] = stage
            
            if i == 1:  # Encryption stage
                encrypted_package = self.encrypt_data(api_data)
                packet['encrypted_data'] = encrypted_package
                packet['original_data'] = api_data
                self.encrypted_packets += 1
                
                # Show encryption details
                print(f"\n🔐 ENCRYPTION DETAILS for Packet {packet['id']:03d}:")
                print(f"   Original Size: {encrypted_package['original_size']} bytes")
                print(f"   Encrypted Size: {encrypted_package['encrypted_size']} bytes")
                print(f"   Shared Secret Hash: {encrypted_package['shared_secret_hash']}")
                print(f"   Kyber Ciphertext U Size: {len(encrypted_package['kyber_ciphertext']['u'])}")
                print(f"   Kyber Ciphertext V Size: {len(encrypted_package['kyber_ciphertext']['v'])}")
                
            elif i == 3:  # Decryption stage
                if 'encrypted_data' in packet:
                    try:
                        decrypted_data = self.decrypt_data(packet['encrypted_data'])
                        packet['decrypted_data'] = decrypted_data
                        self.decrypted_packets += 1
                        
                        # Verify decryption
                        original_json = json.loads(packet['original_data'])
                        decrypted_json = json.loads(decrypted_data)
                        success = original_json == decrypted_json
                        
                        print(f"\n🔓 DECRYPTION DETAILS for Packet {packet['id']:03d}:")
                        print(f"   Decryption Success: {'✅ YES' if success else '❌ NO'}")
                        print(f"   Original Endpoint: {original_json.get('endpoint', 'N/A')}")
                        print(f"   Decrypted Endpoint: {decrypted_json.get('endpoint', 'N/A')}")
                        
                    except Exception as e:
                        print(f"   ❌ Decryption failed: {str(e)}")
            
            time.sleep(0.5)  # Simulate processing time
    
    def run_continuous_simulation(self):
        """Run continuous simulation of API data flow"""
        self.running = True
        packet_counter = 0
        
        print("🚀 Starting CRYSTALS-Kyber API Data Flow Simulation...")
        print("📝 This simulation shows post-quantum encrypted API traffic")
        print("⏹️  Press Ctrl+C to stop the simulation\n")
        
        try:
            while self.running:
                # Clean up old packets
                current_time = time.time()
                self.data_packets = [p for p in self.data_packets 
                                   if current_time - p['creation_time'] < 10]
                
                # Generate new packet
                packet_counter += 1
                api_data = self.generate_api_data()
                packet = self.create_data_packet(packet_counter, 'api_request')
                
                self.data_packets.append(packet)
                self.total_packets += 1
                
                # Display current state
                self.display_flow_state()
                
                # Simulate packet flow in a separate thread for better visualization
                flow_thread = threading.Thread(
                    target=self.simulate_packet_flow, 
                    args=(packet, api_data)
                )
                flow_thread.daemon = True
                flow_thread.start()
                
                # Wait before next packet
                time.sleep(2)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Simulation stopped by user")
            self.running = False
    
    def run_single_demo(self):
        """Run a single demonstration of the encryption process"""
        print("🔐 CRYSTALS-KYBER SINGLE PACKET DEMONSTRATION")
        print("="*60)
        
        # Generate sample data
        api_data = self.generate_api_data()
        print("📝 Original API Data:")
        print(api_data)
        print(f"\n📏 Data Size: {len(api_data)} characters")
        
        # Encrypt
        print("\n🔐 Encrypting with CRYSTALS-Kyber...")
        start_time = time.time()
        encrypted_package = self.encrypt_data(api_data)
        encryption_time = time.time() - start_time
        
        print(f"✅ Encryption completed in {encryption_time:.4f} seconds")
        print(f"📦 Encrypted payload size: {len(encrypted_package['encrypted_payload'])//2} bytes")
        print(f"🔑 Shared secret hash: {encrypted_package['shared_secret_hash']}")
        print(f"📊 Kyber ciphertext components:")
        print(f"   - U component: {len(encrypted_package['kyber_ciphertext']['u'])} elements")
        print(f"   - V component: {len(encrypted_package['kyber_ciphertext']['v'])} elements")
        
        # Decrypt
        print("\n🔓 Decrypting with CRYSTALS-Kyber...")
        start_time = time.time()
        decrypted_data = self.decrypt_data(encrypted_package)
        decryption_time = time.time() - start_time
        
        print(f"✅ Decryption completed in {decryption_time:.4f} seconds")
        
        # Verify
        original_json = json.loads(api_data)
        decrypted_json = json.loads(decrypted_data)
        verification_success = original_json == decrypted_json
        
        print(f"\n🔍 Verification Result: {'✅ SUCCESS' if verification_success else '❌ FAILED'}")
        
        if verification_success:
            print("🎉 The decrypted data matches the original perfectly!")
            print("🛡️  CRYSTALS-Kyber successfully protected the API data!")
        else:
            print("⚠️  There was an issue with the encryption/decryption process")
        
        print("\n📊 Performance Summary:")
        print(f"   Encryption Time: {encryption_time:.4f}s")
        print(f"   Decryption Time: {decryption_time:.4f}s")
        print(f"   Total Round-trip: {encryption_time + decryption_time:.4f}s")
        print(f"   Data Integrity: {'✅ Verified' if verification_success else '❌ Failed'}")

def main():
    """Main function to run the visualization"""
    print("🔐 CRYSTALS-KYBER API DATA FLOW VISUALIZER")
    print("==========================================")
    print("Choose an option:")
    print("1. Single packet demonstration")
    print("2. Continuous flow simulation")
    print("3. Exit")
    
    while True:
        try:
            choice = input("\nEnter your choice (1-3): ").strip()
            
            if choice == '1':
                visualizer = APIDataFlowVisualizer()
                visualizer.run_single_demo()
                break
                
            elif choice == '2':
                visualizer = APIDataFlowVisualizer()
                visualizer.run_continuous_simulation()
                break
                
            elif choice == '3':
                print("👋 Goodbye!")
                break
                
            else:
                print("❌ Invalid choice. Please enter 1, 2, or 3.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ An error occurred: {e}")

if __name__ == "__main__":
    main()
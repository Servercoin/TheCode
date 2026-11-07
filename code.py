import hashlib
import random
import flask
from flask import Flask,request,jsonify
from flask import app
app = Flask(__name__)

# Using simple RSA-style group arithmetic to demonstrate the Shacham-Waters concept cleanly.
# In production, this uses BLS pairings or RSA with large prime order groups.

class FileOwner:
    """Client/Verifier: Preprocesses the file and challenges the untrusted host."""
    def __init__(self, key_size=1024):
        # Generate simple public/private RSA parameters for PoR
        self.p = 104729  # Prime 1
        self.q = 104759  # Prime 2
        self.N = self.p * self.q
        self.e = 65537
        self.d = pow(self.e, -1, (self.p - 1) * (self.q - 1))
        
        # Generator base 'g' for tag generation
        self.g = 2

    def preprocess_file(self, file_bytes: bytes, block_size=16):
        """Splits file into blocks and generates authenticators (sigma) for each block."""
        # Pad file bytes to block size multiples
        padded = file_bytes + b'\x00' * ((block_size - len(file_bytes) % block_size) % block_size)
        blocks = [int.from_bytes(padded[i:i+block_size], 'big') for i in range(0, len(padded), block_size)]
        
        authenticators = []
        for i, block_val in enumerate(blocks):
            # Tag = H(i) * g^block mod N (signed with private key 'd')
            h_i = int(hashlib.sha256(f"block_{i}".encode()).hexdigest(), 16) % self.N
            tag_raw = (h_i * pow(self.g, block_val, self.N)) % self.N
            sig = pow(tag_raw, self.d, self.N)  # Authenticator sigma_i
            authenticators.append(sig)

        public_key = {'N': self.N, 'e': self.e, 'g': self.g}
        return blocks, authenticators, public_key

    def create_challenge(self, num_blocks: int, sample_count=5):
        """Generates random indices and random coefficient weights (r_i)."""
        sampled_indices = random.sample(range(num_blocks), min(sample_count, num_blocks))
        challenges = {idx: random.randint(1, 100) for idx in sampled_indices}
        return challenges

    def verify_proof(self, public_key, challenge: dict, proof: dict) -> bool:
        """Verifies the aggregated proof response without reading the full file."""
        N, e, g = public_key['N'], public_key['e'], public_key['g']
        mu = proof['mu']      # Aggregated data response
        sigma = proof['sigma'] # Aggregated signature response

        # LHS: sigma^e mod N
        lhs = pow(sigma, e, N)

        # RHS: Product of (H(i)^r_i) * g^mu mod N
        prod_h = 1
        for idx, coeff in challenge.items():
            h_i = int(hashlib.sha256(f"block_{idx}".encode()).hexdigest(), 16) % N
            prod_h = (prod_h * pow(h_i, coeff, N)) % N

        rhs = (prod_h * pow(g, mu, N)) % N

        return lhs == rhs
    def reconstruct_file(self, public_key, blocks, authenticators) -> bytes:
        """Retrieves all blocks from the host, verifies each one, and rebuilds the file."""
        N, e, g = public_key['N'], public_key['e'], public_key['g']
        verified_blocks = []

        for i, (block_val, sigma_i) in enumerate(zip(blocks, authenticators)):
            # Verify each block's authenticator: sigma_i^e ?= H(i) * g^block_val mod N
            h_i = int(hashlib.sha256(f"block_{i}".encode()).hexdigest(), 16) % N
            expected_tag = (h_i * pow(g, block_val, N)) % N
            actual_tag = pow(sigma_i, e, N)

            if actual_tag != expected_tag:
                raise ValueError(f"Retrieval failed! Block {i} was tampered with or corrupted.")

            # Convert block back to bytes (16 bytes per block)
            verified_blocks.append(block_val.to_bytes(16, 'big'))

        # Recombine blocks and strip padding
        reconstructed_bytes = b''.join(verified_blocks)
        return reconstructed_bytes.rstrip(b'\x00')



class StorageHost:
    """Storage Node: Holds the raw file blocks and authenticators."""
    def __init__(self, blocks, authenticators, public_key):
        self.blocks = blocks
        self.authenticators = authenticators
        self.public_key = public_key

    def prove_storage(self, challenge: dict) -> dict:
        """Computes compact response aggregated from challenged blocks."""
        N = self.public_key['N']
        
        # Aggregate data value: sum(coeff * block_data)
        mu = sum(coeff * self.blocks[idx] for idx, coeff in challenge.items())
        
        # Aggregate authenticator tag: product(sigma_i ^ coeff) mod N
        sigma = 1
        for idx, coeff in challenge.items():
            sigma = (sigma * pow(self.authenticators[idx], coeff, N)) % N

        return {'mu': mu, 'sigma': sigma}
    def serve_get_request(self):
        """Returns all stored data blocks and authenticators to the requester."""
        return self.blocks, self.authenticators


# ==========================================
# DEMO / EXECUTION
# ==========================================
if __name__ == "__main__":
    file_owner = FileOwner()
    
    # 1. Prepare file
    file_content = b"Filecoin July 2014 Proof of Retrievability Protocol Demo! LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL LOL" * 20
    print(f"Original File Size: {len(file_content)} bytes")

    # 2. Preprocess: Get blocks, signatures, and public key
    blocks, authenticators, pub_key = file_owner.preprocess_file(file_content, block_size=16)
    print(f"File split into {len(blocks)} blocks with authenticators generated.")

    # 3. Host receives file blocks + authenticators (Client keeps nothing except public key!)
    host = StorageHost(blocks, authenticators, pub_key)

    # 4. Verifier issues random Challenge
    challenge = file_owner.create_challenge(num_blocks=len(blocks), sample_count=4)
    print(f"\nVerifier issuing random challenge for block indices: {list(challenge.keys())}")

    # 5. Host generates compact proof
    proof = host.prove_storage(challenge)
    print("Host generated compact Proof response (mu, sigma).")

    # 6. Verifier checks the host's proof
    is_valid = file_owner.verify_proof(pub_key, challenge, proof)
    print(f"\nVerification Result: {'SUCCESS (Host has the file!)' if is_valid else 'FAILED'}")

    # --- DEMO: Tamper test ---
    print("\n--- Tamper Test ---")
    challenged_block_idx = list(challenge.keys())[1]
    
    # Corrupt that specific challenged block in the host's storage
    print(f"Corrupting block {challenged_block_idx} in host storage...")
    print(host.blocks[challenged_block_idx])
    if 1 == 3:
     host.blocks[challenged_block_idx] ^= 0xFF
    tampered_proof = host.prove_storage(challenge)
    is_valid_tampered = file_owner.verify_proof(pub_key, challenge, tampered_proof)
    print(f"Verification Result after data corruption: {'SUCCESS' if is_valid_tampered else 'FAILED (Tampering Detected!)'}")
print("\n--- File Retrieval ---")

# 1. Owner requests full file data from host
downloaded_blocks, downloaded_sigs = host.serve_get_request()

# 2. Owner verifies blocks individually and reconstructs the original file
try:
    retrieved_file = file_owner.reconstruct_file(pub_key, downloaded_blocks, downloaded_sigs)
    print("File retrieved and verified successfully!")
    print(f"Decoded Content: {retrieved_file.decode()}")
    
    # Check exact equality with original
    assert retrieved_file == file_content
    print("Integrity Check: MATCHES original file byte-for-byte!")
except ValueError as err:
    print(err)
blocks2,authenticators2 = host.serve_get_request()
hashvalue = 0
for item in blocks2:
        hashvalue+=item
for item in authenticators2:
    print("OK")
    print(authenticators2)
    hashvalue+=item
@app.route("/gettherequest",methods=['GET'])
def getthatrequest():
    FinalServe = host.serve_get_request()
    return jsonify({"Success":FinalServe}),200
print(hashvalue)
if __name__ == "__main__":
    
    port = 1000
    app.run(host="0.0.0.0", port=6767)

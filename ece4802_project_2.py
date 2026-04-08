from phe import paillier
import ecdsa
import math

# --- System Parameters ---
NUM_COMMITTEE = 5
THRESHOLD_PERCENT = 0.80
REQUIRED_SHARES = math.ceil(NUM_COMMITTEE * THRESHOLD_PERCENT) # 4 out of 5

print("==================================================")
print(f"  SYSTEM BOOT: 80% Threshold Protocol")
print(f"  Requires {REQUIRED_SHARES} out of {NUM_COMMITTEE} committee members to decrypt.")
print("==================================================\n")

# ==========================================
# SERVER-SIDE LOGIC (The Bulletin Board)
# ==========================================
class SecureVotingServer:
    def __init__(self):
        # 1. Setup Phase: Generate the Group Keys
        self.public_key, self.__private_key = paillier.generate_paillier_keypair(n_length=1024)
        
        # Publicly accessible data
        self.vip_directory = {}
        self.public_bulletin_board = []
        
        # Committee decryption state
        self.collected_shares = set()
        
    def register_voter(self, voter_id, public_verifying_key):
        """Adds a voter's public key to the VIP directory."""
        self.vip_directory[voter_id] = public_verifying_key

    def receive_vote_payload(self, payload):
        """API Endpoint: Receives vote from a client over the network."""
        v_id = payload["voter_id"]
        
        # A. Verify Authentication (Signature)
        try:
            vk = self.vip_directory[v_id]
            message = str(payload["ciphertext_int"]).encode('utf-8')
            vk.verify(payload["signature"], message)
        except (KeyError, ecdsa.BadSignatureError):
            print(f"[SERVER LOG] ❌ REJECTED Payload from {v_id}: Invalid Signature/Not Authorized.")
            return False
            
        # B. Verify Integrity (Zero-Knowledge Proof)
        if not payload["zkp_valid"]:
            print(f"[SERVER LOG] ❌ REJECTED Payload from {v_id}: ZKP Failed (Invalid vote amount).")
            return False
            
        # C. Append to Bulletin Board
        self.public_bulletin_board.append(payload)
        print(f"[SERVER LOG] ✅ ACCEPTED Payload from {v_id}: Appended to public board.")
        return True

    def calculate_public_tally(self):
        """Homomorphically combines all valid encrypted ballots."""
        encrypted_tally = self.public_key.encrypt(0)
        for ballot in self.public_bulletin_board:
            encrypted_tally = encrypted_tally + ballot["encrypted_vote"]
        return encrypted_tally, len(self.public_bulletin_board)

    def submit_decryption_share(self, committee_member_id):
        """API Endpoint: Committee members submit their key share to unlock the vault."""
        self.collected_shares.add(committee_member_id)
        print(f"[SERVER LOG] 🔑 Received key share from Committee Member {committee_member_id}")

    def execute_threshold_decryption(self):
        """Attempts to decrypt the final tally if the 80% threshold is met."""
        if len(self.collected_shares) < REQUIRED_SHARES:
            print(f"\n[SERVER ERROR] 🔒 Decryption Failed! Only {len(self.collected_shares)} shares collected. {REQUIRED_SHARES} required.")
            return None
            
        print(f"\n[SERVER LOG] 🔓 Threshold of {REQUIRED_SHARES} met! Decrypting vault...")
        encrypted_tally, total_valid_ballots = self.calculate_public_tally()
        
        # Apply the private key (Simulating the reconstruction of Shamir's Secret Shares)
        yes_votes = self.__private_key.decrypt(encrypted_tally)
        no_votes = total_valid_ballots - yes_votes
        
        return yes_votes, no_votes


# ==========================================
# CLIENT-SIDE LOGIC (The Voter's Machine)
# ==========================================
class VoterClient:
    def __init__(self, voter_id):
        self.voter_id = voter_id
        # Client generates their own keys locally. Private key NEVER leaves this machine.
        self.__signing_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_verifying_key = self.__signing_key.get_verifying_key()
        
    def create_encrypted_payload(self, raw_vote, server_public_key):
        """Packages the vote to be sent securely over the network."""
        print(f"[CLIENT {self.voter_id}] Generating encrypted payload locally...")
        
        # 1. Encrypt using the server's public vault key
        encrypted_vote = server_public_key.encrypt(raw_vote)
        ciphertext_int = encrypted_vote.ciphertext()
        
        # 2. Sign the ciphertext with the client's local private key
        message = str(ciphertext_int).encode('utf-8')
        signature = self.__signing_key.sign(message)
        
        # 3. Generate ZKP (Simulated)
        zkp_valid = (raw_vote in [0, 1])
        
        # Return the JSON-like payload to send over the network
        return {
            "voter_id": self.voter_id,
            "encrypted_vote": encrypted_vote,
            "ciphertext_int": ciphertext_int,
            "signature": signature,
            "zkp_valid": zkp_valid
        }


# ==========================================
# EXECUTION SIMULATION (The Network)
# ==========================================

# 1. Boot the Server
cloud_server = SecureVotingServer()

# 2. Boot the Clients (Voters) & Register them
voters = [VoterClient(f"Voter_{i}") for i in range(1, 6)]
for v in voters:
    cloud_server.register_voter(v.voter_id, v.public_verifying_key)

print("\n--- PHASE 2: Networked Ballot Casting ---")

# Client 1 votes YES
payload_1 = voters[0].create_encrypted_payload(1, cloud_server.public_key)
cloud_server.receive_vote_payload(payload_1)

# Client 2 votes NO
payload_2 = voters[1].create_encrypted_payload(0, cloud_server.public_key)
cloud_server.receive_vote_payload(payload_2)

# Client 3 votes YES
payload_3 = voters[2].create_encrypted_payload(1, cloud_server.public_key)
cloud_server.receive_vote_payload(payload_3)

# Client 4 tries to cheat by voting '5' YES votes at once
payload_4 = voters[3].create_encrypted_payload(5, cloud_server.public_key)
cloud_server.receive_vote_payload(payload_4)

# Client 5 votes NO
payload_5 = voters[4].create_encrypted_payload(0, cloud_server.public_key)
cloud_server.receive_vote_payload(payload_5)


print("\n--- PHASE 3: Threshold Decryption ---")
# Let's simulate members submitting their keys. We need 4.
cloud_server.submit_decryption_share("Member_A")
cloud_server.submit_decryption_share("Member_B")
cloud_server.submit_decryption_share("Member_C")

# Let's try to decrypt early (It should fail)
cloud_server.execute_threshold_decryption()

# Submit the 4th required key
cloud_server.submit_decryption_share("Member_D")

# Now the threshold is met, it will succeed
results = cloud_server.execute_threshold_decryption()

if results:
    yes_votes, no_votes = results
    print("\n========================================")
    print(f"  FINAL NETWORK TALLY")
    print(f"  YES: {yes_votes} | NO: {no_votes}")
    print("========================================")
    
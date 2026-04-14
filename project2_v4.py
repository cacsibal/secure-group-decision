import hashlib
import random
import math
import uuid

# ==========================================
# DYNAMIC SYSTEM PARAMETERS
# ==========================================
NUM_COMMITTEE = 5
THRESHOLD = 3 
MAX_VOTERS = 5 # Used to calculate safe bit-packing

# 1. Dynamic Bitwise Masking (Fixes the Overflow Bomb)
# We calculate exactly how many bits we need to safely hold MAX_VOTERS
BITS_PER_CANDIDATE = math.ceil(math.log2(MAX_VOTERS + 1)) 
ALLOWED_VOTES = [1 << (i * BITS_PER_CANDIDATE) for i in range(5)]

print("==================================================")
print(f"  SYSTEM BOOT: Fully Decentralized VSS Protocol")
print(f"  Dynamic Bit-Packing: {BITS_PER_CANDIDATE} bits per candidate")
print("==================================================\n")

# ==========================================
# CRYPTOGRAPHIC SETUP (Schnorr Group)
# ==========================================
def is_prime(n: int, k: int = 5) -> bool:
    if n <= 1 or n % 2 == 0: return False
    if n == 2 or n == 3: return True
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
k = 2
while not is_prime(k * Q + 1): k += 2
P = k * Q + 1
G = pow(2, k, P)
H = pow(3, k, P)

def short_num(val: int) -> str:
    s = str(val)
    if len(s) <= 12: return s
    return f"{s[:5]}...{s[-5:]}"

def lagrange_interpolate(shares: list, prime: int) -> int:
    secret = 0
    for i, (x_i, y_i) in enumerate(shares):
        numerator, denominator = 1, 1
        for j, (x_j, _) in enumerate(shares):
            if i != j:
                numerator = (numerator * (0 - x_j)) % prime
                denominator = (denominator * (x_i - x_j)) % prime
        L_i = (numerator * pow(denominator, -1, prime)) % prime
        secret = (secret + y_i * L_i) % prime
    return secret


# ==========================================
# DECENTRALIZED INFRASTRUCTURE
# ==========================================

class AnonymizingMixNet:
    """Simulates Tor/I2P routing. Strips identities and shuffles payloads."""
    def __init__(self, smart_contract):
        self.pool = []
        self.smart_contract = smart_contract
        
    def route_payload(self, payload: dict):
        # 1. Network-layer Deanonymization Fix: Strip the Voter ID entirely
        anon_payload = payload.copy()
        if "voter_id" in anon_payload:
            del anon_payload["voter_id"]
        self.pool.append(anon_payload)
        print(f"  [MIX-NET] Payload routed. Identity scrubbed.")
        
    def flush_to_blockchain(self):
        print(f"\n[MIX-NET] Shuffling traffic and broadcasting to Blockchain...")
        random.shuffle(self.pool)
        for p in self.pool:
            self.smart_contract.process_transaction(p)
        self.pool = []

class SmartContractLedger:
    """Simulates an immutable, decentralized blockchain contract."""
    def __init__(self):
        self.ledger = {} # Append-only dictionary
        self.verified_node_tallies = []
        
        # Dispute resolution state
        self.forced_inclusions = {i: {"S": 0, "T": 0} for i in range(1, NUM_COMMITTEE + 1)}

    def _verify_zkp(self, C: int, proof: dict) -> bool:
        c, z = proof["c"], proof["z"]
        try:
            A_rebuilt = {}
            for x in ALLOWED_VOTES:
                G_pow_x_inv = pow(pow(G, x, P), -1, P)
                A_rebuilt[x] = (pow(H, z[x], P) * pow((C * G_pow_x_inv) % P, -c[x], P)) % P
            
            hash_input = f"{C}:" + ":".join(str(A_rebuilt[x]) for x in ALLOWED_VOTES)
            expected_e = int(hashlib.sha256(hash_input.encode('utf-8')).hexdigest(), 16) % Q
            return (sum(c.values()) % Q) == expected_e
        except ValueError: return False

    def process_transaction(self, payload: dict):
        t_id = payload["tracking_id"]
        C_0 = payload["C_poly"][0] 
        
        if not self._verify_zkp(C_0, payload["zkp_proof"]):
            print(f"  ❌ [SMART CONTRACT] REJECTED {t_id}: ZKP Math Failed.")
            return
            
        self.ledger[t_id] = payload
        print(f"  ✅ [SMART CONTRACT] Validated {short_num(t_id)}. Appended to Ledger.")

    def execute_on_chain_dispute(self, node_id: int, tracking_id: str, s_i: int, t_i: int):
        """DISPUTE RESOLUTION: The Contract mathematically audits a "lost" share."""
        print(f"\n  ⚖️ [SMART CONTRACT] Dispute Initiated against Node {node_id} for ID {short_num(tracking_id)}")
        
        if tracking_id not in self.ledger:
            print("    ❌ Dispute Failed: Tracking ID not on public ledger.")
            return
            
        C_poly = self.ledger[tracking_id]["C_poly"]
        
        # 1. Calculate what the public polynomial says the node's share SHOULD be
        expected_C = 1
        for k, C_k in enumerate(C_poly):
            expected_C = (expected_C * pow(C_k, (node_id ** k), P)) % P
            
        # 2. Calculate what the disputed share mathematically represents
        provided_C = (pow(G, s_i, P) * pow(H, t_i, P)) % P
        
        if expected_C == provided_C:
            print(f"    ✅ Math Confirmed! The share belongs to the public lockbox.")
            print(f"    🚨 PENALTY: Node {node_id} is lying. Contract forcing share inclusion.")
            self.forced_inclusions[node_id]["S"] = (self.forced_inclusions[node_id]["S"] + s_i) % Q
            self.forced_inclusions[node_id]["T"] = (self.forced_inclusions[node_id]["T"] + t_i) % Q
        else:
            print("    ❌ Dispute Failed: Provided share does not match public lockbox.")

    def verify_node_tally(self, node_id: int, S_i: int, T_i: int):
        print(f"\n[SMART CONTRACT] Auditing Node {node_id}'s Subtally...")
        node_commitment = (pow(G, S_i, P) * pow(H, T_i, P)) % P
        
        # Sum the polynomials from the ledger
        expected_commitment = 1
        for payload in self.ledger.values():
            voter_C_i = 1
            for k, C_k in enumerate(payload["C_poly"]):
                voter_C_i = (voter_C_i * pow(C_k, (node_id ** k), P)) % P
            expected_commitment = (expected_commitment * voter_C_i) % P
            
        # Add any shares the contract forced the node to include due to disputes
        forced_S = self.forced_inclusions[node_id]["S"]
        forced_T = self.forced_inclusions[node_id]["T"]
        forced_commitment = (pow(G, forced_S, P) * pow(H, forced_T, P)) % P
        expected_commitment = (expected_commitment * forced_commitment) % P
            
        if node_commitment == expected_commitment:
            self.verified_node_tallies.append((node_id, S_i))
            print(f"  ✅ NODE {node_id} VERIFIED.")
        else:
            print(f"  ❌ NODE {node_id} REJECTED: Forgery detected!")

    def execute_threshold_decryption(self):
        if len(self.verified_node_tallies) < THRESHOLD:
            print("\n❌ ELECTION FAILED: Threshold not reached.")
            return
            
        print(f"\n--- [SMART CONTRACT] Interpolating Final Tally ---")
        packed_tally = lagrange_interpolate(self.verified_node_tallies[:THRESHOLD], Q)
        print(f"  Raw Packed Integer: {packed_tally}")
        
        print("\n  --- Dynamic Bitwise Unpacking ---")
        bit_mask = (1 << BITS_PER_CANDIDATE) - 1 
        for i in range(5):
            candidate_num = i + 1
            shift_amount = i * BITS_PER_CANDIDATE
            candidate_votes = (packed_tally >> shift_amount) & bit_mask
            print(f"  Candidate {candidate_num} Votes: {candidate_votes}")


# ==========================================
# EDGE NODES & CLIENTS
# ==========================================

class CommitteeNode:
    def __init__(self, node_id: int):
        self.node_id = node_id
        self.inbox = {} 
        self.S_tally = 0 
        self.T_tally = 0 
        
    def receive_private_share(self, tracking_id: str, s_i: int, t_i: int):
        self.inbox[tracking_id] = {"s": s_i, "t": t_i}
        
    def calculate_subtally(self, public_ledger: dict):
        for t_id, private_data in self.inbox.items():
            if t_id not in public_ledger: continue 
                
            s_i, t_i = private_data["s"], private_data["t"]
            expected_C = (pow(G, s_i, P) * pow(H, t_i, P)) % P
            
            C_poly = public_ledger[t_id]["C_poly"]
            public_C = 1
            for k, C_k in enumerate(C_poly):
                public_C = (public_C * pow(C_k, (self.node_id ** k), P)) % P
            
            if expected_C == public_C:
                self.S_tally = (self.S_tally + s_i) % Q
                self.T_tally = (self.T_tally + t_i) % Q

class VoterClient:
    def __init__(self, voter_id: str):
        self.voter_id = voter_id
        self.sys_rand = random.SystemRandom()
        # The tracking ID breaks the link between the Voter's IP and their Payload
        self.tracking_id = str(uuid.uuid4().int)[:12] 

    def _generate_zkp(self, v: int, r: int, C: int) -> dict:
        z, c, A = {}, {}, {}
        if v not in ALLOWED_VOTES: return {"c": {x: 1 for x in ALLOWED_VOTES}, "z": {x: 1 for x in ALLOWED_VOTES}}

        for x in ALLOWED_VOTES:
            if x == v: continue
            z[x], c[x] = self.sys_rand.randrange(1, Q), self.sys_rand.randrange(1, Q)
            G_pow_x_inv = pow(pow(G, x, P), -1, P)
            A[x] = (pow(H, z[x], P) * pow((C * G_pow_x_inv) % P, -c[x], P)) % P

        w = self.sys_rand.randrange(1, Q)
        A[v] = pow(H, w, P)
        hash_input = f"{C}:" + ":".join(str(A[x]) for x in ALLOWED_VOTES)
        e = int(hashlib.sha256(hash_input.encode('utf-8')).hexdigest(), 16) % Q
        sum_fake_c = sum(c[x] for x in ALLOWED_VOTES if x != v) % Q
        c[v] = (e - sum_fake_c) % Q
        z[v] = (w + ((c[v] * r) % Q)) % Q
        return {"c": c, "z": z}

    def cast_vote(self, candidate_id: int, mix_net: AnonymizingMixNet, committee: list) -> dict:
        packed_vote = 1 << (BITS_PER_CANDIDATE * (candidate_id - 1))
        
        degree = THRESHOLD - 1
        f_coeffs = [packed_vote] + [self.sys_rand.randrange(1, Q) for _ in range(degree)]
        r_coeffs = [self.sys_rand.randrange(1, Q) for _ in range(degree + 1)]
        C_poly = [(pow(G, f_coeffs[k], P) * pow(H, r_coeffs[k], P)) % P for k in range(degree + 1)]
        zkp_proof = self._generate_zkp(packed_vote, r_coeffs[0], C_poly[0])
        
        saved_shares_for_disputes = {} # Saved locally on Voter's machine just in case
        
        for node in committee:
            x = node.node_id
            s_i = sum(f_coeffs[k] * (x ** k) for k in range(degree + 1)) % Q
            t_i = sum(r_coeffs[k] * (x ** k) for k in range(degree + 1)) % Q
            
            node.receive_private_share(self.tracking_id, s_i, t_i)
            saved_shares_for_disputes[x] = {"s": s_i, "t": t_i}
            
        payload = {
            "voter_id": self.voter_id, # Will be stripped by Mix-Net
            "tracking_id": self.tracking_id,
            "C_poly": C_poly,
            "zkp_proof": zkp_proof
        }
        mix_net.route_payload(payload)
        return saved_shares_for_disputes


# ==========================================
# EXECUTION SIMULATION (Sabotage & Dispute)
# ==========================================

blockchain = SmartContractLedger()
mix_net = AnonymizingMixNet(blockchain)
committee = [CommitteeNode(i+1) for i in range(NUM_COMMITTEE)] 

# 1. Voting Phase
print("\n--- PHASE 1: VOTING & ROUTING ---")
v1 = VoterClient("Alice")
v1_shares = v1.cast_vote(3, mix_net, committee)

v2 = VoterClient("Bob")
v2.cast_vote(5, mix_net, committee)

v3 = VoterClient("Charlie")
v3.cast_vote(3, mix_net, committee)

v4 = VoterClient("David")
v4.cast_vote(1, mix_net, committee)

# 2. Mix-Net Flush
mix_net.flush_to_blockchain()

# --- THE SABOTAGE: SHARE WITHHOLDING ATTACK ---
print("\n[ALERT] Node 2 is maliciously deleting Alice's private share to suppress her vote!")
del committee[1].inbox[v1.tracking_id] # Node 2 deletes the P2P message

# 3. Dispute Resolution Phase
print("\n--- PHASE 2: AUDIT & DISPUTE ---")
print(f"Alice audits Node 2 and notices her Tracking ID ({short_num(v1.tracking_id)}) was ignored.")

# Alice submits the missing math directly to the Smart Contract
missing_s = v1_shares[2]["s"]
missing_t = v1_shares[2]["t"]
blockchain.execute_on_chain_dispute(node_id=2, tracking_id=v1.tracking_id, s_i=missing_s, t_i=missing_t)

# 4. Tally Phase
print("\n--- PHASE 3: SUBTALLIES & FINAL REVEAL ---")
for node in committee:
    node.calculate_subtally(blockchain.ledger)
    # The nodes submit their tallies to the blockchain for verification
    blockchain.verify_node_tally(node.node_id, node.S_tally, node.T_tally)

blockchain.execute_threshold_decryption()
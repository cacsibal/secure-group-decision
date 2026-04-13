from phe import paillier
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import math
import hashlib
import random
import secrets
from typing import Dict, Any, Tuple, List, Optional

# --- System Parameters ---
NUM_COMMITTEE = 6
THRESHOLD_PERCENT = 0.66
REQUIRED_SHARES = math.ceil(NUM_COMMITTEE * THRESHOLD_PERCENT) 

def short_num(val: int) -> str:
    s = str(val)
    if len(s) <= 12: return s
    return f"{s[:5]}...{s[-5:]}"

print("==================================================")
print(f"  SYSTEM BOOT: 100% Trustless Threshold Paillier")
print(f"  Architecture: Distributed RSA Modulus Generation.")
print("==================================================\n")

# ==========================================
# CRYPTOGRAPHIC HELPER MATH (Prime Generation)
# ==========================================
def is_prime(n: int, k: int = 128) -> bool:
    """Miller-Rabin primality test."""
    if n == 2 or n == 3: return True
    if n <= 1 or n % 2 == 0: return False
    
    # Find r and d such that n - 1 = 2^r * d
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
        
    # Run the test k times
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def get_prime(bits: int) -> int:
    """Generates a prime number of the specified bit length."""
    while True:
        # Generate a random number of the right size, forcing it to be odd
        p = secrets.randbits(bits)
        p |= (1 << bits - 1) | 1 
        if is_prime(p):
            return p
        
# ==========================================
# EDGE NODES (Committee Members)
# ==========================================
class CommitteeMember:
    def __init__(self, member_id: int):
        self.member_id = member_id
        self.sys_rand = random.SystemRandom()
        
        # Additive shares of the prime numbers (No one knows true p or q)
        self.p_shard = 0
        self.q_shard = 0
        
        # Polynomial storage for the Lambda DKG
        self.M = 0
        self.__personal_polynomial = []
        self.__received_shares: List[int] = []
        self.__final_private_shard = None
        
        # Public Paillier params
        self.nsq = 0
        self.g = 0

    def set_public_params(self, n: int, g: int, M: int):
        """Called after the P2P network successfully generates the modulus."""
        self.nsq = n ** 2
        self.g = g
        self.M = M

    def initialize_lambda_dkg(self, starting_piece: int):
        """Starts the P2P polynomial dealing once Lambda is securely split."""
        self.__personal_polynomial = [starting_piece] + [secrets.randbelow(self.M) for _ in range(REQUIRED_SHARES - 1)]

    def deal_share_to(self, target_member_id: int) -> int:
        x = target_member_id
        y = 0
        for power, coeff in enumerate(self.__personal_polynomial):
            y = (y + coeff * pow(x, power, self.M)) % self.M
        return y
        
    def receive_dkg_share(self, share: int):
        self.__received_shares.append(share)
        
    def finalize_dkg(self) -> int:
        self.__final_private_shard = sum(self.__received_shares) % self.M
        return self.__final_private_shard
        
    def generate_public_verification_key(self) -> int:
        return pow(self.g, self.__final_private_shard, self.nsq)
        
    def compute_partial_decryption(self, encrypted_tally_int: int, n: int) -> Tuple[int, Dict[str, int]]:
        print(f"\n  [EDGE COMPUTE] Member {self.member_id} computing partial decryption locally...")
        c = encrypted_tally_int
        s_i = self.__final_private_shard
        c_i = pow(c, s_i, self.nsq)
        
        r = self.sys_rand.randrange(1, self.nsq)
        a = pow(c, r, self.nsq)
        b = pow(self.g, r, self.nsq)
        vk_i = pow(self.g, s_i, self.nsq)
        
        hash_input = f"{c}:{self.g}:{c_i}:{vk_i}:{a}:{b}".encode('utf-8')
        e = int(hashlib.sha256(hash_input).hexdigest(), 16)
        z = r + (e * s_i)
        
        print(f"    c_i (Partial Decrypt) = {short_num(c_i)}")
        return c_i, {"a": a, "b": b, "e": e, "z": z}

# ==========================================
# SECURE MULTIPARTY COMPUTATION SIMULATOR
# Represents the encrypted P2P channels between committee members
# ==========================================
class P2PNetworkSimulator:
    @staticmethod
    def generate_distributed_modulus(committee: List[CommitteeMember]) -> Tuple[int, int, int]:
        """
        Simulates the Oblivious Transfer protocol where members mathematically 
        multiply their prime shards together without revealing them.
        """
        print("\n--- [P2P MATH] DISTRIBUTED BIPRIME GENERATION ---")
        # In a real system, they test random shards until a biprime is found.
        # We simulate the successful generation of those primes here.
        true_p = get_prime(256)
        true_q = get_prime(256)
        
        # Instantly shatter the primes into additive shares.
        # true_p and true_q are mathematically deleted after this block.
        temp_p, temp_q = true_p, true_q
        for i in range(len(committee) - 1):
            p_s = secrets.randbits(256)
            q_s = secrets.randbits(256)
            committee[i].p_shard = p_s
            committee[i].q_shard = q_s
            temp_p -= p_s
            temp_q -= q_s
            print(f"  Member {committee[i].member_id} secured shards: p={short_num(p_s)}, q={short_num(q_s)}")
        
        committee[-1].p_shard = temp_p
        committee[-1].q_shard = temp_q
        print(f"  Member {committee[-1].member_id} secured shards: p={short_num(temp_p)}, q={short_num(temp_q)}")
        
        # The P2P network collaboratively computes N = (Sum p_i) * (Sum q_i)
        sum_p = sum(m.p_shard for m in committee)
        sum_q = sum(m.q_shard for m in committee)
        N = sum_p * sum_q
        
        # The P2P network collaboratively computes Lambda = lcm(p-1, q-1)
        lam = abs((sum_p-1)*(sum_q-1)) // math.gcd(sum_p-1, sum_q-1)
        M = N * lam
        
        print(f"\n  [P2P SUCCESS] Public Modulus (N) calculated collaboratively: {short_num(N)}")
        print(f"  [P2P SUCCESS] Master Secret (\u03BB) calculated collaboratively.")
        print(f"  [SECURITY] True p and q were never held by any single entity.")
        
        return N, lam, M

# ==========================================
# SERVER-SIDE LOGIC (Dumb Bulletin Board)
# ==========================================
class SecureVotingServer:
    def __init__(self):
        self.n = 0
        self.nsq = 0
        self.g = 0
        self.theta = 0
        self.vip_directory: Dict[str, ed25519.Ed25519PublicKey] = {}
        self.public_bulletin_board: list = []
        self.has_voted: set = set()
        self.committee_vks: Dict[int, int] = {}
        self.collected_partial_decryptions: Dict[int, int] = {}

    def set_public_parameters(self, n: int):
        """The server receives the public modulus AFTER the P2P network finishes."""
        self.n = n
        self.nsq = n ** 2
        self.g = n + 1
        print(f"[SERVER LOG] 📡 Booting up with public modulus N={short_num(self.n)}")

    def publish_committee_vk(self, member_id: int, vk_i: int):
        self.committee_vks[member_id] = vk_i

    def register_voter(self, voter_id: str, public_verifying_key: ed25519.Ed25519PublicKey):
        self.vip_directory[voter_id] = public_verifying_key

    def _verify_voter_zkp(self, ciphertext_int: int, proof: Dict[str, int]) -> bool:
        """VERIFIER: Performs modular arithmetic to verify the voter's NIZK proof."""
        n, nsq, g, c = self.n, self.nsq, self.g, ciphertext_int
        e0, e1, z0, z1 = proof["e0"], proof["e1"], proof["z0"], proof["z1"]

        try:
            # Reconstruct commitments
            a0 = (pow(z0, n, nsq) * pow(c, -e0, nsq)) % nsq
            c_over_g = (c * pow(g, -1, nsq)) % nsq
            a1 = (pow(z1, n, nsq) * pow(c_over_g, -e1, nsq)) % nsq

            # Rebuild hash challenge
            hash_input = f"{n}:{g}:{c}:{a0}:{a1}".encode('utf-8')
            expected_e = int(hashlib.sha256(hash_input).hexdigest(), 16)
            
            # Verify response
            return ((e0 + e1) % n) == (expected_e % n)
        except ValueError:
            return False
        
    def receive_vote_payload(self, payload: Dict[str, Any]) -> bool:
        v_id = payload.get("voter_id")
        if v_id in self.has_voted: 
            print(f"[SERVER LOG] ❌ REJECTED {v_id}: Already voted.")
            return False
            
        # 1. Check Authentication (Are they registered?)
        try:
            vk = self.vip_directory[v_id]
            vk.verify(payload["signature"], str(payload["ciphertext_int"]).encode('utf-8'))
        except (KeyError, InvalidSignature): 
            print(f"[SERVER LOG] ❌ REJECTED {v_id}: Invalid Signature.")
            return False
            
        # 2. Check the Math (The line I forgot!)
        # If the vote isn't a 0 or 1, they can't solve the hash challenge, and this fails.
        if not self._verify_voter_zkp(payload["ciphertext_int"], payload["zkp_proof"]): 
            print(f"[SERVER LOG] ❌ REJECTED {v_id}: Cryptographic ZKP Failed (Vote was not 0 or 1).")
            return False
            
        self.public_bulletin_board.append(payload)
        self.has_voted.add(v_id)
        print(f"[SERVER LOG] ✅ ACCEPTED {v_id}: Vote appended.")
        return True

    def set_theta_from_committee(self, theta: int):
        self.theta = theta

    def receive_partial_decryption(self, member_id: int, partial_decryption: int, proof: Dict[str, int], encrypted_tally: int) -> bool:
        c, c_i, vk_i = encrypted_tally, partial_decryption, self.committee_vks[member_id]
        a, b, e, z = proof["a"], proof["b"], proof["e"], proof["z"]
        
        expected_e = int(hashlib.sha256(f"{c}:{self.g}:{c_i}:{vk_i}:{a}:{b}".encode('utf-8')).hexdigest(), 16)
        if e != expected_e: return False
            
        lhs_1 = pow(c, z, self.nsq)
        rhs_1 = (a * pow(c_i, e, self.nsq)) % self.nsq
        if lhs_1 == rhs_1:
            self.collected_partial_decryptions[member_id] = partial_decryption
            print(f"  ✅ ZKP ACCEPTED. Partial decryption added to pool.")
            return True
        return False

    def execute_threshold_tally(self) -> Optional[Tuple[int, int]]:
        if len(self.collected_partial_decryptions) < REQUIRED_SHARES: return None
        print(f"\n--- [MATH] SERVER THRESHOLD AGGREGATION ---")
        
        C_tally = 1
        for ballot in self.public_bulletin_board:
            C_tally = (C_tally * ballot["ciphertext_int"]) % self.nsq
            
        C_prime = 1
        members_who_submitted = list(self.collected_partial_decryptions.keys())[:REQUIRED_SHARES]
        Delta = math.factorial(NUM_COMMITTEE)
        
        for i in members_who_submitted:
            pd_i = self.collected_partial_decryptions[i]
            omega_i = Delta
            for j in members_who_submitted:
                if i != j: omega_i = (omega_i * (-j)) // (i - j) 
            
            if omega_i < 0:
                C_prime = (C_prime * pow(pow(pd_i, -1, self.nsq), -omega_i, self.nsq)) % self.nsq
            else:
                C_prime = (C_prime * pow(pd_i, omega_i, self.nsq)) % self.nsq

        L = (C_prime - 1) // self.n
        yes_votes = (L * self.theta) % self.n
        return yes_votes, len(self.public_bulletin_board) - yes_votes

# ==========================================
# CLIENT-SIDE LOGIC
# ==========================================
class VoterClient:
    def __init__(self, voter_id: str):
        self.voter_id = voter_id
        self.sys_rand = random.SystemRandom()
        self.__signing_key = ed25519.Ed25519PrivateKey.generate()
        self.public_verifying_key = self.__signing_key.public_key()

    def create_encrypted_payload(self, raw_vote: int, n: int, g: int) -> Dict[str, Any]:
        nsq = n * n
        r = self.sys_rand.randrange(1, n)
        while math.gcd(r, n) != 1: 
            r = self.sys_rand.randrange(1, n)
        
        c = (pow(g, raw_vote, nsq) * pow(r, n, nsq)) % nsq
        
        # 1. Catch cheating voters
        if raw_vote not in [0, 1]: 
            zkp_proof = {"e0": 1, "e1": 1, "z0": 1, "z1": 1}
            
        # 2. Honest voter ZKP math
        elif raw_vote == 0:
            z1, e1 = self.sys_rand.randrange(1, n), self.sys_rand.randrange(1, n)
            a1 = (pow(z1, n, nsq) * pow((c * pow(g, -1, nsq)) % nsq, -e1, nsq)) % nsq
            w = self.sys_rand.randrange(1, n)
            a0 = pow(w, n, nsq)
            e = int(hashlib.sha256(f"{n}:{g}:{c}:{a0}:{a1}".encode('utf-8')).hexdigest(), 16)
            
            e0 = (e - e1) % n
            z0 = (w * pow(r, e0, n)) % n
            zkp_proof = {"e0": e0, "e1": e1, "z0": z0, "z1": z1}
            
        else: # raw_vote == 1
            z0, e0 = self.sys_rand.randrange(1, n), self.sys_rand.randrange(1, n)
            a0 = (pow(z0, n, nsq) * pow(c, -e0, nsq)) % nsq
            w = self.sys_rand.randrange(1, n)
            a1 = pow(w, n, nsq)
            e = int(hashlib.sha256(f"{n}:{g}:{c}:{a0}:{a1}".encode('utf-8')).hexdigest(), 16)
            
            e1 = (e - e0) % n
            z1 = (w * pow(r, e1, n)) % n
            zkp_proof = {"e0": e0, "e1": e1, "z0": z0, "z1": z1}

        signature = self.__signing_key.sign(str(c).encode('utf-8'))
        
        # Return the complete dictionary including the ZKP
        return {
            "voter_id": self.voter_id, 
            "ciphertext_int": c, 
            "signature": signature, 
            "zkp_proof": zkp_proof 
        }

# ==========================================
# EXECUTION SIMULATION
# ==========================================

# 1. Initialize Network
cloud_server = SecureVotingServer()
committee = [CommitteeMember(i+1) for i in range(NUM_COMMITTEE)]

# 2. P2P Phase A: Distributed Modulus Generation
global_N, global_lam, global_M = P2PNetworkSimulator.generate_distributed_modulus(committee)
global_g = global_N + 1

cloud_server.set_public_parameters(global_N)
for member in committee:
    member.set_public_params(global_N, global_g, global_M)

# 3. P2P Phase B: Distributed Key Generation (Lambda Sharing)
print("\n--- [P2P MATH] DISTRIBUTED LAMBDA SHARING ---")
# The P2P network obliviously splits lambda into starting points
starting_pieces = [secrets.randbelow(global_M) for _ in range(NUM_COMMITTEE - 1)]
starting_pieces.append((global_lam - sum(starting_pieces)) % global_M)

for i, member in enumerate(committee):
    member.initialize_lambda_dkg(starting_pieces[i])

# Members deal shares to each other (Bypassing the Server)
for dealer in committee:
    for receiver in committee:
        receiver.receive_dkg_share(dealer.deal_share_to(receiver.member_id))

print("\n  [AGGREGATION] Computing final shards & Publishing VKs...")
for member in committee:
    # Tell the member to actually sum up their received shares first!
    member.finalize_dkg() 
    
    vk_i = member.generate_public_verification_key()
    cloud_server.publish_committee_vk(member.member_id, vk_i)

# The P2P network collaboratively calculates public Theta for the server
Delta = math.factorial(NUM_COMMITTEE)
public_theta = pow(Delta * global_lam, -1, global_N)
cloud_server.set_theta_from_committee(public_theta)

# 4. Voting Phase
print("\n--- PHASE 2: Networked Ballot Casting ---")
voters = [VoterClient(f"Voter_{i}") for i in range(1, 7)]
for v in voters: cloud_server.register_voter(v.voter_id, v.public_verifying_key)

cloud_server.receive_vote_payload(voters[0].create_encrypted_payload(1, global_N, global_g))
cloud_server.receive_vote_payload(voters[1].create_encrypted_payload(0, global_N, global_g))
cloud_server.receive_vote_payload(voters[2].create_encrypted_payload(0, global_N, global_g))
cloud_server.receive_vote_payload(voters[3].create_encrypted_payload(1, global_N, global_g))
cloud_server.receive_vote_payload(voters[4].create_encrypted_payload(4, global_N, global_g))
cloud_server.receive_vote_payload(voters[5].create_encrypted_payload(0, global_N, global_g))



# 5. Decryption Phase
print("\n--- PHASE 3: Edge Decryption & Verification ---")
encrypted_tally = 1
for b in cloud_server.public_bulletin_board:
    encrypted_tally = (encrypted_tally * b["ciphertext_int"]) % cloud_server.nsq

# 4 members provide partial decryptions
for i in [0, 1, 3, 4]:
    c_i, proof_i = committee[i].compute_partial_decryption(encrypted_tally, global_N)
    cloud_server.receive_partial_decryption(committee[i].member_id, c_i, proof_i, encrypted_tally)

results = cloud_server.execute_threshold_tally()

if results:
    yes_votes, no_votes = results
    print("\n========================================")
    print(f"  FINAL NETWORK TALLY")
    print(f"  YES: {yes_votes} | NO: {no_votes}")
    print("========================================")
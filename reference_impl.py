from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import asymmetric, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from secrets import SystemRandom
from typing import Dict, Tuple
import math
import pickle
import logging

# Q is a prime of at least 256 bits
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
# k is the first integer found that makes P = kQ + 1 prime and at least 1024 bits
k = (1 << 1024) + 0x19a
P = k * Q + 1
# G and H are generators for order Q subgroups
G = pow(2, k, P)
H = pow(3, k, P)

# We just use SHA256 for everything
HASH = hashes.SHA256()

# Computes F(0) (mod `prime`) for some secret polynomial F. The list `shares` contains points of F
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

def hash(data: bytes) -> int:
    digest = hashes.Hash(HASH)
    digest.update(data)
    return int.from_bytes(digest.finalize(), "big")

class MultiplicativePoly:
    def __init__(self, coeffs: list):
        self.coeffs = coeffs

    def eval(self, pt: int) -> int:
        val = 1
        for i, c in enumerate(self.coeffs):
            val = (val * pow(c, pow(pt, i, Q), P)) % P
        return val

    def __mul__(self, other):
        return MultiplicativePoly(
            list(map(lambda c1, c2: (c1 * c2) % P, self.coeffs, other.coeffs))
        )
        

class AdditivePoly:
    def __init__(self, coeffs: list):
        self.coeffs = coeffs

    def eval(self, pt: int) -> int:
        val = 0
        for i, c in enumerate(self.coeffs):
            val = (val + c * pow(pt, i, Q)) % Q
        return val

    def __rpow__(self, base: int) -> MultiplicativePoly:
        return MultiplicativePoly(
            map(lambda c: pow(base, c, P), self.coeffs)
        )

# Public place for group members to submit commitments and proofs.
# Also stores public keys and allows for members to communicate with one another.
class PublicBulletin:
    def __init__(self, threshold_pct: float, options: int):
        if options < 2:
            raise ValueError("There must be at least two options to vote for (i.e., Reject/Approve)")
        # We should think of this as only storing public things about the members, such as their public keys
        # In a real implementation, the bulletin would definitely not have access to each member's private key
        self.members: Dict[int, 'GroupMember'] = {}
        # Stores the commitment polynomial, zkp, and signature for each voters vote
        # In theory, if the server has stored these, the signature and zkp are valid, but other voters can check these as they wish
        self.votes: Dict[int, Tuple[MultiplicativePoly, Tuple[Dict, Dict], bytes]] = {}

        self.__threshold_pct = threshold_pct
        self.__options = options
        self.required_shares = 0
        self.bits_per_option = 0
        self.allowed_votes = [0 for _ in range(self.__options)]

        self.verified_subtallies = []

        self.__r = SystemRandom()

    # In a real system, we assume registration, including generation and accepting of public keys, has already happened out of band
    def register(self, member_id: int, member: 'GroupMember'):
        self.members[member_id] = member

        voters = len(self.members)
        self.required_shares = math.ceil(voters * self.__threshold_pct)
        self.bits_per_option = math.ceil(math.log2(voters + 1))
        self.allowed_votes = [1 << (i * self.bits_per_option) for i in range(self.__options)]

    def submit_vote(self, member_id: int, vote_payload: bytes, sig: bytes):
        if not self.verify_sig(member_id, vote_payload, sig):
            logging.warning(f"Ignoring vote from voter {member_id} due to signature mismatch")
            return
        c_poly, zkp = pickle.loads(vote_payload)

        if not self.verify_zkp(c_poly.coeffs[0], zkp):
            logging.warning(f"Ignoring vote from voter {member_id} due to zkp failure")
            return

        self.votes[member_id] = (c_poly, zkp, sig)

    def verify_subtally(self, member_id: int, s_i: int, t_i: int):
        commitment = (pow(G, s_i, P) * pow(H, t_i, P)) % P

        expected_commitment = 1
        for poly, _, _ in self.votes.values():
            expected_commitment = (expected_commitment * poly.eval(member_id)) % P

        if commitment == expected_commitment:
            self.verified_subtallies.append((member_id, s_i))
        else:
            logging.warning(f"Ignoring subtally from voter {member_id}")

    def decrypt_final_vote(self):
        if len(self.verified_subtallies) < self.required_shares:
            logging.error(f"Failed to execute threshold decryption! Only collected {len(self.verified_subtallies)} out of {self.required_shares} shares")
            return
        packed_tally = lagrange_interpolate(self.verified_subtallies[:self.required_shares], Q)

        bit_mask = (1 << self.bits_per_option) - 1 
        for i in range(self.__options):
            option_num = i + 1
            shift_amount = i * self.bits_per_option
            votes = (packed_tally >> shift_amount) & bit_mask
            print(f"Option {option_num} Votes: {votes}")

    # Encrypts a message for `member_id`
    def encrypt(self, plaintext: bytes, member_id: int) -> bytes:
        return self.members[member_id].public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(HASH),
                algorithm=HASH,
                label=None
            )
        )

    # Verifies that `msg` was sent by `member_id`
    def verify_sig(self, member_id: int, msg: bytes, sig: bytes) -> bool:
        try:
            self.members[member_id].public_key.verify(
                sig,
                msg,
                padding.PSS(
                    mgf=padding.MGF1(HASH),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                HASH
            )
            return True
        except InvalidSignature:
            return False

    def verify_zkp(self, C: int, proof: Tuple[Dict, Dict]) -> bool:
        c, z = proof
        try:
            A_rebuilt = {}
            for x in self.allowed_votes:
                G_pow_x_inv = pow(pow(G, x, P), -1, P)
                A_rebuilt[x] = (pow(H, z[x], P) * pow((C * G_pow_x_inv) % P, Q-c[x], P)) % P
            
            hash_input = f"{C}:" + ":".join(str(A_rebuilt[x]) for x in self.allowed_votes)
            expected_e = hash(hash_input.encode("utf-8")) % Q
            return (sum(c.values()) % Q) == expected_e
        except ValueError: return False
        
        

class GroupMember:
    def __init__(self, id: int, board: PublicBulletin):
        if id == 0:
            raise ValueError("Must not use 0 as an id")

        self.id = id

        self.__private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.__private_key.public_key()

        self._b = board
        self._b.register(self.id, self)

        self.__r = SystemRandom()

        self.s_tally = 0
        self.t_tally = 0

    def cast_vote(self, option: int):
        packed_vote = 1 << (self._b.bits_per_option * (option - 1))
        # packed_vote = self._b.allowed_votes[option - 1]
        
        degree = self._b.required_shares - 1
        f = AdditivePoly([packed_vote] + [self.__r.randrange(1, Q) for _ in range(degree)])
        r = AdditivePoly([self.__r.randrange(1, Q) for _ in range(degree + 1)])
        c_poly = pow(G, f) * pow(H, r)
        assert(c_poly.coeffs[0] == (pow(G, f.coeffs[0], P) * pow(H, r.coeffs[0], P)) % P)
        zkp_proof = self._generate_zkp(packed_vote, r.coeffs[0], c_poly.coeffs[0])

        encoded_vote = pickle.dumps((c_poly, zkp_proof), protocol=5)
        sig = self.__sign(encoded_vote)
        self._b.submit_vote(self.id, encoded_vote, sig)
        
        for j, m in self._b.members.items():
            s_j = f.eval(j)
            t_j = r.eval(j)

            if j == self.id:
                self.s_tally = (self.s_tally + s_j) % Q
                self.t_tally = (self.t_tally + t_j) % Q
            else:
                raw_bytes = pickle.dumps((s_j, t_j), protocol=5)
                encrypted = self._b.encrypt(raw_bytes, j)
                sig = self.__sign(encrypted)

                m.receive_private_share(self.id, encrypted, sig)

    def submit_subtally(self):
        self._b.verify_subtally(self.id, self.s_tally, self.t_tally)

    def _generate_zkp(self, v: int, r: int, C: int) -> Dict:
        z, c, A = {}, {}, {}
        if v not in self._b.allowed_votes: return ({x: 1 for x in self._b.allowed_votes}, {x: 1 for x in self._b.allowed_votes})

        for x in self._b.allowed_votes:
            if x == v: continue
            z[x], c[x] = self.__r.randrange(1, Q), self.__r.randrange(1, Q)
            G_pow_x_inv = pow(pow(G, x, P), -1, P)
            A[x] = (pow(H, z[x], P) * pow((C * G_pow_x_inv) % P, -c[x], P)) % P

        w = self.__r.randrange(1, Q)
        A[v] = pow(H, w, P)
        hash_input = f"{C}:" + ":".join(str(A[x]) for x in self._b.allowed_votes)
        e = hash(hash_input.encode("utf-8")) % Q
        sum_fake_c = sum(c[x] for x in self._b.allowed_votes if x != v) % Q
        c[v] = (e - sum_fake_c) % Q
        z[v] = (w + ((c[v] * r) % Q)) % Q

        return (c, z)
    
    def receive_private_share(self, from_id: int, ciphertext: bytes, sig: bytes):
        if not self._b.verify_sig(from_id, ciphertext, sig):
            # Ignore message with invalid signature
            logging.warning(f"Ignoring private share from voter {from_id} due to signature mismatch")
            return
        plaintext = self.__decrypt(ciphertext)
        s_i, t_i = pickle.loads(plaintext)

        # For now we trust that the server has verified submitted vote commitments correctly. In practice we should re-check this
        if from_id not in self._b.votes:
            logging.warning(f"Ignoring private share from voter {from_id} due to zkp or signature mismatch")
            return

        if (pow(G, s_i, P) * pow(H, t_i, P)) % P != self._b.votes[from_id][0].eval(self.id):
            logging.warning(f"Ignoring private share from voter {from_id} due to commitment mismatch")
            return

        self.s_tally = (self.s_tally + s_i) % Q
        self.t_tally = (self.t_tally + t_i) % Q

    def __decrypt(self, ciphertext: bytes) -> bytes:
        return self.__private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(HASH),
                algorithm=HASH,
                label=None
            )
        )

    def __sign(self, msg: bytes) -> bytes:
        return self.__private_key.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(HASH),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            HASH
        )

board = PublicBulletin(.8, 2)
alice, bob, charlie, david, eve = (voters := [GroupMember(i + 1, board) for i in range(5)])

alice.cast_vote(1)
bob.cast_vote(2)
charlie.cast_vote(1)
david.cast_vote(1)
eve.cast_vote(3)

for voter in voters:
    voter.submit_subtally()

board.decrypt_final_vote()

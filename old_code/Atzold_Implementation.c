#include <stdio.h>

#define P 3
#define T 2
#define MOD 83   // A safe prime (p)
#define Q 41     // The prime order of the subgroup (q)
#define G 4      // Generator for the subgroup of order Q

// ---------------- EXPONENT (SUBGROUP) ARITHMETIC ----------------
// Secret shares and Lagrange coefficients operate modulo Q
int mod_q(int x) {
    int r = x % Q;
    return (r < 0) ? r + Q : r;
}

int modmul_q(int a, int b) { return mod_q(a * b); }
int modadd_q(int a, int b) { return mod_q(a + b); }

int modinv_q(int a) {
    a = mod_q(a);
    for (int i = 1; i < Q; i++) {
        if (modmul_q(a, i) == 1) return i;
    }
    return -1;
}

// ---------------- CIPHERTEXT ARITHMETIC ----------------
// Ciphertexts operate modulo MOD
int mod(int x) {
    int r = x % MOD;
    return (r < 0) ? r + MOD : r;
}

int modmul(int a, int b) { return mod(a * b); }
int modadd(int a, int b) { return mod(a + b); }

int modinv(int a) {
    a = mod(a);
    for (int i = 1; i < MOD; i++) {
        if (modmul(a, i) == 1) return i;
    }
    return -1;
}

int modexp(int base, int exp) {
    int result = 1;
    base = mod(base);
    
    // Handle negative exponents via modular inverse
    if (exp < 0) {
        base = modinv(base);
        exp = -exp;
    }
    
    while (exp > 0) {
        if (exp & 1)
            result = modmul(result, base);
        base = modmul(base, base);
        exp >>= 1;
    }
    return result;
}

// ---------------- STRUCTS ----------------
typedef struct {
    int a0;
    int a1;
} Poly;

typedef struct {
    int sk_share;
    int id;
} Node;

typedef struct {
    int c1;
    int c2;
} Cipher;

// ---------------- DKG ----------------
int dkg(Node nodes[P]) {
    Poly polys[P] = {
        {10, 3},
        {7, 2},
        {4, 6}
    };

    printf("\n=== DKG ===\n");

    int pk = 1;

    for (int j = 0; j < P; j++) {
        int pk_i = modexp(G, polys[j].a0);
        pk = modmul(pk, pk_i);
    }

    printf("Public Key pk = %d\n", pk);

    for (int i = 0; i < P; i++) {
        int sum = 0;

        for (int j = 0; j < P; j++) {
            // Secret shares are exponents, so they are calculated modulo Q
            int term = modadd_q(polys[j].a0, modmul_q(polys[j].a1, i + 1));
            sum = modadd_q(sum, term);
        }

        nodes[i].sk_share = sum;
        nodes[i].id = i + 1;

        printf("Node %d share = %d\n", i+1, sum);
    }

    return pk;
}

// ---------------- ENCRYPT ----------------
Cipher encrypt(int m, int pk, int r) {
    Cipher c;
    c.c1 = modexp(G, r);
    c.c2 = modmul(modexp(G, m), modexp(pk, r));
    return c;
}

// ---------------- AGGREGATION ----------------
Cipher aggregate(Cipher c[]) {
    Cipher C = {1, 1};
    for (int i = 0; i < P; i++) {
        C.c1 = modmul(C.c1, c[i].c1);
        C.c2 = modmul(C.c2, c[i].c2);
    }
    return C;
}

// ---------------- PARTIAL DECRYPT ----------------
int partial_decrypt(Cipher C, Node n) {
    return modexp(C.c1, n.sk_share);
}

// ---------------- COMBINE (LAGRANGE INTERPOLATION) ----------------
int combine(int parts[], int ids[], int k) {
    int result = 1;

    for (int i = 0; i < k; i++) {
        int num = 1;
        int den = 1;

        // Calculate Lagrange basis polynomial lambda_i modulo Q
        for (int j = 0; j < k; j++) {
            if (i == j) continue;
            num = modmul_q(num, mod_q(-ids[j]));
            den = modmul_q(den, mod_q(ids[i] - ids[j]));
        }
        
        int lambda = modmul_q(num, modinv_q(den));

        // Raise the partial decryption to the lambda coefficient
        int part_pow = modexp(parts[i], lambda);
        result = modmul(result, part_pow);
    }

    return result;
}

// ---------------- SAFE DECODING (NO DISCRETE LOG) ----------------
int decode_tally(int value) {
    int table[10];
    for (int i = 0; i <= P; i++) {
        table[i] = modexp(G, i);
        if (table[i] == value)
            return i;
    }
    return -1;
}

// ---------------- MAIN ----------------
int main() {
    Node nodes[P];
    int pk = dkg(nodes);

    int votes[P] = {1, 0, 1};
    Cipher c[P];

    printf("\n=== ENCRYPTION ===\n");
    for (int i = 0; i < P; i++) {
        c[i] = encrypt(votes[i], pk, i + 2);
        printf("Vote %d encrypted\n", i);
    }

    Cipher C = aggregate(c);

    printf("\n=== AGGREGATED ===\n");
    printf("C1=%d C2=%d\n", C.c1, C.c2);

    printf("\n=== THRESHOLD DECRYPTION ===\n");
    
    // We must track the Node IDs to compute Lagrange coefficients
    int ids[T] = {nodes[0].id, nodes[1].id};
    int parts[T];

    for (int i = 0; i < T; i++) {
        parts[i] = partial_decrypt(C, nodes[i]);
    }

    // Pass the IDs alongside the parts
    int D = combine(parts, ids, T);

    int M = modmul(C.c2, modinv(D));

    printf("Recovered group element M = %d\n", M);

    int tally = decode_tally(M);

    printf("\nFINAL VOTE TALLY = %d\n", tally);

    return 0;
}

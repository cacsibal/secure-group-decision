#include <stdio.h>

#define N 97          // toy modulus
#define T 2           // threshold
#define P 3           // number of participants

// -----------------------------
// simple modular arithmetic
// -----------------------------
int mod(int x) {
    int r = x % N;
    return (r < 0) ? r + N : r;
}

int modmul(int a, int b) {
    return mod(a * b);
}

int modadd(int a, int b) {
    return mod(a + b);
}

// -----------------------------
// STRUCTS
// -----------------------------
typedef struct {
    int a0; // constant term
    int a1; // slope
} Poly;

// each participant's share
typedef struct {
    int sk_share;
} Node;

// -----------------------------
// DKG: each participant creates polynomial
// -----------------------------
void generate_poly(Poly *p, int a0, int a1) {
    p->a0 = a0;
    p->a1 = a1;
}

// evaluate polynomial at x
int eval_poly(Poly p, int x) {
    return modadd(p.a0, modmul(p.a1, x));
}

// -----------------------------
// DKG SHARE DISTRIBUTION
// -----------------------------
void dkg_generate(Node nodes[P]) {

    Poly polys[P];

    // Each node picks secret polynomial
    generate_poly(&polys[0], 10, 3); // Alice
    generate_poly(&polys[1], 7,  2); // Bob
    generate_poly(&polys[2], 4,  6); // Carol

    // Each node receives sum of evaluations
    for (int i = 0; i < P; i++) {
        int sum = 0;

        for (int j = 0; j < P; j++) {
            sum = modadd(sum, eval_poly(polys[j], i + 1));
        }

        nodes[i].sk_share = sum;
    }
}

// -----------------------------
// ENCRYPTION (toy homomorphic)
// c = v + r (mod N)
// -----------------------------
int encrypt(int v, int r) {
    return modadd(v, r);
}

// -----------------------------
// HOMOMORPHIC AGGREGATION
// -----------------------------
int aggregate(int c[], int n) {
    int sum = 0;

    for (int i = 0; i < n; i++) {
        sum = modadd(sum, c[i]);
    }

    return sum;
}

// -----------------------------
// THRESHOLD DECRYPTION (toy)
// each node contributes sk_share
// -----------------------------
int partial_decrypt(int C, int sk_share) {
    return modmul(C, sk_share);
}

// combine shares
int combine(int d1, int d2) {
    return modadd(d1, d2);
}

// -----------------------------
// MAIN DEMO
// -----------------------------
int main() {

    Node nodes[P];

    printf("=== DKG Phase ===\n");
    dkg_generate(nodes);

    for (int i = 0; i < P; i++) {
        printf("Node %d secret share: %d\n", i, nodes[i].sk_share);
    }

    printf("\n=== Voting Phase ===\n");

    int votes[P] = {1, 0, 1};
    int c[P];

    for (int i = 0; i < P; i++) {
        c[i] = encrypt(votes[i], 5); // r=5 fixed for simplicity
        printf("Encrypted vote %d: %d\n", i, c[i]);
    }

    printf("\n=== Aggregation Phase ===\n");
    int C = aggregate(c, P);
    printf("Aggregated ciphertext C: %d\n", C);

    printf("\n=== Threshold Decryption Phase ===\n");

    int dA = partial_decrypt(C, nodes[0].sk_share);
    int dB = partial_decrypt(C, nodes[1].sk_share);

    printf("Partial A: %d\n", dA);
    printf("Partial B: %d\n", dB);

    int result = combine(dA, dB);

    printf("\n=== Final Result ===\n");
    printf("Decrypted (toy) value: %d\n", result);

    return 0;
}
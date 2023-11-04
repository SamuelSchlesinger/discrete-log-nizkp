# NIZKP for Discrete Logarithms

## Interactive Proof

To prove that B = A^x (mod p),

1. Prover chooses a random number 0 <= r < p - 1 and sends the verifier h = A^r (mod p).
2. Verifier sends back a random bit b.
3. Prover sends s = (r + bx) (mod (p - 1)).
4. Verifier computes A^s (mod p) which should equal hB^b (mod p).

## Non-Interactive Version

The non-interactive version will choose M random numbers Rs, then compute Hs
via H[i] = A^R\[i\] (mod p). Then, they will hash the Hs to produce a seed to
randomly generate the Bs bits. Then the prover computes S[i] = (R[i] + B[i] *
x) (mod (p - 1)), and the proof consists of:

A, B, p, Hs, Ss.

The verifier checks that for all i, A^S\[i\] (mod p) = hB^B\[i\] (mod p).

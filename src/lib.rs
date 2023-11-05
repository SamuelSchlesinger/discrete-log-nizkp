//! # Non-Interactive Proofs of Discrete Logarithm
//!
//! and an accompanying signature scheme.
//!
//! NB: THIS IS NOT SECURE. This is merely an academic exercise at the moment.
//! The numbers are too small of width, the parameters aren't right, there are almost certainly timing attacks due to the conditionals.

use mod_exp::mod_exp;

use rand::{distributions::Standard, rngs::OsRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// A zero-knowledge proof that there exists x such that b = a^x (mod p).
pub struct DiscreteLogPf {
    /// Prime number
    p: u128,
    /// Number between 0 and p - 1
    a: u128,
    /// Number between 0 and p - 1
    b: u128,
    /// Arbitrary 32 byte nonce
    nonce: [u8; 32],
    /// Some fun values :)
    hs: Box<[u128]>,
    /// Some more fun values :)
    ss: Box<[u128]>,
}
// TODO ^ store hs, ss as Box<[(u128, u128)]> so there is no incosistent case where len()
// differs

impl DiscreteLogPf {
    /// Prove that a^x = b (mod p) such that the verifier can be sure with probability 1/2^m.
    pub fn prove(a: u128, b: u128, p: u128, x: u128, nonce: [u8; 32], m: usize) -> Self {
        let mut rng = OsRng;
        let rs: Box<[u128]> = (0..m).map(|_| rng.gen_range(0..p - 1)).collect();
        let hs: Box<[u128]> = (0..m).map(|i| mod_exp(a, rs[i], p)).collect();
        let ctx: Vec<u8> = bincode::serialize(&(&a, &b, &p, &hs, &nonce)).expect("ok");
        let seed: [u8; 32] = blake3::hash(&ctx).as_bytes().to_owned();
        let mut public_coin_rng = ChaCha20Rng::from_seed(seed);
        let bools: Box<[bool]> = (0..m).map(|_| public_coin_rng.sample(Standard)).collect();
        let ss: Box<[u128]> = (0..m)
            .map(|i| (rs[i] + if bools[i] { x } else { 0 }) % (p - 1))
            .collect();

        DiscreteLogPf {
            p,
            a,
            b,
            hs,
            ss,
            nonce,
        }
    }

    /// Verify that there exists x such that a^x = b (mod p) with whatever probability of error.
    pub fn verify(&self) -> bool {
        if self.hs.len() != self.ss.len() {
            return false;
        }
        let m = self.hs.len();
        let ctx =
            bincode::serialize(&(&self.a, &self.b, &self.p, &self.hs, &self.nonce)).expect("ok");
        let seed: [u8; 32] = blake3::hash(&ctx).as_bytes().to_owned();
        let mut public_coin_rng = ChaCha20Rng::from_seed(seed);
        let bools: Box<[bool]> = (0..m).map(|_| public_coin_rng.sample(Standard)).collect();

        (0..m).all(|i| {
            mod_exp(self.a, self.ss[i], self.p)
                == ((self.hs[i] * mod_exp(self.b, if bools[i] { 1 } else { 0 }, self.p)) % self.p)
        })
    }

    pub fn security(&self) -> usize {
        self.hs.len()
    }
}

#[test]
fn test_signature_scheme() {
    let p = 569873509u128;
    let a = rand::random::<u128>() % p;
    let x: u128 = rand::random::<u128>() % p;
    let b = mod_exp(a, x, p);
    let pubkey = PublicKey { p, a, b };
    let private_key = PrivateKey { pubkey, x };
    let signature = private_key.sign(b"uhh hello?", 32);
    assert!(signature.verify(b"uhh hello?"))
}

/// Public identity for an individual. Totally safe to reveal.
pub struct PublicKey {
    a: u128,
    b: u128,
    p: u128,
}

/// Secret identity for an individual. Not safe to reveal.
pub struct PrivateKey {
    pubkey: PublicKey,
    x: u128,
}

impl PrivateKey {
    pub fn sign(&self, content: &[u8], security_level: usize) -> Signature {
        let nonce = blake3::hash(content).as_bytes().to_owned();
        Signature {
            pf: DiscreteLogPf::prove(
                self.pubkey.a,
                self.pubkey.b,
                self.pubkey.p,
                self.x,
                nonce,
                security_level,
            ),
        }
    }
}

/// Signature containing a proof of knowledge of discrete log.
pub struct Signature {
    pf: DiscreteLogPf,
}

impl Signature {
    /// Verify the signature.
    pub fn verify(&self, content: &[u8]) -> bool {
        blake3::hash(content) == self.pf.nonce && self.pf.verify()
    }

    /// Compute a natural number n such that the probability of the prover, in one go, being able to construct
    /// a verifying but false proof is 1/2^n.
    pub fn security(&self) -> usize {
        self.pf.hs.len()
    }
}

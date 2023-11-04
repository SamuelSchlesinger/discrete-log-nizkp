use mod_exp::mod_exp;

use rand::{distributions::Standard, rngs::OsRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub struct DiscreteLogPf {
    p: u128,
    a: u128,
    b: u128,
    nonce: [u8; 32],
    hs: Box<[u128]>,
    ss: Box<[u128]>,
}

impl DiscreteLogPf {
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

pub struct PublicKey {
    a: u128,
    b: u128,
    p: u128,
}

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

pub struct Signature {
    pf: DiscreteLogPf,
}

impl Signature {
    pub fn verify(&self, content: &[u8]) -> bool {
        blake3::hash(content) == self.pf.nonce && self.pf.verify()
    }
}

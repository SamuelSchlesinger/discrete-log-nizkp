use mod_exp::mod_exp;

use rand::{distributions::Standard, rngs::OsRng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub struct DiscreteLogPf {
    p: u128,
    a: u128,
    b: u128,
    hs: Box<[u128]>,
    ss: Box<[u128]>,
}

impl DiscreteLogPf {
    pub fn prove(a: u128, b: u128, p: u128, x: u128, m: usize) -> Self {
        let mut rng = OsRng;
        let rs: Box<[u128]> = (0..m).map(|_| rng.gen_range(0..p - 1)).collect();
        let hs: Box<[u128]> = (0..m).map(|i| mod_exp(a, rs[i], p)).collect();
        let ctx: Vec<u8> = bincode::serialize(&(&a, &b, &p, &hs)).expect("ok");
        let seed: [u8; 32] = blake3::hash(&ctx).as_bytes().to_owned();
        let mut public_coin_rng = ChaCha20Rng::from_seed(seed);
        let bools: Box<[bool]> = (0..m).map(|_| public_coin_rng.sample(Standard)).collect();
        let ss: Box<[u128]> = (0..m)
            .map(|i| (rs[i] + if bools[i] { x } else { 0 }) % (p - 1))
            .collect();

        DiscreteLogPf { p, a, b, hs, ss }
    }

    pub fn verify(&self) -> bool {
        if self.hs.len() != self.ss.len() {
            return false;
        }
        let m = self.hs.len();
        let ctx = bincode::serialize(&(&self.a, &self.b, &self.p, &self.hs)).expect("ok");
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
fn test() {
    let p = 569873509u128;
    let a = rand::random::<u128>() % p;
    let x: u128 = rand::random::<u128>() % p;
    let b = mod_exp(a, x, p);
    let pf = DiscreteLogPf::prove(a, b, p, x, 32);
    assert!(pf.verify())
}

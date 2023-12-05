use rand::{distributions::Standard, prelude::Distribution, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

pub type PrfSeed = [u8; 32];

pub struct Prf {
    prf_1: ChaCha12Rng,
    prf_2: ChaCha12Rng,
    prf_p: ChaCha12Rng,
}

impl Default for Prf {
    fn default() -> Self {
        Self {
            prf_1: ChaCha12Rng::from_entropy(),
            prf_2: ChaCha12Rng::from_entropy(),
            prf_p: ChaCha12Rng::from_entropy(),
        }
    }
}

impl Prf {
    pub fn new(prf_1: PrfSeed, prf_2: PrfSeed, prf_p: PrfSeed) -> Self {
        Self {
            prf_1: ChaCha12Rng::from_seed(prf_1),
            prf_2: ChaCha12Rng::from_seed(prf_2),
            prf_p: ChaCha12Rng::from_seed(prf_p),
        }
    }

    pub fn gen_seed() -> PrfSeed {
        let mut rng = ChaCha12Rng::from_entropy();
        rng.gen::<PrfSeed>()
    }

    pub fn gen_1<T>(&mut self) -> T
    where
        Standard: Distribution<T>,
    {
        self.prf_1.gen::<T>()
    }

    pub fn gen_2<T>(&mut self) -> T
    where
        Standard: Distribution<T>,
    {
        self.prf_2.gen::<T>()
    }

    pub fn gen_p<T>(&mut self) -> T
    where
        Standard: Distribution<T>,
    {
        self.prf_p.gen::<T>()
    }
}

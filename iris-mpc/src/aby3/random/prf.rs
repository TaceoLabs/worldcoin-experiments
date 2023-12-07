use crate::types::sharable::Sharable;
use rand::{distributions::Standard, prelude::Distribution, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

pub type PrfSeed = [u8; 32];

pub struct Prf {
    my_prf: ChaCha12Rng,
    next_prf: ChaCha12Rng,
}

impl Default for Prf {
    fn default() -> Self {
        Self {
            my_prf: ChaCha12Rng::from_entropy(),
            next_prf: ChaCha12Rng::from_entropy(),
        }
    }
}

impl Prf {
    pub fn new(my_key: PrfSeed, next_key: PrfSeed) -> Self {
        Self {
            my_prf: ChaCha12Rng::from_seed(my_key),
            next_prf: ChaCha12Rng::from_seed(next_key),
        }
    }

    pub fn gen_seed() -> PrfSeed {
        let mut rng = ChaCha12Rng::from_entropy();
        rng.gen::<PrfSeed>()
    }

    pub(crate) fn gen_rands<T>(&mut self) -> (T, T)
    where
        Standard: Distribution<T>,
    {
        let a = self.my_prf.gen::<T>();
        let b = self.next_prf.gen::<T>();
        (a, b)
    }

    pub(crate) fn gen_zero_share<T: Sharable>(&mut self) -> T::Share
    where
        Standard: Distribution<T::Share>,
    {
        let (a, b) = self.gen_rands::<T::Share>();
        a - b
    }

    pub(crate) fn gen_binary_zero_share<T: Sharable>(&mut self) -> T::Share
    where
        Standard: Distribution<T::Share>,
    {
        let (a, b) = self.gen_rands::<T::Share>();
        a ^ b
    }
}

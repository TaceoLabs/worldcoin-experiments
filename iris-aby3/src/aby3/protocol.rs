use super::random::prf::{Prf, PrfSeed};
use super::utils;
use crate::aby3::share::Share;
use crate::error::Error;
use crate::traits::mpc_trait::MpcTrait;
use crate::traits::network_trait::NetworkTrait;
use crate::types::ring_element::RingImpl;
use crate::types::sharable::Sharable;
use bytes::Bytes;
use rand::distributions::{Distribution, Standard};

pub struct Aby3<N: NetworkTrait> {
    network: N,
    prf: Prf,
}

impl<N: NetworkTrait> Aby3<N> {
    pub fn new(network: N) -> Self {
        let prf = Prf::default();

        Self { network, prf }
    }

    async fn setup_prf(&mut self) -> Result<(), Error> {
        let seed = Prf::gen_seed();
        self.setup_prf_from_seed(seed).await
    }

    async fn setup_prf_from_seed(&mut self, seed: PrfSeed) -> Result<(), Error> {
        let data = Bytes::from_iter(seed.into_iter());
        let response = utils::send_and_receive(&mut self.network, data).await?;
        let their_seed = utils::bytes_to_seed(response)?;
        self.prf = Prf::new(seed, their_seed);
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        self.network.shutdown().await?;
        Ok(())
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<Share<T>, Share<T>> for Aby3<N>
where
    Standard: Distribution<T::Share>,
{
    async fn preprocess(&mut self) -> Result<(), Error> {
        self.setup_prf().await
    }

    fn add(a: Share<T>, b: Share<T>) -> Share<T> {
        a + b
    }

    async fn mul(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        let (rand_a, rand_b) = self.prf.gen_rands::<T::Share>();
        let mut c = a * b;
        c.a += rand_a - rand_b;

        // Network
        let response =
            utils::send_and_receive(&mut self.network, c.a.to_owned().to_bytes()).await?;
        c.b = T::Share::from_bytes_mut(response)?;

        Ok(c)
    }
}

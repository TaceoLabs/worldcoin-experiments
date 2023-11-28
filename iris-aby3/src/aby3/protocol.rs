use super::random::prf::{Prf, PrfSeed};
use super::utils;
use crate::aby3::share::Share;
use crate::error::Error;
use crate::traits::mpc_trait::MpcTrait;
use crate::traits::network_trait::NetworkTrait;
use crate::types::ring_element::RingImpl;
use crate::types::ring_element::{ring_vec_from_bytes, ring_vec_to_bytes};
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
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, Share<T>, Share<T>> for Aby3<N>
where
    Standard: Distribution<T::Share>,
{
    async fn finish(mut self) -> Result<(), Error> {
        self.network.shutdown().await?;
        Ok(())
    }

    async fn preprocess(&mut self) -> Result<(), Error> {
        self.setup_prf().await
    }

    async fn input_all(&mut self, input: T) -> Result<Vec<Share<T>>, Error> {
        let mut shares_a = Vec::with_capacity(3);
        for i in 0..3 {
            let mut share = self.prf.gen_zero_share::<T>();

            if i == self.network.get_id() {
                share += input.to_sharetype();
            }

            shares_a.push(share);
        }

        // Network: reshare
        let response =
            utils::send_and_receive(&mut self.network, ring_vec_to_bytes(shares_a.to_owned()))
                .await?;
        let shares_b = ring_vec_from_bytes(response, 3)?;

        let mut shares = Vec::with_capacity(3);
        for (share_a, share_b) in shares_a.into_iter().zip(shares_b.into_iter()) {
            shares.push(Share::new(share_a, share_b));
        }

        Ok(shares)
    }

    async fn open(&mut self, share: Share<T>) -> Result<T, Error> {
        let response =
            utils::send_and_receive(&mut self.network, share.b.to_owned().to_bytes()).await?;
        let c = T::Share::from_bytes_mut(response)?;
        Ok(T::from_sharetype(share.a + share.b + c))
    }

    async fn open_many(&mut self, shares: &[Share<T>]) -> Result<Vec<T>, Error> {
        let shares_b = shares.iter().map(|s| s.b.to_owned()).collect();
        let response =
            utils::send_and_receive(&mut self.network, ring_vec_to_bytes(shares_b)).await?;

        let shares_c: Vec<T::Share> = ring_vec_from_bytes(response, 3)?;
        let res: Vec<T> = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| T::from_sharetype(c + &s.a + &s.b))
            .collect();
        Ok(res)
    }

    fn add(a: Share<T>, b: Share<T>) -> Share<T> {
        a + b
    }

    async fn mul(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        let rand = self.prf.gen_zero_share::<T>();
        let mut c = a * b;
        c.a += rand;

        // Network: reshare
        let response =
            utils::send_and_receive(&mut self.network, c.a.to_owned().to_bytes()).await?;
        c.b = T::Share::from_bytes_mut(response)?;

        Ok(c)
    }
}

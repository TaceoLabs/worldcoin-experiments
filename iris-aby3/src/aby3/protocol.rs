use super::binary_trait::BinaryMpcTrait;
use super::random::prf::{Prf, PrfSeed};
use super::utils;
use crate::aby3::share::Share;
use crate::error::Error;
use crate::traits::mpc_trait::MpcTrait;
use crate::traits::network_trait::NetworkTrait;
use crate::traits::security::SemiHonest;
use crate::types::bit::Bit;
use crate::types::ring_element::RingImpl;
use crate::types::ring_element::{ring_vec_from_bytes, ring_vec_to_bytes};
use crate::types::sharable::Sharable;
use async_trait::async_trait;
use bytes::Bytes;
use num_traits::Zero;
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use std::ops::Mul;

pub struct Aby3<N: NetworkTrait> {
    network: N,
    prf: Prf,
}

impl<N: NetworkTrait> SemiHonest for Aby3<N> {}

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

    pub async fn finish(self) -> Result<(), Error> {
        self.network.shutdown().await?;
        Ok(())
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, Share<T>, Share<Bit>> for Aby3<N>
where
    Standard: Distribution<T::Share>,
    Share<T>: Mul<Output = Share<T>>,
    Share<T>: Mul<T::Share, Output = Share<T>>,
    Aby3<N>: BinaryMpcTrait<T>,
{
    fn get_id(&self) -> usize {
        self.network.get_id()
    }

    async fn finish(self) -> Result<(), Error> {
        self.network.shutdown().await?;
        Ok(())
    }

    async fn preprocess(&mut self) -> Result<(), Error> {
        self.setup_prf().await
    }

    async fn input(&mut self, input: Option<T>, id: usize) -> Result<Share<T>, Error> {
        if id >= self.network.get_num_parties() {
            return Err(Error::IdError(id));
        }

        let mut share_a = self.prf.gen_zero_share::<T>();
        if id == self.network.get_id() {
            let value = match input {
                Some(x) => x.to_sharetype(),
                None => return Err(Error::ValueError("Cannot share None".to_string())),
            };
            share_a += value;
        }

        // Network: reshare
        let response =
            utils::send_and_receive(&mut self.network, share_a.to_owned().to_bytes()).await?;
        let share_b = T::Share::from_bytes_mut(response)?;

        Ok(Share::new(share_a, share_b))
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

    async fn share<R: Rng>(input: T, rng: &mut R) -> Vec<Share<T>> {
        let a = rng.gen::<T::Share>();
        let b = rng.gen::<T::Share>();
        let c = input.to_sharetype() - &a - &b;

        let share1 = Share::new(a.to_owned(), c.to_owned());
        let share2 = Share::new(b.to_owned(), a);
        let share3 = Share::new(c, b);

        vec![share1, share2, share3]
    }

    async fn open(&mut self, share: Share<T>) -> Result<T, Error> {
        let response =
            utils::send_and_receive(&mut self.network, share.b.to_owned().to_bytes()).await?;
        let c = T::Share::from_bytes_mut(response)?;
        Ok(T::from_sharetype(share.a + share.b + c))
    }

    async fn open_many(&mut self, shares: Vec<Share<T>>) -> Result<Vec<T>, Error> {
        let shares_b = shares.iter().map(|s| s.b.to_owned()).collect();
        let response =
            utils::send_and_receive(&mut self.network, ring_vec_to_bytes(shares_b)).await?;

        let shares_c: Vec<T::Share> = ring_vec_from_bytes(response, shares.len())?;
        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| T::from_sharetype(c + &s.a + &s.b))
            .collect();
        Ok(res)
    }

    async fn open_bit(&mut self, share: Share<Bit>) -> Result<bool, Error> {
        let response =
            utils::send_and_receive(&mut self.network, share.b.to_owned().to_bytes()).await?;
        let c = <Bit as Sharable>::Share::from_bytes_mut(response)?;
        Ok((share.a ^ share.b ^ c).convert().convert())
    }

    fn add(&self, a: Share<T>, b: Share<T>) -> Share<T> {
        a + b
    }

    fn sub(&self, a: Share<T>, b: Share<T>) -> Share<T> {
        a - b
    }

    fn add_const(&self, a: Share<T>, b: T) -> Share<T> {
        a.add_const(
            &b.to_sharetype(),
            self.network
                .get_id()
                .try_into()
                .expect("ID is checked during establishing connection"),
        )
    }

    fn sub_const(&self, a: Share<T>, b: T) -> Share<T> {
        a.sub_const(
            &b.to_sharetype(),
            self.network
                .get_id()
                .try_into()
                .expect("ID is checked during establishing connection"),
        )
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

    fn mul_const(&self, a: Share<T>, b: T) -> Share<T> {
        a * b.to_sharetype()
    }

    async fn dot(&mut self, a: Vec<Share<T>>, b: Vec<Share<T>>) -> Result<Share<T>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvlidSizeError);
        }

        let rand = self.prf.gen_zero_share::<T>();
        let mut c = Share::new(rand, T::zero().to_sharetype());
        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            c += a_ * b_;
        }

        // Network: reshare
        let response =
            utils::send_and_receive(&mut self.network, c.a.to_owned().to_bytes()).await?;
        c.b = T::Share::from_bytes_mut(response)?;

        Ok(c)
    }

    async fn get_msb(&mut self, a: Share<T>) -> Result<Share<Bit>, Error> {
        let bits = self.arithmetic_to_binary(a).await?;
        Ok(bits.get_msb())
    }

    async fn binary_or(&mut self, a: Share<Bit>, b: Share<Bit>) -> Result<Share<Bit>, Error> {
        <Self as BinaryMpcTrait<Bit>>::or(self, a, b).await
    }
}

macro_rules! binary_mpc_trait_impl_functions {
    ($s:ty) => {
        async fn and(&mut self, a: Share<$s>, b: Share<$s>) -> Result<Share<$s>, Error> {
            let rand = self.prf.gen_binary_zero_share::<$s>();
            let mut c = a & b;
            c.a ^= rand;

            // Network: reshare
            let response =
                utils::send_and_receive(&mut self.network, c.a.to_owned().to_bytes()).await?;
            c.b = <$s as Sharable>::Share::from_bytes_mut(response)?;

            Ok(c)
        }

        async fn and_many(
            &mut self,
            a: Vec<Share<$s>>,
            b: Vec<Share<$s>>,
        ) -> Result<Vec<Share<$s>>, Error> {
            if a.len() != b.len() {
                return Err(Error::InvlidSizeError);
            }
            let mut shares_a = Vec::with_capacity(a.len());
            for (a_, b_) in a.into_iter().zip(b.into_iter()) {
                let rand = self.prf.gen_binary_zero_share::<$s>();
                let mut c = a_ & b_;
                c.a ^= rand;
                shares_a.push(c.a);
            }

            // Network: reshare
            let response =
                utils::send_and_receive(&mut self.network, ring_vec_to_bytes(shares_a.to_owned()))
                    .await?;
            let shares_b: Vec<<$s as Sharable>::Share> =
                ring_vec_from_bytes(response, shares_a.len())?;

            let res = shares_a
                .into_iter()
                .zip(shares_b.into_iter())
                .map(|(a_, b_)| Share::new(a_, b_))
                .collect();

            Ok(res)
        }

        async fn arithmetic_to_binary(&mut self, x: Share<$s>) -> Result<Share<$s>, Error> {
            let (a, b) = x.get_ab();

            let mut x1 = Share::<$s>::zero();
            let mut x2 = Share::<$s>::zero();
            let mut x3 = Share::<$s>::zero();

            match self.network.get_id() {
                0 => {
                    x1.a = a;
                    x3.b = b;
                }
                1 => {
                    x2.a = a;
                    x1.b = b;
                }
                2 => {
                    x3.a = a;
                    x2.b = b;
                }
                _ => unreachable!(),
            }

            self.binary_add_3(x1, x2, x3).await
        }
    };
}

macro_rules! binary_mpc_trait_impl {
    ($($s:ty),*) => ($(
        #[async_trait]
        impl<N: NetworkTrait> BinaryMpcTrait<$s> for Aby3<N>
        {
            binary_mpc_trait_impl_functions!{$s}
        }
    )*)
}

binary_mpc_trait_impl! {
    Bit, i8, i16, i32, i64, i128, u8, u16, u32, u64, u128
}

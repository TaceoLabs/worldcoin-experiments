use super::random::prf::{Prf, PrfSeed};
use super::utils;
use crate::aby3::share::Share;
use crate::error::Error;
use crate::iris::protocol::OR_TREE_PACK_SIZE;
use crate::traits::binary_trait::BinaryMpcTrait;
use crate::traits::mpc_trait::MpcTrait;
use crate::traits::network_trait::NetworkTrait;
use crate::traits::security::SemiHonest;
use crate::types::bit::Bit;
use crate::types::ring_element::{RingElement, RingImpl};
use crate::types::sharable::Sharable;
use bytes::Bytes;
use num_traits::Zero;
use plain_reference::IrisCodeArray;
use rand::distributions::{Distribution, Standard};
use rand::Rng;
use std::ops::Mul;

pub struct Aby3<N: NetworkTrait> {
    pub(crate) network: N,
    pub(crate) prf: Prf,
}

impl<N: NetworkTrait> SemiHonest for Aby3<N> {}

macro_rules! reduce_or {
    ($([$typ_a:ident, $typ_b:ident,$name_a:ident,$name_b:ident]),*) => {
        $(
            async fn $name_a(&mut self, a: Share<$typ_a>) -> Result<Share<Bit>, Error> {
                let (a, b) = a.get_ab();
                let (a1, a2) = utils::split::<$typ_a, $typ_b>(a);
                let (b1, b2) = utils::split::<$typ_a, $typ_b>(b);

                let share_a = Share::new(a1, b1);
                let share_b = Share::new(a2, b2);

                let out = self.or(share_a, share_b).await?;
                self.$name_b(out).await
            }
        )*
    };
}

impl<N: NetworkTrait> Aby3<N> {
    pub fn new(network: N) -> Self {
        let prf = Prf::default();

        Self { network, prf }
    }

    pub async fn fork(&mut self) -> Result<Self, Error> {
        let network = self.network.fork().await?;
        let (my_seed, next_seed) = self.prf.gen_rands();
        Ok(Self {
            network,
            prf: Prf::new(my_seed, next_seed),
        })
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

    pub(crate) fn a2b_pre<T: Sharable>(&self, x: Share<T>) -> (Share<T>, Share<T>, Share<T>) {
        let (a, b) = x.get_ab();

        let mut x1 = Share::<T>::zero();
        let mut x2 = Share::<T>::zero();
        let mut x3 = Share::<T>::zero();

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
        (x1, x2, x3)
    }

    fn pack<T: Sharable>(&self, a: Vec<Share<Bit>>) -> Vec<Share<T>> {
        let outlen = (a.len() + T::Share::K - 1) / T::Share::K;
        let mut out = Vec::with_capacity(outlen);

        for a_ in a.chunks(T::Share::K) {
            let mut share_a = T::Share::zero();
            let mut share_b = T::Share::zero();
            for (i, bit) in a_.iter().enumerate() {
                let (bit_a, bit_b) = bit.to_owned().get_ab();
                share_a |= T::Share::from(bit_a.convert().convert()) << (i as u32);
                share_b |= T::Share::from(bit_b.convert().convert()) << (i as u32);
            }
            let share = Share::new(share_a, share_b);
            out.push(share);
        }

        out
    }

    reduce_or!(
        [u128, u64, reduce_or_u128, reduce_or_u64],
        [u64, u32, reduce_or_u64, reduce_or_u32],
        [u32, u16, reduce_or_u32, reduce_or_u16],
        [u16, u8, reduce_or_u16, reduce_or_u8]
    );

    async fn reduce_or_u8(&mut self, a: Share<u8>) -> Result<Share<Bit>, Error> {
        const K: usize = 8;

        let mut decomp: Vec<Share<Bit>> = Vec::with_capacity(K);
        for i in 0..K as u32 {
            let bit_a = ((a.a.to_owned() >> i) & RingElement(1)) == RingElement(1);
            let bit_b = ((a.b.to_owned() >> i) & RingElement(1)) == RingElement(1);

            decomp.push(Share::new(
                <Bit as Sharable>::Share::from(bit_a),
                <Bit as Sharable>::Share::from(bit_b),
            ));
        }

        let mut k = K;
        while k != 1 {
            k >>= 1;
            decomp = <Self as BinaryMpcTrait<Bit, Share<Bit>>>::or_many(
                self,
                decomp[..k].to_vec(),
                decomp[k..].to_vec(),
            )
            .await?;
        }

        Ok(decomp[0].to_owned())
    }

    pub(crate) async fn mul_many<T: Sharable>(
        &mut self,
        a: Vec<Share<T>>,
        b: Vec<Share<T>>,
    ) -> Result<Vec<Share<T>>, Error>
    where
        Standard: Distribution<T::Share>,
    {
        debug_assert_eq!(a.len(), b.len());

        let mut shares_a = Vec::with_capacity(a.len());

        for (a_, b_) in a.iter().cloned().zip(b.iter().cloned()) {
            let rand = self.prf.gen_zero_share::<T>();
            let mut c = a_ * b_;
            c.a += rand;
            shares_a.push(c.a);
        }

        // Network: reshare
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned()).await?;

        let res: Vec<Share<T>> = shares_a
            .into_iter()
            .zip(shares_b.into_iter())
            .map(|(a_, b_)| Share::new(a_, b_))
            .collect();

        Ok(res)
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, Share<T>, Share<Bit>> for Aby3<N>
where
    Standard: Distribution<T::Share>,
    Share<T>: Mul<Output = Share<T>>,
    Share<T>: Mul<T::Share, Output = Share<T>>,
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

    fn set_mac_key(&mut self, _key: Share<T>) {}
    fn set_new_mac_key(&mut self) {}
    #[cfg(test)]
    async fn open_mac_key(&mut self) -> Result<T::VerificationShare, Error> {
        Ok(T::VerificationShare::default())
    }

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        Ok(self.network.print_connection_stats(out)?)
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
        let share_b = utils::send_and_receive_value(&mut self.network, share_a.to_owned()).await?;

        Ok(Share::new(share_a, share_b))
    }

    #[cfg(test)]
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
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned()).await?;

        let mut shares = Vec::with_capacity(3);
        for (share_a, share_b) in shares_a.into_iter().zip(shares_b.into_iter()) {
            shares.push(Share::new(share_a, share_b));
        }

        Ok(shares)
    }

    fn share<R: Rng>(input: T, _mac_key: T::VerificationShare, rng: &mut R) -> Vec<Share<T>> {
        let a = rng.gen::<T::Share>();
        let b = rng.gen::<T::Share>();
        let c = input.to_sharetype() - &a - &b;

        let share1 = Share::new(a.to_owned(), c.to_owned());
        let share2 = Share::new(b.to_owned(), a);
        let share3 = Share::new(c, b);

        vec![share1, share2, share3]
    }

    async fn open(&mut self, share: Share<T>) -> Result<T, Error> {
        let c = utils::send_and_receive_value(&mut self.network, share.b.to_owned()).await?;
        Ok(T::from_sharetype(share.a + share.b + c))
    }

    async fn open_many(&mut self, shares: Vec<Share<T>>) -> Result<Vec<T>, Error> {
        let shares_b = shares.iter().map(|s| s.b.to_owned()).collect();
        let shares_c = utils::send_and_receive_vec(&mut self.network, shares_b).await?;
        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| T::from_sharetype(c + &s.a + &s.b))
            .collect();
        Ok(res)
    }

    async fn open_bit(&mut self, share: Share<Bit>) -> Result<bool, Error> {
        let c = utils::send_and_receive_value(&mut self.network, share.b.to_owned()).await?;
        Ok((share.a ^ share.b ^ c).convert().convert())
    }

    async fn open_bit_many(&mut self, shares: Vec<Share<Bit>>) -> Result<Vec<bool>, Error> {
        let shares_b = shares.iter().map(|s| s.b.to_owned()).collect();
        let shares_c = utils::send_and_receive_vec(&mut self.network, shares_b).await?;
        let res = shares
            .iter()
            .zip(shares_c.into_iter())
            .map(|(s, c)| (c ^ &s.a ^ &s.b).convert().convert())
            .collect();
        Ok(res)
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
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned()).await?;

        Ok(c)
    }

    fn mul_const(&self, a: Share<T>, b: T) -> Share<T> {
        a * b.to_sharetype()
    }

    async fn dot(&mut self, a: Vec<Share<T>>, b: Vec<Share<T>>) -> Result<Share<T>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let rand = self.prf.gen_zero_share::<T>();
        let mut c = Share::new(rand, T::zero().to_sharetype());
        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            c += a_ * b_;
        }

        // Network: reshare
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned()).await?;

        Ok(c)
    }

    async fn dot_many(
        &mut self,
        a: &[Vec<Share<T>>],
        b: &[Vec<Share<T>>],
    ) -> Result<Vec<Share<T>>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut shares_a = Vec::with_capacity(a.len());

        for (a_, b_) in a.iter().zip(b.iter()) {
            let mut rand = self.prf.gen_zero_share::<T>();
            if a_.len() != b_.len() {
                return Err(Error::InvalidSizeError);
            }
            for (a__, b__) in a_.iter().zip(b_.iter()) {
                rand += (a__.clone() * b__).a; // TODO: check if we can allow ref * ref ops in RingImpl
            }
            shares_a.push(rand);
        }

        // Network: reshare
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned()).await?;

        let res = shares_a
            .into_iter()
            .zip(shares_b.into_iter())
            .map(|(a_, b_)| Share::new(a_, b_))
            .collect();

        Ok(res)
    }

    async fn masked_dot_many(
        &mut self,
        a: &[Share<T>],
        b: &[Vec<Share<T>>],
        masks: &[IrisCodeArray],
    ) -> Result<Vec<Share<T>>, Error> {
        let mut shares_a = Vec::with_capacity(a.len());

        for (b_, mask_) in b.iter().zip(masks.iter()) {
            let mut rand = self.prf.gen_zero_share::<T>();
            if a.len() != b_.len() || a.len() != IrisCodeArray::IRIS_CODE_SIZE {
                return Err(Error::InvalidSizeError);
            }
            for (i, (a__, b__)) in a.iter().zip(b_.iter()).enumerate() {
                // only aggregate if mask is set
                if mask_.get_bit(i) {
                    rand += (a__.clone() * b__).a; // TODO: check if we can allow ref * ref ops in RingImpl
                }
            }
            shares_a.push(rand);
        }

        // Network: reshare
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned()).await?;

        let res = shares_a
            .into_iter()
            .zip(shares_b.into_iter())
            .map(|(a_, b_)| Share::new(a_, b_))
            .collect();

        Ok(res)
    }

    async fn get_msb(&mut self, a: Share<T>) -> Result<Share<Bit>, Error> {
        let bits = self.arithmetic_to_binary(a).await?;
        Ok(bits.get_msb())
    }

    async fn get_msb_many(&mut self, a: Vec<Share<T>>) -> Result<Vec<Share<Bit>>, Error> {
        let bits = self.arithmetic_to_binary_many(a).await?;
        let res = bits.into_iter().map(|a| a.get_msb()).collect();
        Ok(res)
    }

    async fn binary_or(&mut self, a: Share<Bit>, b: Share<Bit>) -> Result<Share<Bit>, Error> {
        <Self as BinaryMpcTrait<Bit, Share<Bit>>>::or(self, a, b).await
    }

    async fn reduce_binary_or(&mut self, a: Vec<Share<Bit>>) -> Result<Share<Bit>, Error> {
        let packed = self.pack(a);
        let reduced = utils::or_tree::<u128, _, _, OR_TREE_PACK_SIZE>(self, packed).await?;
        self.reduce_or_u128(reduced).await
    }

    async fn verify(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl<N: NetworkTrait, T: Sharable> BinaryMpcTrait<T, Share<T>> for Aby3<N>
where
    Standard: Distribution<T::Share>,
{
    async fn and(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error> {
        let rand = self.prf.gen_binary_zero_share::<T>();
        let mut c = a & b;
        c.a ^= rand;

        // Network: reshare
        c.b = utils::send_and_receive_value(&mut self.network, c.a.to_owned()).await?;

        Ok(c)
    }

    async fn and_many(
        &mut self,
        a: Vec<Share<T>>,
        b: Vec<Share<T>>,
    ) -> Result<Vec<Share<T>>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }
        let mut shares_a = Vec::with_capacity(a.len());
        for (a_, b_) in a.into_iter().zip(b.into_iter()) {
            let rand = self.prf.gen_binary_zero_share::<T>();
            let mut c = a_ & b_;
            c.a ^= rand;
            shares_a.push(c.a);
        }

        // Network: reshare
        let shares_b = utils::send_and_receive_vec(&mut self.network, shares_a.to_owned()).await?;

        let res = shares_a
            .into_iter()
            .zip(shares_b.into_iter())
            .map(|(a_, b_)| Share::new(a_, b_))
            .collect();

        Ok(res)
    }

    async fn arithmetic_to_binary(&mut self, x: Share<T>) -> Result<Share<T>, Error> {
        let (x1, x2, x3) = self.a2b_pre(x);
        self.binary_add_3(x1, x2, x3).await
    }

    async fn arithmetic_to_binary_many(
        &mut self,
        x: Vec<Share<T>>,
    ) -> Result<Vec<Share<T>>, Error> {
        let len = x.len();
        let mut x1 = Vec::with_capacity(len);
        let mut x2 = Vec::with_capacity(len);
        let mut x3 = Vec::with_capacity(len);

        for x_ in x {
            let (x1_, x2_, x3_) = self.a2b_pre(x_);
            x1.push(x1_);
            x2.push(x2_);
            x3.push(x3_);
        }
        self.binary_add_3_many(x1, x2, x3).await
    }
}

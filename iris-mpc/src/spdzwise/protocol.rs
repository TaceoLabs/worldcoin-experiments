use super::share::Share;
use crate::prelude::{Aby3, Aby3Share, Bit, Error, MpcTrait, NetworkTrait, Sharable};
use rand::distributions::{Distribution, Standard};
use std::ops::Mul;

#[allow(type_alias_bounds)]
pub(crate) type TShare<T: Sharable> = Share<T::VerificationShare>;
pub(crate) type BitShare = Share<<Bit as Sharable>::VerificationShare>;
pub(crate) type BitShareType = <Bit as Sharable>::VerificationShare;
#[allow(type_alias_bounds)]
pub(crate) type UShare<T: Sharable> = <T::VerificationShare as Sharable>::Share;

pub struct SpdzWise<N: NetworkTrait, U: Sharable> {
    aby3: Aby3<N>,
    mac_key: Aby3Share<U>,
    verifyqueue: Vec<Share<U>>,
}

impl<N: NetworkTrait, U: Sharable> SpdzWise<N, U> {
    pub fn new(network: N) -> Self {
        let aby3 = Aby3::new(network);
        Self {
            aby3,
            mac_key: Aby3Share::default(),
            verifyqueue: Vec::new(),
        }
    }

    fn get_r(&self) -> Aby3Share<U> {
        self.mac_key.to_owned()
    }

    fn get_id(&self) -> usize {
        self.aby3.network.get_id()
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, TShare<T>, BitShare>
    for SpdzWise<N, T::VerificationShare>
where
    Standard: Distribution<UShare<T>>,
    Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
    Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
{
    fn get_id(&self) -> usize {
        self.get_id()
    }

    async fn preprocess(&mut self) -> Result<(), Error> {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::preprocess(&mut self.aby3)
        .await?;

        self.mac_key = self.aby3.prf.gen_rand::<T::VerificationShare>();

        Ok(())
    }

    async fn finish(self) -> Result<(), Error> {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::finish(self.aby3)
        .await
    }

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::print_connection_stats(&self.aby3, out)
    }

    async fn input(&mut self, input: Option<T>, id: usize) -> Result<TShare<T>, Error> {
        let input = input.map(|i| T::to_verificationshare(i));

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::input(&mut self.aby3, input, id)
        .await?;

        let r = self.get_r();
        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul(&mut self.aby3, value.to_owned(), r)
        .await?;

        let share = Share::new(value, mac);

        self.verifyqueue.push(share.to_owned());

        Ok(share)
    }

    #[cfg(test)]
    async fn input_all(&mut self, input: T) -> Result<Vec<TShare<T>>, Error> {
        // Since this is only for testing we perform a bad one
        let mut inputs = [None; 3];
        inputs[self.get_id()] = Some(input);
        let mut shares = Vec::with_capacity(3);

        for (i, inp) in inputs.into_iter().enumerate() {
            shares.push(self.input(inp.to_owned(), i).await?);
        }

        Ok(shares)
    }

    fn share<R: rand::prelude::Rng>(input: T, rng: &mut R) -> Vec<TShare<T>> {
        let input = T::to_verificationtype(input.to_sharetype());
        let r = rng.gen::<UShare<T>>();
        let rz = r * &input;

        let values = <Aby3<N> as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::share(T::VerificationShare::from_sharetype(input), rng);
        let macs = <Aby3<N> as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::share(T::VerificationShare::from_sharetype(rz), rng);

        values
            .into_iter()
            .zip(macs)
            .map(|(v, m)| Share::new(v, m))
            .collect()
    }

    async fn open(&mut self, share: TShare<T>) -> Result<T, Error> {
        let result = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::open(&mut self.aby3, share.get_value())
        .await?;

        Ok(T::from_verificationshare(result))
    }

    async fn open_many(&mut self, shares: Vec<TShare<T>>) -> Result<Vec<T>, Error> {
        let values = shares.into_iter().map(|s| s.get_value()).collect();

        let result = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::open_many(&mut self.aby3, values)
        .await?;

        let result = result
            .into_iter()
            .map(|r| T::from_verificationshare(r))
            .collect();

        Ok(result)
    }

    async fn open_bit(&mut self, share: BitShare) -> Result<bool, Error> {
        let result = <_ as MpcTrait<BitShareType, Aby3Share<BitShareType>, Aby3Share<Bit>>>::open(
            &mut self.aby3,
            share.get_value(),
        )
        .await?;

        Ok(Bit::from_verificationshare(result).convert())
    }

    async fn open_bit_many(&mut self, shares: Vec<BitShare>) -> Result<Vec<bool>, Error> {
        let values = shares.into_iter().map(|s| s.get_value()).collect();

        let result =
            <_ as MpcTrait<BitShareType, Aby3Share<BitShareType>, Aby3Share<Bit>>>::open_many(
                &mut self.aby3,
                values,
            )
            .await?;

        let result = result
            .into_iter()
            .map(|r| Bit::from_verificationshare(r).convert())
            .collect();

        Ok(result)
    }

    fn add(&self, a: TShare<T>, b: TShare<T>) -> TShare<T> {
        let (a_v, a_m) = a.get();
        let (b_v, b_m) = b.get();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::add(&self.aby3, a_v, b_v);

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::add(&self.aby3, a_m, b_m);

        Share::new(value, mac)
    }

    fn add_const(&self, a: TShare<T>, b: T) -> TShare<T> {
        let b = T::to_verificationshare(b);
        let (a_v, a_m) = a.get();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::add_const(&self.aby3, a_v, b);

        let mac_b = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul_const(&self.aby3, self.get_r(), b);

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::add(&self.aby3, a_m, mac_b);

        Share::new(value, mac)
    }

    fn sub(&self, a: TShare<T>, b: TShare<T>) -> TShare<T> {
        let (a_v, a_m) = a.get();
        let (b_v, b_m) = b.get();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::sub(&self.aby3, a_v, b_v);

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::sub(&self.aby3, a_m, b_m);

        Share::new(value, mac)
    }

    fn sub_const(&self, a: TShare<T>, b: T) -> TShare<T> {
        let b = T::to_verificationshare(b);
        let (a_v, a_m) = a.get();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::sub_const(&self.aby3, a_v, b);

        let mac_b = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul_const(&self.aby3, self.get_r(), b);

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::sub(&self.aby3, a_m, mac_b);

        Share::new(value, mac)
    }

    async fn mul(&mut self, a: TShare<T>, b: TShare<T>) -> Result<TShare<T>, Error> {
        let (a_v, a_m) = a.get();
        let b_v = b.get_value();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul(&mut self.aby3, a_v, b_v.to_owned())
        .await?;

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul(&mut self.aby3, a_m, b_v)
        .await?;

        let result = Share::new(value, mac);

        self.verifyqueue.push(result.to_owned());
        Ok(result)
    }

    fn mul_const(&self, a: TShare<T>, b: T) -> TShare<T> {
        let b = T::to_verificationshare(b);
        let (a_v, a_m) = a.get();

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul_const(&self.aby3, a_v, b);

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::mul_const(&self.aby3, a_m, b);

        Share::new(value, mac)
    }

    async fn dot(&mut self, a: Vec<TShare<T>>, b: Vec<TShare<T>>) -> Result<TShare<T>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }
        let mut a_values = Vec::with_capacity(len);
        let mut a_macs = Vec::with_capacity(len);
        let mut b_values = Vec::with_capacity(len);

        for (a, b) in a.into_iter().zip(b.into_iter()) {
            let (a_v, a_m) = a.get();
            let b_v = b.get_value();
            a_values.push(a_v);
            a_macs.push(a_m);
            b_values.push(b_v);
        }

        let value = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::dot(&mut self.aby3, a_values, b_values.to_owned())
        .await?;

        let mac = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::dot(&mut self.aby3, a_macs, b_values)
        .await?;

        let result = Share::new(value, mac);

        self.verifyqueue.push(result.to_owned());
        Ok(result)
    }

    async fn dot_many(
        &mut self,
        a: Vec<Vec<TShare<T>>>,
        b: Vec<Vec<TShare<T>>>,
    ) -> Result<Vec<TShare<T>>, Error> {
        let len = a.len();
        if len != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut a_values = Vec::with_capacity(len);
        let mut a_macs = Vec::with_capacity(len);
        let mut b_values = Vec::with_capacity(len);

        for (a, b) in a.into_iter().zip(b.into_iter()) {
            let mut a_v = Vec::with_capacity(len);
            let mut a_m = Vec::with_capacity(len);
            let mut b_v = Vec::with_capacity(len);
            for (a, b) in a.into_iter().zip(b.into_iter()) {
                let (a_v_, a_m_) = a.get();
                let b_v_ = b.get_value();
                a_v.push(a_v_);
                a_m.push(a_m_);
                b_v.push(b_v_);
            }
            a_values.push(a_v);
            a_macs.push(a_m);
            b_values.push(b_v);
        }

        let values = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::dot_many(&mut self.aby3, a_values, b_values.to_owned())
        .await?;

        let macs = <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::dot_many(&mut self.aby3, a_macs, b_values)
        .await?;

        let mut result = Vec::with_capacity(len);
        self.verifyqueue.reserve(len);

        for (value, mac) in values.into_iter().zip(macs) {
            let share = Share::new(value, mac);
            self.verifyqueue.push(share.to_owned());
            result.push(share);
        }

        Ok(result)
    }

    async fn get_msb(&mut self, a: TShare<T>) -> Result<BitShare, Error> {
        todo!()
    }

    async fn get_msb_many(&mut self, a: Vec<TShare<T>>) -> Result<Vec<BitShare>, Error> {
        todo!()
    }

    async fn binary_or(&mut self, a: BitShare, b: BitShare) -> Result<BitShare, Error> {
        todo!()
    }

    async fn reduce_binary_or(&mut self, a: Vec<BitShare>) -> Result<BitShare, Error> {
        todo!()
    }

    async fn verify(&mut self) -> Result<(), Error> {
        // todo!()
        Ok(())
    }
}

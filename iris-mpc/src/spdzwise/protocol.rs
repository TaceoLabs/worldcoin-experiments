use super::share::Share;
use crate::prelude::{Aby3, Aby3Share, Bit, Error, MpcTrait, NetworkTrait, Sharable};
use rand::distributions::{Distribution, Standard};
use std::ops::Mul;

#[allow(type_alias_bounds)]
pub(crate) type TShare<T: Sharable> = Share<T::VerificationShare>;
pub(crate) type BitShare = Share<<Bit as Sharable>::VerificationShare>;
#[allow(type_alias_bounds)]
pub(crate) type UShare<T: Sharable> = <T::VerificationShare as Sharable>::Share;

pub struct SpdzWise<N: NetworkTrait> {
    aby3: Aby3<N>,
}

impl<N: NetworkTrait> SpdzWise<N> {
    pub fn new(network: N) -> Self {
        let aby3 = Aby3::new(network);
        Self { aby3 }
    }
}

impl<N: NetworkTrait, T: Sharable> MpcTrait<T, TShare<T>, BitShare> for SpdzWise<N>
where
    Standard: Distribution<UShare<T>>,
    Aby3Share<T::VerificationShare>: Mul<Output = Aby3Share<T::VerificationShare>>,
    Aby3Share<T::VerificationShare>: Mul<UShare<T>, Output = Aby3Share<T::VerificationShare>>,
{
    fn get_id(&self) -> usize {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::get_id(&self.aby3)
    }

    async fn preprocess(&mut self) -> Result<(), Error> {
        <_ as MpcTrait<
            T::VerificationShare,
            Aby3Share<T::VerificationShare>,
            Aby3Share<Bit>,
        >>::preprocess(&mut self.aby3)
        .await
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
        todo!()
    }

    #[cfg(test)]
    async fn input_all(&mut self, input: T) -> Result<Vec<TShare<T>>, Error> {
        todo!()
    }

    fn share<R: rand::prelude::Rng>(input: T, rng: &mut R) -> Vec<TShare<T>> {
        todo!()
    }

    async fn open(&mut self, share: TShare<T>) -> Result<T, Error> {
        todo!()
    }

    async fn open_many(&mut self, shares: Vec<TShare<T>>) -> Result<Vec<T>, Error> {
        todo!()
    }

    async fn open_bit(&mut self, share: BitShare) -> Result<bool, Error> {
        todo!()
    }

    async fn open_bit_many(&mut self, shares: Vec<BitShare>) -> Result<Vec<bool>, Error> {
        todo!()
    }

    fn add(&self, a: TShare<T>, b: TShare<T>) -> TShare<T> {
        todo!()
    }

    fn add_const(&self, a: TShare<T>, b: T) -> TShare<T> {
        todo!()
    }

    fn sub(&self, a: TShare<T>, b: TShare<T>) -> TShare<T> {
        todo!()
    }

    fn sub_const(&self, a: TShare<T>, b: T) -> TShare<T> {
        todo!()
    }

    #[cfg(test)]
    async fn mul(&mut self, a: TShare<T>, b: TShare<T>) -> Result<TShare<T>, Error> {
        todo!()
    }

    fn mul_const(&self, a: TShare<T>, b: T) -> TShare<T> {
        todo!()
    }

    async fn dot(&mut self, a: Vec<TShare<T>>, b: Vec<TShare<T>>) -> Result<TShare<T>, Error> {
        todo!()
    }

    async fn dot_many(
        &mut self,
        a: Vec<Vec<TShare<T>>>,
        b: Vec<Vec<TShare<T>>>,
    ) -> Result<Vec<TShare<T>>, Error> {
        todo!()
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
        todo!()
    }
}

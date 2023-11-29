use crate::{
    error::Error,
    types::{ring_element::RingImpl, sharable::Sharable},
};
use rand::Rng;

#[allow(async_fn_in_trait)]
pub trait MpcTrait<T: Sharable, Ashare, Bshare> {
    async fn finish(self) -> Result<(), Error>;

    async fn preprocess(&mut self) -> Result<(), Error>;

    async fn input(&mut self, input: Option<T>, id: usize) -> Result<Ashare, Error>;
    // Each party inputs an arithmetic share
    async fn input_all(&mut self, input: T) -> Result<Vec<Ashare>, Error>;
    async fn share<R: Rng>(input: T, rng: &mut R) -> Vec<Ashare>;

    async fn open(&mut self, share: Ashare) -> Result<T, Error>;
    async fn open_many(&mut self, shares: Vec<Ashare>) -> Result<Vec<T>, Error>;

    fn add(&self, a: Ashare, b: Ashare) -> Ashare;
    fn add_const(&self, a: Ashare, b: T) -> Ashare;
    fn sub(&self, a: Ashare, b: Ashare) -> Ashare;
    fn sub_const(&self, a: Ashare, b: T) -> Ashare;
    async fn mul(&mut self, a: Ashare, b: Ashare) -> Result<Ashare, Error>;
    fn mul_const(&self, a: Ashare, b: T) -> Ashare;

    async fn dot(&mut self, a: Vec<Ashare>, b: Vec<Ashare>) -> Result<Ashare, Error>;
    async fn get_msb(&mut self, a: Ashare) -> Result<Bshare, Error>;
}

#[derive(Default)]
pub struct Plain {}

impl<T: Sharable> MpcTrait<T, T, bool> for Plain {
    async fn finish(self) -> Result<(), Error> {
        Ok(())
    }

    async fn preprocess(&mut self) -> Result<(), Error> {
        Ok(())
    }

    async fn input(&mut self, input: Option<T>, _id: usize) -> Result<T, Error> {
        input.ok_or(Error::ValueError("Cannot share None".to_string()))
    }

    async fn input_all(&mut self, input: T) -> Result<Vec<T>, Error> {
        Ok(vec![input])
    }

    async fn share<R: Rng>(input: T, _rng: &mut R) -> Vec<T> {
        vec![input]
    }

    async fn open(&mut self, share: T) -> Result<T, Error> {
        Ok(share)
    }

    async fn open_many(&mut self, shares: Vec<T>) -> Result<Vec<T>, Error> {
        Ok(shares)
    }

    fn add(&self, a: T, b: T) -> T {
        a.wrapping_add(&b)
    }

    fn sub(&self, a: T, b: T) -> T {
        a.wrapping_sub(&b)
    }

    fn add_const(&self, a: T, b: T) -> T {
        a.wrapping_add(&b)
    }

    fn sub_const(&self, a: T, b: T) -> T {
        a.wrapping_sub(&b)
    }

    async fn mul(&mut self, a: T, b: T) -> Result<T, Error> {
        Ok(a.wrapping_mul(&b))
    }

    fn mul_const(&self, a: T, b: T) -> T {
        a.wrapping_mul(&b)
    }

    async fn dot(&mut self, a: Vec<T>, b: Vec<T>) -> Result<T, Error> {
        if a.len() != b.len() {
            return Err(Error::InvlidSizeError);
        }
        let mut res = T::zero();
        for (a, b) in a.into_iter().zip(b.into_iter()) {
            res = res.wrapping_add(&a.wrapping_mul(&b));
        }
        Ok(res)
    }

    async fn get_msb(&mut self, a: T) -> Result<bool, Error> {
        Ok((a >> (T::Share::get_k() - 1) & T::one()) == T::one())
    }
}

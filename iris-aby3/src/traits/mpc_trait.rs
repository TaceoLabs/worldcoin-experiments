use crate::{
    error::Error,
    types::{ring_element::RingImpl, sharable::Sharable},
};
use rand::Rng;

#[allow(async_fn_in_trait)]
pub trait MpcTrait<T: Sharable, Ashare, Bshare> {
    fn get_id(&self) -> usize;
    async fn preprocess(&mut self) -> Result<(), Error>;
    async fn finish(self) -> Result<(), Error>;

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error>;

    async fn input(&mut self, input: Option<T>, id: usize) -> Result<Ashare, Error>;
    // Each party inputs an arithmetic share
    async fn input_all(&mut self, input: T) -> Result<Vec<Ashare>, Error>;
    fn share<R: Rng>(input: T, rng: &mut R) -> Vec<Ashare>;

    async fn open(&mut self, share: Ashare) -> Result<T, Error>;
    async fn open_many(&mut self, shares: Vec<Ashare>) -> Result<Vec<T>, Error>;
    async fn open_bit(&mut self, share: Bshare) -> Result<bool, Error>;
    async fn open_bit_many(&mut self, shares: Vec<Bshare>) -> Result<Vec<bool>, Error>;

    fn add(&self, a: Ashare, b: Ashare) -> Ashare;
    fn add_const(&self, a: Ashare, b: T) -> Ashare;
    fn sub(&self, a: Ashare, b: Ashare) -> Ashare;
    fn sub_const(&self, a: Ashare, b: T) -> Ashare;
    async fn mul(&mut self, a: Ashare, b: Ashare) -> Result<Ashare, Error>;
    fn mul_const(&self, a: Ashare, b: T) -> Ashare;

    async fn dot(&mut self, a: Vec<Ashare>, b: Vec<Ashare>) -> Result<Ashare, Error>;
    async fn dot_many(
        &mut self,
        a: Vec<Vec<Ashare>>,
        b: Vec<Vec<Ashare>>,
    ) -> Result<Vec<Ashare>, Error>;

    async fn get_msb(&mut self, a: Ashare) -> Result<Bshare, Error>;
    async fn get_msb_many(&mut self, a: Vec<Ashare>) -> Result<Vec<Bshare>, Error>;
    async fn binary_or(&mut self, a: Bshare, b: Bshare) -> Result<Bshare, Error>;
    async fn reduce_binary_or(&mut self, a: Vec<Bshare>) -> Result<Bshare, Error>;
}

#[derive(Default)]
pub struct Plain {}

impl<T: Sharable> MpcTrait<T, T, bool> for Plain {
    fn get_id(&self) -> usize {
        0
    }

    async fn finish(self) -> Result<(), Error> {
        Ok(())
    }

    async fn preprocess(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        writeln!(out, "Connection 0 stats:\n\tSENT: 0 bytes\n\tRECV: 0 bytes")?;
        Ok(())
    }

    async fn input(&mut self, input: Option<T>, _id: usize) -> Result<T, Error> {
        input.ok_or(Error::ValueError("Cannot share None".to_string()))
    }

    async fn input_all(&mut self, input: T) -> Result<Vec<T>, Error> {
        Ok(vec![input])
    }

    fn share<R: Rng>(input: T, _rng: &mut R) -> Vec<T> {
        vec![input]
    }

    async fn open(&mut self, share: T) -> Result<T, Error> {
        Ok(share)
    }

    async fn open_many(&mut self, shares: Vec<T>) -> Result<Vec<T>, Error> {
        Ok(shares)
    }

    async fn open_bit(&mut self, share: bool) -> Result<bool, Error> {
        Ok(share)
    }

    async fn open_bit_many(&mut self, shares: Vec<bool>) -> Result<Vec<bool>, Error> {
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

    async fn dot_many(&mut self, a: Vec<Vec<T>>, b: Vec<Vec<T>>) -> Result<Vec<T>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvlidSizeError);
        }

        let mut res = Vec::with_capacity(a.len());
        for (a_, b_) in a.into_iter().zip(b) {
            let r = self.dot(a_, b_).await?;
            res.push(r);
        }

        Ok(res)
    }

    async fn get_msb(&mut self, a: T) -> Result<bool, Error> {
        Ok(a.to_sharetype().get_msb().convert().convert())
    }

    async fn get_msb_many(&mut self, a: Vec<T>) -> Result<Vec<bool>, Error> {
        let res = a
            .into_iter()
            .map(|a_| a_.to_sharetype().get_msb().convert().convert())
            .collect();
        Ok(res)
    }

    async fn binary_or(&mut self, a: bool, b: bool) -> Result<bool, Error> {
        Ok(a | b)
    }

    async fn reduce_binary_or(&mut self, a: Vec<bool>) -> Result<bool, Error> {
        Ok(a.into_iter().fold(false, |a, b| a | b))
    }
}

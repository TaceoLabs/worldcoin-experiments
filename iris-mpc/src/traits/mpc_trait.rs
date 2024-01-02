use crate::{
    error::Error,
    types::{ring_element::RingImpl, sharable::Sharable},
};
use rand::Rng;

pub trait MpcTrait<T: Sharable, Ashare, Bshare> {
    fn get_id(&self) -> usize;
    fn preprocess(&mut self) -> Result<(), Error>;
    fn set_mac_key(&mut self, key: Ashare);
    fn set_new_mac_key(&mut self);
    #[cfg(test)]
    fn open_mac_key(&mut self) -> Result<T::VerificationShare, Error>;

    fn finish(self) -> Result<(), Error>;

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error>;

    fn input(&mut self, input: Option<T>, id: usize) -> Result<Ashare, Error>;

    // Each party inputs an arithmetic share
    #[cfg(test)]
    fn input_all(&mut self, input: T) -> Result<Vec<Ashare>, Error>;
    fn share<R: Rng>(input: T, mac_key: T::VerificationShare, rng: &mut R) -> Vec<Ashare>;

    fn open(&mut self, share: Ashare) -> Result<T, Error>;
    fn open_many(&mut self, shares: Vec<Ashare>) -> Result<Vec<T>, Error>;
    fn open_bit(&mut self, share: Bshare) -> Result<bool, Error>;
    fn open_bit_many(&mut self, shares: Vec<Bshare>) -> Result<Vec<bool>, Error>;

    fn add(&self, a: Ashare, b: Ashare) -> Ashare;
    fn add_const(&self, a: Ashare, b: T) -> Ashare;
    fn sub(&self, a: Ashare, b: Ashare) -> Ashare;
    fn sub_const(&self, a: Ashare, b: T) -> Ashare;
    fn mul(&mut self, a: Ashare, b: Ashare) -> Result<Ashare, Error>;
    fn mul_const(&self, a: Ashare, b: T) -> Ashare;

    fn dot(&mut self, a: Vec<Ashare>, b: Vec<Ashare>) -> Result<Ashare, Error>;
    fn dot_many(&mut self, a: &[Vec<Ashare>], b: &[Vec<Ashare>]) -> Result<Vec<Ashare>, Error>;

    fn get_msb(&mut self, a: Ashare) -> Result<Bshare, Error>;
    fn get_msb_many(&mut self, a: Vec<Ashare>) -> Result<Vec<Bshare>, Error>;
    fn binary_or(&mut self, a: Bshare, b: Bshare) -> Result<Bshare, Error>;
    fn reduce_binary_or(&mut self, a: Vec<Bshare>) -> Result<Bshare, Error>;

    fn verify(&mut self) -> Result<(), Error>;
}

#[derive(Default)]
pub struct Plain {}

impl<T: Sharable> MpcTrait<T, T, bool> for Plain {
    fn get_id(&self) -> usize {
        0
    }

    fn finish(self) -> Result<(), Error> {
        Ok(())
    }

    fn preprocess(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn set_mac_key(&mut self, _key: T) {}
    fn set_new_mac_key(&mut self) {}
    #[cfg(test)]
    fn open_mac_key(&mut self) -> Result<T::VerificationShare, Error> {
        Ok(T::VerificationShare::default())
    }

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        writeln!(out, "Connection 0 stats:\n\tSENT: 0 bytes\n\tRECV: 0 bytes")?;
        Ok(())
    }

    fn input(&mut self, input: Option<T>, _id: usize) -> Result<T, Error> {
        input.ok_or(Error::ValueError("Cannot share None".to_string()))
    }

    #[cfg(test)]
    fn input_all(&mut self, input: T) -> Result<Vec<T>, Error> {
        Ok(vec![input])
    }

    fn share<R: Rng>(input: T, _mac_key: T::VerificationShare, _rng: &mut R) -> Vec<T> {
        vec![input]
    }

    fn open(&mut self, share: T) -> Result<T, Error> {
        Ok(share)
    }

    fn open_many(&mut self, shares: Vec<T>) -> Result<Vec<T>, Error> {
        Ok(shares)
    }

    fn open_bit(&mut self, share: bool) -> Result<bool, Error> {
        Ok(share)
    }

    fn open_bit_many(&mut self, shares: Vec<bool>) -> Result<Vec<bool>, Error> {
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

    fn mul(&mut self, a: T, b: T) -> Result<T, Error> {
        Ok(a.wrapping_mul(&b))
    }

    fn mul_const(&self, a: T, b: T) -> T {
        a.wrapping_mul(&b)
    }

    fn dot(&mut self, a: Vec<T>, b: Vec<T>) -> Result<T, Error> {
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }
        let mut res = T::zero();
        for (a, b) in a.into_iter().zip(b.into_iter()) {
            res = res.wrapping_add(&a.wrapping_mul(&b));
        }
        Ok(res)
    }

    fn dot_many(&mut self, a: &[Vec<T>], b: &[Vec<T>]) -> Result<Vec<T>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut res = Vec::with_capacity(a.len());
        for (a_, b_) in a.iter().zip(b) {
            let r = self.dot(a_.to_owned(), b_.to_owned())?;
            res.push(r);
        }

        Ok(res)
    }

    fn get_msb(&mut self, a: T) -> Result<bool, Error> {
        Ok(a.to_sharetype().get_msb().convert().convert())
    }

    fn get_msb_many(&mut self, a: Vec<T>) -> Result<Vec<bool>, Error> {
        let res = a
            .into_iter()
            .map(|a_| a_.to_sharetype().get_msb().convert().convert())
            .collect();
        Ok(res)
    }

    fn binary_or(&mut self, a: bool, b: bool) -> Result<bool, Error> {
        Ok(a | b)
    }

    fn reduce_binary_or(&mut self, a: Vec<bool>) -> Result<bool, Error> {
        Ok(a.into_iter().fold(false, |a, b| a | b))
    }

    fn verify(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

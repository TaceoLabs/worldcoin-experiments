use super::share_trait::{ShareTrait, VecShareTrait};
use crate::{
    error::Error,
    prelude::Bit,
    types::{ring_element::RingImpl, sharable::Sharable},
};
use plain_reference::IrisCodeArray;
use rand::Rng;

#[allow(async_fn_in_trait)]
pub trait MpcTrait<T: Sharable, Ashare: ShareTrait, Bshare: ShareTrait> {
    fn get_id(&self) -> usize;
    async fn preprocess(&mut self) -> Result<(), Error>;
    fn set_mac_key(&mut self, key: Ashare);
    fn set_new_mac_key(&mut self);
    #[cfg(test)]
    async fn open_mac_key(&mut self) -> Result<T::VerificationShare, Error>;

    async fn finish(self) -> Result<(), Error>;

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error>;

    async fn input(&mut self, input: Option<T>, id: usize) -> Result<Ashare, Error>;

    // Each party inputs an arithmetic share
    #[cfg(test)]
    async fn input_all(&mut self, input: T) -> Result<Vec<Ashare>, Error>;
    fn share<R: Rng>(input: T, mac_key: T::VerificationShare, rng: &mut R) -> Vec<Ashare>;

    async fn open(&mut self, share: Ashare) -> Result<T, Error>;
    async fn open_many(&mut self, shares: Ashare::VecShare) -> Result<Vec<T>, Error>;
    async fn open_bit(&mut self, share: Bshare) -> Result<bool, Error>;
    async fn open_bit_many(&mut self, shares: Bshare::VecShare) -> Result<Vec<bool>, Error>;

    fn add(&self, a: Ashare, b: Ashare) -> Ashare;
    fn add_const(&self, a: Ashare, b: T) -> Ashare;
    fn sub(&self, a: Ashare, b: Ashare) -> Ashare;
    fn sub_const(&self, a: Ashare, b: T) -> Ashare;
    async fn mul(&mut self, a: Ashare, b: Ashare) -> Result<Ashare, Error>;
    fn mul_const(&self, a: Ashare, b: T) -> Ashare;

    async fn dot(&mut self, a: Ashare::VecShare, b: Ashare::VecShare) -> Result<Ashare, Error>;
    async fn dot_many(
        &mut self,
        a: &[Ashare::VecShare],
        b: &[Ashare::VecShare],
    ) -> Result<Vec<Ashare>, Error>;
    // TODO Remove Generic impl
    async fn masked_dot_many(
        &mut self,
        a: &Ashare::VecShare,
        b: &[Ashare::VecShare],
        masks: &[IrisCodeArray],
    ) -> Result<Vec<Ashare>, Error> {
        let mut a_vec = Vec::with_capacity(b.len());
        let mut b_vec = Vec::with_capacity(b.len());

        for (b_, mask) in b.iter().zip(masks.iter()) {
            let mut code1 = a.to_owned();
            let mut code2 = b_.to_owned();
            if code1.len() != IrisCodeArray::IRIS_CODE_SIZE
                || code2.len() != IrisCodeArray::IRIS_CODE_SIZE
            {
                return Err(Error::InvalidCodeSizeError);
            }

            for i in 0..IrisCodeArray::IRIS_CODE_SIZE {
                if !mask.get_bit(i) {
                    code1.set_at(i, Ashare::zero());
                    code2.set_at(i, Ashare::zero());
                }
            }

            a_vec.push(code1);
            b_vec.push(code2);
        }
        self.dot_many(&a_vec, &b_vec).await
    }

    async fn get_msb(&mut self, a: Ashare) -> Result<Bshare, Error>;
    async fn get_msb_many(&mut self, a: Ashare::VecShare) -> Result<Bshare::VecShare, Error>;
    async fn binary_or(&mut self, a: Bshare, b: Bshare) -> Result<Bshare, Error>;
    async fn reduce_binary_or(
        &mut self,
        a: Bshare::VecShare,
        chunk_size: usize,
    ) -> Result<Bshare, Error>;

    async fn verify(&mut self) -> Result<(), Error>;
}

#[derive(Default)]
pub struct Plain {}

impl<T: Sharable> ShareTrait for T {
    type VecShare = Vec<Self>;
}

impl<T: Sharable> VecShareTrait for Vec<T> {
    type Share = T;

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn filter_reduce_add_twice(
        a: &Self,
        b: &Self,
        mask: &plain_reference::IrisCodeArray,
    ) -> Result<(Self::Share, Self::Share), Error> {
        if a.is_empty() || a.len() != b.len() {
            return Err(Error::InvalidCodeSizeError);
        }

        let (sum_a, sum_b) = a
            .iter()
            .zip(b)
            .enumerate()
            .filter(|(i, _)| mask.get_bit(*i))
            .map(|(_, (a_, b_))| (a_.to_owned(), b_.to_owned()))
            .reduce(|(aa, ab), (ba, bb)| (aa + ba, ab + bb))
            .expect("Size is not zero");
        Ok((sum_a, sum_b))
    }

    fn with_capacity(capacity: usize) -> Self {
        Vec::with_capacity(capacity)
    }

    fn xor_many(self, b: Self) -> Result<Self, Error> {
        if self.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let res = self.into_iter().zip(b).map(|(a_, b_)| a_ ^ b_).collect();
        Ok(res)
    }

    fn xor_assign_many(&mut self, b: Self) -> Result<Self, Error> {
        if self.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        for (a_, b_) in self.iter_mut().zip(b) {
            *a_ ^= b_;
        }
        Ok(self.to_owned())
    }

    fn shl_assign_many(&mut self, shift: u32) -> Self {
        for a_ in self.iter_mut() {
            *a_ = a_.wrapping_shl(shift);
        }
        self.to_owned()
    }

    fn reserve(&mut self, additional: usize) {
        Vec::reserve(self, additional);
    }

    fn push(&mut self, value: Self::Share) {
        Vec::push(self, value);
    }

    fn extend(&mut self, other: Self) {
        <Vec<_> as std::iter::Extend<_>>::extend(self, other);
    }

    fn split_at(&self, mid: usize) -> (Self, Self) {
        let (a, b) = self[..].split_at(mid);
        (a.to_owned(), b.to_owned())
    }

    fn chunks(self, chunk_size: usize) -> Vec<Self> {
        let capacity = self.len() / chunk_size + (self.len() % chunk_size != 0) as usize;

        let mut res = Vec::with_capacity(capacity);
        for chunk in self[..].chunks(chunk_size) {
            res.push(chunk.to_owned());
        }
        res
    }

    fn get_at(&self, index: usize) -> &Self::Share {
        &self[index]
    }

    fn set_at(&mut self, index: usize, value: Self::Share) {
        self[index] = value;
    }
}

impl<T: Sharable> MpcTrait<T, T, Bit> for Plain {
    fn get_id(&self) -> usize {
        0
    }

    async fn finish(self) -> Result<(), Error> {
        Ok(())
    }

    async fn preprocess(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn set_mac_key(&mut self, _key: T) {}
    fn set_new_mac_key(&mut self) {}
    #[cfg(test)]
    async fn open_mac_key(&mut self) -> Result<T::VerificationShare, Error> {
        Ok(T::VerificationShare::default())
    }

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        writeln!(out, "Connection 0 stats:\n\tSENT: 0 bytes\n\tRECV: 0 bytes")?;
        Ok(())
    }

    async fn input(&mut self, input: Option<T>, _id: usize) -> Result<T, Error> {
        input.ok_or(Error::ValueError("Cannot share None".to_string()))
    }

    #[cfg(test)]
    async fn input_all(&mut self, input: T) -> Result<Vec<T>, Error> {
        Ok(vec![input])
    }

    fn share<R: Rng>(input: T, _mac_key: T::VerificationShare, _rng: &mut R) -> Vec<T> {
        vec![input]
    }

    async fn open(&mut self, share: T) -> Result<T, Error> {
        Ok(share)
    }

    async fn open_many(&mut self, shares: Vec<T>) -> Result<Vec<T>, Error> {
        Ok(shares)
    }

    async fn open_bit(&mut self, share: Bit) -> Result<bool, Error> {
        Ok(share.convert())
    }

    async fn open_bit_many(&mut self, shares: Vec<Bit>) -> Result<Vec<bool>, Error> {
        Ok(Bit::convert_vec(shares))
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
            return Err(Error::InvalidSizeError);
        }
        let mut res = T::zero();
        for (a, b) in a.into_iter().zip(b.into_iter()) {
            res = res.wrapping_add(&a.wrapping_mul(&b));
        }
        Ok(res)
    }

    async fn dot_many(&mut self, a: &[Vec<T>], b: &[Vec<T>]) -> Result<Vec<T>, Error> {
        if a.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let mut res = Vec::with_capacity(a.len());
        for (a_, b_) in a.iter().zip(b) {
            let r = self.dot(a_.to_owned(), b_.to_owned()).await?;
            res.push(r);
        }

        Ok(res)
    }

    async fn get_msb(&mut self, a: T) -> Result<Bit, Error> {
        Ok(a.to_sharetype().get_msb().convert())
    }

    async fn get_msb_many(&mut self, a: Vec<T>) -> Result<Vec<Bit>, Error> {
        let res = a
            .into_iter()
            .map(|a_| a_.to_sharetype().get_msb().convert())
            .collect();
        Ok(res)
    }

    async fn binary_or(&mut self, a: Bit, b: Bit) -> Result<Bit, Error> {
        Ok(a | b)
    }

    async fn reduce_binary_or(&mut self, a: Vec<Bit>, _: usize) -> Result<Bit, Error> {
        Ok(a.into_iter().fold(Bit::new(false), |a, b| a | b))
    }

    async fn verify(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

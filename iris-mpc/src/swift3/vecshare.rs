use super::share::Share;
use crate::{
    prelude::{Error, Sharable},
    traits::share_trait::VecShareTrait,
};

impl<T: Sharable> VecShareTrait for Vec<Share<T>> {
    type Share = Share<T>;

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
            .zip(mask.bits())
            .filter(|(_, b)| *b)
            .map(|((a_, b_), _)| (a_.to_owned(), b_.to_owned()))
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
            *a_ <<= shift;
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

    fn get_at(&self, index: usize) -> Self::Share {
        self[index].to_owned()
    }

    fn set_at(&mut self, index: usize, value: Self::Share) {
        self[index] = value;
    }
}

use crate::{
    prelude::{Aby3Share, Error, Sharable},
    traits::share_trait::{ShareTrait, VecShareTrait},
};
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::ops::Add;

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Share<T: Sharable> {
    value: Aby3Share<T>,
    mac: Aby3Share<T>,
}

impl<T: Sharable> ShareTrait for Share<T> {
    type VecShare = Vec<Self>;
}

impl<T: Sharable> VecShareTrait for Vec<Share<T>> {
    type Share = Share<T>;

    fn len(&self) -> usize {
        Vec::len(self)
    }

    // TODO update for other share
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

    fn xor_many(self, _b: Self) -> Result<Self, Error> {
        unreachable!()
    }

    fn xor_assign_many(&mut self, _b: Self) -> Result<Self, Error> {
        unreachable!()
    }

    fn shl_assign_many(&mut self, _shift: u32) -> Self {
        unreachable!()
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
}

impl<T: Sharable> Share<T> {
    pub fn new(value: Aby3Share<T>, mac: Aby3Share<T>) -> Self {
        Self { value, mac }
    }

    pub fn get(self) -> (Aby3Share<T>, Aby3Share<T>) {
        (self.value, self.mac)
    }

    pub fn get_value(self) -> Aby3Share<T> {
        self.value
    }

    pub fn get_mac(self) -> Aby3Share<T> {
        self.mac
    }
}

impl<T: Sharable> Add for Share<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            value: self.value + rhs.value,
            mac: self.mac + rhs.mac,
        }
    }
}

impl<T: Sharable> Zero for Share<T> {
    fn zero() -> Self {
        Self {
            value: Aby3Share::zero(),
            mac: Aby3Share::zero(),
        }
    }

    // TODO is this corect?
    fn is_zero(&self) -> bool {
        self.value.is_zero() && self.mac.is_zero()
    }
}

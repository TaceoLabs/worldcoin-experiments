use super::share::Share;
use crate::{
    prelude::{Error, Sharable},
    traits::share_trait::VecShareTrait,
};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

// share x = x1 + x2 + x3 where party i has (xi, x{i-1})
#[derive(Clone, Debug, PartialEq, Default, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VecShare<T: Sharable> {
    pub(crate) a: Vec<T::Share>,
    pub(crate) b: Vec<T::Share>,
    sharetype: PhantomData<T>,
}

impl<T: Sharable> VecShare<T> {
    pub fn get_ab(self) -> (Vec<T::Share>, Vec<T::Share>) {
        (self.a, self.b)
    }
}

impl<T: Sharable> VecShareTrait for VecShare<T> {
    type Share = Share<T>;

    fn len(&self) -> usize {
        debug_assert_eq!(self.a.len(), self.b.len());
        self.a.len()
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

        let (sum_aa, sum_ab, sum_ba, sum_bb) =
            a.a.iter()
                .zip(a.b.iter())
                .zip(b.a.iter().zip(b.b.iter()))
                .enumerate()
                .filter(|(i, _)| mask.get_bit(*i))
                .map(|(_, ((aa_, ab_), (ba_, bb_)))| {
                    (
                        aa_.to_owned(),
                        ab_.to_owned(),
                        ba_.to_owned(),
                        bb_.to_owned(),
                    )
                })
                .reduce(|(aa, ab, ba, bb), (aa_, ab_, ba_, bb_)| {
                    (aa + aa_, ab + ab_, ba + ba_, bb + bb_)
                })
                .expect("Size is not zero");

        let sum_a = Share::new(sum_aa, sum_ab);
        let sum_b = Share::new(sum_ba, sum_bb);

        Ok((sum_a, sum_b))
    }

    fn with_capacity(capacity: usize) -> Self {
        let a = Vec::with_capacity(capacity);
        let b = Vec::with_capacity(capacity);
        Self {
            a,
            b,
            sharetype: PhantomData,
        }
    }

    fn xor_many(self, b: Self) -> Result<Self, Error> {
        if self.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        let res_a = self
            .a
            .into_iter()
            .zip(b.a)
            .map(|(a_, b_)| a_ ^ b_)
            .collect();

        let res_b = self
            .b
            .into_iter()
            .zip(b.b)
            .map(|(a_, b_)| a_ ^ b_)
            .collect();

        let res = Self {
            a: res_a,
            b: res_b,
            sharetype: PhantomData,
        };
        Ok(res)
    }

    fn xor_assign_many(&mut self, b: Self) -> Result<Self, Error> {
        if self.len() != b.len() {
            return Err(Error::InvalidSizeError);
        }

        for (a_, b_) in self.a.iter_mut().zip(b.a) {
            *a_ ^= b_;
        }

        for (a_, b_) in self.b.iter_mut().zip(b.b) {
            *a_ ^= b_;
        }
        Ok(self.to_owned())
    }

    fn shl_assign_many(&mut self, shift: u32) -> Self {
        for a_ in self.a.iter_mut() {
            *a_ <<= shift;
        }
        for b_ in self.b.iter_mut() {
            *b_ <<= shift;
        }
        self.to_owned()
    }

    fn reserve(&mut self, additional: usize) {
        self.a.reserve(additional);
        self.b.reserve(additional);
    }

    fn push(&mut self, value: Self::Share) {
        let (a, b) = value.get_ab();
        self.a.push(a);
        self.b.push(b);
    }

    fn extend(&mut self, other: Self) {
        let (a, b) = other.get_ab();
        self.a.extend(a);
        self.b.extend(b);
    }

    fn split_at(&self, mid: usize) -> (Self, Self) {
        let (aa, ab) = self.a.split_at(mid);
        let (ba, bb) = self.b.split_at(mid);

        let a = Self {
            a: aa.to_owned(),
            b: ba.to_owned(),
            sharetype: PhantomData,
        };
        let b = Self {
            a: ab.to_owned(),
            b: bb.to_owned(),
            sharetype: PhantomData,
        };
        (a, b)
    }

    fn chunks(self, chunk_size: usize) -> Vec<Self> {
        let len = self.len();
        let capacity = len / chunk_size + (len % chunk_size != 0) as usize;

        let mut res = Vec::with_capacity(capacity);
        for (a, b) in self.a.chunks(chunk_size).zip(self.b.chunks(chunk_size)) {
            let r = Self {
                a: a.to_owned(),
                b: b.to_owned(),
                sharetype: PhantomData,
            };
            res.push(r);
        }
        res
    }

    fn get_at(&self, index: usize) -> Self::Share {
        let a = self.a[index].to_owned();
        let b = self.b[index].to_owned();
        Share::new(a, b)
    }

    fn set_at(&mut self, index: usize, value: Self::Share) {
        let (a, b) = value.get_ab();
        self.a[index] = a;
        self.b[index] = b;
    }
}

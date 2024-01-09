use crate::{
    prelude::{Aby3Share, Error, Sharable},
    traits::share_trait::VecShareTrait,
};
use serde::{Deserialize, Serialize};

use super::share::Share;

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VecShare<T: Sharable> {
    pub(crate) values: Vec<Aby3Share<T>>,
    pub(crate) macs: Vec<Aby3Share<T>>,
}

impl<T: Sharable> VecShare<T> {
    pub fn new(values: Vec<Aby3Share<T>>, macs: Vec<Aby3Share<T>>) -> Self {
        assert_eq!(values.len(), macs.len());
        Self { values, macs }
    }

    pub fn get(self) -> (Vec<Aby3Share<T>>, Vec<Aby3Share<T>>) {
        (self.values, self.macs)
    }

    pub fn get_values(self) -> Vec<Aby3Share<T>> {
        self.values
    }

    pub fn get_macs(self) -> Vec<Aby3Share<T>> {
        self.macs
    }

    pub fn from_vec(vec: Vec<Share<T>>) -> Self {
        let (values, macs) = vec.into_iter().map(|s| s.get()).unzip();
        Self::new(values, macs)
    }
}

impl<T: Sharable> VecShareTrait for VecShare<T> {
    type Share = Share<T>;

    fn len(&self) -> usize {
        debug_assert!(self.values.len() == self.macs.len());
        self.values.len()
    }

    fn filter_reduce_add_twice(
        a: &Self,
        b: &Self,
        mask: &plain_reference::IrisCodeArray,
    ) -> Result<(Self::Share, Self::Share), Error> {
        if a.is_empty() || a.len() != b.len() {
            return Err(Error::InvalidCodeSizeError);
        }

        let (sum_a, sum_amac, sum_b, sum_bmac) = a
            .values
            .iter()
            .zip(a.macs.iter())
            .zip(b.values.iter().zip(b.macs.iter()))
            .zip(mask.bits())
            .filter(|(_, b)| *b)
            .map(|(((aval, amac), (bval, bmac)), _)| {
                (
                    aval.to_owned(),
                    amac.to_owned(),
                    bval.to_owned(),
                    bmac.to_owned(),
                )
            })
            .reduce(|(aa, ab, ba, bb), (aa_, ab_, ba_, bb_)| {
                (aa + aa_, ab + ab_, ba + ba_, bb + bb_)
            })
            .expect("Size is not zero");

        let sum_a = Share::new(sum_a, sum_amac);
        let sum_b = Share::new(sum_b, sum_bmac);

        Ok((sum_a, sum_b))
    }

    fn with_capacity(capacity: usize) -> Self {
        let values = Vec::with_capacity(capacity);
        let macs = Vec::with_capacity(capacity);
        Self { values, macs }
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
        self.values.reserve(additional);
        self.macs.reserve(additional);
    }

    fn push(&mut self, value: Self::Share) {
        let (val, mac) = value.get();
        self.values.push(val);
        self.macs.push(mac);
    }

    fn extend(&mut self, other: Self) {
        let (values, macs) = other.get();
        <Vec<_> as std::iter::Extend<_>>::extend(&mut self.values, values);
        <Vec<_> as std::iter::Extend<_>>::extend(&mut self.macs, macs);
    }

    fn split_at(&self, mid: usize) -> (Self, Self) {
        let (a, b) = self.values.split_at(mid);
        let (mac_a, mac_b) = self.macs.split_at(mid);
        (Self::new(a, mac_a), Self::new(b, mac_b))
    }

    fn chunks(self, chunk_size: usize) -> Vec<Self> {
        let len = self.len();
        let capacity = len / chunk_size + (len % chunk_size != 0) as usize;

        let (values, macs) = self.get();

        let mut res = Vec::with_capacity(capacity);
        for (v, m) in values
            .chunks(chunk_size)
            .into_iter()
            .zip(macs.chunks(chunk_size))
        {
            res.push(Self::new(v.to_owned(), m.to_owned()));
        }

        res
    }

    fn get_at(&self, index: usize) -> Self::Share {
        let val = self.values[index].to_owned();
        let mac = self.macs[index].to_owned();
        Share::new(val, mac)
    }

    fn set_at(&mut self, index: usize, value: Self::Share) {
        let (val, mac) = value.get();
        self.values[index] = val;
        self.macs[index] = mac;
    }
}

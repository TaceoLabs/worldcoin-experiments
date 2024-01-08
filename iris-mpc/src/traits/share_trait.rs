use num_traits::Zero;
use plain_reference::IrisCodeArray;

use crate::prelude::Error;

pub trait ShareTrait: Clone + Sized + Zero {
    type VecShare: VecShareTrait<Share = Self>;
}

// TODO replace with Index at some point
pub trait VecShareTrait: Clone {
    type Share: ShareTrait;

    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn filter_reduce_add_twice(
        a: &Self,
        b: &Self,
        mask: &IrisCodeArray,
    ) -> Result<(Self::Share, Self::Share), Error>;

    fn xor_many(self, b: Self) -> Result<Self, Error>;
    fn xor_assign_many(&mut self, b: Self) -> Result<Self, Error>;
    fn shl_assign_many(&mut self, shift: u32) -> Self;

    fn with_capacity(capacity: usize) -> Self;
    fn reserve(&mut self, additional: usize);
    fn push(&mut self, value: Self::Share);
    fn extend(&mut self, other: Self);
    fn split_at(&self, index: usize) -> (Self, Self);
    fn chunks(self, chunk_size: usize) -> Vec<Self>;
    fn get_at(&self, index: usize) -> &Self::Share;
    fn set_at(&mut self, index: usize, value: Self::Share);
}

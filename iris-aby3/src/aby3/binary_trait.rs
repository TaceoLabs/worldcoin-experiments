use super::share::Share;
use crate::prelude::{Error, Sharable};

pub trait BinaryMpcTrait<T: Sharable> {
    fn xor(a: Share<T>, b: Share<T>) -> Share<T>;
    fn xor_assign(a: &mut Share<T>, b: Share<T>);
    async fn and(&mut self, a: Share<T>, b: Share<T>) -> Result<Share<T>, Error>;

    async fn and_many(
        &mut self,
        a: Vec<Share<T>>,
        b: Vec<Share<T>>,
    ) -> Result<Vec<Share<T>>, Error>;

    async fn binary_add_3(
        &mut self,
        x1: Share<T>,
        x2: Share<T>,
        x3: Share<T>,
    ) -> Result<Share<T>, Error>;

    async fn arithmetic_to_binary(&mut self, x: Share<T>) -> Result<Share<T>, Error>;
}

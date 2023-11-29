use crate::{error::Error, types::sharable::Sharable};
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
    async fn mul(&mut self, a: Ashare, b: Ashare) -> Result<Ashare, Error>;
    fn mul_const(&self, a: Ashare, b: T) -> Ashare;
}

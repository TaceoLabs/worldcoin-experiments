use crate::{error::Error, types::sharable::Sharable};

#[allow(async_fn_in_trait)]
pub trait MpcTrait<T: Sharable, Ashare, Bshare> {
    async fn preprocess(&mut self) -> Result<(), Error>;

    // Each party inputs an arithmetic share
    async fn input_all(&mut self, input: T) -> Result<Vec<Ashare>, Error>;

    async fn open(&mut self, share: Ashare) -> Result<T, Error>;
    async fn open_many(&mut self, share: &[Ashare]) -> Result<Vec<T>, Error>;

    fn add(a: Ashare, b: Ashare) -> Ashare;
    async fn mul(&mut self, a: Ashare, b: Ashare) -> Result<Ashare, Error>;
}

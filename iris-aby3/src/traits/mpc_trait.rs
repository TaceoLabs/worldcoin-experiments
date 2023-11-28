use crate::error::Error;

pub trait MpcTrait<Ashare, Bshare> {
    async fn preprocess(&mut self) -> Result<(), Error>;

    fn add(a: Ashare, b: Ashare) -> Ashare;
    async fn mul(&mut self, a: Ashare, b: Ashare) -> Result<Ashare, Error>;
}

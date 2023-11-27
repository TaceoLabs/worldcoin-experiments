use bytes::Bytes;
use std::io::Error;

#[allow(async_fn_in_trait)]
pub trait Network {
    fn get_id(&self) -> usize;
    fn get_num_parties(&self) -> usize;

    async fn send(&mut self, id: usize, data: Bytes) -> Result<(), Error>;
    async fn receive(&mut self, id: usize) -> Result<Bytes, Error>;
    async fn broadcast(&mut self, data: Bytes) -> (Result<Bytes, Error>, Result<Bytes, Error>);
}

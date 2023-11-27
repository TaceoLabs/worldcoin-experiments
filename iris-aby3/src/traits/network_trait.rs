use bytes::Bytes;
use std::io::Error;

#[allow(async_fn_in_trait)]
pub trait NetworkTrait {
    fn get_id(&self) -> usize;
    fn get_num_parties(&self) -> usize;

    async fn send(&mut self, id: usize, data: Bytes) -> Result<(), Error>;
    async fn sent_next_id(&mut self, data: Bytes) -> Result<(), Error>;

    async fn receive(&mut self, id: usize) -> Result<Bytes, Error>;
    async fn receive_prev_id(&mut self) -> Result<Bytes, Error>;

    async fn broadcast(&mut self, data: Bytes) -> Vec<Result<Bytes, Error>>;
}

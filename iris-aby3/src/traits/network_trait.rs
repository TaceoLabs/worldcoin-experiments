use bytes::{Bytes, BytesMut};
use std::io::Error;

#[allow(async_fn_in_trait)]
pub trait NetworkTrait {
    fn get_id(&self) -> usize;
    fn get_num_parties(&self) -> usize;

    async fn shutdown(self) -> Result<(), Error>;

    async fn send(&mut self, id: usize, data: Bytes) -> Result<(), Error>;
    async fn send_next_id(&mut self, data: Bytes) -> Result<(), Error>;

    async fn receive(&mut self, id: usize) -> Result<BytesMut, Error>;
    async fn receive_prev_id(&mut self) -> Result<BytesMut, Error>;

    async fn broadcast(&mut self, data: Bytes) -> Result<Vec<BytesMut>, Error>;
}

use bytes::{Bytes, BytesMut};
use std::future::Future;
use std::io::Error;

pub trait NetworkTrait {
    fn get_id(&self) -> usize;
    fn get_num_parties(&self) -> usize;

    fn shutdown(self) -> impl Future<Output = Result<(), Error>> + Send;

    fn send(&mut self, id: usize, data: Bytes) -> impl Future<Output = Result<(), Error>> + Send;
    fn send_next_id(&mut self, data: Bytes) -> impl Future<Output = Result<(), Error>> + Send;

    fn receive(&mut self, id: usize) -> impl Future<Output = Result<BytesMut, Error>> + Send;
    fn receive_prev_id(&mut self) -> impl Future<Output = Result<BytesMut, Error>> + Send;

    fn broadcast(
        &mut self,
        data: Bytes,
    ) -> impl Future<Output = Result<Vec<BytesMut>, Error>> + Send;
}

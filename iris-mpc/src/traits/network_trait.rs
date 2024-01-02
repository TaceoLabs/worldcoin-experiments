use bytes::{Bytes, BytesMut};
use std::io::Error;

pub trait NetworkTrait {
    fn get_id(&self) -> usize;
    fn get_num_parties(&self) -> usize;

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error>;

    fn shutdown(self) -> Result<(), Error>;

    fn send(&mut self, id: usize, data: Bytes) -> Result<(), Error>;
    fn send_next_id(&mut self, data: Bytes) -> Result<(), Error>;
    fn send_prev_id(&mut self, data: Bytes) -> Result<(), Error>;

    fn receive(&mut self, id: usize) -> Result<BytesMut, Error>;
    fn receive_prev_id(&mut self) -> Result<BytesMut, Error>;
    fn receive_next_id(&mut self) -> Result<BytesMut, Error>;

    fn broadcast(&mut self, data: Bytes) -> Result<Vec<BytesMut>, Error>;
}

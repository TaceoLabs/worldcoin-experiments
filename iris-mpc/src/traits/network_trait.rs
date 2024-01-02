use bytes::{Bytes, BytesMut};
use std::io::Error;

use crate::{
    aby3::utils::{ring_vec_from_bytes, ring_vec_to_bytes},
    types::ring_element::RingImpl,
};

#[allow(async_fn_in_trait)]
pub trait NetworkTrait {
    fn get_id(&self) -> usize;
    fn get_num_parties(&self) -> usize;

    fn print_connection_stats(&self, out: &mut impl std::io::Write) -> Result<(), Error>;

    async fn shutdown(self) -> Result<(), Error>;

    async fn send(&mut self, id: usize, data: Bytes) -> Result<(), Error>;
    async fn send_next_id(&mut self, data: Bytes) -> Result<(), Error>;
    async fn send_prev_id(&mut self, data: Bytes) -> Result<(), Error>;

    async fn receive(&mut self, id: usize) -> Result<BytesMut, Error>;
    async fn receive_prev_id(&mut self) -> Result<BytesMut, Error>;
    async fn receive_next_id(&mut self) -> Result<BytesMut, Error>;

    async fn broadcast(&mut self, data: Bytes) -> Result<Vec<BytesMut>, Error>;

    #[inline]
    async fn send_value<R: RingImpl>(&mut self, id: usize, data: R) -> Result<(), Error> {
        let bytes = data.to_bytes();
        self.send(id, bytes).await
    }

    #[inline]
    async fn send_value_next_id<R: RingImpl>(&mut self, data: R) -> Result<(), Error> {
        let bytes = data.to_bytes();
        self.send_next_id(bytes).await
    }

    #[inline]
    async fn send_value_prev_id<R: RingImpl>(&mut self, data: R) -> Result<(), Error> {
        let bytes = data.to_bytes();
        self.send_prev_id(bytes).await
    }

    #[inline]
    async fn receive_value<R: RingImpl>(&mut self, id: usize) -> Result<R, Error> {
        self.receive(id)
            .await
            .map(|bytes| R::from_bytes_mut(bytes).expect("Invalid bytes"))
    }

    #[inline]
    async fn receive_value_prev_id<R: RingImpl>(&mut self) -> Result<R, Error> {
        self.receive_prev_id()
            .await
            .map(|bytes| R::from_bytes_mut(bytes).expect("Invalid bytes"))
    }

    #[inline]
    async fn receive_value_next_id<R: RingImpl>(&mut self) -> Result<R, Error> {
        self.receive_next_id()
            .await
            .map(|bytes| R::from_bytes_mut(bytes).expect("Invalid bytes"))
    }

    #[inline]
    async fn send_vec<R: RingImpl>(&mut self, id: usize, data: Vec<R>) -> Result<(), Error> {
        let bytes = ring_vec_to_bytes(data);
        self.send(id, bytes).await
    }

    #[inline]
    async fn send_vec_next_id<R: RingImpl>(&mut self, data: Vec<R>) -> Result<(), Error> {
        let bytes = ring_vec_to_bytes(data);
        self.send_next_id(bytes).await
    }

    #[inline]
    async fn send_vec_prev_id<R: RingImpl>(&mut self, data: Vec<R>) -> Result<(), Error> {
        let bytes = ring_vec_to_bytes(data);
        self.send_prev_id(bytes).await
    }

    #[inline]
    async fn receive_vec<R: RingImpl>(&mut self, id: usize) -> Result<Vec<R>, Error> {
        self.receive(id)
            .await
            .map(|bytes| ring_vec_from_bytes(bytes).expect("Invalid bytes"))
    }

    #[inline]
    async fn receive_vec_prev_id<R: RingImpl>(&mut self) -> Result<Vec<R>, Error> {
        self.receive_prev_id()
            .await
            .map(|bytes| ring_vec_from_bytes(bytes).expect("Invalid bytes"))
    }

    #[inline]
    async fn receive_vec_next_id<R: RingImpl>(&mut self) -> Result<Vec<R>, Error> {
        self.receive_next_id()
            .await
            .map(|bytes| ring_vec_from_bytes(bytes).expect("Invalid bytes"))
    }
}

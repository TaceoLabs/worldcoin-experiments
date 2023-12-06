use super::random::prf::PrfSeed;
use crate::{
    error::Error,
    prelude::Sharable,
    traits::{binary_trait::BinaryMpcTrait, network_trait::NetworkTrait},
    types::ring_element::RingImpl,
};
use bytes::{Buf, Bytes, BytesMut};
use std::{
    io::Error as IOError,
    ops::{BitXor, BitXorAssign},
};

pub(crate) fn bytes_to_seed(mut bytes: BytesMut) -> Result<PrfSeed, Error> {
    if bytes.len() != 32 {
        Err(Error::Other(
            "cannot setup prf because wrong seed length from other party".to_owned(),
        ))
    } else {
        let mut their_seed: PrfSeed = [0; 32];
        bytes.copy_to_slice(&mut their_seed);
        Ok(their_seed)
    }
}

pub(crate) fn ceil_log2(x: usize) -> usize {
    let mut y = 0;
    let mut x = x - 1;
    while x > 0 {
        x >>= 1;
        y += 1;
    }
    y
}

pub(crate) async fn send_and_receive<N: NetworkTrait>(
    network: &mut N,
    data: Bytes,
) -> Result<BytesMut, IOError> {
    network.send_next_id(data).await?;
    let data = network.receive_prev_id().await?;
    Ok(data)
}

pub(crate) async fn send_and_receive_value<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    value: R,
) -> Result<R, Error> {
    let response = send_and_receive(network, value.to_bytes()).await?;
    R::from_bytes_mut(response)
}

pub(crate) async fn send_and_receive_vec<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    values: Vec<R>,
) -> Result<Vec<R>, Error> {
    let len = values.len();
    let response = send_and_receive(network, ring_vec_to_bytes(values)).await?;
    ring_vec_from_bytes(response, len)
}

pub(crate) async fn send_value<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    value: R,
    id: usize,
) -> Result<(), Error> {
    Ok(network.send(id, value.to_bytes()).await?)
}

pub(crate) async fn receive_value<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    id: usize,
) -> Result<R, Error> {
    let response = network.receive(id).await?;
    R::from_bytes_mut(response)
}

pub(crate) async fn send_vec<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    value: Vec<R>,
    id: usize,
) -> Result<(), Error> {
    Ok(network.send(id, ring_vec_to_bytes(value)).await?)
}

pub(crate) async fn receive_vec<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    id: usize,
    len: usize,
) -> Result<Vec<R>, Error> {
    let response = network.receive(id).await?;
    ring_vec_from_bytes(response, len)
}

pub(crate) fn ring_vec_from_bytes<T>(mut bytes: BytesMut, n: usize) -> Result<Vec<T>, Error>
where
    T: RingImpl,
{
    let mut res = Vec::with_capacity(n);
    for _ in 0..n {
        res.push(T::take_from_bytes_mut(&mut bytes)?);
    }
    if bytes.remaining() != 0 {
        return Err(Error::ConversionError);
    }
    Ok(res)
}

pub(crate) fn ring_vec_to_bytes<T>(vec: Vec<T>) -> Bytes
where
    T: RingImpl,
{
    let size = T::get_k() / 8 + ((T::get_k() % 8) != 0) as usize;
    let mut out = BytesMut::with_capacity(size * vec.len());
    for v in vec {
        v.add_to_bytes(&mut out);
    }
    out.freeze()
}

pub(crate) async fn or_tree<T, Mpc, Share>(
    engine: &mut Mpc,
    mut inputs: Vec<Share>,
) -> Result<Share, Error>
where
    T: Sharable,
    Mpc: BinaryMpcTrait<T, Share>,
    Share: Clone
        + BitXorAssign
        + BitXor<Output = Share>
        + std::ops::ShlAssign<u32>
        + std::ops::Shl<u32, Output = Share>
        + Send
        + Sync
        + 'static,
{
    const PACK_SIZE: usize = 256; // TODO Move

    let mut num = inputs.len();

    while num > 1 {
        let mod_ = num & 1;
        num >>= 1;

        let a_vec = &inputs[0..num];
        let b_vec = &inputs[num..2 * num];

        let mut res = Vec::with_capacity(num + mod_);
        for (tmp_a, tmp_b) in a_vec.chunks(PACK_SIZE).zip(b_vec.chunks(PACK_SIZE)) {
            let r = engine.or_many(tmp_a.to_vec(), tmp_b.to_vec()).await?;
            res.extend(r);
        }

        for leftover in inputs.into_iter().skip(2 * num) {
            res.push(leftover);
        }
        inputs = res;

        num += mod_;
    }

    let output = inputs[0].to_owned();
    Ok(output)
}

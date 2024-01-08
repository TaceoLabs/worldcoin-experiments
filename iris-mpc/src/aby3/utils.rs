use super::random::prf::PrfSeed;
use crate::{
    error::Error,
    prelude::Sharable,
    traits::{
        binary_trait::BinaryMpcTrait,
        network_trait::NetworkTrait,
        share_trait::{ShareTrait, VecShareTrait},
    },
    types::{
        int_ring::IntRing2k,
        ring_element::{RingElement, RingImpl},
    },
};
use bytes::{Buf, Bytes, BytesMut};
use num_traits::{AsPrimitive, Zero};
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

pub(crate) fn to_bits<R: RingImpl>(mut x: usize) -> Vec<R> {
    let mut res = Vec::new();
    while !x.is_zero() {
        res.push(R::from(x & 1 == 1));
        x >>= 1;
    }
    res
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

pub(crate) async fn send_value_next<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    value: R,
) -> Result<(), Error> {
    Ok(network.send_next_id(value.to_bytes()).await?)
}

pub(crate) async fn send_value_prev<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    value: R,
) -> Result<(), Error> {
    Ok(network.send_prev_id(value.to_bytes()).await?)
}

pub(crate) async fn receive_value<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    id: usize,
) -> Result<R, Error> {
    let response = network.receive(id).await?;
    R::from_bytes_mut(response)
}

pub(crate) async fn receive_value_prev<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
) -> Result<R, Error> {
    let response = network.receive_prev_id().await?;
    R::from_bytes_mut(response)
}

pub(crate) async fn receive_value_next<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
) -> Result<R, Error> {
    let response = network.receive_next_id().await?;
    R::from_bytes_mut(response)
}

pub(crate) async fn send_vec<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    value: Vec<R>,
    id: usize,
) -> Result<(), Error> {
    Ok(network.send(id, ring_vec_to_bytes(value)).await?)
}

pub(crate) async fn send_vec_next<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    value: Vec<R>,
) -> Result<(), Error> {
    Ok(network.send_next_id(ring_vec_to_bytes(value)).await?)
}

#[allow(dead_code)]
pub(crate) async fn send_vec_prev<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    value: Vec<R>,
) -> Result<(), Error> {
    Ok(network.send_prev_id(ring_vec_to_bytes(value)).await?)
}

pub(crate) async fn receive_vec<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    id: usize,
    len: usize,
) -> Result<Vec<R>, Error> {
    let response = network.receive(id).await?;
    ring_vec_from_bytes(response, len)
}

pub(crate) async fn receive_vec_prev<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    len: usize,
) -> Result<Vec<R>, Error> {
    let response = network.receive_prev_id().await?;
    ring_vec_from_bytes(response, len)
}

#[allow(dead_code)]
pub(crate) async fn receive_vec_next<N: NetworkTrait, R: RingImpl>(
    network: &mut N,
    len: usize,
) -> Result<Vec<R>, Error> {
    let response = network.receive_next_id().await?;
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
    let size = T::K / 8 + ((T::K % 8) != 0) as usize;
    let mut out = BytesMut::with_capacity(size * vec.len());
    for v in vec {
        v.add_to_bytes(&mut out);
    }
    out.freeze()
}

pub(crate) async fn or_tree<T, Mpc, Share: ShareTrait>(
    engine: &mut Mpc,
    mut inputs: Share::VecShare,
    chunk_size: usize,
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
    let mut num = inputs.len();

    while num > 1 {
        let mod_ = num & 1;
        num >>= 1;

        let (a_vec, tmp) = inputs.split_at(num);
        let (b_vec, leftover) = tmp.split_at(num);

        let mut res = Share::VecShare::with_capacity(num + mod_);

        for (tmp_a, tmp_b) in a_vec
            .chunks(chunk_size)
            .into_iter()
            .zip(b_vec.chunks(chunk_size))
        {
            let r = engine.or_many(tmp_a, tmp_b).await?;
            res.extend(r);
        }

        res.extend(leftover);
        inputs = res;

        num += mod_;
    }

    let output = inputs[0].to_owned();
    Ok(output)
}

pub(crate) fn split<T: IntRing2k, U: IntRing2k>(
    a: RingElement<T>,
) -> (RingElement<U>, RingElement<U>)
where
    T: AsPrimitive<U>,
{
    debug_assert_eq!(T::K, 2 * U::K);
    let shift = U::K;

    let a1 = RingElement((a.0).as_());
    let a2 = RingElement((a.0 >> shift).as_());

    (a1, a2)
}

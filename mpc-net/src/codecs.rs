use std::{io, mem::size_of};

use bytes::{Buf, BufMut, BytesMut};
use serde::{de::DeserializeOwned, Serialize};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

#[derive(Default, Debug)]
pub struct BincodeCodec<M: Serialize + DeserializeOwned> {
    inner: LengthDelimitedCodec,
    phantom: std::marker::PhantomData<M>,
}

impl<M: Serialize + DeserializeOwned> Clone for BincodeCodec<M> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<M: Serialize + DeserializeOwned> BincodeCodec<M> {
    pub fn new() -> Self {
        Self {
            inner: LengthDelimitedCodec::new(),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<M> Encoder<M> for BincodeCodec<M>
where
    M: serde::Serialize + serde::de::DeserializeOwned,
{
    type Error = io::Error;

    fn encode(&mut self, item: M, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        // reserve a bit to avoid reallocations, but this does not work well for nested types
        let mut buf = BytesMut::with_capacity(std::mem::size_of::<M>() + 16).writer();
        bincode::serialize_into(&mut buf, &item).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to serialize message with bincode: {}", e),
            )
        })?;
        let buf = buf.into_inner().freeze();
        self.inner.encode(buf, dst)
    }
}

impl<M> Decoder for BincodeCodec<M>
where
    M: serde::Serialize + serde::de::DeserializeOwned,
{
    type Item = M;

    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let buf = match self.inner.decode(src)? {
            Some(buf) => buf,
            None => return Ok(None),
        };

        let reader = buf.reader();

        let result = bincode::deserialize_from::<_, M>(reader).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to deserialize message with bincode: {}", e),
            )
        })?;
        Ok(Some(result))
    }
}

#[derive(Default, Debug, Clone)]
pub struct VecU16Codec {
    decode_state: Option<usize>,
}

impl Encoder<Vec<u16>> for VecU16Codec {
    type Error = io::Error;

    fn encode(&mut self, item: Vec<u16>, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        dst.reserve(size_of::<u32>() + item.len() * size_of::<u16>());
        dst.put_u32(u32::try_from(item.len()).expect("Max Vector size is u32::MAX"));
        for i in item {
            dst.put_u16(i);
        }
        Ok(())
    }
}

impl Decoder for VecU16Codec {
    type Item = Vec<u16>;

    type Error = io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let n = match self.decode_state {
            // we are expecting a new frame
            None => {
                if src.len() < size_of::<u32>() {
                    return Ok(None);
                }
                let len = usize::try_from(src.get_u32()).expect("we need u32 to fit into usize...");
                self.decode_state = Some(len);
                src.reserve(len);
                len
            }
            Some(n) => n,
        };
        if src.len() < n * size_of::<u16>() {
            return Ok(None);
        }
        let mut res = Vec::with_capacity(n);
        for _ in 0..n {
            res.push(src.get_u16());
        }
        self.decode_state = None;
        src.reserve(size_of::<u32>());
        Ok(Some(res))
    }
}

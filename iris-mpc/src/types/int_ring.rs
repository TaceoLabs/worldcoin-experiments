use super::{bit::Bit, ring_element::RingElement, sharable::Sharable};
use crate::error::Error;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_traits::{
    One, WrappingAdd, WrappingMul, WrappingNeg, WrappingShl, WrappingShr, WrappingSub, Zero,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{Debug, Display},
    mem::size_of,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not},
};

pub trait IntRing2k:
    Sized
    + Send
    + Sync
    + Copy
    + PartialEq
    + Debug
    + std::fmt::Display
    + WrappingAdd<Output = Self>
    + WrappingSub<Output = Self>
    + WrappingShl
    + WrappingShr
    + WrappingNeg
    + Not<Output = Self>
    + BitXor<Output = Self>
    + BitOr<Output = Self>
    + BitOrAssign
    + WrappingMul<Output = Self>
    + BitXorAssign
    + BitAnd<Output = Self>
    + BitAndAssign
    + Zero
    + One
    + From<bool>
    + Default
    + PartialOrd
    + Ord
    + Serialize
    + TryFrom<usize>
    + for<'a> Deserialize<'a>
    + Display
    + 'static
{
    type Signed: Sharable<Share = RingElement<Self>>;

    fn get_k() -> usize;
    fn to_signed(self) -> Self::Signed;

    fn add_to_bytes(self, other: &mut BytesMut);
    fn from_bytes_mut(other: BytesMut) -> Result<Self, Error>;
    fn from_bytes(other: Bytes) -> Result<Self, Error>;

    fn take_from_bytes_mut(other: &mut BytesMut) -> Result<Self, Error>;

    fn to_bytes(self) -> Bytes {
        let mut out = BytesMut::new();
        self.add_to_bytes(&mut out);
        out.freeze()
    }

    /// a += b
    #[inline(always)]
    fn wrapping_add_assign(&mut self, rhs: &Self) {
        *self = self.wrapping_add(rhs);
    }

    /// a -= b
    #[inline(always)]
    fn wrapping_sub_assign(&mut self, rhs: &Self) {
        *self = self.wrapping_sub(rhs);
    }

    /// a = -a
    #[inline(always)]
    fn wrapping_neg_inplace(&mut self) {
        *self = self.wrapping_neg();
    }

    /// a*= b
    #[inline(always)]
    fn wrapping_mul_assign(&mut self, rhs: &Self) {
        *self = self.wrapping_mul(rhs);
    }

    /// a <<= b
    #[inline(always)]
    fn wrapping_shl_assign(&mut self, rhs: u32) {
        *self = self.wrapping_shl(rhs);
    }

    /// a >>= b
    #[inline(always)]
    fn wrapping_shr_assign(&mut self, rhs: u32) {
        *self = self.wrapping_shr(rhs);
    }
}

impl IntRing2k for Bit {
    type Signed = Self;

    #[inline(always)]
    fn get_k() -> usize {
        1
    }

    fn to_signed(self) -> Self::Signed {
        self
    }

    fn add_to_bytes(self, other: &mut BytesMut) {
        other.put_u8(self.into());
    }

    fn from_bytes_mut(mut other: BytesMut) -> Result<Self, Error> {
        if other.remaining() != 1 {
            return Err(Error::ConversionError);
        }
        Bit::try_from(other.get_u8())
    }

    fn from_bytes(mut other: Bytes) -> Result<Self, Error> {
        if other.remaining() != 1 {
            return Err(Error::ConversionError);
        }
        Bit::try_from(other.get_u8())
    }

    fn take_from_bytes_mut(other: &mut BytesMut) -> Result<Self, Error> {
        if other.remaining() < 1 {
            return Err(Error::ConversionError);
        }
        Bit::try_from(other.get_u8())
    }
}

impl IntRing2k for u8 {
    type Signed = i8;

    #[inline(always)]
    fn get_k() -> usize {
        Self::BITS as usize
    }

    fn to_signed(self) -> Self::Signed {
        self as Self::Signed
    }

    fn add_to_bytes(self, other: &mut BytesMut) {
        other.put_u8(self);
    }

    fn from_bytes_mut(mut other: BytesMut) -> Result<Self, Error> {
        if other.remaining() != size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u8())
    }

    fn from_bytes(mut other: Bytes) -> Result<Self, Error> {
        if other.remaining() != size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u8())
    }

    fn take_from_bytes_mut(other: &mut BytesMut) -> Result<Self, Error> {
        if other.remaining() < size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u8())
    }
}

impl IntRing2k for u16 {
    type Signed = i16;

    #[inline(always)]
    fn get_k() -> usize {
        Self::BITS as usize
    }

    fn to_signed(self) -> Self::Signed {
        self as Self::Signed
    }

    fn add_to_bytes(self, other: &mut BytesMut) {
        other.put_u16(self);
    }

    fn from_bytes_mut(mut other: BytesMut) -> Result<Self, Error> {
        if other.remaining() != size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u16())
    }

    fn from_bytes(mut other: Bytes) -> Result<Self, Error> {
        if other.remaining() != size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u16())
    }

    fn take_from_bytes_mut(other: &mut BytesMut) -> Result<Self, Error> {
        if other.remaining() < size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u16())
    }
}

impl IntRing2k for u32 {
    type Signed = i32;

    #[inline(always)]
    fn get_k() -> usize {
        Self::BITS as usize
    }

    fn to_signed(self) -> Self::Signed {
        self as Self::Signed
    }

    fn add_to_bytes(self, other: &mut BytesMut) {
        other.put_u32(self);
    }

    fn from_bytes_mut(mut other: BytesMut) -> Result<Self, Error> {
        if other.remaining() != size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u32())
    }

    fn from_bytes(mut other: Bytes) -> Result<Self, Error> {
        if other.remaining() != size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u32())
    }

    fn take_from_bytes_mut(other: &mut BytesMut) -> Result<Self, Error> {
        if other.remaining() < size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u32())
    }
}

impl IntRing2k for u64 {
    type Signed = i64;

    #[inline(always)]
    fn get_k() -> usize {
        Self::BITS as usize
    }

    fn to_signed(self) -> Self::Signed {
        self as Self::Signed
    }

    fn add_to_bytes(self, other: &mut BytesMut) {
        other.put_u64(self);
    }

    fn from_bytes_mut(mut other: BytesMut) -> Result<Self, Error> {
        if other.remaining() != size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u64())
    }

    fn from_bytes(mut other: Bytes) -> Result<Self, Error> {
        if other.remaining() != size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u64())
    }

    fn take_from_bytes_mut(other: &mut BytesMut) -> Result<Self, Error> {
        if other.remaining() < size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u64())
    }
}

impl IntRing2k for u128 {
    type Signed = i128;

    #[inline(always)]
    fn get_k() -> usize {
        Self::BITS as usize
    }

    fn to_signed(self) -> Self::Signed {
        self as Self::Signed
    }

    fn add_to_bytes(self, other: &mut BytesMut) {
        other.put_u128(self);
    }

    fn from_bytes_mut(mut other: BytesMut) -> Result<Self, Error> {
        if other.remaining() != size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u128())
    }

    fn from_bytes(mut other: Bytes) -> Result<Self, Error> {
        if other.remaining() != size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u128())
    }

    fn take_from_bytes_mut(other: &mut BytesMut) -> Result<Self, Error> {
        if other.remaining() < size_of::<Self>() {
            return Err(Error::ConversionError);
        }
        Ok(other.get_u128())
    }
}

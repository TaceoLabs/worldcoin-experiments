use super::{bit::Bit, ring_element::RingElement, sharable::Sharable};
use crate::{error::Error, types::extended_euclid_rev};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_traits::{
    One, WrappingAdd, WrappingMul, WrappingNeg, WrappingShl, WrappingShr, WrappingSub, Zero,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
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
    const K: usize;
    type Signed: Sharable<Share = RingElement<Self>>;

    fn to_signed(self) -> Self::Signed;
    fn upgrade_to_128(self) -> u128;

    fn add_to_bytes(self, other: &mut BytesMut);
    fn from_bytes_mut(other: BytesMut) -> Result<Self, Error>;
    fn from_bytes(other: Bytes) -> Result<Self, Error>;

    fn take_from_bytes_mut(other: &mut BytesMut) -> Result<Self, Error>;

    fn to_bytes(self) -> Bytes {
        let mut out = BytesMut::new();
        self.add_to_bytes(&mut out);
        out.freeze()
    }

    fn floor_div(self, other: &Self) -> Self;
    fn inverse(&self) -> Result<Self, Error>;

    fn add_to_hash<D: Digest>(&self, hasher: &mut D);

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
    const K: usize = 1;
    type Signed = Self;

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

    fn floor_div(self, other: &Self) -> Self {
        if !other.0 {
            panic!("Division by zero")
        }
        self
    }

    fn inverse(&self) -> Result<Self, Error> {
        if !self.0 {
            return Err(Error::NoInverseError);
        }
        Ok(*self)
    }

    fn add_to_hash<D: Digest>(&self, hasher: &mut D) {
        hasher.update([self.0 as u8]);
    }

    fn upgrade_to_128(self) -> u128 {
        self.0 as u128
    }
}

impl IntRing2k for u8 {
    const K: usize = Self::BITS as usize;
    type Signed = i8;

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

    fn floor_div(self, other: &Self) -> Self {
        self / other
    }

    fn inverse(&self) -> Result<Self, Error> {
        if 1 & self == 0 {
            return Err(Error::NoInverseError);
        }

        let (_, inv) = extended_euclid_rev(*self as u16, Self::MAX as u16 + 1);

        debug_assert!((inv as Self).wrapping_mul(*self) == 1);
        Ok(inv as Self)
    }

    fn add_to_hash<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.to_le_bytes());
    }

    fn upgrade_to_128(self) -> u128 {
        self as u128
    }
}

impl IntRing2k for u16 {
    const K: usize = Self::BITS as usize;
    type Signed = i16;

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

    fn floor_div(self, other: &Self) -> Self {
        self / other
    }

    fn inverse(&self) -> Result<Self, Error> {
        if 1 & self == 0 {
            return Err(Error::NoInverseError);
        }

        let (_, inv) = extended_euclid_rev(*self as u32, Self::MAX as u32 + 1);

        debug_assert!((inv as Self).wrapping_mul(*self) == 1);
        Ok(inv as Self)
    }

    fn add_to_hash<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.to_le_bytes());
    }

    fn upgrade_to_128(self) -> u128 {
        self as u128
    }
}

impl IntRing2k for u32 {
    const K: usize = Self::BITS as usize;
    type Signed = i32;

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

    fn floor_div(self, other: &Self) -> Self {
        self / other
    }

    fn inverse(&self) -> Result<Self, Error> {
        if 1 & self == 0 {
            return Err(Error::NoInverseError);
        }

        let (_, inv) = extended_euclid_rev(*self as u64, Self::MAX as u64 + 1);

        debug_assert!((inv as Self).wrapping_mul(*self) == 1);
        Ok(inv as Self)
    }

    fn add_to_hash<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.to_le_bytes());
    }

    fn upgrade_to_128(self) -> u128 {
        self as u128
    }
}

impl IntRing2k for u64 {
    const K: usize = Self::BITS as usize;
    type Signed = i64;

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

    fn floor_div(self, other: &Self) -> Self {
        self / other
    }

    fn inverse(&self) -> Result<Self, Error> {
        if 1 & self == 0 {
            return Err(Error::NoInverseError);
        }

        let (_, inv) = extended_euclid_rev(*self as u128, Self::MAX as u128 + 1);

        debug_assert!((inv as Self).wrapping_mul(*self) == 1);
        Ok(inv as Self)
    }

    fn add_to_hash<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.to_le_bytes());
    }

    fn upgrade_to_128(self) -> u128 {
        self as u128
    }
}

impl IntRing2k for u128 {
    const K: usize = Self::BITS as usize;
    type Signed = i128;

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

    fn floor_div(self, other: &Self) -> Self {
        self / other
    }

    fn inverse(&self) -> Result<Self, Error> {
        todo!("Implement inverse for u128")
    }

    fn add_to_hash<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.to_le_bytes());
    }

    fn upgrade_to_128(self) -> u128 {
        self
    }
}
